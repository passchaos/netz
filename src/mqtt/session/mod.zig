//! Bounded MQTT server Session State for reconnect and offline delivery.
//!
//! Sessions are addressed by generation-checked handles, so callers never hold
//! pointers invalidated by table growth. Variable-length protocol data is
//! owned for the Session lifetime; multi-destination offline fanout may share
//! immutable Topic Name and payload bytes through a reference-counted broker
//! Publication. Queue/inflight scans write borrowed views into caller storage
//! and allocate only when a previously unsent message moves into inflight.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const persistence = @import("../persistence/codec.zig");
const StorageCache = @import("../storage_cache.zig").Cache;
const open_admission = @import("open.zig");
const identifiers = @import("identifiers.zig");
pub const PacketIdentifierOwnership = identifiers.Ownership;
pub const SharedPublication = @import("../broker/publication.zig").Publication;
const shared_publication_wire = std.math.maxInt(usize);

pub const Error = mqtt.Error || error{
    SessionNotFound,
    SessionLimitExceeded,
    SessionByteLimitExceeded,
    SubscriptionLimitExceeded,
    QueueFull,
    InflightFull,
    IncomingQoS2Full,
    InvalidAcknowledgement,
    BufferTooSmall,
};

pub const Options = struct {
    max_sessions: usize = 16_384,
    max_subscriptions_per_session: usize = 1_024,
    max_queued_per_session: usize = 16_384,
    /// Maximum payload bytes retained in one Session's outgoing queue. Zero
    /// disables this independent byte bound, matching Mosquitto's
    /// `max_queued_bytes` convention. Topic/property ownership remains covered
    /// by `max_session_bytes` and `max_total_bytes`.
    max_queued_payload_bytes_per_session: usize = 0,
    /// Administrative cap for new outgoing QoS 1/2 transactions. Snapshot
    /// restore may retain more transactions after a configuration decrease;
    /// `drainInto` then releases no new work until acknowledgements bring the
    /// Session back below this limit.
    max_inflight_per_session: usize = std.math.maxInt(u16),
    /// Maximum payload bytes occupying outgoing QoS 1/2 inflight state. Zero
    /// disables the byte bound. Like Mosquitto, admission inspects the current
    /// window, so a single message may cross the threshold but no later
    /// PUBLISH enters until acknowledgements or expiry release bytes.
    max_inflight_payload_bytes_per_session: usize = 0,
    max_incoming_qos2_per_session: usize = 16_384,
    max_session_bytes: usize = 64 * 1024 * 1024,
    max_total_bytes: usize = 1024 * 1024 * 1024,
};

pub const Handle = struct {
    index: usize,
    generation: u64,
};

const OpenContext = struct {
    pub const StoreType = Store;
    pub const HandleType = Handle;
};
pub const PreparedOpen = open_admission.PreparedOpen(OpenContext);

pub const OpenResult = struct {
    handle: Handle,
    route_id: u64,
    session_present: bool,
    /// True when another live Network Connection owned this ClientID.
    /// Broker integration must disconnect the previous connection.
    replaced_connection: bool,
};

pub const Stats = struct {
    connected: bool,
    expiry_interval: u32,
    subscription_count: usize,
    queued_count: usize,
    queued_payload_bytes: usize,
    inflight_count: usize,
    /// QoS 1/2 PUBLISH packets sent on the current Network Connection that
    /// still consume the peer's Receive Maximum window.
    outgoing_publish_window_used: usize,
    inflight_payload_bytes: usize,
    incoming_qos2_count: usize,
    owned_wire_bytes: usize,
};

/// Aggregate Session Store gauges captured while the owner provides external
/// synchronization. Counts include transient connected Sessions and durable
/// connected/offline Sessions. Totals saturate so observability cannot fail
/// or wrap under deliberately extreme configured limits.
pub const StoreStats = struct {
    session_count: usize,
    connected_count: usize,
    disconnected_count: usize,
    subscription_count: usize,
    queued_count: usize,
    queued_payload_bytes: usize,
    inflight_count: usize,
    outgoing_publish_window_used: usize,
    inflight_payload_bytes: usize,
    incoming_qos2_count: usize,
    owned_wire_bytes: usize,
};

pub const Subscription = struct {
    topic_filter: []const u8,
    qos: mqtt.QoS,
    no_local: bool,
    retain_as_published: bool,
    retain_handling: u2,
    subscription_identifier: ?usize,
};

pub const EnqueueResult = enum {
    queued,
    expired,
};

pub const EnqueueOptions = struct {
    qos: mqtt.QoS,
    retain: bool = false,
    properties: []const mqtt.Property = &.{},
    now: std.Io.Timestamp,
};

pub fn validatePublishForSession(
    topic: []const u8,
    payload: []const u8,
    properties: []const mqtt.Property,
) mqtt.Error!void {
    try mqtt.validateTopicName(topic);
    try mqtt.validatePublishProperties(properties);
    try validateQueuedPayload(properties, payload);
    if (mqtt.topicAlias(properties) != null) {
        // Alias mappings are scoped to a Network Connection and cannot be
        // replayed from persistent Session State.
        return error.InvalidProperty;
    }
}

pub const PublishTransmission = struct {
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    dup: bool,
    packet_id: u16,
    properties: []const mqtt.Property,
    message_expiry_interval: ?u32,

    pub fn write(
        self: PublishTransmission,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
    ) Error!void {
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(allocator);
        if (protocol == .v5) {
            try properties.ensureTotalCapacity(
                allocator,
                self.properties.len,
            );
            for (self.properties) |property| {
                if (property == .four_byte and
                    property.four_byte.id == .message_expiry_interval)
                {
                    const remaining = self.message_expiry_interval orelse
                        continue;
                    properties.appendAssumeCapacity(.{ .four_byte = .{
                        .id = .message_expiry_interval,
                        .value = remaining,
                    } });
                } else {
                    properties.appendAssumeCapacity(property);
                }
            }
        }
        try mqtt.writePublish(
            list,
            allocator,
            protocol,
            self.topic,
            self.payload,
            .{
                .qos = self.qos,
                .retain = self.retain,
                .dup = self.qos != .at_most_once and self.dup,
                // Zero is an internal completion sentinel for queued QoS 0;
                // MQTT forbids a Packet Identifier in its wire PUBLISH.
                .packet_id = if (self.qos == .at_most_once)
                    null
                else
                    self.packet_id,
                .properties = properties.items,
            },
        );
    }
};

pub const PubRelTransmission = struct {
    packet_id: u16,
    /// The transaction has already emitted PUBREL on an earlier attempt.
    dup: bool = false,

    pub fn write(
        self: PubRelTransmission,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
    ) Error!void {
        try mqtt.AckPacket.writeWithDup(
            list,
            allocator,
            protocol,
            .pubrel,
            self.dup and protocol == .v3_1,
            self.packet_id,
            0,
            &.{},
        );
    }
};

pub const Transmission = union(enum) {
    publish: PublishTransmission,
    pubrel: PubRelTransmission,
};

pub const AckAction = enum {
    completed,
    send_pubrel,
};

pub const DropAction = enum {
    dropped,
    ignored,
};

const OwnedSubscription = struct {
    topic_filter: []u8,
    qos: mqtt.QoS,
    no_local: bool,
    retain_as_published: bool,
    retain_handling: u2,
    subscription_identifier: ?usize,

    fn deinit(
        self: *OwnedSubscription,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.topic_filter);
        self.* = undefined;
    }

    fn view(self: OwnedSubscription) Subscription {
        return .{
            .topic_filter = self.topic_filter,
            .qos = self.qos,
            .no_local = self.no_local,
            .retain_as_published = self.retain_as_published,
            .retain_handling = self.retain_handling,
            .subscription_identifier = self.subscription_identifier,
        };
    }
};

const OwnedPublish = struct {
    /// One allocation owns the immutable Topic Name and payload bytes. Session
    /// fanout creates this object per durable destination, so co-locating the
    /// two slices removes one allocator round trip without sharing reconnect
    /// ownership or changing snapshot/wire views.
    wire: []u8,
    wire_allocation_len: usize,
    topic: []u8,
    payload: []u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []mqtt.Property,
    stored_at_ns: i96,
    expiry_interval: ?u32,
    allocation_bytes: usize,

    fn deinit(
        self: *OwnedPublish,
        allocator: std.mem.Allocator,
        cache: *StorageCache,
    ) void {
        owned_properties.deinit(allocator, self.properties);
        if (self.wire_allocation_len == shared_publication_wire) {
            SharedPublication.ownerForBytes(self.wire).release();
        } else {
            const allocation = self.wire.ptr[0..self.wire_allocation_len];
            cache.release(allocation);
        }
        self.* = undefined;
    }
};

const InflightState = enum {
    await_puback,
    await_pubrec,
    await_pubcomp,
};

pub const OutgoingQoSState = InflightState;

pub const IncomingQoS2State = enum {
    await_pubrel,
    release_pending,
};

const IncomingQoS2 = struct {
    state: IncomingQoS2State,
    /// False only for a locally staged marker that has never begun a PUBREC
    /// write. Once output is attempted, rollback is unsafe even if the write
    /// reports an error because the peer may have received the packet.
    pubrec_may_be_visible: bool,
};

const Inflight = struct {
    publish: OwnedPublish,
    packet_id: u16,
    state: InflightState,
    needs_send: bool,
    retransmission: bool,
    /// Process-local durability barrier for an accepted PUBREC. Snapshots
    /// intentionally omit this bit: restoring an encoded `await_pubcomp`
    /// state proves that the transition was committed and may emit PUBREL.
    pubrel_blocked: bool = false,
    /// Stable PUBLISH insertion order, independent of reusable array slots.
    order_previous: u16 = no_inflight_send,
    order_next: u16 = no_inflight_send,
    /// Free-list links reuse tail padding. `free_head` is meaningful only on
    /// the active order head; `free_next` is meaningful only when packet_id=0.
    free_head: u16 = no_inflight_send,
    free_next: u16 = no_inflight_send,
};

const PendingQoS0 = struct {
    publish: OwnedPublish,
    /// Generation of the Network Connection that owns the serialized write.
    /// Completion from that writer remains valid across a ClientID takeover,
    /// while unrelated stale handles cannot consume a newer pending message.
    generation: u64,
};

const Session = struct {
    generation: u64,
    route_id: u64,
    client_id: []u8,
    connected: bool,
    expiry_interval: u32,
    expires_at_ns: ?i96,
    subscriptions: std.ArrayList(?OwnedSubscription) = .empty,
    subscription_count: usize = 0,
    queued: std.ArrayList(?OwnedPublish) = .empty,
    /// First queue slot that can still contain a publication. Draining leaves
    /// null tombstones so snapshot/inflight views remain stable; retaining a
    /// cursor prevents every outgoing packet from rescanning the consumed
    /// prefix. The storage is reset as soon as the logical queue is empty.
    queued_head: usize = 0,
    queued_count: usize = 0,
    queued_payload_bytes: usize = 0,
    inflight: std.ArrayList(Inflight) = .empty,
    inflight_count: usize = 0,
    inflight_payload_bytes: usize = 0,
    /// Conservative earliest expiry across queued and expirable inflight
    /// publications. A stale early value is safe and repaired by the next due
    /// scan; the sentinel lets the ordinary no-expiry path avoid both scans.
    next_publish_expiry_ns: i96 = no_publish_expiry,
    /// Owns one QoS 0 publication between queue selection and completion of
    /// the corresponding socket write. No MQTT acknowledgement can own QoS 0,
    /// so this transient slot keeps borrowed transmission slices valid and
    /// lets a failed write return the message to the durable queue.
    pending_qos0: ?PendingQoS0 = null,
    packet_index: identifiers.Index = .{},
    incoming_qos2: std.AutoHashMapUnmanaged(u16, IncomingQoS2) = .empty,
    next_packet_id: u16 = 1,
    /// Sent PUBLISH packets that still consume the peer's Receive Maximum.
    /// PUBREL and packets awaiting their first/retry send do not count.
    sent_publish_count: u16 = 0,
    /// Earliest point in the stable inflight order that may need transmission.
    next_inflight_send: u16 = no_inflight_send,
    inflight_order_head: u16 = no_inflight_send,
    allocation_bytes: usize,

    fn deinit(
        self: *Session,
        allocator: std.mem.Allocator,
        cache: *StorageCache,
    ) void {
        for (self.subscriptions.items) |*maybe_subscription| {
            if (maybe_subscription.*) |*subscription| {
                subscription.deinit(allocator);
            }
        }
        self.subscriptions.deinit(allocator);
        for (self.queued.items) |*maybe_publish| {
            if (maybe_publish.*) |*publish| {
                publish.deinit(allocator, cache);
            }
        }
        self.queued.deinit(allocator);
        for (self.inflight.items) |*inflight| {
            if (inflight.packet_id == 0) continue;
            inflight.publish.deinit(allocator, cache);
        }
        self.inflight.deinit(allocator);
        if (self.pending_qos0) |*pending| {
            pending.publish.deinit(allocator, cache);
        }
        self.packet_index.deinit(allocator);
        self.incoming_qos2.deinit(allocator);
        allocator.free(self.client_id);
        self.* = undefined;
    }
};

fn noteInflightSelected(session: *Session, inflight: *Inflight) void {
    std.debug.assert(inflight.needs_send);
    inflight.needs_send = false;
    if (inflight.state == .await_pubcomp) return;
    std.debug.assert(session.sent_publish_count < std.math.maxInt(u16));
    session.sent_publish_count += 1;
}

fn releasePublishWindow(session: *Session, inflight: *const Inflight) void {
    if (inflight.state != .await_pubcomp and !inflight.needs_send) {
        std.debug.assert(session.sent_publish_count != 0);
        session.sent_publish_count -= 1;
    }
}

fn retainInflightForLater(session: *Session, index: usize) void {
    std.debug.assert(index < no_inflight_send);
    if (session.next_inflight_send == no_inflight_send) {
        session.next_inflight_send = @intCast(index);
    }
}

fn appendInflightAssumeCapacity(
    session: *Session,
    value: Inflight,
) usize {
    if (session.inflight_count != 0) {
        const order_head = &session.inflight.items[session.inflight_order_head];
        const free_index = order_head.free_head;
        if (free_index != no_inflight_send) {
            order_head.free_head = session.inflight.items[free_index].free_next;
            session.inflight.items[free_index] = value;
            return free_index;
        }
    } else {
        std.debug.assert(session.inflight.items.len == 0);
    }
    session.inflight.appendAssumeCapacity(value);
    return session.inflight.items.len - 1;
}

fn noteInflightAdded(
    session: *Session,
    index: usize,
    inflight: *Inflight,
) void {
    std.debug.assert(index < no_inflight_send);
    std.debug.assert(inflight.order_previous == no_inflight_send);
    std.debug.assert(inflight.order_next == no_inflight_send);
    const compact_index: u16 = @intCast(index);
    if (session.inflight_order_head == no_inflight_send) {
        inflight.order_previous = compact_index;
        inflight.order_next = compact_index;
        session.inflight_order_head = compact_index;
    } else {
        const head = session.inflight_order_head;
        const tail = session.inflight.items[head].order_previous;
        inflight.order_previous = tail;
        inflight.order_next = head;
        session.inflight.items[tail].order_next = compact_index;
        session.inflight.items[head].order_previous = compact_index;
    }

    if (inflight.needs_send) {
        if (session.next_inflight_send == no_inflight_send) {
            session.next_inflight_send = compact_index;
        }
        return;
    }
    std.debug.assert(inflight.state != .await_pubcomp);
    std.debug.assert(session.sent_publish_count < std.math.maxInt(u16));
    session.sent_publish_count += 1;
}

fn noteInflightNeedsSend(
    session: *Session,
    index: usize,
    inflight: *Inflight,
) void {
    if (!inflight.needs_send) {
        const had_pending = session.next_inflight_send != no_inflight_send;
        releasePublishWindow(session, inflight);
        inflight.needs_send = true;
        session.next_inflight_send = if (had_pending)
            session.inflight_order_head
        else
            @intCast(index);
    } else if (session.next_inflight_send == no_inflight_send) {
        session.next_inflight_send = session.inflight_order_head;
    }
}

fn repairInflightSendCursor(session: *Session) void {
    session.next_inflight_send = no_inflight_send;
    var index = session.inflight_order_head;
    var remaining = session.inflight_count;
    while (remaining != 0) : (remaining -= 1) {
        const inflight = session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        if (inflight.needs_send) {
            session.next_inflight_send = index;
            return;
        }
        index = inflight.order_next;
    }
}

fn assertInflightSendCursor(session: Session) void {
    if (!std.debug.runtime_safety) return;
    var pending_count: usize = 0;
    var order_count: usize = 0;
    if (session.inflight_count == 0) {
        std.debug.assert(session.inflight_order_head == no_inflight_send);
    } else {
        std.debug.assert(session.inflight_order_head != no_inflight_send);
    }
    var cursor_reached = session.next_inflight_send == no_inflight_send;
    var index: u16 = session.inflight_order_head;
    var previous = if (index == no_inflight_send)
        no_inflight_send
    else
        session.inflight.items[index].order_previous;
    const expected_tail = previous;
    while (order_count < session.inflight_count) {
        std.debug.assert(index < session.inflight.items.len);
        const inflight = session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        std.debug.assert(inflight.order_previous == previous);
        if (index == session.next_inflight_send) cursor_reached = true;
        if (inflight.needs_send) {
            pending_count += 1;
            std.debug.assert(cursor_reached);
        }
        previous = index;
        index = inflight.order_next;
        order_count += 1;
        std.debug.assert(order_count <= session.inflight_count);
    }
    std.debug.assert(order_count == session.inflight_count);
    std.debug.assert(previous == expected_tail);
    std.debug.assert(
        session.inflight_count == 0 or
            index == session.inflight_order_head,
    );
    std.debug.assert(
        (pending_count == 0) ==
            (session.next_inflight_send == no_inflight_send),
    );
    std.debug.assert(
        session.next_inflight_send == no_inflight_send or cursor_reached,
    );

    var active_slots: usize = 0;
    for (session.inflight.items) |inflight| {
        active_slots += @intFromBool(inflight.packet_id != 0);
    }
    std.debug.assert(active_slots == session.inflight_count);
    if (session.inflight_count == 0) {
        std.debug.assert(session.inflight.items.len == 0);
        return;
    }
    var free_count: usize = 0;
    var free_index = session.inflight.items[
        session.inflight_order_head
    ].free_head;
    while (free_index != no_inflight_send) {
        std.debug.assert(free_index < session.inflight.items.len);
        const free_slot = session.inflight.items[free_index];
        std.debug.assert(free_slot.packet_id == 0);
        free_index = free_slot.free_next;
        free_count += 1;
        std.debug.assert(free_count <= session.inflight.items.len);
    }
    std.debug.assert(
        free_count == session.inflight.items.len - session.inflight_count,
    );
}

pub const Store = struct {
    allocator: std.mem.Allocator,
    options: Options,
    sessions: std.ArrayList(?Session) = .empty,
    client_index: std.StringHashMapUnmanaged(usize) = .empty,
    route_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    session_count: usize = 0,
    persistent_session_count: usize = 0,
    total_bytes: usize = 0,
    publish_wire_cache: StorageCache,
    next_generation: u64 = 1,
    next_route_id: u64 = 1,
    /// Conservative lower bound for the next offline Session expiry.
    ///
    /// Disconnect can lower this value in O(1). Reconnect/removal may leave a
    /// stale early value, which is safe: the next due check rescans and repairs
    /// it. This keeps the normal broker publish path allocation-free.
    next_expiry_ns: ?i96 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) Store {
        return .{
            .allocator = allocator,
            .options = options,
            .publish_wire_cache = .init(allocator, options.max_sessions),
        };
    }

    pub fn deinit(self: *Store) void {
        for (self.sessions.items) |*maybe_session| {
            if (maybe_session.*) |*session| {
                session.deinit(
                    self.allocator,
                    &self.publish_wire_cache,
                );
            }
        }
        self.sessions.deinit(self.allocator);
        self.client_index.deinit(self.allocator);
        self.route_index.deinit(self.allocator);
        self.publish_wire_cache.deinit();
        self.* = undefined;
    }

    pub fn count(self: Store) usize {
        return self.session_count;
    }

    pub fn persistentCount(self: Store) usize {
        return self.persistent_session_count;
    }

    pub fn totalBytes(self: Store) usize {
        return self.total_bytes;
    }

    pub fn aggregateStats(self: Store) StoreStats {
        var result = StoreStats{
            .session_count = self.session_count,
            .connected_count = 0,
            .disconnected_count = 0,
            .subscription_count = 0,
            .queued_count = 0,
            .queued_payload_bytes = 0,
            .inflight_count = 0,
            .outgoing_publish_window_used = 0,
            .inflight_payload_bytes = 0,
            .incoming_qos2_count = 0,
            .owned_wire_bytes = self.total_bytes,
        };
        for (self.sessions.items) |maybe_session| {
            const session = maybe_session orelse continue;
            assertInflightSendCursor(session);
            if (session.connected) {
                result.connected_count +|= 1;
            } else {
                result.disconnected_count +|= 1;
            }
            result.subscription_count +|= session.subscription_count;
            result.queued_count +|= session.queued_count +|
                @intFromBool(session.pending_qos0 != null);
            result.queued_payload_bytes +|= session.queued_payload_bytes +|
                if (session.pending_qos0) |pending|
                    pending.publish.payload.len
                else
                    0;
            result.inflight_count +|= session.inflight_count;
            result.outgoing_publish_window_used +|=
                session.sent_publish_count;
            result.inflight_payload_bytes +|=
                session.inflight_payload_bytes;
            result.incoming_qos2_count +|= session.incoming_qos2.count();
        }
        std.debug.assert(
            result.connected_count + result.disconnected_count ==
                result.session_count,
        );
        return result;
    }

    /// Encode durable Session State without exposing private slot layouts.
    ///
    /// Connected sessions are serialized as offline: network descriptors and
    /// short-lived generation capabilities never cross a process boundary.
    /// Outgoing inflight messages are restored with DUP/retransmit semantics.
    pub fn writeSnapshot(
        self: *Store,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        now: std.Io.Timestamp,
    ) (Error || persistence.Error)!void {
        var snapshot_count: u32 = 0;
        for (self.sessions.items) |maybe_session| {
            const session = maybe_session orelse continue;
            if (session.expiry_interval == 0 or
                self.isExpired(session, now))
            {
                continue;
            }
            snapshot_count = std.math.add(u32, snapshot_count, 1) catch
                return error.SnapshotLimitExceeded;
        }
        try persistence.appendInt(out, allocator, u32, snapshot_count);
        for (self.sessions.items) |maybe_session| {
            const session = maybe_session orelse continue;
            if (session.expiry_interval == 0 or
                self.isExpired(session, now))
            {
                continue;
            }
            try persistence.appendBlob(
                out,
                allocator,
                session.client_id,
            );
            try persistence.appendInt(
                out,
                allocator,
                u64,
                session.route_id,
            );
            try persistence.appendInt(
                out,
                allocator,
                u32,
                session.expiry_interval,
            );
            try persistence.appendBool(
                out,
                allocator,
                session.connected,
            );
            try persistence.appendOptionalInt(
                out,
                allocator,
                u64,
                if (session.connected)
                    null
                else
                    sessionRemainingExpiryNs(session, now.nanoseconds),
            );
            try persistence.appendInt(
                out,
                allocator,
                u16,
                session.next_packet_id,
            );
            // A live checkpoint can race with the network write only at the
            // broker state barrier. Once selected, pending QoS 0 is no longer
            // in `queued`, but it is still durable until the writer commits.
            // Serialize it ahead of the remaining queue so a crash before the
            // commit cannot silently lose the opt-in message.
            const pending_qos0 = if (session.pending_qos0) |pending|
                pending.publish
            else
                null;

            try persistence.appendInt(
                out,
                allocator,
                u32,
                try snapshotCount(session.subscription_count),
            );
            for (session.subscriptions.items) |maybe_subscription| {
                const subscription = maybe_subscription orelse continue;
                try writeSubscription(
                    out,
                    allocator,
                    subscription,
                );
            }

            var queued_count: u32 = @intFromBool(
                if (pending_qos0) |publish|
                    publishRemainingExpiryNs(
                        publish,
                        now.nanoseconds,
                    ) != 0
                else
                    false,
            );
            for (session.queued.items[session.queued_head..]) |maybe_publish| {
                const publish = maybe_publish orelse continue;
                if (publishRemainingExpiryNs(
                    publish,
                    now.nanoseconds,
                ) == 0) continue;
                queued_count = std.math.add(u32, queued_count, 1) catch
                    return error.SnapshotLimitExceeded;
            }
            try persistence.appendInt(
                out,
                allocator,
                u32,
                queued_count,
            );
            if (pending_qos0) |publish| {
                const remaining_ns = publishRemainingExpiryNs(
                    publish,
                    now.nanoseconds,
                );
                if (remaining_ns != 0) {
                    try writePublishSnapshot(
                        out,
                        allocator,
                        publish,
                        remaining_ns,
                    );
                }
            }
            for (session.queued.items[session.queued_head..]) |maybe_publish| {
                const publish = maybe_publish orelse continue;
                const remaining_ns = publishRemainingExpiryNs(
                    publish,
                    now.nanoseconds,
                );
                if (remaining_ns == 0) continue;
                try writePublishSnapshot(
                    out,
                    allocator,
                    publish,
                    remaining_ns,
                );
            }

            var inflight_count: u32 = 0;
            for (session.inflight.items) |inflight| {
                if (inflight.packet_id == 0) continue;
                if (inflight.state != .await_pubcomp and
                    publishRemainingExpiryNs(
                        inflight.publish,
                        now.nanoseconds,
                    ) == 0)
                {
                    continue;
                }
                inflight_count = std.math.add(
                    u32,
                    inflight_count,
                    1,
                ) catch return error.SnapshotLimitExceeded;
            }
            try persistence.appendInt(
                out,
                allocator,
                u32,
                inflight_count,
            );
            var ordered_inflight_index = session.inflight_order_head;
            var ordered_inflight_remaining = session.inflight_count;
            while (ordered_inflight_remaining != 0) : (ordered_inflight_remaining -= 1) {
                const inflight = session.inflight.items[ordered_inflight_index];
                ordered_inflight_index = inflight.order_next;
                const remaining_ns = publishRemainingExpiryNs(
                    inflight.publish,
                    now.nanoseconds,
                );
                if (inflight.state != .await_pubcomp and
                    remaining_ns == 0)
                {
                    continue;
                }
                try persistence.appendInt(
                    out,
                    allocator,
                    u16,
                    inflight.packet_id,
                );
                try persistence.appendInt(
                    out,
                    allocator,
                    u8,
                    @intFromEnum(inflight.state),
                );
                try writePublishSnapshot(
                    out,
                    allocator,
                    inflight.publish,
                    // Once PUBREC has been accepted, MQTT requires the PUBREL /
                    // PUBCOMP handshake to survive Message Expiry. Mark that
                    // record as unbounded; its Application Message is no longer
                    // delivered again, but the transaction must complete.
                    if (inflight.state == .await_pubcomp)
                        null
                    else
                        remaining_ns,
                );
            }
        }
    }

    pub fn restoreSnapshot(
        self: *Store,
        cursor: *persistence.Cursor,
        restore_now: std.Io.Timestamp,
        downtime_ns: i96,
    ) (Error || persistence.Error)!void {
        const snapshot_count = try cursor.readInt(u32);
        if (snapshot_count > self.options.max_sessions) {
            return error.SessionLimitExceeded;
        }
        for (0..snapshot_count) |_| {
            try self.restoreSession(
                cursor,
                restore_now,
                downtime_ns,
            );
        }
    }

    pub fn swap(self: *Store, other: *Store) void {
        const value = self.*;
        self.* = other.*;
        other.* = value;
    }

    fn restoreSession(
        self: *Store,
        cursor: *persistence.Cursor,
        restore_now: std.Io.Timestamp,
        downtime_ns: i96,
    ) (Error || persistence.Error)!void {
        const client_id = try cursor.readBlob();
        if (self.client_index.contains(client_id)) {
            return error.CorruptSnapshot;
        }
        const route_id = try cursor.readInt(u64);
        if (route_id == 0 or route_id >= (@as(u64, 1) << 63) or
            self.route_index.contains(route_id))
        {
            return error.CorruptSnapshot;
        }
        const expiry_interval = try cursor.readInt(u32);
        if (expiry_interval == 0) return error.CorruptSnapshot;
        const was_connected = try cursor.readBool();
        const saved_expiry_ns = try cursor.readOptionalInt(u64);
        if ((was_connected and saved_expiry_ns != null) or
            (!was_connected and
                (expiry_interval == std.math.maxInt(u32)) !=
                    (saved_expiry_ns == null)))
        {
            return error.CorruptSnapshot;
        }
        const remaining_expiry_ns = if (was_connected)
            if (expiry_interval == std.math.maxInt(u32))
                null
            else
                remainingAfterDowntimeNs(
                    @as(u64, expiry_interval) * std.time.ns_per_s,
                    downtime_ns,
                )
        else
            remainingAfterDowntimeNs(saved_expiry_ns, downtime_ns);
        if (remaining_expiry_ns == 0) {
            return self.skipExpiredSession(cursor);
        }
        const next_packet_id = try cursor.readInt(u16);
        if (next_packet_id == 0) return error.CorruptSnapshot;

        if (self.session_count >= self.options.max_sessions) {
            return error.SessionLimitExceeded;
        }
        const client_owned = try self.allocator.dupe(u8, client_id);
        var client_owned_by_local = true;
        errdefer if (client_owned_by_local) {
            self.allocator.free(client_owned);
        };
        if (client_owned.len > self.options.max_session_bytes or
            client_owned.len > self.options.max_total_bytes -|
                self.total_bytes)
        {
            return error.SessionByteLimitExceeded;
        }
        try self.client_index.ensureUnusedCapacity(self.allocator, 1);
        try self.route_index.ensureUnusedCapacity(self.allocator, 1);
        var appended_slot = false;
        const index = for (self.sessions.items, 0..) |
            maybe_session,
            candidate,
        | {
            if (maybe_session == null) break candidate;
        } else blk: {
            try self.sessions.append(self.allocator, null);
            appended_slot = true;
            break :blk self.sessions.items.len - 1;
        };
        errdefer if (appended_slot and
            self.sessions.items[index] == null)
        {
            _ = self.sessions.pop();
        };
        const generation = self.nextGeneration();
        self.sessions.items[index] = .{
            .generation = generation,
            .route_id = route_id,
            .client_id = client_owned,
            .connected = false,
            .expiry_interval = expiry_interval,
            .expires_at_ns = if (remaining_expiry_ns) |remaining|
                restore_now.nanoseconds + @as(i96, remaining)
            else
                null,
            .next_packet_id = next_packet_id,
            .allocation_bytes = client_owned.len,
        };
        errdefer self.removeAt(index);
        client_owned_by_local = false;
        self.client_index.putAssumeCapacityNoClobber(client_owned, index);
        self.route_index.putAssumeCapacityNoClobber(route_id, index);
        self.session_count += 1;
        self.persistent_session_count += 1;
        self.total_bytes += client_owned.len;
        self.next_route_id = @max(self.next_route_id, route_id +| 1);
        if (self.next_route_id == 0 or
            self.next_route_id >= (@as(u64, 1) << 63))
        {
            self.next_route_id = 1;
        }
        const session = &self.sessions.items[index].?;

        const subscription_count = try cursor.readInt(u32);
        if (subscription_count >
            self.options.max_subscriptions_per_session)
        {
            return error.SubscriptionLimitExceeded;
        }
        for (0..subscription_count) |_| {
            const subscription = try readSubscription(cursor);
            _ = try self.setSubscription(
                .{ .index = index, .generation = generation },
                subscription.subscription,
                subscription.identifier,
            );
        }

        const queued_count = try cursor.readInt(u32);
        if (queued_count > self.options.max_queued_per_session) {
            return error.QueueFull;
        }
        for (0..queued_count) |_| {
            var restored = try readPublishSnapshot(
                self.allocator,
                &self.publish_wire_cache,
                cursor,
                restore_now.nanoseconds,
                downtime_ns,
                false,
            );
            if (restored) |*publish| {
                errdefer publish.deinit(
                    self.allocator,
                    &self.publish_wire_cache,
                );
                if (queuedPayloadLimitReached(
                    self.options,
                    session.queued_payload_bytes,
                )) {
                    return error.QueueFull;
                }
                try self.ensureBytes(session, publish.allocation_bytes);
                const queued_payload_bytes = std.math.add(
                    usize,
                    session.queued_payload_bytes,
                    publish.payload.len,
                ) catch return error.SessionByteLimitExceeded;
                try session.queued.append(self.allocator, publish.*);
                session.queued_count += 1;
                session.queued_payload_bytes = queued_payload_bytes;
                session.allocation_bytes += publish.allocation_bytes;
                self.total_bytes += publish.allocation_bytes;
                notePublishExpiry(session, publish.*);
                restored = null;
            }
        }

        const inflight_count = try cursor.readInt(u32);
        if (inflight_count > std.math.maxInt(u16)) {
            return error.InflightFull;
        }
        try session.packet_index.ensureUnusedCapacity(
            self.allocator,
            @intCast(inflight_count),
        );
        try session.inflight.ensureUnusedCapacity(
            self.allocator,
            inflight_count,
        );
        for (0..inflight_count) |_| {
            const packet_id = try cursor.readInt(u16);
            const state = std.enums.fromInt(
                InflightState,
                try cursor.readInt(u8),
            ) orelse return error.CorruptSnapshot;
            var publish = (try readPublishSnapshot(
                self.allocator,
                &self.publish_wire_cache,
                cursor,
                restore_now.nanoseconds,
                downtime_ns,
                state == .await_pubcomp,
            )) orelse {
                continue;
            };
            errdefer publish.deinit(
                self.allocator,
                &self.publish_wire_cache,
            );
            if (packet_id == 0 or
                session.packet_index.contains(packet_id))
            {
                return error.CorruptSnapshot;
            }
            if (inflightPayloadLimitReached(
                self.options,
                session.inflight_payload_bytes,
            )) {
                return error.InflightFull;
            }
            const inflight_payload_bytes = std.math.add(
                usize,
                session.inflight_payload_bytes,
                publish.payload.len,
            ) catch return error.SessionByteLimitExceeded;
            try self.ensureBytes(session, publish.allocation_bytes);
            const inflight_index = appendInflightAssumeCapacity(
                session,
                .{
                    .publish = publish,
                    .packet_id = packet_id,
                    .state = state,
                    .needs_send = true,
                    .retransmission = state != .await_pubcomp,
                    .pubrel_blocked = false,
                },
            );
            session.packet_index.putAssumeCapacityNoClobber(
                packet_id,
                inflight_index,
            );
            session.inflight_count += 1;
            noteInflightAdded(
                session,
                inflight_index,
                &session.inflight.items[inflight_index],
            );
            session.inflight_payload_bytes = inflight_payload_bytes;
            session.allocation_bytes += publish.allocation_bytes;
            self.total_bytes += publish.allocation_bytes;
            if (state != .await_pubcomp) {
                notePublishExpiry(session, publish);
            }
            publish = undefined;
        }

        if (session.expires_at_ns) |deadline| {
            if (self.next_expiry_ns == null or
                deadline < self.next_expiry_ns.?)
            {
                self.next_expiry_ns = deadline;
            }
        }
    }

    fn skipExpiredSession(
        _: *Store,
        cursor: *persistence.Cursor,
    ) persistence.Error!void {
        _ = try cursor.readInt(u16); // next packet identifier
        const subscription_count = try cursor.readInt(u32);
        for (0..subscription_count) |_| {
            _ = try cursor.readBlob();
            _ = try cursor.readInt(u8);
            _ = try cursor.readBool();
            _ = try cursor.readBool();
            _ = try cursor.readInt(u8);
            _ = try cursor.readOptionalInt(u32);
        }
        const queued_count = try cursor.readInt(u32);
        for (0..queued_count) |_| try skipPublishSnapshot(cursor);
        const inflight_count = try cursor.readInt(u32);
        for (0..inflight_count) |_| {
            _ = try cursor.readInt(u16);
            _ = try cursor.readInt(u8);
            try skipPublishSnapshot(cursor);
        }
    }

    pub fn containsClientId(
        self: Store,
        client_id: []const u8,
    ) bool {
        return self.client_index.contains(client_id);
    }

    pub fn expiryForConnect(
        protocol: mqtt.ProtocolVersion,
        clean_start: bool,
        properties: []const mqtt.Property,
    ) u32 {
        return switch (protocol) {
            .v5 => mqtt.sessionExpiryInterval(properties) orelse 0,
            // Pre-v5 CleanSession=0 has no timer and therefore persists
            // until an administrative action or a later clean connection.
            .v3_1, .v3_1_1 => if (clean_start)
                0
            else
                std.math.maxInt(u32),
        };
    }

    pub fn open(
        self: *Store,
        client_id: []const u8,
        clean_start: bool,
        expiry_interval: u32,
        now: std.Io.Timestamp,
    ) Error!OpenResult {
        var prepared = try self.prepareOpen(client_id, clean_start, expiry_interval, now);
        defer prepared.deinit();
        return self.commitOpen(&prepared);
    }

    pub fn prepareOpen(
        self: *Store,
        client_id: []const u8,
        clean_start: bool,
        expiry_interval: u32,
        now: std.Io.Timestamp,
    ) Error!PreparedOpen {
        if (client_id.len == 0 and !clean_start) {
            return error.InvalidClientId;
        }
        var replaced_connection = false;
        var replacement_index: ?usize = null;
        if (self.client_index.get(client_id)) |index| {
            if (self.isExpired(self.sessions.items[index].?, now)) {
                replacement_index = index;
            }
        }
        if (clean_start) {
            if (self.client_index.get(client_id)) |index| {
                replaced_connection = self.sessions.items[index].?.connected;
                replacement_index = index;
            }
        } else if (replacement_index == null) if (self.client_index.get(client_id)) |index| {
            const session = &self.sessions.items[index].?;
            replaced_connection = session.connected;
            if (session.expiry_interval == 0) {
                // A live clean/transient connection owns Session State only
                // until its Network Connection ends. ClientID takeover ends
                // that connection, so Clean Start=0 cannot resume this state
                // or report Session Present. Keep `replaced_connection` set so
                // the broker still sends the required takeover shutdown.
                replacement_index = index;
            } else {
                return .{
                    .store = self,
                    .index = index,
                    .previous = .{ .index = index, .generation = session.generation },
                    .expiry_interval = expiry_interval,
                    .session_present = true,
                    .replaced_connection = replaced_connection,
                };
            }
        };

        const final_count = try open_admission.finalCount(self.session_count, replacement_index != null, self.options.max_sessions);
        const replacement_bytes = if (replacement_index) |index| self.sessions.items[index].?.allocation_bytes else 0;
        const client_owned = try open_admission.prepareClientId(self.allocator, self.options, client_id, self.total_bytes, replacement_bytes);
        errdefer self.allocator.free(client_owned);
        const index_capacity = std.math.cast(u32, final_count) orelse return error.SessionLimitExceeded;
        try self.client_index.ensureTotalCapacity(self.allocator, index_capacity);
        try self.route_index.ensureTotalCapacity(self.allocator, index_capacity);
        var appended_slot = false;
        const index = replacement_index orelse for (self.sessions.items, 0..) |
            maybe_session,
            candidate,
        | {
            if (maybe_session == null) break candidate;
        } else blk: {
            try self.sessions.append(self.allocator, null);
            appended_slot = true;
            break :blk self.sessions.items.len - 1;
        };
        errdefer if (appended_slot and
            self.sessions.items[index] == null)
        {
            _ = self.sessions.pop();
        };
        return .{
            .store = self,
            .index = index,
            .previous = if (replacement_index != null) .{ .index = index, .generation = self.sessions.items[index].?.generation } else null,
            .client_id = client_owned,
            .expiry_interval = expiry_interval,
            .session_present = false,
            .replaced_connection = replaced_connection,
            .appended_slot = appended_slot,
        };
    }

    /// Commit a prepared open under the same Store serialization boundary.
    /// Every admission allocation and limit check has already succeeded.
    pub fn commitOpen(self: *Store, prepared: *PreparedOpen) OpenResult {
        std.debug.assert(prepared.store == self and !prepared.committed);
        const index = prepared.index;
        if (prepared.previous) |previous| {
            std.debug.assert(self.sessions.items[index].?.generation == previous.generation);
        } else {
            std.debug.assert(self.sessions.items[index] == null);
        }
        if (prepared.session_present) {
            const session = &self.sessions.items[index].?;
            const generation = self.nextGeneration();
            // Every resumed/takeover Network Connection gets a fresh
            // handle. This immediately invalidates the old connection's
            // capability to mutate the shared Session after takeover.
            session.generation = generation;
            session.connected = true;
            if (prepared.expiry_interval == 0) {
                self.persistent_session_count -= 1;
            }
            session.expiry_interval = prepared.expiry_interval;
            session.expires_at_ns = null;
            session.next_inflight_send = no_inflight_send;
            for (session.inflight.items, 0..) |*inflight, inflight_index| {
                if (inflight.packet_id == 0) continue;
                noteInflightNeedsSend(
                    session,
                    inflight_index,
                    inflight,
                );
                inflight.retransmission = true;
            }
            std.debug.assert(session.sent_publish_count == 0);
            session.sent_publish_count = 0;
            prepared.committed = true;
            return .{
                .handle = .{
                    .index = index,
                    .generation = session.generation,
                },
                .route_id = session.route_id,
                .session_present = true,
                .replaced_connection = prepared.replaced_connection,
            };
        }
        const client_owned = prepared.client_id.?;
        const generation = self.nextGeneration();
        const route_id = self.nextRouteId();
        // Every fallible admission step completed. Retire the old state only
        // at this commit point and reuse its already-reserved table slot.
        if (prepared.previous != null) self.removeAt(index);
        self.sessions.items[index] = .{
            .generation = generation,
            .route_id = route_id,
            .client_id = client_owned,
            .connected = true,
            .expiry_interval = prepared.expiry_interval,
            .expires_at_ns = null,
            .allocation_bytes = client_owned.len,
        };
        self.client_index.putAssumeCapacityNoClobber(
            client_owned,
            index,
        );
        self.route_index.putAssumeCapacityNoClobber(route_id, index);
        self.session_count += 1;
        self.persistent_session_count += @intFromBool(prepared.expiry_interval != 0);
        self.total_bytes += client_owned.len;
        prepared.client_id = null;
        prepared.committed = true;
        return .{
            .handle = .{ .index = index, .generation = generation },
            .route_id = route_id,
            .session_present = false,
            .replaced_connection = prepared.replaced_connection,
        };
    }

    pub fn openConnect(
        self: *Store,
        connect: mqtt.Connect,
        now: std.Io.Timestamp,
    ) Error!OpenResult {
        return self.open(
            connect.client_id,
            connect.clean_start,
            expiryForConnect(
                connect.protocol,
                connect.clean_start,
                connect.properties,
            ),
            now,
        );
    }

    /// Validate a DISCONNECT Session Expiry override without mutating Session
    /// State. Protocol owners call this before applying coupled Will and
    /// Session transitions.
    pub fn validateDisconnect(
        self: *Store,
        handle: Handle,
        expiry_override: ?u32,
    ) Error!void {
        const session = try self.getSession(handle);
        try mqtt.validateDisconnectSessionExpiry(
            session.expiry_interval,
            expiry_override,
        );
    }

    pub fn disconnect(
        self: *Store,
        handle: Handle,
        expiry_override: ?u32,
        now: std.Io.Timestamp,
    ) Error!void {
        try self.validateDisconnect(handle, expiry_override);
        const session = try self.getSession(handle);
        if (expiry_override) |new_expiry| {
            if (session.expiry_interval != 0 and new_expiry == 0) {
                self.persistent_session_count -= 1;
            } else if (session.expiry_interval == 0 and new_expiry != 0) {
                self.persistent_session_count += 1;
            }
            session.expiry_interval = new_expiry;
        }
        if (session.expiry_interval == 0) {
            self.removeAt(handle.index);
            return;
        }
        // A QoS 0 packet selected for a socket write has no retransmission or
        // acknowledgement state. If the connection ends before the writer
        // reports success, put it back at the front of the durable queue so
        // the opt-in offline-QoS0 policy does not silently lose it.
        rollbackPendingQos0(session, handle.generation);
        session.connected = false;
        session.expires_at_ns = expiryDeadline(
            now.nanoseconds,
            session.expiry_interval,
        );
        if (session.expires_at_ns) |deadline| {
            if (self.next_expiry_ns == null or
                deadline < self.next_expiry_ns.?)
            {
                self.next_expiry_ns = deadline;
            }
        }
        session.next_inflight_send = no_inflight_send;
        for (session.inflight.items, 0..) |*inflight, index| {
            if (inflight.packet_id == 0) continue;
            noteInflightNeedsSend(session, index, inflight);
            inflight.retransmission = true;
        }
        std.debug.assert(session.sent_publish_count == 0);
        session.sent_publish_count = 0;
    }

    pub fn disconnectPacket(
        self: *Store,
        handle: Handle,
        protocol: mqtt.ProtocolVersion,
        packet: mqtt.Disconnect,
        now: std.Io.Timestamp,
    ) Error!void {
        return self.disconnect(
            handle,
            if (protocol == .v5)
                mqtt.sessionExpiryInterval(packet.properties)
            else
                null,
            now,
        );
    }

    pub fn discard(self: *Store, client_id: []const u8) bool {
        const index = self.client_index.get(client_id) orelse return false;
        self.removeAt(index);
        return true;
    }

    /// Discard exactly the generation represented by `handle`.
    ///
    /// Broker accept rollback uses this after Session State was opened but
    /// CONNACK could not be written. A stale takeover handle must not remove
    /// the newer Session generation.
    pub fn discardHandle(
        self: *Store,
        handle: Handle,
    ) Error!void {
        _ = try self.getSession(handle);
        self.removeAt(handle.index);
    }

    pub fn pruneExpired(
        self: *Store,
        now: std.Io.Timestamp,
    ) usize {
        return self.pruneExpiredWithContext(
            now,
            {},
            struct {
                fn removed(_: void, _: u64) void {}
            }.removed,
        );
    }

    /// Remove every due offline Session and report its stable route identity.
    ///
    /// The callback runs synchronously before the next Session is inspected. A
    /// broker can therefore hold its state lock and retire the corresponding
    /// router and QoS records in the same atomic lifecycle transition without
    /// allocating an array proportional to the number of expired Sessions.
    pub fn pruneExpiredWithContext(
        self: *Store,
        now: std.Io.Timestamp,
        context: anytype,
        comptime onExpired: anytype,
    ) usize {
        const due = self.next_expiry_ns orelse return 0;
        if (now.nanoseconds < due) return 0;

        var removed: usize = 0;
        var next_expiry_ns: ?i96 = null;
        var index: usize = 0;
        while (index < self.sessions.items.len) : (index += 1) {
            const session = self.sessions.items[index] orelse continue;
            if (self.isExpired(session, now)) {
                const route_id = session.route_id;
                self.removeAt(index);
                onExpired(context, route_id);
                removed += 1;
            } else if (!session.connected) {
                if (session.expires_at_ns) |deadline| {
                    if (next_expiry_ns == null or
                        deadline < next_expiry_ns.?)
                    {
                        next_expiry_ns = deadline;
                    }
                }
            }
        }
        // Reconnect and explicit removal can leave the cached value earlier
        // than every live deadline. A due pass is the repair point, ensuring
        // the lifecycle driver never spins on a stale timestamp.
        self.next_expiry_ns = next_expiry_ns;
        return removed;
    }

    /// Remove expired Sessions and return their stable route identities.
    ///
    /// Returning route IDs lets broker routing remove corresponding entries
    /// before matching another publication, so an expired shared member cannot
    /// consume one selection and drop that message.
    pub fn pruneExpiredInto(
        self: *Store,
        now: std.Io.Timestamp,
        out: []u64,
    ) Error![]u64 {
        const due = self.next_expiry_ns orelse return out[0..0];
        if (now.nanoseconds < due) return out[0..0];

        var required: usize = 0;
        for (self.sessions.items) |maybe_session| {
            const session = maybe_session orelse continue;
            required += @intFromBool(self.isExpired(session, now));
        }
        if (out.len < required) return error.BufferTooSmall;

        var written: usize = 0;
        var next_expiry_ns: ?i96 = null;
        var index: usize = 0;
        while (index < self.sessions.items.len) : (index += 1) {
            const session = self.sessions.items[index] orelse continue;
            if (self.isExpired(session, now)) {
                out[written] = session.route_id;
                written += 1;
                self.removeAt(index);
            } else if (!session.connected) {
                if (session.expires_at_ns) |deadline| {
                    if (next_expiry_ns == null or
                        deadline < next_expiry_ns.?)
                    {
                        next_expiry_ns = deadline;
                    }
                }
            }
        }
        self.next_expiry_ns = next_expiry_ns;
        return out[0..written];
    }

    /// Return the exact output capacity needed by a due expiry sweep.
    ///
    /// The common not-due path is O(1), allowing broker routing to avoid both a
    /// Session scan and a temporary allocation for every published message.
    pub fn dueExpiryCount(
        self: *Store,
        now: std.Io.Timestamp,
    ) usize {
        const due = self.next_expiry_ns orelse return 0;
        if (now.nanoseconds < due) return 0;
        var due_count: usize = 0;
        var next_expiry_ns: ?i96 = null;
        for (self.sessions.items) |maybe_session| {
            const session = maybe_session orelse continue;
            due_count += @intFromBool(self.isExpired(session, now));
            if (!session.connected) {
                if (session.expires_at_ns) |deadline| {
                    if (deadline > now.nanoseconds and
                        (next_expiry_ns == null or
                            deadline < next_expiry_ns.?))
                    {
                        next_expiry_ns = deadline;
                    }
                }
            }
        }
        // A stale lower bound is common after reconnect or explicit removal.
        // Repair it when no removal sweep will follow this call.
        if (due_count == 0) self.next_expiry_ns = next_expiry_ns;
        return due_count;
    }

    /// Conservative awake-clock deadline for the next offline Session.
    ///
    /// The value can be stale and early after a reconnect or explicit discard,
    /// but is never later than an actual deadline. Callers should run one due
    /// sweep when it fires; the sweep repairs the cached lower bound.
    pub fn nextExpiryDeadline(self: Store) ?std.Io.Timestamp {
        const deadline = self.next_expiry_ns orelse return null;
        return .{ .nanoseconds = deadline };
    }

    /// Check the per-Session count before another subsystem prepares a route.
    /// Existing filters remain replaceable when the count has reached its cap.
    pub fn checkSubscriptionLimit(self: *Store, handle: Handle, topic_filter: []const u8) Error!void {
        const value = try self.getSession(handle);
        if (value.subscription_count < self.options.max_subscriptions_per_session) return;
        for (value.subscriptions.items) |item| {
            if (item) |subscription| {
                if (std.mem.eql(u8, subscription.topic_filter, topic_filter)) return;
            }
        }
        return error.SubscriptionLimitExceeded;
    }

    pub fn setSubscription(
        self: *Store,
        handle: Handle,
        subscription: mqtt.Subscription,
        subscription_identifier: ?usize,
    ) Error!bool {
        try mqtt.validateSubscription(subscription, subscription_identifier);
        const session = try self.getSession(handle);
        for (session.subscriptions.items) |*maybe_subscription| {
            if (maybe_subscription.*) |*existing| {
                if (!std.mem.eql(
                    u8,
                    existing.topic_filter,
                    subscription.topic_filter,
                )) continue;
                existing.qos = subscription.qos;
                existing.no_local = subscription.no_local;
                existing.retain_as_published =
                    subscription.retain_as_published;
                existing.retain_handling = subscription.retain_handling;
                existing.subscription_identifier =
                    subscription_identifier;
                return true;
            }
        }
        if (session.subscription_count >=
            self.options.max_subscriptions_per_session)
        {
            return error.SubscriptionLimitExceeded;
        }
        const filter_owned = try self.allocator.dupe(
            u8,
            subscription.topic_filter,
        );
        errdefer self.allocator.free(filter_owned);
        try self.ensureBytes(session, filter_owned.len);
        _ = try appendOrReuse(
            OwnedSubscription,
            self.allocator,
            &session.subscriptions,
            .{
                .topic_filter = filter_owned,
                .qos = subscription.qos,
                .no_local = subscription.no_local,
                .retain_as_published = subscription.retain_as_published,
                .retain_handling = subscription.retain_handling,
                .subscription_identifier = subscription_identifier,
            },
        );
        session.subscription_count += 1;
        session.allocation_bytes += filter_owned.len;
        self.total_bytes += filter_owned.len;
        return false;
    }

    pub fn removeSubscription(
        self: *Store,
        handle: Handle,
        topic_filter: []const u8,
    ) Error!bool {
        const session = try self.getSession(handle);
        for (session.subscriptions.items, 0..) |
            *maybe_subscription,
            index,
        | {
            if (maybe_subscription.*) |subscription| {
                if (!std.mem.eql(
                    u8,
                    subscription.topic_filter,
                    topic_filter,
                )) continue;
                var removed = session.subscriptions.items[index].?;
                session.subscriptions.items[index] = null;
                const bytes = removed.topic_filter.len;
                removed.deinit(self.allocator);
                session.subscription_count -= 1;
                session.allocation_bytes -= bytes;
                self.total_bytes -= bytes;
                return true;
            }
        }
        return false;
    }

    pub fn subscriptionsInto(
        self: *Store,
        handle: Handle,
        out: []Subscription,
    ) Error![]Subscription {
        const session = try self.getSession(handle);
        if (out.len < session.subscription_count) {
            return error.BufferTooSmall;
        }
        var written: usize = 0;
        for (session.subscriptions.items) |maybe_subscription| {
            const subscription = maybe_subscription orelse continue;
            out[written] = subscription.view();
            written += 1;
        }
        return out[0..written];
    }

    pub fn stats(self: *Store, handle: Handle) Error!Stats {
        const session = try self.getSession(handle);
        assertInflightSendCursor(session.*);
        const pending_qos0 = session.pending_qos0;
        return .{
            .connected = session.connected,
            .expiry_interval = session.expiry_interval,
            .subscription_count = session.subscription_count,
            .queued_count = session.queued_count +|
                @intFromBool(pending_qos0 != null),
            .queued_payload_bytes = session.queued_payload_bytes +|
                if (pending_qos0) |pending|
                    pending.publish.payload.len
                else
                    0,
            .inflight_count = session.inflight_count,
            .outgoing_publish_window_used = session.sent_publish_count,
            .inflight_payload_bytes = session.inflight_payload_bytes,
            .incoming_qos2_count = session.incoming_qos2.count(),
            .owned_wire_bytes = session.allocation_bytes,
        };
    }

    /// Whether this Session retains a transmission that has not yet been
    /// selected by `drainInto`. The currently detached QoS 0 packet is not
    /// counted: its caller already owns that write, while any queued suffix is
    /// included and becomes eligible after the write is committed.
    pub fn hasUnselectedTransmission(
        self: *Store,
        handle: Handle,
    ) Error!bool {
        const session = try self.getSession(handle);
        assertInflightSendCursor(session.*);
        return session.next_inflight_send != no_inflight_send or
            session.queued_count != 0;
    }

    pub fn routeId(
        self: *Store,
        handle: Handle,
    ) Error!u64 {
        return (try self.getSession(handle)).route_id;
    }

    /// Borrow the stable ClientID associated with a Session. The slice remains
    /// valid until that Session is removed or the Store is deinitialized.
    pub fn clientId(
        self: *Store,
        handle: Handle,
    ) Error![]const u8 {
        return (try self.getSession(handle)).client_id;
    }

    pub fn handleForRouteId(
        self: Store,
        route_id: u64,
    ) ?Handle {
        const index = self.route_index.get(route_id) orelse return null;
        const session = self.sessions.items[index] orelse return null;
        return .{
            .index = index,
            .generation = session.generation,
        };
    }

    pub fn routeIdsInto(
        self: Store,
        out: []u64,
    ) Error![]u64 {
        if (out.len < self.session_count) return error.BufferTooSmall;
        var written: usize = 0;
        for (self.sessions.items) |maybe_session| {
            const session = maybe_session orelse continue;
            out[written] = session.route_id;
            written += 1;
        }
        return out[0..written];
    }

    pub fn ownsPacketId(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) bool {
        const session = self.getSession(handle) catch return false;
        return session.packet_index.contains(packet_id);
    }

    /// Borrow the live sender index with a lazy stable descriptor so the view
    /// survives Store moves, table growth and rehashing. Detach before the
    /// Session is deleted or replaced.
    pub fn packetIdentifierOwnership(self: *Store, handle: Handle) Error!PacketIdentifierOwnership {
        const target = try self.getSession(handle);
        return target.packet_index.borrow(self.allocator);
    }

    /// Return a currently usable handle for a known ClientID.
    ///
    /// Offline routing uses this to enqueue publications without opening a
    /// Network Connection. Expired Sessions are removed before returning.
    pub fn find(
        self: *Store,
        client_id: []const u8,
        now: std.Io.Timestamp,
    ) ?Handle {
        const index = self.client_index.get(client_id) orelse return null;
        if (self.isExpired(self.sessions.items[index].?, now)) {
            self.removeAt(index);
            return null;
        }
        const session = &self.sessions.items[index].?;
        return .{ .index = index, .generation = session.generation };
    }

    pub fn enqueuePublish(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
    ) Error!EnqueueResult {
        var ignored_snapshot_change = false;
        return self.enqueuePublishTrackingSnapshotChange(
            handle,
            topic,
            payload,
            options,
            &ignored_snapshot_change,
        );
    }

    /// Like `enqueuePublish`, while also reporting expiry pruning performed
    /// before admission. This lets broker persistence account for a real
    /// deletion even when the new message is expired or the queue is full.
    pub fn enqueuePublishTrackingSnapshotChange(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
        snapshot_changed: *bool,
    ) Error!EnqueueResult {
        try validatePublishForSession(topic, payload, options.properties);
        return self.enqueueValidatedPublishTrackingSnapshotChange(
            handle,
            topic,
            payload,
            options,
            snapshot_changed,
        );
    }

    /// Broker-internal ingress path after the Topic Name, properties, payload
    /// format, and connection-scoped Topic Alias have already been validated.
    pub fn enqueueValidatedPublishTrackingSnapshotChange(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
        snapshot_changed: *bool,
    ) Error!EnqueueResult {
        const session = (try self.prepareValidatedPublishEnqueue(
            handle,
            options,
            snapshot_changed,
        )) orelse return .expired;
        var publish = try clonePublish(
            self.allocator,
            &self.publish_wire_cache,
            topic,
            payload,
            options.qos,
            options.retain,
            options.properties,
            options.now.nanoseconds,
        );
        errdefer publish.deinit(
            self.allocator,
            &self.publish_wire_cache,
        );
        return self.enqueueOwnedPublish(
            session,
            &publish,
            snapshot_changed,
        );
    }

    /// Queue one Session-specific delivery while sharing the immutable Topic
    /// Name and payload owned by a broker Publication. QoS, Retain, properties,
    /// expiry accounting, and byte limits remain independent per Session.
    pub fn enqueueSharedPublicationTrackingSnapshotChange(
        self: *Store,
        handle: Handle,
        publication: *SharedPublication,
        options: EnqueueOptions,
        snapshot_changed: *bool,
    ) Error!EnqueueResult {
        try validatePublishForSession(
            publication.topic(),
            publication.payload(),
            options.properties,
        );
        return self.enqueueValidatedSharedPublicationTrackingSnapshotChange(
            handle,
            publication,
            options,
            snapshot_changed,
        );
    }

    /// Shared-publication counterpart to the validated broker ingress path.
    pub fn enqueueValidatedSharedPublicationTrackingSnapshotChange(
        self: *Store,
        handle: Handle,
        publication: *SharedPublication,
        options: EnqueueOptions,
        snapshot_changed: *bool,
    ) Error!EnqueueResult {
        const session = (try self.prepareValidatedPublishEnqueue(
            handle,
            options,
            snapshot_changed,
        )) orelse return .expired;
        var publish = try clonePublishFromSharedPublication(
            self.allocator,
            publication,
            options.qos,
            options.retain,
            options.properties,
            options.now.nanoseconds,
        );
        errdefer publish.deinit(
            self.allocator,
            &self.publish_wire_cache,
        );
        return self.enqueueOwnedPublish(
            session,
            &publish,
            snapshot_changed,
        );
    }

    fn preparePublishEnqueue(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
        snapshot_changed: *bool,
    ) Error!?*Session {
        try validatePublishForSession(topic, payload, options.properties);
        return self.prepareValidatedPublishEnqueue(
            handle,
            options,
            snapshot_changed,
        );
    }

    fn prepareValidatedPublishEnqueue(
        self: *Store,
        handle: Handle,
        options: EnqueueOptions,
        snapshot_changed: *bool,
    ) Error!?*Session {
        snapshot_changed.* = false;
        const session = try self.getSession(handle);
        // Admission uses the current queue size, as Mosquitto does: the message
        // that reaches/crosses the threshold is retained, while later messages
        // wait for draining or expiry to release byte budget. Prune first so an
        // expired head never blocks a fresh Application Message.
        snapshot_changed.* = self.pruneExpiredPublishes(
            session,
            options.now.nanoseconds,
        );
        // A selected QoS 0 publication still consumes the same logical queue
        // count and payload-byte admission budget until its socket write is
        // committed. This prevents concurrent routing from exceeding the
        // configured queue bound while that element is temporarily detached.
        const pending_qos0_count: usize = @intFromBool(
            session.pending_qos0 != null,
        );
        const pending_qos0_payload_bytes = if (session.pending_qos0) |pending|
            pending.publish.payload.len
        else
            0;
        if (session.queued_count +| pending_qos0_count >=
            self.options.max_queued_per_session)
        {
            return error.QueueFull;
        }
        if (queuedPayloadLimitReached(
            self.options,
            session.queued_payload_bytes +| pending_qos0_payload_bytes,
        )) {
            return error.QueueFull;
        }
        if (mqtt.messageExpiryInterval(options.properties) == 0) {
            return null;
        }
        return session;
    }

    fn enqueueOwnedPublish(
        self: *Store,
        session: *Session,
        publish: *OwnedPublish,
        snapshot_changed: *bool,
    ) Error!EnqueueResult {
        try self.ensureBytes(session, publish.allocation_bytes);
        const queued_payload_bytes = std.math.add(
            usize,
            session.queued_payload_bytes,
            publish.payload.len,
        ) catch return error.SessionByteLimitExceeded;
        if (session.queued_count == 0 and session.pending_qos0 == null) {
            session.queued.items.len = 0;
            session.queued_head = 0;
        } else if (session.pending_qos0 == null and
            session.queued.items.len >=
                self.options.max_queued_per_session)
        {
            compactQueue(session);
        }
        try session.queued.append(self.allocator, publish.*);
        session.queued_count += 1;
        session.queued_payload_bytes = queued_payload_bytes;
        session.allocation_bytes += publish.allocation_bytes;
        self.total_bytes += publish.allocation_bytes;
        notePublishExpiry(session, publish.*);
        publish.* = undefined;
        snapshot_changed.* = true;
        return .queued;
    }

    /// Own one QoS 1/2 Application Message for immediate transmission and
    /// return the exact Packet Identifier assigned to this call. Unlike the
    /// general queue drain, this never selects an older replay or leaves the
    /// new message hidden in the queue when the peer's Receive Maximum is
    /// exhausted.
    pub fn beginImmediatePublish(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
        receive_maximum: u16,
    ) Error!PublishTransmission {
        return self.addImmediatePublish(
            handle,
            topic,
            payload,
            options,
            receive_maximum,
            false,
            null,
        );
    }

    /// Allocate around both durable IDs and borrowed connection commands.
    pub fn beginImmediatePublishAvoiding(self: *Store, handle: Handle, topic: []const u8, payload: []const u8, options: EnqueueOptions, receive_maximum: u16, reserved: PacketIdentifierOwnership) Error!PublishTransmission {
        return self.addImmediatePublish(handle, topic, payload, options, receive_maximum, false, reserved);
    }

    /// Own one QoS 1/2 Application Message and reserve its Packet Identifier
    /// without selecting it for a socket write. A coordinator can persist this
    /// state before `drainInto` exposes the first wire transmission.
    pub fn stageImmediatePublish(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
        receive_maximum: u16,
    ) Error!u16 {
        return (try self.addImmediatePublish(
            handle,
            topic,
            payload,
            options,
            receive_maximum,
            true,
            null,
        )).packet_id;
    }

    pub fn stageImmediatePublishAvoiding(self: *Store, handle: Handle, topic: []const u8, payload: []const u8, options: EnqueueOptions, receive_maximum: u16, reserved: PacketIdentifierOwnership) Error!u16 {
        return (try self.addImmediatePublish(handle, topic, payload, options, receive_maximum, true, reserved)).packet_id;
    }

    fn addImmediatePublish(
        self: *Store,
        handle: Handle,
        topic: []const u8,
        payload: []const u8,
        options: EnqueueOptions,
        receive_maximum: u16,
        needs_send: bool,
        reserved: ?PacketIdentifierOwnership,
    ) Error!PublishTransmission {
        if (options.qos == .at_most_once or receive_maximum == 0) {
            return error.InvalidProperty;
        }
        try validatePublishForSession(topic, payload, options.properties);
        const session = try self.getSession(handle);
        _ = self.pruneExpiredPublishes(session, options.now.nanoseconds);
        if (session.pending_qos0 != null or session.queued_count != 0) {
            return error.InflightFull;
        }
        if (session.next_inflight_send != no_inflight_send) {
            return error.InflightFull;
        }
        if (session.sent_publish_count >= receive_maximum or
            session.inflight_count >= self.options.max_inflight_per_session or
            inflightPayloadLimitReached(
                self.options,
                session.inflight_payload_bytes,
            ))
        {
            return error.InflightFull;
        }

        var publish = try clonePublish(
            self.allocator,
            &self.publish_wire_cache,
            topic,
            payload,
            options.qos,
            options.retain,
            options.properties,
            options.now.nanoseconds,
        );
        errdefer publish.deinit(
            self.allocator,
            &self.publish_wire_cache,
        );
        try self.ensureBytes(session, publish.allocation_bytes);
        try session.packet_index.ensureUnusedCapacity(self.allocator, 1);
        const append_needed: usize = @intFromBool(
            session.inflight.items.len == session.inflight_count,
        );
        try session.inflight.ensureUnusedCapacity(
            self.allocator,
            append_needed,
        );

        const packet_id = try identifiers.reserve(session, reserved);
        const inflight_index = appendInflightAssumeCapacity(
            session,
            .{
                .publish = publish,
                .packet_id = packet_id,
                .state = switch (options.qos) {
                    .at_least_once => .await_puback,
                    .exactly_once => .await_pubrec,
                    .at_most_once => unreachable,
                },
                .needs_send = needs_send,
                .retransmission = false,
                .pubrel_blocked = false,
            },
        );
        session.packet_index.putAssumeCapacityNoClobber(
            packet_id,
            inflight_index,
        );
        session.inflight_count += 1;
        noteInflightAdded(
            session,
            inflight_index,
            &session.inflight.items[inflight_index],
        );
        session.inflight_payload_bytes += publish.payload.len;
        session.allocation_bytes += publish.allocation_bytes;
        self.total_bytes += publish.allocation_bytes;
        notePublishExpiry(session, publish);
        publish = undefined;
        return publishTransmission(
            session.inflight.items[inflight_index],
            options.now.nanoseconds,
        );
    }

    /// Remove a publication staged before its first wire attempt. Once a drain
    /// selects the PUBLISH, or a restored snapshot marks it as a possible
    /// retransmission, the operation is no longer safely reversible.
    pub fn discardStagedPublish(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const target = try self.getSession(handle);
        const index = target.packet_index.get(packet_id) orelse
            return error.InvalidAcknowledgement;
        const inflight = target.inflight.items[index];
        if (inflight.packet_id == 0) return error.InvalidAcknowledgement;
        if (!inflight.needs_send or inflight.retransmission or
            inflight.state == .await_pubcomp)
        {
            return error.InvalidAcknowledgement;
        }
        self.removeInflight(target, index);
    }

    pub fn outgoingQoSState(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!?OutgoingQoSState {
        const session = try self.getSession(handle);
        const index = session.packet_index.get(packet_id) orelse return null;
        const inflight = session.inflight.items[index];
        if (inflight.packet_id == 0) return null;
        return inflight.state;
    }

    /// Inspect Message Expiry without pruning ownership. Durable coordinators
    /// can commit the resulting terminal state before discarding the PUBLISH.
    /// Accepted QoS 2 PUBREL/PUBCOMP state is independent of Message Expiry.
    pub fn outgoingPublishExpired(self: *Store, handle: Handle, packet_id: u16, now: std.Io.Timestamp) Error!bool {
        const current = try self.getSession(handle);
        const index = current.packet_index.get(packet_id) orelse return false;
        const inflight = current.inflight.items[index];
        if (inflight.state == .await_pubcomp) return false;
        return publishRemainingExpiryNs(inflight.publish, now.nanoseconds) == 0;
    }

    /// Emit all pending retransmissions that fit `out`, then move unsent
    /// queued messages into the available Receive Maximum window.
    pub fn drainInto(
        self: *Store,
        handle: Handle,
        now: std.Io.Timestamp,
        receive_maximum: u16,
        out: []Transmission,
    ) Error![]Transmission {
        var ignored_snapshot_change = false;
        return self.drainIntoTrackingSnapshotChange(
            handle,
            now,
            receive_maximum,
            out,
            &ignored_snapshot_change,
        );
    }

    /// Like `drainInto`, while reporting whether selection changed the durable
    /// snapshot representation. Retransmission flags and the temporary QoS 0
    /// write owner are deliberately excluded because snapshots do not encode
    /// those distinctions.
    pub fn drainIntoTrackingSnapshotChange(
        self: *Store,
        handle: Handle,
        now: std.Io.Timestamp,
        receive_maximum: u16,
        out: []Transmission,
        snapshot_changed: *bool,
    ) Error![]Transmission {
        return self.drainIntoInternal(handle, now, receive_maximum, out, snapshot_changed, null);
    }

    /// Borrow reservations only for this call; queued messages do not retain
    /// pointers into a Network Connection and snapshots remain Session-only.
    pub fn drainIntoAvoiding(self: *Store, handle: Handle, now: std.Io.Timestamp, receive_maximum: u16, out: []Transmission, reserved: PacketIdentifierOwnership) Error![]Transmission {
        var ignored_snapshot_change = false;
        return self.drainIntoInternal(handle, now, receive_maximum, out, &ignored_snapshot_change, reserved);
    }

    fn drainIntoInternal(self: *Store, handle: Handle, now: std.Io.Timestamp, receive_maximum: u16, out: []Transmission, snapshot_changed: *bool, reserved: ?PacketIdentifierOwnership) Error![]Transmission {
        snapshot_changed.* = false;
        if (receive_maximum == 0) return error.InvalidProperty;
        const session = try self.getSession(handle);
        snapshot_changed.* = self.pruneExpiredPublishes(
            session,
            now.nanoseconds,
        );
        // The returned slices borrow Session-owned memory. The caller must
        // finish or roll back a previously selected QoS 0 publication before
        // requesting another batch.
        if (session.pending_qos0 != null) return error.InflightFull;
        var written: usize = 0;
        var publish_window_used: usize = session.sent_publish_count;
        var blocked_qos_publish = false;
        const max_inflight = @min(
            self.options.max_inflight_per_session,
            @as(usize, std.math.maxInt(u16)),
        );
        var new_inflight_capacity = @min(
            out.len,
            session.queued_count,
            @as(usize, receive_maximum) -| @min(
                @as(usize, receive_maximum),
                publish_window_used,
            ),
            max_inflight -| session.inflight_count,
        );
        if (inflightPayloadLimitReached(
            self.options,
            session.inflight_payload_bytes,
        )) {
            new_inflight_capacity = 0;
        }
        // Reserve the worst-case QoS 1/2 additions before changing any
        // retransmission flags. QoS 0 may make the estimate conservative, but
        // this keeps an allocation failure from partially consuming a drain.
        try session.packet_index.ensureUnusedCapacity(
            self.allocator,
            @intCast(new_inflight_capacity),
        );
        const free_inflight_slots = session.inflight.items.len -
            session.inflight_count;
        const append_needed = new_inflight_capacity -| free_inflight_slots;
        try session.inflight.ensureUnusedCapacity(
            self.allocator,
            append_needed,
        );
        var send_index: usize = session.next_inflight_send;
        const send_tail = if (session.inflight_order_head == no_inflight_send)
            no_inflight_send
        else
            session.inflight.items[session.inflight_order_head].order_previous;
        session.next_inflight_send = no_inflight_send;
        while (send_index != no_inflight_send) {
            std.debug.assert(send_index < session.inflight.items.len);
            const inflight = &session.inflight.items[send_index];
            std.debug.assert(inflight.packet_id != 0);
            const next_send_index = if (send_index == send_tail)
                no_inflight_send
            else
                inflight.order_next;
            if (!inflight.needs_send) {
                send_index = next_send_index;
                continue;
            }
            // Even a full output must skip already-sent slots before retaining
            // its cursor. A one-slot PUBREL drain otherwise advertises phantom
            // work when its remaining suffix contains only sent PUBLISHes.
            if (written == out.len) break;
            if (inflight.state == .await_pubcomp and
                inflight.pubrel_blocked)
            {
                retainInflightForLater(session, send_index);
                send_index = next_send_index;
                continue;
            }
            const transmission = transmissionForInflight(
                inflight.*,
                now.nanoseconds,
            );
            if (transmission == .publish and
                publish_window_used >=
                    @as(usize, receive_maximum))
            {
                // A peer can lower Receive Maximum on reconnect. Preserve
                // those already-sent PUBLISH packets for a later drain call
                // rather than violating the new connection's window.
                blocked_qos_publish = true;
                retainInflightForLater(session, send_index);
                send_index = next_send_index;
                continue;
            }
            out[written] = transmission;
            noteInflightSelected(session, inflight);
            if (transmission == .publish) {
                publish_window_used += 1;
            }
            written += 1;
            send_index = next_send_index;
        }
        if (written == out.len and send_index != no_inflight_send) {
            retainInflightForLater(session, send_index);
        }
        if (written == out.len) return out[0..written];

        var queue_index = session.queued_head;
        while (written != out.len and
            queue_index < session.queued.items.len)
        {
            if (session.queued.items[queue_index]) |publish_value| {
                var publish = publish_value;
                if (publish.qos == .at_most_once) {
                    // Preserve FIFO ordering with QoS 1/2. QoS 0 consumes no
                    // Receive Maximum credit, but it must not overtake an
                    // earlier durable PUBLISH that is waiting for such credit.
                    if (blocked_qos_publish) break;
                    out[written] = .{ .publish = .{
                        .topic = publish.topic,
                        .payload = publish.payload,
                        .qos = .at_most_once,
                        .retain = publish.retain,
                        .dup = false,
                        .packet_id = 0,
                        .properties = publish.properties,
                        .message_expiry_interval = remainingExpiry(
                            publish,
                            now.nanoseconds,
                        ),
                    } };
                    // Unlike QoS 1/2, no ACK can own this publication after
                    // return. Keep it alive in a transient owner until
                    // the caller confirms or rolls back the socket write.
                    session.queued.items[queue_index] = null;
                    session.queued_count -= 1;
                    session.queued_payload_bytes -= publish.payload.len;
                    session.pending_qos0 = .{
                        .publish = publish,
                        .generation = session.generation,
                    };
                    written += 1;
                    publish = undefined;
                    queue_index += 1;
                    break;
                }
                if (publish_window_used >=
                    @as(usize, receive_maximum))
                {
                    blocked_qos_publish = true;
                    break;
                }
                if (inflightPayloadLimitReached(
                    self.options,
                    session.inflight_payload_bytes,
                )) break;
                if (session.inflight_count >= max_inflight) {
                    blocked_qos_publish = true;
                    break;
                }
                const packet_id = identifiers.reserve(session, reserved) catch |err| {
                    // Earlier members have already been selected. Return that
                    // committed prefix while the blocked queued item remains
                    // owned; no transmission may disappear behind an error.
                    if (written != 0 and err == error.InflightFull) break;
                    return err;
                };
                const state: InflightState = switch (publish.qos) {
                    .at_least_once => .await_puback,
                    .exactly_once => .await_pubrec,
                    .at_most_once => unreachable,
                };
                const inflight_index = appendInflightAssumeCapacity(
                    session,
                    .{
                        .publish = publish,
                        .packet_id = packet_id,
                        .state = state,
                        .needs_send = false,
                        .retransmission = false,
                        .pubrel_blocked = false,
                    },
                );
                session.queued.items[queue_index] = null;
                session.queued_count -= 1;
                session.queued_payload_bytes -= publish.payload.len;
                session.packet_index.putAssumeCapacityNoClobber(
                    packet_id,
                    inflight_index,
                );
                session.inflight_count += 1;
                noteInflightAdded(
                    session,
                    inflight_index,
                    &session.inflight.items[inflight_index],
                );
                session.inflight_payload_bytes = std.math.add(
                    usize,
                    session.inflight_payload_bytes,
                    publish.payload.len,
                ) catch unreachable;
                // This is the only drain transition that changes serialized
                // ownership: queued QoS 1/2 becomes inflight and consumes a
                // persistent Packet Identifier.
                snapshot_changed.* = true;
                publish_window_used += 1;
                out[written] = .{ .publish = publishTransmission(
                    session.inflight.items[inflight_index],
                    now.nanoseconds,
                ) };
                written += 1;
                publish = undefined;
            }
            queue_index += 1;
        }
        session.queued_head = queue_index;
        advanceQueueHead(session);
        return out[0..written];
    }

    /// Roll back one PUBLISH selected by `drainInto` when encoding or socket
    /// submission fails before the peer can receive it. Selection moves a
    /// queued message into inflight state; without this rollback a reconnect
    /// marks that never-sent message as DUP, conflating local failure with a
    /// genuine retransmission.
    pub fn retryUnsentPublish(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        if (packet_id == 0) {
            const session = try self.pendingQoS0Session(handle);
            const publish = session.pending_qos0.?.publish;
            session.pending_qos0 = null;
            std.debug.assert(session.queued_head != 0);
            session.queued_head -= 1;
            session.queued.items[session.queued_head] = publish;
            session.queued_count += 1;
            session.queued_payload_bytes += publish.payload.len;
            notePublishExpiry(session, publish);
            return;
        }
        const session = try self.getSession(handle);
        const index = session.packet_index.get(packet_id) orelse
            return error.InvalidAcknowledgement;
        const inflight = &session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        if (inflight.state != .await_puback and
            inflight.state != .await_pubrec)
        {
            return error.InvalidAcknowledgement;
        }
        noteInflightNeedsSend(session, index, inflight);
        // Selection does not change retransmission. A never-sent PUBLISH
        // stays fresh, but a failed retry of an earlier connection's PUBLISH
        // must keep DUP on its next local attempt.
    }

    /// Make a PUBREL selected by `drainInto` eligible for a later retry when
    /// the caller could not transfer it to its transport.
    pub fn retryUnsentPubRel(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const target = try self.getSession(handle);
        const index = target.packet_index.get(packet_id) orelse
            return error.InvalidAcknowledgement;
        const inflight = &target.inflight.items[index];
        if (inflight.packet_id == 0 or inflight.state != .await_pubcomp or
            inflight.needs_send)
        {
            return error.InvalidAcknowledgement;
        }
        noteInflightNeedsSend(target, index, inflight);
    }

    /// Apply a QoS acknowledgement after validating its MQTT 5 reason code.
    /// MQTT 3.1.1 callers pass zero. Invalid codes leave all delivery state,
    /// Receive Maximum credit, and persistence data unchanged.
    pub fn handleAck(
        self: *Store,
        handle: Handle,
        packet_type: mqtt.PacketType,
        packet_id: u16,
        reason_code: u8,
    ) Error!AckAction {
        const session = try self.getSession(handle);
        const index = session.packet_index.get(packet_id) orelse
            return error.InvalidAcknowledgement;
        const inflight = &session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        switch (packet_type) {
            .puback, .pubrec, .pubcomp => try mqtt.validateAckReasonCode(packet_type, reason_code),
            else => return error.InvalidAcknowledgement,
        }
        switch (packet_type) {
            .puback => {
                if (inflight.state != .await_puback) {
                    return error.InvalidAcknowledgement;
                }
                self.removeInflight(session, index);
                return .completed;
            },
            .pubrec => {
                if (inflight.state == .await_pubcomp) {
                    // A repeated successful PUBREC requests retransmission of
                    // the PUBREL already emitted for this transaction. Keep
                    // the durable stage and make the control packet eligible
                    // for the connection writer again.
                    if (reason_code >= 0x80) {
                        return error.InvalidAcknowledgement;
                    }
                    noteInflightNeedsSend(session, index, inflight);
                    inflight.retransmission = true;
                    return .send_pubrel;
                }
                if (inflight.state != .await_pubrec) {
                    return error.InvalidAcknowledgement;
                }
                if (reason_code >= 0x80) {
                    self.removeInflight(session, index);
                    return .completed;
                }
                noteInflightNeedsSend(session, index, inflight);
                inflight.state = .await_pubcomp;
                inflight.retransmission = false;
                return .send_pubrel;
            },
            .pubcomp => {
                if (inflight.state != .await_pubcomp) {
                    return error.InvalidAcknowledgement;
                }
                self.removeInflight(session, index);
                return .completed;
            },
            else => return error.InvalidAcknowledgement,
        }
    }

    /// Hold an accepted outgoing QoS 2 transaction at its durable
    /// `await_pubcomp` state without allowing `drainInto` to expose PUBREL.
    /// The gate survives transport reconnects in this process but is omitted
    /// from snapshots, whose existence proves the transition was committed.
    pub fn blockPendingPubRel(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const session = try self.getSession(handle);
        const index = session.packet_index.get(packet_id) orelse
            return error.InvalidAcknowledgement;
        const inflight = &session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        if (inflight.state != .await_pubcomp or !inflight.needs_send) {
            return error.InvalidAcknowledgement;
        }
        inflight.pubrel_blocked = true;
    }

    /// Release every PUBREL held behind the caller's durability boundary.
    /// Selection and wire output still occur later through `drainInto`.
    pub fn releasePendingPubRels(
        self: *Store,
        handle: Handle,
    ) Error!void {
        const session = try self.getSession(handle);
        for (session.inflight.items) |*inflight| {
            if (inflight.packet_id == 0) continue;
            if (inflight.state == .await_pubcomp) {
                inflight.pubrel_blocked = false;
            }
        }
    }

    /// Drop one outgoing PUBLISH that cannot be represented for this peer.
    ///
    /// MQTT 5 Maximum Packet Size can shrink across reconnects. Mosquitto
    /// removes an oversized queued/inflight message instead of retrying it
    /// forever and blocking the Session Receive Maximum window. PUBREL is
    /// intentionally not droppable because it is the continuation of an
    /// already accepted QoS 2 transaction.
    pub fn dropOversizedPublish(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!DropAction {
        return self.dropOutgoingPublish(handle, packet_id);
    }

    /// Drop a selected outgoing PUBLISH before it reaches the peer. This is
    /// used for both packet-size policy and delivery ACL re-evaluation. A
    /// PUBREL is intentionally retained because its QoS 2 PUBLISH was already
    /// accepted by the peer and the transaction must still complete.
    pub fn dropOutgoingPublish(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!DropAction {
        if (packet_id == 0) {
            const session = try self.pendingQoS0Session(handle);
            var publish = session.pending_qos0.?.publish;
            session.pending_qos0 = null;
            session.allocation_bytes -= publish.allocation_bytes;
            self.total_bytes -= publish.allocation_bytes;
            publish.deinit(
                self.allocator,
                &self.publish_wire_cache,
            );
            advanceQueueHead(session);
            return .dropped;
        }
        const session = try self.getSession(handle);
        const index = session.packet_index.get(packet_id) orelse
            return .ignored;
        const inflight = &session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        if (inflight.state == .await_pubcomp) return .ignored;
        self.removeInflight(session, index);
        return .dropped;
    }

    /// Commit a Session PUBLISH whose encoded wire QoS is 0. Native queued
    /// QoS 0 uses the zero sentinel; a QoS 1/2 transaction capped to QoS 0 by
    /// the broker's Maximum QoS is removed because no ACK will follow.
    pub fn completeQoS0Transmission(
        self: *Store,
        handle: Handle,
        route_id: u64,
        packet_id: u16,
    ) Error!void {
        if (packet_id != 0) {
            const current = self.handleForRouteId(route_id) orelse
                return error.SessionNotFound;
            const session = try self.getSession(current);
            const index = session.packet_index.get(packet_id) orelse
                return error.InvalidAcknowledgement;
            const inflight = &session.inflight.items[index];
            std.debug.assert(inflight.packet_id != 0);
            if (inflight.state != .await_puback and
                inflight.state != .await_pubrec)
            {
                return error.InvalidAcknowledgement;
            }
            self.removeInflight(session, index);
            return;
        }
        const session = try self.pendingQoS0Session(handle);
        var publish = session.pending_qos0.?.publish;
        session.pending_qos0 = null;
        session.allocation_bytes -= publish.allocation_bytes;
        self.total_bytes -= publish.allocation_bytes;
        publish.deinit(
            self.allocator,
            &self.publish_wire_cache,
        );
        advanceQueueHead(session);
    }

    fn pendingQoS0Session(
        self: *Store,
        handle: Handle,
    ) Error!*Session {
        if (handle.index >= self.sessions.items.len) {
            return error.SessionNotFound;
        }
        const session = &(self.sessions.items[handle.index] orelse
            return error.SessionNotFound);
        const pending = session.pending_qos0 orelse {
            if (session.generation != handle.generation) {
                return error.SessionNotFound;
            }
            return error.InvalidAcknowledgement;
        };
        if (pending.generation != handle.generation) {
            return error.SessionNotFound;
        }
        return session;
    }

    fn rollbackPendingQos0(session: *Session, generation: u64) void {
        const pending = session.pending_qos0 orelse return;
        if (pending.generation != generation) return;
        const publish = pending.publish;
        session.pending_qos0 = null;
        std.debug.assert(session.queued_head != 0);
        session.queued_head -= 1;
        session.queued.items[session.queued_head] = publish;
        session.queued_count += 1;
        session.queued_payload_bytes += publish.payload.len;
        notePublishExpiry(session, publish);
    }

    pub fn recordIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!bool {
        return self.addIncomingQoS2(handle, packet_id, true);
    }

    pub fn stageIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!bool {
        return self.addIncomingQoS2(handle, packet_id, false);
    }

    fn addIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
        pubrec_may_be_visible: bool,
    ) Error!bool {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const session = try self.getSession(handle);
        if (session.incoming_qos2.contains(packet_id)) return true;
        if (session.incoming_qos2.count() >=
            self.options.max_incoming_qos2_per_session)
        {
            return error.IncomingQoS2Full;
        }
        try session.incoming_qos2.put(
            self.allocator,
            packet_id,
            .{
                .state = .await_pubrel,
                .pubrec_may_be_visible = pubrec_may_be_visible,
            },
        );
        return false;
    }

    /// Mark the point after all local PUBREC validation but before transport
    /// output begins. An error after this call is ambiguous and cannot safely
    /// make a staged transaction discardable again.
    pub fn markIncomingQoS2PubRecStarted(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const session = try self.getSession(handle);
        const transaction = session.incoming_qos2.getPtr(packet_id) orelse
            return error.InvalidPacketIdentifier;
        if (transaction.state != .await_pubrel) {
            return error.InvalidPacketIdentifier;
        }
        transaction.pubrec_may_be_visible = true;
    }

    /// Roll back a pre-wire inbound QoS 2 marker after an enclosing durable
    /// transaction fails. Any PUBREC write attempt permanently closes this
    /// escape hatch because the peer may already have advanced to PUBREL.
    pub fn discardStagedIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const session = try self.getSession(handle);
        const transaction = session.incoming_qos2.get(packet_id) orelse
            return error.InvalidPacketIdentifier;
        if (transaction.state != .await_pubrel or
            transaction.pubrec_may_be_visible)
        {
            return error.InvalidAcknowledgement;
        }
        _ = session.incoming_qos2.remove(packet_id);
    }

    pub fn restoreIncomingQoS2ReleasePending(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const duplicate = try self.addIncomingQoS2(
            handle,
            packet_id,
            true,
        );
        if (duplicate) return error.InvalidAcknowledgement;
        try self.markIncomingQoS2ReleasePending(handle, packet_id);
    }

    pub fn completeIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const session = try self.getSession(handle);
        if (session.incoming_qos2.fetchRemove(packet_id) == null) {
            return error.InvalidPacketIdentifier;
        }
    }

    /// Test whether a durable inbound QoS 2 transaction is awaiting PUBREL.
    /// Reconnecting clients use this before writing PUBCOMP because the new
    /// transport's connection-local receive table cannot represent state that
    /// was established on an earlier Network Connection.
    pub fn containsIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!bool {
        const session = try self.getSession(handle);
        return session.incoming_qos2.contains(packet_id);
    }

    pub fn incomingQoS2State(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!?IncomingQoS2State {
        const session = try self.getSession(handle);
        const transaction = session.incoming_qos2.get(packet_id) orelse
            return null;
        return transaction.state;
    }

    pub fn incomingQoS2PubRecMayBeVisible(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!?bool {
        const session = try self.getSession(handle);
        const transaction = session.incoming_qos2.get(packet_id) orelse
            return null;
        return transaction.pubrec_may_be_visible;
    }

    /// Encode reconnect-client inbound QoS 2 protocol markers separately from
    /// the broker Session snapshot. Broker persistence owns the corresponding
    /// Application Messages in its dedicated pending-QoS2 store; standalone
    /// reconnect clients need only these compact receive phases.
    pub fn writeIncomingQoS2Snapshot(
        self: *Store,
        handle: Handle,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
    ) (Error || persistence.Error)!void {
        const target = try self.getSession(handle);
        const transaction_count = target.incoming_qos2.count();
        if (transaction_count > std.math.maxInt(u32)) {
            return error.SnapshotLimitExceeded;
        }
        try persistence.appendInt(
            out,
            allocator,
            u32,
            @intCast(transaction_count),
        );
        const Transaction = struct {
            packet_id: u16,
            state: IncomingQoS2State,

            fn lessThan(_: void, left: @This(), right: @This()) bool {
                return left.packet_id < right.packet_id;
            }
        };
        const transactions = try allocator.alloc(Transaction, transaction_count);
        defer allocator.free(transactions);
        var index: usize = 0;
        var iterator = target.incoming_qos2.iterator();
        while (iterator.next()) |entry| {
            transactions[index] = .{
                .packet_id = entry.key_ptr.*,
                .state = entry.value_ptr.state,
            };
            index += 1;
        }
        std.mem.sort(Transaction, transactions, {}, Transaction.lessThan);
        for (transactions) |transaction| {
            try persistence.appendInt(
                out,
                allocator,
                u16,
                transaction.packet_id,
            );
            try persistence.appendInt(
                out,
                allocator,
                u8,
                @intFromEnum(transaction.state),
            );
        }
    }

    /// Restore a complete reconnect-client inbound QoS 2 marker section. The
    /// caller decodes into a temporary Store, so a later error can discard the
    /// partially built map without mutating live reconnect state.
    pub fn restoreIncomingQoS2Snapshot(
        self: *Store,
        handle: Handle,
        cursor: *persistence.Cursor,
    ) (Error || persistence.Error)!void {
        const target = try self.getSession(handle);
        const transaction_count = try cursor.readInt(u32);
        if (transaction_count > self.options.max_incoming_qos2_per_session) {
            return error.IncomingQoS2Full;
        }
        try target.incoming_qos2.ensureUnusedCapacity(
            self.allocator,
            @intCast(transaction_count),
        );
        for (0..transaction_count) |_| {
            const packet_id = try cursor.readInt(u16);
            if (packet_id == 0 or target.incoming_qos2.contains(packet_id)) {
                return error.CorruptSnapshot;
            }
            const state = std.enums.fromInt(
                IncomingQoS2State,
                try cursor.readInt(u8),
            ) orelse return error.CorruptSnapshot;
            target.incoming_qos2.putAssumeCapacityNoClobber(
                packet_id,
                .{
                    .state = state,
                    .pubrec_may_be_visible = true,
                },
            );
        }
    }

    /// Mark that PUBREL has authorized application release. Repeated PUBREL
    /// keeps the same phase so a failed idempotent release can be retried by a
    /// later event without creating a second protocol transaction.
    pub fn markIncomingQoS2ReleasePending(
        self: *Store,
        handle: Handle,
        packet_id: u16,
    ) Error!void {
        const session = try self.getSession(handle);
        const transaction = session.incoming_qos2.getPtr(packet_id) orelse
            return error.InvalidPacketIdentifier;
        transaction.state = .release_pending;
        transaction.pubrec_may_be_visible = true;
    }

    fn getSession(self: *Store, handle: Handle) Error!*Session {
        if (handle.index >= self.sessions.items.len) {
            return error.SessionNotFound;
        }
        const session = &(self.sessions.items[handle.index] orelse
            return error.SessionNotFound);
        if (session.generation != handle.generation) {
            return error.SessionNotFound;
        }
        return session;
    }

    fn ensureBytes(
        self: *Store,
        session: *Session,
        additional: usize,
    ) Error!void {
        if (additional > self.options.max_session_bytes -|
            session.allocation_bytes or
            additional > self.options.max_total_bytes -|
                self.total_bytes)
        {
            return error.SessionByteLimitExceeded;
        }
    }

    fn removeAt(self: *Store, index: usize) void {
        var session = self.sessions.items[index].?;
        _ = self.client_index.fetchRemove(session.client_id).?;
        _ = self.route_index.fetchRemove(session.route_id).?;
        self.sessions.items[index] = null;
        self.session_count -= 1;
        self.persistent_session_count -= @intFromBool(
            session.expiry_interval != 0,
        );
        self.total_bytes -= session.allocation_bytes;
        session.deinit(
            self.allocator,
            &self.publish_wire_cache,
        );
    }

    fn isExpired(
        _: Store,
        session: Session,
        now: std.Io.Timestamp,
    ) bool {
        if (session.connected) return false;
        const deadline = session.expires_at_ns orelse return false;
        return now.nanoseconds >= deadline;
    }

    fn nextGeneration(self: *Store) u64 {
        const generation = self.next_generation;
        self.next_generation +%= 1;
        if (self.next_generation == 0) self.next_generation = 1;
        return generation;
    }

    fn nextRouteId(self: *Store) u64 {
        const first = self.next_route_id;
        while (true) {
            const route_id = self.next_route_id;
            self.next_route_id +%= 1;
            if (self.next_route_id == 0 or
                self.next_route_id >= (@as(u64, 1) << 63))
            {
                self.next_route_id = 1;
            }
            if (!self.route_index.contains(route_id)) return route_id;
            // Reaching this assertion requires all 2^63-1 route IDs to be
            // simultaneously live, which is impossible under `max_sessions`.
            std.debug.assert(self.next_route_id != first);
        }
    }

    fn pruneExpiredPublishes(
        self: *Store,
        session: *Session,
        now_ns: i96,
    ) bool {
        if (now_ns < session.next_publish_expiry_ns) return false;
        var changed = false;
        var next_expiry_ns: i96 = no_publish_expiry;
        for (session.queued.items[session.queued_head..]) |*maybe_publish| {
            if (maybe_publish.*) |publish| {
                const deadline = publishExpiryDeadline(publish);
                if (deadline == no_publish_expiry) continue;
                if (now_ns < deadline) {
                    next_expiry_ns = @min(next_expiry_ns, deadline);
                    continue;
                }
                var removed = publish;
                maybe_publish.* = null;
                session.queued_count -= 1;
                session.queued_payload_bytes -= removed.payload.len;
                session.allocation_bytes -= removed.allocation_bytes;
                self.total_bytes -= removed.allocation_bytes;
                removed.deinit(
                    self.allocator,
                    &self.publish_wire_cache,
                );
                changed = true;
            }
        }
        advanceQueueHead(session);
        var index: usize = 0;
        while (index < session.inflight.items.len) : (index += 1) {
            const inflight = session.inflight.items[index];
            if (inflight.packet_id == 0) continue;
            if (inflight.state == .await_pubcomp) continue;
            const deadline = publishExpiryDeadline(inflight.publish);
            if (deadline == no_publish_expiry) continue;
            if (now_ns < deadline) {
                next_expiry_ns = @min(next_expiry_ns, deadline);
                continue;
            }
            self.removeInflight(session, index);
            changed = true;
        }
        session.next_publish_expiry_ns = next_expiry_ns;
        return changed;
    }

    fn removeInflight(
        self: *Store,
        session: *Session,
        index: usize,
    ) void {
        var inflight = session.inflight.items[index];
        std.debug.assert(inflight.packet_id != 0);
        releasePublishWindow(session, &inflight);
        const compact_index: u16 = @intCast(index);
        const repair_send_cursor = inflight.needs_send or
            session.next_inflight_send == compact_index;
        const free_head = session.inflight.items[
            session.inflight_order_head
        ].free_head;
        if (inflight.order_next == compact_index) {
            std.debug.assert(inflight.order_previous == compact_index);
            std.debug.assert(session.inflight_order_head == compact_index);
            session.inflight_order_head = no_inflight_send;
        } else {
            session.inflight.items[inflight.order_previous].order_next =
                inflight.order_next;
            session.inflight.items[inflight.order_next].order_previous =
                inflight.order_previous;
            if (session.inflight_order_head == compact_index) {
                session.inflight_order_head = inflight.order_next;
            }
        }
        _ = session.packet_index.fetchRemove(inflight.packet_id).?;
        session.inflight_count -= 1;
        if (session.inflight_count == 0) {
            session.next_inflight_send = no_inflight_send;
            session.inflight.clearRetainingCapacity();
            std.debug.assert(
                session.inflight_order_head == no_inflight_send,
            );
        } else {
            const order_head = &session.inflight.items[
                session.inflight_order_head
            ];
            session.inflight.items[index].packet_id = 0;
            session.inflight.items[index].free_next = free_head;
            order_head.free_head = compact_index;
            if (repair_send_cursor) {
                repairInflightSendCursor(session);
            }
        }
        session.inflight_payload_bytes -= inflight.publish.payload.len;
        session.allocation_bytes -= inflight.publish.allocation_bytes;
        self.total_bytes -= inflight.publish.allocation_bytes;
        inflight.publish.deinit(
            self.allocator,
            &self.publish_wire_cache,
        );
    }
};

fn clonePublish(
    allocator: std.mem.Allocator,
    cache: *StorageCache,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
    now_ns: i96,
) Error!OwnedPublish {
    const wire_len = std.math.add(usize, topic.len, payload.len) catch
        return error.SessionByteLimitExceeded;
    const allocation = try cache.acquire(wire_len);
    errdefer cache.release(allocation);
    const wire = allocation[0..wire_len];
    @memcpy(wire[0..topic.len], topic);
    @memcpy(wire[topic.len..], payload);
    const property_result = owned_properties.clone(
        allocator,
        properties,
        keepQueuedProperty,
    ) catch |err| switch (err) {
        error.OwnedPropertyLimitExceeded => return error.SessionByteLimitExceeded,
        else => return @errorCast(err),
    };
    errdefer owned_properties.deinit(
        allocator,
        property_result.properties,
    );
    const bytes = std.math.add(
        usize,
        wire.len,
        property_result.allocation_bytes,
    ) catch return error.SessionByteLimitExceeded;
    return .{
        .wire = wire,
        .wire_allocation_len = allocation.len,
        .topic = wire[0..topic.len],
        .payload = wire[topic.len..],
        .qos = qos,
        .retain = retain,
        .properties = property_result.properties,
        .stored_at_ns = now_ns,
        .expiry_interval = mqtt.messageExpiryInterval(properties),
        .allocation_bytes = bytes,
    };
}

fn clonePublishFromSharedPublication(
    allocator: std.mem.Allocator,
    publication: *SharedPublication,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
    now_ns: i96,
) Error!OwnedPublish {
    const property_result = owned_properties.clone(
        allocator,
        properties,
        keepQueuedProperty,
    ) catch |err| switch (err) {
        error.OwnedPropertyLimitExceeded => return error.SessionByteLimitExceeded,
        else => return @errorCast(err),
    };
    errdefer owned_properties.deinit(
        allocator,
        property_result.properties,
    );
    const wire_len = std.math.add(
        usize,
        publication.topic().len,
        publication.payload().len,
    ) catch return error.SessionByteLimitExceeded;
    const bytes = std.math.add(
        usize,
        wire_len,
        property_result.allocation_bytes,
    ) catch return error.SessionByteLimitExceeded;
    publication.retain();
    return .{
        // A reserved allocation length tags this as a shared Publication. The
        // complete bytes slice recovers its coallocated owner at release.
        .wire = publication.bytes,
        .wire_allocation_len = shared_publication_wire,
        .topic = publication.bytes[0..publication.topic().len],
        .payload = publication.bytes[publication.topic().len..],
        .qos = qos,
        .retain = retain,
        .properties = property_result.properties,
        .stored_at_ns = now_ns,
        .expiry_interval = mqtt.messageExpiryInterval(properties),
        .allocation_bytes = bytes,
    };
}

const RestoredSubscription = struct {
    subscription: mqtt.Subscription,
    identifier: ?usize,
};

fn writeSubscription(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    subscription: OwnedSubscription,
) persistence.Error!void {
    try persistence.appendBlob(
        out,
        allocator,
        subscription.topic_filter,
    );
    try persistence.appendInt(
        out,
        allocator,
        u8,
        @intFromEnum(subscription.qos),
    );
    try persistence.appendBool(out, allocator, subscription.no_local);
    try persistence.appendBool(
        out,
        allocator,
        subscription.retain_as_published,
    );
    try persistence.appendInt(
        out,
        allocator,
        u8,
        subscription.retain_handling,
    );
    try persistence.appendOptionalInt(
        out,
        allocator,
        u32,
        if (subscription.subscription_identifier) |value|
            @intCast(value)
        else
            null,
    );
}

fn readSubscription(
    cursor: *persistence.Cursor,
) persistence.Error!RestoredSubscription {
    const topic_filter = try cursor.readBlob();
    const qos = try persistence.qosFromByte(try cursor.readInt(u8));
    const no_local = try cursor.readBool();
    const retain_as_published = try cursor.readBool();
    const retain_handling_raw = try cursor.readInt(u8);
    if (retain_handling_raw > 2) return error.CorruptSnapshot;
    const identifier = try cursor.readOptionalInt(u32);
    return .{
        .subscription = .{
            .topic_filter = topic_filter,
            .qos = qos,
            .no_local = no_local,
            .retain_as_published = retain_as_published,
            .retain_handling = @intCast(retain_handling_raw),
        },
        .identifier = if (identifier) |value| value else null,
    };
}

fn writePublishSnapshot(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    publish: OwnedPublish,
    remaining_expiry_ns: ?u64,
) persistence.Error!void {
    try persistence.appendBlob(out, allocator, publish.topic);
    try persistence.appendBlob(out, allocator, publish.payload);
    try persistence.appendInt(
        out,
        allocator,
        u8,
        @intFromEnum(publish.qos),
    );
    try persistence.appendBool(out, allocator, publish.retain);
    try persistence.appendOptionalInt(
        out,
        allocator,
        u64,
        remaining_expiry_ns,
    );
    try persistence.appendProperties(
        out,
        allocator,
        publish.properties,
    );
}

fn readPublishSnapshot(
    allocator: std.mem.Allocator,
    cache: *StorageCache,
    cursor: *persistence.Cursor,
    restore_now_ns: i96,
    downtime_ns: i96,
    ignore_expiry: bool,
) (Error || persistence.Error)!?OwnedPublish {
    const topic = try cursor.readBlob();
    const payload = try cursor.readBlob();
    const qos = try persistence.qosFromByte(try cursor.readInt(u8));
    const retain = try cursor.readBool();
    const saved_remaining_ns = try cursor.readOptionalInt(u64);
    const remaining_ns = remainingAfterDowntimeNs(
        saved_remaining_ns,
        downtime_ns,
    );
    const properties = try cursor.readProperties(allocator);
    defer allocator.free(properties);
    if (!ignore_expiry and
        (mqtt.messageExpiryInterval(properties) == null) !=
            (saved_remaining_ns == null))
    {
        return error.CorruptSnapshot;
    }
    if (!ignore_expiry and remaining_ns == 0) return null;

    var publish = try clonePublish(
        allocator,
        cache,
        topic,
        payload,
        qos,
        retain,
        properties,
        restore_now_ns,
    );
    errdefer publish.deinit(allocator, cache);
    if (!ignore_expiry) if (remaining_ns) |remaining| {
        const interval = publish.expiry_interval orelse
            return error.CorruptSnapshot;
        const lifetime_ns = @as(u64, interval) * std.time.ns_per_s;
        if (remaining > lifetime_ns) return error.CorruptSnapshot;
        publish.stored_at_ns = restore_now_ns -
            @as(i96, lifetime_ns - remaining);
    };
    return publish;
}

fn skipPublishSnapshot(
    cursor: *persistence.Cursor,
) persistence.Error!void {
    _ = try cursor.readBlob();
    _ = try cursor.readBlob();
    _ = try cursor.readInt(u8);
    _ = try cursor.readBool();
    _ = try cursor.readOptionalInt(u64);
    _ = try cursor.readBlob(); // encoded properties
}

fn sessionRemainingExpiryNs(
    session: Session,
    now_ns: i96,
) ?u64 {
    std.debug.assert(!session.connected);
    const deadline = session.expires_at_ns orelse return null;
    return @intCast(@max(deadline - now_ns, 0));
}

fn publishRemainingExpiryNs(
    publish: OwnedPublish,
    now_ns: i96,
) ?u64 {
    const interval = publish.expiry_interval orelse return null;
    const lifetime_ns = @as(u64, interval) * std.time.ns_per_s;
    const elapsed_ns: u64 = @intCast(@max(
        now_ns - publish.stored_at_ns,
        0,
    ));
    return lifetime_ns -| elapsed_ns;
}

fn remainingAfterDowntimeNs(
    remaining: ?u64,
    downtime_ns: i96,
) ?u64 {
    const value = remaining orelse return null;
    const elapsed: u64 = @intCast(@min(
        @max(downtime_ns, 0),
        std.math.maxInt(u64),
    ));
    return value -| elapsed;
}

fn snapshotCount(value: usize) persistence.Error!u32 {
    return std.math.cast(u32, value) orelse
        error.SnapshotLimitExceeded;
}

fn keepQueuedProperty(property: mqtt.Property) bool {
    // Topic aliases are scoped to one connection and are negotiated anew after
    // reconnect. All other forwarding properties, including server-generated
    // Subscription Identifiers, form part of the queued PUBLISH.
    return !(property == .two_byte and
        property.two_byte.id == .topic_alias);
}

fn compactQueue(session: *Session) void {
    var write_index: usize = 0;
    for (session.queued.items[session.queued_head..]) |maybe_publish| {
        const publish = maybe_publish orelse continue;
        session.queued.items[write_index] = publish;
        write_index += 1;
    }
    session.queued.items.len = write_index;
    session.queued_head = 0;
    std.debug.assert(write_index == session.queued_count);
}

fn queuedPayloadLimitReached(options: Options, current_bytes: usize) bool {
    const limit = options.max_queued_payload_bytes_per_session;
    return limit != 0 and current_bytes >= limit;
}

fn inflightPayloadLimitReached(options: Options, current_bytes: usize) bool {
    const limit = options.max_inflight_payload_bytes_per_session;
    return limit != 0 and current_bytes >= limit;
}

fn advanceQueueHead(session: *Session) void {
    while (session.queued_head < session.queued.items.len and
        session.queued.items[session.queued_head] == null)
    {
        session.queued_head += 1;
    }
    if (session.queued_count == 0 and session.pending_qos0 == null) {
        // Reusing the retained allocation at index zero keeps a sustained
        // online Session bounded by its live backlog rather than by the total
        // number of messages observed since CONNECT.
        session.queued.items.len = 0;
        session.queued_head = 0;
        std.debug.assert(session.queued_payload_bytes == 0);
    }
}

fn validateQueuedPayload(
    properties: []const mqtt.Property,
    payload: []const u8,
) mqtt.Error!void {
    for (properties) |property| {
        if (property == .byte and
            property.byte.id == .payload_format_indicator and
            property.byte.value == 1 and
            !std.unicode.utf8ValidateSlice(payload))
        {
            return error.InvalidUtf8;
        }
    }
}

fn expiryDeadline(now_ns: i96, interval: u32) ?i96 {
    if (interval == std.math.maxInt(u32)) return null;
    const duration = @as(i96, interval) * std.time.ns_per_s;
    return std.math.add(i96, now_ns, duration) catch
        std.math.maxInt(i96);
}

fn remainingExpiry(publish: OwnedPublish, now_ns: i96) ?u32 {
    const interval = publish.expiry_interval orelse return null;
    if (interval == 0) return 0;
    const elapsed = @max(now_ns - publish.stored_at_ns, 0);
    const expiry_ns = @as(i96, interval) * std.time.ns_per_s;
    if (elapsed >= expiry_ns) return 0;
    return interval - @as(u32, @intCast(
        @divTrunc(elapsed, std.time.ns_per_s),
    ));
}

const no_publish_expiry = std.math.maxInt(i96);
const no_inflight_send = std.math.maxInt(u16);

fn publishExpiryDeadline(publish: OwnedPublish) i96 {
    const interval = publish.expiry_interval orelse return no_publish_expiry;
    const lifetime_ns = @as(i96, interval) * std.time.ns_per_s;
    return std.math.add(i96, publish.stored_at_ns, lifetime_ns) catch
        no_publish_expiry;
}

fn notePublishExpiry(session: *Session, publish: OwnedPublish) void {
    session.next_publish_expiry_ns = @min(
        session.next_publish_expiry_ns,
        publishExpiryDeadline(publish),
    );
}

fn transmissionForInflight(
    inflight: Inflight,
    now_ns: i96,
) Transmission {
    return switch (inflight.state) {
        .await_puback, .await_pubrec => .{
            .publish = publishTransmission(inflight, now_ns),
        },
        .await_pubcomp => .{
            .pubrel = .{
                .packet_id = inflight.packet_id,
                .dup = inflight.retransmission,
            },
        },
    };
}

fn publishTransmission(
    inflight: Inflight,
    now_ns: i96,
) PublishTransmission {
    return .{
        .topic = inflight.publish.topic,
        .payload = inflight.publish.payload,
        .qos = inflight.publish.qos,
        .retain = inflight.publish.retain,
        .dup = inflight.retransmission,
        .packet_id = inflight.packet_id,
        .properties = inflight.publish.properties,
        .message_expiry_interval = remainingExpiry(
            inflight.publish,
            now_ns,
        ),
    };
}

fn appendOrReuse(
    comptime T: type,
    allocator: std.mem.Allocator,
    list: *std.ArrayList(?T),
    value: T,
) std.mem.Allocator.Error!usize {
    for (list.items, 0..) |maybe_value, index| {
        if (maybe_value == null) {
            list.items[index] = value;
            return index;
        }
    }
    try list.append(allocator, value);
    return list.items.len - 1;
}

fn appendOrReuseAssumeCapacity(
    comptime T: type,
    list: *std.ArrayList(?T),
    value: T,
) usize {
    for (list.items, 0..) |maybe_value, index| {
        if (maybe_value == null) {
            list.items[index] = value;
            return index;
        }
    }
    list.appendAssumeCapacity(value);
    return list.items.len - 1;
}

test "Session store tracks persistent sessions across lifetime changes" {
    var store = Store.init(std.testing.allocator, .{ .max_sessions = 4 });
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.persistentCount());

    const transient = try store.open("transient", true, 0, .zero);
    try std.testing.expectEqual(@as(usize, 0), store.persistentCount());

    _ = try store.open("durable", false, 60, .zero);
    try std.testing.expectEqual(@as(usize, 1), store.persistentCount());
    const resumed = try store.open("durable", false, 0, .zero);
    try std.testing.expect(resumed.session_present);
    try std.testing.expectEqual(@as(usize, 0), store.persistentCount());
    try store.disconnect(resumed.handle, null, .zero);

    _ = try store.open("durable", true, 60, .zero);
    try std.testing.expectEqual(@as(usize, 1), store.persistentCount());
    _ = try store.open("durable", true, 60, .zero);
    try std.testing.expectEqual(@as(usize, 1), store.persistentCount());
    try std.testing.expect(store.discard("durable"));
    try std.testing.expectEqual(@as(usize, 0), store.persistentCount());

    try store.disconnect(transient.handle, null, .zero);
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "Session publish expiry deadline skips and repairs scans" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const opened = try store.open("expiry-deadline", false, 60, .zero);
    _ = try store.enqueuePublish(
        opened.handle,
        "unbounded",
        "value",
        .{ .qos = .at_least_once, .now = .zero },
    );
    const session = try store.getSession(opened.handle);
    try std.testing.expectEqual(
        no_publish_expiry,
        session.next_publish_expiry_ns,
    );

    var one_second = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 1,
    } }};
    var three_seconds = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 3,
    } }};
    _ = try store.enqueuePublish(
        opened.handle,
        "first",
        "value",
        .{
            .qos = .at_least_once,
            .properties = &one_second,
            .now = .zero,
        },
    );
    _ = try store.enqueuePublish(
        opened.handle,
        "second",
        "value",
        .{
            .qos = .at_least_once,
            .properties = &three_seconds,
            .now = .zero,
        },
    );
    try std.testing.expectEqual(
        @as(i96, std.time.ns_per_s),
        session.next_publish_expiry_ns,
    );
    try std.testing.expect(!store.pruneExpiredPublishes(
        session,
        std.time.ns_per_s - 1,
    ));
    try std.testing.expect(store.pruneExpiredPublishes(
        session,
        std.time.ns_per_s,
    ));
    try std.testing.expectEqual(@as(usize, 2), session.queued_count);
    try std.testing.expectEqual(
        @as(i96, 3 * std.time.ns_per_s),
        session.next_publish_expiry_ns,
    );
    try std.testing.expect(store.pruneExpiredPublishes(
        session,
        3 * std.time.ns_per_s,
    ));
    try std.testing.expectEqual(@as(usize, 1), session.queued_count);
    try std.testing.expectEqual(
        no_publish_expiry,
        session.next_publish_expiry_ns,
    );
}

test "Session fanout can share immutable publication bytes" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{ .max_sessions = 2 });
    defer store.deinit();
    const first = try store.open("shared-first", false, 60, .zero);
    const second = try store.open("shared-second", false, 60, .zero);

    const publication = try SharedPublication.createFromPublish(
        allocator,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "shared/topic",
            .packet_id = 7,
            .properties = &.{},
            .payload = "shared-payload",
        },
        1,
        .zero,
    );
    var publication_owned = true;
    defer if (publication_owned) publication.release();
    var first_changed = false;
    var second_changed = false;
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(
        first.handle,
        publication,
        .{ .qos = .exactly_once, .now = .zero },
        &first_changed,
    );
    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(
        second.handle,
        publication,
        .{ .qos = .at_least_once, .now = .zero },
        &second_changed,
    );
    publication.release();
    publication_owned = false;

    var first_output: [1]Transmission = undefined;
    var second_output: [1]Transmission = undefined;
    const first_delivery = try store.drainInto(
        first.handle,
        .zero,
        1,
        &first_output,
    );
    const second_delivery = try store.drainInto(
        second.handle,
        .zero,
        1,
        &second_output,
    );
    try std.testing.expect(first_changed);
    try std.testing.expect(second_changed);
    try std.testing.expectEqual(@as(usize, 1), first_delivery.len);
    try std.testing.expectEqual(@as(usize, 1), second_delivery.len);
    try std.testing.expectEqualStrings(
        "shared/topic",
        first_delivery[0].publish.topic,
    );
    try std.testing.expectEqualStrings(
        "shared-payload",
        second_delivery[0].publish.payload,
    );
    try std.testing.expectEqual(
        first_delivery[0].publish.topic.ptr,
        second_delivery[0].publish.topic.ptr,
    );
    try std.testing.expectEqual(
        first_delivery[0].publish.payload.ptr,
        second_delivery[0].publish.payload.ptr,
    );
    try std.testing.expectEqual(
        mqtt.QoS.exactly_once,
        first_delivery[0].publish.qos,
    );
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        second_delivery[0].publish.qos,
    );
}

test "Session shared fanout removes per-destination wire allocations" {
    const session_count = 8;
    const options: Options = .{
        .max_sessions = session_count,
        .max_queued_per_session = 1,
    };
    const publish = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "shared/allocation/topic",
        .packet_id = 1,
        .properties = &.{},
        .payload = "shared-allocation-payload",
    };

    var independent_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var independent = Store.init(
        independent_allocator.allocator(),
        options,
    );
    defer independent.deinit();
    var independent_handles: [session_count]Handle = undefined;
    for (&independent_handles, 0..) |*handle, index| {
        var client_id: [32]u8 = undefined;
        handle.* = (try independent.open(
            try std.fmt.bufPrint(&client_id, "independent-{d}", .{index}),
            false,
            60,
            .zero,
        )).handle;
    }
    const independent_before = independent_allocator.allocations;
    for (independent_handles) |handle| {
        _ = try independent.enqueuePublish(
            handle,
            publish.topic,
            publish.payload,
            .{ .qos = publish.qos, .now = .zero },
        );
    }
    const independent_allocations =
        independent_allocator.allocations - independent_before;

    var shared_allocator = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var shared = Store.init(
        shared_allocator.allocator(),
        options,
    );
    defer shared.deinit();
    var shared_handles: [session_count]Handle = undefined;
    for (&shared_handles, 0..) |*handle, index| {
        var client_id: [32]u8 = undefined;
        handle.* = (try shared.open(
            try std.fmt.bufPrint(&client_id, "shared-{d}", .{index}),
            false,
            60,
            .zero,
        )).handle;
    }
    const shared_before = shared_allocator.allocations;
    const publication = try SharedPublication.createFromPublish(
        shared_allocator.allocator(),
        publish,
        1,
        .zero,
    );
    for (shared_handles) |handle| {
        var changed = false;
        _ = try shared.enqueueSharedPublicationTrackingSnapshotChange(
            handle,
            publication,
            .{ .qos = publish.qos, .now = .zero },
            &changed,
        );
        try std.testing.expect(changed);
    }
    publication.release();
    const shared_allocations = shared_allocator.allocations - shared_before;

    try std.testing.expectEqual(
        independent_allocations - (session_count - 1),
        shared_allocations,
    );
}

test "Session queue cursor releases a fully consumed prefix" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const opened = try store.open("queue-cursor", false, 60, .zero);
    for (0..3) |index| {
        var topic_buffer: [32]u8 = undefined;
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "cursor/{d}",
            .{index},
        );
        _ = try store.enqueuePublish(opened.handle, topic, "value", .{
            .qos = .at_least_once,
            .now = .zero,
        });
    }

    var output: [1]Transmission = undefined;
    const first = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    const session = try store.getSession(opened.handle);
    try std.testing.expect(try store.hasUnselectedTransmission(opened.handle));
    try std.testing.expectEqual(@as(usize, 1), session.queued_head);
    try std.testing.expectEqual(@as(usize, 2), session.queued_count);
    _ = try store.handleAck(
        opened.handle,
        .puback,
        first[0].publish.packet_id,
        0,
    );

    for (0..2) |_| {
        const next = try store.drainInto(
            opened.handle,
            .zero,
            1,
            &output,
        );
        _ = try store.handleAck(
            opened.handle,
            .puback,
            next[0].publish.packet_id,
            0,
        );
    }
    try std.testing.expect(!try store.hasUnselectedTransmission(opened.handle));
    try std.testing.expectEqual(@as(usize, 0), session.queued_head);
    try std.testing.expectEqual(@as(usize, 0), session.queued.items.len);
}

test "Session unselected transmission tracks the QoS 2 handshake" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const opened = try store.open("pending-qos2", false, 60, .zero);
    _ = try store.enqueuePublish(
        opened.handle,
        "pending/qos2",
        "value",
        .{ .qos = .exactly_once, .now = .zero },
    );
    try std.testing.expect(try store.hasUnselectedTransmission(opened.handle));

    var output: [1]Transmission = undefined;
    const publish = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(@as(usize, 1), publish.len);
    try std.testing.expect(!try store.hasUnselectedTransmission(opened.handle));

    const packet_id = publish[0].publish.packet_id;
    try std.testing.expectEqual(
        AckAction.send_pubrel,
        try store.handleAck(opened.handle, .pubrec, packet_id, 0),
    );
    try std.testing.expect(try store.hasUnselectedTransmission(opened.handle));

    const pubrel = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(@as(usize, 1), pubrel.len);
    try std.testing.expect(pubrel[0] == .pubrel);
    try std.testing.expect(!try store.hasUnselectedTransmission(opened.handle));
}

test {
    _ = @import("tests.zig");
    _ = @import("ack_tests.zig");
    _ = @import("open_tests.zig");
    _ = @import("expiry_inspection_tests.zig");
}

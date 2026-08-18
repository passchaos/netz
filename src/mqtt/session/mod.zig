//! Bounded MQTT server Session State for reconnect and offline delivery.
//!
//! Sessions are addressed by generation-checked handles, so callers never hold
//! pointers invalidated by table growth. All variable-length protocol data is
//! deeply owned. Queue/inflight scans write borrowed views into caller storage
//! and allocate only when a previously unsent message moves into inflight.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");

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
    max_inflight_per_session: usize = std.math.maxInt(u16),
    max_incoming_qos2_per_session: usize = 16_384,
    max_session_bytes: usize = 64 * 1024 * 1024,
    max_total_bytes: usize = 1024 * 1024 * 1024,
};

pub const Handle = struct {
    index: usize,
    generation: u64,
};

pub const OpenResult = struct {
    handle: Handle,
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
    inflight_count: usize,
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
                .dup = self.dup,
                .packet_id = self.packet_id,
                .properties = properties.items,
            },
        );
    }
};

pub const PubRelTransmission = struct {
    packet_id: u16,

    pub fn write(
        self: PubRelTransmission,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
    ) Error!void {
        try mqtt.AckPacket.write(
            list,
            allocator,
            protocol,
            .pubrel,
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
    topic: []u8,
    payload: []u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []mqtt.Property,
    stored_at_ns: i96,
    expiry_interval: ?u32,
    allocation_bytes: usize,

    fn deinit(self: *OwnedPublish, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.payload);
        allocator.free(self.topic);
        self.* = undefined;
    }
};

const InflightState = enum {
    await_puback,
    await_pubrec,
    await_pubcomp,
};

const Inflight = struct {
    publish: OwnedPublish,
    packet_id: u16,
    state: InflightState,
    needs_send: bool,
    retransmission: bool,
};

const Session = struct {
    generation: u64,
    client_id: []u8,
    connected: bool,
    expiry_interval: u32,
    expires_at_ns: ?i96,
    subscriptions: std.ArrayList(?OwnedSubscription) = .empty,
    subscription_count: usize = 0,
    queued: std.ArrayList(?OwnedPublish) = .empty,
    queued_count: usize = 0,
    inflight: std.ArrayList(?Inflight) = .empty,
    inflight_count: usize = 0,
    packet_index: std.AutoHashMapUnmanaged(u16, usize) = .empty,
    incoming_qos2: std.AutoHashMapUnmanaged(u16, void) = .empty,
    next_packet_id: u16 = 1,
    allocation_bytes: usize,

    fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        for (self.subscriptions.items) |*maybe_subscription| {
            if (maybe_subscription.*) |*subscription| {
                subscription.deinit(allocator);
            }
        }
        self.subscriptions.deinit(allocator);
        for (self.queued.items) |*maybe_publish| {
            if (maybe_publish.*) |*publish| publish.deinit(allocator);
        }
        self.queued.deinit(allocator);
        for (self.inflight.items) |*maybe_inflight| {
            if (maybe_inflight.*) |*inflight| {
                inflight.publish.deinit(allocator);
            }
        }
        self.inflight.deinit(allocator);
        self.packet_index.deinit(allocator);
        self.incoming_qos2.deinit(allocator);
        allocator.free(self.client_id);
        self.* = undefined;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    options: Options,
    sessions: std.ArrayList(?Session) = .empty,
    client_index: std.StringHashMapUnmanaged(usize) = .empty,
    session_count: usize = 0,
    total_bytes: usize = 0,
    next_generation: u64 = 1,

    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) Store {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *Store) void {
        for (self.sessions.items) |*maybe_session| {
            if (maybe_session.*) |*session| {
                session.deinit(self.allocator);
            }
        }
        self.sessions.deinit(self.allocator);
        self.client_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Store) usize {
        return self.session_count;
    }

    pub fn totalBytes(self: Store) usize {
        return self.total_bytes;
    }

    pub fn expiryForConnect(
        protocol: mqtt.ProtocolVersion,
        clean_start: bool,
        properties: []const mqtt.Property,
    ) u32 {
        return switch (protocol) {
            .v5 => mqtt.sessionExpiryInterval(properties) orelse 0,
            // MQTT 3.1.1 CleanSession=0 has no timer and therefore persists
            // until an administrative action or a later clean connection.
            .v3_1_1 => if (clean_start) 0 else std.math.maxInt(u32),
        };
    }

    pub fn open(
        self: *Store,
        client_id: []const u8,
        clean_start: bool,
        expiry_interval: u32,
        now: std.Io.Timestamp,
    ) Error!OpenResult {
        if (client_id.len == 0 and !clean_start) {
            return error.InvalidClientId;
        }
        var replaced_connection = false;
        if (self.client_index.get(client_id)) |index| {
            if (self.isExpired(self.sessions.items[index].?, now)) {
                self.removeAt(index);
            }
        }
        if (clean_start) {
            if (self.client_index.get(client_id)) |index| {
                replaced_connection = self.sessions.items[index].?.connected;
                self.removeAt(index);
            }
        } else if (self.client_index.get(client_id)) |index| {
            const generation = self.nextGeneration();
            const session = &self.sessions.items[index].?;
            replaced_connection = session.connected;
            // Every resumed/takeover Network Connection gets a fresh handle.
            // This immediately invalidates the old connection's capability to
            // mutate the shared Session after broker takeover.
            session.generation = generation;
            session.connected = true;
            session.expiry_interval = expiry_interval;
            session.expires_at_ns = null;
            for (session.inflight.items) |*maybe_inflight| {
                if (maybe_inflight.*) |*inflight| {
                    inflight.needs_send = true;
                    inflight.retransmission = true;
                }
            }
            return .{
                .handle = .{
                    .index = index,
                    .generation = session.generation,
                },
                .session_present = true,
                .replaced_connection = replaced_connection,
            };
        }

        if (self.session_count >= self.options.max_sessions) {
            return error.SessionLimitExceeded;
        }
        const client_owned = try self.allocator.dupe(u8, client_id);
        errdefer self.allocator.free(client_owned);
        if (client_owned.len > self.options.max_session_bytes or
            client_owned.len > self.options.max_total_bytes -|
                self.total_bytes)
        {
            return error.SessionByteLimitExceeded;
        }
        try self.client_index.ensureUnusedCapacity(self.allocator, 1);
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
            .client_id = client_owned,
            .connected = true,
            .expiry_interval = expiry_interval,
            .expires_at_ns = null,
            .allocation_bytes = client_owned.len,
        };
        self.client_index.putAssumeCapacityNoClobber(
            client_owned,
            index,
        );
        self.session_count += 1;
        self.total_bytes += client_owned.len;
        return .{
            .handle = .{ .index = index, .generation = generation },
            .session_present = false,
            .replaced_connection = replaced_connection,
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

    pub fn disconnect(
        self: *Store,
        handle: Handle,
        expiry_override: ?u32,
        now: std.Io.Timestamp,
    ) Error!void {
        const session = try self.getSession(handle);
        if (expiry_override) |new_expiry| {
            if (session.expiry_interval == 0 and new_expiry != 0) {
                return error.InvalidProperty;
            }
            session.expiry_interval = new_expiry;
        }
        if (session.expiry_interval == 0) {
            self.removeAt(handle.index);
            return;
        }
        session.connected = false;
        session.expires_at_ns = expiryDeadline(
            now.nanoseconds,
            session.expiry_interval,
        );
        for (session.inflight.items) |*maybe_inflight| {
            if (maybe_inflight.*) |*inflight| {
                inflight.needs_send = true;
                inflight.retransmission = true;
            }
        }
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
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.sessions.items.len) : (index += 1) {
            const session = self.sessions.items[index] orelse continue;
            if (!self.isExpired(session, now)) continue;
            self.removeAt(index);
            removed += 1;
        }
        return removed;
    }

    pub fn setSubscription(
        self: *Store,
        handle: Handle,
        subscription: mqtt.Subscription,
        subscription_identifier: ?usize,
    ) Error!bool {
        try mqtt.validateTopicFilter(subscription.topic_filter);
        if (subscription.retain_handling > 2 or
            (subscription.no_local and std.mem.startsWith(
                u8,
                subscription.topic_filter,
                "$share/",
            )))
        {
            return error.InvalidSubscription;
        }
        if (subscription_identifier) |identifier| {
            if (identifier == 0 or identifier > 268_435_455) {
                return error.InvalidProperty;
            }
        }
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
        return .{
            .connected = session.connected,
            .expiry_interval = session.expiry_interval,
            .subscription_count = session.subscription_count,
            .queued_count = session.queued_count,
            .inflight_count = session.inflight_count,
            .incoming_qos2_count = session.incoming_qos2.count(),
            .owned_wire_bytes = session.allocation_bytes,
        };
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
        options: struct {
            qos: mqtt.QoS,
            retain: bool = false,
            properties: []const mqtt.Property = &.{},
            now: std.Io.Timestamp,
        },
    ) Error!EnqueueResult {
        if (options.qos == .at_most_once) return error.InvalidQoS;
        try mqtt.validateTopicName(topic);
        try mqtt.validatePublishProperties(options.properties);
        try validateQueuedPayload(options.properties, payload);
        if (mqtt.topicAlias(options.properties) != null) {
            // Alias mappings are scoped to a Network Connection and cannot be
            // replayed from persistent Session State.
            return error.InvalidProperty;
        }
        const session = try self.getSession(handle);
        if (session.queued_count >= self.options.max_queued_per_session) {
            return error.QueueFull;
        }
        if (mqtt.messageExpiryInterval(options.properties) == 0) {
            return .expired;
        }
        var publish = try clonePublish(
            self.allocator,
            topic,
            payload,
            options.qos,
            options.retain,
            options.properties,
            options.now.nanoseconds,
        );
        errdefer publish.deinit(self.allocator);
        try self.ensureBytes(session, publish.allocation_bytes);
        if (session.queued.items.len >=
            self.options.max_queued_per_session)
        {
            compactQueue(session);
        }
        try session.queued.append(self.allocator, publish);
        session.queued_count += 1;
        session.allocation_bytes += publish.allocation_bytes;
        self.total_bytes += publish.allocation_bytes;
        publish = undefined;
        return .queued;
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
        if (receive_maximum == 0) return error.InvalidProperty;
        const session = try self.getSession(handle);
        self.pruneExpiredPublishes(session, now.nanoseconds);
        var written: usize = 0;
        var publish_window_used = countSentPublishInflight(session.*);
        for (session.inflight.items) |*maybe_inflight| {
            if (written == out.len) break;
            const inflight = &(maybe_inflight.* orelse continue);
            if (!inflight.needs_send) continue;
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
                continue;
            }
            out[written] = transmission;
            inflight.needs_send = false;
            publish_window_used += @intFromBool(
                transmission == .publish,
            );
            written += 1;
        }
        if (written == out.len) return out[0..written];

        var available = @as(usize, receive_maximum) -|
            @min(@as(usize, receive_maximum), publish_window_used);
        available = @min(available, out.len - written);
        available = @min(available, session.queued_count);
        if (available == 0) return out[0..written];
        const max_inflight = @min(
            self.options.max_inflight_per_session,
            @as(usize, std.math.maxInt(u16)),
        );
        if (session.inflight_count + available > max_inflight) {
            return error.InflightFull;
        }
        try session.packet_index.ensureUnusedCapacity(
            self.allocator,
            @intCast(available),
        );
        const append_needed = @max(
            available - countNullSlots(Inflight, session.inflight.items),
            0,
        );
        try session.inflight.ensureUnusedCapacity(
            self.allocator,
            append_needed,
        );

        var queue_index: usize = 0;
        while (available != 0 and
            queue_index < session.queued.items.len)
        {
            if (session.queued.items[queue_index]) |publish_value| {
                var publish = publish_value;
                session.queued.items[queue_index] = null;
                session.queued_count -= 1;
                const packet_id = try reservePacketId(session);
                const state: InflightState = switch (publish.qos) {
                    .at_least_once => .await_puback,
                    .exactly_once => .await_pubrec,
                    .at_most_once => unreachable,
                };
                const inflight_index = appendOrReuseAssumeCapacity(
                    Inflight,
                    &session.inflight,
                    .{
                        .publish = publish,
                        .packet_id = packet_id,
                        .state = state,
                        .needs_send = false,
                        .retransmission = false,
                    },
                );
                session.packet_index.putAssumeCapacityNoClobber(
                    packet_id,
                    inflight_index,
                );
                session.inflight_count += 1;
                out[written] = .{ .publish = publishTransmission(
                    session.inflight.items[inflight_index].?,
                    now.nanoseconds,
                ) };
                written += 1;
                available -= 1;
                publish = undefined;
            }
            queue_index += 1;
        }
        return out[0..written];
    }

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
        const inflight = &session.inflight.items[index].?;
        switch (packet_type) {
            .puback => {
                if (inflight.state != .await_puback) {
                    return error.InvalidAcknowledgement;
                }
                self.removeInflight(session, index);
                return .completed;
            },
            .pubrec => {
                if (inflight.state != .await_pubrec) {
                    return error.InvalidAcknowledgement;
                }
                if (reason_code >= 0x80) {
                    self.removeInflight(session, index);
                    return .completed;
                }
                inflight.state = .await_pubcomp;
                inflight.needs_send = true;
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

    pub fn recordIncomingQoS2(
        self: *Store,
        handle: Handle,
        packet_id: u16,
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
            {},
        );
        return false;
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
        self.sessions.items[index] = null;
        self.session_count -= 1;
        self.total_bytes -= session.allocation_bytes;
        session.deinit(self.allocator);
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

    fn pruneExpiredPublishes(
        self: *Store,
        session: *Session,
        now_ns: i96,
    ) void {
        for (session.queued.items) |*maybe_publish| {
            if (maybe_publish.*) |publish| {
                if (remainingExpiry(publish, now_ns) != 0) continue;
                var removed = publish;
                maybe_publish.* = null;
                session.queued_count -= 1;
                session.allocation_bytes -= removed.allocation_bytes;
                self.total_bytes -= removed.allocation_bytes;
                removed.deinit(self.allocator);
            }
        }
        var index: usize = 0;
        while (index < session.inflight.items.len) : (index += 1) {
            const inflight = session.inflight.items[index] orelse continue;
            if (inflight.state == .await_pubcomp or
                remainingExpiry(inflight.publish, now_ns) != 0)
            {
                continue;
            }
            self.removeInflight(session, index);
        }
    }

    fn removeInflight(
        self: *Store,
        session: *Session,
        index: usize,
    ) void {
        var inflight = session.inflight.items[index].?;
        session.inflight.items[index] = null;
        _ = session.packet_index.fetchRemove(inflight.packet_id).?;
        session.inflight_count -= 1;
        session.allocation_bytes -= inflight.publish.allocation_bytes;
        self.total_bytes -= inflight.publish.allocation_bytes;
        inflight.publish.deinit(self.allocator);
    }
};

fn clonePublish(
    allocator: std.mem.Allocator,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
    now_ns: i96,
) Error!OwnedPublish {
    const topic_owned = try allocator.dupe(u8, topic);
    errdefer allocator.free(topic_owned);
    const payload_owned = try allocator.dupe(u8, payload);
    errdefer allocator.free(payload_owned);
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
        topic_owned.len + payload_owned.len,
        property_result.allocation_bytes,
    ) catch return error.SessionByteLimitExceeded;
    return .{
        .topic = topic_owned,
        .payload = payload_owned,
        .qos = qos,
        .retain = retain,
        .properties = property_result.properties,
        .stored_at_ns = now_ns,
        .expiry_interval = mqtt.messageExpiryInterval(properties),
        .allocation_bytes = bytes,
    };
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
    for (session.queued.items) |maybe_publish| {
        const publish = maybe_publish orelse continue;
        session.queued.items[write_index] = publish;
        write_index += 1;
    }
    session.queued.items.len = write_index;
    std.debug.assert(write_index == session.queued_count);
}

fn countSentPublishInflight(session: Session) usize {
    var count: usize = 0;
    for (session.inflight.items) |maybe_inflight| {
        const inflight = maybe_inflight orelse continue;
        if (inflight.state == .await_pubcomp) continue;
        if (!inflight.needs_send) count += 1;
    }
    return count;
}

fn validateQueuedPayload(
    properties: []const mqtt.Property,
    payload: []const u8,
) Error!void {
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

fn transmissionForInflight(
    inflight: Inflight,
    now_ns: i96,
) Transmission {
    return switch (inflight.state) {
        .await_puback, .await_pubrec => .{
            .publish = publishTransmission(inflight, now_ns),
        },
        .await_pubcomp => .{
            .pubrel = .{ .packet_id = inflight.packet_id },
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

fn reservePacketId(session: *Session) Error!u16 {
    var attempts: usize = 0;
    while (attempts < std.math.maxInt(u16)) : (attempts += 1) {
        const packet_id = session.next_packet_id;
        session.next_packet_id +%= 1;
        if (session.next_packet_id == 0) session.next_packet_id = 1;
        if (!session.packet_index.contains(packet_id)) return packet_id;
    }
    return error.InflightFull;
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

fn countNullSlots(comptime T: type, items: []const ?T) usize {
    var count: usize = 0;
    for (items) |item| count += @intFromBool(item == null);
    return count;
}

test {
    _ = @import("tests.zig");
}

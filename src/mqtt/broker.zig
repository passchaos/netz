//! Bounded in-memory MQTT broker core.
//!
//! This module composes the transport-independent connection runtime with the
//! topic router and bounded retained, Session, QoS 2, and Will state. It
//! focuses on the live broker hot path: SUBSCRIBE/UNSUBSCRIBE, QoS 0/1/2
//! routing, offline Session queueing, reconnect retransmission, No Local/shared
//! selection, downstream acknowledgements, and connection cleanup.

const std = @import("std");
const mqtt = @import("mod.zig");
const owned_properties = @import("owned_properties.zig");
const router_mod = @import("router.zig");
const runtime = @import("runtime.zig");
const client_id_mod = @import("broker/client_id.zig");
const persistence_mod = @import("persistence/mod.zig");
const commit_log_mod = persistence_mod.commit_log;
const qos2_mod = @import("broker/qos2.zig");
const publication_mod = @import("broker/publication.zig");
const session_delivery = @import("broker/session_delivery.zig");
const session_route = @import("broker/session_route.zig");
const deadline_driver_mod = @import("broker/deadline_driver.zig");
const retained_mod = @import("retained/mod.zig");
const session_mod = @import("session/mod.zig");
const will_mod = @import("will/mod.zig");

const net = std.Io.net;

pub const Error = runtime.Error || router_mod.Error ||
    retained_mod.Error || publication_mod.Error || qos2_mod.Error ||
    session_mod.Error || will_mod.Error || persistence_mod.Error ||
    commit_log_mod.Error ||
    std.Io.RandomSecureError || error{
    BrokerFull,
    ClientNotRegistered,
    ClientOffline,
    CommitLogAlreadyEnabled,
};

pub const PendingQoS2Store = qos2_mod.Store;

pub const Limits = struct {
    max_connections: usize = 1024,
    max_queued_deliveries_per_connection: usize = 256,
    /// Maximum MQTT Application Message payload in bytes; zero is unlimited.
    ///
    /// This is intentionally distinct from `runtime.max_packet_size`: packet
    /// size bounds transport memory, while this policy can reject or discard
    /// a large payload without penalizing its Topic Name or MQTT 5 properties.
    /// It mirrors Mosquitto's `message_size_limit` and rumqttd's
    /// `max_payload_size`.
    max_payload_size: usize = 0,
    /// Aggregate cap for inbound QoS 2 Application Messages awaiting PUBREL.
    ///
    /// Per-connection Receive Maximum remains enforced by `runtime.Connection`;
    /// this independent broker-wide bound prevents many clients from turning
    /// valid-but-stalled handshakes into unbounded owned payload memory.
    max_pending_incoming_qos2: usize = 4096,
    runtime: runtime.Limits = .{},
};

pub const Options = struct {
    limits: Limits = .{},
    /// Prefix for broker-assigned Client Identifiers. Copied by `listen`.
    ///
    /// Mosquitto limits `auto_id_prefix` to 50 bytes; matching that cap keeps
    /// the generated identifier below MQTT's u16 UTF-8 string bound.
    auto_client_id_prefix: []const u8 = "netz-",
    router: router_mod.Options = .{},
    retained: retained_mod.Options = .{},
    session: session_mod.Options = .{},
    will: will_mod.Options = .{},
    /// Mosquitto-compatible opt-in that sends messages at the subscription
    /// QoS even when that raises the publisher's original QoS. MQTT otherwise
    /// requires min(source QoS, granted subscription QoS), which remains the
    /// default.
    upgrade_outgoing_qos: bool = false,
    /// Mosquitto-compatible opt-in for retaining QoS 0 Application Messages
    /// while a persistent Session is offline. The MQTT-oriented default drops
    /// those messages because delivery has no reliability guarantee.
    queue_qos0_messages: bool = false,
    accept: runtime.AcceptOptions = .{
        .protocol = .v5,
        .max_outgoing_inflight = 64,
    },
    /// Optional policy for MQTT 5 re-authentication AUTH packets received by
    /// the live broker event loop.
    authentication: ?AuthenticationHandler = null,
    /// Optional CONNECT authorization evaluated before Session, Will, or
    /// routing state is created. This covers MQTT 3.1.1/5 username/password
    /// policy; Enhanced Authentication remains owned by `authentication`.
    connect_authorization: ?ConnectAuthorizationHandler = null,
    /// Optional per-client checks for incoming PUBLISH, SUBSCRIBE, and
    /// UNSUBSCRIBE packets plus outgoing Application Message delivery.
    /// Callbacks can run concurrently and receive borrowed views. They must
    /// not re-enter this Broker: delivery checks run under its state lock so
    /// routing and Session admission remain one atomic authorization decision.
    /// Incoming denials precede retained, Session, and router mutation;
    /// outgoing denials precede the destination's queue mutation.
    access_control: ?AccessControlHandler = null,
    /// Optional diagnostics attached to broker-generated negative PUBLISH,
    /// SUBSCRIBE, and UNSUBSCRIBE acknowledgements. The runtime filters them
    /// when CONNECT requested no Problem Information. `Broker.listen`
    /// deep-copies the property array and all referenced strings.
    problem_information: []const mqtt.Property = &.{},
};

pub const ConnectAuthorizationHandler = struct {
    context: *anyopaque,
    /// `connect` and all of its slices are borrowed for this call only.
    authorize: *const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
    ) bool,
};

pub const AccessControlHandler = struct {
    context: *anyopaque,
    authorize_publish: *const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool,
    authorize_subscribe: *const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        subscription: mqtt.Subscription,
    ) bool,
    authorize_unsubscribe: ?*const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        topic_filter: []const u8,
    ) bool = null,
    authorize_delivery: ?*const fn (
        context: *anyopaque,
        delivery: DeliveryAuthorization,
    ) bool = null,
    authorize_will: ?*const fn (
        context: *anyopaque,
        publication: WillAuthorization,
    ) bool = null,
};

/// Borrowed recipient and Application Message metadata for an outgoing ACL.
/// The packet identifier is intentionally absent because this authorization
/// precedes Session/inflight allocation and applies equally to QoS 0.
pub const DeliveryAuthorization = struct {
    client_id: []const u8,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
};

/// Borrowed source and Application Message metadata for a Will write ACL.
/// The callback runs when the Will becomes due, not when CONNECT registers it,
/// so a policy update during Will Delay can suppress publication.
pub const WillAuthorization = struct {
    client_id: []const u8,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
};

pub const AuthenticationHandler = struct {
    context: *anyopaque,
    /// Complete any CONNECT-before-CONNACK exchange and call
    /// `pending.authorizeAuthentication()` only after policy success.
    start: *const fn (
        context: *anyopaque,
        pending: *runtime.PendingAcceptedClient,
    ) Error!void,
    handle: *const fn (
        context: *anyopaque,
        connection: *runtime.Connection,
        auth: mqtt.Auth,
        complete: bool,
    ) Error!void,
};

const Publication = publication_mod.Publication;

const Delivery = struct {
    publication: *Publication,
    qos: mqtt.QoS,
    retain: bool,
    subscription_identifier: ?usize = null,
    additional_subscription_identifiers: []usize = &.{},

    fn deinit(self: *Delivery) void {
        if (self.additional_subscription_identifiers.len != 0) {
            self.publication.allocator.free(
                self.additional_subscription_identifiers,
            );
        }
        self.publication.release();
        self.* = undefined;
    }

    fn appendSubscriptionIdentifier(
        self: *Delivery,
        allocator: std.mem.Allocator,
        identifier: ?usize,
    ) Error!void {
        const value = identifier orelse return;
        if (self.subscription_identifier == null) {
            self.subscription_identifier = value;
            return;
        }
        for (self.additional_subscription_identifiers) |existing| {
            if (existing == value) return;
        }
        const old = self.additional_subscription_identifiers;
        const replacement = try allocator.alloc(usize, old.len + 1);
        @memcpy(replacement[0..old.len], old);
        replacement[old.len] = value;
        if (old.len != 0) allocator.free(old);
        self.additional_subscription_identifiers = replacement;
    }

    fn identifiersInto(
        self: Delivery,
        out: []usize,
    ) []const usize {
        var count: usize = 0;
        if (self.subscription_identifier) |identifier| {
            out[count] = identifier;
            count += 1;
        }
        @memcpy(
            out[count..][0..self.additional_subscription_identifiers.len],
            self.additional_subscription_identifiers,
        );
        return out[0 .. count + self.additional_subscription_identifiers.len];
    }
};

const RoutePlan = struct {
    storage: []router_mod.Match,
    deliveries: []const router_mod.Match,
    session_targets: []const router_mod.Match,
    has_matching_subscriber: bool,
};

const Registration = struct {
    subscriber_id: router_mod.SubscriberId,
    replaced_owner_id: ?router_mod.SubscriberId,
};

const EncodedSessionPacket = struct {
    encoded: session_route.EncodedPacket,
    handle: session_mod.Handle,
    route_id: u64,

    fn deinit(self: *EncodedSessionPacket) void {
        self.encoded.deinit();
        self.* = undefined;
    }
};
const subscriberId = session_route.connectionSubscriberId;
const nextConnectionGeneration = session_route.nextConnectionGeneration;
const sessionSubscriberId = session_route.sessionSubscriberId;
const sessionRouteId = session_route.sessionRouteId;
const subscriberIndex = session_route.connectionIndex;

const ClientSlot = struct {
    generation: u32 = 0,
    active: bool = false,
    connection: ?runtime.Connection = null,
    will_handle: ?will_mod.Handle = null,
    session_handle: ?session_mod.Handle = null,
    session_present: bool = false,
    /// Whether Server Session State survives loss of this Network Connection.
    ///
    /// Transient sessions still use a stable route while connected, but live
    /// QoS 1/2 fanout can use the connection-local inflight state and one
    /// shared Publication. Durable sessions must instead deep-own each queued
    /// message so reconnect retransmission remains possible.
    session_persistent: bool = false,
    assigned_client_id_len: u8 = 0,
    assigned_client_id: [client_id_mod.max_len]u8 = undefined,
    graceful_disconnect: bool = false,
    writer_mutex: std.Io.Mutex = .init,
    queue: std.ArrayList(Delivery) = .empty,
    queue_head: usize = 0,
    // Used only while `state_mutex` is held. A route can select the same
    // client through overlapping subscriptions, so capacity must account for
    // every delivery in the plan before any queue is mutated.
    route_reservations: usize = 0,

    fn clearQueue(self: *ClientSlot) void {
        for (self.queue.items[self.queue_head..]) |*delivery| {
            delivery.deinit();
        }
        self.queue.clearRetainingCapacity();
        self.queue_head = 0;
    }

    fn queuedCount(self: ClientSlot) usize {
        return self.queue.items.len - self.queue_head;
    }

    fn popDelivery(self: *ClientSlot) ?Delivery {
        if (self.queue_head == self.queue.items.len) return null;
        const delivery = self.queue.items[self.queue_head];
        self.queue_head += 1;
        if (self.queue_head >= 64 and
            self.queue_head * 2 >= self.queue.items.len)
        {
            const remaining = self.queue.items.len - self.queue_head;
            if (remaining != 0) {
                std.mem.copyForwards(
                    Delivery,
                    self.queue.items[0..remaining],
                    self.queue.items[self.queue_head..],
                );
            }
            self.queue.items.len = remaining;
            self.queue_head = 0;
        }
        return delivery;
    }

    fn pushFront(self: *ClientSlot, delivery: Delivery) void {
        if (self.queue_head != 0) {
            self.queue_head -= 1;
            self.queue.items[self.queue_head] = delivery;
            return;
        }

        // `popDelivery` can compact consumed storage before the network write
        // reports InflightFull. Compaction leaves at least one unused element
        // of capacity, allowing the delivery to be restored without an
        // allocation or a fallible backpressure path.
        std.debug.assert(self.queue.items.len < self.queue.capacity);
        const old_len = self.queue.items.len;
        self.queue.appendAssumeCapacity(delivery);
        std.mem.copyBackwards(
            Delivery,
            self.queue.items[1 .. old_len + 1],
            self.queue.items[0..old_len],
        );
        self.queue.items[0] = delivery;
    }

    fn appendDeliveryAssumeCapacity(
        self: *ClientSlot,
        delivery: Delivery,
    ) void {
        // Consumed prefix storage is part of the bounded queue allocation. Use
        // it before growing logical length; this keeps the hot route path
        // allocation-free even if compaction has not reached its threshold.
        if (self.queue.items.len == self.queue.capacity and
            self.queue_head != 0)
        {
            const remaining = self.queuedCount();
            std.mem.copyForwards(
                Delivery,
                self.queue.items[0..remaining],
                self.queue.items[self.queue_head..],
            );
            self.queue.items.len = remaining;
            self.queue_head = 0;
        }
        std.debug.assert(self.queue.items.len < self.queue.capacity);
        self.queue.appendAssumeCapacity(delivery);
    }

    fn removePublication(self: *ClientSlot, publication: *Publication) usize {
        var removed: usize = 0;
        var index = self.queue_head;
        while (index < self.queue.items.len) {
            if (self.queue.items[index].publication != publication) {
                index += 1;
                continue;
            }
            var delivery = self.queue.orderedRemove(index);
            delivery.deinit();
            removed += 1;
        }
        if (self.queue_head == self.queue.items.len) {
            self.queue.clearRetainingCapacity();
            self.queue_head = 0;
        }
        return removed;
    }
};

/// A broker listener that accepts a configured, bounded number of live TCP
/// clients and routes between them until each disconnects.
pub const Broker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: runtime.Server,
    options: Options,
    router: router_mod.Router,
    pending_qos2: qos2_mod.Store,
    retained: retained_mod.Store,
    sessions: session_mod.Store,
    wills: will_mod.Scheduler,
    deadline_driver: deadline_driver_mod.Driver = .{},
    session_owners: std.AutoHashMapUnmanaged(
        u64,
        router_mod.SubscriberId,
    ) = .empty,
    will_publishers: will_mod.PublisherMap = .empty,
    slots: []ClientSlot,
    commit_log: ?commit_log_mod.Log = null,
    persistence_mutex: std.Io.Mutex = .init,
    state_mutex: std.Io.Mutex = .init,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: Options,
    ) Error!Broker {
        if (options.limits.max_connections == 0 or
            std.math.cast(
                u32,
                options.limits.max_connections,
            ) == null or
            options.limits.max_queued_deliveries_per_connection == 0 or
            options.limits.max_pending_incoming_qos2 == 0 or
            options.limits.max_pending_incoming_qos2 >
                std.math.maxInt(u32) or
            std.math.cast(u32, options.will.max_wills) == null or
            options.auto_client_id_prefix.len >
                client_id_mod.max_prefix_len)
        {
            return error.InvalidProperty;
        }
        try mqtt.validateUtf8String(options.auto_client_id_prefix);
        if (options.accept.response_information) |value| {
            if (value.len > std.math.maxInt(u16)) {
                return error.InvalidProperty;
            }
            try mqtt.validateUtf8String(value);
        }
        try validateProblemInformationProperties(
            options.problem_information,
        );
        const auto_client_id_prefix = try allocator.dupe(
            u8,
            options.auto_client_id_prefix,
        );
        errdefer allocator.free(auto_client_id_prefix);
        const response_information = if (options.accept.response_information) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (response_information) |value| allocator.free(value);
        var owned_options = options;
        owned_options.auto_client_id_prefix = auto_client_id_prefix;
        owned_options.accept.response_information = response_information;
        const problem_information = owned_properties.clone(
            allocator,
            options.problem_information,
            owned_properties.keepAll,
        ) catch |err| switch (err) {
            error.OwnedPropertyLimitExceeded => return error.InvalidProperty,
            else => |other| return other,
        };
        errdefer owned_properties.deinit(
            allocator,
            problem_information.properties,
        );
        owned_options.problem_information =
            problem_information.properties;
        const slots = try allocator.alloc(
            ClientSlot,
            options.limits.max_connections,
        );
        @memset(slots, .{});
        errdefer allocator.free(slots);
        var router = try router_mod.Router.initWithOptions(
            allocator,
            options.router,
        );
        errdefer router.deinit();
        var pending_qos2 = try qos2_mod.Store.init(
            allocator,
            options.limits.max_pending_incoming_qos2,
        );
        errdefer pending_qos2.deinit();
        var retained = retained_mod.Store.init(
            allocator,
            options.retained,
        );
        errdefer retained.deinit();
        var sessions = session_mod.Store.init(
            allocator,
            options.session,
        );
        errdefer sessions.deinit();
        var wills = will_mod.Scheduler.init(
            allocator,
            options.will,
        );
        errdefer wills.deinit();
        var session_owners: std.AutoHashMapUnmanaged(
            u64,
            router_mod.SubscriberId,
        ) = .empty;
        errdefer session_owners.deinit(allocator);
        try session_owners.ensureTotalCapacity(
            allocator,
            @intCast(options.limits.max_connections),
        );
        var will_publishers: will_mod.PublisherMap = .empty;
        errdefer will_publishers.deinit(allocator);
        try will_publishers.ensureTotalCapacity(
            allocator,
            @intCast(options.will.max_wills),
        );
        return .{
            .allocator = allocator,
            .io = io,
            .server = try runtime.Server.listen(
                allocator,
                io,
                bind_address,
                options.limits.runtime,
            ),
            .options = owned_options,
            .router = router,
            .pending_qos2 = pending_qos2,
            .retained = retained,
            .sessions = sessions,
            .wills = wills,
            .session_owners = session_owners,
            .will_publishers = will_publishers,
            .slots = slots,
        };
    }

    pub fn deinit(self: *Broker) void {
        for (self.slots) |*slot| {
            slot.clearQueue();
            slot.queue.deinit(self.allocator);
            if (slot.connection) |*connection| connection.close();
        }
        self.allocator.free(self.slots);
        self.allocator.free(self.options.auto_client_id_prefix);
        if (self.options.accept.response_information) |value| {
            self.allocator.free(value);
        }
        owned_properties.deinit(
            self.allocator,
            @constCast(self.options.problem_information),
        );
        self.session_owners.deinit(self.allocator);
        self.will_publishers.deinit(self.allocator);
        self.wills.deinit();
        self.sessions.deinit();
        self.retained.deinit();
        self.pending_qos2.deinit();
        self.router.deinit();
        self.server.deinit();
        if (self.commit_log) |*log| log.deinit();
        self.* = undefined;
    }

    pub fn address(self: Broker) net.IpAddress {
        return self.server.address();
    }

    /// Start a crash-tolerant append journal with the broker's current state.
    /// The initial state image is synced before the journal becomes visible.
    pub fn createCommitLog(
        self: *Broker,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: commit_log_mod.Options,
    ) Error!void {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        if (self.commit_log != null) return error.CommitLogAlreadyEnabled;

        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const encoded = try self.encodeLiveStateLocked(false);
        defer self.allocator.free(encoded);
        var log = try commit_log_mod.Log.createWithInitial(
            self.allocator,
            self.io,
            dir,
            sub_path,
            options,
            encoded,
        );
        errdefer log.deinit();
        self.commit_log = log;
    }

    /// Restore the latest complete transaction and keep its journal open.
    /// Torn final writes are truncated; corruption in complete data is fatal.
    pub fn restoreCommitLog(
        self: *Broker,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: commit_log_mod.Options,
    ) Error!void {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        if (self.commit_log != null) return error.CommitLogAlreadyEnabled;
        var log = try commit_log_mod.Log.open(
            self.allocator,
            self.io,
            dir,
            sub_path,
            options,
        );
        errdefer log.deinit();
        const encoded = try log.latestAlloc();
        defer self.allocator.free(encoded);

        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        try self.restoreEncodedStateLocked(encoded);
        self.commit_log = log;
        self.deadline_driver.notify(self.io);
    }

    /// Append and sync a coherent live-broker state generation.
    pub fn appendCommit(self: *Broker) Error!u64 {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        const log = &(self.commit_log orelse
            return error.CommitLogNotFound);
        const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            break :blk try self.encodeLiveStateLocked(false);
        };
        defer self.allocator.free(encoded);
        return log.append(encoded);
    }

    /// Replace prior journal history with one synced baseline generation.
    pub fn compactCommitLog(self: *Broker) Error!void {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        const log = &(self.commit_log orelse
            return error.CommitLogNotFound);
        const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            break :blk try self.encodeLiveStateLocked(false);
        };
        defer self.allocator.free(encoded);
        try log.reset(encoded);
    }

    fn appendCommitIfEnabled(self: *Broker) Error!void {
        return self.appendCommitModeIfEnabled(false);
    }

    fn appendProvisionalCommitIfEnabled(self: *Broker) Error!void {
        return self.appendCommitModeIfEnabled(true);
    }

    fn appendCommitModeIfEnabled(
        self: *Broker,
        allow_provisional_registration: bool,
    ) Error!void {
        if (self.commit_log == null) return;
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        const log = &self.commit_log.?;
        const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            break :blk try self.encodeLiveStateLocked(
                allow_provisional_registration,
            );
        };
        defer self.allocator.free(encoded);
        _ = try log.append(encoded);
    }

    /// Atomically persist retained messages and durable Session State.
    ///
    /// This strict API retains the original quiescent-only contract. Use
    /// `saveLiveSnapshot` for a running broker. Both variants encode under the
    /// state mutex and perform synchronous file I/O only after releasing it; a
    /// separate persistence mutex preserves call order between concurrent
    /// checkpoint writers.
    pub fn saveSnapshot(
        self: *Broker,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) Error!void {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            for (self.slots) |slot| {
                if (slot.active or slot.connection != null or
                    slot.queuedCount() != 0)
                {
                    return error.SnapshotBusy;
                }
            }
            if (self.session_owners.count() != 0 or
                self.will_publishers.count() != self.wills.count())
            {
                return error.SnapshotBusy;
            }
            break :blk try persistence_mod.encode(
                self.allocator,
                .{
                    .retained = &self.retained,
                    .sessions = &self.sessions,
                    .wills = &self.wills,
                    .will_publishers = &self.will_publishers,
                    .pending_qos2 = &self.pending_qos2,
                },
                std.Io.Clock.awake.now(self.io),
                std.Io.Clock.real.now(self.io),
            );
        };
        defer self.allocator.free(encoded);
        try persistence_mod.saveEncodedAtomic(
            self.io,
            dir,
            sub_path,
            encoded,
        );
    }

    /// Persist durable broker state while clients remain connected.
    ///
    /// The global state mutex freezes all durable ownership transitions while
    /// encoding deep-copies every persistent value. Outgoing Session frames
    /// are selected under this same mutex before their writer releases it, so
    /// a checkpoint falls cleanly before or after that selection; restoring
    /// any selected transaction retransmits it with DUP as MQTT requires. The
    /// expensive write, fsync, and atomic rename happen after traffic is
    /// unblocked. Callers can invoke this periodically to implement autosave;
    /// concurrent snapshot calls are serialized by `persistence_mutex`.
    ///
    /// Volatile per-connection queues are deliberately excluded. Durable QoS
    /// 1/2 fanout and opt-in queued QoS 0 live in Session State before a live
    /// flush begins, while transient-Session delivery and transient inbound
    /// QoS 2 do not survive a broker crash.
    pub fn saveLiveSnapshot(
        self: *Broker,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) Error!void {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            break :blk try self.encodeLiveStateLocked(false);
        };
        defer self.allocator.free(encoded);

        try persistence_mod.saveEncodedAtomic(
            self.io,
            dir,
            sub_path,
            encoded,
        );
    }

    fn encodeLiveStateLocked(
        self: *Broker,
        allow_provisional_registration: bool,
    ) Error![]u8 {
        for (self.slots) |slot| {
            // Registration becomes durable only once CONNACK succeeds and the
            // accepted connection is attached. Retrying while this short
            // transaction is in flight prevents a failed accept from
            // manufacturing Session Present after restart.
            if (!allow_provisional_registration and
                slot.active and slot.connection == null)
            {
                return error.SnapshotBusy;
            }
        }
        return persistence_mod.encodeLive(
            self.allocator,
            .{
                .retained = &self.retained,
                .sessions = &self.sessions,
                .wills = &self.wills,
                .will_publishers = &self.will_publishers,
                .pending_qos2 = &self.pending_qos2,
            },
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
    }

    /// Restore a snapshot before accepting clients and rebuild Session routes.
    ///
    /// Live connection, pending inbound QoS 2, and Will state cannot be merged
    /// safely with a database from another process generation, so restore is
    /// rejected unless those transient sets and the router are empty.
    pub fn restoreSnapshot(
        self: *Broker,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) Error!void {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const encoded = dir.readFileAlloc(
            self.io,
            sub_path,
            self.allocator,
            .limited(persistence_mod.max_snapshot_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => return error.SnapshotNotFound,
            else => |other| return other,
        };
        defer self.allocator.free(encoded);
        try self.restoreEncodedStateLocked(encoded);
        self.deadline_driver.notify(self.io);
    }

    fn restoreEncodedStateLocked(
        self: *Broker,
        encoded: []const u8,
    ) Error!void {
        for (self.slots) |slot| {
            if (slot.active) return error.SnapshotBusy;
        }
        if (self.router.subscriptionCount() != 0 or
            self.pending_qos2.count() != 0 or
            self.session_owners.count() != 0 or
            self.will_publishers.count() != 0)
        {
            return error.SnapshotBusy;
        }
        var restored = try persistence_mod.decode(
            self.allocator,
            encoded,
            self.options.retained,
            self.options.session,
            self.options.will,
            self.options.limits.max_pending_incoming_qos2,
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
        errdefer {
            restored.retained.deinit();
            restored.sessions.deinit();
            restored.wills.deinit();
            restored.will_publishers.deinit(self.allocator);
            restored.pending_qos2.deinit();
        }
        var staged_router = try router_mod.Router.initWithOptions(
            self.allocator,
            self.options.router,
        );
        errdefer staged_router.deinit();
        const route_ids = try self.allocator.alloc(
            u64,
            restored.sessions.count(),
        );
        defer self.allocator.free(route_ids);
        const restored_routes = try restored.sessions.routeIdsInto(route_ids);
        for (restored_routes) |route_id| {
            const handle = restored.sessions.handleForRouteId(
                route_id,
            ) orelse return error.CorruptSnapshot;
            try restoreSessionSubscriptionsFrom(
                self.allocator,
                &staged_router,
                &restored.sessions,
                handle,
                route_id,
            );
        }
        self.retained.swap(&restored.retained);
        self.sessions.swap(&restored.sessions);
        self.wills.swap(&restored.wills);
        self.pending_qos2.swap(&restored.pending_qos2);
        std.mem.swap(
            will_mod.PublisherMap,
            &self.will_publishers,
            &restored.will_publishers,
        );
        self.router.deinit();
        self.router = staged_router;
        restored.retained.deinit();
        restored.sessions.deinit();
        restored.wills.deinit();
        restored.will_publishers.deinit(self.allocator);
        restored.pending_qos2.deinit();
    }

    /// Accept exactly `connection_count` clients and serve them concurrently.
    ///
    /// This finite form makes lifecycle and benchmark teardown deterministic.
    /// A process-level accept loop can call it repeatedly in batches.
    pub fn serve(
        self: *Broker,
        connection_count: usize,
    ) anyerror!void {
        if (connection_count > self.slots.len) return error.BrokerFull;
        var group: std.Io.Group = .init;
        self.deadline_driver.start();
        // Unlike `Io.async`, `concurrent` guarantees the deadline driver is
        // assigned execution before we block in the client group. A merely
        // lazy future could otherwise leave an immediate Will queued or an
        // expired Session resident until all clients had disconnected.
        var deadline_future = try std.Io.concurrent(
            self.io,
            Broker.runDeadlineDriver,
            .{self},
        );
        var clients_started: usize = 0;
        var clients_joined = false;
        defer if (!clients_joined) {
            // An accept/setup failure must not strand already-started readers
            // behind this finite serve call.
            for (self.slots[0..clients_started]) |*slot| {
                if (slot.connection) |*connection| {
                    connection.shutdown() catch {};
                }
            }
            group.cancel(self.io);
        };
        var stop_driver = true;
        defer if (stop_driver) {
            self.deadline_driver.stop(self.io);
            _ = deadline_future.cancel(self.io);
        };
        const errors = try self.allocator.alloc(
            ?anyerror,
            connection_count,
        );
        defer self.allocator.free(errors);
        @memset(errors, null);

        for (errors, 0..) |*result, index| {
            var pending = try self.server.acceptPending(
                self.options.accept,
            );
            errdefer pending.deinit(self.allocator);
            var accept_options = try pending.resolvedOptions(
                self.options.accept,
            );
            if (accept_options.reason_code != 0) {
                // Resolve policies before registration so rejected CONNECTs
                // cannot create Session, Will, or router state.
                var refused = try pending.finish(accept_options);
                refused.deinit(self.allocator);
                clients_started += 1;
                continue;
            }
            if (pending.connect.connect.will) |will| {
                if (self.payloadTooLarge(will.payload)) {
                    // MQTT 5 has a precise Packet Too Large CONNACK reason.
                    // MQTT 3.1.1 has no equivalent and Mosquitto uses its
                    // legacy Not Authorized refusal for this policy failure.
                    var refused = try pending.finish(.{
                        .reason_code = switch (pending.connect.connect.protocol) {
                            .v5 => 0x95,
                            .v3_1_1 => 0x05,
                        },
                    });
                    refused.deinit(self.allocator);
                    clients_started += 1;
                    continue;
                }
            }
            if (pending.connection.authentication.phase ==
                .authenticating)
            {
                const handler = self.options.authentication orelse
                    return error.AuthenticationNotConfigured;
                try handler.start(
                    handler.context,
                    &pending,
                );
                if (!pending.authentication_authorized) {
                    return error.AuthenticationInProgress;
                }
            }
            if (self.options.connect_authorization) |authorization| {
                if (!authorization.authorize(
                    authorization.context,
                    pending.connect.connect,
                )) {
                    // Match Mosquitto's version-specific refusal codes. This
                    // happens before registration so rejected credentials
                    // cannot create, resume, replace, or erase durable state.
                    var refused = try pending.finish(.{
                        .reason_code = switch (pending.connect.connect.protocol) {
                            .v3_1_1 => 0x05,
                            .v5 => 0x87,
                        },
                    });
                    refused.deinit(self.allocator);
                    clients_started += 1;
                    continue;
                }
            }
            const registration = try self.register(
                index,
                pending.connect.connect,
            );
            const subscriber_id = registration.subscriber_id;
            accept_options.session_present =
                self.slots[index].session_present;
            if (self.slots[index].assigned_client_id_len != 0) {
                accept_options.assigned_client_identifier =
                    self.slots[index].assigned_client_id[0..self.slots[index].assigned_client_id_len];
            }
            // The Session/Will generation must reach the journal before the
            // peer can observe a successful CONNACK. Snapshot encoding treats
            // this short registration phase as crash-disconnected state.
            self.appendProvisionalCommitIfEnabled() catch |err| {
                self.abortRegistration(index, subscriber_id);
                return err;
            };
            var accepted = pending.finish(accept_options) catch |err| {
                self.abortRegistration(index, subscriber_id);
                self.appendCommitIfEnabled() catch {};
                return err;
            };
            // MQTT requires the replacement to be accepted before the old
            // Network Connection is terminated. Sending its CONNACK first
            // also prevents a slow displaced writer from delaying acceptance.
            if (registration.replaced_owner_id) |owner_id| {
                self.disconnectReplacedSessionOwner(owner_id);
            }
            var accepted_owns_connection = true;
            errdefer if (accepted_owns_connection) {
                accepted.deinit(self.allocator);
            };
            self.attachConnection(
                index,
                subscriber_id,
                &accepted.connection,
            );
            accepted_owns_connection = false;
            errdefer accepted.connect.deinit(self.allocator);
            // From this point the slot owns the connection. Setup failures
            // must follow normal unregister cleanup rather than the transient
            // AcceptedClient errdefer, whose connection was moved above.
            errdefer self.unregister(
                index,
                subscriber_id,
            ) catch {};
            try self.flushSlot(index, &self.slots[index]);
            const task = ClientTask{
                .broker = self,
                .slot_index = index,
                .subscriber_id = subscriber_id,
                .connect = accepted.connect,
                .result = result,
            };
            group.async(self.io, ClientTask.run, .{task});
            // The task now owns only the compact CONNECT parse tree. Keeping
            // the moved Connection out of the async closure avoids copying
            // its large inflight bitsets through every worker stack.
            accepted.connect = undefined;
            accepted.connection = undefined;
            clients_started += 1;
        }
        group.await(self.io) catch {};
        clients_joined = true;
        self.deadline_driver.stop(self.io);
        const deadline_result = deadline_future.await(self.io);
        stop_driver = false;
        if (deadline_result) |err| return err;
        for (errors) |maybe_error| {
            if (maybe_error) |err| return err;
        }
    }

    fn register(
        self: *Broker,
        slot_index: usize,
        connect: mqtt.Connect,
    ) Error!Registration {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        if (slot.active) return error.BrokerFull;
        slot.generation = nextConnectionGeneration(slot.generation);
        slot.active = true;
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.session_persistent = false;
        slot.assigned_client_id_len = 0;
        slot.graceful_disconnect = false;
        // The configured queue count is also the memory bound. Reserve it once
        // during setup so routing performs no destination queue allocation
        // while holding the global router lock.
        slot.queue.ensureTotalCapacity(
            self.allocator,
            self.options.limits
                .max_queued_deliveries_per_connection,
        ) catch |err| {
            slot.active = false;
            return err;
        };
        const id = subscriberId(slot_index, slot.generation);
        const now = std.Io.Clock.awake.now(self.io);
        // `find` removes an expired Session without exposing its route ID.
        // Prune first so the router and Session Store always retire stable
        // identities atomically from the broker's point of view.
        _ = self.pruneExpiredSessionRoutesLocked(now);
        var effective_connect = connect;
        if (connect.client_id.len == 0) {
            effective_connect.client_id = self.assignClientIdLocked(
                slot,
            ) catch |err| {
                slot.active = false;
                return err;
            };
        }
        const previous_session_handle = self.sessions.find(
            effective_connect.client_id,
            now,
        );
        const previous_route_id = if (previous_session_handle) |handle|
            self.sessions.routeId(handle) catch null
        else
            null;
        const previous_session_owner = if (previous_session_handle) |handle|
            if (self.sessions.routeId(handle) catch null) |route_id|
                self.session_owners.get(route_id)
            else
                null
        else
            null;
        const opened_session = self.sessions.openConnect(
            effective_connect,
            now,
        ) catch |err| {
            slot.active = false;
            return err;
        };
        if (previous_route_id) |route_id| {
            _ = self.session_owners.remove(route_id);
        }
        const replaced_owner_id = if (opened_session.replaced_connection)
            previous_session_owner
        else
            null;
        if (replaced_owner_id) |owner_id| {
            self.detachReplacedSessionOwnerLocked(owner_id);
        }
        if (previous_route_id) |route_id| {
            if (route_id != opened_session.route_id) {
                // Clean Start destroys the previous Session and allocates a
                // new stable identity. The old subscriptions must disappear
                // immediately rather than surviving as an unresolvable route.
                _ = self.router.removeSubscriber(
                    sessionSubscriberId(route_id),
                ) catch {};
                _ = self.pending_qos2.removePublisher(
                    sessionSubscriberId(route_id),
                );
            }
        }
        slot.session_handle = opened_session.handle;
        slot.session_present = opened_session.session_present;
        slot.session_persistent = (try self.sessions.stats(
            opened_session.handle,
        )).expiry_interval != 0;
        self.session_owners.putAssumeCapacityNoClobber(
            opened_session.route_id,
            id,
        );
        self.restoreSessionSubscriptions(
            opened_session.handle,
            opened_session.route_id,
        ) catch |err| {
            self.rollbackOpenedSessionLocked(
                opened_session.handle,
                opened_session.route_id,
                opened_session.session_present,
                now,
            );
            slot.active = false;
            return err;
        };
        const previous_handle = self.wills.handleForClient(
            effective_connect.client_id,
        );
        const accepted_will = self.wills.acceptConnect(
            effective_connect,
            now,
        ) catch |err| {
            self.rollbackOpenedSessionLocked(
                opened_session.handle,
                opened_session.route_id,
                opened_session.session_present,
                now,
            );
            slot.active = false;
            return err;
        };
        if (accepted_will.previous == .canceled) {
            if (previous_handle) |handle| {
                _ = self.will_publishers.remove(handle);
            }
        }
        if (accepted_will.previous == .due_now and
            accepted_will.previous_due != null)
        {
            // A due prior Will keeps its existing publisher mapping. It is
            // detached from the ClientID index by the scheduler and the timer
            // will release both records after publication.
            std.debug.assert(previous_handle != null);
        }
        slot.will_handle = accepted_will.current;
        if (accepted_will.current) |handle| {
            self.will_publishers.putAssumeCapacityNoClobber(
                handle,
                sessionSubscriberId(opened_session.route_id),
            );
        }
        self.deadline_driver.notify(self.io);
        return .{
            .subscriber_id = id,
            .replaced_owner_id = replaced_owner_id,
        };
    }

    fn assignClientIdLocked(
        self: *Broker,
        slot: *ClientSlot,
    ) Error![]const u8 {
        while (true) {
            var random: [client_id_mod.random_len]u8 = undefined;
            try std.Io.randomSecure(self.io, &random);
            const id = client_id_mod.format(
                &slot.assigned_client_id,
                self.options.auto_client_id_prefix,
                random,
            );
            if (self.sessions.containsClientId(id)) continue;
            slot.assigned_client_id_len = @intCast(id.len);
            return id;
        }
    }

    /// Roll back a Session generation opened before CONNACK commits.
    ///
    /// Existing Session State remains resumable after a failed transport;
    /// brand-new provisional state is discarded so a failed accept cannot
    /// manufacture Session Present or consume the Session quota.
    fn rollbackOpenedSessionLocked(
        self: *Broker,
        handle: session_mod.Handle,
        route_id: u64,
        session_present: bool,
        now: std.Io.Timestamp,
    ) void {
        _ = self.session_owners.remove(route_id);
        if (session_present) {
            self.sessions.disconnect(handle, null, now) catch {};
        } else {
            self.sessions.discardHandle(handle) catch {};
        }
        if (self.sessions.handleForRouteId(route_id) == null) {
            _ = self.router.removeSubscriber(
                sessionSubscriberId(route_id),
            ) catch {};
        }
    }

    fn detachReplacedSessionOwnerLocked(
        self: *Broker,
        owner_id: router_mod.SubscriberId,
    ) void {
        const owner_index = subscriberIndex(
            owner_id,
            self.slots.len,
        ) orelse return;
        const owner = &self.slots[owner_index];
        if (!owner.active or
            subscriberId(owner_index, owner.generation) != owner_id)
        {
            return;
        }
        owner.session_handle = null;
        owner.session_persistent = false;
    }

    fn disconnectReplacedSessionOwner(
        self: *Broker,
        owner_id: router_mod.SubscriberId,
    ) void {
        const owner_index = subscriberIndex(
            owner_id,
            self.slots.len,
        ) orelse return;
        const owner = &self.slots[owner_index];
        // Serialize the terminal frame with every other writer, then verify
        // that unregister did not retire or reuse this slot while waiting.
        owner.writer_mutex.lockUncancelable(self.io);
        defer owner.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        const still_replaced = owner.active and
            subscriberId(owner_index, owner.generation) == owner_id and
            owner.session_handle == null and
            owner.connection != null;
        self.state_mutex.unlock(self.io);
        if (!still_replaced) return;

        const connection = &owner.connection.?;
        if (connection.protocol == .v5) {
            connection.writeDisconnectWithProperties(0x8e, &.{}) catch {};
        }
        // The reader task remains the sole eventual close owner. Full shutdown
        // wakes its blocked read only after the final frame has been written.
        connection.shutdown() catch {};
    }

    /// Apply a peer DISCONNECT to a Will still owned by this connection slot.
    /// A takeover clears `session_handle` under the same state mutex before it
    /// cancels or detaches the old Will, so `WillNotFound` is expected only for
    /// that displaced generation and must not fail the whole broker.
    pub fn closeWillForDisconnectLocked(
        self: *Broker,
        slot: *ClientSlot,
        disconnect: mqtt.Disconnect,
        now: std.Io.Timestamp,
    ) Error!void {
        const handle = slot.will_handle orelse return;
        const result = self.wills.closeDisconnect(
            handle,
            disconnect,
            now,
        ) catch |err| {
            if (err == error.WillNotFound and
                slot.session_handle == null)
            {
                slot.will_handle = null;
                return;
            }
            return err;
        };
        if (result == .canceled) {
            _ = self.will_publishers.remove(handle);
            slot.will_handle = null;
        }
    }

    fn attachConnection(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        std.debug.assert(slot.active);
        std.debug.assert(slot.connection == null);
        std.debug.assert(
            subscriberId(slot_index, slot.generation) == id,
        );
        slot.connection = connection.*;
        connection.* = undefined;
    }

    fn abortRegistration(
        self: *Broker,
        slot_index: usize,
        _: router_mod.SubscriberId,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        const slot = &self.slots[slot_index];
        // Session Store, router, and Will scheduler are committed before the
        // CONNACK write. A transport failure at that final step must roll back
        // every provisional owner. A resumed Session is returned offline
        // rather than discarded: its pre-existing subscriptions and inflight
        // QoS state remain valid even though this transport never completed.
        if (slot.session_handle) |handle| {
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                self.rollbackOpenedSessionLocked(
                    handle,
                    value,
                    slot.session_present,
                    std.Io.Clock.awake.now(self.io),
                );
            }
        }
        if (slot.will_handle) |handle| {
            _ = self.will_publishers.remove(handle);
            _ = self.wills.close(handle, .normal_disconnect, .zero) catch {};
        }
        slot.active = false;
        slot.connection = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.session_persistent = false;
        slot.will_handle = null;
        self.state_mutex.unlock(self.io);
        self.deadline_driver.notify(self.io);
    }

    fn restoreSessionSubscriptions(
        self: *Broker,
        handle: session_mod.Handle,
        route_id: u64,
    ) Error!void {
        return self.restoreSessionSubscriptionsTo(
            &self.router,
            handle,
            route_id,
        );
    }

    fn restoreSessionSubscriptionsTo(
        self: *Broker,
        target_router: *router_mod.Router,
        handle: session_mod.Handle,
        route_id: u64,
    ) Error!void {
        const stats = try self.sessions.stats(handle);
        const subscriptions = try self.allocator.alloc(
            session_mod.Subscription,
            stats.subscription_count,
        );
        defer self.allocator.free(subscriptions);
        const restored = try self.sessions.subscriptionsInto(
            handle,
            subscriptions,
        );
        for (restored) |subscription| {
            _ = try target_router.subscribeWithIdentifierStatus(
                sessionSubscriberId(route_id),
                .{
                    .topic_filter = subscription.topic_filter,
                    .qos = subscription.qos,
                    .no_local = subscription.no_local,
                    .retain_as_published = subscription.retain_as_published,
                    .retain_handling = subscription.retain_handling,
                },
                subscription.subscription_identifier,
            );
        }
    }

    fn restoreSessionSubscriptionsFrom(
        allocator: std.mem.Allocator,
        target_router: *router_mod.Router,
        sessions: *session_mod.Store,
        handle: session_mod.Handle,
        route_id: u64,
    ) Error!void {
        const stats = try sessions.stats(handle);
        const subscriptions = try allocator.alloc(
            session_mod.Subscription,
            stats.subscription_count,
        );
        defer allocator.free(subscriptions);
        const restored = try sessions.subscriptionsInto(
            handle,
            subscriptions,
        );
        for (restored) |subscription| {
            _ = try target_router.subscribeWithIdentifierStatus(
                sessionSubscriberId(route_id),
                .{
                    .topic_filter = subscription.topic_filter,
                    .qos = subscription.qos,
                    .no_local = subscription.no_local,
                    .retain_as_published = subscription.retain_as_published,
                    .retain_handling = subscription.retain_handling,
                },
                subscription.subscription_identifier,
            );
        }
    }

    fn unregister(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
    ) Error!void {
        const slot = &self.slots[slot_index];
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        if (!slot.graceful_disconnect) {
            if (slot.will_handle) |handle| {
                _ = self.wills.close(
                    handle,
                    .ungraceful,
                    std.Io.Clock.awake.now(self.io),
                ) catch |err| {
                    if (err == error.WillNotFound) {
                        // A newer connection with the same ClientID already
                        // canceled or committed this generation during
                        // takeover. The stale transport close has no remaining
                        // Will lifecycle work.
                        slot.will_handle = null;
                    } else {
                        self.state_mutex.unlock(self.io);
                        return err;
                    }
                };
            }
        }
        if (slot.session_handle) |handle| {
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                _ = self.session_owners.remove(value);
            }
            self.sessions.disconnect(
                handle,
                null,
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                if (err != error.SessionNotFound) {
                    self.state_mutex.unlock(self.io);
                    return err;
                }
            };
            const stats = self.sessions.stats(handle) catch null;
            if (stats == null or stats.?.expiry_interval == 0) {
                if (route_id) |value| {
                    _ = self.pending_qos2.removePublisher(
                        sessionSubscriberId(value),
                    );
                    _ = self.router.removeSubscriber(
                        sessionSubscriberId(value),
                    ) catch {};
                }
            }
        }
        // A transient connection has no stable Session route. Durable Session
        // transactions are keyed above by route identity and survive this
        // transport generation.
        if (slot.session_handle == null) {
            _ = self.pending_qos2.removePublisher(id);
        }
        slot.active = false;
        slot.clearQueue();
        self.state_mutex.unlock(self.io);
        self.deadline_driver.notify(self.io);
        // Persist disconnect, Session expiry, and Will scheduling before an
        // orderly close becomes observable to the peer.
        try self.appendCommitIfEnabled();
        if (slot.connection) |*value| value.close();
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.session_persistent = false;
    }

    fn handleDisconnect(
        self: *Broker,
        slot: *ClientSlot,
        disconnect: mqtt.Disconnect,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        self.closeWillForDisconnectLocked(
            slot,
            disconnect,
            std.Io.Clock.awake.now(self.io),
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        if (slot.session_handle) |handle| {
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                _ = self.session_owners.remove(value);
            }
            self.sessions.disconnectPacket(
                handle,
                slot.connection.?.protocol,
                disconnect,
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const session_removed = self.sessions.stats(handle) catch |err|
                err == error.SessionNotFound;
            if (session_removed == true) {
                if (route_id) |value| {
                    _ = self.pending_qos2.removePublisher(
                        sessionSubscriberId(value),
                    );
                    _ = self.router.removeSubscriber(
                        sessionSubscriberId(value),
                    ) catch {};
                }
            }
            slot.session_handle = null;
        }
        slot.graceful_disconnect = true;
        self.state_mutex.unlock(self.io);
        self.deadline_driver.notify(self.io);
    }

    fn handleSubscribe(
        self: *Broker,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
        connect: mqtt.Connect,
        subscribe: mqtt.Subscribe,
    ) Error!void {
        const reasons = try self.allocator.alloc(
            u8,
            subscribe.subscriptions.len,
        );
        defer self.allocator.free(reasons);
        for (subscribe.subscriptions, reasons) |subscription, *reason| {
            reason.* = if (self.options.access_control) |access|
                if (access.authorize_subscribe(
                    access.context,
                    connect,
                    subscription,
                ))
                    0xff
                else
                    subscriptionDeniedReason(connection.protocol)
            else
                0xff;
        }
        const subscription_identifier = mqtt.subscriptionIdentifier(
            subscribe.properties,
        );
        const now = std.Io.Clock.awake.now(self.io);
        const slot = try self.slotForSubscriber(id);
        const session_handle = slot.session_handle orelse
            return error.SessionNotFound;
        const session_route_id = try self.sessions.routeId(
            session_handle,
        );
        // Serialize the subscription transition with every writer. Once the
        // router makes a new subscription visible, concurrent publishers may
        // enqueue for this slot; holding the writer lock guarantees SUBACK is
        // emitted before either retained replay or those live deliveries.
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        for (subscribe.subscriptions, 0..) |subscription, index| {
            if (reasons[index] != 0xff) continue;
            var granted = subscription;
            granted.qos = minQos(
                granted.qos,
                self.maximumQoS(),
            );
            const session_existed = self.sessions.setSubscription(
                session_handle,
                granted,
                subscription_identifier,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const route_id = try self.sessions.routeId(session_handle);
            const existed = self.router.subscribeWithIdentifierStatus(
                sessionSubscriberId(route_id),
                granted,
                subscription_identifier,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            std.debug.assert(existed == session_existed);
            reasons[index] = @intFromEnum(granted.qos);
            const deliveries = self.retained.deliveriesAlloc(
                self.allocator,
                granted,
                .{
                    .subscription_existed = existed,
                    .subscriber_id = sessionSubscriberId(session_route_id),
                    .subscription_identifier = subscription_identifier,
                    .upgrade_outgoing_qos = self.options.upgrade_outgoing_qos,
                },
                now,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            defer self.allocator.free(deliveries);
            self.enqueueRetainedDeliveries(
                slot,
                deliveries,
                now,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
        }
        self.state_mutex.unlock(self.io);
        // SUBACK makes the subscription durable from the peer's perspective.
        // The journal must reach disk before that acknowledgement is emitted.
        try self.appendCommitIfEnabled();
        try connection.writeSubAck(
            subscribe.packet_id,
            reasons,
            self.problemInformationForReasons(
                connection.protocol,
                reasons,
            ),
        );
        // Retained replay is deliberately queued before SUBACK but flushed
        // only afterwards. This preserves protocol ordering while using the
        // same Receive Maximum/backpressure path as live fanout.
        try self.flushSlotLocked(slot);
    }

    /// Queue retained replay while `state_mutex` is held.
    ///
    /// Each Store delivery is a borrowed view. Apply the recipient's read ACL
    /// before reserving any Session/connection queue state, then clone it into
    /// one reference-counted Publication per retained Application Message.
    /// The Store lock is released only after that sole reference has moved to
    /// the subscriber queue.
    fn enqueueRetainedDeliveries(
        self: *Broker,
        slot: *ClientSlot,
        deliveries: []const retained_mod.Delivery,
        now: std.Io.Timestamp,
    ) Error!void {
        const handle = slot.session_handle orelse
            return error.SessionNotFound;
        const client_id = try self.sessions.clientId(handle);
        for (deliveries) |delivery| {
            var properties: std.ArrayList(mqtt.Property) = .empty;
            defer properties.deinit(self.allocator);
            try properties.ensureTotalCapacity(
                self.allocator,
                delivery.properties.len,
            );
            for (delivery.properties) |property| {
                if (property == .four_byte and
                    property.four_byte.id == .message_expiry_interval)
                {
                    const remaining =
                        delivery.message_expiry_interval orelse continue;
                    properties.appendAssumeCapacity(.{ .four_byte = .{
                        .id = .message_expiry_interval,
                        .value = remaining,
                    } });
                } else {
                    properties.appendAssumeCapacity(property);
                }
            }
            const publish = mqtt.Publish{
                .dup = false,
                .qos = delivery.qos,
                .retain = delivery.retain,
                .topic = delivery.topic,
                .packet_id = null,
                .properties = properties.items,
                .payload = delivery.payload,
            };
            if (!self.deliveryAuthorized(.{
                .client_id = client_id,
                .topic = publish.topic,
                .payload = publish.payload,
                .qos = publish.qos,
                .retain = publish.retain,
                .properties = publish.properties,
            })) continue;
            if (delivery.qos != .at_most_once) {
                // Persistent Session State is the sole Packet Identifier
                // owner for every QoS 1/2 delivery to this client, including
                // retained replay. Mixing this path with Connection.writePublish
                // would let two independent allocators reuse the same ID.
                try self.enqueueSessionDeliveryLocked(
                    handle,
                    delivery.subscription_identifier,
                    delivery.retain,
                    delivery.qos,
                    publish,
                    now,
                );
                continue;
            }
            if (slot.queuedCount() >= self.options.limits
                .max_queued_deliveries_per_connection)
            {
                // Retained replay follows the same bounded outgoing queue
                // policy as live fanout. A successful SUBSCRIBE is not turned
                // into a connection failure merely because this client is
                // already saturated.
                continue;
            }
            const publication = try Publication.createFromRetained(
                self.allocator,
                delivery,
                1,
                now,
            );
            slot.appendDeliveryAssumeCapacity(.{
                .publication = publication,
                .qos = delivery.qos,
                .retain = true,
                .subscription_identifier = delivery.subscription_identifier,
            });
        }
    }

    fn handleUnsubscribe(
        self: *Broker,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
        connect: mqtt.Connect,
        unsubscribe: mqtt.Unsubscribe,
    ) Error!void {
        const reasons = try self.allocator.alloc(
            u8,
            unsubscribe.topic_filters.len,
        );
        defer self.allocator.free(reasons);
        const slot = try self.slotForSubscriber(id);
        self.state_mutex.lockUncancelable(self.io);
        for (unsubscribe.topic_filters, 0..) |filter, index| {
            if (self.options.access_control) |access| {
                if (access.authorize_unsubscribe) |authorize| {
                    if (!authorize(access.context, connect, filter)) {
                        reasons[index] = unsubscribeDeniedReason(
                            connection.protocol,
                        );
                        continue;
                    }
                }
            }
            const session_handle = slot.session_handle orelse {
                self.state_mutex.unlock(self.io);
                return error.SessionNotFound;
            };
            const session_removed = self.sessions.removeSubscription(
                session_handle,
                filter,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const route_id = try self.sessions.routeId(session_handle);
            self.router.unsubscribe(
                sessionSubscriberId(route_id),
                filter,
            ) catch |err| switch (err) {
                error.SubscriptionNotFound => {
                    std.debug.assert(!session_removed);
                    reasons[index] = 0x11;
                    continue;
                },
                else => {
                    self.state_mutex.unlock(self.io);
                    return err;
                },
            };
            std.debug.assert(session_removed);
            reasons[index] = 0;
        }
        self.state_mutex.unlock(self.io);
        try self.appendCommitIfEnabled();
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        try connection.writeUnsubAck(
            unsubscribe.packet_id,
            if (connection.protocol == .v5) reasons else &.{},
            self.problemInformationForReasons(
                connection.protocol,
                reasons,
            ),
        );
    }

    fn routePublish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) Error!void {
        // Subscription Identifier is generated by a Server while forwarding;
        // it is never legal on a Client-to-Server PUBLISH.
        if (mqtt.subscriptionIdentifier(publish.properties) != null) {
            return error.InvalidProperty;
        }
        if (self.options.access_control) |access| {
            if (!access.authorize_publish(
                access.context,
                connect,
                publish,
            )) {
                return self.rejectPublish(
                    publisher_id,
                    publisher,
                    publish,
                    0x87,
                );
            }
        }
        if (self.payloadTooLarge(publish.payload)) {
            return self.rejectPublish(
                publisher_id,
                publisher,
                publish,
                0x95,
            );
        }
        if (publish.qos == .exactly_once) {
            return self.recordQoS2Publish(
                publisher_id,
                publisher,
                publish,
            );
        }
        return self.routeReleasedPublish(
            publisher_id,
            publisher,
            publish,
            true,
        );
    }

    fn payloadTooLarge(self: Broker, payload: []const u8) bool {
        return self.options.limits.max_payload_size != 0 and
            payload.len > self.options.limits.max_payload_size;
    }

    fn rejectPublish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
        reason_code: u8,
    ) Error!void {
        // Rejected QoS 0 Application Messages are silently discarded. QoS 1/2
        // still complete their transport handshake so the peer can reuse its
        // Packet Identifier; MQTT 5 carries the precise policy reason while
        // MQTT 3.1.1 has no negative PUBACK/PUBREC representation.
        const packet_id = publish.packet_id orelse return;
        const slot = try self.slotForSubscriber(publisher_id);
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        switch (publish.qos) {
            .at_most_once => unreachable,
            .at_least_once => try publisher.writePubAckWithProperties(
                packet_id,
                protocolReason(publisher.protocol, reason_code),
                self.problemInformationForReason(
                    publisher.protocol,
                    reason_code,
                ),
            ),
            .exactly_once => try publisher.writePubRecWithProperties(
                packet_id,
                protocolReason(publisher.protocol, reason_code),
                self.problemInformationForReason(
                    publisher.protocol,
                    reason_code,
                ),
            ),
        }
    }

    fn recordQoS2Publish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        const durable_publisher_id = self.canonicalPublisherId(
            publisher_id,
        );
        _ = self.pending_qos2.record(
            durable_publisher_id,
            publish,
            std.Io.Clock.awake.now(self.io),
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            if (err != error.ReceiveMaximumExceeded) return err;

            // A broker-wide pending-transaction cap is an MQTT quota failure,
            // not malformed client behavior. Reject this transaction with the
            // standard QoS 2 response and release the runtime receive slot so
            // the connection can continue.
            const publisher_slot = try self.slotForSubscriber(publisher_id);
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            defer publisher_slot.writer_mutex.unlock(self.io);
            // MQTT 3.1.1 has no PUBREC reason field. Mosquitto emits the same
            // control packet but its wire helper omits the negative reason,
            // completing the QoS handshake without routing the rejected
            // Application Message.
            try publisher.writePubRecWithProperties(
                publish.packet_id.?,
                protocolReason(publisher.protocol, 0x97),
                self.problemInformationForReason(
                    publisher.protocol,
                    0x97,
                ),
            );
            return;
        };
        self.state_mutex.unlock(self.io);

        // A successful PUBREC promises that this QoS 2 transaction survives a
        // reconnect. Establish the durability point before sending PUBREC.
        try self.appendCommitIfEnabled();

        // Mosquitto stores the inbound QoS 2 base message before PUBREC and
        // routes only when PUBREL arrives. A retransmitted PUBLISH receives the
        // same PUBREC without replacing or duplicating the stored message.
        const publisher_slot = try self.slotForSubscriber(publisher_id);
        publisher_slot.writer_mutex.lockUncancelable(self.io);
        defer publisher_slot.writer_mutex.unlock(self.io);
        try publisher.writePubRec(publish.packet_id.?, 0);
    }

    fn handlePubRel(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        ack: mqtt.AckPacket,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        const durable_publisher_id = self.canonicalPublisherId(
            publisher_id,
        );
        var pending = self.pending_qos2.take(
            durable_publisher_id,
            ack.packet_id,
        ) orelse {
            self.state_mutex.unlock(self.io);
            // Mosquitto deliberately acknowledges an unknown/repeated PUBREL:
            // the original PUBCOMP may have been lost after the message was
            // already released. MQTT 5 allows 0x92, but Success is maximally
            // interoperable and keeps this path idempotent.
            const publisher_slot = try self.slotForSubscriber(publisher_id);
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            defer publisher_slot.writer_mutex.unlock(self.io);
            if (durable_publisher_id != publisher_id) {
                // The completed inbound transaction belongs to a durable
                // Session from an earlier Network Connection. Reconcile the
                // fresh connection's fixed receive table so writePubComp can
                // release it normally. MQTT 3.1.1 identifies this retry with
                // PUBREL DUP; MQTT 5 defines repeated PUBREL as idempotent
                // without carrying a DUP bit.
                if (publisher.protocol == .v5 or ack.dup) {
                    try publisher.resumeIncomingQoS2(ack.packet_id);
                }
            }
            try publisher.writePubComp(ack.packet_id, 0);
            return;
        };
        self.state_mutex.unlock(self.io);
        defer pending.deinit();

        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        if (try pending.asPublish(
            ack.packet_id,
            std.Io.Clock.awake.now(self.io),
            &properties,
        )) |publish| {
            try self.routeReleasedPublish(
                publisher_id,
                publisher,
                publish,
                false,
            );
        }
        // `routeReleasedPublish` journals the routed state before returning.
        // If Message Expiry discarded the Application Message instead, the
        // pending inbound transaction removal is still a durable mutation.
        try self.appendCommitIfEnabled();

        const publisher_slot = try self.slotForSubscriber(publisher_id);
        publisher_slot.writer_mutex.lockUncancelable(self.io);
        defer publisher_slot.writer_mutex.unlock(self.io);
        try publisher.writePubComp(ack.packet_id, 0);
    }

    fn routeReleasedPublish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
        acknowledge_qos1: bool,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        const plan = self.enqueuePublishLocked(
            publisher_id,
            publish,
            std.Io.Clock.awake.now(self.io),
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        defer self.allocator.free(plan.storage);
        self.state_mutex.unlock(self.io);

        // Retained changes and durable fanout queues precede PUBACK and every
        // downstream write. A crash after either peer observes progress can
        // therefore recover a state no older than that observable boundary.
        try self.appendCommitIfEnabled();

        if (acknowledge_qos1) if (publish.packet_id) |packet_id| {
            const publisher_slot = try self.slotForSubscriber(
                publisher_id,
            );
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            publisher.writePubAck(
                packet_id,
                protocolReason(
                    publisher.protocol,
                    if (plan.has_matching_subscriber) 0 else 0x10,
                ),
            ) catch |err| {
                publisher_slot.writer_mutex.unlock(self.io);
                return err;
            };
            publisher_slot.writer_mutex.unlock(self.io);
        };
        try self.flushPlan(plan);
    }

    /// Apply retained state and enqueue live fanout while `state_mutex` is held.
    ///
    /// Will publication reuses this exact route without a publisher
    /// Connection, while client PUBLISH adds its acknowledgement after the
    /// lock is released.
    fn enqueuePublishLocked(
        self: *Broker,
        publisher_id: ?router_mod.SubscriberId,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!RoutePlan {
        _ = self.pruneExpiredSessionRoutesLocked(now);
        const route_publisher_id = if (publisher_id) |id|
            self.canonicalPublisherId(id)
        else
            null;
        _ = self.retained.applyParsedPublish(
            publish,
            route_publisher_id,
            now,
        ) catch |err| return err;
        const matches = self.router.matchAllocForPublisher(
            self.allocator,
            publish.topic,
            route_publisher_id,
        ) catch |err| return err;
        errdefer self.allocator.free(matches);
        // Compact the router result in place into a stable enqueue plan. This
        // is important for shared subscriptions: running the match a second
        // time would advance their round-robin cursor twice. It also makes the
        // publication's reference count exactly equal to transferred queue
        // ownership.
        var has_matching_subscriber = matches.len != 0;
        if (!has_matching_subscriber and
            route_publisher_id != null)
        {
            // No Local suppresses delivery, but Mosquitto still treats the
            // underlying subscription as a match and returns a successful
            // PUBACK rather than reason 0x10. Keep the publisher-aware route
            // allocation (and shared cursor) single-pass; this count-only
            // query cannot advance shared-subscription selection.
            has_matching_subscriber = self.router.hasTopicMatch(
                publish.topic,
            );
        }
        var session_plan = try session_delivery.Plan.init(
            self.allocator,
            matches,
            publish.qos,
            publish.retain,
            self.options.upgrade_outgoing_qos,
        );
        defer session_plan.deinit();
        for (session_plan.routes) |*route| {
            const handle = self.sessions.handleForRouteId(
                route.route_id,
            ) orelse {
                // A stable route without Session State can only be a rollback
                // residue. Its raw matches are discarded in the rewrite pass
                // below.
                continue;
            };
            const owner_id = self.session_owners.get(route.route_id);
            const destination_index = if (owner_id) |id|
                subscriberIndex(id, self.slots.len)
            else
                null;
            const destination = if (destination_index) |index|
                &self.slots[index]
            else
                null;
            const online = if (destination) |slot|
                self.slotOwnsSessionRoute(
                    destination_index.?,
                    slot,
                    owner_id.?,
                    route.route_id,
                )
            else
                false;
            // Persisted Sessions can outlive a broker configuration change.
            // Cap the route even if the stored subscription predates the
            // listener's current Maximum QoS setting.
            route.qos = minQos(route.qos, self.maximumQoS());
            if (!self.deliveryAuthorized(.{
                .client_id = try self.sessions.clientId(handle),
                .topic = publish.topic,
                .payload = publish.payload,
                .qos = route.qos,
                .retain = route.retain,
                .properties = publish.properties,
            })) {
                // A read denial suppresses every overlapping subscription for
                // this Session before either its durable queue or live queue
                // changes. The raw router match still counts for the
                // publisher's MQTT 5 "matching subscriber" PUBACK reason,
                // as it does in Mosquitto.
                continue;
            }
            has_matching_subscriber = true;
            if ((route.qos == .at_most_once and
                (!self.options.queue_qos0_messages or online)) or
                (online and !destination.?.session_persistent))
            {
                // Mosquitto always delivers QoS 0 directly to an online
                // persistent client. It drops QoS 0 while offline unless its
                // non-default queue_qos0 option is enabled. QoS 1/2 can take
                // the same shared-Publication
                // path when Session Expiry is zero: the runtime keeps the
                // Packet Identifier state until ACK, and no payload is
                // allowed to survive this Network Connection.
                if (online) route.output_subscriber_id = owner_id.?;
                continue;
            }
            try self.enqueueSessionDeliveryManyLocked(
                handle,
                session_plan.identifiersFor(route),
                route.retain,
                route.qos,
                publish,
                now,
            );
            if (online) {
                route.output_subscriber_id =
                    sessionSubscriberId(route.route_id);
            }
        }
        // Apply one route decision to every overlapping raw match. Keeping all
        // online transient matches lets the existing live Delivery merge
        // preserve their identifiers. Durable routes have already been reduced
        // to one Session enqueue, so only their first raw match remains as a
        // flush target.
        for (matches) |*match| {
            if (sessionRouteId(match.subscriber_id)) |route_id| {
                match.subscriber_id =
                    session_plan.nextOutputSubscriberId(route_id);
            }
        }

        // Partition Session-backed QoS 1/2 flush targets into the tail. A swap
        // is safe while walking backwards: every element in the target tail
        // has already been classified. The front remains available for
        // lightweight QoS 0 delivery compaction without another allocation.
        var session_target_start = matches.len;
        var match_index = matches.len;
        while (match_index != 0) {
            match_index -= 1;
            const route_id = sessionRouteId(
                matches[match_index].subscriber_id,
            ) orelse continue;
            session_target_start -= 1;
            if (match_index != session_target_start) {
                std.mem.swap(
                    router_mod.Match,
                    &matches[match_index],
                    &matches[session_target_start],
                );
            }
            matches[session_target_start].subscriber_id =
                self.session_owners.get(route_id).?;
        }

        var plan_count: usize = 0;
        for (matches[0..session_target_start]) |match| {
            if (match.subscriber_id == 0) continue;
            const destination_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ) orelse continue;
            const destination = &self.slots[destination_index];
            if (!destination.active or
                subscriberId(
                    destination_index,
                    destination.generation,
                ) != match.subscriber_id)
            {
                continue;
            }
            has_matching_subscriber = true;
            if (destination.queuedCount() +
                destination.route_reservations >=
                self.options.limits
                    .max_queued_deliveries_per_connection)
            {
                // Match Mosquitto's bounded outgoing queues: a saturated
                // subscriber drops this delivery, but it was still a matching
                // subscription and therefore does not turn the publisher's
                // PUBACK into "No matching subscribers".
                continue;
            }
            destination.route_reservations += 1;
            matches[plan_count] = match;
            plan_count += 1;
        }
        const plan = matches[0..plan_count];

        const publication = if (plan.len == 0)
            null
        else
            Publication.createFromPublish(
                self.allocator,
                publish,
                plan.len,
                now,
            ) catch |err| {
                self.releaseRouteReservations(plan);
                return err;
            };
        var publication_committed = false;
        errdefer if (!publication_committed) {
            if (publication) |value| {
                var removed: usize = 0;
                for (self.slots) |*slot| {
                    removed += slot.removePublication(value);
                }
                // `Publication` starts with one reference per raw match. Queue
                // rollback released one per materialized destination; release
                // the unmaterialized/merged owners here.
                for (removed..plan.len) |_| value.release();
            }
            self.releaseRouteReservations(plan);
        };
        var enqueued_count: usize = 0;
        for (plan) |match| {
            const destination_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ).?;
            const destination = &self.slots[destination_index];
            var duplicate: ?*Delivery = null;
            for (destination.queue.items[destination.queue_head..]) |
                *queued_delivery,
            | {
                if (queued_delivery.publication == publication.?) {
                    duplicate = queued_delivery;
                    break;
                }
            }
            const delivery_qos = minQos(
                if (self.options.upgrade_outgoing_qos)
                    match.subscription.qos
                else
                    minQos(publish.qos, match.subscription.qos),
                self.maximumQoS(),
            );
            if (duplicate) |delivery| {
                try delivery.appendSubscriptionIdentifier(
                    self.allocator,
                    match.subscription_identifier,
                );
                delivery.qos = maxQos(
                    delivery.qos,
                    delivery_qos,
                );
                delivery.retain = delivery.retain or
                    (match.subscription.retain_as_published and
                        publish.retain);
                continue;
            }
            const delivery = Delivery{
                .publication = publication.?,
                .qos = delivery_qos,
                .retain = if (match.subscription.retain_as_published)
                    publish.retain
                else
                    false,
                .subscription_identifier = match.subscription_identifier,
            };
            destination.appendDeliveryAssumeCapacity(delivery);
            enqueued_count += 1;
        }
        // Publication references were reserved from raw match count before
        // overlapping subscriptions were merged. Release the unused owners.
        for (enqueued_count..plan.len) |_| publication.?.release();
        self.releaseRouteReservations(plan);
        publication_committed = true;
        return .{
            .storage = matches,
            .deliveries = matches[0..plan_count],
            .session_targets = matches[session_target_start..],
            .has_matching_subscriber = has_matching_subscriber,
        };
    }

    fn pruneExpiredSessionRoutesLocked(
        self: *Broker,
        now: std.Io.Timestamp,
    ) usize {
        return self.sessions.pruneExpiredWithContext(
            now,
            self,
            struct {
                fn removed(broker: *Broker, route_id: u64) void {
                    _ = broker.pending_qos2.removePublisher(
                        sessionSubscriberId(route_id),
                    );
                    _ = broker.router.removeSubscriber(
                        sessionSubscriberId(route_id),
                    ) catch {};
                }
            }.removed,
        );
    }

    fn enqueueSessionDeliveryLocked(
        self: *Broker,
        handle: session_mod.Handle,
        subscription_identifier: ?usize,
        retain: bool,
        qos: mqtt.QoS,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!void {
        var identifier_storage: [1]usize = undefined;
        const identifiers: []const usize = if (subscription_identifier) |id| blk: {
            identifier_storage[0] = id;
            break :blk &identifier_storage;
        } else &.{};
        return self.enqueueSessionDeliveryManyLocked(
            handle,
            identifiers,
            retain,
            qos,
            publish,
            now,
        );
    }

    fn enqueueSessionDeliveryManyLocked(
        self: *Broker,
        handle: session_mod.Handle,
        subscription_identifiers: []const usize,
        retain: bool,
        qos: mqtt.QoS,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!void {
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.ensureTotalCapacity(
            self.allocator,
            publish.properties.len +
                subscription_identifiers.len,
        );
        for (publish.properties) |property| {
            if ((property == .two_byte and
                property.two_byte.id == .topic_alias) or
                (property == .varint and
                    property.varint.id == .subscription_identifier))
            {
                continue;
            }
            properties.appendAssumeCapacity(property);
        }
        for (subscription_identifiers) |identifier| {
            properties.appendAssumeCapacity(.{ .varint = .{
                .id = .subscription_identifier,
                .value = identifier,
            } });
        }
        _ = self.sessions.enqueuePublish(
            handle,
            publish.topic,
            publish.payload,
            .{
                .qos = qos,
                .retain = retain,
                .properties = properties.items,
                .now = now,
            },
        ) catch |err| switch (err) {
            error.QueueFull => return,
            else => return err,
        };
    }

    fn handleSessionAckLocked(
        self: *Broker,
        slot: *ClientSlot,
        ack: mqtt.AckPacket,
    ) Error!bool {
        const handle = slot.session_handle orelse return false;
        if (!self.sessions.ownsPacketId(handle, ack.packet_id)) {
            return false;
        }
        _ = try self.sessions.handleAck(
            handle,
            ack.packet_type,
            ack.packet_id,
            ack.reason_code,
        );
        return true;
    }

    fn canonicalPublisherId(
        self: *Broker,
        id: router_mod.SubscriberId,
    ) router_mod.SubscriberId {
        if (sessionRouteId(id) != null) return id;
        const index = subscriberIndex(id, self.slots.len) orelse return id;
        const slot = &self.slots[index];
        const handle = slot.session_handle orelse return id;
        const route_id = self.sessions.routeId(handle) catch return id;
        return sessionSubscriberId(route_id);
    }

    fn slotOwnsSessionRoute(
        self: *Broker,
        index: usize,
        slot: *ClientSlot,
        owner_id: router_mod.SubscriberId,
        route_id: u64,
    ) bool {
        if (!slot.active or slot.connection == null or
            subscriberId(index, slot.generation) != owner_id)
        {
            return false;
        }
        const handle = slot.session_handle orelse return false;
        return (self.sessions.routeId(handle) catch return false) == route_id;
    }

    fn maximumQoS(self: Broker) mqtt.QoS {
        // MQTT 3.1.1 cannot advertise this limit in CONNACK, but Mosquitto
        // still applies its listener-wide cap to subscription grants and
        // forwarded deliveries.
        return self.options.accept.maximum_qos orelse .exactly_once;
    }

    fn problemInformationForReason(
        self: Broker,
        protocol: mqtt.ProtocolVersion,
        reason_code: u8,
    ) []const mqtt.Property {
        if (protocol != .v5 or reason_code < 0x80) return &.{};
        return self.options.problem_information;
    }

    fn problemInformationForReasons(
        self: Broker,
        protocol: mqtt.ProtocolVersion,
        reason_codes: []const u8,
    ) []const mqtt.Property {
        if (protocol != .v5) return &.{};
        for (reason_codes) |reason_code| {
            if (reason_code >= 0x80) {
                return self.options.problem_information;
            }
        }
        return &.{};
    }

    fn deliveryAuthorized(
        self: Broker,
        delivery: DeliveryAuthorization,
    ) bool {
        const access = self.options.access_control orelse return true;
        const authorize = access.authorize_delivery orelse return true;
        return authorize(access.context, delivery);
    }

    fn releaseRouteReservations(
        self: *Broker,
        plan: []const router_mod.Match,
    ) void {
        for (plan) |match| {
            const destination_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ).?;
            const destination = &self.slots[destination_index];
            std.debug.assert(destination.route_reservations != 0);
            destination.route_reservations -= 1;
        }
    }

    fn slotForSubscriber(
        self: *Broker,
        id: router_mod.SubscriberId,
    ) Error!*ClientSlot {
        const index = subscriberIndex(id, self.slots.len) orelse
            return error.ClientNotRegistered;
        const slot = &self.slots[index];
        if (!slot.active or
            subscriberId(index, slot.generation) != id or
            slot.connection == null)
        {
            return error.ClientOffline;
        }
        return slot;
    }

    fn flushPlan(
        self: *Broker,
        plan: RoutePlan,
    ) Error!void {
        // A slot flush drains its entire queue. Overlapping subscriptions can
        // therefore appear more than once, but revisiting that slot only sees
        // an empty queue. This O(matches) walk avoids the former O(matches²)
        // prefix searches and remains safe when concurrent publish plans
        // interleave outside the broker state mutex.
        try self.flushMatches(plan.deliveries);
        try self.flushMatches(plan.session_targets);
    }

    fn flushMatches(
        self: *Broker,
        matches: []const router_mod.Match,
    ) Error!void {
        for (matches) |match| {
            const slot_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ) orelse continue;
            const slot = &self.slots[slot_index];
            try self.flushSlot(slot_index, slot);
        }
    }

    fn flushSlot(
        self: *Broker,
        slot_index: usize,
        slot: *ClientSlot,
    ) Error!void {
        _ = slot_index;
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        return self.flushSlotLocked(slot);
    }

    fn flushSlotLocked(
        self: *Broker,
        slot: *ClientSlot,
    ) Error!void {
        while (true) {
            if (try self.takeSessionPacketLocked(slot)) |packet_value| {
                var packet = packet_value;
                defer packet.deinit();
                // Selecting a durable QoS 1/2 message moves it from queued to
                // inflight and assigns its Packet Identifier. Sync that state
                // before the bytes can reach the peer, so restart retransmits
                // the same identifier with DUP rather than inventing a new
                // transaction.
                try self.appendCommitIfEnabled();
                slot.connection.?.writeEncodedSessionPacket(
                    packet.encoded.bytes,
                ) catch |err| switch (err) {
                    error.OutgoingPacketTooLarge => {
                        if (packet.encoded.kind == .pubrel) return err;
                        // Match Mosquitto's oversized outgoing handling: once
                        // the peer's Maximum Packet Size rejects a PUBLISH,
                        // remove that transaction and continue draining rather
                        // than permanently consuming Session inflight credit.
                        self.state_mutex.lockUncancelable(self.io);
                        _ = self.sessions.dropOversizedPublish(
                            packet.handle,
                            packet.encoded.packet_id,
                        ) catch {};
                        self.state_mutex.unlock(self.io);
                        continue;
                    },
                    else => {
                        if (packet.encoded.kind != .pubrel) {
                            self.state_mutex.lockUncancelable(self.io);
                            self.sessions.retryUnsentPublish(
                                packet.handle,
                                packet.encoded.packet_id,
                            ) catch {};
                            self.state_mutex.unlock(self.io);
                        }
                        return err;
                    },
                };
                if (packet.encoded.kind == .qos0_publish) {
                    self.state_mutex.lockUncancelable(self.io);
                    const completion = self.sessions
                        .completeQoS0Transmission(
                        packet.handle,
                        packet.route_id,
                        packet.encoded.packet_id,
                    );
                    self.state_mutex.unlock(self.io);
                    // A concurrent ClientID takeover invalidates the old
                    // Session handle. Native QoS 0 completion is tied to that
                    // writer generation, while a QoS 1/2 transaction capped
                    // to wire QoS 0 is resolved by stable route identity.
                    // Ignore only a genuinely stale/missing transaction after
                    // releasing the global state barrier.
                    completion catch |err| switch (err) {
                        error.SessionNotFound => {},
                        else => return err,
                    };
                    try self.appendCommitIfEnabled();
                }
                continue;
            }
            self.state_mutex.lockUncancelable(self.io);
            if (!slot.active or slot.connection == null or
                slot.queuedCount() == 0)
            {
                self.state_mutex.unlock(self.io);
                return;
            }
            var delivery = slot.popDelivery().?;
            self.state_mutex.unlock(self.io);

            const connection = &slot.connection.?;
            var properties: std.ArrayList(mqtt.Property) = .empty;
            defer properties.deinit(self.allocator);
            const identifier_count =
                delivery.additional_subscription_identifiers.len +
                @intFromBool(delivery.subscription_identifier != null);
            var identifiers_stack: [8]usize = undefined;
            const identifiers = if (identifier_count <= identifiers_stack.len)
                identifiers_stack[0..identifier_count]
            else
                try self.allocator.alloc(usize, identifier_count);
            defer if (identifiers.ptr != identifiers_stack[0..].ptr) {
                self.allocator.free(identifiers);
            };
            if (!try delivery.publication.appendDeliveryPropertiesMany(
                &properties,
                self.allocator,
                connection.protocol,
                delivery.identifiersInto(identifiers),
                std.Io.Clock.awake.now(self.io),
            )) {
                delivery.deinit();
                continue;
            }
            const outgoing_topic = try connection
                .prepareAutomaticTopicAlias(
                delivery.publication.topic(),
                &properties,
            );
            const packet_id = connection.writePublish(
                outgoing_topic,
                delivery.publication.payload(),
                .{
                    .qos = delivery.qos,
                    .retain = delivery.retain,
                    .properties = properties.items,
                },
            ) catch |err| switch (err) {
                error.InflightFull => {
                    // Mirror Mosquitto's queued/inflight split: retain the
                    // delivery at the front until a downstream PUBACK frees
                    // credit. Never turn ordinary backpressure into message
                    // loss or a connection error.
                    self.state_mutex.lockUncancelable(self.io);
                    slot.pushFront(delivery);
                    self.state_mutex.unlock(self.io);
                    return;
                },
                error.OutgoingPacketTooLarge => {
                    // A live/transient delivery is not backed by Session
                    // packet state, but MQTT 5 Maximum Packet Size has the
                    // same semantics: discard this Application Message and
                    // keep draining/using the Network Connection.
                    delivery.deinit();
                    continue;
                },
                else => {
                    delivery.deinit();
                    return err;
                },
            };
            delivery.deinit();
            // QoS 1 completion arrives later through this connection's reader;
            // only one writer mutates its outgoing inflight table at a time.
            _ = packet_id;
        }
    }

    /// Reserve and encode one Session transmission under the state lock.
    ///
    /// `drainInto` mutates queued/inflight ownership. Encoding before unlocking
    /// guarantees its borrowed views cannot be invalidated by an ACK or
    /// takeover, while the detached byte slice keeps network I/O outside the
    /// global lock.
    fn takeSessionPacketLocked(
        self: *Broker,
        slot: *ClientSlot,
    ) Error!?EncodedSessionPacket {
        const handle = slot.session_handle orelse return null;
        const connection = &(slot.connection orelse return null);
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const route_id = try self.sessions.routeId(handle);
        const client_id = try self.sessions.clientId(handle);

        while (true) {
            var storage: [1]session_mod.Transmission = undefined;
            const transmissions = self.sessions.drainInto(
                handle,
                std.Io.Clock.awake.now(self.io),
                connection.max_outgoing_inflight,
                &storage,
            ) catch |err| switch (err) {
                error.SessionNotFound => return null,
                else => return err,
            };
            if (transmissions.len == 0) return null;
            const transmission = transmissions[0];
            if (transmission == .publish and
                !self.deliveryAuthorized(.{
                    .client_id = client_id,
                    .topic = transmission.publish.topic,
                    .payload = transmission.publish.payload,
                    .qos = transmission.publish.qos,
                    .retain = transmission.publish.retain,
                    .properties = transmission.publish.properties,
                }))
            {
                // Re-check durable messages immediately before their first or
                // resumed delivery, matching Mosquitto's removal of queued and
                // inflight messages when read ACL policy changes. A PUBREL is
                // never dropped: the peer has already accepted that QoS 2
                // PUBLISH and its handshake must be completed.
                _ = try self.sessions.dropOutgoingPublish(
                    handle,
                    transmission.publish.packet_id,
                );
                continue;
            }
            const encoded = session_route.encodeTransmission(
                self.allocator,
                connection.protocol,
                transmission,
                self.maximumQoS(),
            ) catch |err| {
                switch (transmission) {
                    .publish => |publish| self.sessions.retryUnsentPublish(
                        handle,
                        publish.packet_id,
                    ) catch {},
                    .pubrel => {},
                }
                return err;
            };
            return .{
                .encoded = encoded,
                .handle = handle,
                .route_id = route_id,
            };
        }
    }

    fn runDeadlineDriver(
        self: *Broker,
    ) ?anyerror {
        while (!self.deadline_driver.stopped()) {
            self.state_mutex.lockUncancelable(self.io);
            const now = std.Io.Clock.awake.now(self.io);
            const expired_count = self.pruneExpiredSessionRoutesLocked(now);
            const published_any = self.publishDueWillsLocked(
                now,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const deadline = earliestDeadline(
                self.wills.nextDeadline(),
                self.sessions.nextExpiryDeadline(),
            );
            const generation =
                self.deadline_driver.currentGeneration();
            self.state_mutex.unlock(self.io);

            if (published_any or expired_count != 0) {
                self.appendCommitIfEnabled() catch |err| return err;
            }
            if (published_any) {
                self.flushAllSlots() catch |err| return err;
            }
            self.deadline_driver.wait(
                self.io,
                generation,
                deadline,
            ) catch |err| switch (err) {
                error.Canceled => return err,
            };
        }
        return null;
    }

    /// Claim and route every Will whose deadline has passed.
    ///
    /// `state_mutex` stays held from scheduler claim through queue ownership
    /// transfer and scheduler release. This makes reconnect cancellation race
    /// against one atomic publication decision: a reconnect either removes the
    /// scheduled Will first, or observes it already committed.
    fn publishDueWillsLocked(
        self: *Broker,
        now: std.Io.Timestamp,
    ) Error!bool {
        var published_any = false;
        while (self.wills.pollOneDue(now)) |handle| {
            try self.publishWillLocked(handle, now);
            published_any = true;
        }
        return published_any;
    }

    fn flushAllSlots(self: *Broker) Error!void {
        for (self.slots, 0..) |*slot, index| {
            try self.flushSlot(index, slot);
        }
    }

    fn publishWillLocked(
        self: *Broker,
        handle: will_mod.Handle,
        now: std.Io.Timestamp,
    ) Error!void {
        const will = try self.wills.view(handle);
        const publisher_id = self.will_publishers.get(handle) orelse null;
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.ensureTotalCapacity(
            self.allocator,
            will.properties.len,
        );
        for (will.properties) |property| {
            // Will Delay controls scheduling and is forbidden on a normal
            // PUBLISH. Message Expiry and all other Will Application Message
            // properties begin when the Will is actually published.
            if (property == .four_byte and
                property.four_byte.id == .will_delay_interval)
            {
                continue;
            }
            properties.appendAssumeCapacity(property);
        }
        const publish = mqtt.Publish{
            .dup = false,
            .qos = will.qos,
            .retain = will.retain,
            .topic = will.topic,
            .packet_id = null,
            .properties = properties.items,
            .payload = will.payload,
        };
        if (self.options.access_control) |access| {
            if (access.authorize_will) |authorize| {
                if (!authorize(access.context, .{
                    .client_id = will.client_id,
                    .topic = publish.topic,
                    .payload = publish.payload,
                    .qos = publish.qos,
                    .retain = publish.retain,
                    .properties = publish.properties,
                })) {
                    // A denied Will is consumed, not postponed. This mirrors
                    // Mosquitto's publication-time write ACL and prevents a
                    // later policy change from resurrecting the same Will.
                    try self.wills.releaseDue(handle);
                    _ = self.will_publishers.remove(handle);
                    return;
                }
            }
        }
        const plan = try self.enqueuePublishLocked(
            publisher_id,
            publish,
            now,
        );
        defer self.allocator.free(plan.storage);
        try self.wills.releaseDue(handle);
        _ = self.will_publishers.remove(handle);

        // The state lock cannot be held across socket writes. Queue ownership
        // is committed at this point; the timer loop releases the lock before
        // flushing all active slots below.
    }
};

const ClientTask = struct {
    broker: *Broker,
    slot_index: usize,
    subscriber_id: router_mod.SubscriberId,
    connect: runtime.OwnedConnect,
    result: *?anyerror,

    fn run(task: ClientTask) std.Io.Cancelable!void {
        var connect = task.connect;
        defer connect.deinit(task.broker.allocator);
        const slot = &task.broker.slots[task.slot_index];
        const connection = &slot.connection.?;

        task.runLoop(slot, connection, connect.connect) catch |err| {
            if (!ungracefulTransportClose(err)) {
                task.result.* = err;
            }
        };
        task.broker.unregister(
            task.slot_index,
            task.subscriber_id,
        ) catch |err| {
            task.result.* = err;
        };
    }

    fn runLoop(
        task: ClientTask,
        slot: *ClientSlot,
        connection: *runtime.Connection,
        connect: mqtt.Connect,
    ) !void {
        while (true) {
            var event = connection.readBrokerEventWithKeepAlive() catch |err| {
                if (try task.disconnectForReadViolation(
                    slot,
                    connection,
                    err,
                )) return;
                return err;
            };
            defer event.deinit(task.broker.allocator);
            switch (event) {
                .auth => |*owned| {
                    const handler = task.broker.options.authentication orelse
                        return error.AuthenticationNotConfigured;
                    const complete =
                        try connection.applyAuthenticationEvent(
                            owned.auth,
                        );
                    try handler.handle(
                        handler.context,
                        connection,
                        owned.auth,
                        complete,
                    );
                },
                .subscribe => |*owned| {
                    try task.broker.handleSubscribe(
                        task.subscriber_id,
                        connection,
                        connect,
                        owned.subscribe,
                    );
                },
                .unsubscribe => |*owned| {
                    try task.broker.handleUnsubscribe(
                        task.subscriber_id,
                        connection,
                        connect,
                        owned.unsubscribe,
                    );
                },
                .publish => |*owned| {
                    try task.broker.routePublish(
                        task.subscriber_id,
                        connection,
                        connect,
                        owned.publish,
                    );
                },
                .puback => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_owned =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (session_owned) {
                        task.broker.appendCommitIfEnabled() catch |err| {
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    }
                    if (!session_owned) connection.applyPubAck(
                        owned.ack,
                    ) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                    try task.broker.flushSlot(
                        task.slot_index,
                        slot,
                    );
                },
                .pubrec => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_owned =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (session_owned) {
                        task.broker.appendCommitIfEnabled() catch |err| {
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    }
                    if (!session_owned) connection.applyPubRec(
                        owned.ack,
                    ) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                    if (session_owned) {
                        try task.broker.flushSlot(
                            task.slot_index,
                            slot,
                        );
                    }
                },
                .pubrel => |*owned| {
                    try task.broker.handlePubRel(
                        task.subscriber_id,
                        connection,
                        owned.ack,
                    );
                },
                .pubcomp => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_owned =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (session_owned) {
                        task.broker.appendCommitIfEnabled() catch |err| {
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    }
                    if (!session_owned) connection.applyPubComp(
                        owned.ack,
                    ) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                    try task.broker.flushSlot(
                        task.slot_index,
                        slot,
                    );
                },
                .pingreq => {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    connection.writePingResp() catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                },
                .disconnect => |*owned| {
                    try task.broker.handleDisconnect(
                        slot,
                        owned.disconnect,
                    );
                    return;
                },
            }
        }
    }

    fn disconnectForReadViolation(
        task: ClientTask,
        slot: *ClientSlot,
        connection: *runtime.Connection,
        err: anyerror,
    ) !bool {
        const reason_code = disconnectReasonForReadViolation(err) orelse
            return false;
        if (connection.protocol == .v5) {
            slot.writer_mutex.lockUncancelable(task.broker.io);
            defer slot.writer_mutex.unlock(task.broker.io);
            connection.writeDisconnectWithProperties(
                reason_code,
                &.{},
            ) catch |write_err| switch (write_err) {
                // A peer can close first or advertise a Maximum Packet Size
                // too small for the four-byte MQTT 5 DISCONNECT. In both
                // cases closing the Network Connection is the required
                // fallback, so do not turn client behavior into a broker-wide
                // serve failure.
                error.OutgoingPacketTooLarge => {},
                else => if (!ungracefulTransportClose(write_err)) {
                    return write_err;
                },
            };
        }
        return true;
    }
};

fn disconnectReasonForReadViolation(err: anyerror) ?u8 {
    return switch (err) {
        error.QoSNotSupported => 0x9b,
        error.RetainNotSupported => 0x9a,
        error.TopicAliasInvalid => 0x94,
        error.ReceiveMaximumExceeded => 0x93,
        error.SharedSubscriptionsNotSupported => 0x9e,
        error.SubscriptionIdentifiersNotSupported => 0xa1,
        error.WildcardSubscriptionsNotSupported => 0xa2,
        error.InvalidPacketType,
        error.InvalidFlags,
        error.InvalidQoS,
        error.InvalidProperty,
        error.InvalidReasonCode,
        error.InvalidTopic,
        error.InvalidSubscription,
        error.InvalidPacketIdentifier,
        error.UnexpectedPacket,
        => 0x82,
        error.BufferTooShort,
        error.MalformedRemainingLength,
        error.RemainingLengthTooLarge,
        error.InvalidUtf8,
        => 0x81,
        error.PacketTooLarge => 0x95,
        else => null,
    };
}

test "broker maps negotiated capability violations to DISCONNECT reasons" {
    try std.testing.expectEqual(
        @as(?u8, 0x9b),
        disconnectReasonForReadViolation(error.QoSNotSupported),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x9a),
        disconnectReasonForReadViolation(error.RetainNotSupported),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x93),
        disconnectReasonForReadViolation(error.ReceiveMaximumExceeded),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x94),
        disconnectReasonForReadViolation(error.TopicAliasInvalid),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x9e),
        disconnectReasonForReadViolation(
            error.SharedSubscriptionsNotSupported,
        ),
    );
    try std.testing.expectEqual(
        @as(?u8, 0xa1),
        disconnectReasonForReadViolation(
            error.SubscriptionIdentifiersNotSupported,
        ),
    );
    try std.testing.expectEqual(
        @as(?u8, 0xa2),
        disconnectReasonForReadViolation(
            error.WildcardSubscriptionsNotSupported,
        ),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReasonForReadViolation(error.InvalidProperty),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReasonForReadViolation(error.InvalidQoS),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidUtf8),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x95),
        disconnectReasonForReadViolation(error.PacketTooLarge),
    );
}

fn ungracefulTransportClose(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.ConnectionAborted,
        error.SocketUnconnected,
        error.Timeout,
        => true,
        else => false,
    };
}

fn earliestDeadline(
    a: ?std.Io.Timestamp,
    b: ?std.Io.Timestamp,
) ?std.Io.Timestamp {
    const left = a orelse return b;
    const right = b orelse return left;
    return if (left.nanoseconds <= right.nanoseconds) left else right;
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

fn maxQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
}

fn protocolReason(
    protocol: mqtt.ProtocolVersion,
    reason_code: u8,
) u8 {
    // MQTT 3.1.1 ACK packets have no reason-code field. Success is the only
    // representable response; MQTT 5 keeps the broker's richer result.
    return if (protocol == .v5) reason_code else 0;
}

fn subscriptionDeniedReason(protocol: mqtt.ProtocolVersion) u8 {
    // MQTT 3.1.1 uses the generic SUBACK failure byte. MQTT 5 can expose the
    // precise Not Authorized reason without terminating the connection.
    return if (protocol == .v5) 0x87 else 0x80;
}

fn unsubscribeDeniedReason(protocol: mqtt.ProtocolVersion) u8 {
    // MQTT 3.1.1 UNSUBACK has no per-filter result. The subscription stays in
    // place while the only representable acknowledgement remains Success.
    return if (protocol == .v5) 0x87 else 0x00;
}

fn validateProblemInformationProperties(
    properties: []const mqtt.Property,
) Error!void {
    var has_reason_string = false;
    for (properties) |property| {
        switch (property) {
            .utf8 => |value| {
                if (value.id != .reason_string or has_reason_string) {
                    return error.InvalidProperty;
                }
                if (value.value.len > std.math.maxInt(u16)) {
                    return error.InvalidProperty;
                }
                try mqtt.validateUtf8String(value.value);
                has_reason_string = true;
            },
            .utf8_pair => |value| {
                if (value.id != .user_property) {
                    return error.InvalidProperty;
                }
                if (value.key.len > std.math.maxInt(u16) or
                    value.value.len > std.math.maxInt(u16))
                {
                    return error.InvalidProperty;
                }
                try mqtt.validateUtf8String(value.key);
                try mqtt.validateUtf8String(value.value);
            },
            else => return error.InvalidProperty,
        }
    }
}

test {
    _ = @import("broker_tests.zig");
    _ = @import("broker/persistence_tests.zig");
}

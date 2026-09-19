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
const listener_namespace = @import("listener_namespace.zig");
const client_id_mod = @import("broker/client_id.zig");
const load_metrics = @import("broker/load_metrics.zig");
const persistence_mod = @import("persistence/mod.zig");
const commit_log_mod = persistence_mod.commit_log;
const qos2_mod = @import("broker/qos2.zig");
pub const bridge_qos2_mod = @import("broker/bridge_qos2.zig");
pub const BridgeQoS2Store = bridge_qos2_mod.Store;
pub const BridgeQoS2Key = bridge_qos2_mod.Key;
pub const BridgeQoS2StageResult = bridge_qos2_mod.StageResult;
pub const BridgeQoS2StageOptions = struct {
    /// Mirrors the upstream PUBLISH DUP bit. The stored local message always
    /// clears this connection-scoped flag.
    duplicate: bool = false,
};

pub const BridgeQoS2ReleaseResult = enum {
    applied,
    already_applied,
    unknown,
};

pub const BridgeQoS2Release = struct {
    disposition: BridgeQoS2ReleaseResult,
    /// A non-null error means durable admission succeeded but one or more live
    /// subscriber writes did not. The caller may still complete upstream QoS 2:
    /// retransmitting PUBREL cannot safely repeat the already-persisted route.
    delivery_error: ?anyerror = null,
};
const publication_mod = @import("broker/publication.zig");
const session_delivery = @import("broker/session_delivery.zig");
const session_route = @import("broker/session_route.zig");
const deadline_driver_mod = @import("broker/deadline_driver.zig");
const retained_mod = @import("retained/mod.zig");
const session_mod = @import("session/mod.zig");
const will_mod = @import("will/mod.zig");

const net = std.Io.net;

pub const LoadRates = load_metrics.Rates;
pub const LoadSnapshot = load_metrics.Snapshot;

pub const Error = runtime.Error || router_mod.Error ||
    retained_mod.Error || publication_mod.Error || qos2_mod.Error ||
    bridge_qos2_mod.Error ||
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

/// Save a live broker snapshot after this many persistent state changes.
///
/// `dir` remains borrowed for the lifetime of the Broker. `sub_path` is
/// deep-copied by `Broker.init`, matching the ownership contract of the other
/// string-bearing broker options.
pub const ChangeAutosaveOptions = struct {
    dir: std.Io.Dir,
    sub_path: []const u8,
    max_changes: usize,
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
    bridge_qos2: bridge_qos2_mod.Options = .{},
    /// Mosquitto-compatible opt-in that sends messages at the subscription
    /// QoS even when that raises the publisher's original QoS. MQTT otherwise
    /// requires min(source QoS, granted subscription QoS), which remains the
    /// default.
    upgrade_outgoing_qos: bool = false,
    /// Mosquitto-compatible opt-in for retaining QoS 0 Application Messages
    /// while a persistent Session is offline. The MQTT-oriented default drops
    /// those messages because delivery has no reliability guarantee.
    queue_qos0_messages: bool = false,
    /// Re-evaluate the original publisher's current write authorization before
    /// replaying a retained Application Message. Mosquitto enables this by
    /// default to prevent a retained write from surviving later ACL revocation.
    check_retain_source: bool = true,
    /// Reject network-client writes to broker-owned `$SYS` topics and to the
    /// `$share` subscription namespace. The Mosquitto-compatible
    /// `$SYS/broker/connection/+/state` bridge-status shape remains allowed.
    /// Trusted `publishLocal` producers do not cross this client boundary.
    protect_reserved_topics: bool = true,
    /// Mosquitto-compatible administrative upper bound for a durable
    /// Session's offline lifetime. Null leaves the protocol value unchanged.
    /// This also bounds MQTT 3.1.1 CleanSession=0, whose native lifetime is
    /// otherwise unlimited. The cap applies to CONNECT, a later MQTT 5
    /// DISCONNECT override, and the Session lifetime that bounds Will Delay.
    /// Zero is rejected because it would silently turn every persistent
    /// request into a transient Session.
    persistent_session_expiry_seconds: ?u32 = null,
    /// Publish retained `$SYS` gauge snapshots at this interval. Null disables
    /// periodic publication. Explicit `publishSystemStats` remains available.
    system_stats_interval: ?std.Io.Duration = null,
    /// Optional broker-managed snapshot policy driven by durable mutations.
    ///
    /// The path is copied during initialization. The directory handle remains
    /// borrowed and must stay valid until `Broker.deinit` returns.
    persistent_change_autosave: ?ChangeAutosaveOptions = null,
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
    /// Transport-aware counterpart to `connect_authorization`. When both are
    /// configured they must both approve the connection.
    connect_context_authorization: ?ConnectContextAuthorizationHandler = null,
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

/// CONNECT authorization context combining the MQTT identity with transport
/// provenance. Trusted PROXY v2 TLVs are exposed without overwriting MQTT's
/// username, so applications can require a verified edge TLS assertion while
/// retaining the original protocol credentials for auditing.
pub const ConnectContext = struct {
    connect: mqtt.Connect,
    remote_address: net.IpAddress,
    proxy: ?*const mqtt.proxy_protocol.Metadata,
    peer_certificates: ?[]const []const u8,
};

pub const ConnectContextAuthorizationHandler = struct {
    context: *anyopaque,
    /// The request and every nested slice are borrowed for this call only.
    authorize: *const fn (
        context: *anyopaque,
        request: ConnectContext,
    ) bool,
};

/// Optional CONNECT admission overlay for one listener. Broker-wide
/// authorization remains mandatory when configured; listener callbacks add
/// narrower credentials or transport requirements without weakening it.
pub const ListenerAuthorization = struct {
    connect: ?ConnectAuthorizationHandler = null,
    connect_context: ?ConnectContextAuthorizationHandler = null,
    access_control: ?ListenerAccessControlHandler = null,
    /// Mosquitto-compatible listener policy that uses the authenticated MQTT
    /// username as the effective Client Identifier. CONNECT authorization is
    /// evaluated first against the original wire identity; Session, Will,
    /// takeover, ACL and delivery state then consistently use the username.
    /// A missing username is refused as Not Authorized.
    use_username_as_client_id: bool = false,
};

/// Per-listener packet policy. Every callback is optional because this is an
/// overlay: configured broker-wide ACL callbacks are always evaluated first.
/// Delayed Wills intentionally remain broker-scoped because they can outlive
/// both the listener serve call and its borrowed callback context.
pub const ListenerAccessControlHandler = struct {
    context: *anyopaque,
    authorize_publish: ?*const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool = null,
    authorize_subscribe: ?*const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        subscription: mqtt.Subscription,
    ) bool = null,
    authorize_unsubscribe: ?*const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        topic_filter: []const u8,
    ) bool = null,
    authorize_delivery: ?*const fn (
        context: *anyopaque,
        delivery: DeliveryAuthorization,
    ) bool = null,
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
    authorize_retained_source: ?*const fn (
        context: *anyopaque,
        publication: RetainedSourceAuthorization,
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

/// Original retained publisher and Application Message metadata for replay-
/// time write authorization. The Client Identifier is owned by retained state
/// and remains available after disconnect, Session expiry, and snapshot load.
pub const RetainedSourceAuthorization = struct {
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
    // Runs under the connection's writer lock so AUTH responses cannot
    // interleave with broker fanout. It must not re-enter this Broker.
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

const WillPublishProgress = struct {
    /// Any snapshot-visible mutation, including unrelated expiry pruning.
    persistent_changed: bool = false,
    /// The Will changed retained state or entered at least one durable Session
    /// queue. Once true, retrying the claimed Will could duplicate delivery.
    publication_effect_committed: bool = false,
};

const Registration = struct {
    subscriber_id: router_mod.SubscriberId,
    replaced_owner_id: ?router_mod.SubscriberId,
    persistent_changed: bool,
};

const RegistrationProgress = struct {
    /// Net durable change left after a failed registration is rolled back.
    /// New provisional Session/Will objects do not count because abort removes
    /// them; expiry pruning and replacement of prior durable state do.
    rollback_changed: bool = false,
};

const EncodedSessionPacket = struct {
    encoded: session_route.EncodedPacket,
    transmission: session_mod.Transmission,
    handle: session_mod.Handle,
    route_id: u64,

    fn deinit(self: *EncodedSessionPacket) void {
        self.encoded.deinit();
        self.* = undefined;
    }
};

const SessionAckResult = struct {
    owned: bool,
    persistent_changed: bool,
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
    /// Borrowed from the active listener descriptor. It is cleared before the
    /// slot can be reused and is never persisted with a durable Session.
    listener_access_control: ?ListenerAccessControlHandler = null,
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

/// Point-in-time broker gauges. The snapshot is collected under the same state
/// lock as routing and Session transitions, so cross-field invariants describe
/// one coherent instant rather than a mixture of concurrent updates.
pub const Stats = struct {
    uptime_seconds: u64,
    /// Successfully parsed CONNECT packets admitted to the broker core.
    connections_received: u64,
    active_connections: usize,
    maximum_active_connections: usize,
    expired_sessions: usize,
    /// Complete MQTT Control Packets and their encoded MQTT bytes across all
    /// broker connections and transports. TCP/TLS/WebSocket framing is not
    /// included, matching Mosquitto's `$SYS/broker/messages/*` and
    /// `$SYS/broker/bytes/*` counter boundary.
    messages_received: u64,
    messages_sent: u64,
    bytes_received: u64,
    bytes_sent: u64,
    /// Successfully parsed client PUBLISH packets accepted by the broker
    /// dispatch loop. Retransmissions count as packets, matching Mosquitto's
    /// `$SYS/broker/publish/messages/received` counter.
    publish_messages_received: usize,
    publish_payload_bytes_received: usize,
    /// Outbound Application Messages discarded because a destination queue or
    /// negotiated packet-size bound could not admit them.
    publish_messages_dropped: usize,
    /// PUBLISH packets successfully written to subscribers. Retransmissions
    /// and retained/session replays count again because they consume wire work.
    publish_messages_sent: usize,
    publish_payload_bytes_sent: usize,
    sessions: usize,
    connected_sessions: usize,
    disconnected_sessions: usize,
    subscriptions: usize,
    shared_subscriptions: usize,
    retained_messages: usize,
    retained_bytes: usize,
    live_queued_deliveries: usize,
    session_queued_messages: usize,
    session_queued_payload_bytes: usize,
    session_inflight_messages: usize,
    session_inflight_payload_bytes: usize,
    pending_incoming_qos2: usize,
    scheduled_wills: usize,
    scheduled_will_bytes: usize,
    session_owned_bytes: usize,
    /// Latest rates sampled by `publishSystemStats`. Values are expressed as
    /// events/bytes per minute and begin at zero until a second sample.
    load: LoadSnapshot,
};

/// Stable `$SYS` gauge names emitted by `publishSystemStats`. Applications may
/// expose the same snapshot through another telemetry backend without parsing
/// topic strings.
pub const SystemMetric = enum {
    uptime,
    clients_connected,
    clients_maximum,
    clients_disconnected,
    clients_expired,
    clients_total,
    messages_received,
    messages_sent,
    bytes_received,
    bytes_sent,
    publish_messages_received,
    publish_messages_dropped,
    publish_messages_sent,
    publish_bytes_received,
    publish_bytes_sent,
    subscriptions,
    shared_subscriptions,
    retained_messages,
    retained_bytes,
    live_queued_deliveries,
    session_queued_messages,
    session_queued_payload_bytes,
    session_inflight_messages,
    session_inflight_payload_bytes,
    pending_incoming_qos2,
    scheduled_wills,
    scheduled_will_bytes,
    session_owned_bytes,
    load_messages_received_1min,
    load_messages_received_5min,
    load_messages_received_15min,
    load_messages_sent_1min,
    load_messages_sent_5min,
    load_messages_sent_15min,
    load_publish_dropped_1min,
    load_publish_dropped_5min,
    load_publish_dropped_15min,
    load_publish_received_1min,
    load_publish_received_5min,
    load_publish_received_15min,
    load_publish_sent_1min,
    load_publish_sent_5min,
    load_publish_sent_15min,
    load_bytes_received_1min,
    load_bytes_received_5min,
    load_bytes_received_15min,
    load_bytes_sent_1min,
    load_bytes_sent_5min,
    load_bytes_sent_15min,
    load_connections_1min,
    load_connections_5min,
    load_connections_15min,

    pub fn topic(self: SystemMetric) []const u8 {
        return switch (self) {
            .uptime => "$SYS/broker/uptime",
            .clients_connected => "$SYS/broker/clients/connected",
            .clients_maximum => "$SYS/broker/clients/maximum",
            .clients_disconnected => "$SYS/broker/clients/disconnected",
            .clients_expired => "$SYS/broker/clients/expired",
            .clients_total => "$SYS/broker/clients/total",
            .messages_received => "$SYS/broker/messages/received",
            .messages_sent => "$SYS/broker/messages/sent",
            .bytes_received => "$SYS/broker/bytes/received",
            .bytes_sent => "$SYS/broker/bytes/sent",
            .publish_messages_received => "$SYS/broker/publish/messages/received",
            .publish_messages_dropped => "$SYS/broker/publish/messages/dropped",
            .publish_messages_sent => "$SYS/broker/publish/messages/sent",
            .publish_bytes_received => "$SYS/broker/publish/bytes/received",
            .publish_bytes_sent => "$SYS/broker/publish/bytes/sent",
            .subscriptions => "$SYS/broker/subscriptions/count",
            .shared_subscriptions => "$SYS/broker/shared_subscriptions/count",
            .retained_messages => "$SYS/broker/retained messages/count",
            .retained_bytes => "$SYS/broker/store/retained/bytes",
            .live_queued_deliveries => "$SYS/broker/store/live/queued/count",
            .session_queued_messages => "$SYS/broker/store/session/queued/count",
            .session_queued_payload_bytes => "$SYS/broker/store/session/queued/payload bytes",
            .session_inflight_messages => "$SYS/broker/store/session/inflight/count",
            .session_inflight_payload_bytes => "$SYS/broker/store/session/inflight/payload bytes",
            .pending_incoming_qos2 => "$SYS/broker/store/incoming qos2/count",
            .scheduled_wills => "$SYS/broker/wills/scheduled/count",
            .scheduled_will_bytes => "$SYS/broker/wills/scheduled/bytes",
            .session_owned_bytes => "$SYS/broker/store/session/bytes",
            .load_messages_received_1min => "$SYS/broker/load/messages/received/1min",
            .load_messages_received_5min => "$SYS/broker/load/messages/received/5min",
            .load_messages_received_15min => "$SYS/broker/load/messages/received/15min",
            .load_messages_sent_1min => "$SYS/broker/load/messages/sent/1min",
            .load_messages_sent_5min => "$SYS/broker/load/messages/sent/5min",
            .load_messages_sent_15min => "$SYS/broker/load/messages/sent/15min",
            .load_publish_dropped_1min => "$SYS/broker/load/publish/dropped/1min",
            .load_publish_dropped_5min => "$SYS/broker/load/publish/dropped/5min",
            .load_publish_dropped_15min => "$SYS/broker/load/publish/dropped/15min",
            .load_publish_received_1min => "$SYS/broker/load/publish/received/1min",
            .load_publish_received_5min => "$SYS/broker/load/publish/received/5min",
            .load_publish_received_15min => "$SYS/broker/load/publish/received/15min",
            .load_publish_sent_1min => "$SYS/broker/load/publish/sent/1min",
            .load_publish_sent_5min => "$SYS/broker/load/publish/sent/5min",
            .load_publish_sent_15min => "$SYS/broker/load/publish/sent/15min",
            .load_bytes_received_1min => "$SYS/broker/load/bytes/received/1min",
            .load_bytes_received_5min => "$SYS/broker/load/bytes/received/5min",
            .load_bytes_received_15min => "$SYS/broker/load/bytes/received/15min",
            .load_bytes_sent_1min => "$SYS/broker/load/bytes/sent/1min",
            .load_bytes_sent_5min => "$SYS/broker/load/bytes/sent/5min",
            .load_bytes_sent_15min => "$SYS/broker/load/bytes/sent/15min",
            .load_connections_1min => "$SYS/broker/load/connections/1min",
            .load_connections_5min => "$SYS/broker/load/connections/5min",
            .load_connections_15min => "$SYS/broker/load/connections/15min",
        };
    }
};

pub const Listener = struct {
    source: runtime.PendingSource,
    namespace: listener_namespace.Namespace = .{},
    /// Null inherits `Broker.Options.accept`; an override makes CONNECT and
    /// advertised capabilities listener-specific. Borrowed property strings
    /// must remain alive throughout `serveListeners`.
    accept: ?runtime.AcceptOptions = null,
    /// Additional listener-local CONNECT authorization. Callback state is
    /// borrowed and must remain alive throughout `serveListeners`.
    authorization: ListenerAuthorization = .{},
    /// Finite accept count for deterministic process/test teardown.
    connection_count: usize,
};

/// One endpoint in a long-running heterogeneous listener service.
///
/// Multiple workers permit TLS and HTTP Upgrade handshakes and established
/// connections to overlap. Their aggregate concurrency must fit the Broker's
/// `max_connections`; each worker accepts another client after its prior one
/// disconnects or is refused.
pub const ListenerEndpoint = struct {
    source: runtime.PendingSource,
    namespace: listener_namespace.Namespace = .{},
    /// Null inherits `Broker.Options.accept`; borrowed values must remain alive
    /// throughout `serveListenersUntil`.
    accept: ?runtime.AcceptOptions = null,
    /// Additional listener-local CONNECT authorization. Callback state is
    /// borrowed and must remain alive throughout `serveListenersUntil`.
    authorization: ListenerAuthorization = .{},
    accept_concurrency: usize = 1,
};

pub const ListenerErrorStage = enum {
    accept,
    connection,
};

pub const ListenerErrorPolicy = enum {
    continue_serving,
    stop,
};

pub const ListenerErrorEvent = struct {
    listener_index: usize,
    stage: ListenerErrorStage,
    err: anyerror,
};

pub const ListenerErrorObserver = struct {
    context: *anyopaque,
    /// May run concurrently for independent listeners and connections.
    observe: *const fn (context: *anyopaque, event: ListenerErrorEvent) void,
};

pub const ServeListenersUntilOptions = struct {
    /// Setting this event cancels pending accepts and active client reads.
    shutdown: *std.Io.Event,
    /// Handshake and malformed-CONNECT errors normally affect only that peer.
    accept_error_policy: ListenerErrorPolicy = .continue_serving,
    /// Protocol/transport errors after CONNACK normally affect only that peer.
    connection_error_policy: ListenerErrorPolicy = .continue_serving,
    /// Prevent a failed/closed listener from becoming an unbounded retry loop.
    accept_error_backoff: std.Io.Duration = .fromMilliseconds(10),
    error_observer: ?ListenerErrorObserver = null,
};

pub const system_metrics = [_]SystemMetric{
    .uptime,
    .clients_connected,
    .clients_maximum,
    .clients_disconnected,
    .clients_expired,
    .clients_total,
    .messages_received,
    .messages_sent,
    .bytes_received,
    .bytes_sent,
    .publish_messages_received,
    .publish_messages_dropped,
    .publish_messages_sent,
    .publish_bytes_received,
    .publish_bytes_sent,
    .subscriptions,
    .shared_subscriptions,
    .retained_messages,
    .retained_bytes,
    .live_queued_deliveries,
    .session_queued_messages,
    .session_queued_payload_bytes,
    .session_inflight_messages,
    .session_inflight_payload_bytes,
    .pending_incoming_qos2,
    .scheduled_wills,
    .scheduled_will_bytes,
    .session_owned_bytes,
    .load_messages_received_1min,
    .load_messages_received_5min,
    .load_messages_received_15min,
    .load_messages_sent_1min,
    .load_messages_sent_5min,
    .load_messages_sent_15min,
    .load_publish_dropped_1min,
    .load_publish_dropped_5min,
    .load_publish_dropped_15min,
    .load_publish_received_1min,
    .load_publish_received_5min,
    .load_publish_received_15min,
    .load_publish_sent_1min,
    .load_publish_sent_5min,
    .load_publish_sent_15min,
    .load_bytes_received_1min,
    .load_bytes_received_5min,
    .load_bytes_received_15min,
    .load_bytes_sent_1min,
    .load_bytes_sent_5min,
    .load_bytes_sent_15min,
    .load_connections_1min,
    .load_connections_5min,
    .load_connections_15min,
};

/// A bounded broker core with an optional compatibility TCP listener.
///
/// `listen` preserves the original one-listener API. `init` plus
/// `serveListeners` or `serveListenersUntil` lets TCP/TLS/WS/WSS listeners
/// share the same router, retained store, Session store, Will scheduler and
/// deadline driver.
pub const Broker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: ?runtime.Server = null,
    options: Options,
    router: router_mod.Router,
    pending_qos2: qos2_mod.Store,
    bridge_qos2: bridge_qos2_mod.Store,
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
    /// Monotonic durable-state generations protected by `state_mutex`.
    ///
    /// Autosave captures `persistent_generation` together with encoded state,
    /// and acknowledges only that captured value after the atomic replacement
    /// succeeds. Mutations concurrent with disk I/O therefore remain pending.
    persistent_generation: u128 = 0,
    autosave_generation: u128 = 0,
    /// Last asynchronous checkpoint failure. Autosave is best-effort because
    /// its caller's broker mutation is already committed; returning the I/O
    /// error would falsely invite the caller to retry that mutation.
    persistent_change_autosave_error: ?anyerror = null,
    /// Cumulative lifecycle counters protected by `state_mutex`. They are
    /// intentionally process-local like Mosquitto's `$SYS` counters and are
    /// not restored from protocol-state snapshots.
    maximum_active_connections: usize = 0,
    connections_received: u64 = 0,
    expired_sessions: usize = 0,
    traffic: runtime.TrafficCounters = .{},
    publish_messages_received: usize = 0,
    publish_payload_bytes_received: usize = 0,
    publish_messages_dropped: usize = 0,
    publish_messages_sent: usize = 0,
    publish_payload_bytes_sent: usize = 0,
    started_at_ns: i96,
    load_tracker: load_metrics.Tracker = .{},
    next_system_stats_ns: ?i96 = null,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: Options,
    ) Error!Broker {
        var broker = try init(allocator, io, options);
        errdefer broker.deinit();
        broker.server = try runtime.Server.listen(
            allocator,
            io,
            bind_address,
            options.limits.runtime,
        );
        return broker;
    }

    /// Construct shared broker state without binding a transport listener.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
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
        if (options.system_stats_interval) |interval| {
            if (interval.nanoseconds <= 0) return error.InvalidProperty;
        }
        if (options.persistent_change_autosave) |autosave| {
            if (autosave.sub_path.len == 0 or autosave.max_changes == 0) {
                return error.InvalidProperty;
            }
        }
        if (options.persistent_session_expiry_seconds == 0) {
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
        const autosave_sub_path = if (options.persistent_change_autosave) |autosave|
            try allocator.dupe(u8, autosave.sub_path)
        else
            null;
        var autosave_path_owned = autosave_sub_path != null;
        errdefer if (autosave_path_owned) {
            allocator.free(autosave_sub_path.?);
        };
        if (owned_options.persistent_change_autosave) |*autosave| {
            autosave.sub_path = autosave_sub_path.?;
        }
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
        var bridge_qos2 = try bridge_qos2_mod.Store.init(
            allocator,
            options.bridge_qos2,
        );
        errdefer bridge_qos2.deinit();
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
        const started_at_ns = std.Io.Clock.awake.now(io).nanoseconds;
        const broker: Broker = .{
            .allocator = allocator,
            .io = io,
            .options = owned_options,
            .router = router,
            .pending_qos2 = pending_qos2,
            .bridge_qos2 = bridge_qos2,
            .retained = retained,
            .sessions = sessions,
            .wills = wills,
            .session_owners = session_owners,
            .will_publishers = will_publishers,
            .slots = slots,
            .started_at_ns = started_at_ns,
            // Establish a zero-counter baseline at process start so the first
            // periodic `$SYS` update covers the complete initial interval.
            .load_tracker = .init(started_at_ns),
        };
        // Ownership moved into `broker.options`; later initialization failures
        // above have already run their guards, while successful destruction is
        // centralized in `Broker.deinit`.
        autosave_path_owned = false;
        return broker;
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
        if (self.options.persistent_change_autosave) |autosave| {
            self.allocator.free(@constCast(autosave.sub_path));
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
        self.bridge_qos2.deinit();
        self.router.deinit();
        if (self.server) |*server| server.deinit();
        if (self.commit_log) |*log| log.deinit();
        self.* = undefined;
    }

    pub fn address(self: Broker) net.IpAddress {
        return self.server.?.address();
    }

    /// Wake every active client reader without racing slot ownership changes.
    /// The serving task still owns and closes each connection after it exits.
    pub fn shutdownActiveConnections(self: *Broker) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        for (self.slots) |*slot| {
            if (slot.connection) |*connection| {
                connection.shutdown() catch {};
            }
        }
    }

    /// Return a coherent, allocation-free snapshot suitable for metrics,
    /// health checks, and a future `$SYS` publisher.
    pub fn stats(self: *Broker) Stats {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.statsLocked();
    }

    /// Return the most recent background change-autosave failure.
    ///
    /// Autosave runs after a broker mutation has committed, so failures are
    /// observable here rather than returned from the mutation API as though
    /// the MQTT operation itself had failed. A later successful autosave
    /// clears the value.
    pub fn persistentChangeAutosaveError(self: *Broker) ?anyerror {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.persistent_change_autosave_error;
    }

    /// Enqueue a canonical publication for an existing offline Session.
    ///
    /// This uses the same bounded Session queue, expiry handling and journal
    /// boundary as routed fanout. It is useful to external broker components
    /// that restore or inject durable work without synthesizing a live client.
    pub fn enqueueSessionPublish(
        self: *Broker,
        client_id: []const u8,
        publish: mqtt.Publish,
        qos: mqtt.QoS,
        retain: bool,
        subscription_identifier: ?usize,
    ) Error!void {
        const now = std.Io.Clock.awake.now(self.io);
        self.state_mutex.lockUncancelable(self.io);
        var state_locked = true;
        var persistent_changed = self.pruneExpiredSessionRoutesLocked(now) != 0;
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        const handle = self.sessions.find(client_id, now) orelse {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            state_locked = false;
            self.finishPartialPersistentChange(persistent_changed);
            return error.SessionNotFound;
        };
        try self.enqueueSessionDeliveryLocked(
            handle,
            subscription_identifier,
            retain,
            qos,
            publish,
            now,
            &persistent_changed,
        );
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;
        try self.finalizePersistentChange(true, persistent_changed);
    }

    /// Publish a trusted, transport-independent Application Message.
    ///
    /// This is the ingress boundary for broker-owned producers such as an
    /// inbound bridge. It intentionally has no MQTT client identity, so write
    /// ACL and No Local checks do not apply to the source; ordinary recipient
    /// ACLs, retained storage, bounded live/Session queues, expiry, routing,
    /// and persistence use the exact same path as a released network PUBLISH.
    ///
    /// Packet Identifiers and DUP describe a transaction on one Network
    /// Connection. Callers must therefore remove them before crossing this
    /// boundary. In particular, forwarding a remote Packet Identifier would
    /// incorrectly make it meaningful in the local broker.
    pub fn publishLocal(
        self: *Broker,
        publish: mqtt.Publish,
    ) Error!void {
        try validateLocalPublish(publish);
        if (self.payloadTooLarge(publish.payload)) {
            return error.PacketTooLarge;
        }

        self.state_mutex.lockUncancelable(self.io);
        var state_locked = true;
        var persistent_changed = false;
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        const plan = self.enqueuePublishLocked(
            null,
            publish,
            null,
            std.Io.Clock.awake.now(self.io),
            &persistent_changed,
            null,
        ) catch |err| {
            return err;
        };
        defer self.allocator.free(plan.storage);
        self.publish_messages_received +|= 1;
        self.publish_payload_bytes_received +|= publish.payload.len;
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;

        // Neither durable I/O nor destination socket writes may hold the
        // global routing lock. The state mutation is complete at this point,
        // so journal it before making the publication visible on the wire.
        try self.finalizePersistentChange(
            persistent_changed,
            persistent_changed,
        );
        try self.flushPlan(plan);
    }

    /// Durably stage one already-mapped bridge QoS 2 Application Message.
    /// The returned result may be acknowledged upstream with PUBREC only after
    /// this call succeeds. The complete mapped message, not connection-scoped
    /// Topic Alias or Subscription Identifier metadata, becomes part of the
    /// broker snapshot/commit-log state.
    pub fn stageBridgeQoS2(
        self: *Broker,
        key: BridgeQoS2Key,
        publish: mqtt.Publish,
        options: BridgeQoS2StageOptions,
    ) Error!BridgeQoS2StageResult {
        var staged = publish;
        staged.dup = false;
        staged.packet_id = null;
        try validateLocalPublish(staged);
        if (staged.qos != .exactly_once) return error.InvalidQoS;
        if (self.payloadTooLarge(staged.payload)) return error.PacketTooLarge;
        staged.dup = options.duplicate;

        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        const result = self.bridge_qos2.stage(
            key,
            staged,
            std.Io.Clock.awake.now(self.io),
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        const changed = result != .duplicate;
        self.recordPersistentChangeLocked(changed);
        self.state_mutex.unlock(self.io);
        // A duplicate may be retrying an earlier call whose commit append
        // failed after the in-memory stage succeeded. Re-append the current
        // snapshot before permitting PUBREC even when no state changed now.
        try self.finalizePersistentChangeLocked(true, changed);
        return result;
    }

    /// Atomically move one staged bridge message through the broker's retained
    /// and durable Session admission boundary and install a released tombstone.
    /// Socket flushing happens only after that snapshot/commit-log transaction.
    /// A repeated release sees the tombstone and never enqueues the message
    /// again. Online delivery errors are reported separately from durable
    /// admission; callers may complete upstream QoS 2 because downstream
    /// Session retry/connection cleanup owns those already-admitted messages.
    pub fn releaseBridgeQoS2(
        self: *Broker,
        key: BridgeQoS2Key,
    ) Error!BridgeQoS2Release {
        self.persistence_mutex.lockUncancelable(self.io);
        var persistence_locked = true;
        defer if (persistence_locked) self.persistence_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        const phase = self.bridge_qos2.getPhase(key) orelse {
            self.state_mutex.unlock(self.io);
            // An earlier successful tombstone deletion may have been followed
            // by an ambiguous commit-log append. Rewriting the current state
            // closes that durability gap before reporting the missing key.
            try self.finalizePersistentChangeLocked(true, false);
            return .{ .disposition = .unknown };
        };
        if (phase == .released) {
            self.state_mutex.unlock(self.io);
            // The first release may have installed the in-memory tombstone
            // before its journal append failed. Retry persistence on every
            // duplicate PUBREL before reporting an idempotent completion.
            try self.finalizePersistentChangeLocked(true, true);
            return .{ .disposition = .already_applied };
        }
        const release_now = std.Io.Clock.awake.now(self.io);
        var adjusted_properties: std.ArrayList(mqtt.Property) = .empty;
        defer adjusted_properties.deinit(self.allocator);
        const maybe_publish = self.bridge_qos2.pendingAsPublish(
            key,
            release_now,
            &adjusted_properties,
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        const publish = maybe_publish orelse {
            // PUBREL still completes an expired transaction. Persisting the
            // tombstone before reporting success prevents a repeated PUBREL
            // from reviving an Application Message whose lifetime elapsed.
            if (!self.bridge_qos2.markReleased(key)) {
                self.state_mutex.unlock(self.io);
                return error.InvalidReleaseState;
            }
            self.recordPersistentChangeLocked(true);
            self.state_mutex.unlock(self.io);
            try self.finalizePersistentChangeLocked(true, true);
            self.persistence_mutex.unlock(self.io);
            persistence_locked = false;
            return .{ .disposition = .applied };
        };
        const released_payload_len = publish.payload.len;
        var persistent_changed = false;
        var publication_effect_committed = false;
        const plan = self.enqueuePublishLocked(
            null,
            publish,
            null,
            release_now,
            &persistent_changed,
            &publication_effect_committed,
        ) catch |err| {
            if (publication_effect_committed) {
                if (!self.bridge_qos2.markReleased(key)) {
                    self.state_mutex.unlock(self.io);
                    return error.InvalidReleaseState;
                }
                self.recordPersistentChangeLocked(true);
                self.state_mutex.unlock(self.io);
                // Some durable effect has already escaped. Persist that state
                // and consume the transaction rather than retrying a partial
                // fanout and duplicating its successful prefix.
                try self.finalizePersistentChangeLocked(true, true);
                self.persistence_mutex.unlock(self.io);
                persistence_locked = false;
                return .{
                    .disposition = .applied,
                    .delivery_error = err,
                };
            }
            self.state_mutex.unlock(self.io);
            return err;
        };
        defer self.allocator.free(plan.storage);
        if (!self.bridge_qos2.markReleased(key)) {
            self.state_mutex.unlock(self.io);
            return error.InvalidReleaseState;
        }
        self.publish_messages_received +|= 1;
        self.publish_payload_bytes_received +|= released_payload_len;
        self.recordPersistentChangeLocked(true);
        self.state_mutex.unlock(self.io);
        try self.finalizePersistentChangeLocked(true, true);
        self.persistence_mutex.unlock(self.io);
        persistence_locked = false;

        // Durable admission is already complete. A subscriber write error must
        // not make a repeated PUBREL enqueue the Application Message again.
        const delivery_error: ?anyerror = blk: {
            self.flushPlan(plan) catch |err| break :blk err;
            break :blk null;
        };
        return .{
            .disposition = .applied,
            .delivery_error = delivery_error,
        };
    }

    /// Forget a released bridge tombstone after the corresponding upstream
    /// PUBCOMP has been written successfully. The deletion is itself
    /// persisted; retrying after an ambiguous append writes the current
    /// snapshot again and remains idempotent. Pending messages cannot be
    /// completed without first crossing `releaseBridgeQoS2`.
    pub fn completeBridgeQoS2(
        self: *Broker,
        key: BridgeQoS2Key,
    ) Error!bool {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        if (self.bridge_qos2.getPhase(key) == .pending) {
            self.state_mutex.unlock(self.io);
            return error.InvalidReleaseState;
        }
        const removed = self.bridge_qos2.complete(key);
        self.recordPersistentChangeLocked(removed);
        self.state_mutex.unlock(self.io);
        // Even an absent key can be a retry after an in-memory deletion whose
        // previous journal append failed. Re-appending is the only way to make
        // the idempotent result durable before its caller forgets the key.
        self.appendCommitIfEnabledLocked() catch |err| {
            if (removed) {
                self.state_mutex.lockUncancelable(self.io);
                self.bridge_qos2.restoreReleased(key);
                self.state_mutex.unlock(self.io);
            }
            return err;
        };
        self.finishPersistentChangeLocked(removed);
        return removed;
    }

    pub fn latestBridgeQoS2SessionEpoch(
        self: *Broker,
        bridge_id: [16]u8,
    ) ?u64 {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.bridge_qos2.latestSessionEpoch(bridge_id);
    }

    /// Test whether a bridge transaction still exists after a best-effort
    /// post-PUBCOMP tombstone cleanup.
    pub fn containsBridgeQoS2(
        self: *Broker,
        key: BridgeQoS2Key,
    ) bool {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.bridge_qos2.contains(key);
    }

    /// Copy the inbound QoS 2 protocol markers a recreated bridge client must
    /// restore before reading traffic from a resumed upstream Session.
    pub fn bridgeQoS2SessionTransactionsAlloc(
        self: *Broker,
        allocator: std.mem.Allocator,
        bridge_id: [16]u8,
        session_epoch: u64,
    ) std.mem.Allocator.Error![]bridge_qos2_mod.Transaction {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.bridge_qos2.sessionTransactionsAlloc(
            allocator,
            bridge_id,
            session_epoch,
        );
    }

    /// Retire every durable transaction and advance the stable bridge epoch
    /// after the upstream CONNACK reports Session Present=false. Both changes
    /// enter one commit-log record before the Bridge accepts a new PUBLISH.
    pub fn beginBridgeQoS2Session(
        self: *Broker,
        bridge_id: [16]u8,
    ) Error!u64 {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        const epoch = self.bridge_qos2.advanceSession(bridge_id) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        _ = self.bridge_qos2.removeBridge(bridge_id);
        self.recordPersistentChangeLocked(true);
        self.state_mutex.unlock(self.io);
        try self.finalizePersistentChangeLocked(true, true);
        return epoch;
    }

    fn statsLocked(self: *const Broker) Stats {
        var active_connections: usize = 0;
        var live_queued_deliveries: usize = 0;
        for (self.slots) |slot| {
            active_connections +|= @intFromBool(slot.active);
            live_queued_deliveries +|= slot.queuedCount();
        }
        const sessions = self.sessions.aggregateStats();
        const traffic = self.traffic.stats();
        return .{
            .uptime_seconds = uptimeSeconds(
                self.started_at_ns,
                std.Io.Clock.awake.now(self.io).nanoseconds,
            ),
            .connections_received = self.connections_received,
            .active_connections = active_connections,
            .maximum_active_connections = self.maximum_active_connections,
            .expired_sessions = self.expired_sessions,
            .messages_received = traffic.messages_received,
            .messages_sent = traffic.messages_sent,
            .bytes_received = traffic.bytes_received,
            .bytes_sent = traffic.bytes_sent,
            .publish_messages_received = self.publish_messages_received,
            .publish_payload_bytes_received = self.publish_payload_bytes_received,
            .publish_messages_dropped = self.publish_messages_dropped,
            .publish_messages_sent = self.publish_messages_sent,
            .publish_payload_bytes_sent = self.publish_payload_bytes_sent,
            .sessions = sessions.session_count,
            .connected_sessions = sessions.connected_count,
            .disconnected_sessions = sessions.disconnected_count,
            .subscriptions = self.router.subscriptionCount(),
            .shared_subscriptions = self.router.sharedSubscriptionCount(),
            .retained_messages = self.retained.count(),
            .retained_bytes = self.retained.totalBytes(),
            .live_queued_deliveries = live_queued_deliveries,
            .session_queued_messages = sessions.queued_count,
            .session_queued_payload_bytes = sessions.queued_payload_bytes,
            .session_inflight_messages = sessions.inflight_count,
            .session_inflight_payload_bytes = sessions.inflight_payload_bytes,
            .pending_incoming_qos2 = self.pending_qos2.count(),
            .scheduled_wills = self.wills.count(),
            .scheduled_will_bytes = self.wills.totalBytes(),
            .session_owned_bytes = sessions.owned_wire_bytes,
            .load = self.load_tracker.snapshot,
        };
    }

    /// Publish one coherent gauge snapshot as retained QoS 0 `$SYS` messages.
    ///
    /// Every value is derived before the first retained/router mutation, so
    /// subscribers observe one logical snapshot even though MQTT transports
    /// carry its topics as distinct Application Messages. The system
    /// publications use the normal routing, overlap, ACL, queue-bound and
    /// protocol-conversion paths; no privileged delivery bypass is created.
    pub fn publishSystemStats(self: *Broker) Error!void {
        var plans: [system_metrics.len]RoutePlan = undefined;
        var plan_count: usize = 0;
        defer for (plans[0..plan_count]) |plan| {
            self.allocator.free(plan.storage);
        };
        var payloads: [system_metrics.len][64]u8 = undefined;

        self.state_mutex.lockUncancelable(self.io);
        var snapshot = self.statsLocked();
        snapshot.load = self.load_tracker.sample(
            std.Io.Clock.awake.now(self.io).nanoseconds,
            loadCounters(snapshot),
        );
        for (system_metrics, 0..) |metric, index| {
            const payload = formatSystemMetric(
                &payloads[index],
                snapshot,
                metric,
            );
            const plan = self.enqueuePublishLocked(
                null,
                .{
                    .dup = false,
                    .qos = .at_most_once,
                    .retain = true,
                    .topic = metric.topic(),
                    .packet_id = null,
                    .properties = &.{},
                    .payload = payload,
                },
                null,
                std.Io.Clock.awake.now(self.io),
                null,
                null,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            plans[plan_count] = plan;
            plan_count += 1;
        }
        self.state_mutex.unlock(self.io);

        // Persist the complete retained snapshot before any subscriber can
        // observe it, then perform socket writes outside the global state lock.
        try self.appendCommitIfEnabled();
        for (plans[0..plan_count]) |plan| try self.flushPlan(plan);
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

    /// Return whether durable mutations synchronously append to a crash-safe
    /// journal before their MQTT acknowledgement boundary is exposed.
    pub fn commitLogEnabled(self: *Broker) bool {
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        return self.commit_log != null;
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

    /// Append while the caller already owns `persistence_mutex`.
    fn appendCommitIfEnabledLocked(self: *Broker) Error!void {
        if (self.commit_log == null) return;
        const log = &self.commit_log.?;
        const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            break :blk try self.encodeLiveStateLocked(false);
        };
        defer self.allocator.free(encoded);
        _ = try log.append(encoded);
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

    /// Record one externally meaningful persistent transition. Callers group
    /// all store mutations belonging to one broker operation into one change.
    /// This must be called while `state_mutex` is held.
    fn recordPersistentChangeLocked(self: *Broker, changed: bool) void {
        if (!changed) return;
        if (self.persistent_generation == std.math.maxInt(u128)) {
            // Preserve all outstanding debt while rebasing away from the
            // saturation edge. Values above every practical threshold remain
            // represented as `maxInt(usize)`.
            const pending = self.pendingAutosaveChangesLocked();
            self.persistent_generation = @min(
                pending,
                std.math.maxInt(usize),
            );
            self.autosave_generation = 0;
        }
        self.persistent_generation += 1;
    }

    /// Retry an eligible checkpoint without changing the result of the broker
    /// operation that made it necessary.
    fn finishPersistentChange(self: *Broker, changed: bool) void {
        if (changed) self.autosavePersistentChangesIfNeeded();
    }

    /// Persist an already-recorded durable transition through every enabled
    /// backend. Journal failures remain synchronous errors because callers may
    /// be waiting to expose an MQTT acknowledgement, but they must not suppress
    /// an independently configured best-effort autosave. `append_commit` is
    /// separate from `changed`: retransmission selection is journaled for its
    /// wire state even when it does not alter the snapshot representation.
    fn finalizePersistentChange(
        self: *Broker,
        append_commit: bool,
        changed: bool,
    ) Error!void {
        defer self.finishPersistentChange(changed);
        if (append_commit) try self.appendCommitIfEnabled();
    }

    /// Variant for callers that already own `persistence_mutex`. The global
    /// lock order remains persistence then state for both journal and autosave
    /// capture. Callers must have released `state_mutex` before entering.
    fn finalizePersistentChangeLocked(
        self: *Broker,
        append_commit: bool,
        changed: bool,
    ) Error!void {
        defer self.finishPersistentChangeLocked(changed);
        if (append_commit) try self.appendCommitIfEnabledLocked();
    }

    /// Preserve a partially completed durable transition without replacing the
    /// operation's original error. Both persistence mechanisms are retried on
    /// later mutations if their best-effort write fails here.
    fn finishPartialPersistentChange(self: *Broker, changed: bool) void {
        if (!changed) return;
        self.finalizePersistentChange(true, true) catch {};
    }

    fn finishPersistentChangeLocked(self: *Broker, changed: bool) void {
        if (changed) self.autosavePersistentChangesIfNeededLocked();
    }

    fn finishPartialPersistentChangeLocked(
        self: *Broker,
        changed: bool,
    ) void {
        if (!changed) return;
        self.finalizePersistentChangeLocked(true, true) catch {};
    }

    fn sessionIsPersistentLocked(
        self: *Broker,
        handle: session_mod.Handle,
    ) bool {
        const session_stats = self.sessions.stats(handle) catch return false;
        return session_stats.expiry_interval != 0;
    }

    fn subscriptionEqualsLocked(
        self: *Broker,
        handle: session_mod.Handle,
        candidate: mqtt.Subscription,
        subscription_identifier: ?usize,
    ) Error!bool {
        const session_stats = try self.sessions.stats(handle);
        const subscriptions = try self.allocator.alloc(
            session_mod.Subscription,
            session_stats.subscription_count,
        );
        defer self.allocator.free(subscriptions);
        const current = try self.sessions.subscriptionsInto(
            handle,
            subscriptions,
        );
        for (current) |existing| {
            if (!std.mem.eql(
                u8,
                existing.topic_filter,
                candidate.topic_filter,
            )) continue;
            return existing.qos == candidate.qos and
                existing.no_local == candidate.no_local and
                existing.retain_as_published ==
                    candidate.retain_as_published and
                existing.retain_handling == candidate.retain_handling and
                existing.subscription_identifier == subscription_identifier;
        }
        return false;
    }

    fn publisherIsPersistentLocked(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
    ) bool {
        const route_id = sessionRouteId(publisher_id) orelse return false;
        const handle = self.sessions.handleForRouteId(route_id) orelse
            return false;
        return self.sessionIsPersistentLocked(handle);
    }

    /// Write a live snapshot when enough unacknowledged changes accumulated.
    ///
    /// Lock ordering is always persistence then state. Encoding captures a
    /// generation while state is frozen, but the atomic disk replacement runs
    /// with traffic unblocked. Only the captured generation is acknowledged,
    /// so mutations racing that I/O remain due for the next checkpoint. A
    /// provisional CONNECT makes live encoding temporarily unsafe; retain the
    /// dirty generation and retry after attachment or at the next persistent
    /// mutation. Encoding and filesystem failures are recorded for inspection
    /// but never retroactively fail the already-committed broker operation.
    fn autosavePersistentChangesIfNeeded(self: *Broker) void {
        if (self.options.persistent_change_autosave == null) return;
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        self.autosavePersistentChangesIfNeededLocked();
    }

    fn autosavePersistentChangesIfNeededLocked(self: *Broker) void {
        const autosave = self.options.persistent_change_autosave orelse return;
        const captured_generation, const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            const pending = self.pendingAutosaveChangesLocked();
            if (pending < autosave.max_changes) return;
            const generation = self.persistent_generation;
            const state = self.encodeLiveStateLocked(false) catch |err| {
                if (err != error.SnapshotBusy) {
                    self.persistent_change_autosave_error = err;
                }
                return;
            };
            break :blk .{ generation, state };
        };
        defer self.allocator.free(encoded);
        persistence_mod.saveEncodedAtomic(
            self.io,
            autosave.dir,
            autosave.sub_path,
            encoded,
        ) catch |err| {
            self.state_mutex.lockUncancelable(self.io);
            self.persistent_change_autosave_error = err;
            self.state_mutex.unlock(self.io);
            return;
        };

        self.state_mutex.lockUncancelable(self.io);
        self.acknowledgeAutosaveGenerationLocked(captured_generation);
        self.state_mutex.unlock(self.io);
    }

    fn snapshotIsConfiguredAutosaveTarget(
        self: *const Broker,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) bool {
        const autosave = self.options.persistent_change_autosave orelse
            return false;
        // Handle and byte-for-byte path equality is intentionally conservative:
        // aliases or separately opened handles may cause one redundant write,
        // but can never suppress a checkpoint to a distinct destination.
        return dir.handle == autosave.dir.handle and
            std.mem.eql(u8, sub_path, autosave.sub_path);
    }

    fn pendingAutosaveChangesLocked(self: *const Broker) u128 {
        return self.persistent_generation -| self.autosave_generation;
    }

    fn acknowledgeAutosaveGeneration(
        self: *Broker,
        captured_generation: u128,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        self.acknowledgeAutosaveGenerationLocked(captured_generation);
    }

    fn acknowledgeAutosaveGenerationLocked(
        self: *Broker,
        captured_generation: u128,
    ) void {
        self.autosave_generation = @max(
            self.autosave_generation,
            captured_generation,
        );
        if (self.autosave_generation == self.persistent_generation and
            self.persistent_generation == std.math.maxInt(u128))
        {
            self.persistent_generation = 0;
            self.autosave_generation = 0;
        }
        self.persistent_change_autosave_error = null;
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
        const captured_generation, const encoded = blk: {
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
            const generation = self.persistent_generation;
            const state = try persistence_mod.encode(
                self.allocator,
                .{
                    .retained = &self.retained,
                    .sessions = &self.sessions,
                    .wills = &self.wills,
                    .will_publishers = &self.will_publishers,
                    .pending_qos2 = &self.pending_qos2,
                    .bridge_qos2 = &self.bridge_qos2,
                },
                std.Io.Clock.awake.now(self.io),
                std.Io.Clock.real.now(self.io),
            );
            break :blk .{ generation, state };
        };
        defer self.allocator.free(encoded);
        try persistence_mod.saveEncodedAtomic(
            self.io,
            dir,
            sub_path,
            encoded,
        );
        if (self.snapshotIsConfiguredAutosaveTarget(dir, sub_path)) {
            self.acknowledgeAutosaveGeneration(captured_generation);
        }
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
        const captured_generation, const encoded = blk: {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            const generation = self.persistent_generation;
            const state = try self.encodeLiveStateLocked(false);
            break :blk .{ generation, state };
        };
        defer self.allocator.free(encoded);

        try persistence_mod.saveEncodedAtomic(
            self.io,
            dir,
            sub_path,
            encoded,
        );
        if (self.snapshotIsConfiguredAutosaveTarget(dir, sub_path)) {
            self.acknowledgeAutosaveGeneration(captured_generation);
        }
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
                .bridge_qos2 = &self.bridge_qos2,
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
            self.bridge_qos2.stats().entries != 0 or
            self.bridge_qos2.stats().bridges != 0 or
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
            self.options.bridge_qos2,
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
        errdefer {
            restored.retained.deinit();
            restored.sessions.deinit();
            restored.wills.deinit();
            restored.will_publishers.deinit(self.allocator);
            restored.pending_qos2.deinit();
            restored.bridge_qos2.deinit();
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
        self.bridge_qos2.swap(&restored.bridge_qos2);
        std.mem.swap(
            will_mod.PublisherMap,
            &self.will_publishers,
            &restored.will_publishers,
        );
        self.router.deinit();
        self.router = staged_router;
        // A successful restore is a new persistence baseline. Debt from an
        // earlier in-memory generation must not influence its autosave window.
        self.persistent_generation = 0;
        self.autosave_generation = 0;
        self.persistent_change_autosave_error = null;
        restored.retained.deinit();
        restored.sessions.deinit();
        restored.wills.deinit();
        restored.will_publishers.deinit(self.allocator);
        restored.pending_qos2.deinit();
        restored.bridge_qos2.deinit();
    }

    /// Accept exactly `connection_count` clients and serve them concurrently.
    ///
    /// This finite form makes lifecycle and benchmark teardown deterministic.
    /// A process-level accept loop can call it repeatedly in batches.
    pub fn serve(
        self: *Broker,
        connection_count: usize,
    ) anyerror!void {
        const server = &(self.server orelse return error.InvalidProperty);
        var accept_options = self.options.accept;
        accept_options.traffic_counters = &self.traffic;
        const listener = Listener{
            .source = server.pendingSource(),
            .accept = accept_options,
            .connection_count = connection_count,
        };
        return self.serveListeners(&.{listener});
    }

    /// Serve finite accept counts from heterogeneous listeners over one broker
    /// state core. One accept task is scheduled per finite connection, so
    /// listeners and their established clients make progress concurrently;
    /// connection slots are allocated atomically by the shared state mutex.
    pub fn serveListeners(
        self: *Broker,
        listeners: []const Listener,
    ) anyerror!void {
        var connection_count: usize = 0;
        for (listeners) |listener| {
            _ = try listener_namespace.Namespace.init(
                listener.namespace.prefix,
            );
            connection_count = std.math.add(
                usize,
                connection_count,
                listener.connection_count,
            ) catch return error.BrokerFull;
        }
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
        var clients_joined = false;
        defer if (!clients_joined) {
            // An accept/setup failure must not strand already-started readers
            // behind this finite serve call.
            for (self.slots) |*slot| {
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

        var next_result: usize = 0;
        for (listeners) |listener| {
            for (0..listener.connection_count) |_| {
                const result = &errors[next_result];
                next_result += 1;
                const accept_task = ListenerAcceptTask{
                    .broker = self,
                    .listener = self.listenerWithTraffic(listener),
                    .result = result,
                };
                group.async(
                    self.io,
                    ListenerAcceptTask.run,
                    .{accept_task},
                );
            }
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

    /// Run heterogeneous listeners until `options.shutdown` is set.
    ///
    /// This is the production-oriented counterpart to finite `serveListeners`.
    /// It continuously replaces completed connections, bounds live clients by
    /// the Broker's configured slot count, and cancels accepts plus active
    /// client reads before returning. The caller must keep listener servers,
    /// namespaces, the shutdown event and any error observer alive throughout
    /// the call. Only one serve method may run on a Broker at a time.
    pub fn serveListenersUntil(
        self: *Broker,
        listeners: []const ListenerEndpoint,
        options: ServeListenersUntilOptions,
    ) anyerror!void {
        if (listeners.len == 0) return error.InvalidProperty;
        if (options.accept_error_backoff.nanoseconds < 0) {
            return error.InvalidProperty;
        }
        var worker_count: usize = 0;
        for (listeners) |listener| {
            _ = try listener_namespace.Namespace.init(
                listener.namespace.prefix,
            );
            if (listener.accept_concurrency == 0) {
                return error.InvalidProperty;
            }
            worker_count = std.math.add(
                usize,
                worker_count,
                listener.accept_concurrency,
            ) catch return error.BrokerFull;
        }
        if (worker_count > self.slots.len) return error.BrokerFull;

        var group: std.Io.Group = .init;
        var supervisor = ListenerSupervisorState{
            .broker = self,
            .options = options,
        };
        self.deadline_driver.start();
        var stop_driver = true;
        defer if (stop_driver) {
            self.deadline_driver.stop(self.io);
        };
        var group_finished = false;
        defer if (!group_finished) {
            supervisor.stopping.store(true, .release);
            group.cancel(self.io);
        };

        for (listeners, 0..) |listener, listener_index| {
            for (0..listener.accept_concurrency) |_| {
                try group.concurrent(
                    self.io,
                    ListenerSupervisorAcceptTask.run,
                    .{ListenerSupervisorAcceptTask{
                        .supervisor = &supervisor,
                        .listener = self.listenerEndpointWithTraffic(
                            listener,
                        ),
                        .listener_index = listener_index,
                    }},
                );
            }
        }

        const Wake = union(enum) {
            shutdown: std.Io.Cancelable!void,
            failure: std.Io.Cancelable!void,
            deadline: ?anyerror,
        };
        var wake_buffer: [3]Wake = undefined;
        var select: std.Io.Select(Wake) = .init(self.io, &wake_buffer);
        defer select.cancelDiscard();
        try select.concurrent(
            .shutdown,
            waitForListenerEvent,
            .{ options.shutdown, self.io },
        );
        try select.concurrent(
            .failure,
            waitForListenerEvent,
            .{ &supervisor.failed, self.io },
        );
        // A persistence or periodic-$SYS failure in the deadline driver must
        // terminate the supervisor rather than leave it waiting forever for
        // an unrelated shutdown request. Select also owns cancellation of the
        // driver after an ordinary shutdown/error wake.
        try select.concurrent(
            .deadline,
            Broker.runDeadlineDriver,
            .{self},
        );
        const wake = try select.await();
        const deadline_error: ?anyerror = switch (wake) {
            .shutdown => |result| blk: {
                try result;
                break :blk null;
            },
            .failure => |result| blk: {
                try result;
                break :blk null;
            },
            .deadline => |maybe_error| maybe_error,
        };

        supervisor.stopping.store(true, .release);
        group.cancel(self.io);
        group_finished = true;
        self.deadline_driver.stop(self.io);
        stop_driver = false;
        select.cancelDiscard();
        if (deadline_error) |err| return err;
        if (supervisor.firstError()) |err| return err;
    }

    fn listenerWithTraffic(self: *Broker, listener: Listener) Listener {
        var result = listener;
        var accept_options = listener.accept orelse self.options.accept;
        accept_options.traffic_counters = &self.traffic;
        result.accept = accept_options;
        return result;
    }

    fn listenerEndpointWithTraffic(
        self: *Broker,
        listener: ListenerEndpoint,
    ) ListenerEndpoint {
        var result = listener;
        var accept_options = listener.accept orelse self.options.accept;
        accept_options.traffic_counters = &self.traffic;
        result.accept = accept_options;
        return result;
    }

    /// Admit one already parsed CONNECT from any transport listener and run
    /// it synchronously through the shared broker state machine. This is the
    /// composable building block for external accept-loop orchestration.
    pub fn servePending(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        namespace: listener_namespace.Namespace,
    ) anyerror!void {
        return self.servePendingWithOptions(
            pending,
            namespace,
            self.options.accept,
        );
    }

    /// Admit one parsed CONNECT with an explicit listener policy.
    pub fn servePendingWithOptions(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        namespace: listener_namespace.Namespace,
        accept_options: runtime.AcceptOptions,
    ) anyerror!void {
        return self.servePendingWithListenerOptions(
            pending,
            namespace,
            accept_options,
            .{},
        );
    }

    /// Admit one parsed CONNECT with explicit listener capability and
    /// authorization policy. This is the complete boundary for external
    /// listener orchestration that does not use `serveListeners*`.
    pub fn servePendingWithListenerOptions(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        namespace: listener_namespace.Namespace,
        accept_options: runtime.AcceptOptions,
        authorization: ListenerAuthorization,
    ) anyerror!void {
        pending.connection.attachTrafficCounters(&self.traffic);
        const slot_index = try self.claimSlot();
        var slot_claimed = true;
        defer if (slot_claimed) {
            self.releaseClaimedSlot(slot_index);
        };
        var result: ?anyerror = null;
        const task = try self.preparePending(
            slot_index,
            pending,
            namespace,
            accept_options,
            authorization,
            &result,
        ) orelse {
            slot_claimed = false;
            self.releaseClaimedSlot(slot_index);
            return;
        };
        slot_claimed = false;
        ClientTask.run(task) catch |err| return err;
        if (result) |err| return err;
    }

    fn claimSlot(self: *Broker) Error!usize {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        for (self.slots, 0..) |slot, index| {
            if (!slot.active) {
                self.slots[index].active = true;
                self.connections_received +|= 1;
                return index;
            }
        }
        return error.BrokerFull;
    }

    fn releaseClaimedSlot(self: *Broker, slot_index: usize) void {
        self.state_mutex.lockUncancelable(self.io);
        const slot = &self.slots[slot_index];
        std.debug.assert(slot.active);
        std.debug.assert(slot.connection == null);
        slot.active = false;
        self.state_mutex.unlock(self.io);
    }

    fn preparePending(
        self: *Broker,
        index: usize,
        pending: *runtime.PendingAcceptedClient,
        namespace: @import("listener_namespace.zig").Namespace,
        listener_accept: runtime.AcceptOptions,
        listener_authorization: ListenerAuthorization,
        result: *?anyerror,
    ) Error!?ClientTask {
        var pending_owned = true;
        defer if (pending_owned) pending.deinit(self.allocator);
        pending.connection.attachTrafficCounters(&self.traffic);
        var suppress_reserved_will =
            self.options.protect_reserved_topics and
            if (pending.connect.connect.will) |will|
                !clientMayPublishTopic(will.topic)
            else
                false;
        try pending.connection.setTopicNamespace(namespace.prefix);
        var mapped_will = try namespace.mapConnectWill(
            self.allocator,
            &pending.connect.connect,
        );
        defer if (mapped_will) |*mapped| mapped.deinit();
        if (self.options.protect_reserved_topics) {
            if (pending.connect.connect.will) |will| {
                suppress_reserved_will = suppress_reserved_will or
                    !clientMayPublishTopic(will.topic);
            }
        }

        var accept_options = try pending.resolvedOptions(listener_accept);
        if (accept_options.reason_code != 0) {
            var refused = try pending.finish(accept_options);
            pending_owned = false;
            refused.deinit(self.allocator);
            return null;
        }
        if (pending.connect.connect.will) |will| {
            if (self.payloadTooLarge(will.payload)) {
                var refused = try pending.finish(.{
                    .reason_code = switch (pending.connect.connect.protocol) {
                        .v5 => 0x95,
                        .v3_1_1 => 0x05,
                    },
                });
                pending_owned = false;
                refused.deinit(self.allocator);
                return null;
            }
        }
        if (pending.connection.authentication.phase == .authenticating) {
            const handler = self.options.authentication orelse {
                var refused = try pending.finish(.{ .reason_code = 0x8c });
                pending_owned = false;
                refused.deinit(self.allocator);
                return null;
            };
            try handler.start(handler.context, pending);
            if (!pending.authentication_authorized) {
                return error.AuthenticationInProgress;
            }
        }
        if (self.options.connect_authorization) |authorization| {
            if (!authorization.authorize(
                authorization.context,
                pending.connect.connect,
            )) {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            }
        }
        if (self.options.connect_context_authorization) |authorization| {
            if (!authorization.authorize(authorization.context, .{
                .connect = pending.connect.connect,
                .remote_address = pending.connection.remoteAddress(),
                .proxy = pending.connection.proxyMetadata(),
                .peer_certificates = pending.connection.peerCertificates(),
            })) {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            }
        }
        if (listener_authorization.connect) |authorization| {
            if (!authorization.authorize(
                authorization.context,
                pending.connect.connect,
            )) {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            }
        }
        if (listener_authorization.connect_context) |authorization| {
            if (!authorization.authorize(authorization.context, .{
                .connect = pending.connect.connect,
                .remote_address = pending.connection.remoteAddress(),
                .proxy = pending.connection.proxyMetadata(),
                .peer_certificates = pending.connection.peerCertificates(),
            })) {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            }
        }
        if (suppress_reserved_will) {
            if (mapped_will) |*mapped| {
                mapped.deinit();
                mapped_will = null;
            }
            if (pending.connect.connect.will) |*will| {
                will.deinit(self.allocator);
                pending.connect.connect.will = null;
            }
        }
        var effective_connect = pending.connect.connect;
        if (listener_authorization.use_username_as_client_id) {
            effective_connect.client_id = effective_connect.username orelse {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            };
        }
        var registration_progress: RegistrationProgress = .{};
        const registration = self.register(
            index,
            effective_connect,
            listener_authorization.access_control,
            &registration_progress,
        ) catch |err| {
            // Registration can delete durable state before a later allocation
            // fails. `register` records that partial transition; persist it to
            // both configured backends without replacing the original error.
            self.finishPartialPersistentChange(
                registration_progress.rollback_changed,
            );
            return err;
        };
        const subscriber_id = registration.subscriber_id;
        // The Will scheduler now owns its canonical topic. Restore the parsed
        // CONNECT view before it transfers to the long-lived client task.
        if (mapped_will) |*mapped| {
            mapped.deinit();
            mapped_will = null;
        }
        // OwnedConnect keeps all original packet storage alive; changing this
        // borrowed view makes downstream ACLs and Will cleanup observe the
        // same effective identity used for Session registration.
        pending.connect.connect.client_id = effective_connect.client_id;
        accept_options.session_present = self.slots[index].session_present;
        if (self.slots[index].assigned_client_id_len != 0) {
            accept_options.assigned_client_identifier =
                self.slots[index].assigned_client_id[0..self.slots[index].assigned_client_id_len];
        }
        self.appendProvisionalCommitIfEnabled() catch |err| {
            self.abortRegistration(
                index,
                subscriber_id,
                registration_progress.rollback_changed,
            );
            // The failed append may nevertheless have left a complete record
            // containing provisional state. Always append the rolled-back
            // image; only genuine net changes advance change-count autosave.
            self.finalizePersistentChange(
                true,
                registration_progress.rollback_changed,
            ) catch {};
            return err;
        };
        var accepted = pending.finish(accept_options) catch |err| {
            self.abortRegistration(
                index,
                subscriber_id,
                registration_progress.rollback_changed,
            );
            // The provisional record was synced before CONNACK. Append the
            // rollback even when it restores the original in-memory state.
            self.finalizePersistentChange(
                true,
                registration_progress.rollback_changed,
            ) catch {};
            return err;
        };
        pending_owned = false;
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
            registration.persistent_changed,
        );
        // A threshold reached during the provisional CONNECT window was left
        // pending by SnapshotBusy. Attachment is the first safe retry point.
        self.autosavePersistentChangesIfNeeded();
        accepted_owns_connection = false;
        errdefer accepted.connect.deinit(self.allocator);
        errdefer self.unregister(index, subscriber_id) catch {};
        try self.flushSlot(index, &self.slots[index]);
        const task = ClientTask{
            .broker = self,
            .slot_index = index,
            .subscriber_id = subscriber_id,
            .connect = accepted.connect,
            .result = result,
        };
        accepted.connect = undefined;
        accepted.connection = undefined;
        return task;
    }

    fn refuseUnauthorizedConnect(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        pending_owned: *bool,
    ) Error!void {
        var refused = try pending.finish(.{
            .reason_code = switch (pending.connect.connect.protocol) {
                .v3_1_1 => 0x05,
                .v5 => 0x87,
            },
        });
        pending_owned.* = false;
        refused.deinit(self.allocator);
    }

    fn register(
        self: *Broker,
        slot_index: usize,
        connect: mqtt.Connect,
        listener_access_control: ?ListenerAccessControlHandler,
        progress: *RegistrationProgress,
    ) Error!Registration {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        // `claimSlot` reserves the slot before CONNECT-dependent setup begins.
        // Legacy direct callers may still provide an unclaimed slot.
        if (slot.active and slot.connection != null) return error.BrokerFull;
        slot.generation = nextConnectionGeneration(slot.generation);
        slot.active = true;
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.session_persistent = false;
        slot.assigned_client_id_len = 0;
        slot.graceful_disconnect = false;
        slot.listener_access_control = listener_access_control;
        errdefer slot.listener_access_control = null;
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
        const expired_count = self.pruneExpiredSessionRoutesLocked(now);
        var persistent_changed = expired_count != 0;
        progress.rollback_changed = persistent_changed;
        errdefer {
            self.recordPersistentChangeLocked(persistent_changed);
        }
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
        const previous_session_persistent = if (previous_session_handle) |handle| blk: {
            const session_stats = self.sessions.stats(handle) catch
                break :blk false;
            break :blk session_stats.expiry_interval != 0;
        } else false;
        // Clean Start may remove the previous Session before allocating its
        // replacement, so carry that durable deletion through any later error.
        persistent_changed = persistent_changed or previous_session_persistent;
        progress.rollback_changed = persistent_changed;
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
        const opened_session = self.sessions.open(
            effective_connect.client_id,
            effective_connect.clean_start,
            self.sessionExpiryForConnect(effective_connect),
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
        const accepted_will = self.wills.acceptConnectWithSessionExpiry(
            effective_connect,
            self.sessionExpiryForConnect(effective_connect),
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
        // A previous Will canceled or made due by this CONNECT survives abort
        // as a real lifecycle change. This conservative flag may journal an
        // already-due Will again, but never misses a cancellation/schedule.
        progress.rollback_changed = progress.rollback_changed or
            accepted_will.previous != .no_will;
        slot.will_handle = accepted_will.current;
        if (accepted_will.current) |handle| {
            self.will_publishers.putAssumeCapacityNoClobber(
                handle,
                sessionSubscriberId(opened_session.route_id),
            );
        }
        self.deadline_driver.notify(self.io);
        persistent_changed = persistent_changed or slot.session_persistent or
            previous_handle != null or accepted_will.current != null;
        return .{
            .subscriber_id = id,
            .replaced_owner_id = replaced_owner_id,
            .persistent_changed = persistent_changed,
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

    fn sessionExpiryForConnect(
        self: Broker,
        connect: mqtt.Connect,
    ) u32 {
        const requested = session_mod.Store.expiryForConnect(
            connect.protocol,
            connect.clean_start,
            connect.properties,
        );
        return self.capPersistentSessionExpiry(requested);
    }

    fn sessionExpiryForDisconnect(
        self: Broker,
        protocol: mqtt.ProtocolVersion,
        disconnect: mqtt.Disconnect,
    ) ?u32 {
        if (protocol != .v5) return null;
        const requested = mqtt.sessionExpiryInterval(
            disconnect.properties,
        ) orelse return null;
        return self.capPersistentSessionExpiry(requested);
    }

    fn capPersistentSessionExpiry(self: Broker, requested: u32) u32 {
        const maximum = self.options.persistent_session_expiry_seconds orelse
            return requested;
        if (requested == 0) return 0;
        return @min(requested, maximum);
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
        const session_expiry_override = if (slot.connection) |connection|
            self.sessionExpiryForDisconnect(
                connection.protocol,
                disconnect,
            )
        else if (mqtt.sessionExpiryInterval(disconnect.properties)) |requested|
            self.capPersistentSessionExpiry(requested)
        else
            null;
        return self.closeWillForDisconnectWithExpiryLocked(
            slot,
            disconnect,
            session_expiry_override,
            now,
        );
    }

    fn closeWillForDisconnectWithExpiryLocked(
        self: *Broker,
        slot: *ClientSlot,
        disconnect: mqtt.Disconnect,
        session_expiry_override: ?u32,
        now: std.Io.Timestamp,
    ) Error!void {
        const handle = slot.will_handle orelse return;
        const result = self.wills.closeDisconnectWithSessionExpiry(
            handle,
            disconnect,
            session_expiry_override,
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
        persistent_changed: bool,
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
        var active_connections: usize = 0;
        for (self.slots) |candidate| {
            active_connections +|= @intFromBool(
                candidate.active and candidate.connection != null,
            );
        }
        self.maximum_active_connections = @max(
            self.maximum_active_connections,
            active_connections,
        );
        self.recordPersistentChangeLocked(persistent_changed);
    }

    fn abortRegistration(
        self: *Broker,
        slot_index: usize,
        _: router_mod.SubscriberId,
        persistent_changed: bool,
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
        slot.listener_access_control = null;
        slot.will_handle = null;
        self.recordPersistentChangeLocked(persistent_changed);
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
        const session_stats = try self.sessions.stats(handle);
        const subscriptions = try self.allocator.alloc(
            session_mod.Subscription,
            session_stats.subscription_count,
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
        const session_stats = try sessions.stats(handle);
        const subscriptions = try allocator.alloc(
            session_mod.Subscription,
            session_stats.subscription_count,
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
        var state_locked = true;
        var persistent_changed = false;
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        if (!slot.graceful_disconnect) {
            if (slot.will_handle) |handle| {
                const result: ?will_mod.CloseResult = self.wills.close(
                    handle,
                    .ungraceful,
                    std.Io.Clock.awake.now(self.io),
                ) catch |err| switch (err) {
                    error.WillNotFound => blk: {
                        // A newer connection with the same ClientID already
                        // canceled or committed this generation during
                        // takeover. The stale transport close has no remaining
                        // Will lifecycle work.
                        slot.will_handle = null;
                        break :blk null;
                    },
                    else => {
                        return err;
                    },
                };
                if (result) |changed_result| {
                    persistent_changed = changed_result != .no_will;
                }
            }
        }
        if (slot.session_handle) |handle| {
            persistent_changed = persistent_changed or slot.session_persistent;
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
                    return err;
                }
            };
            const session_stats = self.sessions.stats(handle) catch null;
            if (session_stats == null or
                session_stats.?.expiry_interval == 0)
            {
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
        slot.clearQueue();
        // Publish an idle slot only after every field from the old generation
        // has been detached. `claimSlot` observes this state under the same
        // mutex, so it can never reserve a slot that still owns a connection.
        var connection = slot.connection;
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.session_persistent = false;
        slot.listener_access_control = null;
        slot.active = false;
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;
        self.deadline_driver.notify(self.io);
        defer if (connection) |*value| value.close();
        // Persist disconnect, Session expiry, and Will scheduling before an
        // orderly close becomes observable to the peer.
        try self.finalizePersistentChange(
            persistent_changed,
            persistent_changed,
        );
    }

    fn handleDisconnect(
        self: *Broker,
        slot: *ClientSlot,
        disconnect: mqtt.Disconnect,
    ) Error!void {
        const now = std.Io.Clock.awake.now(self.io);
        const session_expiry_override = self.sessionExpiryForDisconnect(
            slot.connection.?.protocol,
            disconnect,
        );
        self.state_mutex.lockUncancelable(self.io);
        var state_locked = true;
        var persistent_changed = false;
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        // Validate state-dependent DISCONNECT properties before changing the
        // Will, Session owner, router, or persistence state. In particular,
        // MQTT-3.14.2-2 makes zero-to-nonzero Session Expiry a Protocol Error.
        if (slot.session_handle) |handle| {
            try self.sessions.validateDisconnect(
                handle,
                session_expiry_override,
            );
        }
        if (slot.will_handle) |handle| {
            const result: ?will_mod.CloseResult = self.wills.closeDisconnectWithSessionExpiry(
                handle,
                disconnect,
                session_expiry_override,
                now,
            ) catch |err| switch (err) {
                error.WillNotFound => blk: {
                    if (slot.session_handle != null) {
                        return err;
                    }
                    slot.will_handle = null;
                    break :blk null;
                },
                else => {
                    return err;
                },
            };
            if (result) |close_result| {
                persistent_changed = close_result != .no_will;
                if (close_result == .canceled) {
                    _ = self.will_publishers.remove(handle);
                    slot.will_handle = null;
                }
            }
        }
        if (slot.session_handle) |handle| {
            persistent_changed = persistent_changed or slot.session_persistent;
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                _ = self.session_owners.remove(value);
            }
            self.sessions.disconnect(
                handle,
                session_expiry_override,
                now,
            ) catch |err| {
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
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;
        self.deadline_driver.notify(self.io);
        try self.finalizePersistentChange(
            persistent_changed,
            persistent_changed,
        );
    }

    fn handleSubscribe(
        self: *Broker,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
        connect: mqtt.Connect,
        subscribe: mqtt.Subscribe,
    ) Error!void {
        const namespace = listener_namespace.Namespace{
            .prefix = connection.topicNamespace(),
        };
        const mapped_subscriptions = try self.allocator.alloc(
            mqtt.Subscription,
            subscribe.subscriptions.len,
        );
        defer self.allocator.free(mapped_subscriptions);
        var mapped_count: usize = 0;
        defer for (mapped_subscriptions[0..mapped_count]) |subscription| {
            self.allocator.free(subscription.topic_filter);
        };
        for (subscribe.subscriptions, mapped_subscriptions) |
            subscription,
            *mapped,
        | {
            mapped.* = subscription;
            mapped.topic_filter = try namespace.mapFilterAlloc(
                self.allocator,
                subscription.topic_filter,
            );
            mapped_count += 1;
        }
        const reasons = try self.allocator.alloc(
            u8,
            mapped_subscriptions.len,
        );
        defer self.allocator.free(reasons);
        const slot = try self.slotForSubscriber(id);
        for (mapped_subscriptions, reasons) |subscription, *reason| {
            reason.* = if (self.subscribeAuthorized(
                slot.listener_access_control,
                connect,
                subscription,
            )) 0xff else subscriptionDeniedReason(connection.protocol);
        }
        const subscription_identifier = mqtt.subscriptionIdentifier(
            subscribe.properties,
        );
        const now = std.Io.Clock.awake.now(self.io);
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
        var state_locked = true;
        var persistent_changed = false;
        const persistent_session = self.sessionIsPersistentLocked(
            session_handle,
        );
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        for (mapped_subscriptions, 0..) |subscription, index| {
            if (reasons[index] != 0xff) continue;
            var granted = subscription;
            granted.qos = minQos(
                granted.qos,
                connection.localMaximumQoS(),
            );
            const unchanged = if (persistent_session)
                self.subscriptionEqualsLocked(
                    session_handle,
                    granted,
                    subscription_identifier,
                ) catch |err| {
                    return err;
                }
            else
                true;
            const session_existed = self.sessions.setSubscription(
                session_handle,
                granted,
                subscription_identifier,
            ) catch |err| switch (err) {
                // MQTT lets one SUBSCRIBE packet carry several filters. Hitting
                // the per-session subscription cap for one new filter must not
                // tear down the connection or hide earlier successes in the
                // same packet. Existing filters still reach the in-place
                // replacement path inside `setSubscription`, so only truly new
                // over-limit filters land here.
                error.SubscriptionLimitExceeded => {
                    reasons[index] = subscriptionQuotaExceededReason(
                        connection.protocol,
                    );
                    continue;
                },
                else => return err,
            };
            persistent_changed = persistent_changed or !unchanged;
            const route_id = try self.sessions.routeId(session_handle);
            const existed = self.router.subscribeWithIdentifierStatus(
                sessionSubscriberId(route_id),
                granted,
                subscription_identifier,
            ) catch |err| {
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
                    .subscriber_client_id = try self.sessions.clientId(
                        session_handle,
                    ),
                    .subscription_identifier = subscription_identifier,
                    .upgrade_outgoing_qos = self.options.upgrade_outgoing_qos,
                },
                now,
            ) catch |err| return err;
            defer self.allocator.free(deliveries);
            try self.enqueueRetainedDeliveries(
                slot,
                deliveries,
                now,
                &persistent_changed,
            );
        }
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;
        // SUBACK makes the subscription durable from the peer's perspective.
        // The journal must reach disk before that acknowledgement is emitted.
        try self.finalizePersistentChange(
            persistent_changed,
            persistent_changed,
        );
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
        persistent_changed: *bool,
    ) Error!void {
        const handle = slot.session_handle orelse
            return error.SessionNotFound;
        const client_id = try self.sessions.clientId(handle);
        for (deliveries) |delivery| {
            if (!self.retainedSourceAuthorized(delivery)) continue;
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
            if (!self.deliveryAuthorized(slot.listener_access_control, .{
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
                    persistent_changed,
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
                self.publish_messages_dropped +|= 1;
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
        const namespace = listener_namespace.Namespace{
            .prefix = connection.topicNamespace(),
        };
        const mapped_filters = try self.allocator.alloc(
            []u8,
            unsubscribe.topic_filters.len,
        );
        var mapped_count: usize = 0;
        defer {
            for (mapped_filters[0..mapped_count]) |filter| {
                self.allocator.free(filter);
            }
            self.allocator.free(mapped_filters);
        }
        for (unsubscribe.topic_filters, mapped_filters) |filter, *mapped| {
            mapped.* = try namespace.mapFilterAlloc(self.allocator, filter);
            mapped_count += 1;
        }
        const reasons = try self.allocator.alloc(
            u8,
            mapped_filters.len,
        );
        defer self.allocator.free(reasons);
        const slot = try self.slotForSubscriber(id);
        self.state_mutex.lockUncancelable(self.io);
        var state_locked = true;
        var persistent_changed = false;
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        for (mapped_filters, 0..) |filter, index| {
            if (!self.unsubscribeAuthorized(
                slot.listener_access_control,
                connect,
                filter,
            )) {
                reasons[index] = unsubscribeDeniedReason(
                    connection.protocol,
                );
                continue;
            }
            const session_handle = slot.session_handle orelse {
                return error.SessionNotFound;
            };
            const session_removed = self.sessions.removeSubscription(
                session_handle,
                filter,
            ) catch |err| {
                return err;
            };
            persistent_changed = persistent_changed or
                (session_removed and
                    self.sessionIsPersistentLocked(session_handle));
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
                    return err;
                },
            };
            std.debug.assert(session_removed);
            reasons[index] = 0;
        }
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;
        try self.finalizePersistentChange(
            persistent_changed,
            persistent_changed,
        );
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
        self.recordPublishReceived(publish.payload.len);
        // Subscription Identifier is generated by a Server while forwarding;
        // it is never legal on a Client-to-Server PUBLISH.
        if (mqtt.subscriptionIdentifier(publish.properties) != null) {
            return error.InvalidProperty;
        }
        if (self.options.protect_reserved_topics and
            !clientMayPublishTopic(publish.topic))
        {
            return self.rejectPublish(
                publisher_id,
                publisher,
                publish,
                0x87,
            );
        }
        const namespace = listener_namespace.Namespace{
            .prefix = publisher.topicNamespace(),
        };
        const mapped_topic = try namespace.mapTopicAlloc(
            self.allocator,
            publish.topic,
        );
        defer self.allocator.free(mapped_topic);
        var canonical_publish = publish;
        canonical_publish.topic = mapped_topic;
        const publisher_slot = try self.slotForSubscriber(publisher_id);
        if (self.options.protect_reserved_topics and
            !clientMayPublishTopic(canonical_publish.topic))
        {
            return self.rejectPublish(
                publisher_id,
                publisher,
                canonical_publish,
                0x87,
            );
        }
        if (!self.publishAuthorized(
            publisher_slot.listener_access_control,
            connect,
            canonical_publish,
        )) {
            return self.rejectPublish(
                publisher_id,
                publisher,
                canonical_publish,
                0x87,
            );
        }
        if (self.payloadTooLarge(canonical_publish.payload)) {
            return self.rejectPublish(
                publisher_id,
                publisher,
                canonical_publish,
                0x95,
            );
        }
        if (canonical_publish.qos == .exactly_once) {
            return self.recordQoS2Publish(
                publisher_id,
                publisher,
                canonical_publish,
            );
        }
        return self.routeReleasedPublish(
            publisher_id,
            publisher,
            canonical_publish,
            connect.client_id,
            true,
        );
    }

    fn payloadTooLarge(self: Broker, payload: []const u8) bool {
        return self.options.limits.max_payload_size != 0 and
            payload.len > self.options.limits.max_payload_size;
    }

    fn recordPublishReceived(self: *Broker, payload_len: usize) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        self.publish_messages_received +|= 1;
        self.publish_payload_bytes_received +|= payload_len;
    }

    fn recordPublishSent(self: *Broker, payload_len: usize) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        self.publish_messages_sent +|= 1;
        self.publish_payload_bytes_sent +|= payload_len;
    }

    fn recordPublishDropped(self: *Broker) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        self.publish_messages_dropped +|= 1;
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
        const persistent_publisher = self.publisherIsPersistentLocked(
            durable_publisher_id,
        );
        const record_changed = self.pending_qos2.record(
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
        self.recordPersistentChangeLocked(
            persistent_publisher and record_changed,
        );
        self.state_mutex.unlock(self.io);

        // A successful PUBREC promises that this QoS 2 transaction survives a
        // reconnect. Establish the durability point before sending PUBREC.
        const durable_changed = persistent_publisher and record_changed;
        try self.finalizePersistentChange(
            durable_changed,
            durable_changed,
        );

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
        source_client_id: []const u8,
        ack: mqtt.AckPacket,
    ) Error!void {
        // Keep snapshot/journal writers outside the entire take-and-route
        // transaction. Acquiring persistence before state preserves the global
        // lock order and prevents a checkpoint from observing the gap between
        // removal of the inbound QoS 2 record and installation of its effects.
        self.persistence_mutex.lockUncancelable(self.io);
        var persistence_locked = true;
        defer if (persistence_locked) self.persistence_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        const durable_publisher_id = self.canonicalPublisherId(
            publisher_id,
        );
        const persistent_publisher = self.publisherIsPersistentLocked(
            durable_publisher_id,
        );
        var pending = self.pending_qos2.take(
            durable_publisher_id,
            ack.packet_id,
        ) orelse {
            self.state_mutex.unlock(self.io);
            self.persistence_mutex.unlock(self.io);
            persistence_locked = false;
            // Mosquitto deliberately acknowledges an unknown/repeated PUBREL:
            // the original PUBCOMP may have been lost after the message was
            // already released. MQTT 5 allows 0x92, but Success is maximally
            // interoperable and keeps this path idempotent.
            const publisher_slot = try self.slotForSubscriber(publisher_id);
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            defer publisher_slot.writer_mutex.unlock(self.io);
            // `writePubComp` treats an absent connection-local marker
            // idempotently. This matters after durable Session recovery, where
            // the completed inbound transaction belongs to an earlier Network
            // Connection and cannot be reconstructed from a PUBREL flag.
            try publisher.writePubComp(ack.packet_id, 0);
            return;
        };
        var persistent_changed = persistent_publisher;
        self.state_mutex.unlock(self.io);
        defer pending.deinit();

        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        const maybe_publish = pending.asPublish(
            ack.packet_id,
            std.Io.Clock.awake.now(self.io),
            &properties,
        ) catch |err| {
            self.state_mutex.lockUncancelable(self.io);
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChangeLocked(persistent_changed);
            return err;
        };
        if (maybe_publish) |publish| {
            self.routeReleasedPublishMode(
                publisher_id,
                publisher,
                publish,
                source_client_id,
                false,
                false,
                false,
                &persistent_changed,
            ) catch |err| {
                self.state_mutex.lockUncancelable(self.io);
                self.recordPersistentChangeLocked(persistent_changed);
                self.state_mutex.unlock(self.io);
                self.finishPartialPersistentChangeLocked(persistent_changed);
                return err;
            };
        }
        self.state_mutex.lockUncancelable(self.io);
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        // `routeReleasedPublish` journals the routed state before returning.
        // If Message Expiry discarded the Application Message instead, the
        // pending inbound transaction removal is still a durable mutation.
        try self.finalizePersistentChangeLocked(
            persistent_changed,
            persistent_changed,
        );
        // Socket delivery is intentionally delayed until after the atomic
        // pending-QoS2 removal/routing persistence transaction above.
        self.persistence_mutex.unlock(self.io);
        persistence_locked = false;
        try self.flushAllSlots();

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
        source_client_id: []const u8,
        acknowledge_qos1: bool,
    ) Error!void {
        return self.routeReleasedPublishMode(
            publisher_id,
            publisher,
            publish,
            source_client_id,
            acknowledge_qos1,
            true,
            true,
            null,
        );
    }

    fn routeReleasedPublishMode(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
        source_client_id: []const u8,
        acknowledge_qos1: bool,
        count_persistent_change: bool,
        flush_routed_deliveries: bool,
        outer_changed: ?*bool,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        var state_locked = true;
        var persistent_changed = false;
        errdefer if (state_locked) {
            if (count_persistent_change) {
                self.recordPersistentChangeLocked(persistent_changed);
            }
            self.state_mutex.unlock(self.io);
            if (count_persistent_change) {
                self.finishPartialPersistentChange(persistent_changed);
            }
        };
        const plan = self.enqueuePublishLocked(
            publisher_id,
            publish,
            source_client_id,
            std.Io.Clock.awake.now(self.io),
            &persistent_changed,
            null,
        ) catch |err| {
            if (outer_changed) |changed| {
                changed.* = changed.* or persistent_changed;
            }
            return err;
        };
        defer self.allocator.free(plan.storage);
        if (outer_changed) |changed| {
            changed.* = changed.* or persistent_changed;
        }
        self.recordPersistentChangeLocked(
            count_persistent_change and persistent_changed,
        );
        self.state_mutex.unlock(self.io);
        state_locked = false;

        // Retained changes and durable fanout queues precede PUBACK and every
        // downstream write. A crash after either peer observes progress can
        // therefore recover a state no older than that observable boundary.
        // PUBREL owns the surrounding transaction and appends once after
        // combining inbound removal with any routing mutations.
        const recorded_change = count_persistent_change and persistent_changed;
        try self.finalizePersistentChange(
            recorded_change,
            recorded_change,
        );

        // Mosquitto queues a self-matched delivery before the publisher's
        // PUBACK, which makes the PUBLISH observable first on their shared
        // socket. Preserve that deterministic same-connection boundary
        // without making unrelated slow subscribers delay the publisher
        // acknowledgement.
        if (acknowledge_qos1) if (publish.packet_id) |packet_id| {
            try self.flushPublisherMatch(plan, publisher_id);
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
        if (flush_routed_deliveries) try self.flushPlan(plan);
    }

    /// Apply retained state and enqueue live fanout while `state_mutex` is held.
    ///
    /// Will publication reuses this exact route without a publisher
    /// Connection, while client PUBLISH adds its acknowledgement after the
    /// lock is released. `source_client_id` is copied only when the PUBLISH
    /// creates retained state, preserving provenance independently of the
    /// Session route used for No Local matching.
    fn enqueuePublishLocked(
        self: *Broker,
        publisher_id: ?router_mod.SubscriberId,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        now: std.Io.Timestamp,
        persistent_changed: ?*bool,
        publication_effect_committed: ?*bool,
    ) Error!RoutePlan {
        if (self.pruneExpiredSessionRoutesLocked(now) != 0) {
            if (persistent_changed) |changed| changed.* = true;
        }
        const route_publisher_id = if (publisher_id) |id|
            self.canonicalPublisherId(id)
        else
            null;
        const retained_result = self.retained.applyParsedPublish(
            publish,
            route_publisher_id,
            source_client_id,
            now,
        ) catch |err| return err;
        if (retained_result != .ignored) {
            if (persistent_changed) |changed| changed.* = true;
            if (publication_effect_committed) |committed| committed.* = true;
        }
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
        var ignored_persistent_change = false;
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
            // Live Sessions use the current destination listener policy. An
            // offline Session has no listener until it reconnects, so retain
            // its granted QoS and cap it immediately before a later write.
            if (online) {
                route.qos = minQos(
                    route.qos,
                    destination.?.connection.?.localMaximumQoS(),
                );
            }
            if (!self.deliveryAuthorized(if (online)
                destination.?.listener_access_control
            else
                null, .{
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
            const changed = persistent_changed orelse &ignored_persistent_change;
            var route_persistent_changed = false;
            var route_enqueued = false;
            self.enqueueSessionDeliveryManyLocked(
                handle,
                session_plan.identifiersFor(route),
                route.retain,
                route.qos,
                publish,
                now,
                &route_persistent_changed,
                &route_enqueued,
            ) catch |err| {
                changed.* = changed.* or route_persistent_changed;
                if (publication_effect_committed) |committed| {
                    committed.* = committed.* or route_enqueued;
                }
                return err;
            };
            changed.* = changed.* or route_persistent_changed;
            if (publication_effect_committed) |committed| {
                committed.* = committed.* or route_enqueued;
            }
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
                self.publish_messages_dropped +|= 1;
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
                destination.connection.?.localMaximumQoS(),
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
        const RemovalContext = struct {
            broker: *Broker,
            now: std.Io.Timestamp,
        };
        var context = RemovalContext{ .broker = self, .now = now };
        const removed = self.sessions.pruneExpiredWithContext(
            now,
            &context,
            struct {
                fn removed(ctx: *RemovalContext, route_id: u64) void {
                    ctx.broker.expireWillForSessionRouteLocked(
                        route_id,
                        ctx.now,
                    );
                    _ = ctx.broker.pending_qos2.removePublisher(
                        sessionSubscriberId(route_id),
                    );
                    _ = ctx.broker.router.removeSubscriber(
                        sessionSubscriberId(route_id),
                    ) catch {};
                }
            }.removed,
        );
        self.expired_sessions +|= removed;
        return removed;
    }

    fn expireWillForSessionRouteLocked(
        self: *Broker,
        route_id: u64,
        now: std.Io.Timestamp,
    ) void {
        const session_id = sessionSubscriberId(route_id);
        // Will handles are generation-safe but the Session store reports its
        // stable route on expiry. The publisher map is therefore the sole
        // authoritative bridge from Session lifetime to delayed Will state.
        var iterator = self.will_publishers.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.* != session_id) continue;
            _ = self.wills.close(
                entry.key_ptr.*,
                .session_ended,
                now,
            ) catch {};
        }
    }

    fn enqueueSessionDeliveryLocked(
        self: *Broker,
        handle: session_mod.Handle,
        subscription_identifier: ?usize,
        retain: bool,
        qos: mqtt.QoS,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
        persistent_changed: *bool,
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
            persistent_changed,
            null,
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
        persistent_changed: *bool,
        publication_enqueued: ?*bool,
    ) Error!void {
        if (publication_enqueued) |enqueued| enqueued.* = false;
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
        var snapshot_changed = false;
        const result = self.sessions.enqueuePublishTrackingSnapshotChange(
            handle,
            publish.topic,
            publish.payload,
            .{
                .qos = qos,
                .retain = retain,
                .properties = properties.items,
                .now = now,
            },
            &snapshot_changed,
        ) catch |err| switch (err) {
            error.QueueFull => {
                self.publish_messages_dropped +|= 1;
                persistent_changed.* = persistent_changed.* or
                    (snapshot_changed and
                        self.sessionIsPersistentLocked(handle));
                return;
            },
            else => {
                persistent_changed.* = persistent_changed.* or
                    (snapshot_changed and
                        self.sessionIsPersistentLocked(handle));
                return err;
            },
        };
        persistent_changed.* = persistent_changed.* or
            (snapshot_changed and self.sessionIsPersistentLocked(handle));
        if (publication_enqueued) |enqueued| {
            enqueued.* = result == .queued;
        }
    }

    fn handleSessionAckLocked(
        self: *Broker,
        slot: *ClientSlot,
        ack: mqtt.AckPacket,
    ) Error!SessionAckResult {
        const handle = slot.session_handle orelse return .{
            .owned = false,
            .persistent_changed = false,
        };
        if (!self.sessions.ownsPacketId(handle, ack.packet_id)) {
            return .{
                .owned = false,
                .persistent_changed = false,
            };
        }
        const persistent_changed = self.sessionIsPersistentLocked(handle);
        _ = try self.sessions.handleAck(
            handle,
            ack.packet_type,
            ack.packet_id,
            ack.reason_code,
        );
        self.recordPersistentChangeLocked(persistent_changed);
        return .{
            .owned = true,
            .persistent_changed = persistent_changed,
        };
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

    fn publishAuthorized(
        self: Broker,
        listener_access: ?ListenerAccessControlHandler,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool {
        if (self.options.access_control) |access| {
            if (!access.authorize_publish(
                access.context,
                connect,
                publish,
            )) return false;
        }
        const access = listener_access orelse return true;
        const authorize = access.authorize_publish orelse return true;
        return authorize(access.context, connect, publish);
    }

    fn subscribeAuthorized(
        self: Broker,
        listener_access: ?ListenerAccessControlHandler,
        connect: mqtt.Connect,
        subscription: mqtt.Subscription,
    ) bool {
        if (self.options.access_control) |access| {
            if (!access.authorize_subscribe(
                access.context,
                connect,
                subscription,
            )) return false;
        }
        const access = listener_access orelse return true;
        const authorize = access.authorize_subscribe orelse return true;
        return authorize(access.context, connect, subscription);
    }

    fn unsubscribeAuthorized(
        self: Broker,
        listener_access: ?ListenerAccessControlHandler,
        connect: mqtt.Connect,
        topic_filter: []const u8,
    ) bool {
        if (self.options.access_control) |access| {
            if (access.authorize_unsubscribe) |authorize| {
                if (!authorize(access.context, connect, topic_filter)) {
                    return false;
                }
            }
        }
        const access = listener_access orelse return true;
        const authorize = access.authorize_unsubscribe orelse return true;
        return authorize(access.context, connect, topic_filter);
    }

    fn deliveryAuthorized(
        self: Broker,
        listener_access: ?ListenerAccessControlHandler,
        delivery: DeliveryAuthorization,
    ) bool {
        if (self.options.access_control) |access| {
            if (access.authorize_delivery) |authorize| {
                if (!authorize(access.context, delivery)) return false;
            }
        }
        const access = listener_access orelse return true;
        const authorize = access.authorize_delivery orelse return true;
        return authorize(access.context, delivery);
    }

    fn retainedSourceAuthorized(
        self: Broker,
        delivery: retained_mod.Delivery,
    ) bool {
        if (!self.options.check_retain_source) return true;
        const source_client_id = delivery.source_client_id orelse return true;
        const access = self.options.access_control orelse return true;
        const authorize = access.authorize_retained_source orelse return true;
        return authorize(access.context, .{
            .client_id = source_client_id,
            .topic = delivery.topic,
            .payload = delivery.payload,
            .qos = delivery.source_qos,
            .retain = true,
            .properties = delivery.properties,
        });
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

    fn flushPublisherMatch(
        self: *Broker,
        plan: RoutePlan,
        publisher_id: router_mod.SubscriberId,
    ) Error!void {
        const slot_index = subscriberIndex(
            publisher_id,
            self.slots.len,
        ) orelse return;
        for (plan.deliveries) |match| {
            if (match.subscriber_id == publisher_id) {
                try self.flushSlot(slot_index, &self.slots[slot_index]);
                return;
            }
        }
        for (plan.session_targets) |match| {
            if (match.subscriber_id == publisher_id) {
                try self.flushSlot(slot_index, &self.slots[slot_index]);
                return;
            }
        }
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
            var take_changed = false;
            const maybe_packet = self.takeSessionPacketLocked(
                slot,
                &take_changed,
            ) catch |err| {
                if (take_changed) {
                    try self.finalizePersistentChange(true, true);
                }
                return err;
            };
            if (take_changed or maybe_packet != null) {
                // Commit logs retain their historical behavior of recording
                // every selected Session packet, including retransmissions.
                // Change autosave advances only for snapshot-visible changes.
                try self.finalizePersistentChange(true, take_changed);
            }
            if (maybe_packet) |packet_value| {
                var packet = packet_value;
                defer packet.deinit();
                // Selecting a durable QoS 1/2 message moves it from queued to
                // inflight and assigns its Packet Identifier. Sync that state
                // before the bytes can reach the peer, so restart retransmits
                // the same identifier with DUP rather than inventing a new
                // transaction.
                slot.connection.?.writeSessionTransmission(
                    packet.transmission,
                    slot.connection.?.localMaximumQoS(),
                ) catch |err| switch (err) {
                    error.OutgoingPacketTooLarge => {
                        if (packet.encoded.kind == .pubrel) return err;
                        // Match Mosquitto's oversized outgoing handling: once
                        // the peer's Maximum Packet Size rejects a PUBLISH,
                        // remove that transaction and continue draining rather
                        // than permanently consuming Session inflight credit.
                        self.state_mutex.lockUncancelable(self.io);
                        const drop_action = self.sessions.dropOversizedPublish(
                            packet.handle,
                            packet.encoded.packet_id,
                        ) catch null;
                        const persistent_changed = drop_action != null and
                            drop_action.? == .dropped and
                            self.sessionIsPersistentLocked(packet.handle);
                        self.recordPersistentChangeLocked(persistent_changed);
                        self.state_mutex.unlock(self.io);
                        if (persistent_changed) {
                            try self.finalizePersistentChange(true, true);
                        }
                        self.recordPublishDropped();
                        continue;
                    },
                    else => {
                        if (packet.encoded.kind != .pubrel) {
                            self.state_mutex.lockUncancelable(self.io);
                            const retry = self.sessions.retryUnsentPublish(
                                packet.handle,
                                packet.encoded.packet_id,
                            );
                            self.state_mutex.unlock(self.io);
                            retry catch {};
                        }
                        return err;
                    },
                };
                if (packet.transmission == .publish) {
                    self.recordPublishSent(
                        packet.transmission.publish.payload.len,
                    );
                }
                if (packet.encoded.kind == .qos0_publish) {
                    self.state_mutex.lockUncancelable(self.io);
                    const completion = self.sessions
                        .completeQoS0Transmission(
                        packet.handle,
                        packet.route_id,
                        packet.encoded.packet_id,
                    );
                    const current_handle = self.sessions.handleForRouteId(
                        packet.route_id,
                    );
                    const completion_succeeded = if (completion) |_|
                        true
                    else |_|
                        false;
                    const persistent_changed = completion_succeeded and
                        (if (current_handle) |value|
                            self.sessionIsPersistentLocked(value)
                        else
                            false);
                    self.recordPersistentChangeLocked(persistent_changed);
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
                    try self.finalizePersistentChange(
                        persistent_changed,
                        persistent_changed,
                    );
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
            const visible_topic = connection.topic_namespace.visibleTopic(
                delivery.publication.topic(),
            ) catch |err| switch (err) {
                error.TopicOutsideNamespace => {
                    // The canonical route should make this impossible for a
                    // correctly namespaced subscription. Fail closed if
                    // restored/corrupt state violates that invariant.
                    delivery.deinit();
                    continue;
                },
                else => return err,
            };
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
                visible_topic,
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
                    self.recordPublishDropped();
                    delivery.deinit();
                    continue;
                },
                else => {
                    delivery.deinit();
                    return err;
                },
            };
            self.recordPublishSent(delivery.publication.payload().len);
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
        persistent_changed_out: *bool,
    ) Error!?EncodedSessionPacket {
        persistent_changed_out.* = false;
        const handle = slot.session_handle orelse return null;
        const connection = &(slot.connection orelse return null);
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const route_id = try self.sessions.routeId(handle);
        const client_id = try self.sessions.clientId(handle);
        const persistent_session = self.sessionIsPersistentLocked(handle);
        var persistent_changed = false;
        errdefer {
            persistent_changed_out.* = persistent_changed;
            self.recordPersistentChangeLocked(persistent_changed);
        }

        while (true) {
            var storage: [1]session_mod.Transmission = undefined;
            var selection_changed = false;
            const transmissions = self.sessions.drainIntoTrackingSnapshotChange(
                handle,
                std.Io.Clock.awake.now(self.io),
                connection.max_outgoing_inflight,
                &storage,
                &selection_changed,
            ) catch |err| {
                persistent_changed = persistent_changed or
                    (persistent_session and selection_changed);
                if (err == error.SessionNotFound) return null;
                return err;
            };
            persistent_changed = persistent_changed or
                (persistent_session and selection_changed);
            if (transmissions.len == 0) {
                persistent_changed_out.* = persistent_changed;
                self.recordPersistentChangeLocked(persistent_changed);
                return null;
            }
            const transmission = transmissions[0];
            if (transmission == .publish and
                !self.deliveryAuthorized(slot.listener_access_control, .{
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
                const drop_action = try self.sessions.dropOutgoingPublish(
                    handle,
                    transmission.publish.packet_id,
                );
                persistent_changed = persistent_changed or
                    (persistent_session and drop_action == .dropped);
                continue;
            }
            if (transmission == .publish and
                !connection.topic_namespace.containsTopic(
                    transmission.publish.topic,
                ))
            {
                // A durable Session may reconnect through a listener with a
                // different mount point. Its subscriptions remain canonical,
                // but a queued publication outside the new listener's view
                // must not abort the connection or permanently block later
                // visible messages. This follows the same fail-closed/drop
                // policy as a delivery whose read ACL changed while offline.
                const drop_action = try self.sessions.dropOutgoingPublish(
                    handle,
                    transmission.publish.packet_id,
                );
                persistent_changed = persistent_changed or
                    (persistent_session and drop_action == .dropped);
                continue;
            }
            const encoded = session_route.encodeTransmission(
                self.allocator,
                connection.protocol,
                transmission,
                connection.localMaximumQoS(),
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
            persistent_changed_out.* = persistent_changed;
            self.recordPersistentChangeLocked(persistent_changed);
            return .{
                .encoded = encoded,
                .transmission = transmission,
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
            var published_any = false;
            var persistent_changed = expired_count != 0;
            self.publishDueWillsLocked(
                now,
                &published_any,
                &persistent_changed,
            ) catch |err| {
                self.recordPersistentChangeLocked(persistent_changed);
                self.state_mutex.unlock(self.io);
                if (persistent_changed) {
                    self.finalizePersistentChange(true, true) catch {};
                }
                // A prior Will, or a failing Will with a partially committed
                // publication, may already have populated live/durable queues.
                // Preserve the original route error while making that prefix
                // observable exactly once.
                if (published_any) self.flushAllSlots() catch {};
                return err;
            };
            self.recordPersistentChangeLocked(persistent_changed);
            // `$SYS` publication itself uses the state lock and ordinary
            // routing. Decide whether it is due here, but advance the next
            // deadline only after a complete snapshot is published. A failed
            // update is therefore retryable instead of silently skipped.
            var publish_system_stats = false;
            if (self.options.system_stats_interval != null) {
                // Wait one full interval after startup. Publishing before the
                // first accepted connection is registered would expose a
                // misleading zero-client snapshot to that client.
                if (self.next_system_stats_ns == null) {
                    self.next_system_stats_ns = now.addDuration(
                        self.options.system_stats_interval.?,
                    ).nanoseconds;
                }
                const due = self.next_system_stats_ns.?;
                if (now.nanoseconds >= due) {
                    publish_system_stats = true;
                }
            }
            const lifecycle_deadline = earliestDeadline(
                self.wills.nextDeadline(),
                self.sessions.nextExpiryDeadline(),
            );
            const deadline = earliestDeadline(
                lifecycle_deadline,
                if (self.next_system_stats_ns) |value|
                    .{ .nanoseconds = value }
                else
                    null,
            );
            const generation =
                self.deadline_driver.currentGeneration();
            self.state_mutex.unlock(self.io);

            if (published_any or expired_count != 0) {
                try self.finalizePersistentChange(
                    persistent_changed,
                    persistent_changed,
                );
            }
            if (published_any) {
                self.flushAllSlots() catch |err| return err;
            }
            if (publish_system_stats) {
                self.publishSystemStats() catch |err| return err;
                self.state_mutex.lockUncancelable(self.io);
                const interval = self.options.system_stats_interval.?;
                // Skip missed ticks instead of bursting stale snapshots after
                // a long scheduling pause.
                self.next_system_stats_ns = std.Io.Clock.awake.now(self.io)
                    .addDuration(interval).nanoseconds;
                self.state_mutex.unlock(self.io);
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
        published_any: *bool,
        persistent_changed: *bool,
    ) Error!void {
        while (self.wills.pollOneDue(now)) |handle| {
            var progress: WillPublishProgress = .{};
            self.publishWillLocked(handle, now, &progress) catch |err| {
                persistent_changed.* = persistent_changed.* or
                    progress.persistent_changed;
                if (progress.publication_effect_committed) {
                    // Some Will effect is already durable. Retrying would add
                    // a second copy to every Session reached before the error.
                    self.wills.releaseDue(handle) catch unreachable;
                    _ = self.will_publishers.remove(handle);
                    persistent_changed.* = true;
                    published_any.* = true;
                } else {
                    // No Will effect escaped, so preserve its original deadline
                    // and retry on the next driver turn.
                    self.wills.retryDue(handle) catch unreachable;
                }
                return err;
            };
            self.wills.releaseDue(handle) catch unreachable;
            _ = self.will_publishers.remove(handle);
            persistent_changed.* = true;
            published_any.* = true;
        }
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
        progress: *WillPublishProgress,
    ) Error!void {
        progress.* = .{};
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
        if (self.options.protect_reserved_topics and
            !clientMayPublishTopic(publish.topic))
        {
            return;
        }
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
                    return;
                }
            }
        }
        const plan = try self.enqueuePublishLocked(
            publisher_id,
            publish,
            will.client_id,
            now,
            &progress.persistent_changed,
            &progress.publication_effect_committed,
        );
        defer self.allocator.free(plan.storage);

        // The state lock cannot be held across socket writes. Queue ownership
        // is committed at this point; the timer loop releases the lock before
        // flushing all active slots below.
    }
};

fn clientMayPublishTopic(topic: []const u8) bool {
    if (std.mem.startsWith(u8, topic, "$share")) return false;
    if (!std.mem.startsWith(u8, topic, "$SYS")) return true;
    return mqtt.topicMatchesFilter(
        topic,
        "$SYS/broker/connection/+/state",
    );
}

test "MQTT Will route failure consumes a partially committed publication" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
        },
        .retained = .{ .max_messages = 1 },
    });
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);

    const handle = try broker.wills.set(
        "partial-will",
        .{
            .topic = "will/partial",
            .payload = "committed-once",
            .qos = .at_least_once,
            .retain = true,
        },
        60,
    );
    try broker.will_publishers.put(allocator, handle, null);
    _ = broker.wills.close(handle, .session_ended, now) catch unreachable;

    // Fail the route-plan allocation only. The retained store and router own
    // their original allocator, while match allocation uses Broker.allocator.
    try broker.router.subscribe(1, .{ .topic_filter = "will/#" });
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    broker.allocator = failing.allocator();
    var published_any = false;
    var persistent_changed = false;
    const result = broker.publishDueWillsLocked(
        now,
        &published_any,
        &persistent_changed,
    );
    broker.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(published_any);
    try std.testing.expect(persistent_changed);
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    var retained_storage: [1]retained_mod.Match = undefined;
    const retained = try broker.retained.matchInto(
        "will/partial",
        now,
        &retained_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), retained.len);
    try std.testing.expectEqualStrings(
        "committed-once",
        retained[0].payload,
    );
    try std.testing.expect(broker.wills.pollOneDue(now) == null);
}

test "MQTT failed Clean Start journals the durable deletion" {
    const backing = std.testing.allocator;
    var threaded = std.Io.Threaded.init(backing, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(backing, .{});
    var broker = try Broker.init(failing.allocator(), io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
        },
        .session = .{ .max_sessions = 2 },
    });
    defer broker.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const now = std.Io.Clock.awake.now(io);
    const old = try broker.sessions.open(
        "failed-clean-start",
        false,
        60,
        now,
    );
    _ = try broker.sessions.setSubscription(
        old.handle,
        .{ .topic_filter = "failed/clean/#", .qos = .at_least_once },
        null,
    );
    _ = try broker.router.subscribeWithIdentifierStatus(
        sessionSubscriberId(old.route_id),
        .{ .topic_filter = "failed/clean/#", .qos = .at_least_once },
        null,
    );
    _ = try broker.pending_qos2.record(
        sessionSubscriberId(old.route_id),
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "failed/clean/inbound",
            .packet_id = 91,
            .properties = &.{},
            .payload = "must-not-return",
        },
        now,
    );
    try broker.sessions.disconnect(old.handle, null, now);
    try broker.createCommitLog(tmp.dir, "failed-clean.log", .{});

    // Reserve the connection queue before arming failure so registration
    // reaches the allocation immediately after Clean Start removes the old
    // durable Session. The out-progress bit must survive that error.
    const slot_index = try broker.claimSlot();
    try broker.slots[slot_index].queue.ensureTotalCapacity(
        broker.allocator,
        broker.options.limits.max_queued_deliveries_per_connection,
    );
    var progress: RegistrationProgress = .{};
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        broker.register(
            slot_index,
            .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 30,
                .client_id = "failed-clean-start",
            },
            null,
            &progress,
        ),
    );
    try std.testing.expect(progress.rollback_changed);
    failing.fail_index = std.math.maxInt(usize);
    broker.finishPartialPersistentChange(progress.rollback_changed);

    var restored = try Broker.init(backing, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
        },
    });
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "failed-clean.log", .{});
    try std.testing.expect(restored.sessions.find(
        "failed-clean-start",
        std.Io.Clock.awake.now(io),
    ) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        restored.router.subscriptionCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        restored.pending_qos2.count(),
    );
}

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
                if (try task.disconnectForProtocolViolation(
                    slot,
                    connection,
                    err,
                )) return;
                return err;
            };
            defer event.deinit(task.broker.allocator);
            switch (event) {
                .auth => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    defer slot.writer_mutex.unlock(task.broker.io);
                    const complete =
                        connection.applyAuthenticationEvent(
                            owned.auth,
                        ) catch |err| switch (err) {
                            error.AuthenticationMethodMismatch,
                            error.AuthenticationNotConfigured,
                            error.InvalidAuthenticationState,
                            => return,
                            else => return err,
                        };
                    const handler = task.broker.options.authentication orelse
                        return error.AuthenticationNotConfigured;
                    try handler.handle(
                        handler.context,
                        connection,
                        owned.auth,
                        complete,
                    );
                },
                .subscribe => |*owned| {
                    task.broker.handleSubscribe(
                        task.subscriber_id,
                        connection,
                        connect,
                        owned.subscribe,
                    ) catch |err| {
                        if (try task.disconnectForProtocolViolation(
                            slot,
                            connection,
                            err,
                        )) return;
                        return err;
                    };
                },
                .unsubscribe => |*owned| {
                    task.broker.handleUnsubscribe(
                        task.subscriber_id,
                        connection,
                        connect,
                        owned.unsubscribe,
                    ) catch |err| {
                        if (try task.disconnectForProtocolViolation(
                            slot,
                            connection,
                            err,
                        )) return;
                        return err;
                    };
                },
                .publish => |*owned| {
                    task.broker.routePublish(
                        task.subscriber_id,
                        connection,
                        connect,
                        owned.publish,
                    ) catch |err| {
                        if (try task.disconnectForProtocolViolation(
                            slot,
                            connection,
                            err,
                        )) return;
                        return err;
                    };
                },
                .puback => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_ack =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            if (try task.disconnectForProtocolViolation(
                                slot,
                                connection,
                                err,
                            )) return;
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (session_ack.persistent_changed) {
                        task.broker.finalizePersistentChange(
                            true,
                            true,
                        ) catch |err| {
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    }
                    if (!session_ack.owned and
                        connection.hasOutgoingPacketIdentifier(
                            owned.ack.packet_id,
                        ))
                    {
                        connection.applyPubAck(owned.ack) catch |err|
                            switch (err) {
                                error.PublishRefused => {},
                                else => {
                                    slot.writer_mutex.unlock(task.broker.io);
                                    if (try task.disconnectForProtocolViolation(
                                        slot,
                                        connection,
                                        err,
                                    )) return;
                                    return err;
                                },
                            };
                    }
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
                    const session_ack =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            if (try task.disconnectForProtocolViolation(
                                slot,
                                connection,
                                err,
                            )) return;
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (session_ack.persistent_changed) {
                        task.broker.finalizePersistentChange(
                            true,
                            true,
                        ) catch |err| {
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    }
                    if (!session_ack.owned) {
                        if (connection.hasOutgoingPacketIdentifier(
                            owned.ack.packet_id,
                        )) {
                            connection.applyPubRec(owned.ack) catch |err|
                                switch (err) {
                                    error.PublishRefused => {},
                                    else => {
                                        slot.writer_mutex.unlock(task.broker.io);
                                        if (try task.disconnectForProtocolViolation(
                                            slot,
                                            connection,
                                            err,
                                        )) return;
                                        return err;
                                    },
                                };
                        } else if (owned.ack.accepted()) {
                            // An accepted PUBREC always advances the QoS 2
                            // exchange with PUBREL. If Session state was lost,
                            // sending PUBREL lets the receiver finish (or answer
                            // Packet Identifier not found) without poisoning the
                            // Network Connection. A negative PUBREC is already
                            // terminal and requires no response.
                            connection.writePubRel(
                                owned.ack.packet_id,
                                0,
                            ) catch |err| {
                                slot.writer_mutex.unlock(task.broker.io);
                                return err;
                            };
                        }
                    }
                    slot.writer_mutex.unlock(task.broker.io);
                    if (session_ack.owned) {
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
                        connect.client_id,
                        owned.ack,
                    );
                },
                .pubcomp => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_ack =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            if (try task.disconnectForProtocolViolation(
                                slot,
                                connection,
                                err,
                            )) return;
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (session_ack.persistent_changed) {
                        task.broker.finalizePersistentChange(
                            true,
                            true,
                        ) catch |err| {
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    }
                    if (!session_ack.owned and
                        connection.hasOutgoingPacketIdentifier(
                            owned.ack.packet_id,
                        ))
                    {
                        connection.applyPubComp(owned.ack) catch |err|
                            switch (err) {
                                error.PublishRefused => {},
                                else => {
                                    slot.writer_mutex.unlock(task.broker.io);
                                    if (try task.disconnectForProtocolViolation(
                                        slot,
                                        connection,
                                        err,
                                    )) return;
                                    return err;
                                },
                            };
                    }
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
                    task.broker.handleDisconnect(
                        slot,
                        owned.disconnect,
                    ) catch |err| {
                        // Some DISCONNECT rules depend on CONNECT/Session
                        // state and therefore cannot be enforced by the
                        // packet parser. Report those violations with the
                        // same MQTT 5 reason mapping as malformed reads before
                        // unregister performs ungraceful Session/Will cleanup.
                        if (try task.disconnectForProtocolViolation(
                            slot,
                            connection,
                            err,
                        )) return;
                        return err;
                    };
                    return;
                },
            }
        }
    }

    fn disconnectForProtocolViolation(
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

const ListenerAcceptTask = struct {
    broker: *Broker,
    listener: Listener,
    result: *?anyerror,

    fn run(task: ListenerAcceptTask) std.Io.Cancelable!void {
        var pending = task.listener.source.acceptPending(
            task.listener.accept orelse task.broker.options.accept,
        ) catch |err| {
            task.result.* = err;
            return;
        };
        const slot_index = task.broker.claimSlot() catch |err| {
            pending.deinit(task.broker.allocator);
            task.result.* = err;
            return;
        };
        var slot_claimed = true;
        defer if (slot_claimed) {
            task.broker.releaseClaimedSlot(slot_index);
        };
        const client_task = task.broker.preparePending(
            slot_index,
            &pending,
            task.listener.namespace,
            task.listener.accept orelse task.broker.options.accept,
            task.listener.authorization,
            task.result,
        ) catch |err| {
            // `preparePending` owns and closes the pending connection on every
            // error path. Only the slot reservation remains ours to release.
            task.result.* = err;
            return;
        } orelse {
            slot_claimed = false;
            task.broker.releaseClaimedSlot(slot_index);
            return;
        };
        slot_claimed = false;
        ClientTask.run(client_task) catch |err| {
            task.result.* = err;
        };
    }
};

const ListenerSupervisorState = struct {
    broker: *Broker,
    options: ServeListenersUntilOptions,
    stopping: std.atomic.Value(bool) = .init(false),
    failed: std.Io.Event = .unset,
    error_mutex: std.Io.Mutex = .init,
    first_error: ?anyerror = null,

    fn shouldStop(self: *@This()) bool {
        return self.stopping.load(.acquire) or
            self.options.shutdown.isSet();
    }

    fn report(
        self: *@This(),
        listener_index: usize,
        stage: ListenerErrorStage,
        err: anyerror,
    ) void {
        if (self.options.error_observer) |observer| {
            observer.observe(observer.context, .{
                .listener_index = listener_index,
                .stage = stage,
                .err = err,
            });
        }
        const policy = switch (stage) {
            .accept => self.options.accept_error_policy,
            .connection => self.options.connection_error_policy,
        };
        if (policy != .stop) return;
        self.error_mutex.lockUncancelable(self.broker.io);
        if (self.first_error == null) self.first_error = err;
        self.error_mutex.unlock(self.broker.io);
        self.stopping.store(true, .release);
        self.failed.set(self.broker.io);
    }

    fn firstError(self: *@This()) ?anyerror {
        self.error_mutex.lockUncancelable(self.broker.io);
        defer self.error_mutex.unlock(self.broker.io);
        return self.first_error;
    }
};

const ListenerSupervisorAcceptTask = struct {
    supervisor: *ListenerSupervisorState,
    listener: ListenerEndpoint,
    listener_index: usize,

    fn run(task: ListenerSupervisorAcceptTask) std.Io.Cancelable!void {
        while (!task.supervisor.shouldStop()) {
            var pending = task.listener.source.acceptPending(
                task.listener.accept orelse
                    task.supervisor.broker.options.accept,
            ) catch |err| {
                if (err == error.Canceled or task.supervisor.shouldStop()) {
                    return error.Canceled;
                }
                task.supervisor.report(task.listener_index, .accept, err);
                if (task.supervisor.shouldStop()) return;
                const backoff = task.supervisor.options.accept_error_backoff;
                if (backoff.nanoseconds > 0) {
                    std.Io.sleep(
                        task.supervisor.broker.io,
                        backoff,
                        .awake,
                    ) catch |sleep_err| switch (sleep_err) {
                        error.Canceled => return error.Canceled,
                    };
                }
                continue;
            };
            if (task.supervisor.shouldStop()) {
                pending.deinit(task.supervisor.broker.allocator);
                return;
            }
            const slot_index = task.supervisor.broker.claimSlot() catch |err| {
                pending.deinit(task.supervisor.broker.allocator);
                task.supervisor.report(
                    task.listener_index,
                    .connection,
                    err,
                );
                if (task.supervisor.shouldStop()) return;
                continue;
            };
            var slot_claimed = true;
            defer if (slot_claimed) {
                task.supervisor.broker.releaseClaimedSlot(slot_index);
            };
            var connection_error: ?anyerror = null;
            const client_task = task.supervisor.broker.preparePending(
                slot_index,
                &pending,
                task.listener.namespace,
                task.listener.accept orelse
                    task.supervisor.broker.options.accept,
                task.listener.authorization,
                &connection_error,
            ) catch |err| {
                task.supervisor.report(
                    task.listener_index,
                    .connection,
                    err,
                );
                if (task.supervisor.shouldStop()) return;
                continue;
            } orelse {
                task.supervisor.broker.releaseClaimedSlot(slot_index);
                slot_claimed = false;
                continue;
            };
            slot_claimed = false;
            ClientTask.run(client_task) catch |err| {
                connection_error = err;
            };
            if (connection_error) |err| {
                if (err == error.Canceled and
                    task.supervisor.shouldStop()) return;
                task.supervisor.report(
                    task.listener_index,
                    .connection,
                    err,
                );
            }
        }
    }
};

fn waitForListenerEvent(
    event: *std.Io.Event,
    io: std.Io,
) std.Io.Cancelable!void {
    try event.wait(io);
}

fn disconnectReasonForReadViolation(err: anyerror) ?u8 {
    return switch (err) {
        error.QoSNotSupported => 0x9b,
        error.RetainNotSupported => 0x9a,
        error.TopicAliasInvalid => 0x94,
        error.ReceiveMaximumExceeded => 0x93,
        error.SharedSubscriptionsNotSupported => 0x9e,
        error.SubscriptionIdentifiersNotSupported => 0xa1,
        error.WildcardSubscriptionsNotSupported => 0xa2,
        error.InvalidPacketDirection,
        error.ReservedPacketType,
        error.InvalidProperty,
        error.InvalidReasonCode,
        error.InvalidTopic,
        error.InvalidSubscription,
        error.InvalidPacketIdentifier,
        error.InvalidAcknowledgement,
        error.UnexpectedPacket,
        => 0x82,
        error.InvalidPacketType,
        error.InvalidFlags,
        error.InvalidQoS,
        error.InvalidPropertyIdentifier,
        error.MalformedPropertyContext,
        error.MalformedSubscriptionOptions,
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
        disconnectReasonForReadViolation(error.InvalidPacketDirection),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReasonForReadViolation(error.ReservedPacketType),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidFlags),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidQoS),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidPacketType),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidPropertyIdentifier),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.MalformedPropertyContext),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.MalformedSubscriptionOptions),
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

fn uptimeSeconds(started_at_ns: i96, now_ns: i96) u64 {
    if (now_ns <= started_at_ns) return 0;
    const elapsed = @divTrunc(now_ns - started_at_ns, std.time.ns_per_s);
    return @intCast(@min(elapsed, std.math.maxInt(u64)));
}

fn loadCounters(stats_value: Stats) load_metrics.Counters {
    return .{
        .connections = stats_value.connections_received,
        .messages_received = stats_value.messages_received,
        .messages_sent = stats_value.messages_sent,
        .publish_messages_dropped = @intCast(stats_value.publish_messages_dropped),
        .publish_messages_received = @intCast(stats_value.publish_messages_received),
        .publish_messages_sent = @intCast(stats_value.publish_messages_sent),
        .bytes_received = stats_value.bytes_received,
        .bytes_sent = stats_value.bytes_sent,
    };
}

fn formatSystemMetric(
    buffer: []u8,
    stats_value: Stats,
    metric: SystemMetric,
) []const u8 {
    if (metric == .uptime) {
        return std.fmt.bufPrint(
            buffer,
            "{d} seconds",
            .{stats_value.uptime_seconds},
        ) catch unreachable;
    }
    return if (systemMetricLoadValue(stats_value, metric)) |value|
        std.fmt.bufPrint(buffer, "{d:.2}", .{value}) catch unreachable
    else
        std.fmt.bufPrint(
            buffer,
            "{d}",
            .{systemMetricValue(stats_value, metric)},
        ) catch unreachable;
}

fn systemMetricLoadValue(
    stats_value: Stats,
    metric: SystemMetric,
) ?f64 {
    return switch (metric) {
        .load_messages_received_1min => stats_value.load.one_minute.messages_received,
        .load_messages_received_5min => stats_value.load.five_minutes.messages_received,
        .load_messages_received_15min => stats_value.load.fifteen_minutes.messages_received,
        .load_messages_sent_1min => stats_value.load.one_minute.messages_sent,
        .load_messages_sent_5min => stats_value.load.five_minutes.messages_sent,
        .load_messages_sent_15min => stats_value.load.fifteen_minutes.messages_sent,
        .load_publish_dropped_1min => stats_value.load.one_minute.publish_messages_dropped,
        .load_publish_dropped_5min => stats_value.load.five_minutes.publish_messages_dropped,
        .load_publish_dropped_15min => stats_value.load.fifteen_minutes.publish_messages_dropped,
        .load_publish_received_1min => stats_value.load.one_minute.publish_messages_received,
        .load_publish_received_5min => stats_value.load.five_minutes.publish_messages_received,
        .load_publish_received_15min => stats_value.load.fifteen_minutes.publish_messages_received,
        .load_publish_sent_1min => stats_value.load.one_minute.publish_messages_sent,
        .load_publish_sent_5min => stats_value.load.five_minutes.publish_messages_sent,
        .load_publish_sent_15min => stats_value.load.fifteen_minutes.publish_messages_sent,
        .load_bytes_received_1min => stats_value.load.one_minute.bytes_received,
        .load_bytes_received_5min => stats_value.load.five_minutes.bytes_received,
        .load_bytes_received_15min => stats_value.load.fifteen_minutes.bytes_received,
        .load_bytes_sent_1min => stats_value.load.one_minute.bytes_sent,
        .load_bytes_sent_5min => stats_value.load.five_minutes.bytes_sent,
        .load_bytes_sent_15min => stats_value.load.fifteen_minutes.bytes_sent,
        .load_connections_1min => stats_value.load.one_minute.connections,
        .load_connections_5min => stats_value.load.five_minutes.connections,
        .load_connections_15min => stats_value.load.fifteen_minutes.connections,
        else => null,
    };
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

fn systemMetricValue(stats_value: Stats, metric: SystemMetric) u64 {
    return switch (metric) {
        .uptime => stats_value.uptime_seconds,
        .clients_connected => @intCast(stats_value.active_connections),
        .clients_maximum => @intCast(stats_value.maximum_active_connections),
        .clients_disconnected => @intCast(stats_value.disconnected_sessions),
        .clients_expired => @intCast(stats_value.expired_sessions),
        .clients_total => @intCast(stats_value.sessions),
        .messages_received => stats_value.messages_received,
        .messages_sent => stats_value.messages_sent,
        .bytes_received => stats_value.bytes_received,
        .bytes_sent => stats_value.bytes_sent,
        .publish_messages_received => @intCast(stats_value.publish_messages_received),
        .publish_messages_dropped => @intCast(stats_value.publish_messages_dropped),
        .publish_messages_sent => @intCast(stats_value.publish_messages_sent),
        .publish_bytes_received => @intCast(stats_value.publish_payload_bytes_received),
        .publish_bytes_sent => @intCast(stats_value.publish_payload_bytes_sent),
        .subscriptions => @intCast(stats_value.subscriptions),
        .shared_subscriptions => @intCast(stats_value.shared_subscriptions),
        .retained_messages => @intCast(stats_value.retained_messages),
        .retained_bytes => @intCast(stats_value.retained_bytes),
        .live_queued_deliveries => @intCast(stats_value.live_queued_deliveries),
        .session_queued_messages => @intCast(stats_value.session_queued_messages),
        .session_queued_payload_bytes => @intCast(stats_value.session_queued_payload_bytes),
        .session_inflight_messages => @intCast(stats_value.session_inflight_messages),
        .session_inflight_payload_bytes => @intCast(stats_value.session_inflight_payload_bytes),
        .pending_incoming_qos2 => @intCast(stats_value.pending_incoming_qos2),
        .scheduled_wills => @intCast(stats_value.scheduled_wills),
        .scheduled_will_bytes => @intCast(stats_value.scheduled_will_bytes),
        .session_owned_bytes => @intCast(stats_value.session_owned_bytes),
        .load_messages_received_1min,
        .load_messages_received_5min,
        .load_messages_received_15min,
        .load_messages_sent_1min,
        .load_messages_sent_5min,
        .load_messages_sent_15min,
        .load_publish_dropped_1min,
        .load_publish_dropped_5min,
        .load_publish_dropped_15min,
        .load_publish_received_1min,
        .load_publish_received_5min,
        .load_publish_received_15min,
        .load_publish_sent_1min,
        .load_publish_sent_5min,
        .load_publish_sent_15min,
        .load_bytes_received_1min,
        .load_bytes_received_5min,
        .load_bytes_received_15min,
        .load_bytes_sent_1min,
        .load_bytes_sent_5min,
        .load_bytes_sent_15min,
        .load_connections_1min,
        .load_connections_5min,
        .load_connections_15min,
        => unreachable,
    };
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

fn subscriptionQuotaExceededReason(protocol: mqtt.ProtocolVersion) u8 {
    // MQTT 5 can distinguish the broker's configured subscription-capacity
    // bound from ACL denial. MQTT 3.1.1 exposes only the generic SUBACK
    // failure byte while still allowing other filters in the packet to
    // succeed.
    return if (protocol == .v5) 0x97 else 0x80;
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

fn validateLocalPublish(publish: mqtt.Publish) Error!void {
    try mqtt.validateTopicName(publish.topic);
    try mqtt.validatePublishProperties(publish.properties);
    if (publish.dup or publish.packet_id != null) {
        return error.InvalidPacketIdentifier;
    }
    for (publish.properties) |property| {
        // Both values are scoped to a particular MQTT connection. A local
        // producer must supply the resolved Topic Name and let the broker
        // generate Subscription Identifiers for each destination.
        if ((property == .two_byte and
            property.two_byte.id == .topic_alias) or
            (property == .varint and
                property.varint.id == .subscription_identifier))
        {
            return error.InvalidProperty;
        }
        if (property == .byte and
            property.byte.id == .payload_format_indicator and
            property.byte.value == 1 and
            !std.unicode.utf8ValidateSlice(publish.payload))
        {
            return error.InvalidUtf8;
        }
    }
}

test {
    _ = load_metrics;
    _ = @import("broker_tests.zig");
    _ = @import("broker/persistence_tests.zig");
}

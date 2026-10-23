//! Bounded in-memory MQTT broker core.
//!
//! This module composes the transport-independent connection runtime with the
//! topic router and bounded retained, Session, QoS 2, and Will state. It
//! focuses on the live broker hot path: SUBSCRIBE/UNSUBSCRIBE, QoS 0/1/2
//! routing, offline Session queueing, reconnect retransmission, No Local/shared
//! selection, downstream acknowledgements, and connection cleanup.

const std = @import("std");
const builtin = @import("builtin");
const mqtt = @import("mod.zig");
const netz_runtime = @import("../runtime.zig");
const owned_properties = @import("owned_properties.zig");
const router_mod = @import("router.zig");
const runtime = @import("runtime.zig");
const listener_namespace = @import("listener_namespace.zig");
const client_id_mod = @import("broker/client_id.zig");
const load_metrics = @import("broker/load_metrics.zig");
const local_consumer_mod = @import("broker/local_consumer.zig");
const publish_counters = @import("broker/publish_counters.zig");
const persistence_mod = @import("persistence/mod.zig");
const commit_log_mod = persistence_mod.commit_log;
const vail = @import("vail");
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
const session_writer = @import("broker/session_writer.zig");
const deadline_driver_mod = @import("broker/deadline_driver.zig");
const runtime_policy_mod = @import("broker/runtime_policy.zig");
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
    ClientIdPrefixMismatch,
    ClientNotRegistered,
    ClientOffline,
    CommitLogAlreadyEnabled,
    LocalConsumerAlreadyOpen,
    LocalConsumerClosed,
    LocalConsumerIdentityMismatch,
    OwnedPropertyLimitExceeded,
};

const LocalConsumerContext = struct {
    pub const BrokerType = Broker;
    pub const ErrorType = Error;
    pub const pruneExpiredSessionRoutesLocked = Broker.pruneExpiredSessionRoutesLocked;
    pub const recordPersistentChangeLocked = Broker.recordPersistentChangeLocked;
    pub const finishPartialPersistentChange = Broker.finishPartialPersistentChange;
    pub const retainedSourceAuthorized = Broker.retainedSourceAuthorized;
    pub const enqueueSessionDeliveryLocked = Broker.enqueueSessionDeliveryLocked;
    pub const finalizePersistentChange = Broker.finalizeLocalConsumerChange;
    pub const prepareRetainedDeliveryProperties = prepareLocalConsumerProperties;
};

const registration_persistence = @import("broker/registration_persistence.zig");
const RegistrationPersistenceContext = struct {
    pub const BrokerType = Broker;
    pub const appendCommitIfEnabledLocked = Broker.appendCommitIfEnabledLocked;
    pub const autosavePersistentChangesIfNeededLocked = Broker.autosavePersistentChangesIfNeededLocked;
};

const prepareLocalConsumerProperties = prepareRetainedDeliveryProperties;

pub const LocalConsumer = local_consumer_mod.Handle;
pub const LocalConsumerOptions = local_consumer_mod.Options;
pub const LocalConsumerEvent = local_consumer_mod.Event;
pub const LocalConsumerAckAction = local_consumer_mod.AckAction;
pub const LocalConsumerWake = local_consumer_mod.Wake;

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
    /// Keep the target configured while a periodic controller owns scheduling.
    /// Runtime policy can enable this threshold without reallocating the path.
    enabled: bool = true,
};

/// Owned, fallible preparation for changing the broker-managed snapshot
/// target without allocating in the reload commit phase.
pub const PreparedChangeAutosaveTarget = struct {
    allocator: std.mem.Allocator,
    options: ?ChangeAutosaveOptions,
    consumed: bool = false,

    pub fn deinit(self: *PreparedChangeAutosaveTarget) void {
        if (!self.consumed) {
            if (self.options) |options| {
                self.allocator.free(@constCast(options.sub_path));
            }
        }
        self.options = null;
        self.consumed = true;
    }

    fn take(self: *PreparedChangeAutosaveTarget) ?ChangeAutosaveOptions {
        std.debug.assert(!self.consumed);
        const options = self.options;
        self.options = null;
        self.consumed = true;
        return options;
    }
};

pub const RuntimeSchedulingPolicy = deadline_driver_mod.Policy;
pub const RuntimeDeliveryPolicy = runtime_policy_mod.Delivery;

/// Fallible preparation for a no-fail required Client ID prefix commit.
pub const PreparedRequiredClientIdPrefix = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    consumed: bool = false,

    pub fn deinit(self: *PreparedRequiredClientIdPrefix) void {
        if (!self.consumed and self.bytes.len != 0) {
            self.allocator.free(self.bytes);
        }
        self.bytes = &.{};
        self.consumed = true;
    }

    fn take(self: *PreparedRequiredClientIdPrefix) []u8 {
        std.debug.assert(!self.consumed);
        const bytes = self.bytes;
        self.bytes = &.{};
        self.consumed = true;
        return bytes;
    }
};

pub const Options = struct {
    limits: Limits = .{},
    /// Maximum outgoing QoS 1/2 payload bytes held by each transient Network
    /// Connection; zero is unlimited. Durable Sessions use the corresponding
    /// `session.max_inflight_payload_bytes_per_session` option instead.
    max_inflight_payload_bytes_per_connection: usize = 0,
    /// Prefix for broker-assigned Client Identifiers. Copied by `listen`.
    ///
    /// Mosquitto limits `auto_id_prefix` to 50 bytes; matching that cap keeps
    /// the generated identifier below MQTT's u16 UTF-8 string bound.
    auto_client_id_prefix: []const u8 = "netz-",
    /// Optional global prefix required for every network Client Identifier.
    /// The bytes are copied by `init`; an empty slice disables the policy.
    client_id_prefix: []const u8 = &.{},
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
    /// Periodically remove retained Application Messages whose MQTT 5 Message
    /// Expiry Interval has elapsed. Null leaves expiry cleanup lazy: expired
    /// entries are ignored on replay and snapshot but may retain memory until
    /// accessed or replaced.
    retained_expiry_interval: ?std.Io.Duration = null,
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
    /// Use the verified leaf certificate's Subject commonName, or the CN from
    /// a trusted PROXY v2 SSL assertion for a verified client certificate, as
    /// the MQTT username before every authorization callback. Wire
    /// username/password are ignored; a missing or invalid identity is
    /// refused.
    use_identity_as_username: bool = false,
    /// Use the verified leaf certificate's complete OpenSSL-compatible RFC
    /// 2253 Subject as the MQTT username. The CN-only policy takes precedence
    /// when both options are enabled, matching Mosquitto.
    use_subject_as_username: bool = false,
    /// Stable caller-defined identity persisted with retained publications so
    /// replay-time source authorization can select the originating listener's
    /// policy. Mosquitto's configuration adapter uses the listener port.
    retained_source_id: ?u64 = null,
};

/// Per-listener packet policy. Every callback is optional because this is an
/// overlay: configured broker-wide ACL callbacks are always evaluated first.
/// Delayed Wills intentionally remain broker-scoped because they can outlive
/// both the listener serve call and its borrowed callback context. The
/// listener Will callback therefore runs during CONNECT admission; it may
/// suppress registration, while broker-wide `authorize_will` is re-evaluated
/// when a surviving Will actually becomes due.
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
    /// Validate a mapped Will while CONNECT identity and listener policy are
    /// both alive. A denial suppresses that Will without refusing CONNECT.
    authorize_will: ?*const fn (
        context: *anyopaque,
        connect: mqtt.Connect,
        will: mqtt.LastWill,
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
    /// Username from the currently connected destination, if any. Offline
    /// queued messages have no listener policy and are rechecked on reconnect.
    username: ?[]const u8 = null,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
};

/// The broker and listener delivery callbacks form one mandatory chain when
/// either level configured a read policy. Keeping borrowed handler pointers
/// here avoids copying either callback table on every routed destination.
const DeliveryAuthorizationChain = struct {
    broker: ?*const AccessControlHandler = null,
    listener: ?*const ListenerAccessControlHandler = null,

    fn configured(self: DeliveryAuthorizationChain) bool {
        if (self.broker) |access| {
            if (access.authorize_delivery != null) return true;
        }
        if (self.listener) |access| {
            if (access.authorize_delivery != null) return true;
        }
        return false;
    }

    fn authorize(
        self: DeliveryAuthorizationChain,
        delivery: DeliveryAuthorization,
    ) bool {
        if (self.broker) |access| {
            if (access.authorize_delivery) |callback| {
                if (!callback(access.context, delivery)) return false;
            }
        }
        const access = self.listener orelse return true;
        const callback = access.authorize_delivery orelse return true;
        return callback(access.context, delivery);
    }
};

fn prepareRetainedDeliveryProperties(
    out: *std.ArrayList(mqtt.Property),
    allocator: std.mem.Allocator,
    source: []const mqtt.Property,
    remaining_expiry_interval: ?u32,
) std.mem.Allocator.Error!void {
    out.clearRetainingCapacity();
    try out.ensureTotalCapacity(allocator, source.len);
    for (source) |property| {
        if (property == .four_byte and
            property.four_byte.id == .message_expiry_interval)
        {
            const remaining = remaining_expiry_interval orelse continue;
            out.appendAssumeCapacity(.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = remaining,
            } });
        } else {
            out.appendAssumeCapacity(property);
        }
    }
}

/// Borrowed source and Application Message metadata for a Will write ACL.
/// The callback runs when the Will becomes due, not when CONNECT registers it,
/// so a policy update during Will Delay can suppress publication.
pub const WillAuthorization = struct {
    client_id: []const u8,
    username: ?[]const u8 = null,
    listener_id: ?u64 = null,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
};

/// Original retained publisher and Application Message metadata for replay-
/// time write authorization. Identity strings and the caller-defined listener
/// ID are owned by retained state and remain available after disconnect,
/// Session expiry, and snapshot load.
pub const RetainedSourceAuthorization = struct {
    client_id: []const u8,
    username: ?[]const u8 = null,
    listener_id: ?u64 = null,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
};

/// Borrowed identity for reauthorizing an established connection after a
/// policy reload. The callback runs under the broker state lock and must not
/// retain either slice or re-enter the Broker.
pub const ActiveConnectionAuthorization = struct {
    username: ?[]const u8 = null,
    listener_id: ?u64 = null,
};

pub const ConnectionReauthorizationHandler = struct {
    context: *anyopaque,
    still_authorized: *const fn (
        context: *anyopaque,
        connection: ActiveConnectionAuthorization,
    ) bool,
};

pub const AuthenticationHandler = struct {
    context: *anyopaque,
    /// Complete any CONNECT-before-CONNACK exchange and call
    /// `pending.authorizeAuthentication()` only after policy success. The
    /// pending client's ordinary challenge, receive, and finish operations
    /// inherit the original CONNECT admission deadline; explicit deadlines
    /// may shorten that budget but cannot extend it.
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
    /// Online transient targets below the asynchronous queue high watermark.
    deliveries: []const router_mod.Match,
    /// Persistent live QoS 0, same-connection, and backpressured transient
    /// targets remain on the ordered caller-owned flush path.
    synchronous_deliveries: []const router_mod.Match,
    /// Online durable Session targets assigned to the bounded shared writer
    /// pool with a queue below the asynchronous high watermark.
    session_deliveries: []const router_mod.Match,
    /// Same-connection, backpressured, or not-yet-writer-backed durable
    /// Session targets retain the caller-owned ordered path.
    synchronous_session_targets: []const router_mod.Match,
    has_matching_subscriber: bool,
    scratch_owner: ?*std.ArrayList(router_mod.Match) = null,

    fn deinit(self: RoutePlan, allocator: std.mem.Allocator) void {
        if (self.scratch_owner) |scratch| {
            scratch.clearRetainingCapacity();
        } else {
            allocator.free(self.storage);
        }
    }
};

const NetworkDeliveryMode = enum {
    synchronous,
    asynchronous,
    deferred,
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

const DetachedSessionPacket = struct {
    detached: session_route.DetachedPacket,
    payload_len: usize,
    handle: session_mod.Handle,
    route_id: u64,
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
const route_match_scratch_capacity: usize = 32;
const session_write_scratch_retain_limit: usize = 64 * 1024;
const transient_delivery_async_high_watermark: usize = 16;
const shared_session_delivery_writer_count: usize = 2;
const session_property_scratch_retain_capacity =
    session_write_scratch_retain_limit / @sizeOf(mqtt.Property);

const DeliveryWriter = struct {
    stop: std.atomic.Value(bool) = .init(false),
    future: std.Io.Future(?anyerror),
};

/// Storage used only after a connection subscribes, publishes through the
/// router, or has a Session transmission to write. Keeping these empty
/// container headers out of every preallocated capacity slot also lets an
/// idle slot release all retained queue and QoS-map capacity on disconnect.
const ClientBuffers = struct {
    delivery_writer: ?*DeliveryWriter = null,
    queue: std.ArrayList(Delivery) = .empty,
    queue_head: usize = 0,
    route_matches: std.ArrayList(router_mod.Match) = .empty,
    session_write_scratch: std.ArrayList(u8) = .empty,
    session_property_scratch: std.ArrayList(mqtt.Property) = .empty,
    transient_inflight_payloads: std.AutoHashMapUnmanaged(u16, usize) = .empty,
    transient_inflight_payload_bytes: usize = 0,
    route_reservations: usize = 0,
};

const ClientSlot = struct {
    state: packed struct(u64) {
        generation: u31 = 0,
        active: bool = false,
        assigned_client_id_len: u7 = 0,
        username_len: u16 = 0,
        session_present: bool = false,
        session_persistent: bool = false,
        graceful_disconnect: bool = false,
        has_will_handle: bool = false,
        has_session_handle: bool = false,
        has_retained_source_id: bool = false,
        administrative_disconnect: bool = false,
        /// Rollback cleared all provisional state while the admission caller
        /// still owns this reserved slot. It may safely participate in a
        /// checkpoint without making the slot available to another accept.
        registration_aborted: bool = false,
        _padding: u1 = 0,
    } = .{},
    /// Allocated only after policy and Session admission, immediately before a
    /// successful CONNACK. Keeping the large transport/session state out of
    /// line prevents every unused capacity slot from reserving a Connection.
    connection: ?*runtime.Connection = null,
    /// Presence lives in `state`, avoiding an extra machine word for each
    /// generation-checked handle while retaining their complete value range.
    will_handle_value: will_mod.Handle = undefined,
    session_handle_value: session_mod.Handle = undefined,
    /// Whether Server Session State survives loss of this Network Connection.
    ///
    /// Transient sessions still use a stable route while connected, but live
    /// QoS 1/2 fanout can use the connection-local inflight state and one
    /// shared Publication. Durable sessions must instead deep-own each queued
    /// message so reconnect retransmission remains possible.
    /// Present only when the broker assigned an identifier for an empty MQTT 5
    /// Client ID. Ordinary clients do not pay for the maximum 86-byte value.
    assigned_client_id_ptr: ?[*]u8 = null,
    /// Allocated only when a listener contributes an ACL overlay. Callback
    /// contexts remain borrowed from the listener for the connection lifetime.
    listener_access_control: ?*ListenerAccessControlHandler = null,
    retained_source_id_value: u64 = undefined,
    /// Borrowed from `ClientTask.connect` while this slot is active. MQTT's
    /// two-byte UTF-8 length bounds the compact descriptor.
    username_ptr: ?[*]const u8 = null,
    writer_mutex: std.Io.Mutex = .init,
    /// A lazily started connection-lifetime writer waits here for routed
    /// deliveries. Pure publishers therefore pay no extra coroutine cost.
    delivery_ready: std.Io.Event = .unset,
    /// Queue, route, Session-write and transient-QoS storage is allocated as
    /// one descriptor only when the connection first needs any of it.
    buffers: ?*ClientBuffers = null,

    fn ensureBuffers(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*ClientBuffers {
        if (self.buffers) |buffers| return buffers;
        const buffers = try allocator.create(ClientBuffers);
        buffers.* = .{};
        self.buffers = buffers;
        return buffers;
    }

    fn clearBuffers(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) void {
        const buffers = self.buffers orelse return;
        std.debug.assert(buffers.delivery_writer == null);
        self.clearQueue();
        buffers.queue.deinit(allocator);
        buffers.route_matches.deinit(allocator);
        buffers.session_write_scratch.deinit(allocator);
        buffers.session_property_scratch.deinit(allocator);
        buffers.transient_inflight_payloads.deinit(allocator);
        allocator.destroy(buffers);
        self.buffers = null;
    }

    fn ensureDeliveryCapacity(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
        capacity: usize,
    ) Error!void {
        if (self.buffers) |buffers| {
            if (buffers.queue.capacity >= capacity) return;
            try buffers.queue.ensureTotalCapacityPrecise(allocator, capacity);
            return;
        }
        const buffers = try self.ensureBuffers(allocator);
        errdefer self.clearBuffers(allocator);
        try buffers.queue.ensureTotalCapacityPrecise(allocator, capacity);
    }

    /// Reserve queue storage before a route becomes observable. The common
    /// asynchronous window is allocated at subscription time; a genuinely
    /// slow consumer grows geometrically only as its live backlog grows.
    /// Queue mutation after this preflight remains allocation-free.
    fn ensureDeliveryReservationCapacity(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
        additional: usize,
        limit: usize,
    ) Error!void {
        std.debug.assert(additional != 0);
        const buffers = try self.ensureBuffers(allocator);
        const reserved = std.math.add(
            usize,
            buffers.route_reservations,
            additional,
        ) catch return error.OutOfMemory;
        const required_live = std.math.add(
            usize,
            self.queuedCount(),
            reserved,
        ) catch return error.OutOfMemory;
        std.debug.assert(required_live <= limit);

        var required_tail = std.math.add(
            usize,
            buffers.queue.items.len,
            reserved,
        ) catch return error.OutOfMemory;
        if (required_tail <= buffers.queue.capacity) return;

        // A consumed prefix is already paid-for bounded storage. Reclaim it
        // before asking the allocator to grow the backing slice.
        if (buffers.queue_head != 0) {
            self.compactDeliveryQueue();
            required_tail = std.math.add(
                usize,
                buffers.queue.items.len,
                reserved,
            ) catch return error.OutOfMemory;
            if (required_tail <= buffers.queue.capacity) return;
        }

        const geometric_capacity = std.math.add(
            usize,
            buffers.queue.capacity,
            @max(buffers.queue.capacity / 2, 1),
        ) catch limit;
        const target_capacity = @min(
            limit,
            @max(
                required_tail,
                @max(
                    transient_delivery_async_high_watermark,
                    geometric_capacity,
                ),
            ),
        );
        std.debug.assert(target_capacity >= required_tail);
        try buffers.queue.ensureTotalCapacityPrecise(
            allocator,
            target_capacity,
        );
    }

    fn clearQueue(self: *ClientSlot) void {
        const buffers = self.buffers orelse return;
        for (buffers.queue.items[buffers.queue_head..]) |*delivery| {
            delivery.deinit();
        }
        buffers.queue.clearRetainingCapacity();
        buffers.queue_head = 0;
    }

    fn transientInflightPayloadLimitReached(
        self: ClientSlot,
        limit: usize,
    ) bool {
        const buffers = self.buffers orelse return false;
        return limit != 0 and
            buffers.transient_inflight_payload_bytes >= limit;
    }

    fn recordTransientInflight(
        self: *ClientSlot,
        packet_id: u16,
        payload_len: usize,
    ) void {
        const buffers = self.buffers.?;
        std.debug.assert(packet_id != 0);
        std.debug.assert(!buffers.transient_inflight_payloads.contains(
            packet_id,
        ));
        buffers.transient_inflight_payloads.putAssumeCapacityNoClobber(
            packet_id,
            payload_len,
        );
        buffers.transient_inflight_payload_bytes = std.math.add(
            usize,
            buffers.transient_inflight_payload_bytes,
            payload_len,
        ) catch unreachable;
    }

    fn releaseTransientInflight(
        self: *ClientSlot,
        packet_id: u16,
    ) bool {
        const buffers = self.buffers orelse return false;
        const removed = buffers.transient_inflight_payloads.fetchRemove(
            packet_id,
        ) orelse return false;
        buffers.transient_inflight_payload_bytes -= removed.value;
        return true;
    }

    fn hasTransientInflight(
        self: ClientSlot,
        packet_id: u16,
    ) bool {
        const buffers = self.buffers orelse return false;
        return buffers.transient_inflight_payloads.contains(packet_id);
    }

    fn clearTransientInflight(self: *ClientSlot) void {
        const buffers = self.buffers orelse return;
        buffers.transient_inflight_payloads.clearRetainingCapacity();
        buffers.transient_inflight_payload_bytes = 0;
    }

    fn clearAssignedClientId(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) void {
        if (self.takeAssignedClientId()) |client_id| {
            allocator.free(client_id);
        }
    }

    fn assignedClientId(self: ClientSlot) ?[]u8 {
        const ptr = self.assigned_client_id_ptr orelse return null;
        return ptr[0..self.state.assigned_client_id_len];
    }

    fn setAssignedClientId(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
        client_id: []const u8,
    ) std.mem.Allocator.Error![]u8 {
        comptime std.debug.assert(
            client_id_mod.max_len <= std.math.maxInt(u8),
        );
        std.debug.assert(self.assigned_client_id_ptr == null);
        std.debug.assert(client_id.len <= client_id_mod.max_len);
        const owned = try allocator.dupe(u8, client_id);
        self.assigned_client_id_ptr = owned.ptr;
        self.state.assigned_client_id_len = @intCast(owned.len);
        return owned;
    }

    fn takeAssignedClientId(self: *ClientSlot) ?[]u8 {
        const client_id = self.assignedClientId() orelse return null;
        self.assigned_client_id_ptr = null;
        self.state.assigned_client_id_len = 0;
        return client_id;
    }

    fn username(self: ClientSlot) ?[]const u8 {
        const ptr = self.username_ptr orelse return null;
        return ptr[0..self.state.username_len];
    }

    fn setUsername(self: *ClientSlot, maybe_username: ?[]const u8) void {
        const value = maybe_username orelse {
            self.username_ptr = null;
            self.state.username_len = 0;
            return;
        };
        std.debug.assert(value.len <= std.math.maxInt(u16));
        self.username_ptr = value.ptr;
        self.state.username_len = @intCast(value.len);
    }

    pub fn willHandle(self: ClientSlot) ?will_mod.Handle {
        return if (self.state.has_will_handle)
            self.will_handle_value
        else
            null;
    }

    pub fn setWillHandle(
        self: *ClientSlot,
        maybe_handle: ?will_mod.Handle,
    ) void {
        const handle = maybe_handle orelse {
            self.state.has_will_handle = false;
            return;
        };
        self.will_handle_value = handle;
        self.state.has_will_handle = true;
    }

    pub fn sessionHandle(self: ClientSlot) ?session_mod.Handle {
        return if (self.state.has_session_handle)
            self.session_handle_value
        else
            null;
    }

    pub fn setSessionHandle(
        self: *ClientSlot,
        maybe_handle: ?session_mod.Handle,
    ) void {
        const handle = maybe_handle orelse {
            self.state.has_session_handle = false;
            return;
        };
        self.session_handle_value = handle;
        self.state.has_session_handle = true;
    }

    fn retainedSourceId(self: ClientSlot) ?u64 {
        return if (self.state.has_retained_source_id)
            self.retained_source_id_value
        else
            null;
    }

    fn setRetainedSourceId(self: *ClientSlot, maybe_source_id: ?u64) void {
        const source_id = maybe_source_id orelse {
            self.state.has_retained_source_id = false;
            return;
        };
        self.retained_source_id_value = source_id;
        self.state.has_retained_source_id = true;
    }

    fn setListenerAccessControl(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
        access_control: ?ListenerAccessControlHandler,
    ) std.mem.Allocator.Error!void {
        std.debug.assert(self.listener_access_control == null);
        const value = access_control orelse return;
        const owned = try allocator.create(ListenerAccessControlHandler);
        owned.* = value;
        self.listener_access_control = owned;
    }

    fn accessControl(
        self: *const ClientSlot,
    ) ?*const ListenerAccessControlHandler {
        return self.listener_access_control;
    }

    fn clearListenerAccessControl(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) void {
        if (self.listener_access_control) |value| allocator.destroy(value);
        self.listener_access_control = null;
    }

    fn releaseOversizedSessionScratch(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) void {
        const buffers = self.buffers orelse return;
        if (buffers.session_write_scratch.capacity >
            session_write_scratch_retain_limit)
        {
            buffers.session_write_scratch.deinit(allocator);
            buffers.session_write_scratch = .empty;
        }
        if (buffers.session_property_scratch.capacity >
            session_property_scratch_retain_capacity)
        {
            buffers.session_property_scratch.deinit(allocator);
            buffers.session_property_scratch = .empty;
        }
    }

    fn queuedCount(self: ClientSlot) usize {
        const buffers = self.buffers orelse return 0;
        return buffers.queue.items.len - buffers.queue_head;
    }

    fn popDelivery(self: *ClientSlot) ?Delivery {
        const buffers = self.buffers orelse return null;
        if (buffers.queue_head == buffers.queue.items.len) return null;
        const delivery = buffers.queue.items[buffers.queue_head];
        buffers.queue_head += 1;
        if (buffers.queue_head >= 64 and
            buffers.queue_head * 2 >= buffers.queue.items.len)
        {
            self.compactDeliveryQueue();
        }
        return delivery;
    }

    fn compactDeliveryQueue(self: *ClientSlot) void {
        const buffers = self.buffers.?;
        const remaining = self.queuedCount();
        if (remaining != 0) {
            std.mem.copyForwards(
                Delivery,
                buffers.queue.items[0..remaining],
                buffers.queue.items[buffers.queue_head..],
            );
        }
        buffers.queue.items.len = remaining;
        buffers.queue_head = 0;
    }

    fn pushFront(self: *ClientSlot, delivery: Delivery) void {
        const buffers = self.buffers.?;
        if (buffers.queue_head != 0) {
            buffers.queue_head -= 1;
            buffers.queue.items[buffers.queue_head] = delivery;
            return;
        }

        // `popDelivery` can compact consumed storage before the network write
        // reports InflightFull. Compaction leaves at least one unused element
        // of capacity, allowing the delivery to be restored without an
        // allocation or a fallible backpressure path.
        std.debug.assert(buffers.queue.items.len < buffers.queue.capacity);
        const old_len = buffers.queue.items.len;
        buffers.queue.appendAssumeCapacity(delivery);
        std.mem.copyBackwards(
            Delivery,
            buffers.queue.items[1 .. old_len + 1],
            buffers.queue.items[0..old_len],
        );
        buffers.queue.items[0] = delivery;
    }

    fn appendDeliveryAssumeCapacity(
        self: *ClientSlot,
        delivery: Delivery,
    ) void {
        const buffers = self.buffers.?;
        // Consumed prefix storage is part of the bounded queue allocation. Use
        // it before growing logical length; this keeps the hot route path
        // allocation-free even if compaction has not reached its threshold.
        if (buffers.queue.items.len == buffers.queue.capacity and
            buffers.queue_head != 0)
        {
            self.compactDeliveryQueue();
        }
        std.debug.assert(buffers.queue.items.len < buffers.queue.capacity);
        buffers.queue.appendAssumeCapacity(delivery);
    }

    fn tailDeliveryForPublication(
        self: *ClientSlot,
        publication: *Publication,
    ) ?*Delivery {
        if (self.queuedCount() == 0) return null;
        const buffers = self.buffers.?;
        const delivery = &buffers.queue.items[buffers.queue.items.len - 1];
        return if (delivery.publication == publication) delivery else null;
    }

    fn removePublication(self: *ClientSlot, publication: *Publication) usize {
        const buffers = self.buffers orelse return 0;
        var removed: usize = 0;
        var index = buffers.queue_head;
        while (index < buffers.queue.items.len) {
            if (buffers.queue.items[index].publication != publication) {
                index += 1;
                continue;
            }
            var delivery = buffers.queue.orderedRemove(index);
            delivery.deinit();
            removed += 1;
        }
        if (buffers.queue_head == buffers.queue.items.len) {
            buffers.queue.clearRetainingCapacity();
            buffers.queue_head = 0;
        }
        return removed;
    }
};

test "MQTT broker capacity slots keep connection state out of line" {
    try std.testing.expect(
        @sizeOf(ClientSlot) <= @sizeOf(runtime.Connection) / 2,
    );
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 96), @sizeOf(ClientSlot));
        const buffers_size: usize = switch (builtin.mode) {
            .Debug, .ReleaseSafe => 152,
            .ReleaseFast, .ReleaseSmall => 144,
        };
        try std.testing.expectEqual(buffers_size, @sizeOf(ClientBuffers));
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(ClientSlot, "state")),
        );
        try std.testing.expectEqual(
            @sizeOf(?[*]u8),
            @sizeOf(@FieldType(ClientSlot, "assigned_client_id_ptr")),
        );
        try std.testing.expectEqual(
            @sizeOf(?[*]const u8),
            @sizeOf(@FieldType(ClientSlot, "username_ptr")),
        );
        try std.testing.expectEqual(
            @as(usize, 64),
            @bitSizeOf(@FieldType(ClientSlot, "state")),
        );
    }
    try std.testing.expectEqual(
        @sizeOf(?*ListenerAccessControlHandler),
        @sizeOf(@FieldType(ClientSlot, "listener_access_control")),
    );
}

test "MQTT broker allocates client buffers on demand" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.buffers == null);

    var descriptor_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        slot.ensureDeliveryCapacity(descriptor_failure.allocator(), 4),
    );
    try std.testing.expect(slot.buffers == null);

    var queue_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        slot.ensureDeliveryCapacity(queue_failure.allocator(), 4),
    );
    try std.testing.expect(slot.buffers == null);

    try slot.ensureDeliveryCapacity(std.testing.allocator, 4);
    try std.testing.expect(slot.buffers.?.queue.capacity >= 4);
    slot.clearBuffers(std.testing.allocator);
    try std.testing.expect(slot.buffers == null);
}

test "MQTT broker allocates assigned client identifiers on demand" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
    });
    defer broker.deinit();

    const slot_index = try broker.claimSlot();
    const slot = &broker.slots[slot_index];
    try std.testing.expect(slot.assignedClientId() == null);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    broker.allocator = failing.allocator();
    broker.state_mutex.lockUncancelable(io);
    const failed_assignment = broker.assignClientIdLocked(slot, "test-");
    broker.state_mutex.unlock(io);
    broker.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, failed_assignment);
    try std.testing.expect(slot.assignedClientId() == null);
    try std.testing.expectEqual(@as(u7, 0), slot.state.assigned_client_id_len);

    broker.state_mutex.lockUncancelable(io);
    const assigned = broker.assignClientIdLocked(
        slot,
        "test-",
    ) catch |err| {
        broker.state_mutex.unlock(io);
        return err;
    };
    try std.testing.expectEqualStrings(assigned, slot.assignedClientId().?);
    try std.testing.expect(std.mem.startsWith(u8, assigned, "test-"));
    broker.state_mutex.unlock(io);

    broker.abortRegistration(slot_index, 0, false);
    try std.testing.expect(slot.assignedClientId() == null);
    broker.releaseClaimedSlot(slot_index);
}

test "MQTT broker stores borrowed username with wire length" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.username() == null);

    var bytes = [_]u8{ 'u', 's', 'e', 'r' };
    slot.setUsername(&bytes);
    try std.testing.expectEqualStrings("user", slot.username().?);
    bytes[0] = 'U';
    try std.testing.expectEqualStrings("User", slot.username().?);

    slot.setUsername("");
    try std.testing.expectEqualStrings("", slot.username().?);
    slot.setUsername(null);
    try std.testing.expect(slot.username() == null);
    try std.testing.expectEqual(@as(u16, 0), slot.state.username_len);
}

test "MQTT broker stores optional Session and Will handles without tags" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.sessionHandle() == null);
    try std.testing.expect(slot.willHandle() == null);

    const session_handle = session_mod.Handle{
        .index = 7,
        .generation = 11,
    };
    const will_handle = will_mod.Handle{
        .index = 13,
        .generation = 17,
    };
    slot.setSessionHandle(session_handle);
    slot.setWillHandle(will_handle);
    try std.testing.expectEqualDeep(session_handle, slot.sessionHandle().?);
    try std.testing.expectEqualDeep(will_handle, slot.willHandle().?);

    slot.setSessionHandle(null);
    slot.setWillHandle(null);
    try std.testing.expect(slot.sessionHandle() == null);
    try std.testing.expect(slot.willHandle() == null);
}

test "MQTT broker lazily reserves Will publisher index" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(
        std.testing.allocator,
        threaded.io(),
        .{ .limits = .{ .max_connections = 2 } },
    );
    defer broker.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        broker.will_publishers.capacity(),
    );
}

test "MQTT ACK flush lock handoff excludes live persistence backends" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(
        allocator,
        io,
        .{ .limits = .{ .max_connections = 1 } },
    );
    defer broker.deinit();

    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expect(
            broker.canCoalesceAcknowledgedSessionFlushLocked(),
        );
        broker.persistent_change_autosave_enabled.store(true, .release);
        try std.testing.expect(
            !broker.canCoalesceAcknowledgedSessionFlushLocked(),
        );
        broker.persistent_change_autosave_enabled.store(false, .release);
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "ack-handoff.log", .{});

    broker.state_mutex.lockUncancelable(io);
    defer broker.state_mutex.unlock(io);
    try std.testing.expect(
        !broker.canCoalesceAcknowledgedSessionFlushLocked(),
    );
}

test "MQTT broker Will index allocation failure precedes Session mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var broker = try Broker.init(failing.allocator(), io, .{
        .limits = .{ .max_connections = 1 },
        .session = .{ .max_sessions = 1 },
    });
    defer broker.deinit();

    const slot_index = try broker.claimSlot();
    defer broker.releaseClaimedSlot(slot_index);
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
                .client_id = "will-allocation-failure",
                .will = .{
                    .topic = "will/allocation-failure",
                    .payload = "offline",
                    .qos = .at_least_once,
                    .retain = false,
                    .properties = &.{},
                },
            },
            null,
            null,
            broker.options.auto_client_id_prefix,
            &progress,
        ),
    );
    failing.fail_index = std.math.maxInt(usize);

    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        broker.will_publishers.capacity(),
    );
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expect(broker.sessions.find(
        "will-allocation-failure",
        std.Io.Clock.awake.now(io),
    ) == null);
    try std.testing.expect(broker.slots[slot_index].sessionHandle() == null);
    try std.testing.expect(broker.slots[slot_index].willHandle() == null);
}

test "MQTT broker stores optional retained source identity without tag" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.retainedSourceId() == null);

    slot.setRetainedSourceId(0);
    try std.testing.expectEqual(@as(?u64, 0), slot.retainedSourceId());
    slot.setRetainedSourceId(std.math.maxInt(u64));
    try std.testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        slot.retainedSourceId(),
    );

    slot.setRetainedSourceId(null);
    try std.testing.expect(slot.retainedSourceId() == null);
}

test "MQTT broker allocates listener ACL metadata on demand" {
    var slot: ClientSlot = .{};
    var marker: u8 = 0;
    const access_control = ListenerAccessControlHandler{
        .context = &marker,
    };

    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try slot.setListenerAccessControl(failing.allocator(), null);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(slot.accessControl() == null);
    try std.testing.expectError(
        error.OutOfMemory,
        slot.setListenerAccessControl(
            failing.allocator(),
            access_control,
        ),
    );
    try std.testing.expect(slot.accessControl() == null);

    try slot.setListenerAccessControl(
        std.testing.allocator,
        access_control,
    );
    try std.testing.expectEqual(
        access_control.context,
        slot.accessControl().?.context,
    );
    slot.clearListenerAccessControl(std.testing.allocator);
    try std.testing.expect(slot.accessControl() == null);
}

test "MQTT broker detects configured delivery authorization callbacks" {
    const Callbacks = struct {
        fn publish(
            context: *anyopaque,
            connect: mqtt.Connect,
            message: mqtt.Publish,
        ) bool {
            _ = context;
            _ = connect;
            _ = message;
            return true;
        }

        fn subscribe(
            context: *anyopaque,
            connect: mqtt.Connect,
            subscription: mqtt.Subscription,
        ) bool {
            _ = context;
            _ = connect;
            _ = subscription;
            return true;
        }

        fn delivery(
            context: *anyopaque,
            authorization: DeliveryAuthorization,
        ) bool {
            _ = context;
            _ = authorization;
            return true;
        }
    };
    var context: u8 = 0;
    const global_without_delivery = AccessControlHandler{
        .context = &context,
        .authorize_publish = Callbacks.publish,
        .authorize_subscribe = Callbacks.subscribe,
    };
    const global_with_delivery = AccessControlHandler{
        .context = &context,
        .authorize_publish = Callbacks.publish,
        .authorize_subscribe = Callbacks.subscribe,
        .authorize_delivery = Callbacks.delivery,
    };
    const listener_without_delivery = ListenerAccessControlHandler{
        .context = &context,
    };
    const listener_with_delivery = ListenerAccessControlHandler{
        .context = &context,
        .authorize_delivery = Callbacks.delivery,
    };

    try std.testing.expect(!(DeliveryAuthorizationChain{}).configured());
    try std.testing.expect(!(DeliveryAuthorizationChain{
        .broker = &global_without_delivery,
        .listener = &listener_without_delivery,
    }).configured());
    try std.testing.expect((DeliveryAuthorizationChain{
        .broker = &global_with_delivery,
    }).configured());
    try std.testing.expect((DeliveryAuthorizationChain{
        .listener = &listener_with_delivery,
    }).configured());
}

test "MQTT retained replay reuses property scratch" {
    const allocator = std.testing.allocator;
    const source = [_]mqtt.Property{
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 60,
        } },
        .{ .utf8 = .{
            .id = .content_type,
            .value = "application/octet-stream",
        } },
    };
    var scratch: std.ArrayList(mqtt.Property) = .empty;
    defer scratch.deinit(allocator);

    try prepareRetainedDeliveryProperties(
        &scratch,
        allocator,
        &source,
        59,
    );
    const allocation = scratch.allocatedSlice().ptr;
    try std.testing.expectEqual(@as(?u32, 59), mqtt.messageExpiryInterval(scratch.items));

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try prepareRetainedDeliveryProperties(
        &scratch,
        failing.allocator(),
        &source,
        58,
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(allocation, scratch.allocatedSlice().ptr);
    try std.testing.expectEqual(@as(?u32, 58), mqtt.messageExpiryInterval(scratch.items));

    try prepareRetainedDeliveryProperties(
        &scratch,
        failing.allocator(),
        &source,
        null,
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), scratch.items.len);
    try std.testing.expect(scratch.items[0] == .utf8);
}

fn shouldScheduleTransientDelivery(
    session_persistent: bool,
    qos: mqtt.QoS,
    delivery_count: usize,
    queued_count: usize,
    high_watermark: usize,
    same_connection: bool,
) bool {
    std.debug.assert(high_watermark != 0);
    return !same_connection and !session_persistent and qos != .at_most_once and
        delivery_count > 1 and
        queued_count < high_watermark;
}

fn shouldScheduleSessionDelivery(
    delivery_count: usize,
    queued_count: usize,
    high_watermark: usize,
    same_connection: bool,
    writer_pool_active: bool,
) bool {
    std.debug.assert(high_watermark != 0);
    return !same_connection and writer_pool_active and delivery_count > 1 and
        queued_count < high_watermark;
}

fn networkDeliveryMode(
    upgrade_outgoing_qos: bool,
    source_qos: mqtt.QoS,
) NetworkDeliveryMode {
    return if (!upgrade_outgoing_qos and source_qos == .at_most_once)
        .synchronous
    else
        .asynchronous;
}

fn subscriptionsNeedDeliveryWriter(
    local_maximum_qos: mqtt.QoS,
    subscriptions: []const mqtt.Subscription,
) bool {
    if (local_maximum_qos == .at_most_once) return false;
    for (subscriptions) |subscription| {
        if (subscription.qos != .at_most_once) return true;
    }
    return false;
}

test "MQTT transient delivery scheduling respects persistence and watermark" {
    const limit = transient_delivery_async_high_watermark;
    try std.testing.expect(shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        limit - 1,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        limit,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .at_most_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(shouldScheduleTransientDelivery(
        false,
        .at_least_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        true,
        .exactly_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        0,
        limit,
        true,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .at_least_once,
        1,
        0,
        limit,
        false,
    ));
    try std.testing.expect(shouldScheduleSessionDelivery(
        2,
        1,
        limit,
        false,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        2,
        limit,
        limit,
        false,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        1,
        0,
        limit,
        false,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        2,
        0,
        limit,
        true,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        2,
        0,
        limit,
        false,
        false,
    ));

    try std.testing.expectEqual(
        NetworkDeliveryMode.synchronous,
        networkDeliveryMode(false, .at_most_once),
    );
    try std.testing.expectEqual(
        NetworkDeliveryMode.asynchronous,
        networkDeliveryMode(false, .at_least_once),
    );
    try std.testing.expectEqual(
        NetworkDeliveryMode.asynchronous,
        networkDeliveryMode(false, .exactly_once),
    );
    try std.testing.expectEqual(
        NetworkDeliveryMode.asynchronous,
        networkDeliveryMode(true, .at_most_once),
    );

    const subscriptions = [_]mqtt.Subscription{
        .{ .topic_filter = "qos/0", .qos = .at_most_once },
        .{ .topic_filter = "qos/1", .qos = .at_least_once },
    };
    try std.testing.expect(!subscriptionsNeedDeliveryWriter(
        .at_most_once,
        &subscriptions,
    ));
    try std.testing.expect(subscriptionsNeedDeliveryWriter(
        .at_least_once,
        &subscriptions,
    ));
    try std.testing.expect(!subscriptionsNeedDeliveryWriter(
        .exactly_once,
        subscriptions[0..1],
    ));
}

test "MQTT live overlap merge uses the current queue tail" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    const buffers = try slot.ensureBuffers(allocator);
    defer {
        // This test compares pointer identity only; its stack Publications do
        // not own reference-counted allocations and must not be released.
        buffers.queue.clearRetainingCapacity();
        buffers.queue_head = 0;
        slot.clearBuffers(allocator);
    }
    try buffers.queue.ensureTotalCapacityPrecise(allocator, 4);

    var prior_publication: Publication = undefined;
    var current_publication: Publication = undefined;
    var later_publication: Publication = undefined;
    slot.appendDeliveryAssumeCapacity(.{
        .publication = &prior_publication,
        .qos = .at_most_once,
        .retain = false,
    });
    try std.testing.expect(
        slot.tailDeliveryForPublication(&current_publication) == null,
    );

    slot.appendDeliveryAssumeCapacity(.{
        .publication = &current_publication,
        .qos = .at_least_once,
        .retain = false,
    });
    _ = slot.popDelivery();
    const current = slot.tailDeliveryForPublication(
        &current_publication,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(mqtt.QoS.at_least_once, current.qos);

    slot.appendDeliveryAssumeCapacity(.{
        .publication = &later_publication,
        .qos = .at_most_once,
        .retain = false,
    });
    try std.testing.expect(
        slot.tailDeliveryForPublication(&current_publication) == null,
    );
}

test "durable Session write scratch retains only bounded packets" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(allocator);
    const buffers = try slot.ensureBuffers(allocator);

    try buffers.session_write_scratch.ensureTotalCapacityPrecise(
        allocator,
        1024,
    );
    const retained = buffers.session_write_scratch.allocatedSlice().ptr;
    slot.releaseOversizedSessionScratch(allocator);
    try std.testing.expectEqual(
        retained,
        buffers.session_write_scratch.allocatedSlice().ptr,
    );

    try buffers.session_write_scratch.ensureTotalCapacityPrecise(
        allocator,
        session_write_scratch_retain_limit + 1,
    );
    slot.releaseOversizedSessionScratch(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.session_write_scratch.capacity,
    );

    try buffers.session_property_scratch.ensureTotalCapacityPrecise(
        allocator,
        session_property_scratch_retain_capacity + 1,
    );
    slot.releaseOversizedSessionScratch(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.session_property_scratch.capacity,
    );
}

/// Point-in-time broker gauges. State-backed fields are collected under the
/// same lock as routing and Session transitions, so their cross-field
/// invariants describe one coherent instant. Wire and PUBLISH counters are
/// lock-free, independently sampled, and include each complete operation.
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

pub const ListenerAdmissionSnapshot = struct {
    allow_zero_length_client_id: bool,
    retain_available: bool = true,
    maximum_qos: ?mqtt.QoS = null,
    maximum_keep_alive_seconds: ?u16 = null,
    topic_alias_maximum: u16 = 16,
    max_outgoing_topic_aliases: u16 = std.math.maxInt(u16),
    accepted_protocol_versions: mqtt.AcceptedProtocolVersions = .{},
    prefix_storage: [client_id_mod.max_prefix_len]u8 = undefined,
    prefix_len: u6,

    pub fn init(
        allow_zero_length_client_id: bool,
        prefix: []const u8,
    ) Error!ListenerAdmissionSnapshot {
        return initWithCapabilities(
            allow_zero_length_client_id,
            prefix,
            null,
            null,
            16,
            std.math.maxInt(u16),
            .{},
        );
    }

    pub fn initWithCapabilities(
        allow_zero_length_client_id: bool,
        prefix: []const u8,
        maximum_qos: ?mqtt.QoS,
        maximum_keep_alive_seconds: ?u16,
        topic_alias_maximum: u16,
        max_outgoing_topic_aliases: u16,
        accepted_protocol_versions: mqtt.AcceptedProtocolVersions,
    ) Error!ListenerAdmissionSnapshot {
        try validateAutoClientIdPrefix(prefix);
        if (maximum_keep_alive_seconds == 0 or
            !accepted_protocol_versions.any())
        {
            return error.InvalidProperty;
        }
        var result = ListenerAdmissionSnapshot{
            .allow_zero_length_client_id = allow_zero_length_client_id,
            .maximum_qos = maximum_qos,
            .maximum_keep_alive_seconds = maximum_keep_alive_seconds,
            .topic_alias_maximum = topic_alias_maximum,
            .max_outgoing_topic_aliases = max_outgoing_topic_aliases,
            .accepted_protocol_versions = accepted_protocol_versions,
            .prefix_len = @intCast(prefix.len),
        };
        @memcpy(result.prefix_storage[0..prefix.len], prefix);
        return result;
    }

    pub fn autoClientIdPrefix(
        self: *const ListenerAdmissionSnapshot,
    ) []const u8 {
        std.debug.assert(self.prefix_len <= self.prefix_storage.len);
        return self.prefix_storage[0..self.prefix_len];
    }
};

pub const ListenerAdmissionProvider = struct {
    context: *anyopaque,
    snapshot: *const fn (context: *anyopaque) ListenerAdmissionSnapshot,
};

pub const Listener = struct {
    source: runtime.PendingSource,
    namespace: listener_namespace.Namespace = .{},
    /// Optional prefix for Client Identifiers assigned on this listener.
    /// Null inherits `Broker.Options.auto_client_id_prefix`; the bytes are
    /// borrowed only for the duration of `serveListeners`.
    auto_client_id_prefix: ?[]const u8 = null,
    /// Null inherits `Broker.Options.accept`; an override makes CONNECT and
    /// advertised capabilities listener-specific. Borrowed property strings
    /// must remain alive throughout `serveListeners`.
    accept: ?runtime.AcceptOptions = null,
    /// Optional move-stable provider for admission fields that can change while
    /// the listener remains bound. One owned snapshot is taken after CONNECT
    /// parsing and before any Session, Will, or route mutation.
    admission_policy: ?ListenerAdmissionProvider = null,
    /// Additional listener-local CONNECT authorization. Callback state is
    /// borrowed and must remain alive throughout `serveListeners`.
    authorization: ListenerAuthorization = .{},
    /// Optional simultaneous admitted-client limit for this listener. The
    /// finite `connection_count` remains the number of accept attempts.
    max_connections: ?usize = null,
    /// Endpoints with the same group share `max_connections`. The identifier
    /// must be a valid index whose root endpoint names itself, and every group
    /// member must configure the same limit. Null gives this endpoint an
    /// independent cap.
    capacity_group: ?usize = null,
    /// Finite accept count for deterministic process/test teardown.
    connection_count: usize,
};

/// One endpoint in a long-running heterogeneous listener service.
///
/// Multiple workers permit TLS and HTTP Upgrade handshakes and established
/// connections to overlap. The Broker's `max_connections` independently caps
/// admitted clients across all workers; an excess peer is closed and its
/// worker accepts another client after the next disconnect or refusal.
pub const ListenerEndpoint = struct {
    source: runtime.PendingSource,
    namespace: listener_namespace.Namespace = .{},
    /// Null inherits `Broker.Options.auto_client_id_prefix`; borrowed for the
    /// duration of `serveListenersUntil`.
    auto_client_id_prefix: ?[]const u8 = null,
    /// Null inherits `Broker.Options.accept`; borrowed values must remain alive
    /// throughout `serveListenersUntil`.
    accept: ?runtime.AcceptOptions = null,
    admission_policy: ?ListenerAdmissionProvider = null,
    /// Additional listener-local CONNECT authorization. Callback state is
    /// borrowed and must remain alive throughout `serveListenersUntil`.
    authorization: ListenerAuthorization = .{},
    /// Optional simultaneous admitted-client limit for this listener. Use an
    /// `accept_concurrency` greater than this value to actively close excess
    /// peers instead of leaving them queued in the transport backlog.
    max_connections: ?usize = null,
    /// Endpoints with the same group share `max_connections`. The identifier
    /// must be a valid index whose root endpoint names itself, and every group
    /// member must configure the same limit. Null gives this endpoint an
    /// independent cap.
    capacity_group: ?usize = null,
    accept_concurrency: usize = 1,
};

fn validateCapacityGroup(
    comptime ListenerType: type,
    listeners: []const ListenerType,
    listener: ListenerType,
    listener_index: usize,
) error{InvalidProperty}!void {
    const group = listener.capacity_group orelse return;
    if (group >= listeners.len or
        listeners[group].capacity_group != group or
        listener.max_connections == null)
    {
        return error.InvalidProperty;
    }
    for (listeners[0..listener_index]) |previous| {
        if (previous.capacity_group == group and
            previous.max_connections != listener.max_connections)
        {
            return error.InvalidProperty;
        }
    }
}

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
    runtime_delivery_snapshot: runtime_policy_mod.Snapshot,
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
    local_consumer_routes: std.AutoHashMapUnmanaged(
        u64,
        local_consumer_mod.Registration,
    ) = .empty,
    will_publishers: will_mod.PublisherMap = .empty,
    slots: []ClientSlot,
    session_delivery_writers: session_writer.Pool,
    commit_log: ?commit_log_mod.Log = null,
    /// A rollback image blocked by another provisional CONNECT or a journal
    /// failure still needs a final append. Protected by persistence_mutex.
    registration_rollback_commit_pending: bool = false,
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
    persistent_change_autosave_enabled: std.atomic.Value(bool) = .init(false),
    /// Cumulative lifecycle counters protected by `state_mutex`. The traffic
    /// and PUBLISH counters below are lock-free. All are process-local like
    /// Mosquitto's `$SYS` counters and are not restored from snapshots.
    maximum_active_connections: usize = 0,
    connections_received: u64 = 0,
    expired_sessions: usize = 0,
    traffic: runtime.TrafficCounters = .{},
    publish_counters: publish_counters.Counters = .{},
    started_at_ns: i96,
    load_tracker: load_metrics.Tracker = .{},
    next_retained_expiry_ns: ?i96 = null,
    next_system_stats_ns: ?i96 = null,
    /// Prevent an in-flight `$SYS` publication from overwriting a deadline
    /// installed by a concurrent runtime policy update.
    system_stats_schedule_generation: u64 = 0,

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
            std.math.cast(u32, options.will.max_wills) == null)
        {
            return error.InvalidProperty;
        }
        if (!options.accept.accepted_protocol_versions.any()) {
            return error.InvalidProperty;
        }
        try validateAutoClientIdPrefix(options.auto_client_id_prefix);
        try validateClientIdPrefix(options.client_id_prefix);
        try (RuntimeSchedulingPolicy{
            .retained_expiry_interval = options.retained_expiry_interval,
            .system_stats_interval = options.system_stats_interval,
        }).validate();
        if (options.persistent_change_autosave) |autosave| {
            if (autosave.sub_path.len == 0 or autosave.max_changes == 0) {
                return error.InvalidProperty;
            }
        }
        const initial_delivery_policy = RuntimeDeliveryPolicy{
            .max_payload_size = options.limits.max_payload_size,
            .queue_qos0_messages = options.queue_qos0_messages,
            .upgrade_outgoing_qos = options.upgrade_outgoing_qos,
            .check_retain_source = options.check_retain_source,
            .persistent_session_expiry_seconds = options.persistent_session_expiry_seconds,
        };
        try initial_delivery_policy.validate();
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
        const required_client_id_prefix = if (options.client_id_prefix.len == 0)
            &.{}
        else
            try allocator.dupe(u8, options.client_id_prefix);
        errdefer if (required_client_id_prefix.len != 0) {
            allocator.free(required_client_id_prefix);
        };
        const response_information = if (options.accept.response_information) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (response_information) |value| allocator.free(value);
        var owned_options = options;
        owned_options.auto_client_id_prefix = auto_client_id_prefix;
        owned_options.client_id_prefix = required_client_id_prefix;
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
        var session_delivery_writers = try session_writer.Pool.init(
            allocator,
            slots.len,
        );
        errdefer session_delivery_writers.deinit(allocator);
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
        const started_at_ns = std.Io.Clock.awake.now(io).nanoseconds;
        const broker: Broker = .{
            .allocator = allocator,
            .io = io,
            .options = owned_options,
            .runtime_delivery_snapshot = .init(initial_delivery_policy),
            .router = router,
            .pending_qos2 = pending_qos2,
            .bridge_qos2 = bridge_qos2,
            .retained = retained,
            .sessions = sessions,
            .wills = wills,
            .session_owners = session_owners,
            .will_publishers = will_publishers,
            .slots = slots,
            .session_delivery_writers = session_delivery_writers,
            .persistent_change_autosave_enabled = .init(
                if (options.persistent_change_autosave) |autosave|
                    autosave.enabled
                else
                    false,
            ),
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
        self.session_delivery_writers.deinit(self.allocator);
        for (self.slots) |*slot| {
            slot.clearBuffers(self.allocator);
            slot.clearAssignedClientId(self.allocator);
            slot.clearListenerAccessControl(self.allocator);
            if (slot.connection) |connection| {
                connection.close();
                self.allocator.destroy(connection);
            }
        }
        self.allocator.free(self.slots);
        self.allocator.free(self.options.auto_client_id_prefix);
        if (self.options.client_id_prefix.len != 0) {
            self.allocator.free(@constCast(self.options.client_id_prefix));
        }
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
        self.local_consumer_routes.deinit(self.allocator);
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
            if (slot.connection) |connection| {
                connection.shutdown() catch {};
            }
        }
    }

    /// Reauthorize every established connection and administratively close
    /// the ones rejected by `handler`. MQTT 5 peers receive reason 0x98 before
    /// transport shutdown; MQTT 3.1.1 has no server DISCONNECT packet. The
    /// close is graceful from the broker's perspective, so it cancels rather
    /// than publishes the client's Will while preserving durable Session
    /// state. Returns the number of connections selected for disconnection.
    pub fn disconnectUnauthorizedConnections(
        self: *Broker,
        handler: ConnectionReauthorizationHandler,
    ) usize {
        var disconnected: usize = 0;
        for (self.slots) |*slot| {
            slot.writer_mutex.lockUncancelable(self.io);
            self.state_mutex.lockUncancelable(self.io);
            const connection = if (slot.state.active and
                slot.connection != null and
                !slot.state.graceful_disconnect and
                !slot.state.administrative_disconnect and
                !handler.still_authorized(handler.context, .{
                    .username = slot.username(),
                    .listener_id = slot.retainedSourceId(),
                }))
            blk: {
                slot.state.administrative_disconnect = true;
                break :blk slot.connection;
            } else null;
            self.state_mutex.unlock(self.io);
            if (connection) |active| {
                // Commit Session detachment and Will cancellation before the
                // peer can observe the administrative close. If persistence
                // fails, unregister sees `administrative_disconnect` and
                // retries the same idempotent cleanup after transport shutdown.
                self.handleDisconnect(slot, .{}) catch {};
                if (active.protocol == .v5) {
                    active.writeDisconnectWithProperties(0x98, &.{}) catch {};
                }
                active.shutdown() catch {};
                disconnected += 1;
            }
            slot.writer_mutex.unlock(self.io);
        }
        return disconnected;
    }

    /// Return a coherent, allocation-free snapshot suitable for metrics,
    /// health checks, and a future `$SYS` publisher.
    pub fn stats(self: *Broker) Stats {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.statsLocked();
    }

    /// Return one coherent snapshot of reloadable delivery and Session policy.
    pub fn runtimeDeliveryPolicy(self: *const Broker) RuntimeDeliveryPolicy {
        return self.runtime_delivery_snapshot.load();
    }

    /// Atomically apply delivery and persistent-Session limits to subsequent
    /// policy decisions without disturbing active Network Connections.
    pub fn setRuntimeDeliveryPolicy(
        self: *Broker,
        policy: RuntimeDeliveryPolicy,
    ) error{InvalidProperty}!void {
        try policy.validate();
        self.state_mutex.lockUncancelable(self.io);
        self.options.limits.max_payload_size = policy.max_payload_size;
        self.options.queue_qos0_messages = policy.queue_qos0_messages;
        self.options.upgrade_outgoing_qos = policy.upgrade_outgoing_qos;
        self.options.check_retain_source = policy.check_retain_source;
        self.options.persistent_session_expiry_seconds =
            policy.persistent_session_expiry_seconds;
        self.runtime_delivery_snapshot.store(policy);
        self.state_mutex.unlock(self.io);
    }

    /// Validate and own a required Client ID prefix before an atomic reload
    /// reaches its no-fail commit phase.
    pub fn prepareRequiredClientIdPrefix(
        self: *Broker,
        prefix: []const u8,
    ) Error!PreparedRequiredClientIdPrefix {
        try validateClientIdPrefix(prefix);
        return .{
            .allocator = self.allocator,
            .bytes = if (prefix.len == 0)
                &.{}
            else
                try self.allocator.dupe(u8, prefix),
        };
    }

    /// Commit a prepared prefix without allocation. Readers compare under the
    /// same state mutex, so the retired allocation can be released immediately
    /// after the swap without a dangling CONNECT view.
    pub fn commitRequiredClientIdPrefix(
        self: *Broker,
        prepared: *PreparedRequiredClientIdPrefix,
    ) void {
        std.debug.assert(prepared.allocator.ptr == self.allocator.ptr);
        std.debug.assert(prepared.allocator.vtable == self.allocator.vtable);
        const replacement = prepared.take();
        self.state_mutex.lockUncancelable(self.io);
        const retired = self.options.client_id_prefix;
        self.options.client_id_prefix = replacement;
        self.state_mutex.unlock(self.io);
        if (retired.len != 0) self.allocator.free(@constCast(retired));
    }

    /// Convenience wrapper for callers that do not need a larger reload
    /// transaction. Allocation failure leaves the active prefix unchanged.
    pub fn setRequiredClientIdPrefix(
        self: *Broker,
        prefix: []const u8,
    ) Error!void {
        var prepared = try self.prepareRequiredClientIdPrefix(prefix);
        defer prepared.deinit();
        self.commitRequiredClientIdPrefix(&prepared);
    }

    /// Return an owned diagnostic snapshot that remains valid across reloads.
    pub fn requiredClientIdPrefixAlloc(
        self: *Broker,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return allocator.dupe(u8, self.options.client_id_prefix);
    }

    /// Return one coherent snapshot of the currently active periodic policy.
    pub fn runtimeSchedulingPolicy(self: *Broker) RuntimeSchedulingPolicy {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return .{
            .retained_expiry_interval = self.options.retained_expiry_interval,
            .system_stats_interval = self.options.system_stats_interval,
        };
    }

    /// Atomically enable, disable, or retune broker-owned periodic work.
    ///
    /// Changed intervals start a fresh period at commit time. The deadline
    /// driver is notified after the state lock is released so newly enabled or
    /// shortened intervals take effect without waiting for an older timeout.
    pub fn setRuntimeSchedulingPolicy(
        self: *Broker,
        policy: RuntimeSchedulingPolicy,
    ) error{InvalidProperty}!void {
        try policy.validate();

        self.state_mutex.lockUncancelable(self.io);
        const retained_changed = !deadline_driver_mod.intervalsEqual(
            self.options.retained_expiry_interval,
            policy.retained_expiry_interval,
        );
        const system_stats_changed = !deadline_driver_mod.intervalsEqual(
            self.options.system_stats_interval,
            policy.system_stats_interval,
        );
        const retained_deadline_missing =
            policy.retained_expiry_interval != null and
            self.next_retained_expiry_ns == null;
        const system_stats_deadline_missing =
            policy.system_stats_interval != null and
            self.next_system_stats_ns == null;
        const update_retained_deadline =
            retained_changed or retained_deadline_missing;
        const update_system_stats_deadline =
            system_stats_changed or system_stats_deadline_missing;
        if (!update_retained_deadline and !update_system_stats_deadline) {
            self.state_mutex.unlock(self.io);
            return;
        }

        const now = std.Io.Clock.awake.now(self.io);
        self.options.retained_expiry_interval =
            policy.retained_expiry_interval;
        self.options.system_stats_interval = policy.system_stats_interval;
        if (update_retained_deadline) {
            self.next_retained_expiry_ns = if (policy.retained_expiry_interval) |interval|
                now.addDuration(interval).nanoseconds
            else
                null;
        }
        if (update_system_stats_deadline) {
            self.next_system_stats_ns = if (policy.system_stats_interval) |interval|
                now.addDuration(interval).nanoseconds
            else
                null;
            self.system_stats_schedule_generation +%= 1;
        }
        self.state_mutex.unlock(self.io);
        self.deadline_driver.notify(self.io);
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

    /// Atomically enable, disable, or retune mutation-count autosave for the
    /// already-owned target. Enabling a threshold immediately services any
    /// durable change debt accumulated since the last snapshot of that target.
    pub fn setPersistentChangeAutosaveThreshold(
        self: *Broker,
        threshold: ?usize,
    ) Error!void {
        if (threshold == 0 or
            (threshold != null and
                self.options.persistent_change_autosave == null))
        {
            return error.InvalidProperty;
        }
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        if (threshold) |value| {
            self.options.persistent_change_autosave.?.max_changes = value;
            self.persistent_change_autosave_enabled.store(true, .release);
            self.autosavePersistentChangesIfNeededLocked();
        } else {
            self.persistent_change_autosave_enabled.store(false, .release);
        }
    }

    pub fn preparePersistentChangeAutosaveTarget(
        self: *Broker,
        options: ?ChangeAutosaveOptions,
    ) Error!PreparedChangeAutosaveTarget {
        if (options) |target| {
            if (target.sub_path.len == 0 or target.max_changes == 0) {
                return error.InvalidProperty;
            }
        }
        const owned_options: ?ChangeAutosaveOptions = if (options) |target| .{
            .dir = target.dir,
            .sub_path = try self.allocator.dupe(u8, target.sub_path),
            .max_changes = target.max_changes,
            .enabled = target.enabled,
        } else null;
        return .{
            .allocator = self.allocator,
            .options = owned_options,
        };
    }

    /// Swap the broker-managed snapshot destination while no autosave writer
    /// can observe a mixed target/threshold generation.
    pub fn commitPersistentChangeAutosaveTarget(
        self: *Broker,
        prepared: *PreparedChangeAutosaveTarget,
    ) void {
        std.debug.assert(prepared.allocator.ptr == self.allocator.ptr);
        std.debug.assert(prepared.allocator.vtable == self.allocator.vtable);
        const replacement = prepared.take();
        self.persistence_mutex.lockUncancelable(self.io);
        self.persistent_change_autosave_enabled.store(false, .release);
        const retired = self.options.persistent_change_autosave;
        self.options.persistent_change_autosave = replacement;
        self.persistent_change_autosave_enabled.store(
            if (replacement) |target| target.enabled else false,
            .release,
        );
        self.persistence_mutex.unlock(self.io);
        if (retired) |target| {
            self.allocator.free(@constCast(target.sub_path));
        }
    }

    pub fn persistentChangeAutosaveThreshold(self: *Broker) ?usize {
        if (!self.persistent_change_autosave_enabled.load(.acquire)) {
            return null;
        }
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        if (!self.persistent_change_autosave_enabled.load(.acquire)) {
            return null;
        }
        return self.options.persistent_change_autosave.?.max_changes;
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

    const local_consumer_api = local_consumer_mod.Operations(LocalConsumerContext);
    pub const openLocalConsumer = local_consumer_api.openLocalConsumer;
    pub const closeLocalConsumer = local_consumer_api.closeLocalConsumer;
    pub const pollLocalConsumer = local_consumer_api.pollLocalConsumer;
    pub const localConsumerPendingCount = local_consumer_api.localConsumerPendingCount;
    pub const acknowledgeLocalConsumer = local_consumer_api.acknowledgeLocalConsumer;
    pub const completeLocalConsumerQoS0 = local_consumer_api.completeLocalConsumerQoS0;
    pub const retryLocalConsumerEvent = local_consumer_api.retryLocalConsumerEvent;

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
        return self.publishLocalFromSource(null, publish);
    }

    /// Publish on behalf of a broker-local consumer while excluding its own
    /// No Local subscriptions. Bidirectional bridges use this to prevent a
    /// remotely received publication from immediately crossing back over the
    /// same bridge. The consumer must be active and owned by this Broker.
    pub fn publishLocalFromConsumer(
        self: *Broker,
        consumer: *const LocalConsumer,
        publish: mqtt.Publish,
    ) Error!void {
        return self.publishLocalFromSource(consumer, publish);
    }

    fn publishLocalFromSource(
        self: *Broker,
        consumer: ?*const LocalConsumer,
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
        const publisher_id = if (consumer) |source| blk: {
            if (!source.active) return error.LocalConsumerClosed;
            const registration = self.local_consumer_routes.get(
                source.route_id,
            ) orelse return error.LocalConsumerClosed;
            if (registration.session.index != source.session.index or
                registration.session.generation != source.session.generation)
            {
                return error.LocalConsumerClosed;
            }
            break :blk sessionSubscriberId(source.route_id);
        } else null;
        const plan = self.enqueuePublishLocked(
            false,
            publisher_id,
            publish,
            null,
            null,
            null,
            self.options.upgrade_outgoing_qos,
            std.Io.Clock.awake.now(self.io),
            &persistent_changed,
            null,
            null,
            null,
        ) catch |err| {
            return err;
        };
        defer plan.deinit(self.allocator);
        self.publish_counters.recordReceived(publish.payload.len);
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
        return self.releaseBridgeQoS2FromSource(key, null);
    }

    /// Release a durable bridge transaction while treating `consumer` as the
    /// publisher for No Local routing. The exclusion is resolved from the
    /// current local-consumer handle, so it remains correct when a bridge is
    /// recreated and resumes an upstream PUBREL.
    pub fn releaseBridgeQoS2FromConsumer(
        self: *Broker,
        key: BridgeQoS2Key,
        consumer: *const LocalConsumer,
    ) Error!BridgeQoS2Release {
        return self.releaseBridgeQoS2FromSource(key, consumer);
    }

    fn releaseBridgeQoS2FromSource(
        self: *Broker,
        key: BridgeQoS2Key,
        consumer: ?*const LocalConsumer,
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
        const publisher_id = if (consumer) |source| blk: {
            if (!source.active) {
                self.state_mutex.unlock(self.io);
                return error.LocalConsumerClosed;
            }
            const registration = self.local_consumer_routes.get(
                source.route_id,
            ) orelse {
                self.state_mutex.unlock(self.io);
                return error.LocalConsumerClosed;
            };
            if (registration.session.index != source.session.index or
                registration.session.generation != source.session.generation)
            {
                self.state_mutex.unlock(self.io);
                return error.LocalConsumerClosed;
            }
            break :blk sessionSubscriberId(source.route_id);
        } else null;
        const plan = self.enqueuePublishLocked(
            false,
            publisher_id,
            publish,
            null,
            null,
            null,
            self.options.upgrade_outgoing_qos,
            release_now,
            &persistent_changed,
            &publication_effect_committed,
            null,
            null,
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
        defer plan.deinit(self.allocator);
        if (!self.bridge_qos2.markReleased(key)) {
            self.state_mutex.unlock(self.io);
            return error.InvalidReleaseState;
        }
        self.publish_counters.recordReceived(released_payload_len);
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
            active_connections +|= @intFromBool(slot.state.active);
            live_queued_deliveries +|= slot.queuedCount();
        }
        const sessions = self.sessions.aggregateStats();
        var traffic = self.traffic.stats();
        for (self.slots) |slot| {
            if (slot.connection) |connection| {
                std.debug.assert(connection.traffic_sink_deferred);
                traffic.add(connection.trafficStats());
            }
        }
        const publish = self.publish_counters.snapshot();
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
            .publish_messages_received = publish.messages_received,
            .publish_payload_bytes_received = publish.payload_bytes_received,
            .publish_messages_dropped = publish.messages_dropped,
            .publish_messages_sent = publish.messages_sent,
            .publish_payload_bytes_sent = publish.payload_bytes_sent,
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
            plan.deinit(self.allocator);
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
                false,
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
                null,
                null,
                self.options.upgrade_outgoing_qos,
                std.Io.Clock.awake.now(self.io),
                null,
                null,
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
        const sequence = try log.append(encoded);
        self.registration_rollback_commit_pending = false;
        return sequence;
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
        self.registration_rollback_commit_pending = false;
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
        self.registration_rollback_commit_pending = false;
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
        if (!allow_provisional_registration) self.registration_rollback_commit_pending = false;
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

    /// Internal consumers run independently of listener registration. A
    /// provisional CONNECT cannot be serialized yet, but must not make an
    /// otherwise valid bridge ACK fail or discard its durability barrier.
    /// Wait outside both locks until admission attaches or rolls back; actual
    /// journal and allocation failures still propagate to the source owner.
    fn finalizeLocalConsumerChange(
        self: *Broker,
        append_commit: bool,
        changed: bool,
    ) Error!void {
        while (true) {
            self.finalizePersistentChange(append_commit, changed) catch |err| {
                if (err != error.SnapshotBusy) return err;
                try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
                continue;
            };
            return;
        }
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
        if (!self.persistent_change_autosave_enabled.load(.acquire)) return;
        self.persistence_mutex.lockUncancelable(self.io);
        defer self.persistence_mutex.unlock(self.io);
        self.autosavePersistentChangesIfNeededLocked();
    }

    fn autosavePersistentChangesIfNeededLocked(self: *Broker) void {
        if (!self.persistent_change_autosave_enabled.load(.acquire)) return;
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
                if (slot.state.active or slot.connection != null or
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
                slot.state.active and slot.connection == null and
                !slot.state.registration_aborted)
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
            if (slot.state.active) return error.SnapshotBusy;
        }
        if (self.router.subscriptionCount() != 0 or
            self.pending_qos2.count() != 0 or
            self.bridge_qos2.stats().entries != 0 or
            self.bridge_qos2.stats().bridges != 0 or
            self.session_owners.count() != 0 or
            self.local_consumer_routes.count() != 0 or
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
        accept_options.traffic_counters_deferred = true;
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
    /// connection slots are allocated atomically by the shared state mutex and
    /// excess peers are closed without terminating the finite service.
    pub fn serveListeners(
        self: *Broker,
        listeners: []const Listener,
    ) anyerror!void {
        var connection_count: usize = 0;
        for (listeners, 0..) |listener, listener_index| {
            _ = try listener_namespace.Namespace.init(
                listener.namespace.prefix,
            );
            try validateAutoClientIdPrefix(
                listener.auto_client_id_prefix orelse
                    self.options.auto_client_id_prefix,
            );
            if (listener.admission_policy) |provider| {
                const snapshot = provider.snapshot(provider.context);
                try validateListenerAdmissionSnapshot(snapshot);
            }
            if (!(listener.accept orelse self.options.accept)
                .accepted_protocol_versions.any())
            {
                return error.InvalidProperty;
            }
            if (listener.max_connections == 0) {
                return error.InvalidProperty;
            }
            try validateCapacityGroup(
                Listener,
                listeners,
                listener,
                listener_index,
            );
            connection_count = std.math.add(
                usize,
                connection_count,
                listener.connection_count,
            ) catch return error.BrokerFull;
        }
        var group: std.Io.Group = .init;
        var session_writer_group: std.Io.Group = .init;
        self.session_delivery_writers.begin(
            self.io,
            &session_writer_group,
            @min(shared_session_delivery_writer_count, self.slots.len),
            self,
            Broker.flushScheduledSessionSlotErased,
        );
        var session_writers_started = true;
        defer if (session_writers_started) {
            self.session_delivery_writers.stop(
                self.io,
            );
        };
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
                if (slot.connection) |connection| {
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
        const capacities = try self.allocator.alloc(
            ListenerCapacity,
            listeners.len,
        );
        defer self.allocator.free(capacities);
        for (listeners, capacities) |listener, *capacity| {
            capacity.* = .{
                .limit = listener.max_connections orelse
                    listener.connection_count,
            };
        }

        var next_result: usize = 0;
        for (listeners, 0..) |listener, listener_index| {
            const capacity_index = listener.capacity_group orelse
                listener_index;
            for (0..listener.connection_count) |_| {
                const result = &errors[next_result];
                next_result += 1;
                const accept_task = ListenerAcceptTask{
                    .broker = self,
                    .listener = self.listenerWithTraffic(listener),
                    .capacity = &capacities[capacity_index],
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
        self.session_delivery_writers.stop(self.io);
        session_writers_started = false;
        self.deadline_driver.stop(self.io);
        const deadline_result = deadline_future.await(self.io);
        stop_driver = false;
        if (deadline_result) |err| return err;
        // The last client can schedule an immediate Will and wake the driver
        // just as this finite server stops it. Complete every lifecycle action
        // already due at the worker-join boundary before reporting that serve
        // has finished; future delayed Wills remain scheduled.
        try self.processDueLifecycle(std.Io.Clock.awake.now(self.io));
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
        for (listeners, 0..) |listener, listener_index| {
            _ = try listener_namespace.Namespace.init(
                listener.namespace.prefix,
            );
            try validateAutoClientIdPrefix(
                listener.auto_client_id_prefix orelse
                    self.options.auto_client_id_prefix,
            );
            if (listener.admission_policy) |provider| {
                const snapshot = provider.snapshot(provider.context);
                try validateListenerAdmissionSnapshot(snapshot);
            }
            if (!(listener.accept orelse self.options.accept)
                .accepted_protocol_versions.any())
            {
                return error.InvalidProperty;
            }
            if (listener.accept_concurrency == 0) {
                return error.InvalidProperty;
            }
            if (listener.max_connections == 0) {
                return error.InvalidProperty;
            }
            try validateCapacityGroup(
                ListenerEndpoint,
                listeners,
                listener,
                listener_index,
            );
        }
        const capacities = try self.allocator.alloc(
            ListenerCapacity,
            listeners.len,
        );
        defer self.allocator.free(capacities);
        for (listeners, capacities) |listener, *capacity| {
            capacity.* = .{
                .limit = listener.max_connections orelse
                    listener.accept_concurrency,
            };
        }
        var group: std.Io.Group = .init;
        var supervisor = ListenerSupervisorState{
            .broker = self,
            .options = options,
        };
        var session_writer_group: std.Io.Group = .init;
        self.session_delivery_writers.begin(
            self.io,
            &session_writer_group,
            @min(shared_session_delivery_writer_count, self.slots.len),
            self,
            Broker.flushScheduledSessionSlotErased,
        );
        var session_writers_started = true;
        defer if (session_writers_started) {
            self.session_delivery_writers.stop(
                self.io,
            );
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
            const capacity_index = listener.capacity_group orelse
                listener_index;
            for (0..listener.accept_concurrency) |_| {
                try group.concurrent(
                    self.io,
                    ListenerSupervisorAcceptTask.run,
                    .{ListenerSupervisorAcceptTask{
                        .supervisor = &supervisor,
                        .listener = self.listenerEndpointWithTraffic(
                            listener,
                        ),
                        .capacity = &capacities[capacity_index],
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
        self.session_delivery_writers.stop(self.io);
        session_writers_started = false;
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
        accept_options.traffic_counters_deferred = true;
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
        accept_options.traffic_counters_deferred = true;
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
        return self.servePendingWithListenerPolicy(
            pending,
            namespace,
            accept_options,
            authorization,
            self.options.auto_client_id_prefix,
        );
    }

    fn servePendingWithListenerPolicy(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        namespace: listener_namespace.Namespace,
        accept_options: runtime.AcceptOptions,
        authorization: ListenerAuthorization,
        auto_client_id_prefix: []const u8,
    ) anyerror!void {
        try validateAutoClientIdPrefix(auto_client_id_prefix);
        pending.connection.attachDeferredTrafficCounters(&self.traffic);
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
            auto_client_id_prefix,
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
            if (!slot.state.active) {
                self.slots[index].state.active = true;
                self.slots[index].state.registration_aborted = false;
                self.connections_received +|= 1;
                return index;
            }
        }
        return error.BrokerFull;
    }

    fn releaseClaimedSlot(self: *Broker, slot_index: usize) void {
        self.state_mutex.lockUncancelable(self.io);
        const slot = &self.slots[slot_index];
        std.debug.assert(slot.state.active);
        std.debug.assert(slot.connection == null);
        slot.state.active = false;
        slot.state.registration_aborted = false;
        self.state_mutex.unlock(self.io);
        registration_persistence.settled(RegistrationPersistenceContext, self);
    }

    // Certificate parsing has a much larger stack frame than ordinary TCP
    // admission. Keep it off the long-lived per-client coroutine stack when
    // listener identity mapping is disabled.
    noinline fn applyListenerCertificateIdentity(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        authorization: ListenerAuthorization,
        pending_owned: *bool,
    ) Error!bool {
        var owned_username: ?[]u8 = null;
        defer if (owned_username) |username| {
            self.allocator.free(username);
        };
        const username: []const u8 = identity: {
            if (pending.connection.peerCertificates()) |chain| {
                if (chain.len == 0) {
                    try self.refuseUnauthorizedConnect(
                        pending,
                        pending_owned,
                    );
                    return false;
                }
                owned_username = (if (authorization.use_identity_as_username)
                    vail.x509.identity.commonNameAlloc(
                        self.allocator,
                        chain[0],
                    )
                else
                    vail.x509.identity.subjectNameAlloc(
                        self.allocator,
                        chain[0],
                    )) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        try self.refuseUnauthorizedConnect(
                            pending,
                            pending_owned,
                        );
                        return false;
                    },
                };
                break :identity owned_username.?;
            }
            if (authorization.use_identity_as_username) {
                if (pending.connection.authenticatedProxyCommonName()) |name| {
                    break :identity name;
                }
            }
            try self.refuseUnauthorizedConnect(pending, pending_owned);
            return false;
        };
        pending.connect.replaceUsername(
            self.allocator,
            username,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try self.refuseUnauthorizedConnect(
                    pending,
                    pending_owned,
                );
                return false;
            },
        };
        return true;
    }

    // Materializing an AcceptedClient is also comparatively large. Keeping
    // refusal-only storage in this cold helper lowers the successful
    // connection coroutine's retained stack high-water mark.
    noinline fn refuseResolvedConnect(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        options: runtime.AcceptOptions,
        pending_owned: *bool,
    ) Error!void {
        var refused = try pending.finish(options);
        pending_owned.* = false;
        refused.deinit(self.allocator);
    }

    noinline fn finishRegistration(
        self: *Broker,
        index: usize,
        pending: *runtime.PendingAcceptedClient,
        accept_options: runtime.AcceptOptions,
        registration: Registration,
        registration_progress: RegistrationProgress,
        pending_owned: *bool,
        result: *?anyerror,
    ) Error!ClientTask {
        var registration_needs_rollback = true;
        errdefer if (registration_needs_rollback) {
            self.abortRegistration(
                index,
                registration.subscriber_id,
                registration_progress.rollback_changed,
            );
            // The provisional record was synced before CONNACK. Append the
            // rollback even when it restores the original in-memory state.
            registration_persistence.rollback(
                RegistrationPersistenceContext,
                self,
                registration_progress.rollback_changed,
                true,
            );
        };
        // Reserve stable storage before sending a successful CONNACK. An
        // allocation failure can then roll registration back without first
        // telling the peer that its Session was accepted.
        const stored_connection = try self.allocator.create(
            runtime.Connection,
        );
        var stored_connection_owned = true;
        var stored_connection_initialized = false;
        errdefer if (stored_connection_owned) {
            if (stored_connection_initialized) stored_connection.close();
            self.allocator.destroy(stored_connection);
        };
        var accepted = try pending.finish(accept_options);
        pending_owned.* = false;
        var accepted_owns_connection = true;
        errdefer if (accepted_owns_connection) {
            accepted.deinit(self.allocator);
        };
        stored_connection.* = accepted.connection;
        accepted.connection = undefined;
        stored_connection_initialized = true;
        accepted_owns_connection = false;
        errdefer accepted.connect.deinit(self.allocator);
        if (registration.replaced_owner_id) |owner_id| {
            self.disconnectReplacedSessionOwner(owner_id);
        }
        self.attachConnection(
            index,
            registration.subscriber_id,
            stored_connection,
            registration.persistent_changed,
        );
        stored_connection_owned = false;
        registration_needs_rollback = false;
        // A threshold reached during the provisional CONNECT window was left
        // pending by SnapshotBusy. Attachment retries that snapshot and any
        // journal correction deferred by a concurrent CONNECT rollback.
        registration_persistence.settled(RegistrationPersistenceContext, self);
        errdefer self.unregister(
            index,
            registration.subscriber_id,
            null,
        ) catch {};
        try self.flushSlot(index, &self.slots[index]);
        const task = ClientTask{
            .broker = self,
            .slot_index = index,
            .subscriber_id = registration.subscriber_id,
            .connect = accepted.connect,
            .result = result,
        };
        accepted.connect = undefined;
        accepted.connection = undefined;
        return task;
    }

    fn preparePending(
        self: *Broker,
        index: usize,
        pending: *runtime.PendingAcceptedClient,
        namespace: @import("listener_namespace.zig").Namespace,
        listener_accept: runtime.AcceptOptions,
        listener_authorization: ListenerAuthorization,
        auto_client_id_prefix: []const u8,
        result: *?anyerror,
    ) Error!?ClientTask {
        var pending_owned = true;
        defer if (pending_owned) pending.deinit(self.allocator);
        pending.connection.attachDeferredTrafficCounters(&self.traffic);
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
            try self.refuseResolvedConnect(
                pending,
                accept_options,
                &pending_owned,
            );
            return null;
        }
        if (pending.connect.connect.will) |will| {
            if (will.retain and !accept_options.retain_available) {
                try self.refuseResolvedConnect(pending, .{
                    .reason_code = switch (pending.connect.connect.protocol) {
                        .v5 => 0x9a,
                        .v3_1, .v3_1_1 => 0x05,
                    },
                }, &pending_owned);
                return null;
            }
        }
        if (pending.connect.connect.client_id.len != 0 and
            !self.clientIdMatchesRequiredPrefix(
                pending.connect.connect.client_id,
            ))
        {
            try self.refuseUnauthorizedConnect(pending, &pending_owned);
            return null;
        }
        if (pending.connect.connect.will) |will| {
            if (self.payloadTooLarge(will.payload)) {
                try self.refuseResolvedConnect(pending, .{
                    .reason_code = switch (pending.connect.connect.protocol) {
                        .v5 => 0x95,
                        .v3_1, .v3_1_1 => 0x05,
                    },
                }, &pending_owned);
                return null;
            }
        }
        if (listener_authorization.use_identity_as_username or
            listener_authorization.use_subject_as_username)
        {
            if (!try self.applyListenerCertificateIdentity(
                pending,
                listener_authorization,
                &pending_owned,
            )) return null;
        }
        if (pending.connection.authentication.phase == .authenticating) {
            const handler = self.options.authentication orelse {
                try self.refuseResolvedConnect(
                    pending,
                    .{ .reason_code = 0x8c },
                    &pending_owned,
                );
                return null;
            };
            try handler.start(handler.context, pending);
            if (pending.authenticationRejectionReason()) |reason_code| {
                try self.refuseResolvedConnect(
                    pending,
                    .{ .reason_code = reason_code },
                    &pending_owned,
                );
                return null;
            }
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
        var effective_connect = pending.connect.connect;
        if (listener_authorization.use_username_as_client_id) {
            effective_connect.client_id = effective_connect.username orelse {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            };
        }
        if (listener_authorization.access_control) |access| {
            if (access.authorize_will) |authorize| {
                if (effective_connect.will) |will| {
                    suppress_reserved_will = suppress_reserved_will or
                        !authorize(access.context, effective_connect, will);
                }
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
                effective_connect.will = null;
            }
        }
        var registration_progress: RegistrationProgress = .{};
        const registration = self.register(
            index,
            effective_connect,
            listener_authorization.access_control,
            listener_authorization.retained_source_id,
            auto_client_id_prefix,
            &registration_progress,
        ) catch |err| {
            // register records any partial durable transition itself. Clear
            // this slot without counting that change twice, then persist the
            // rollback while retaining the caller's reservation.
            self.abortRegistration(index, 0, false);
            registration_persistence.rollback(
                RegistrationPersistenceContext,
                self,
                registration_progress.rollback_changed,
                registration_progress.rollback_changed,
            );
            if (err == error.SessionLimitExceeded) {
                if (pending.connect.connect.protocol == .v5) {
                    try self.refuseResolvedConnect(
                        pending,
                        .{ .reason_code = 0x89 },
                        &pending_owned,
                    );
                }
                return null;
            }
            if (err == error.ClientIdPrefixMismatch) {
                try self.refuseUnauthorizedConnect(pending, &pending_owned);
                return null;
            }
            if (err == error.WillLimitExceeded or err == error.WillByteLimitExceeded) {
                try self.refuseResolvedConnect(
                    pending,
                    .{ .reason_code = if (pending.connect.connect.protocol == .v5) 0x97 else 0x03 },
                    &pending_owned,
                );
                return null;
            }
            return err;
        };
        const subscriber_id = registration.subscriber_id;
        // The Will scheduler now owns its canonical topic. Restore the parsed
        // CONNECT view before it transfers to the long-lived client task.
        if (mapped_will) |*mapped| {
            mapped.deinit();
            mapped_will = null;
        }
        accept_options.session_present = self.slots[index].state.session_present;
        if (self.slots[index].assignedClientId()) |assigned_client_id| {
            effective_connect.client_id = assigned_client_id;
            accept_options.assigned_client_identifier = assigned_client_id;
        }
        // OwnedConnect keeps all original packet storage alive; changing this
        // borrowed view makes downstream ACLs, retained-source tracking, and
        // Will cleanup observe the same effective identity used for Session
        // registration. Assigned IDs borrow stable storage from this slot.
        pending.connect.connect.client_id = effective_connect.client_id;
        self.appendProvisionalCommitIfEnabled() catch |err| {
            self.abortRegistration(
                index,
                subscriber_id,
                registration_progress.rollback_changed,
            );
            // The failed append may nevertheless have left a complete record
            // containing provisional state. Always append the rolled-back
            // image; only genuine net changes advance change-count autosave.
            registration_persistence.rollback(
                RegistrationPersistenceContext,
                self,
                registration_progress.rollback_changed,
                true,
            );
            return err;
        };
        return @as(?ClientTask, try self.finishRegistration(
            index,
            pending,
            accept_options,
            registration,
            registration_progress,
            &pending_owned,
            result,
        ));
    }

    fn refuseUnauthorizedConnect(
        self: *Broker,
        pending: *runtime.PendingAcceptedClient,
        pending_owned: *bool,
    ) Error!void {
        var refused = try pending.finish(.{
            .reason_code = switch (pending.connect.connect.protocol) {
                .v3_1, .v3_1_1 => 0x05,
                .v5 => 0x87,
            },
        });
        pending_owned.* = false;
        refused.deinit(self.allocator);
    }

    // Session and Will registration has sizeable temporary state. Do not
    // inline it into the coroutine that remains parked for the full Network
    // Connection lifetime.
    noinline fn register(
        self: *Broker,
        slot_index: usize,
        connect: mqtt.Connect,
        listener_access_control: ?ListenerAccessControlHandler,
        retained_source_id: ?u64,
        auto_client_id_prefix: []const u8,
        progress: *RegistrationProgress,
    ) Error!Registration {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        // `claimSlot` reserves the slot before CONNECT-dependent setup begins.
        // Legacy direct callers may still provide an unclaimed slot.
        if (slot.state.active and slot.connection != null) return error.BrokerFull;
        slot.state.generation = @intCast(nextConnectionGeneration(
            slot.state.generation,
        ));
        slot.state.active = true;
        slot.state.registration_aborted = false;
        slot.connection = null;
        slot.setWillHandle(null);
        slot.setSessionHandle(null);
        slot.state.session_present = false;
        slot.state.session_persistent = false;
        slot.state.administrative_disconnect = false;
        std.debug.assert(slot.assignedClientId() == null);
        std.debug.assert(slot.buffers == null);
        errdefer slot.clearBuffers(self.allocator);
        errdefer slot.clearAssignedClientId(self.allocator);
        slot.state.graceful_disconnect = false;
        try slot.setListenerAccessControl(
            self.allocator,
            listener_access_control,
        );
        errdefer slot.clearListenerAccessControl(self.allocator);
        slot.setRetainedSourceId(retained_source_id);
        errdefer slot.setRetainedSourceId(null);
        // `preparePending` passes the effective CONNECT after any
        // username-as-client-id transformation; its username remains the
        // authenticated wire identity used by listener read ACLs.
        slot.setUsername(connect.username);
        errdefer slot.setUsername(null);
        // A slot can retain a harmless late notification from its previous
        // generation. No writer exists while the slot is being registered.
        slot.delivery_ready.reset();
        const id = subscriberId(slot_index, slot.state.generation);
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
            effective_connect.client_id = try self.assignClientIdLocked(
                slot,
                auto_client_id_prefix,
            );
        }
        if (!self.clientIdMatchesRequiredPrefixLocked(
            effective_connect.client_id,
        )) {
            return error.ClientIdPrefixMismatch;
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
        // A connection that has never subscribed cannot receive live fanout,
        // so reserving its complete bounded delivery queue would charge pure
        // publishers for memory they cannot use. Resumed subscriptions are
        // about to become visible to the router and therefore reserve here;
        // a first SUBSCRIBE reserves at its own visibility boundary below.
        if (!connect.clean_start) if (previous_session_handle) |handle| {
            const session_stats = try self.sessions.stats(handle);
            if (session_stats.subscription_count != 0) {
                try slot.ensureDeliveryCapacity(
                    self.allocator,
                    @min(
                        self.options.limits
                            .max_queued_deliveries_per_connection,
                        transient_delivery_async_high_watermark,
                    ),
                );
            }
        };
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
        // Most brokers have no pending Will for most connections. Reserve the
        // publisher association before Session/Will mutation, but grow it only
        // when this CONNECT can actually install a Will instead of allocating
        // for `max_wills` at Broker initialization.
        if (effective_connect.will != null) {
            try self.will_publishers.ensureUnusedCapacity(
                self.allocator,
                1,
            );
        }
        // Reject Will resource failures before replacing any Session or
        // detaching its current owner. Preparation is discarded if Session
        // admission or subscription restoration fails; commit cannot fail.
        var prepared_will = try self.wills.prepareConnectWithSource(
            effective_connect,
            effective_connect.username,
            retained_source_id,
            self.sessionExpiryForConnectLocked(effective_connect),
            now,
        );
        defer prepared_will.deinit();
        const opened_session = try self.sessions.open(
            effective_connect.client_id,
            effective_connect.clean_start,
            self.sessionExpiryForConnectLocked(effective_connect),
            now,
        );
        // A rejected Session admission preserves the old state. Once its
        // replacement commits, later router/CONNACK failures still need
        // to carry that durable transition to persistence.
        persistent_changed = persistent_changed or previous_session_persistent;
        progress.rollback_changed = persistent_changed;
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
        slot.setSessionHandle(opened_session.handle);
        slot.state.session_present = opened_session.session_present;
        slot.state.session_persistent = (try self.sessions.stats(
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
            return err;
        };
        const previous_handle = self.wills.handleForClient(
            effective_connect.client_id,
        );
        const accepted_will = self.wills.commitConnect(&prepared_will);
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
        slot.setWillHandle(accepted_will.current);
        if (accepted_will.current) |handle| {
            self.will_publishers.putAssumeCapacityNoClobber(
                handle,
                sessionSubscriberId(opened_session.route_id),
            );
        }
        self.deadline_driver.notify(self.io);
        persistent_changed = persistent_changed or slot.state.session_persistent or
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
        prefix: []const u8,
    ) Error![]const u8 {
        std.debug.assert(slot.assignedClientId() == null);
        while (true) {
            var random: [client_id_mod.random_len]u8 = undefined;
            try std.Io.randomSecure(self.io, &random);
            var storage: [client_id_mod.max_len]u8 = undefined;
            const candidate = client_id_mod.format(
                &storage,
                prefix,
                random,
            );
            if (self.sessions.containsClientId(candidate)) continue;
            return try slot.setAssignedClientId(
                self.allocator,
                candidate,
            );
        }
    }

    fn clientIdMatchesRequiredPrefix(
        self: *Broker,
        client_id: []const u8,
    ) bool {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.clientIdMatchesRequiredPrefixLocked(client_id);
    }

    fn clientIdMatchesRequiredPrefixLocked(
        self: *const Broker,
        client_id: []const u8,
    ) bool {
        return self.options.client_id_prefix.len == 0 or
            std.mem.startsWith(
                u8,
                client_id,
                self.options.client_id_prefix,
            );
    }

    fn sessionExpiryForConnectLocked(
        self: *const Broker,
        connect: mqtt.Connect,
    ) u32 {
        const requested = session_mod.Store.expiryForConnect(
            connect.protocol,
            connect.clean_start,
            connect.properties,
        );
        return self.capPersistentSessionExpiryLocked(requested);
    }

    fn sessionExpiryForDisconnectLocked(
        self: *const Broker,
        protocol: mqtt.ProtocolVersion,
        disconnect: mqtt.Disconnect,
    ) ?u32 {
        if (protocol != .v5) return null;
        const requested = mqtt.sessionExpiryInterval(
            disconnect.properties,
        ) orelse return null;
        return self.capPersistentSessionExpiryLocked(requested);
    }

    fn capPersistentSessionExpiryLocked(
        self: *const Broker,
        requested: u32,
    ) u32 {
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
        if (!owner.state.active or
            subscriberId(owner_index, owner.state.generation) != owner_id)
        {
            return;
        }
        owner.setSessionHandle(null);
        owner.state.session_persistent = false;
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
        const still_replaced = owner.state.active and
            subscriberId(owner_index, owner.state.generation) == owner_id and
            owner.sessionHandle() == null and
            owner.connection != null;
        self.state_mutex.unlock(self.io);
        if (!still_replaced) return;

        const connection = owner.connection.?;
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
            self.sessionExpiryForDisconnectLocked(
                connection.protocol,
                disconnect,
            )
        else if (mqtt.sessionExpiryInterval(disconnect.properties)) |requested|
            self.capPersistentSessionExpiryLocked(requested)
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
        const handle = slot.willHandle() orelse return;
        const result = self.wills.closeDisconnectWithSessionExpiry(
            handle,
            disconnect,
            session_expiry_override,
            now,
        ) catch |err| {
            if (err == error.WillNotFound and
                slot.sessionHandle() == null)
            {
                slot.setWillHandle(null);
                return;
            }
            return err;
        };
        if (result == .canceled) {
            _ = self.will_publishers.remove(handle);
            slot.setWillHandle(null);
        }
    }

    fn attachConnection(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
        stored_connection: *runtime.Connection,
        persistent_changed: bool,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        std.debug.assert(slot.state.active);
        std.debug.assert(slot.connection == null);
        std.debug.assert(
            subscriberId(slot_index, slot.state.generation) == id,
        );
        slot.connection = stored_connection;
        var active_connections: usize = 0;
        for (self.slots) |candidate| {
            active_connections +|= @intFromBool(
                candidate.state.active and candidate.connection != null,
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
        if (slot.sessionHandle()) |handle| {
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                self.rollbackOpenedSessionLocked(
                    handle,
                    value,
                    slot.state.session_present,
                    std.Io.Clock.awake.now(self.io),
                );
            }
        }
        if (slot.willHandle()) |handle| {
            _ = self.will_publishers.remove(handle);
            _ = self.wills.close(handle, .normal_disconnect, .zero) catch {};
        }
        // The preparePending caller still owns the reservation until a
        // ClientTask is returned. Keep it active across this rollback so no
        // concurrent accept can reuse it before that caller releases it.
        slot.connection = null;
        slot.setSessionHandle(null);
        slot.state.session_present = false;
        slot.state.session_persistent = false;
        slot.setRetainedSourceId(null);
        slot.setUsername(null);
        slot.setWillHandle(null);
        slot.clearBuffers(self.allocator);
        slot.clearListenerAccessControl(self.allocator);
        slot.clearAssignedClientId(self.allocator);
        slot.state.registration_aborted = true;
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
        listener_capacity: ?*ListenerCapacity,
    ) Error!void {
        // Release the listener claim on every terminal path. The successful
        // path transfers this cleanup to the precise inactive-slot boundary
        // below, before the old socket close becomes visible to its peer.
        var capacity_claimed = listener_capacity != null;
        defer if (capacity_claimed) {
            listener_capacity.?.release(self.io);
        };
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
        const will_close_reason: ?will_mod.CloseReason =
            if (slot.state.administrative_disconnect)
                .normal_disconnect
            else if (!slot.state.graceful_disconnect)
                .ungraceful
            else
                null;
        if (will_close_reason) |close_reason| {
            if (slot.willHandle()) |handle| {
                const result: ?will_mod.CloseResult = self.wills.close(
                    handle,
                    close_reason,
                    std.Io.Clock.awake.now(self.io),
                ) catch |err| switch (err) {
                    error.WillNotFound => blk: {
                        // A newer connection with the same ClientID already
                        // canceled or committed this generation during
                        // takeover. The stale transport close has no remaining
                        // Will lifecycle work.
                        slot.setWillHandle(null);
                        break :blk null;
                    },
                    else => {
                        return err;
                    },
                };
                if (result) |changed_result| {
                    persistent_changed = changed_result != .no_will;
                    if (changed_result == .canceled) {
                        _ = self.will_publishers.remove(handle);
                        slot.setWillHandle(null);
                    }
                }
            }
        }
        if (slot.sessionHandle()) |handle| {
            persistent_changed = persistent_changed or slot.state.session_persistent;
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
        if (slot.sessionHandle() == null) {
            _ = self.pending_qos2.removePublisher(id);
        }
        slot.clearBuffers(self.allocator);
        // Publish an idle slot only after every field from the old generation
        // has been detached. `claimSlot` observes this state under the same
        // mutex, so it can never reserve a slot that still owns a connection.
        if (slot.connection) |active| {
            active.flushDeferredTrafficCounters();
        }
        const connection = slot.connection;
        const assigned_client_id = slot.takeAssignedClientId();
        const listener_access_control = slot.listener_access_control;
        slot.connection = null;
        slot.setWillHandle(null);
        slot.setSessionHandle(null);
        slot.state.session_present = false;
        slot.state.session_persistent = false;
        slot.state.administrative_disconnect = false;
        slot.listener_access_control = null;
        slot.setRetainedSourceId(null);
        slot.setUsername(null);
        slot.state.active = false;
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        state_locked = false;
        self.deadline_driver.notify(self.io);
        // The broker slot is now reusable and no code can observe this
        // connection as active. Publish the listener capacity before closing
        // the detached socket so a peer that observes EOF/reset can reconnect
        // immediately without racing a stale capacity count.
        if (listener_capacity) |capacity| {
            capacity.release(self.io);
            capacity_claimed = false;
        }
        defer if (assigned_client_id) |client_id| {
            self.allocator.free(client_id);
        };
        defer if (listener_access_control) |access_control| {
            self.allocator.destroy(access_control);
        };
        defer if (connection) |value| {
            value.close();
            self.allocator.destroy(value);
        };
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
        self.state_mutex.lockUncancelable(self.io);
        var state_locked = true;
        var persistent_changed = false;
        errdefer if (state_locked) {
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChange(persistent_changed);
        };
        const session_expiry_override =
            self.sessionExpiryForDisconnectLocked(
                slot.connection.?.protocol,
                disconnect,
            );
        // Validate state-dependent DISCONNECT properties before changing the
        // Will, Session owner, router, or persistence state. In particular,
        // MQTT-3.14.2-2 makes zero-to-nonzero Session Expiry a Protocol Error.
        if (slot.sessionHandle()) |handle| {
            try self.sessions.validateDisconnect(
                handle,
                session_expiry_override,
            );
        }
        if (slot.willHandle()) |handle| {
            const result: ?will_mod.CloseResult = self.wills.closeDisconnectWithSessionExpiry(
                handle,
                disconnect,
                session_expiry_override,
                now,
            ) catch |err| switch (err) {
                error.WillNotFound => blk: {
                    if (slot.sessionHandle() != null) {
                        return err;
                    }
                    slot.setWillHandle(null);
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
                    slot.setWillHandle(null);
                }
            }
        }
        if (slot.sessionHandle()) |handle| {
            persistent_changed = persistent_changed or slot.state.session_persistent;
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
            slot.setSessionHandle(null);
        }
        slot.state.graceful_disconnect = true;
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
            applyPrivateBridgeSubscriptionPolicy(connect, mapped);
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
                slot.accessControl(),
                connect,
                subscription,
            )) 0xff else subscriptionDeniedReason(connection.protocol);
        }
        const subscription_identifier = mqtt.subscriptionIdentifier(
            subscribe.properties,
        );
        const now = std.Io.Clock.awake.now(self.io);
        const session_handle = slot.sessionHandle() orelse
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
        // Warm the common asynchronous queue window before publishing a new
        // route. Larger slow-consumer backlogs grow transactionally during
        // route preflight instead of charging every subscriber the hard cap.
        for (reasons) |reason| {
            if (reason != 0xff) continue;
            try slot.ensureDeliveryCapacity(
                self.allocator,
                @min(
                    self.options.limits
                        .max_queued_deliveries_per_connection,
                    transient_delivery_async_high_watermark,
                ),
            );
            break;
        }
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
        try self.flushSlotLocked(slot, true);
    }

    fn applyPrivateBridgeSubscriptionPolicy(
        connect: mqtt.Connect,
        subscription: *mqtt.Subscription,
    ) void {
        if (connect.protocol.isLegacy() and connect.bridge_mode) {
            // Mosquitto's private bridge extension gives legacy subscriptions
            // the MQTT 5-style loop prevention and retain preservation that
            // their wire format cannot otherwise express.
            subscription.no_local = true;
            subscription.retain_as_published = true;
        }
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
        const handle = slot.sessionHandle() orelse
            return error.SessionNotFound;
        const authorizers = self.deliveryAuthorizers(slot.accessControl());
        const client_id = if (authorizers.configured())
            try self.sessions.clientId(handle)
        else
            &.{};
        const buffers = try slot.ensureBuffers(self.allocator);
        const properties = &buffers.session_property_scratch;
        defer properties.clearRetainingCapacity();
        for (deliveries) |delivery| {
            if (!self.retainedSourceAuthorized(delivery)) continue;
            try prepareRetainedDeliveryProperties(
                properties,
                self.allocator,
                delivery.properties,
                delivery.message_expiry_interval,
            );
            const publish = mqtt.Publish{
                .dup = false,
                .qos = delivery.qos,
                .retain = delivery.retain,
                .topic = delivery.topic,
                .packet_id = null,
                .properties = properties.items,
                .payload = delivery.payload,
            };
            if (authorizers.configured() and !authorizers.authorize(.{
                .client_id = client_id,
                .username = slot.username(),
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
                self.publish_counters.recordDropped();
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
                slot.accessControl(),
                connect,
                filter,
            )) {
                reasons[index] = unsubscribeDeniedReason(
                    connection.protocol,
                );
                continue;
            }
            const session_handle = slot.sessionHandle() orelse {
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
        owned_publish: *runtime.OwnedPublish,
    ) Error!void {
        const publish = owned_publish.publish;
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
        var mapped_topic = try namespace.mapTopic(
            self.allocator,
            publish.topic,
        );
        defer mapped_topic.deinit(self.allocator);
        var canonical_publish = publish;
        canonical_publish.topic = mapped_topic.value;
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
            publisher_slot.accessControl(),
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
                0x83,
            );
        }
        if (canonical_publish.qos == .exactly_once) {
            return self.recordQoS2Publish(
                publisher_id,
                publisher,
                connect,
                canonical_publish,
            );
        }
        return self.routeReleasedPublish(
            publisher_id,
            publisher,
            canonical_publish,
            connect.client_id,
            connect.username,
            publisher_slot.retainedSourceId(),
            true,
            if (mapped_topic.allocation == null and
                owned_publish.packet.contains(canonical_publish.topic) and
                owned_publish.packet.contains(canonical_publish.payload))
                &owned_publish.packet
            else
                null,
        );
    }

    fn payloadTooLarge(self: *Broker, payload: []const u8) bool {
        const policy = self.runtimeDeliveryPolicy();
        return policy.max_payload_size != 0 and
            payload.len > policy.max_payload_size;
    }

    fn recordPublishReceived(self: *Broker, payload_len: usize) void {
        self.publish_counters.recordReceived(payload_len);
    }

    fn recordPublishSent(self: *Broker, payload_len: usize) void {
        self.publish_counters.recordSent(payload_len);
    }

    fn recordPublishDropped(self: *Broker) void {
        self.publish_counters.recordDropped();
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
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        const durable_publisher_id = self.canonicalPublisherId(
            publisher_id,
        );
        const persistent_publisher = self.publisherIsPersistentLocked(
            durable_publisher_id,
        );
        const publisher_slot = try self.slotForSubscriber(publisher_id);
        // Route selection belongs to PUBREL: matching here could advance a
        // shared-subscription cursor early, and subscriptions may change in
        // between. The global count is a conservative O(1) signal that avoids
        // enlarging the common single-subscription pending record.
        const reserve_publication_prefix =
            self.sessions.persistentCount() != 0 and
            self.router.subscriptionCount() > 1;
        const record_changed = self.pending_qos2.recordValidatedSourceAndPublicationPrefix(
            durable_publisher_id,
            publish,
            connect.client_id,
            connect.username,
            publisher_slot.retainedSourceId(),
            netz_runtime.cachedAwakeNow(self.io),
            reserve_publication_prefix,
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            if (err != error.ReceiveMaximumExceeded) return err;

            // A broker-wide pending-transaction cap is an MQTT quota failure,
            // not malformed client behavior. Reject this transaction with the
            // standard QoS 2 response and release the runtime receive slot so
            // the connection can continue.
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
        var pending_owned = true;
        defer if (pending_owned) pending.deinit();

        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        var deferred_plan: ?RoutePlan = null;
        defer if (deferred_plan) |plan| plan.deinit(self.allocator);
        // Expiry and the routed queue lifetime belong to one atomic PUBREL
        // release, so both must observe the same awake-clock instant.
        const now = netz_runtime.cachedAwakeNow(self.io);
        const maybe_publish = pending.asPublish(
            ack.packet_id,
            now,
            &properties,
        ) catch |err| {
            self.state_mutex.lockUncancelable(self.io);
            self.recordPersistentChangeLocked(persistent_changed);
            self.state_mutex.unlock(self.io);
            self.finishPartialPersistentChangeLocked(persistent_changed);
            return err;
        };
        if (maybe_publish) |publish| {
            const delivery_policy = self.runtimeDeliveryPolicy();
            deferred_plan = self.routeReleasedPublishMode(
                .deferred,
                publisher_id,
                publisher,
                publish,
                pending.source_client_id orelse source_client_id,
                pending.source_username,
                pending.source_listener_id,
                delivery_policy.upgrade_outgoing_qos,
                false,
                false,
                now,
                &persistent_changed,
                null,
                &pending,
            ) catch |err| {
                self.state_mutex.lockUncancelable(self.io);
                self.recordPersistentChangeLocked(persistent_changed);
                self.state_mutex.unlock(self.io);
                self.finishPartialPersistentChangeLocked(persistent_changed);
                return err;
            };
        }
        self.state_mutex.lockUncancelable(self.io);
        self.pending_qos2.recycle(&pending);
        pending_owned = false;
        self.recordPersistentChangeLocked(persistent_changed);
        self.state_mutex.unlock(self.io);
        // `routeReleasedPublish` journals the routed state before returning.
        // If Message Expiry discarded the Application Message instead, the
        // pending inbound transaction removal is still a durable mutation.
        try self.finalizePersistentChangeLocked(
            persistent_changed,
            persistent_changed,
        );
        // Socket delivery is intentionally scheduled only after the atomic
        // pending-QoS2 removal/routing persistence transaction above.
        self.persistence_mutex.unlock(self.io);
        persistence_locked = false;
        if (deferred_plan) |plan| try self.dispatchNetworkPlan(plan);

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
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        acknowledge_qos1: bool,
        prefixed_packet: ?*runtime.OwnedPacket,
    ) Error!void {
        const delivery_policy = self.runtimeDeliveryPolicy();
        const mode = networkDeliveryMode(
            delivery_policy.upgrade_outgoing_qos,
            publish.qos,
        );
        const now = netz_runtime.cachedAwakeNow(self.io);
        const deferred_plan = switch (mode) {
            inline else => |comptime_mode| try self.routeReleasedPublishMode(
                comptime_mode,
                publisher_id,
                publisher,
                publish,
                source_client_id,
                source_username,
                source_listener_id,
                delivery_policy.upgrade_outgoing_qos,
                acknowledge_qos1,
                true,
                now,
                null,
                prefixed_packet,
                null,
            ),
        };
        std.debug.assert(deferred_plan == null);
    }

    fn routeReleasedPublishMode(
        self: *Broker,
        comptime delivery_mode: NetworkDeliveryMode,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
        source_client_id: []const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        upgrade_outgoing_qos: bool,
        acknowledge_qos1: bool,
        count_persistent_change: bool,
        now: std.Io.Timestamp,
        outer_changed: ?*bool,
        prefixed_packet: ?*runtime.OwnedPacket,
        pending_qos2: ?*qos2_mod.Pending,
    ) Error!?RoutePlan {
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
        var plan = self.enqueuePublishLocked(
            delivery_mode != .synchronous,
            publisher_id,
            publish,
            source_client_id,
            source_username,
            source_listener_id,
            upgrade_outgoing_qos,
            now,
            &persistent_changed,
            null,
            prefixed_packet,
            pending_qos2,
        ) catch |err| {
            if (outer_changed) |changed| {
                changed.* = changed.* or persistent_changed;
            }
            return err;
        };
        var plan_owned = true;
        defer if (plan_owned) plan.deinit(self.allocator);
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
        switch (delivery_mode) {
            .synchronous => {
                try self.flushPlan(plan);
                return null;
            },
            .asynchronous => {
                try self.dispatchNetworkPlan(plan);
                return null;
            },
            .deferred => {
                plan_owned = false;
                return plan;
            },
        }
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
        comptime classify_async: bool,
        publisher_id: ?router_mod.SubscriberId,
        publish: mqtt.Publish,
        source_client_id: ?[]const u8,
        source_username: ?[]const u8,
        source_listener_id: ?u64,
        upgrade_outgoing_qos: bool,
        now: std.Io.Timestamp,
        persistent_changed: ?*bool,
        publication_effect_committed: ?*bool,
        prefixed_packet: ?*runtime.OwnedPacket,
        pending_qos2: ?*qos2_mod.Pending,
    ) Error!RoutePlan {
        if (self.pruneExpiredSessionRoutesLocked(now) != 0) {
            if (persistent_changed) |changed| changed.* = true;
        }
        const route_publisher_id = if (publisher_id) |id|
            self.canonicalPublisherId(id)
        else
            null;
        const retained_result: retained_mod.StoreResult = if (publish.retain)
            self.retained.applyParsedPublishWithSource(
                publish,
                route_publisher_id,
                source_client_id,
                source_username,
                source_listener_id,
                now,
            ) catch |err| return err
        else
            .ignored;
        if (retained_result != .ignored) {
            if (persistent_changed) |changed| changed.* = true;
            if (publication_effect_committed) |committed| committed.* = true;
        }
        const match_storage = try self.matchRoutesForPublisherLocked(
            publisher_id,
            route_publisher_id,
            publish.topic,
        );
        const matches = match_storage.items;
        errdefer match_storage.deinit(self.allocator);
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
        var session_plan_scratch: session_delivery.Scratch = .{};
        var session_plan = try session_delivery.Plan.initWithScratch(
            self.allocator,
            matches,
            publish.qos,
            publish.retain,
            upgrade_outgoing_qos,
            &session_plan_scratch,
        );
        defer session_plan.deinit();
        var shared_route_publication: ?*Publication = null;
        defer if (shared_route_publication) |publication| {
            publication.release();
        };
        // `prefixed_packet` is also present when a small PUBLISH borrows the
        // connection's stack storage. Share online Session bytes only when an
        // ingress packet or released QoS 2 transaction already owns backing
        // that Publication can adopt; a borrowed packet must not introduce a
        // new route allocation.
        const can_adopt_source = (if (pending_qos2) |pending|
            pending.canAdoptPublication()
        else
            false) or
            (if (prefixed_packet) |packet|
                packet.prefixedAllocation() != null
            else
                false);
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
            // Internal consumers remain trusted while closed, so durable
            // bridge queues do not acquire network-client ACL semantics.
            const internal_consumer = local_consumer_mod.isInternalClientId(
                try self.sessions.clientId(handle),
            );
            const local_registration = if (internal_consumer)
                self.local_consumer_routes.get(route.route_id)
            else
                null;
            const internal_online = local_registration != null;
            // Live Sessions use the current destination listener policy. An
            // offline Session has no listener until it reconnects, so retain
            // its granted QoS and cap it immediately before a later write.
            if (online) {
                route.qos = minQos(
                    route.qos,
                    destination.?.connection.?.localMaximumQoS(),
                );
            }
            const authorizers = self.deliveryAuthorizers(if (online)
                destination.?.accessControl()
            else
                null);
            if (!internal_consumer and authorizers.configured() and
                !authorizers.authorize(.{
                    .client_id = try self.sessions.clientId(handle),
                    .username = if (online) destination.?.username() else null,
                    .topic = publish.topic,
                    .payload = publish.payload,
                    .qos = route.qos,
                    .retain = route.retain,
                    .properties = publish.properties,
                }))
            {
                // A read denial suppresses every overlapping subscription for
                // this Session before either its durable queue or live queue
                // changes. The raw router match still counts for the
                // publisher's MQTT 5 "matching subscriber" PUBACK reason,
                // as it does in Mosquitto.
                continue;
            }
            has_matching_subscriber = true;
            if ((route.qos == .at_most_once and
                (!internal_online and (!self.options.queue_qos0_messages or online))) or
                (online and !destination.?.state.session_persistent))
            {
                // Mosquitto always delivers QoS 0 directly to an online
                // persistent client. It drops QoS 0 while offline unless its
                // non-default queue_qos0 option is enabled. QoS 1/2 can take
                // the same shared-Publication path when Session Expiry is
                // zero: runtime state owns the transaction until ACK, and no
                // payload may survive this Network Connection.
                if (online) route.output_subscriber_id = owner_id.?;
                continue;
            }
            const changed = persistent_changed orelse
                &ignored_persistent_change;
            var route_persistent_changed = false;
            var route_enqueued = false;
            const shared_publication = if (session_plan.routes.len > 1 and
                (can_adopt_source or !online))
            blk: {
                if (shared_route_publication == null) {
                    shared_route_publication = try self.createRoutePublicationLocked(
                        publish,
                        1,
                        now,
                        prefixed_packet,
                        pending_qos2,
                    );
                }
                break :blk shared_route_publication;
            } else null;
            self.enqueueSessionDeliveryManyLocked(
                handle,
                session_plan.identifiersFor(route),
                route.retain,
                route.qos,
                publish,
                now,
                &route_persistent_changed,
                &route_enqueued,
                shared_publication,
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
            if (route_enqueued) if (local_registration) |registration| {
                if (registration.wake) |wake| wake.signal(self.io);
            };
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
            if (!destination.state.active or
                subscriberId(
                    destination_index,
                    destination.state.generation,
                ) != match.subscriber_id)
            {
                continue;
            }
            has_matching_subscriber = true;
            const destination_buffers = destination.buffers.?;
            if (destination.queuedCount() +
                destination_buffers.route_reservations >=
                self.options.limits
                    .max_queued_deliveries_per_connection)
            {
                // Match Mosquitto's bounded outgoing queues: a saturated
                // subscriber drops this delivery, but it was still a matching
                // subscription and therefore does not turn the publisher's
                // PUBACK into "No matching subscribers".
                self.publish_counters.recordDropped();
                continue;
            }
            destination.ensureDeliveryReservationCapacity(
                self.allocator,
                1,
                self.options.limits
                    .max_queued_deliveries_per_connection,
            ) catch |err| {
                self.releaseRouteReservations(matches[0..plan_count]);
                return err;
            };
            destination_buffers.route_reservations += 1;
            matches[plan_count] = match;
            plan_count += 1;
        }
        const plan = matches[0..plan_count];

        const publication = if (plan.len == 0) null else if (shared_route_publication) |shared| blk: {
            for (0..plan.len) |_| shared.retain();
            break :blk shared;
        } else self.createRoutePublicationLocked(
            publish,
            plan.len,
            now,
            prefixed_packet,
            null,
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
            // A Publication is unique to this route operation, which holds
            // `state_mutex` until every destination has been materialized.
            // If an overlapping subscription already enqueued it for this
            // client, that delivery must still be at the queue tail.
            const duplicate = destination.tailDeliveryForPublication(
                publication.?,
            );
            const delivery_qos = minQos(
                if (upgrade_outgoing_qos)
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

        // Keep live QoS 0 deliveries for persistent Sessions and self-matched
        // delivery on the ordered caller path. The latter preserves the
        // existing PUBLISH-before-PUBACK/PUBCOMP same-connection boundary.
        // Also apply a lower scheduling high watermark before the configured
        // hard queue/drop limit, so an arbitrarily fast publisher cannot turn
        // asynchronous socket progress into unbounded latency and retained
        // Publication memory.
        const async_high_watermark = @min(
            self.options.limits.max_queued_deliveries_per_connection,
            transient_delivery_async_high_watermark,
        );
        var synchronous_delivery_start = plan_count;
        if (!classify_async) {
            // No destination can become QoS 2, so preserve the original
            // ordered path without another per-match classification pass.
            synchronous_delivery_start = 0;
        } else {
            var delivery_index = plan_count;
            while (delivery_index != 0) {
                delivery_index -= 1;
                const destination_index = subscriberIndex(
                    matches[delivery_index].subscriber_id,
                    self.slots.len,
                ).?;
                const destination = &self.slots[destination_index];
                const queued_delivery = destination.tailDeliveryForPublication(
                    publication.?,
                ) orelse unreachable;
                if (shouldScheduleTransientDelivery(
                    destination.state.session_persistent,
                    queued_delivery.qos,
                    enqueued_count,
                    destination.queuedCount(),
                    async_high_watermark,
                    publisher_id != null and
                        matches[delivery_index].subscriber_id == publisher_id.?,
                )) {
                    continue;
                }
                synchronous_delivery_start -= 1;
                if (delivery_index != synchronous_delivery_start) {
                    std.mem.swap(
                        router_mod.Match,
                        &matches[delivery_index],
                        &matches[synchronous_delivery_start],
                    );
                }
            }
        }
        const session_target_count = matches.len - session_target_start;
        var synchronous_session_target_start = matches.len;
        var session_index = matches.len;
        while (session_index != session_target_start) {
            session_index -= 1;
            const destination_index = subscriberIndex(
                matches[session_index].subscriber_id,
                self.slots.len,
            ).?;
            const destination = &self.slots[destination_index];
            const schedule = blk: {
                const handle = destination.sessionHandle() orelse
                    break :blk false;
                const session_stats = self.sessions.stats(handle) catch
                    break :blk false;
                break :blk shouldScheduleSessionDelivery(
                    session_target_count,
                    session_stats.queued_count,
                    async_high_watermark,
                    publisher_id != null and
                        matches[session_index].subscriber_id == publisher_id.?,
                    self.session_delivery_writers.isAvailable(),
                );
            };
            if (schedule) continue;
            synchronous_session_target_start -= 1;
            if (session_index != synchronous_session_target_start) {
                std.mem.swap(
                    router_mod.Match,
                    &matches[session_index],
                    &matches[synchronous_session_target_start],
                );
            }
        }
        return .{
            .storage = matches,
            .deliveries = matches[0..synchronous_delivery_start],
            .synchronous_deliveries = matches[synchronous_delivery_start..plan_count],
            .session_deliveries = matches[session_target_start..synchronous_session_target_start],
            .synchronous_session_targets = matches[synchronous_session_target_start..],
            .has_matching_subscriber = has_matching_subscriber,
            .scratch_owner = match_storage.scratch_owner,
        };
    }

    const RouteMatchStorage = struct {
        items: []router_mod.Match,
        scratch_owner: ?*std.ArrayList(router_mod.Match) = null,

        fn deinit(
            self: RouteMatchStorage,
            allocator: std.mem.Allocator,
        ) void {
            if (self.scratch_owner) |scratch| {
                scratch.clearRetainingCapacity();
            } else {
                allocator.free(self.items);
            }
        }
    };

    fn matchRoutesForPublisherLocked(
        self: *Broker,
        publisher_id: ?router_mod.SubscriberId,
        route_publisher_id: ?router_mod.SubscriberId,
        topic: []const u8,
    ) Error!RouteMatchStorage {
        const match_capacity = self.router.subscriptionCount();
        if (publisher_id) |id| {
            if (subscriberIndex(id, self.slots.len)) |index| {
                const slot = &self.slots[index];
                if (slot.state.active and
                    subscriberId(index, slot.state.generation) == id and
                    match_capacity <= route_match_scratch_capacity)
                {
                    const buffers = try slot.ensureBuffers(self.allocator);
                    const scratch = &buffers.route_matches;
                    std.debug.assert(scratch.items.len == 0);
                    errdefer scratch.clearRetainingCapacity();
                    try scratch.ensureTotalCapacityPrecise(
                        self.allocator,
                        match_capacity,
                    );
                    scratch.items.len = match_capacity;
                    const matches = try self.router.matchValidatedIntoForPublisher(
                        topic,
                        route_publisher_id,
                        scratch.items,
                    );
                    scratch.shrinkRetainingCapacity(matches.len);
                    return .{
                        .items = scratch.items,
                        .scratch_owner = scratch,
                    };
                }
            }
        }
        return .{ .items = try self.router.matchValidatedAllocForPublisher(
            self.allocator,
            topic,
            route_publisher_id,
        ) };
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
        shared_publication: ?*Publication,
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
        const enqueue_options: session_mod.EnqueueOptions = .{
            .qos = qos,
            .retain = retain,
            .properties = properties.items,
            .now = now,
        };
        const result = (if (shared_publication) |shared|
            self.sessions.enqueueValidatedSharedPublicationTrackingSnapshotChange(
                handle,
                shared,
                enqueue_options,
                &snapshot_changed,
            )
        else
            self.sessions.enqueueValidatedPublishTrackingSnapshotChange(
                handle,
                publish.topic,
                publish.payload,
                enqueue_options,
                &snapshot_changed,
            )) catch |err| switch (err) {
            error.QueueFull => {
                self.publish_counters.recordDropped();
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
        const handle = slot.sessionHandle() orelse return .{
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

    /// A manual snapshot shares `state_mutex` and therefore observes either
    /// side of the combined ACK/next-transmission mutation. Live persistence
    /// backends need the existing intermediate durability barrier, so only
    /// the in-memory broker may carry this lock directly into its flush.
    /// The caller holds `state_mutex`, which also serializes commit-log setup.
    fn canCoalesceAcknowledgedSessionFlushLocked(
        self: *Broker,
    ) bool {
        return self.commit_log == null and
            !self.persistent_change_autosave_enabled.load(.acquire);
    }

    fn canonicalPublisherId(
        self: *Broker,
        id: router_mod.SubscriberId,
    ) router_mod.SubscriberId {
        if (sessionRouteId(id) != null) return id;
        const index = subscriberIndex(id, self.slots.len) orelse return id;
        const slot = &self.slots[index];
        const handle = slot.sessionHandle() orelse return id;
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
        if (!slot.state.active or slot.connection == null or
            subscriberId(index, slot.state.generation) != owner_id)
        {
            return false;
        }
        const handle = slot.sessionHandle() orelse return false;
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
        self: *const Broker,
        listener_access: ?*const ListenerAccessControlHandler,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool {
        if (self.options.access_control) |*access| {
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
        self: *const Broker,
        listener_access: ?*const ListenerAccessControlHandler,
        connect: mqtt.Connect,
        subscription: mqtt.Subscription,
    ) bool {
        if (self.options.access_control) |*access| {
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
        self: *const Broker,
        listener_access: ?*const ListenerAccessControlHandler,
        connect: mqtt.Connect,
        topic_filter: []const u8,
    ) bool {
        if (self.options.access_control) |*access| {
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

    fn deliveryAuthorizers(
        self: *const Broker,
        listener_access: ?*const ListenerAccessControlHandler,
    ) DeliveryAuthorizationChain {
        return .{
            .broker = if (self.options.access_control) |*access|
                access
            else
                null,
            .listener = listener_access,
        };
    }

    fn retainedSourceAuthorized(
        self: *const Broker,
        delivery: retained_mod.Delivery,
    ) bool {
        if (!self.options.check_retain_source) return true;
        const source_client_id = delivery.source_client_id orelse return true;
        const access = if (self.options.access_control) |*value|
            value
        else
            return true;
        const authorize = access.authorize_retained_source orelse return true;
        return authorize(access.context, .{
            .client_id = source_client_id,
            .username = delivery.source_username,
            .listener_id = delivery.source_listener_id,
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
            const buffers = destination.buffers.?;
            std.debug.assert(buffers.route_reservations != 0);
            buffers.route_reservations -= 1;
        }
    }

    fn slotForSubscriber(
        self: *Broker,
        id: router_mod.SubscriberId,
    ) Error!*ClientSlot {
        const index = subscriberIndex(id, self.slots.len) orelse
            return error.ClientNotRegistered;
        const slot = &self.slots[index];
        if (!slot.state.active or
            subscriberId(index, slot.state.generation) != id or
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
        try self.flushMatches(plan.synchronous_deliveries);
        try self.flushMatches(plan.session_deliveries);
        try self.flushMatches(plan.synchronous_session_targets);
    }

    /// Online destinations have independent connection-lifetime writers.
    /// Durable Session detachment still serializes its own state/persistence
    /// mutation before each socket write, while batching those socket writes
    /// across connection tasks in the shared I/O executor turn.
    fn dispatchNetworkPlan(self: *Broker, plan: RoutePlan) Error!void {
        self.scheduleMatches(plan.deliveries);
        try self.scheduleSessionMatches(plan.session_deliveries);
        try self.flushMatches(plan.synchronous_deliveries);
        try self.flushMatches(plan.synchronous_session_targets);
    }

    fn scheduleMatches(
        self: *Broker,
        matches: []const router_mod.Match,
    ) void {
        for (matches) |match| {
            const slot_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ) orelse continue;
            self.slots[slot_index].delivery_ready.set(self.io);
        }
    }

    fn scheduleSessionMatches(
        self: *Broker,
        matches: []const router_mod.Match,
    ) Error!void {
        if (matches.len == 0) return;
        if (!self.session_delivery_writers.ensureStarted(self.io)) {
            try self.flushMatches(matches);
            return;
        }
        for (matches) |match| {
            const slot_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ) orelse continue;
            if (!self.session_delivery_writers.schedule(
                self.io,
                slot_index,
            )) {
                try self.flushSlot(slot_index, &self.slots[slot_index]);
            }
        }
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
        for (plan.synchronous_deliveries) |match| {
            if (match.subscriber_id == publisher_id) {
                try self.flushSlot(slot_index, &self.slots[slot_index]);
                return;
            }
        }
        for (plan.session_deliveries) |match| {
            if (match.subscriber_id == publisher_id) {
                try self.flushSlot(slot_index, &self.slots[slot_index]);
                return;
            }
        }
        for (plan.synchronous_session_targets) |match| {
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
        return self.flushSlotLocked(slot, true);
    }

    /// Run one shared-pool durable Session job. Holding the slot writer lock
    /// across validation, flush, and error publication prevents disconnect
    /// from freeing or reusing the connection while a worker still owns it.
    fn flushScheduledSessionSlotErased(
        context: *anyopaque,
        slot_index: usize,
    ) void {
        const self: *Broker = @ptrCast(@alignCast(context));
        self.flushScheduledSessionSlot(slot_index);
    }

    fn flushScheduledSessionSlot(
        self: *Broker,
        slot_index: usize,
    ) void {
        const slot = &self.slots[slot_index];
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);

        self.state_mutex.lockUncancelable(self.io);
        const can_flush = slot.state.active and
            slot.state.session_persistent and
            slot.connection != null;
        self.state_mutex.unlock(self.io);
        if (!can_flush) return;

        self.flushSlotLocked(slot, false) catch |err| {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            if (!slot.state.active or
                !slot.state.session_persistent or
                slot.connection == null)
            {
                return;
            }
            self.session_delivery_writers.recordError(
                self.io,
                slot_index,
                err,
            );
            slot.connection.?.interrupt() catch {};
        };
    }

    fn flushSlotLocked(
        self: *Broker,
        slot: *ClientSlot,
        stop_after_snapshot: bool,
    ) Error!void {
        return self.flushSlotLockedMode(
            slot,
            stop_after_snapshot,
            false,
        );
    }

    /// Variant used when an acknowledgement already owns `state_mutex`.
    /// `flushSlotLockedMode` consumes and releases that lock on its first
    /// iteration; every later iteration follows the ordinary acquisition
    /// path.
    fn flushSlotAssumeStateLocked(
        self: *Broker,
        slot: *ClientSlot,
        stop_after_snapshot: bool,
    ) Error!void {
        return self.flushSlotLockedMode(
            slot,
            stop_after_snapshot,
            true,
        );
    }

    fn flushSlotLockedMode(
        self: *Broker,
        slot: *ClientSlot,
        stop_after_snapshot: bool,
        initial_state_locked: bool,
    ) Error!void {
        var supplied_state_lock = initial_state_locked;
        while (true) {
            if (supplied_state_lock) {
                supplied_state_lock = false;
            } else {
                self.state_mutex.lockUncancelable(self.io);
            }
            var take_changed = false;
            var more_pending = false;
            const maybe_packet = self.takeSessionPacketAssumeLocked(
                slot,
                &take_changed,
                &more_pending,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                if (take_changed) {
                    try self.finalizePersistentChange(true, true);
                }
                return err;
            };
            if (maybe_packet) |packet_value| {
                self.state_mutex.unlock(self.io);
                const packet = packet_value;
                defer slot.releaseOversizedSessionScratch(
                    self.allocator,
                );
                // Commit logs retain their historical behavior of recording
                // every selected Session packet, including retransmissions.
                // Change autosave advances only for snapshot-visible changes.
                try self.finalizePersistentChange(true, take_changed);
                // Selecting a durable QoS 1/2 message moves it from queued to
                // inflight and assigns its Packet Identifier. Sync that state
                // before the bytes can reach the peer, so restart retransmits
                // the same identifier with DUP rather than inventing a new
                // transaction.
                slot.connection.?.writePreparedSessionTransmission(
                    packet.detached.transmission,
                ) catch |err| switch (err) {
                    error.OutgoingPacketTooLarge => {
                        if (packet.detached.kind == .pubrel) return err;
                        // Match Mosquitto's oversized outgoing handling: once
                        // the peer's Maximum Packet Size rejects a PUBLISH,
                        // remove that transaction and continue draining rather
                        // than permanently consuming Session inflight credit.
                        self.state_mutex.lockUncancelable(self.io);
                        const drop_action = self.sessions.dropOversizedPublish(
                            packet.handle,
                            packet.detached.packet_id,
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
                        if (packet.detached.kind != .pubrel) {
                            self.state_mutex.lockUncancelable(self.io);
                            const retry = self.sessions.retryUnsentPublish(
                                packet.handle,
                                packet.detached.packet_id,
                            );
                            self.state_mutex.unlock(self.io);
                            retry catch {};
                        }
                        return err;
                    },
                };
                if (packet.detached.kind != .pubrel) {
                    self.recordPublishSent(packet.payload_len);
                }
                if (packet.detached.kind == .qos0_publish) {
                    self.state_mutex.lockUncancelable(self.io);
                    const completion = self.sessions
                        .completeQoS0Transmission(
                        packet.handle,
                        packet.route_id,
                        packet.detached.packet_id,
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
                if (stop_after_snapshot and !more_pending) return;
                continue;
            }
            if (take_changed) {
                self.state_mutex.unlock(self.io);
                try self.finalizePersistentChange(true, true);
                continue;
            }
            if (!slot.state.active or slot.connection == null or
                slot.queuedCount() == 0)
            {
                self.state_mutex.unlock(self.io);
                return;
            }
            const inflight_payload_limit =
                self.options.max_inflight_payload_bytes_per_connection;
            const buffers = slot.buffers.?;
            const next_delivery = buffers.queue.items[buffers.queue_head];
            if (next_delivery.qos != .at_most_once and
                slot.transientInflightPayloadLimitReached(
                    inflight_payload_limit,
                ))
            {
                self.state_mutex.unlock(self.io);
                return;
            }
            var delivery = slot.popDelivery().?;
            self.state_mutex.unlock(self.io);

            if (delivery.qos != .at_most_once and
                inflight_payload_limit != 0)
            {
                buffers.transient_inflight_payloads.ensureUnusedCapacity(
                    self.allocator,
                    1,
                ) catch |err| {
                    self.state_mutex.lockUncancelable(self.io);
                    slot.pushFront(delivery);
                    self.state_mutex.unlock(self.io);
                    return err;
                };
            }

            const connection = slot.connection.?;
            const visible_topic = connection.visibleTopic(
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
            const identifier_count = std.math.add(
                usize,
                delivery.additional_subscription_identifiers.len,
                @intFromBool(delivery.subscription_identifier != null),
            ) catch return error.OutOfMemory;
            const property_capacity = std.math.add(
                usize,
                delivery.publication.properties.len,
                identifier_count,
            ) catch return error.OutOfMemory;
            const property_capacity_with_alias = std.math.add(
                usize,
                property_capacity,
                1,
            ) catch return error.OutOfMemory;
            var property_stack: [runtime.write_property_staging_capacity]mqtt.Property =
                undefined;
            var property_list = try connection.writePropertyList(
                &property_stack,
                property_capacity_with_alias,
            );
            const properties = &property_list;
            var identifiers_stack: [8]usize = undefined;
            const identifiers = if (identifier_count <= identifiers_stack.len)
                identifiers_stack[0..identifier_count]
            else
                try self.allocator.alloc(usize, identifier_count);
            defer if (identifiers.ptr != identifiers_stack[0..].ptr) {
                self.allocator.free(identifiers);
            };
            // The timestamp is unobserved without Message Expiry; avoid a
            // runtime clock query for every subscriber in ordinary fanout.
            const delivery_now = if (delivery.publication.expiry_interval != null)
                netz_runtime.cachedAwakeNow(self.io)
            else
                std.Io.Timestamp.fromNanoseconds(0);
            if (!try delivery.publication.appendDeliveryPropertiesMany(
                properties,
                self.allocator,
                connection.protocol,
                delivery.identifiersInto(identifiers),
                delivery_now,
            )) {
                delivery.deinit();
                continue;
            }
            const outgoing_topic = try connection
                .prepareAutomaticTopicAliasAssumeCapacity(
                visible_topic,
                properties,
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
            if (packet_id) |id| {
                if (inflight_payload_limit != 0) {
                    slot.recordTransientInflight(
                        id,
                        delivery.publication.payload().len,
                    );
                }
            }
            self.recordPublishSent(delivery.publication.payload().len);
            delivery.deinit();
        }
    }

    /// Reserve and detach one Session transmission while the caller holds the
    /// state lock.
    ///
    /// `drainInto` mutates queued/inflight ownership. Deep copying before
    /// unlocking guarantees its views cannot be invalidated by an ACK or
    /// takeover, while detached scratch keeps encoding and network I/O outside
    /// the global lock.
    fn takeSessionPacketAssumeLocked(
        self: *Broker,
        slot: *ClientSlot,
        persistent_changed_out: *bool,
        more_pending_out: *bool,
    ) Error!?DetachedSessionPacket {
        persistent_changed_out.* = false;
        more_pending_out.* = false;
        const handle = slot.sessionHandle() orelse return null;
        const connection = slot.connection orelse return null;
        const route_id = try self.sessions.routeId(handle);
        const authorizers = self.deliveryAuthorizers(slot.accessControl());
        const client_id = if (authorizers.configured())
            try self.sessions.clientId(handle)
        else
            &.{};
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
                netz_runtime.cachedAwakeNow(self.io),
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
                authorizers.configured() and
                !authorizers.authorize(.{
                    .client_id = client_id,
                    .username = slot.username(),
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
            var wire_transmission = transmission;
            const payload_len = switch (wire_transmission) {
                .publish => |*publish| blk: {
                    publish.topic = connection.visibleTopic(
                        publish.topic,
                    ) catch |err| switch (err) {
                        error.TopicOutsideNamespace => {
                            // A durable Session may reconnect through a
                            // listener with a different mount point. Drop a
                            // queued publication outside that listener's view
                            // without blocking later visible messages.
                            const drop_action = try self.sessions
                                .dropOutgoingPublish(
                                handle,
                                publish.packet_id,
                            );
                            persistent_changed = persistent_changed or
                                (persistent_session and
                                    drop_action == .dropped);
                            continue;
                        },
                        else => return err,
                    };
                    break :blk publish.payload.len;
                },
                .pubrel => 0,
            };
            const buffers = try slot.ensureBuffers(self.allocator);
            const detached = session_route.detachTransmission(
                &buffers.session_write_scratch,
                &buffers.session_property_scratch,
                self.allocator,
                wire_transmission,
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
            more_pending_out.* =
                (try self.sessions.hasUnselectedTransmission(handle)) or
                slot.queuedCount() != 0;
            persistent_changed_out.* = persistent_changed;
            self.recordPersistentChangeLocked(persistent_changed);
            return .{
                .detached = detached,
                .payload_len = payload_len,
                .handle = handle,
                .route_id = route_id,
            };
        }
    }

    fn runDeadlineDriver(
        self: *Broker,
    ) ?anyerror {
        while (!self.deadline_driver.stopped()) {
            const now = std.Io.Clock.awake.now(self.io);
            try self.processDueLifecycle(now);

            self.state_mutex.lockUncancelable(self.io);
            // `$SYS` publication itself uses the state lock and ordinary
            // routing. Decide whether it is due here, but advance the next
            // deadline only after a complete snapshot is published. A failed
            // update is therefore retryable instead of silently skipped.
            var publish_system_stats = false;
            var system_stats_schedule_generation: u64 = 0;
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
                    system_stats_schedule_generation =
                        self.system_stats_schedule_generation;
                }
            } else {
                self.next_system_stats_ns = null;
            }
            const lifecycle_deadline = earliestDeadline(
                self.wills.nextDeadline(),
                self.sessions.nextExpiryDeadline(),
            );
            const retained_deadline = earliestDeadline(
                lifecycle_deadline,
                if (self.next_retained_expiry_ns) |value|
                    .{ .nanoseconds = value }
                else
                    null,
            );
            const deadline = earliestDeadline(
                retained_deadline,
                if (self.next_system_stats_ns) |value|
                    .{ .nanoseconds = value }
                else
                    null,
            );
            const generation =
                self.deadline_driver.currentGeneration();
            self.state_mutex.unlock(self.io);
            if (publish_system_stats) {
                self.publishSystemStats() catch |err| return err;
                self.state_mutex.lockUncancelable(self.io);
                if (self.system_stats_schedule_generation ==
                    system_stats_schedule_generation)
                {
                    if (self.options.system_stats_interval) |interval| {
                        // Skip missed ticks instead of bursting stale snapshots
                        // after a long scheduling pause.
                        self.next_system_stats_ns =
                            std.Io.Clock.awake.now(self.io)
                                .addDuration(interval).nanoseconds;
                    } else {
                        self.next_system_stats_ns = null;
                    }
                }
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

    fn processDueLifecycle(
        self: *Broker,
        now: std.Io.Timestamp,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        var expired_retained_count: usize = 0;
        if (self.options.retained_expiry_interval) |interval| {
            if (self.next_retained_expiry_ns) |deadline| {
                if (now.nanoseconds >= deadline) {
                    expired_retained_count = self.retained.pruneExpired(now);
                    // Skip missed ticks instead of repeatedly scanning after a
                    // long scheduler pause.
                    self.next_retained_expiry_ns =
                        now.addDuration(interval).nanoseconds;
                }
            } else {
                self.next_retained_expiry_ns =
                    now.addDuration(interval).nanoseconds;
            }
        }
        const expired_session_count =
            self.pruneExpiredSessionRoutesLocked(now);
        var published_any = false;
        var persistent_changed =
            expired_retained_count != 0 or expired_session_count != 0;
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
        self.state_mutex.unlock(self.io);

        if (published_any or persistent_changed) {
            try self.finalizePersistentChange(
                persistent_changed,
                persistent_changed,
            );
        }
        if (published_any) try self.flushAllSlots();
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
                    .username = will.source_username,
                    .listener_id = will.source_listener_id,
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
            false,
            publisher_id,
            publish,
            will.client_id,
            will.source_username,
            will.source_listener_id,
            self.options.upgrade_outgoing_qos,
            now,
            &progress.persistent_changed,
            &progress.publication_effect_committed,
            null,
            null,
        );
        defer plan.deinit(self.allocator);

        // The state lock cannot be held across socket writes. Queue ownership
        // is committed at this point; the timer loop releases the lock before
        // flushing all active slots below.
    }

    fn createRoutePublicationLocked(
        self: *Broker,
        publish: mqtt.Publish,
        reference_count: usize,
        now: std.Io.Timestamp,
        prefixed_packet: ?*runtime.OwnedPacket,
        pending_qos2: ?*qos2_mod.Pending,
    ) Error!*Publication {
        if (pending_qos2) |pending| {
            if (pending.canAdoptPublication()) {
                return self.pending_qos2.adoptPublication(
                    pending,
                    publish,
                    reference_count,
                    now,
                );
            }
        }
        return createRoutePublication(
            self.allocator,
            publish,
            reference_count,
            now,
            prefixed_packet,
        );
    }
};

test "legacy private bridge subscriptions prevent loops and preserve retain" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1 }) |protocol| {
        const bridge_connect = mqtt.Connect{
            .protocol = protocol,
            .bridge_mode = true,
            .clean_start = false,
            .keep_alive_seconds = 60,
            .client_id = "bridge",
        };
        var subscription = mqtt.Subscription{
            .topic_filter = "sensors/#",
            .qos = .at_least_once,
        };
        Broker.applyPrivateBridgeSubscriptionPolicy(
            bridge_connect,
            &subscription,
        );
        try std.testing.expect(subscription.no_local);
        try std.testing.expect(subscription.retain_as_published);

        var ordinary = mqtt.Subscription{
            .topic_filter = "sensors/#",
            .qos = .at_least_once,
        };
        var ordinary_connect = bridge_connect;
        ordinary_connect.bridge_mode = false;
        Broker.applyPrivateBridgeSubscriptionPolicy(ordinary_connect, &ordinary);
        try std.testing.expect(!ordinary.no_local);
        try std.testing.expect(!ordinary.retain_as_published);
    }
}

fn createRoutePublication(
    allocator: std.mem.Allocator,
    publish: mqtt.Publish,
    reference_count: usize,
    now: std.Io.Timestamp,
    prefixed_packet: ?*runtime.OwnedPacket,
) Error!*Publication {
    if (prefixed_packet) |packet| {
        if (packet.prefixedAllocation()) |allocation| {
            const publication = try Publication.createFromPrefixedPublish(
                allocator,
                publish,
                reference_count,
                now,
                allocation,
                packet.bytes,
            );
            packet.owns_bytes = false;
            packet.prefix_len = 0;
            return publication;
        }
    }
    return Publication.createFromPublish(
        allocator,
        publish,
        reference_count,
        now,
    );
}

fn clientMayPublishTopic(topic: []const u8) bool {
    if (std.mem.startsWith(u8, topic, "$share")) return false;
    if (!std.mem.startsWith(u8, topic, "$SYS")) return true;
    return mqtt.topicMatchesFilter(
        topic,
        "$SYS/broker/connection/+/state",
    );
}

test "MQTT broker transfers prefixed packet ownership to Publication" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const packet_len = 80;
    const allocation = try failing.allocator().alignedAlloc(
        u8,
        .@"16",
        @sizeOf(Publication) + packet_len,
    );
    const wire = allocation[@sizeOf(Publication)..];
    @memset(wire, 0xaa);
    @memcpy(wire[9..22], "adopted/topic");
    @memcpy(wire[43..50], "payload");
    var packet = runtime.OwnedPacket{
        .bytes = wire,
        .fixed = undefined,
        .prefix_len = @sizeOf(Publication),
    };
    defer packet.deinit(failing.allocator());

    const publication = try createRoutePublication(
        failing.allocator(),
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = wire[9..22],
            .packet_id = 17,
            .properties = &.{},
            .payload = wire[43..50],
        },
        2,
        std.Io.Timestamp.fromNanoseconds(0),
        &packet,
    );
    defer publication.release();
    defer publication.release();

    try std.testing.expectEqual(@as(u16, 0), packet.prefix_len);
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualStrings("adopted/topic", publication.topic());
    try std.testing.expectEqualStrings("payload", publication.payload());
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

test "MQTT delivery queues use bounded eager staging and lazy growth" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(Delivery));
    }
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const queue_capacity = 1_024;
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = queue_capacity,
        },
        .session = .{ .max_sessions = 2 },
    });
    defer broker.deinit();

    const publisher_slot = try broker.claimSlot();
    var publisher_progress: RegistrationProgress = .{};
    _ = try broker.register(
        publisher_slot,
        .{
            .protocol = .v5,
            .clean_start = true,
            .keep_alive_seconds = 30,
            .client_id = "publisher-only",
        },
        null,
        null,
        broker.options.auto_client_id_prefix,
        &publisher_progress,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        if (broker.slots[publisher_slot].buffers) |buffers|
            buffers.queue.capacity
        else
            0,
    );
    broker.abortRegistration(
        publisher_slot,
        0,
        publisher_progress.rollback_changed,
    );
    broker.releaseClaimedSlot(publisher_slot);

    const now = std.Io.Clock.awake.now(io);
    const stored = try broker.sessions.open(
        "returning-subscriber",
        false,
        60,
        now,
    );
    _ = try broker.sessions.setSubscription(
        stored.handle,
        .{ .topic_filter = "queue/#", .qos = .at_least_once },
        null,
    );
    try broker.sessions.disconnect(stored.handle, null, now);

    const subscriber_slot = try broker.claimSlot();
    var subscriber_progress: RegistrationProgress = .{};
    var resume_properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    const subscriber_registration = try broker.register(
        subscriber_slot,
        .{
            .protocol = .v5,
            .clean_start = false,
            .keep_alive_seconds = 30,
            .client_id = "returning-subscriber",
            .properties = &resume_properties,
        },
        null,
        null,
        broker.options.auto_client_id_prefix,
        &subscriber_progress,
    );
    try std.testing.expectEqual(
        @as(usize, transient_delivery_async_high_watermark),
        broker.slots[subscriber_slot].buffers.?.queue.capacity,
    );
    try std.testing.expect(
        broker.slots[subscriber_slot].buffers.?.queue.capacity <
            queue_capacity,
    );
    broker.abortRegistration(
        subscriber_slot,
        subscriber_registration.subscriber_id,
        subscriber_progress.rollback_changed,
    );
    try std.testing.expect(broker.slots[subscriber_slot].buffers == null);
    broker.releaseClaimedSlot(subscriber_slot);
}

test "MQTT delivery queue growth is transactional and bounded" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(allocator);

    try slot.ensureDeliveryCapacity(allocator, 2);
    const buffers = slot.buffers.?;
    buffers.route_reservations = 2;

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        slot.ensureDeliveryReservationCapacity(
            failing.allocator(),
            1,
            64,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), buffers.queue.capacity);
    try std.testing.expectEqual(@as(usize, 2), buffers.route_reservations);

    buffers.route_reservations = 0;
    try slot.ensureDeliveryReservationCapacity(allocator, 3, 64);
    try std.testing.expect(buffers.queue.capacity >= 3);
    try std.testing.expect(buffers.queue.capacity <= 64);

    var no_allocation = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try slot.ensureDeliveryReservationCapacity(
        no_allocation.allocator(),
        1,
        64,
    );
    try std.testing.expect(!no_allocation.has_induced_failure);
}

test "MQTT delivery queue reservations reclaim a consumed prefix" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(allocator);
    try slot.ensureDeliveryCapacity(allocator, 4);

    const publication = try Publication.createFromPublish(
        allocator,
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "queue/compact",
            .packet_id = 1,
            .properties = &.{},
            .payload = "payload",
        },
        2,
        std.Io.Timestamp.fromNanoseconds(0),
    );
    const buffers = slot.buffers.?;
    buffers.queue.items.len = 4;
    buffers.queue.items[2] = .{
        .publication = publication,
        .qos = .at_least_once,
        .retain = false,
    };
    buffers.queue.items[3] = .{
        .publication = publication,
        .qos = .at_least_once,
        .retain = false,
    };
    buffers.queue_head = 2;

    var no_allocation = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try slot.ensureDeliveryReservationCapacity(
        no_allocation.allocator(),
        2,
        64,
    );
    try std.testing.expect(!no_allocation.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), buffers.queue_head);
    try std.testing.expectEqual(@as(usize, 2), buffers.queue.items.len);
    try std.testing.expectEqual(@as(usize, 4), buffers.queue.capacity);
    try std.testing.expectEqual(publication, buffers.queue.items[0].publication);
    try std.testing.expectEqual(publication, buffers.queue.items[1].publication);
}

test "MQTT offline durable fanout adopts and shares prefixed publication bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
        .session = .{
            .max_sessions = 2,
            .max_queued_per_session = 2,
        },
    });
    defer broker.deinit();

    var handles: [2]session_mod.Handle = undefined;
    for (&handles, 0..) |*handle, index| {
        var client_id: [32]u8 = undefined;
        const opened = try broker.sessions.open(
            try std.fmt.bufPrint(&client_id, "offline-{d}", .{index}),
            false,
            60,
            .zero,
        );
        handle.* = opened.handle;
        _ = try broker.sessions.setSubscription(
            opened.handle,
            .{ .topic_filter = "shared/#", .qos = .at_least_once },
            null,
        );
        _ = try broker.router.subscribeWithIdentifierStatus(
            sessionSubscriberId(opened.route_id),
            .{ .topic_filter = "shared/#", .qos = .at_least_once },
            null,
        );
        try broker.sessions.disconnect(opened.handle, null, .zero);
    }

    var persistent_changed = false;
    var publication_committed = false;
    const packet_len = 64;
    const allocation = try allocator.alignedAlloc(
        u8,
        .@"16",
        @sizeOf(Publication) + packet_len,
    );
    const wire = allocation[@sizeOf(Publication)..];
    @memset(wire, 0xaa);
    @memcpy(wire[5..17], "shared/topic");
    @memcpy(wire[31..45], "shared-payload");
    var packet = runtime.OwnedPacket{
        .bytes = wire,
        .fixed = undefined,
        .prefix_len = @sizeOf(Publication),
    };
    defer packet.deinit(allocator);
    var plan = try broker.enqueuePublishLocked(
        false,
        null,
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = wire[5..17],
            .packet_id = 1,
            .properties = &.{},
            .payload = wire[31..45],
        },
        null,
        null,
        null,
        false,
        .zero,
        &persistent_changed,
        &publication_committed,
        &packet,
        null,
    );
    defer plan.deinit(allocator);
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqual(@as(u16, 0), packet.prefix_len);
    try std.testing.expect(persistent_changed);
    try std.testing.expect(publication_committed);
    try std.testing.expectEqual(@as(usize, 0), plan.deliveries.len);
    try std.testing.expectEqual(@as(usize, 0), plan.session_deliveries.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        plan.synchronous_session_targets.len,
    );

    var first_output: [1]session_mod.Transmission = undefined;
    var second_output: [1]session_mod.Transmission = undefined;
    const first = try broker.sessions.drainInto(
        handles[0],
        .zero,
        1,
        &first_output,
    );
    const second = try broker.sessions.drainInto(
        handles[1],
        .zero,
        1,
        &second_output,
    );
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(
        first[0].publish.topic.ptr,
        second[0].publish.topic.ptr,
    );
    try std.testing.expectEqual(
        first[0].publish.payload.ptr,
        second[0].publish.payload.ptr,
    );
    try std.testing.expectEqual(wire.ptr, first[0].publish.topic.ptr);
    try std.testing.expectEqualStrings("shared/topic", first[0].publish.topic);
    try std.testing.expectEqualStrings(
        "shared-payload",
        first[0].publish.payload,
    );
}

test "MQTT released QoS 2 fanout adopts pending publication bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
        .session = .{
            .max_sessions = 2,
            .max_queued_per_session = 2,
        },
    });
    defer broker.deinit();

    var handles: [2]session_mod.Handle = undefined;
    for (&handles, 0..) |*handle, index| {
        var client_id: [32]u8 = undefined;
        const opened = try broker.sessions.open(
            try std.fmt.bufPrint(&client_id, "qos2-offline-{d}", .{index}),
            false,
            60,
            .zero,
        );
        handle.* = opened.handle;
        _ = try broker.sessions.setSubscription(
            opened.handle,
            .{ .topic_filter = "qos2/shared/#", .qos = .exactly_once },
            null,
        );
        _ = try broker.router.subscribeWithIdentifierStatus(
            sessionSubscriberId(opened.route_id),
            .{ .topic_filter = "qos2/shared/#", .qos = .exactly_once },
            null,
        );
        try broker.sessions.disconnect(opened.handle, null, .zero);
    }

    try std.testing.expect(try broker.pending_qos2.recordWithSourceAndPublicationPrefix(
        77,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "qos2/shared/topic",
            .packet_id = 9,
            .payload = "pending-payload",
        },
        "publisher",
        null,
        null,
        .zero,
        true,
    ));
    var pending = broker.pending_qos2.take(77, 9).?;
    var pending_live = true;
    defer if (pending_live) broker.pending_qos2.recycle(&pending);
    const message_pointer = pending.bytes.ptr;
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    const publish = (try pending.asPublish(9, .zero, &properties)).?;
    var plan = try broker.enqueuePublishLocked(
        false,
        null,
        publish,
        null,
        null,
        null,
        false,
        .zero,
        null,
        null,
        null,
        &pending,
    );
    defer plan.deinit(allocator);
    try std.testing.expect(!pending.canAdoptPublication());
    broker.pending_qos2.recycle(&pending);
    pending_live = false;

    var first_output: [1]session_mod.Transmission = undefined;
    var second_output: [1]session_mod.Transmission = undefined;
    const first = try broker.sessions.drainInto(
        handles[0],
        .zero,
        1,
        &first_output,
    );
    const second = try broker.sessions.drainInto(
        handles[1],
        .zero,
        1,
        &second_output,
    );
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(message_pointer, first[0].publish.topic.ptr);
    try std.testing.expectEqual(
        first[0].publish.topic.ptr,
        second[0].publish.topic.ptr,
    );
    try std.testing.expectEqual(
        first[0].publish.payload.ptr,
        second[0].publish.payload.ptr,
    );
}

test "MQTT publisher route plans reuse bounded slot storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
    });
    defer broker.deinit();

    const slot_index = try broker.claimSlot();
    const slot = &broker.slots[slot_index];
    slot.state.generation = @intCast(nextConnectionGeneration(
        slot.state.generation,
    ));
    const publisher_id = subscriberId(slot_index, slot.state.generation);
    try broker.router.subscribe(20, .{ .topic_filter = "tasks/#" });
    try broker.router.subscribe(10, .{ .topic_filter = "$share/g/tasks/+" });
    try broker.router.subscribe(11, .{ .topic_filter = "$share/g/tasks/+" });

    var first = try broker.matchRoutesForPublisherLocked(
        publisher_id,
        publisher_id,
        "tasks/a",
    );
    try std.testing.expect(first.scratch_owner != null);
    try std.testing.expectEqual(@as(usize, 2), first.items.len);
    try std.testing.expectEqual(@as(router_mod.SubscriberId, 10), first.items[1].subscriber_id);
    const scratch_ptr = first.items.ptr;
    first.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        slot.buffers.?.route_matches.items.len,
    );

    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        broker.allocator = failing.allocator();
        defer broker.allocator = allocator;
        var second = try broker.matchRoutesForPublisherLocked(
            publisher_id,
            publisher_id,
            "tasks/b",
        );
        defer second.deinit(broker.allocator);
        try std.testing.expect(second.scratch_owner != null);
        try std.testing.expectEqual(scratch_ptr, second.items.ptr);
        try std.testing.expectEqual(@as(router_mod.SubscriberId, 11), second.items[1].subscriber_id);
        try std.testing.expect(!failing.has_induced_failure);
    }

    // Keep retained per-publisher memory bounded. Larger subscription sets
    // fall back before matching, so an allocation failure cannot advance the
    // shared group's round-robin cursor.
    for (30..60) |id| {
        try broker.router.subscribe(
            @intCast(id),
            .{ .topic_filter = "tasks/#" },
        );
    }
    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        broker.allocator = failing.allocator();
        defer broker.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            broker.matchRoutesForPublisherLocked(
                publisher_id,
                publisher_id,
                "tasks/c",
            ),
        );
    }
    var fallback = try broker.matchRoutesForPublisherLocked(
        null,
        publisher_id,
        "tasks/c",
    );
    defer fallback.deinit(allocator);
    try std.testing.expect(fallback.scratch_owner == null);
    try std.testing.expectEqual(@as(usize, 32), fallback.items.len);
    try std.testing.expectEqual(
        @as(router_mod.SubscriberId, 10),
        fallback.items[fallback.items.len - 1].subscriber_id,
    );

    slot.clearBuffers(allocator);
    broker.releaseClaimedSlot(slot_index);
}

test "MQTT Clean Start journals only committed Session replacement" {
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

    // Failure while preparing the replacement must preserve the durable
    // Session and must not journal a deletion that never committed.
    const slot_index = try broker.claimSlot();
    var slot_claimed = true;
    defer if (slot_claimed) broker.releaseClaimedSlot(slot_index);
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
            null,
            broker.options.auto_client_id_prefix,
            &progress,
        ),
    );
    try std.testing.expect(!progress.rollback_changed);
    try std.testing.expectEqual(@as(?session_mod.Handle, old.handle), broker.sessions.find(
        "failed-clean-start",
        std.Io.Clock.awake.now(io),
    ));
    try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), broker.pending_qos2.count());
    failing.fail_index = std.math.maxInt(usize);
    broker.finishPartialPersistentChange(progress.rollback_changed);

    {
        var rejected_image = try Broker.init(backing, io, .{
            .limits = .{ .max_connections = 1 },
        });
        defer rejected_image.deinit();
        try rejected_image.restoreCommitLog(tmp.dir, "failed-clean.log", .{});
        try std.testing.expect(rejected_image.sessions.find(
            "failed-clean-start",
            std.Io.Clock.awake.now(io),
        ) != null);
        try std.testing.expectEqual(@as(usize, 1), rejected_image.router.subscriptionCount());
        try std.testing.expectEqual(@as(usize, 1), rejected_image.pending_qos2.count());
    }

    // Once replacement commits, aborting the provisional connection at the
    // CONNACK boundary must persist its deletion of the prior durable state.
    progress = .{};
    const registration = try broker.register(slot_index, .{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 30,
        .client_id = "failed-clean-start",
    }, null, null, broker.options.auto_client_id_prefix, &progress);
    try std.testing.expect(progress.rollback_changed);
    broker.abortRegistration(slot_index, registration.subscriber_id, progress.rollback_changed);
    broker.releaseClaimedSlot(slot_index);
    slot_claimed = false;
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
    const packet_storage_capacity = 128;

    broker: *Broker,
    slot_index: usize,
    subscriber_id: router_mod.SubscriberId,
    connect: runtime.OwnedConnect,
    result: *?anyerror,
    listener_capacity: ?*ListenerCapacity = null,

    fn run(task: ClientTask) std.Io.Cancelable!void {
        var connect = task.connect;
        const slot = &task.broker.slots[task.slot_index];
        // The slot's username view borrows CONNECT storage. Register the
        // teardown after this defer so unregister clears that view before
        // OwnedConnect releases the packet or replacement identity.
        defer connect.deinit(task.broker.allocator);
        const connection = slot.connection.?;
        defer task.broker.unregister(
            task.slot_index,
            task.subscriber_id,
            task.listener_capacity,
        ) catch |err| {
            task.result.* = err;
        };

        var read_error: ?anyerror = null;
        task.runLoop(slot, connection, connect.connect) catch |err| {
            if (!ungracefulTransportClose(err)) read_error = err;
        };
        const writer_error = task.stopDeliveryWriter(slot);
        const session_writer_error = task.takeSessionDeliveryWriterError(slot);
        if (read_error) |err| task.result.* = err;
        if (writer_error) |err| {
            if (!ungracefulTransportClose(err) and task.result.* == null) {
                task.result.* = err;
            }
        }
        if (session_writer_error) |err| {
            if (!ungracefulTransportClose(err) and task.result.* == null) {
                task.result.* = err;
            }
        }
    }

    fn ensureDeliveryWriter(
        task: ClientTask,
        slot: *ClientSlot,
    ) (std.mem.Allocator.Error || std.Io.ConcurrentError)!void {
        if (slot.buffers) |buffers| {
            if (buffers.delivery_writer != null) return;
        }
        task.broker.state_mutex.lockUncancelable(task.broker.io);
        const session_persistent = slot.state.session_persistent;
        task.broker.state_mutex.unlock(task.broker.io);
        if (session_persistent) return;

        const buffers = try slot.ensureBuffers(task.broker.allocator);
        const writer = try task.broker.allocator.create(DeliveryWriter);
        errdefer task.broker.allocator.destroy(writer);
        writer.* = .{
            .future = undefined,
        };
        writer.future = try std.Io.concurrent(
            task.broker.io,
            DeliveryWriterTask.run,
            .{
                task.broker,
                task.slot_index,
                &writer.stop,
            },
        );
        task.broker.state_mutex.lockUncancelable(task.broker.io);
        buffers.delivery_writer = writer;
        task.broker.state_mutex.unlock(task.broker.io);
    }

    fn stopDeliveryWriter(
        task: ClientTask,
        slot: *ClientSlot,
    ) ?anyerror {
        task.broker.state_mutex.lockUncancelable(task.broker.io);
        const buffers = slot.buffers orelse {
            task.broker.state_mutex.unlock(task.broker.io);
            return null;
        };
        const writer = buffers.delivery_writer orelse {
            task.broker.state_mutex.unlock(task.broker.io);
            return null;
        };
        buffers.delivery_writer = null;
        task.broker.state_mutex.unlock(task.broker.io);
        defer task.broker.allocator.destroy(writer);
        writer.stop.store(true, .release);
        slot.delivery_ready.set(task.broker.io);
        const writer_error = writer.future.cancel(task.broker.io);
        slot.delivery_ready.reset();
        if (writer_error) |err| return switch (err) {
            error.Canceled => null,
            else => err,
        };
        return null;
    }

    fn takeSessionDeliveryWriterError(
        task: ClientTask,
        _: *ClientSlot,
    ) ?anyerror {
        return task.broker.session_delivery_writers.takeError(
            task.broker.io,
            task.slot_index,
        );
    }

    /// Finish one acknowledgement while retaining the connection's writer
    /// ownership across the resulting durable Session flush. The caller has
    /// already locked `slot.writer_mutex`; every return path releases it.
    fn flushAcknowledgedSessionWhileLocked(
        task: ClientTask,
        slot: *ClientSlot,
        should_flush: bool,
    ) Error!void {
        defer slot.writer_mutex.unlock(task.broker.io);
        if (should_flush) {
            try task.broker.flushSlotLocked(slot, true);
        }
    }

    /// Consume the state lock already held by the ACK handler and release the
    /// writer on every result. Returning false leaves both locks untouched so
    /// callers can run the persistence-aware path without a second protocol
    /// branch.
    fn tryFlushAcknowledgedSessionWithStateLocked(
        task: ClientTask,
        slot: *ClientSlot,
        session_ack: SessionAckResult,
    ) Error!bool {
        if (!session_ack.owned or
            !task.broker.canCoalesceAcknowledgedSessionFlushLocked())
        {
            return false;
        }
        defer slot.writer_mutex.unlock(task.broker.io);
        try task.broker.flushSlotAssumeStateLocked(slot, true);
        return true;
    }

    fn runLoop(
        task: ClientTask,
        slot: *ClientSlot,
        connection: *runtime.Connection,
        connect: mqtt.Connect,
    ) !void {
        // Common small PUBLISH packets as well as ACK/PING/DISCONNECT fit here
        // and can borrow this storage for one event-loop turn. Larger packets
        // retain the owned-allocation path without inflating every task stack
        // to the transport's complete read-ahead capacity.
        var packet_storage: [packet_storage_capacity]u8 = undefined;
        while (true) {
            var event: runtime.BrokerEvent = undefined;
            connection.readBrokerEventWithKeepAliveIntoPrefixedOut(
                &packet_storage,
                @sizeOf(Publication),
                &event,
            ) catch |err| {
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
                    if (!connection.isUsable()) return;
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
                    if (subscriptionsNeedDeliveryWriter(
                        connection.localMaximumQoS(),
                        owned.subscribe.subscriptions,
                    )) {
                        try task.ensureDeliveryWriter(slot);
                    }
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
                        owned,
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
                    if (try task.tryFlushAcknowledgedSessionWithStateLocked(
                        slot,
                        session_ack,
                    )) continue;
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
                        const transient_owned = slot.hasTransientInflight(
                            owned.ack.packet_id,
                        );
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
                        if (transient_owned) {
                            std.debug.assert(slot.releaseTransientInflight(
                                owned.ack.packet_id,
                            ));
                        }
                    }
                    try task.flushAcknowledgedSessionWhileLocked(
                        slot,
                        true,
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
                    if (try task.tryFlushAcknowledgedSessionWithStateLocked(
                        slot,
                        session_ack,
                    )) continue;
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
                    var transient_completed = false;
                    if (!session_ack.owned) {
                        if (connection.hasOutgoingPacketIdentifier(
                            owned.ack.packet_id,
                        )) {
                            const transient_owned = slot.hasTransientInflight(
                                owned.ack.packet_id,
                            );
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
                            if (!owned.ack.accepted()) {
                                transient_completed = true;
                                if (transient_owned) {
                                    std.debug.assert(
                                        slot.releaseTransientInflight(
                                            owned.ack.packet_id,
                                        ),
                                    );
                                }
                            }
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
                    try task.flushAcknowledgedSessionWhileLocked(
                        slot,
                        session_ack.owned or transient_completed,
                    );
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
                    if (try task.tryFlushAcknowledgedSessionWithStateLocked(
                        slot,
                        session_ack,
                    )) continue;
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
                        const transient_owned = slot.hasTransientInflight(
                            owned.ack.packet_id,
                        );
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
                        if (transient_owned) {
                            std.debug.assert(slot.releaseTransientInflight(
                                owned.ack.packet_id,
                            ));
                        }
                    }
                    try task.flushAcknowledgedSessionWhileLocked(
                        slot,
                        true,
                    );
                },
                .pingreq => {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    // A PINGRESP is an observable ordering barrier for this
                    // connection. Preserve the pre-writer behavior by
                    // draining every earlier routed PUBLISH first.
                    task.broker.flushSlotLocked(slot, true) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
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

const DeliveryWriterTask = struct {
    fn run(
        broker: *Broker,
        slot_index: usize,
        stop: *std.atomic.Value(bool),
    ) ?anyerror {
        const slot = &broker.slots[slot_index];
        while (true) {
            slot.delivery_ready.waitUncancelable(broker.io);
            // Reset before draining so a notification racing with the drain
            // remains set for the next turn instead of being lost afterward.
            slot.delivery_ready.reset();
            if (stop.load(.acquire)) return null;
            slot.writer_mutex.lockUncancelable(broker.io);
            defer slot.writer_mutex.unlock(broker.io);
            broker.flushSlotLocked(slot, false) catch |err| {
                if (slot.connection) |connection| {
                    connection.interrupt() catch {};
                }
                return err;
            };
        }
    }
};

const ListenerCapacity = struct {
    limit: usize,
    active: usize = 0,
    mutex: std.Io.Mutex = .init,

    fn claim(self: *ListenerCapacity, io: std.Io) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.active >= self.limit) return false;
        self.active += 1;
        return true;
    }

    fn release(self: *ListenerCapacity, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.active != 0);
        self.active -= 1;
    }
};

const ListenerAcceptTask = struct {
    broker: *Broker,
    listener: Listener,
    capacity: *ListenerCapacity,
    result: *?anyerror,

    fn run(task: ListenerAcceptTask) std.Io.Cancelable!void {
        const client_task = task.acceptClient() catch |err| {
            task.result.* = err;
            return;
        } orelse return;
        ClientTask.run(client_task) catch |err| {
            task.result.* = err;
        };
    }

    // Admission owns parsed CONNECT and policy temporaries that are much
    // larger than the steady-state broker read loop. Return the compact
    // ClientTask before parking on that loop so its long-lived stack does not
    // touch the full admission high-water mark.
    noinline fn acceptClient(task: ListenerAcceptTask) anyerror!?ClientTask {
        const pending = try task.acceptPendingOwned();
        var pending_owned = true;
        defer if (pending_owned) {
            pending.deinit(task.broker.allocator);
            task.broker.allocator.destroy(pending);
        };
        if (!task.capacity.claim(task.broker.io)) {
            return null;
        }
        var capacity_claimed = true;
        defer if (capacity_claimed) {
            task.capacity.release(task.broker.io);
        };
        const slot_index = task.broker.claimSlot() catch |err| {
            // Capacity rejection is local to this newly accepted peer. Other
            // finite listener tasks may still complete after a live client
            // releases its slot.
            if (err == error.BrokerFull) return null;
            return err;
        };
        var slot_claimed = true;
        defer if (slot_claimed) {
            task.broker.releaseClaimedSlot(slot_index);
        };
        // `preparePending` consumes or deinitializes the pointed-to value on
        // every path; this frame retains ownership only of its allocation.
        pending_owned = false;
        defer task.broker.allocator.destroy(pending);
        var accept_options = task.listener.accept orelse
            task.broker.options.accept;
        var auto_client_id_prefix = task.listener.auto_client_id_prefix orelse
            task.broker.options.auto_client_id_prefix;
        var admission_snapshot: ListenerAdmissionSnapshot = undefined;
        if (task.listener.admission_policy) |provider| {
            admission_snapshot = provider.snapshot(provider.context);
            accept_options.allow_zero_length_client_id =
                admission_snapshot.allow_zero_length_client_id;
            accept_options.maximum_qos = admission_snapshot.maximum_qos;
            accept_options.maximum_keep_alive_seconds =
                admission_snapshot.maximum_keep_alive_seconds;
            accept_options.topic_alias_maximum =
                admission_snapshot.topic_alias_maximum;
            accept_options.max_outgoing_topic_aliases =
                admission_snapshot.max_outgoing_topic_aliases;
            accept_options.retain_available =
                admission_snapshot.retain_available;
            accept_options.accepted_protocol_versions =
                admission_snapshot.accepted_protocol_versions;
            auto_client_id_prefix = admission_snapshot.autoClientIdPrefix();
        }
        var client_task = try task.broker.preparePending(
            slot_index,
            pending,
            task.listener.namespace,
            accept_options,
            task.listener.authorization,
            auto_client_id_prefix,
            task.result,
        ) orelse {
            slot_claimed = false;
            task.broker.releaseClaimedSlot(slot_index);
            return null;
        };
        slot_claimed = false;
        client_task.listener_capacity = task.capacity;
        capacity_claimed = false;
        return client_task;
    }

    noinline fn acceptPendingOwned(
        task: ListenerAcceptTask,
    ) anyerror!*runtime.PendingAcceptedClient {
        const pending = try task.broker.allocator.create(
            runtime.PendingAcceptedClient,
        );
        errdefer task.broker.allocator.destroy(pending);
        pending.* = try task.listener.source.acceptPending(
            task.listener.accept orelse task.broker.options.accept,
        );
        return pending;
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
    capacity: *ListenerCapacity,
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
            if (!task.capacity.claim(task.supervisor.broker.io)) {
                pending.deinit(task.supervisor.broker.allocator);
                continue;
            }
            var capacity_claimed = true;
            defer if (capacity_claimed) {
                task.capacity.release(task.supervisor.broker.io);
            };
            const slot_index = task.supervisor.broker.claimSlot() catch |err| {
                pending.deinit(task.supervisor.broker.allocator);
                if (err == error.BrokerFull) continue;
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
            var accept_options = task.listener.accept orelse
                task.supervisor.broker.options.accept;
            var auto_client_id_prefix = task.listener.auto_client_id_prefix orelse
                task.supervisor.broker.options.auto_client_id_prefix;
            var admission_snapshot: ListenerAdmissionSnapshot = undefined;
            if (task.listener.admission_policy) |provider| {
                admission_snapshot = provider.snapshot(provider.context);
                accept_options.allow_zero_length_client_id =
                    admission_snapshot.allow_zero_length_client_id;
                accept_options.maximum_qos = admission_snapshot.maximum_qos;
                accept_options.maximum_keep_alive_seconds =
                    admission_snapshot.maximum_keep_alive_seconds;
                accept_options.topic_alias_maximum =
                    admission_snapshot.topic_alias_maximum;
                accept_options.max_outgoing_topic_aliases =
                    admission_snapshot.max_outgoing_topic_aliases;
                accept_options.retain_available =
                    admission_snapshot.retain_available;
                accept_options.accepted_protocol_versions =
                    admission_snapshot.accepted_protocol_versions;
                auto_client_id_prefix =
                    admission_snapshot.autoClientIdPrefix();
            }
            var client_task = task.supervisor.broker.preparePending(
                slot_index,
                &pending,
                task.listener.namespace,
                accept_options,
                task.listener.authorization,
                auto_client_id_prefix,
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
            client_task.listener_capacity = task.capacity;
            capacity_claimed = false;
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
    return runtime.disconnectReasonForProtocolViolation(err, .server);
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

test "broker rejects invalid listener Client Identifier prefixes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.InvalidProperty,
        Broker.init(allocator, io, .{
            .limits = .{ .max_connections = 1 },
            .client_id_prefix = "bad\x00prefix",
        }),
    );
    var required_prefix = [_]u8{ 's', 'e', 'c', 'u', 'r', 'e', '-' };
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
        .client_id_prefix = &required_prefix,
    });
    defer broker.deinit();
    @memset(&required_prefix, 'x');
    try std.testing.expectEqualStrings(
        "secure-",
        broker.options.client_id_prefix,
    );

    try std.testing.expectError(
        error.InvalidProperty,
        broker.serveListeners(&.{.{
            .source = undefined,
            .auto_client_id_prefix = "x" ** 51,
            .connection_count = 0,
        }}),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        broker.serveListeners(&.{.{
            .source = undefined,
            .auto_client_id_prefix = "bad\x00prefix",
            .connection_count = 0,
        }}),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        broker.serveListeners(&.{.{
            .source = undefined,
            .max_connections = 0,
            .connection_count = 0,
        }}),
    );
    var shutdown: std.Io.Event = .unset;
    try std.testing.expectError(
        error.InvalidProperty,
        broker.serveListenersUntil(&.{.{
            .source = undefined,
            .max_connections = 0,
        }}, .{ .shutdown = &shutdown }),
    );
}

test "transient inflight payload accounting is lazy and clears safely" {
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(std.testing.allocator);

    try std.testing.expect(slot.buffers == null);
    try std.testing.expectEqual(
        @as(u32, 0),
        if (slot.buffers) |buffers|
            buffers.transient_inflight_payloads.capacity()
        else
            0,
    );
    try std.testing.expect(!slot.transientInflightPayloadLimitReached(10));
    const buffers = try slot.ensureBuffers(std.testing.allocator);
    try buffers.transient_inflight_payloads.ensureUnusedCapacity(
        std.testing.allocator,
        2,
    );
    slot.recordTransientInflight(1, 6);
    slot.recordTransientInflight(2, 6);
    try std.testing.expect(slot.transientInflightPayloadLimitReached(10));
    try std.testing.expect(!slot.releaseTransientInflight(99));
    try std.testing.expect(slot.releaseTransientInflight(1));
    try std.testing.expectEqual(
        @as(usize, 6),
        buffers.transient_inflight_payload_bytes,
    );
    slot.clearTransientInflight();
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.transient_inflight_payload_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.transient_inflight_payloads.count(),
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

fn validateAutoClientIdPrefix(prefix: []const u8) Error!void {
    if (prefix.len > client_id_mod.max_prefix_len) {
        return error.InvalidProperty;
    }
    try mqtt.validateUtf8String(prefix);
}

fn validateListenerAdmissionSnapshot(
    snapshot: ListenerAdmissionSnapshot,
) Error!void {
    try validateAutoClientIdPrefix(snapshot.autoClientIdPrefix());
    if (snapshot.maximum_keep_alive_seconds == 0 or
        !snapshot.accepted_protocol_versions.any())
    {
        return error.InvalidProperty;
    }
}

fn validateClientIdPrefix(prefix: []const u8) Error!void {
    if (prefix.len > std.math.maxInt(u16)) return error.InvalidProperty;
    mqtt.validateUtf8String(prefix) catch return error.InvalidProperty;
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
    _ = @import("broker/local_consumer_tests.zig");
}

test "broker retained expiry scan persists physical removal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var source = try Broker.init(allocator, io, .{
        .retained_expiry_interval = .fromMilliseconds(10),
        .persistent_change_autosave = .{
            .dir = tmp.dir,
            .sub_path = "expiry.db",
            .max_changes = 1,
        },
    });
    var source_owned = true;
    defer if (source_owned) source.deinit();
    const stored_at = std.Io.Clock.awake.now(io);
    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 1,
    } }};
    _ = try source.retained.applyPublish(
        "expiry/persisted",
        "value",
        .{
            .retain = true,
            .properties = &expiry,
            .now = stored_at,
        },
    );
    try source.createCommitLog(tmp.dir, "expiry.log", .{});

    // The first lifecycle pass establishes the periodic scan deadline. The
    // second crosses both that deadline and the retained message's lifetime.
    try source.processDueLifecycle(stored_at);
    try source.processDueLifecycle(
        stored_at.addDuration(.fromSeconds(2)),
    );
    try std.testing.expectEqual(@as(usize, 0), source.stats().retained_messages);
    try std.testing.expectEqual(@as(?anyerror, null), source.persistentChangeAutosaveError());
    _ = try tmp.dir.statFile(io, "expiry.db", .{});
    // Initial state is record 1 and periodic removal is record 2.
    try std.testing.expectEqual(@as(u64, 3), try source.appendCommit());
    source.deinit();
    source_owned = false;

    var journal_restored = try Broker.init(allocator, io, .{});
    defer journal_restored.deinit();
    try journal_restored.restoreCommitLog(tmp.dir, "expiry.log", .{});
    try std.testing.expectEqual(
        @as(usize, 0),
        journal_restored.stats().retained_messages,
    );

    var snapshot_restored = try Broker.init(allocator, io, .{});
    defer snapshot_restored.deinit();
    try snapshot_restored.restoreSnapshot(tmp.dir, "expiry.db");
    try std.testing.expectEqual(
        @as(usize, 0),
        snapshot_restored.stats().retained_messages,
    );
}

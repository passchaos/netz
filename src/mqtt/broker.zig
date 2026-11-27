//! Bounded in-memory MQTT broker core.
//!
//! This module composes the transport-independent connection runtime with the
//! topic router and bounded retained, Session, QoS 2, and Will state. It
//! focuses on the live broker hot path: SUBSCRIBE/UNSUBSCRIBE, QoS 0/1/2
//! routing, offline Session queueing, reconnect retransmission, No Local/shared
//! selection, downstream acknowledgements, and connection cleanup.

const std = @import("std");
pub const test_tmp = @import("../internal/test_tmp_dir.zig");
pub const builtin = @import("builtin");
const mqtt = @import("mod.zig");
pub const netz_runtime = @import("../runtime.zig");
pub const owned_properties = @import("owned_properties.zig");
pub const router_mod = @import("router.zig");
const runtime = @import("runtime.zig");
pub const listener_namespace = @import("listener_namespace.zig");
pub const client_id_mod = @import("broker/client_id.zig");
pub const session_subscriptions = @import("broker/session_subscriptions.zig");
pub const connection_storage = @import("broker/connection_storage.zig");
pub const acceptance_mod = @import("broker/acceptance.zig");
pub const load_metrics = @import("broker/load_metrics.zig");
pub const local_consumer_mod = @import("broker/local_consumer.zig");
pub const publish_counters = @import("broker/publish_counters.zig");
pub const persistence_mod = @import("persistence/mod.zig");
pub const commit_log_mod = persistence_mod.commit_log;
pub const vail = @import("vail");
pub const qos2_mod = @import("broker/qos2.zig");
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
pub const session_delivery = @import("broker/session_delivery.zig");
pub const session_route = @import("broker/session_route.zig");
pub const session_writer = @import("broker/session_writer.zig");
pub const deadline_driver_mod = @import("broker/deadline_driver.zig");
pub const runtime_policy_mod = @import("broker/runtime_policy.zig");
pub const retained_mod = @import("retained/mod.zig");
pub const session_mod = @import("session/mod.zig");
pub const will_mod = @import("will/mod.zig");

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

pub const LocalConsumerContext = struct {
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

pub const registration_persistence = @import("broker/registration_persistence.zig");
pub const RegistrationPersistenceContext = struct {
    pub const BrokerType = Broker;
    pub const appendCommitIfEnabledLocked = Broker.appendCommitIfEnabledLocked;
    pub const autosavePersistentChangesIfNeededLocked = Broker.autosavePersistentChangesIfNeededLocked;
};

pub const persistence_admission = @import("broker/persistence_admission.zig");
pub const PersistenceAdmissionContext = struct {
    pub const BrokerType = Broker;
    pub const hasProvisionalRegistration = Broker.hasProvisionalRegistrationLocked;
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

    pub fn take(self: *PreparedChangeAutosaveTarget) ?ChangeAutosaveOptions {
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

    pub fn take(self: *PreparedRequiredClientIdPrefix) []u8 {
        std.debug.assert(!self.consumed);
        const bytes = self.bytes;
        self.bytes = &.{};
        self.consumed = true;
        return bytes;
    }
};

/// One application-owned heap measurement. Mosquitto publishes the same pair
/// as `$SYS/broker/heap/current` and `$SYS/broker/heap/maximum` when it is
/// built with memory tracking.
pub const HeapSnapshot = struct {
    current_bytes: usize,
    maximum_bytes: usize,
};

/// Optional application heap source. The broker calls it while holding its
/// state mutex, so the callback must be allocation-free and must not re-enter
/// the broker.
pub const HeapSource = struct {
    context: *anyopaque,
    snapshot_fn: *const fn (*anyopaque) HeapSnapshot,

    pub fn snapshot(self: HeapSource) HeapSnapshot {
        return self.snapshot_fn(self.context);
    }
};

pub const Options = struct {
    limits: Limits = .{},
    /// Optional broker-heap measurement. Null omits the `$SYS/broker/heap/*`
    /// topics entirely, matching Mosquitto builds without memory tracking.
    heap_source: ?HeapSource = null,
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
pub const DeliveryAuthorizationChain = struct {
    broker: ?*const AccessControlHandler = null,
    listener: ?*const ListenerAccessControlHandler = null,

    pub fn configured(self: DeliveryAuthorizationChain) bool {
        if (self.broker) |access| {
            if (access.authorize_delivery != null) return true;
        }
        if (self.listener) |access| {
            if (access.authorize_delivery != null) return true;
        }
        return false;
    }

    pub fn authorize(
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

pub fn prepareRetainedDeliveryProperties(
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

pub const Publication = publication_mod.Publication;
pub const source_view = @import("broker/source_view.zig");

pub const Delivery = struct {
    publication: *Publication,
    qos: mqtt.QoS,
    retain: bool,
    subscription_identifier: ?usize = null,
    additional_subscription_identifiers: []usize = &.{},

    pub fn deinit(self: *Delivery) void {
        if (self.additional_subscription_identifiers.len != 0) {
            self.publication.allocator.free(
                self.additional_subscription_identifiers,
            );
        }
        self.publication.release();
        self.* = undefined;
    }

    pub fn appendSubscriptionIdentifier(
        self: *Delivery,
        allocator: std.mem.Allocator,
        identifier: ?usize,
    ) Error!void {
        const value = identifier orelse return;
        if (self.subscription_identifier == null) {
            self.subscription_identifier = value;
            return;
        }
        // Each matching filter contributes its Identifier even when another
        // filter uses the same value (MQTT-3.3.4-4).
        const old = self.additional_subscription_identifiers;
        const replacement = try allocator.alloc(usize, old.len + 1);
        @memcpy(replacement[0..old.len], old);
        replacement[old.len] = value;
        if (old.len != 0) allocator.free(old);
        self.additional_subscription_identifiers = replacement;
    }

    pub fn identifiersInto(
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

pub const RoutePlan = struct {
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

    pub fn deinit(self: RoutePlan, allocator: std.mem.Allocator) void {
        if (self.scratch_owner) |scratch| {
            scratch.clearRetainingCapacity();
        } else {
            allocator.free(self.storage);
        }
    }
};

pub const NetworkDeliveryMode = enum {
    synchronous,
    asynchronous,
    deferred,
};

pub const WillPublishProgress = struct {
    /// Any snapshot-visible mutation, including unrelated expiry pruning.
    persistent_changed: bool = false,
    /// The Will changed retained state or entered at least one durable Session
    /// queue. Once true, retrying the claimed Will could duplicate delivery.
    publication_effect_committed: bool = false,
};

pub const Registration = struct {
    subscriber_id: router_mod.SubscriberId,
    replaced_owner_id: ?router_mod.SubscriberId,
    persistent_changed: bool,
};

pub const RegistrationProgress = struct {
    /// Net durable change left after a failed registration is rolled back.
    /// New provisional Session/Will objects do not count because abort removes
    /// them; expiry pruning and replacement of prior durable state do.
    rollback_changed: bool = false,
    /// Optional packet/runtime preparation for full CONNECT admission. Direct
    /// state-only callers retain the same register interface without a peer.
    acceptance: ?*acceptance_mod.Preparation = null,
};

pub const DetachedSessionPacket = struct {
    detached: session_route.DetachedPacket,
    payload_len: usize,
    handle: session_mod.Handle,
    route_id: u64,

    pub fn deinit(self: *DetachedSessionPacket) void {
        self.detached.deinit();
        self.* = undefined;
    }
};

pub const SessionAckResult = struct {
    owned: bool,
    persistent_changed: bool,
};
pub const subscription_change = @import("broker/subscription_change.zig");
pub const subscriberId = session_route.connectionSubscriberId;
pub const nextConnectionGeneration = session_route.nextConnectionGeneration;
pub const sessionSubscriberId = session_route.sessionSubscriberId;
pub const sessionRouteId = session_route.sessionRouteId;
pub const subscriberIndex = session_route.connectionIndex;
pub const route_match_scratch_capacity: usize = 32;
pub const session_write_scratch_retain_limit: usize = 64 * 1024;
pub const transient_delivery_async_high_watermark: usize = 16;
pub const shared_session_delivery_writer_count: usize = 2;
pub const session_property_scratch_retain_capacity =
    session_write_scratch_retain_limit / @sizeOf(mqtt.Property);

pub const DeliveryWriter = struct {
    stop: std.atomic.Value(bool) = .init(false),
    future: std.Io.Future(?anyerror),
};

/// Storage used only after a connection subscribes, publishes through the
/// router, or has a Session transmission to write. Keeping these empty
/// container headers out of every preallocated capacity slot also lets an
/// idle slot release all retained queue and QoS-map capacity on disconnect.
pub const ClientBuffers = struct {
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

pub const ClientSlot = struct {
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
    /// Allocated after CONNECT policy checks and before Session admission.
    /// Attached after successful CONNACK. Keeping transport/session state out of
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
    /// A connection-lifetime writer starts only after a multi-destination
    /// route first selects asynchronous delivery. Pure publishers, idle
    /// subscribers, and single-destination subscribers pay no coroutine cost.
    delivery_ready: std.Io.Event = .unset,
    /// Queue, route, Session-write and transient-QoS storage is allocated as
    /// one descriptor only when the connection first needs any of it.
    buffers: ?*ClientBuffers = null,

    pub fn ensureBuffers(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*ClientBuffers {
        if (self.buffers) |buffers| return buffers;
        const buffers = try allocator.create(ClientBuffers);
        buffers.* = .{};
        self.buffers = buffers;
        return buffers;
    }

    pub fn clearBuffers(
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

    pub fn ensureDeliveryCapacity(
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
    pub fn ensureDeliveryReservationCapacity(
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

    pub fn transientInflightPayloadLimitReached(
        self: ClientSlot,
        limit: usize,
    ) bool {
        const buffers = self.buffers orelse return false;
        return limit != 0 and
            buffers.transient_inflight_payload_bytes >= limit;
    }

    pub fn recordTransientInflight(
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

    pub fn releaseTransientInflight(
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

    pub fn clearTransientInflight(self: *ClientSlot) void {
        const buffers = self.buffers orelse return;
        buffers.transient_inflight_payloads.clearRetainingCapacity();
        buffers.transient_inflight_payload_bytes = 0;
    }

    pub fn clearAssignedClientId(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) void {
        if (self.takeAssignedClientId()) |client_id| {
            allocator.free(client_id);
        }
    }

    pub fn assignedClientId(self: ClientSlot) ?[]u8 {
        const ptr = self.assigned_client_id_ptr orelse return null;
        return ptr[0..self.state.assigned_client_id_len];
    }

    pub fn setAssignedClientId(
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

    pub fn takeAssignedClientId(self: *ClientSlot) ?[]u8 {
        const client_id = self.assignedClientId() orelse return null;
        self.assigned_client_id_ptr = null;
        self.state.assigned_client_id_len = 0;
        return client_id;
    }

    pub fn username(self: ClientSlot) ?[]const u8 {
        const ptr = self.username_ptr orelse return null;
        return ptr[0..self.state.username_len];
    }

    pub fn setUsername(self: *ClientSlot, maybe_username: ?[]const u8) void {
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

    pub fn retainedSourceId(self: ClientSlot) ?u64 {
        return if (self.state.has_retained_source_id)
            self.retained_source_id_value
        else
            null;
    }

    pub fn setRetainedSourceId(self: *ClientSlot, maybe_source_id: ?u64) void {
        const source_id = maybe_source_id orelse {
            self.state.has_retained_source_id = false;
            return;
        };
        self.retained_source_id_value = source_id;
        self.state.has_retained_source_id = true;
    }

    pub fn setListenerAccessControl(
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

    pub fn accessControl(
        self: *const ClientSlot,
    ) ?*const ListenerAccessControlHandler {
        return self.listener_access_control;
    }

    pub fn clearListenerAccessControl(
        self: *ClientSlot,
        allocator: std.mem.Allocator,
    ) void {
        if (self.listener_access_control) |value| allocator.destroy(value);
        self.listener_access_control = null;
    }

    pub fn releaseOversizedSessionScratch(
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

    pub fn queuedCount(self: ClientSlot) usize {
        const buffers = self.buffers orelse return 0;
        return buffers.queue.items.len - buffers.queue_head;
    }

    pub fn popDelivery(self: *ClientSlot) ?Delivery {
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

    pub fn pushFront(self: *ClientSlot, delivery: Delivery) void {
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

    pub fn appendDeliveryAssumeCapacity(
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

    pub fn tailDeliveryForPublication(
        self: *ClientSlot,
        publication: *Publication,
    ) ?*Delivery {
        if (self.queuedCount() == 0) return null;
        const buffers = self.buffers.?;
        const delivery = &buffers.queue.items[buffers.queue.items.len - 1];
        return if (delivery.publication == publication) delivery else null;
    }

    pub fn removePublication(self: *ClientSlot, publication: *Publication) usize {
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

pub fn shouldScheduleTransientDelivery(
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

pub fn shouldScheduleSessionDelivery(
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

pub fn networkDeliveryMode(
    upgrade_outgoing_qos: bool,
    source_qos: mqtt.QoS,
) NetworkDeliveryMode {
    return if (!upgrade_outgoing_qos and source_qos == .at_most_once)
        .synchronous
    else
        .asynchronous;
}

/// Point-in-time broker gauges. State-backed fields are collected under the
/// same lock as routing and Session transitions, so their cross-field
/// invariants describe one coherent instant. Wire and PUBLISH counters are
/// lock-free, independently sampled, and include each complete operation.
pub const Stats = struct {
    uptime_seconds: u64,
    /// Application-provided broker heap measurement. Null when
    /// `Options.heap_source` is unset.
    heap_current_bytes: ?usize = null,
    heap_maximum_bytes: ?usize = null,
    /// Successfully parsed CONNECT packets admitted to the broker core.
    connections_received: u64,
    /// Cumulative transports accepted by a listener, including refused peers.
    sockets_accepted: u64,
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
    version,
    uptime,
    clients_connected,
    clients_active,
    clients_maximum,
    clients_disconnected,
    clients_inactive,
    clients_expired,
    clients_total,
    heap_current,
    heap_maximum,
    messages_received,
    messages_sent,
    messages_stored,
    store_messages_count,
    store_messages_bytes,
    packet_out_count,
    packet_out_bytes,
    connections_socket_count,
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
    load_sockets_1min,
    load_sockets_5min,
    load_sockets_15min,

    pub fn topic(self: SystemMetric) []const u8 {
        return switch (self) {
            .version => "$SYS/broker/version",
            .uptime => "$SYS/broker/uptime",
            .clients_connected => "$SYS/broker/clients/connected",
            .clients_active => "$SYS/broker/clients/active",
            .clients_maximum => "$SYS/broker/clients/maximum",
            .clients_disconnected => "$SYS/broker/clients/disconnected",
            .clients_inactive => "$SYS/broker/clients/inactive",
            .clients_expired => "$SYS/broker/clients/expired",
            .clients_total => "$SYS/broker/clients/total",
            .heap_current => "$SYS/broker/heap/current",
            .heap_maximum => "$SYS/broker/heap/maximum",
            .messages_received => "$SYS/broker/messages/received",
            .messages_sent => "$SYS/broker/messages/sent",
            .messages_stored => "$SYS/broker/messages/stored",
            .store_messages_count => "$SYS/broker/store/messages/count",
            .store_messages_bytes => "$SYS/broker/store/messages/bytes",
            .packet_out_count => "$SYS/broker/packet/out/count",
            .packet_out_bytes => "$SYS/broker/packet/out/bytes",
            .connections_socket_count => "$SYS/broker/connections/socket/count",
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
            .load_sockets_1min => "$SYS/broker/load/sockets/1min",
            .load_sockets_5min => "$SYS/broker/load/sockets/5min",
            .load_sockets_15min => "$SYS/broker/load/sockets/15min",
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

pub fn validateCapacityGroup(
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

/// Observed before connection destruction, independently of error policy.
pub const ListenerConnectionEndEvent = struct {
    listener_index: usize,
    /// Borrowed only for the callback; callers copy it if retained.
    client_id: []const u8,
    read_error: ?anyerror,
    writer_error: ?anyerror,
    graceful_disconnect: bool,
    administrative_disconnect: bool,
    keep_alive_timed_out: bool,
};

pub const ListenerConnectionEndObserver = struct {
    context: *anyopaque,
    /// May run concurrently. Runs outside broker locks and must return promptly.
    observe: *const fn (*anyopaque, ListenerConnectionEndEvent) void,
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
    connection_end_observer: ?ListenerConnectionEndObserver = null,
};

pub const system_metrics = [_]SystemMetric{
    .version,
    .uptime,
    .clients_connected,
    .clients_active,
    .clients_maximum,
    .clients_disconnected,
    .clients_inactive,
    .clients_expired,
    .clients_total,
    .heap_current,
    .heap_maximum,
    .messages_received,
    .messages_sent,
    .messages_stored,
    .store_messages_count,
    .store_messages_bytes,
    .packet_out_count,
    .packet_out_bytes,
    .connections_socket_count,
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
    .load_sockets_1min,
    .load_sockets_5min,
    .load_sockets_15min,
};

/// A bounded broker core with an optional compatibility TCP listener.
///
/// `listen` preserves the original one-listener API. `init` plus
/// `serveListeners` or `serveListenersUntil` lets TCP/TLS/WS/WSS listeners
/// share the same router, retained store, Session store, Will scheduler and
/// deadline driver.
pub const Broker = @import("broker/core.zig").Broker;

pub fn createRoutePublication(
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

pub fn clientMayPublishTopic(topic: []const u8) bool {
    if (std.mem.startsWith(u8, topic, "$share")) return false;
    if (!std.mem.startsWith(u8, topic, "$SYS")) return true;
    return mqtt.topicMatchesFilter(
        topic,
        "$SYS/broker/connection/+/state",
    );
}

pub const ClientTask = struct {
    const packet_storage_capacity = 128;

    broker: *Broker,
    slot_index: usize,
    subscriber_id: router_mod.SubscriberId,
    connect: runtime.OwnedConnect,
    result: *?anyerror,
    listener_capacity: ?*ListenerCapacity = null,
    managed_keep_alive: bool = false,
    listener_index: usize = 0,
    connection_end_observer: ?ListenerConnectionEndObserver = null,

    pub fn run(task: ClientTask) std.Io.Cancelable!void {
        var connect = task.connect;
        const slot = &task.broker.slots[task.slot_index];
        // The slot's username view borrows CONNECT storage. Register the
        // teardown after this defer so unregister clears that view before
        // OwnedConnect releases the packet or replacement identity.
        defer connect.deinit(task.broker.allocator);
        const connection = slot.connection.?;
        if (task.managed_keep_alive) {
            // Serialize first installation with the driver's slot scan and
            // generation snapshot. Later packet activity only extends an
            // existing deadline, so stale earlier wakes are harmless.
            task.broker.state_mutex.lockUncancelable(task.broker.io);
            const deadline_installed =
                connection.startManagedKeepAlive() != null;
            task.broker.state_mutex.unlock(task.broker.io);
            if (deadline_installed) {
                task.broker.deadline_driver.notify(task.broker.io);
            }
        }
        defer @import("broker/session_writer/retirement.zig").settle(struct {
            pub fn unregister(value: ClientTask) Error!?anyerror {
                return value.broker.unregister(value.slot_index, value.subscriber_id, value.listener_capacity);
            }
            pub const transportClosed = ungracefulTransportClose;
        }, task);

        var read_error: ?anyerror = null;
        var raw_read_error: ?anyerror = null;
        const loop_result = if (task.managed_keep_alive)
            task.runLoopMode(true, slot, connection, connect.connect)
        else
            task.runLoopMode(false, slot, connection, connect.connect);
        loop_result catch |err| {
            raw_read_error = err;
            if (!ungracefulTransportClose(err)) read_error = err;
        };
        if (read_error) |err| task.result.* = err;
        @import("broker/disconnect_completion.zig").run(struct {
            pub const retryCurrentCommit = Broker.appendCommitIfEnabled;
        }, task, slot, connection);
        const writer_error = task.broker.stopDeliveryWriter(slot);
        if (writer_error) |err| {
            if (!ungracefulTransportClose(err) and task.result.* == null) {
                task.result.* = err;
            }
        }
        if (task.connection_end_observer) |observer| {
            task.broker.state_mutex.lockUncancelable(task.broker.io);
            const graceful = slot.state.graceful_disconnect;
            const administrative = slot.state.administrative_disconnect;
            task.broker.state_mutex.unlock(task.broker.io);
            observer.observe(observer.context, .{
                .listener_index = task.listener_index,
                .client_id = connect.connect.client_id,
                .read_error = raw_read_error,
                .writer_error = writer_error,
                .graceful_disconnect = graceful,
                .administrative_disconnect = administrative,
                .keep_alive_timed_out = connection.managedKeepAliveTimedOut(),
            });
        }
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

    fn readNextBrokerEvent(
        comptime managed_keep_alive: bool,
        connection: *runtime.Connection,
        storage: []u8,
        out: *runtime.BrokerEvent,
    ) Error!void {
        if (managed_keep_alive) {
            return connection
                .readBrokerEventWithManagedKeepAliveIntoPrefixedOut(
                storage,
                @sizeOf(Publication),
                out,
            );
        }
        return connection.readBrokerEventWithKeepAliveIntoPrefixedOut(
            storage,
            @sizeOf(Publication),
            out,
        );
    }

    fn runLoopMode(
        task: ClientTask,
        comptime managed_keep_alive: bool,
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
            readNextBrokerEvent(
                managed_keep_alive,
                connection,
                &packet_storage,
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

pub const DeliveryWriterTask = struct {
    pub fn run(
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

pub const ListenerCapacity = struct {
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

    pub fn release(self: *ListenerCapacity, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.active != 0);
        self.active -= 1;
    }
};

pub const ListenerAcceptTask = struct {
    broker: *Broker,
    listener: Listener,
    capacity: *ListenerCapacity,
    result: *?anyerror,

    pub fn run(task: ListenerAcceptTask) std.Io.Cancelable!void {
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
        client_task.managed_keep_alive = true;
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

pub const ListenerSupervisorState = struct {
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

    pub fn firstError(self: *@This()) ?anyerror {
        self.error_mutex.lockUncancelable(self.broker.io);
        defer self.error_mutex.unlock(self.broker.io);
        return self.first_error;
    }
};

pub const ListenerSupervisorAcceptTask = struct {
    supervisor: *ListenerSupervisorState,
    listener: ListenerEndpoint,
    capacity: *ListenerCapacity,
    listener_index: usize,

    pub fn run(task: ListenerSupervisorAcceptTask) std.Io.Cancelable!void {
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
            client_task.managed_keep_alive = true;
            client_task.listener_index = task.listener_index;
            client_task.connection_end_observer = task.supervisor.options.connection_end_observer;
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

pub fn waitForListenerEvent(
    event: *std.Io.Event,
    io: std.Io,
) std.Io.Cancelable!void {
    try event.wait(io);
}

pub fn disconnectReasonForReadViolation(err: anyerror) ?u8 {
    return runtime.disconnectReasonForProtocolViolation(err, .server);
}

pub fn ungracefulTransportClose(err: anyerror) bool {
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

pub fn earliestDeadline(
    a: ?std.Io.Timestamp,
    b: ?std.Io.Timestamp,
) ?std.Io.Timestamp {
    const left = a orelse return b;
    const right = b orelse return left;
    return if (left.nanoseconds <= right.nanoseconds) left else right;
}

pub fn uptimeSeconds(started_at_ns: i96, now_ns: i96) u64 {
    if (now_ns <= started_at_ns) return 0;
    const elapsed = @divTrunc(now_ns - started_at_ns, std.time.ns_per_s);
    return @intCast(@min(elapsed, std.math.maxInt(u64)));
}

pub fn loadCounters(stats_value: Stats) load_metrics.Counters {
    return .{
        .connections = stats_value.connections_received,
        .sockets = stats_value.sockets_accepted,
        .messages_received = stats_value.messages_received,
        .messages_sent = stats_value.messages_sent,
        .publish_messages_dropped = @intCast(stats_value.publish_messages_dropped),
        .publish_messages_received = @intCast(stats_value.publish_messages_received),
        .publish_messages_sent = @intCast(stats_value.publish_messages_sent),
        .bytes_received = stats_value.bytes_received,
        .bytes_sent = stats_value.bytes_sent,
    };
}

pub fn formatSystemMetric(
    buffer: []u8,
    stats_value: Stats,
    metric: SystemMetric,
) ?[]const u8 {
    if (metric == .version) {
        return std.fmt.bufPrint(buffer, "netz version 0.1.0", .{}) catch unreachable;
    }
    if (metric == .uptime) {
        return std.fmt.bufPrint(
            buffer,
            "{d} seconds",
            .{stats_value.uptime_seconds},
        ) catch unreachable;
    }
    // Heap gauges exist only when the application supplied a heap source.
    if (metric == .heap_current or metric == .heap_maximum) {
        const value = if (metric == .heap_current)
            stats_value.heap_current_bytes
        else
            stats_value.heap_maximum_bytes;
        return std.fmt.bufPrint(
            buffer,
            "{d}",
            .{value orelse return null},
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
        .load_sockets_1min => stats_value.load.one_minute.sockets,
        .load_sockets_5min => stats_value.load.five_minutes.sockets,
        .load_sockets_15min => stats_value.load.fifteen_minutes.sockets,
        else => null,
    };
}

pub fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

fn systemMetricValue(stats_value: Stats, metric: SystemMetric) u64 {
    return switch (metric) {
        .uptime => stats_value.uptime_seconds,
        .version => 0,
        .clients_connected, .clients_active => @intCast(stats_value.active_connections),
        .clients_maximum => @intCast(stats_value.maximum_active_connections),
        .clients_disconnected, .clients_inactive => @intCast(stats_value.disconnected_sessions),
        .clients_expired => @intCast(stats_value.expired_sessions),
        .clients_total => @intCast(stats_value.sessions),
        // Heap gauges are formatted before this function because they are
        // optional; unreachable keeps the exhaustive switch honest.
        .heap_current, .heap_maximum => unreachable,
        .messages_received => stats_value.messages_received,
        .messages_sent => stats_value.messages_sent,
        .messages_stored, .store_messages_count => @intCast(stats_value.session_queued_messages),
        .store_messages_bytes => @intCast(stats_value.session_queued_payload_bytes),
        .packet_out_count => stats_value.messages_sent,
        .packet_out_bytes => stats_value.bytes_sent,
        .connections_socket_count => stats_value.sockets_accepted,
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
        .load_sockets_1min,
        .load_sockets_5min,
        .load_sockets_15min,
        => unreachable,
    };
}

pub fn maxQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
}

pub fn validateAutoClientIdPrefix(prefix: []const u8) Error!void {
    if (prefix.len > client_id_mod.max_prefix_len) {
        return error.InvalidProperty;
    }
    try mqtt.validateUtf8String(prefix);
}

pub fn validateListenerAdmissionSnapshot(
    snapshot: ListenerAdmissionSnapshot,
) Error!void {
    try validateAutoClientIdPrefix(snapshot.autoClientIdPrefix());
    if (snapshot.maximum_keep_alive_seconds == 0 or
        !snapshot.accepted_protocol_versions.any())
    {
        return error.InvalidProperty;
    }
}

pub fn validateClientIdPrefix(prefix: []const u8) Error!void {
    if (prefix.len > std.math.maxInt(u16)) return error.InvalidProperty;
    mqtt.validateUtf8String(prefix) catch return error.InvalidProperty;
}

pub fn protocolReason(
    protocol: mqtt.ProtocolVersion,
    reason_code: u8,
) u8 {
    // MQTT 3.1.1 ACK packets have no reason-code field. Success is the only
    // representable response; MQTT 5 keeps the broker's richer result.
    return if (protocol == .v5) reason_code else 0;
}

pub fn subscriptionDeniedReason(protocol: mqtt.ProtocolVersion) u8 {
    // MQTT 3.1.1 uses the generic SUBACK failure byte. MQTT 5 can expose the
    // precise Not Authorized reason without terminating the connection.
    return if (protocol == .v5) 0x87 else 0x80;
}

pub fn subscriptionQuotaExceededReason(protocol: mqtt.ProtocolVersion) u8 {
    // MQTT 5 can distinguish the broker's configured subscription-capacity
    // bound from ACL denial. MQTT 3.1.1 exposes only the generic SUBACK
    // failure byte while still allowing other filters in the packet to
    // succeed.
    return if (protocol == .v5) 0x97 else 0x80;
}

pub fn unsubscribeDeniedReason(protocol: mqtt.ProtocolVersion) u8 {
    // MQTT 3.1.1 UNSUBACK has no per-filter result. The subscription stays in
    // place while the only representable acknowledgement remains Success.
    return if (protocol == .v5) 0x87 else 0x00;
}

pub fn validateProblemInformationProperties(
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

pub fn validateLocalPublish(publish: mqtt.Publish) Error!void {
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
    _ = @import("broker/tests.zig");
}

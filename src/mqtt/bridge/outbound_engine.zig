//! Outbound and bidirectional MQTT broker bridge built from a local source
//! Session and one reconnecting remote Session.
//!
//! The source Session subscribes to local topics and acknowledges QoS 1 only
//! after the remote Session receives PUBACK. Optional inbound rules consume
//! publications from that same remote Session and route them locally. Outbound
//! QoS 2 uses an explicit durable coordinator; inbound QoS 2 uses the local
//! broker's durable bridge store.

const std = @import("std");
const builtin = @import("builtin");
const mqtt = @import("../mod.zig");
const listener_namespace = @import("../listener_namespace.zig");
const owned_properties = @import("../owned_properties.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const rule_helpers = @import("rules.zig");
const coordinator_mod = @import("outbound_coordinator.zig");
const local_source = @import("local_source.zig");
const inbound_flow = @import("inbound_flow.zig");
const rule_storage = @import("outbound_rules.zig");
const delivery_values = @import("outbound_delivery.zig");
const keepStableProperty = delivery_values.keepStableProperty;
const stablePropertiesEqual = delivery_values.stablePropertiesEqual;
const publishRetryMatches = delivery_values.publishRetryMatches;
const durablePublishMatches = @import("outbound_retry.zig").durablePublishMatches;

const net = std.Io.net;

/// One reconnectable broker endpoint. Host names are copied and re-resolved
/// for every attempt. Connector contexts and their reachable configuration
/// remain borrowed for the complete Bridge lifetime.
pub const Endpoint = union(enum) {
    address: net.IpAddress,
    host: struct {
        name: []const u8,
        port: u16,
    },
    connector: runtime.ClientConnector,
};

pub const Error = reconnect.Error || local_source.Error || listener_namespace.Error ||
    coordinator_mod.Error || inbound_flow.Error || error{
    NoBridgeRules,
    DuplicateBridgeFilter,
    OverlappingBridgeFilters,
    QoS2RequiresDurableCoordinator,
    QoS2RequiresCommitLog,
    QoS1RequiresPersistentSourceSession,
    QoS2RequiresPersistentSourceSession,
    QoS2RequiresPersistentTargetSession,
    SourceSessionLost,
    TargetSessionLost,
    TopicOutsideBridgeRule,
    EmptyMappedTopic,
    InvalidBridgeQoS,
    TargetAcknowledgementMismatch,
    TargetUnsubscribeRefused,
    UnsafeBidirectionalBridge,
};

pub const Rule = @import("outbound_rule.zig").Rule;
pub const InboundRule = inbound_flow.Rule;

pub const Options = struct {
    source_connect: runtime.ConnectOptions,
    target_connect: runtime.ConnectOptions,
    source_reconnect_policy: reconnect.ReconnectPolicy = .{},
    target_reconnect_policy: reconnect.ReconnectPolicy = .{},
    rule: Rule,
    /// Optional remote-to-local rules carried by the same target Client.
    inbound_rules: []const InboundRule = &.{},
    /// Stable identity for durable inbound QoS 2 state.
    inbound_bridge_id: ?[16]u8 = null,
    preserve_retain: bool = true,
    attempt_target_unsubscribe: bool = false,
    coordinator: ?CoordinatorOptions = null,
    notifications: ?NotificationOptions = null,
    target_protocol_fallback: ?ProtocolFallback = null,
};

pub const MultiOptions = struct {
    source_connect: runtime.ConnectOptions,
    target_connect: runtime.ConnectOptions,
    source_reconnect_policy: reconnect.ReconnectPolicy = .{},
    target_reconnect_policy: reconnect.ReconnectPolicy = .{},
    rules: []const Rule,
    /// Optional remote-to-local rules carried by the same target Client.
    inbound_rules: []const InboundRule = &.{},
    /// Stable identity for durable inbound QoS 2 state.
    inbound_bridge_id: ?[16]u8 = null,
    preserve_retain: bool = true,
    attempt_target_unsubscribe: bool = false,
    coordinator: ?CoordinatorOptions = null,
    notifications: ?NotificationOptions = null,
    target_protocol_fallback: ?ProtocolFallback = null,
    /// Construct a broker-local source without registering it yet. This is
    /// used by configuration reload staging so the active generation retains
    /// sole ownership until commit.
    defer_local_source_connect: bool = false,
    /// Replace an offline persistent local Session when its source filters
    /// changed between configuration generations.
    replace_local_source_subscriptions: bool = false,
};

pub const NotificationOptions = struct {
    topic: []const u8,
    publish_remote: bool = true,
};

pub const ProtocolFallback = struct {
    protocol: mqtt.ProtocolVersion,
    bridge_mode: bool = false,
};

pub const CoordinatorMode = enum {
    create,
    restore,
};

pub const CoordinatorOptions = struct {
    /// Stable deployment identity. Reusing a journal with different client
    /// identities, protocols, rules, or RETAIN policy is rejected separately.
    bridge_id: [16]u8,
    dir: std.Io.Dir,
    sub_path: []const u8,
    mode: CoordinatorMode,
    journal: coordinator_mod.Options = .{},
};

pub const ConnectEvent = struct {
    source_session_present: bool,
    target_session_present: bool,
};

const OwnedRule = rule_storage.OwnedRule;
const OwnedRules = rule_storage.OwnedRules;

const TargetDeliveryState = struct {
    completed: bool = false,
    packet_id: ?u16 = null,
    reason_code: u8 = 0,

    pub fn reset(self: *TargetDeliveryState) void {
        self.* = .{};
    }

    fn complete(context: *anyopaque, delivery: reconnect.PublishDelivery) void {
        // QoS 0 completes at its write and needs no cross-broker ACK state.
        // This includes retained connection-state notifications emitted while
        // reconnecting a journaled QoS 2 transaction.
        if (delivery.qos == .at_most_once) return;
        const self: *TargetDeliveryState = @ptrCast(@alignCast(context));
        self.completed = true;
        self.packet_id = delivery.packet_id;
        self.reason_code = delivery.reason_code;
    }
};

pub const TargetPublishResult = union(enum) {
    published: ?u16,
    completed,
    expired,
};

const CompletedSource = delivery_values.CompletedSource;
/// A single-owner local-to-remote MQTT bridge.
///
/// Both MQTT clients and all rule strings are owned by the Bridge. Connector
/// contexts remain borrowed. The shutdown Event and `std.Io` backing state
/// must outlive the Bridge. QoS 1 requires a persistent source Session so an
/// unacknowledged local delivery survives either transport reconnect.
pub const Bridge = Engine(reconnect.Client);
pub const LocalBridge = Engine(local_source.Client);

/// Shared delivery/coordinator state machine for network and broker sources.
pub fn Engine(comptime Source: type) type {
    return struct {
        const Self = @This();
        const OwnedNotifications = struct { topic: []u8, publish_remote: bool };
        pub const SourceEndpoint = if (Source == reconnect.Client) Endpoint else struct { broker: *@import("../broker.zig").Broker, id: [16]u8 };
        allocator: std.mem.Allocator,
        source: Source,
        target: reconnect.Client,
        target_delivery: *TargetDeliveryState,
        rules: OwnedRules,
        inbound_rules: inbound_flow.OwnedRules,
        inbound_bridge_id: ?[16]u8,
        inbound_session_epoch: u64,
        inbound_qos2_enabled: bool,
        preserve_retain: bool,
        attempt_target_unsubscribe: bool,
        source_session_present: bool = false,
        target_session_present: bool = false,
        source_session_epoch: u64 = 0,
        target_session_epoch: u64 = 0,
        source_pubrec_flushed: bool = false,
        completed_source: ?CompletedSource = null,
        coordinator: ?coordinator_mod.Store = null,
        poll_source_next: bool = true,
        notifications: ?OwnedNotifications = null,
        target_protocol_fallback: ?ProtocolFallback = null,
        local_online: bool = false,
        once: bool = false,

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_address: net.IpAddress,
            target_address: net.IpAddress,
            options: Options,
            shutdown: *std.Io.Event,
        ) Error!Self {
            return initMany(
                allocator,
                io,
                source_address,
                target_address,
                .{
                    .source_connect = options.source_connect,
                    .target_connect = options.target_connect,
                    .source_reconnect_policy = options.source_reconnect_policy,
                    .target_reconnect_policy = options.target_reconnect_policy,
                    .rules = &.{options.rule},
                    .inbound_rules = options.inbound_rules,
                    .inbound_bridge_id = options.inbound_bridge_id,
                    .preserve_retain = options.preserve_retain,
                    .attempt_target_unsubscribe = options.attempt_target_unsubscribe,
                    .coordinator = options.coordinator,
                    .notifications = options.notifications,
                    .target_protocol_fallback = options.target_protocol_fallback,
                },
                shutdown,
            );
        }

        pub fn initMany(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_address: net.IpAddress,
            target_address: net.IpAddress,
            options: MultiOptions,
            shutdown: *std.Io.Event,
        ) Error!Self {
            return initEndpoints(
                allocator,
                io,
                .{ .address = source_address },
                .{ .address = target_address },
                options,
                shutdown,
            );
        }

        pub fn initHost(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_host: []const u8,
            source_port: u16,
            target_host: []const u8,
            target_port: u16,
            options: Options,
            shutdown: *std.Io.Event,
        ) Error!Self {
            return initHostMany(
                allocator,
                io,
                source_host,
                source_port,
                target_host,
                target_port,
                .{
                    .source_connect = options.source_connect,
                    .target_connect = options.target_connect,
                    .source_reconnect_policy = options.source_reconnect_policy,
                    .target_reconnect_policy = options.target_reconnect_policy,
                    .rules = &.{options.rule},
                    .inbound_rules = options.inbound_rules,
                    .inbound_bridge_id = options.inbound_bridge_id,
                    .preserve_retain = options.preserve_retain,
                    .attempt_target_unsubscribe = options.attempt_target_unsubscribe,
                    .coordinator = options.coordinator,
                    .notifications = options.notifications,
                    .target_protocol_fallback = options.target_protocol_fallback,
                },
                shutdown,
            );
        }

        pub fn initHostMany(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_host: []const u8,
            source_port: u16,
            target_host: []const u8,
            target_port: u16,
            options: MultiOptions,
            shutdown: *std.Io.Event,
        ) Error!Self {
            return initEndpoints(
                allocator,
                io,
                .{ .host = .{ .name = source_host, .port = source_port } },
                .{ .host = .{ .name = target_host, .port = target_port } },
                options,
                shutdown,
            );
        }

        pub fn initConnector(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_connector: runtime.ClientConnector,
            target_connector: runtime.ClientConnector,
            options: Options,
            shutdown: *std.Io.Event,
        ) Error!Self {
            return initConnectorMany(
                allocator,
                io,
                source_connector,
                target_connector,
                .{
                    .source_connect = options.source_connect,
                    .target_connect = options.target_connect,
                    .source_reconnect_policy = options.source_reconnect_policy,
                    .target_reconnect_policy = options.target_reconnect_policy,
                    .rules = &.{options.rule},
                    .inbound_rules = options.inbound_rules,
                    .inbound_bridge_id = options.inbound_bridge_id,
                    .preserve_retain = options.preserve_retain,
                    .attempt_target_unsubscribe = options.attempt_target_unsubscribe,
                    .coordinator = options.coordinator,
                    .notifications = options.notifications,
                    .target_protocol_fallback = options.target_protocol_fallback,
                },
                shutdown,
            );
        }

        pub fn initConnectorMany(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_connector: runtime.ClientConnector,
            target_connector: runtime.ClientConnector,
            options: MultiOptions,
            shutdown: *std.Io.Event,
        ) Error!Self {
            return initEndpoints(
                allocator,
                io,
                .{ .connector = source_connector },
                .{ .connector = target_connector },
                options,
                shutdown,
            );
        }

        /// Construct from independently selected source and target endpoint kinds.
        /// This permits fixed/DNS/TLS/WebSocket combinations without a Cartesian
        /// product of constructors.
        pub fn initEndpoints(
            allocator: std.mem.Allocator,
            io: std.Io,
            source_endpoint: SourceEndpoint,
            target_endpoint: Endpoint,
            options: MultiOptions,
            shutdown: *std.Io.Event,
        ) Error!Self {
            const notifications: ?OwnedNotifications = if (options.notifications) |value| blk: {
                if (Source != local_source.Client) return error.InvalidProperty;
                try mqtt.validateTopicName(value.topic);
                break :blk .{ .topic = try allocator.dupe(u8, value.topic), .publish_remote = value.publish_remote };
            } else null;
            errdefer if (notifications) |value| allocator.free(value.topic);
            var target_connect = options.target_connect;
            if (notifications) |value| if (value.publish_remote) {
                if (target_connect.will != null) return error.InvalidProperty;
                target_connect.will = .{ .topic = value.topic, .payload = "0", .qos = .at_least_once, .retain = true };
            };
            var rules = try OwnedRules.init(allocator, options.rules);
            errdefer rules.deinit(allocator);
            var inbound_rules = try inbound_flow.OwnedRules.initOptional(
                allocator,
                options.inbound_rules,
            );
            errdefer inbound_rules.deinit(allocator);
            if (inbound_rules.values.len != 0 and
                Source != local_source.Client)
            {
                return error.InvalidProperty;
            }
            if (inbound_rules.values.len != 0) {
                for (rules.values) |rule| {
                    if (!rule.value.no_local) {
                        return error.UnsafeBidirectionalBridge;
                    }
                }
                switch (options.target_connect.protocol) {
                    .v5 => for (inbound_rules.values) |rule| {
                        if (!rule.no_local) {
                            return error.UnsafeBidirectionalBridge;
                        }
                    },
                    .v3_1, .v3_1_1 => {
                        if (!options.target_connect.bridge_mode) {
                            return error.UnsafeBidirectionalBridge;
                        }
                        for (inbound_rules.values) |rule| {
                            if (rule.no_local) return error.InvalidProperty;
                        }
                    },
                }
            }
            if (options.target_protocol_fallback) |fallback| {
                if (options.target_connect.protocol != .v5 or
                    fallback.protocol == .v5)
                {
                    return error.InvalidProperty;
                }
                if (target_connect.will) |will| {
                    if (will.properties.len != 0) {
                        return error.InvalidProperty;
                    }
                }
                if (inbound_rules.values.len != 0 and
                    rules.values.len != 0 and
                    !fallback.bridge_mode)
                {
                    return error.UnsafeBidirectionalBridge;
                }
            }
            const outbound_qos2 = rulesUseQoS2(rules.values);
            const inbound_qos2 = inbound_flow.rulesUseQoS2(
                inbound_rules.values,
            );
            if (Source == local_source.Client and outbound_qos2 and !source_endpoint.broker.commitLogEnabled()) {
                return error.QoS2RequiresCommitLog;
            }
            if (inbound_qos2) {
                if (options.inbound_bridge_id == null) {
                    return error.MissingBridgeIdentifier;
                }
                if (comptime Source == local_source.Client) {
                    if (!source_endpoint.broker.commitLogEnabled()) {
                        return error.QoS2RequiresCommitLog;
                    }
                }
            }
            if (outbound_qos2 and options.coordinator == null) {
                return error.QoS2RequiresDurableCoordinator;
            }
            if (outbound_qos2 and !persistentSession(options.source_connect)) {
                return error.QoS2RequiresPersistentSourceSession;
            }
            if (!outbound_qos2 and rulesUseQoS1(rules.values) and
                !persistentSession(options.source_connect))
            {
                return error.QoS1RequiresPersistentSourceSession;
            }
            const target_delivery = try allocator.create(TargetDeliveryState);
            errdefer allocator.destroy(target_delivery);
            target_delivery.* = .{};
            var source = try initSource(
                allocator,
                io,
                source_endpoint,
                options.source_connect,
                options.source_reconnect_policy,
                shutdown,
                .{
                    .max_subscriptions = rules.values.len,
                    .manual_acknowledgements = true,
                    .inbound_qos2_release_policy = if (outbound_qos2)
                        .deferred
                    else
                        .automatic,
                    .surface_incoming_qos2_retransmissions = outbound_qos2,
                },
                options.replace_local_source_subscriptions,
            );
            errdefer source.deinit();
            for (rules.values) |rule| {
                try source.seedSubscription(.{
                    .topic_filter = rule.source_filter,
                    .qos = rule.value.qos,
                    .no_local = rule.value.no_local,
                    .retain_as_published = options.source_connect.protocol == .v5,
                }, &.{});
            }
            if ((outbound_qos2 or inbound_qos2) and
                !persistentSession(options.target_connect))
            {
                return error.QoS2RequiresPersistentTargetSession;
            }
            var target = try initClient(
                allocator,
                io,
                target_endpoint,
                target_connect,
                options.target_reconnect_policy,
                shutdown,
                .{
                    .max_subscriptions = inbound_rules.values.len,
                    .manual_acknowledgements = inbound_rules.values.len != 0,
                    .inbound_qos2_release_policy = if (inbound_qos2)
                        .deferred
                    else
                        .automatic,
                    .surface_incoming_qos2_retransmissions = inbound_qos2,
                    .outbound_qos2_release_policy = if (outbound_qos2)
                        .deferred
                    else
                        .automatic,
                    .outbound_replay_capability_policy = .adapt_qos1,
                    .publish_delivery = .{
                        .context = target_delivery,
                        .complete = TargetDeliveryState.complete,
                    },
                },
            );
            errdefer target.deinit();
            const coordinator = if (options.coordinator) |coordinator_options| blk: {
                const identity = coordinatorIdentity(
                    coordinator_options.bridge_id,
                    options.source_connect,
                    options.target_connect,
                    rules.values,
                    inbound_rules.values,
                    options.preserve_retain,
                );
                break :blk switch (coordinator_options.mode) {
                    .create => try coordinator_mod.Store.create(
                        allocator,
                        io,
                        coordinator_options.dir,
                        coordinator_options.sub_path,
                        coordinator_options.journal,
                        identity,
                        &source,
                        &target,
                    ),
                    .restore => try coordinator_mod.Store.restore(
                        allocator,
                        io,
                        coordinator_options.dir,
                        coordinator_options.sub_path,
                        coordinator_options.journal,
                        identity,
                        &source,
                        &target,
                    ),
                };
            } else null;
            if (inbound_qos2) {
                for (inbound_rules.values) |rule| {
                    try target.seedSubscription(.{
                        .topic_filter = rule.filter,
                        .qos = rule.qos,
                        .no_local = rule.no_local,
                        .retain_as_published = options.target_connect.protocol == .v5,
                    }, &.{});
                }
            }
            const inbound_session_epoch = if (inbound_qos2)
                if (comptime Source == local_source.Client)
                    source_endpoint.broker.latestBridgeQoS2SessionEpoch(
                        options.inbound_bridge_id.?,
                    ) orelse 0
                else
                    unreachable
            else
                0;
            var result = Self{
                .allocator = allocator,
                .source = source,
                .target = target,
                .target_delivery = target_delivery,
                .rules = rules,
                .inbound_rules = inbound_rules,
                .inbound_bridge_id = options.inbound_bridge_id,
                .inbound_session_epoch = inbound_session_epoch,
                .inbound_qos2_enabled = inbound_qos2,
                .preserve_retain = options.preserve_retain,
                .attempt_target_unsubscribe = options.attempt_target_unsubscribe,
                .source_session_epoch = if (coordinator) |*store|
                    store.source_session_epoch
                else
                    0,
                .target_session_epoch = if (coordinator) |*store|
                    store.target_session_epoch
                else
                    0,
                .coordinator = coordinator,
                .notifications = notifications,
                .target_protocol_fallback = options.target_protocol_fallback,
            };
            errdefer if (result.coordinator) |*store| store.deinit();
            // `source` and result.source share owned storage at this temporary
            // move boundary. Close only the new broker registration on failure;
            // the earlier source errdefer releases its allocations once.
            errdefer if (Source == local_source.Client) result.source.disconnectTransport();
            if (Source == local_source.Client and
                !options.defer_local_source_connect)
            {
                const connected = try result.source.connect();
                try result.noteSourceConnected(connected);
            }
            return result;
        }

        /// Register a deferred broker-local source immediately before its
        /// generation begins running. Repeated calls are harmless.
        pub fn activateLocalSource(self: *Self) Error!void {
            if (comptime Source == local_source.Client) {
                if (!self.source.isConnected()) {
                    const connected = try self.source.connect();
                    try self.noteSourceConnected(connected);
                }
            }
        }

        pub fn deinit(self: *Self) void {
            self.notifyLocal(false) catch {};
            if (self.notifications) |value| self.allocator.free(value.topic);
            if (self.completed_source) |*completed| {
                completed.deinit(self.allocator);
            }
            if (self.coordinator) |*coordinator| coordinator.deinit();
            self.target.deinit();
            self.source.deinit();
            self.inbound_rules.deinit(self.allocator);
            self.rules.deinit(self.allocator);
            self.allocator.destroy(self.target_delivery);
            self.* = undefined;
        }

        pub fn connect(
            self: *Self,
        ) (Error || std.Io.Cancelable)!ConnectEvent {
            if (self.durableTransaction() != null) {
                // Validate source ownership before reconnecting target: the latter
                // may replay a PUBLISH as part of CONNECT completion. A lost
                // source Session must fail before any more target-side delivery.
                if (!self.sourceConnected()) {
                    const connected = try self.source.connect();
                    try self.noteSourceConnected(connected);
                }
                try self.validateDurableSourceState();
                if (self.target.connection() == null) {
                    const connected = try self.connectTarget();
                    try self.noteTargetConnected(connected);
                }
            } else {
                if (self.target.connection() == null) {
                    const connected = try self.connectTarget();
                    try self.noteTargetConnected(connected);
                }
                if (!self.sourceConnected()) {
                    const connected = try self.source.connect();
                    try self.noteSourceConnected(connected);
                }
            }
            try self.validateDurableTargetState();
            _ = try self.completeDurableSourceIfReady();
            return .{
                .source_session_present = self.source_session_present,
                .target_session_present = self.target_session_present,
            };
        }

        fn connectTarget(
            self: *Self,
        ) (Error || std.Io.Cancelable)!reconnect.ConnectEvent {
            var adaptations: u2 = 0;
            while (true) {
                const connected = self.target.connect() catch |err| {
                    if (err == error.ConnectRefused and
                        adaptations < 3 and
                        try self.adaptTargetConnectRefusal())
                    {
                        adaptations += 1;
                        continue;
                    }
                    return err;
                };
                return connected;
            }
        }

        fn pollTarget(
            self: *Self,
            options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!?reconnect.ClientEvent {
            return self.target.pollWithOptions(options) catch |err| {
                if (err == error.ConnectRefused and
                    try self.adaptTargetConnectRefusal())
                {
                    return null;
                }
                return err;
            };
        }

        fn adaptTargetConnectRefusal(self: *Self) Error!bool {
            if (self.notifications) |notifications| {
                if (notifications.publish_remote and
                    self.target.adaptWillToLastConnectRefusal())
                {
                    return true;
                }
            }
            const fallback = self.target_protocol_fallback orelse return false;
            return self.target.adaptProtocolToLastConnectRefusal(
                fallback.protocol,
                fallback.bridge_mode,
            );
        }

        pub fn disconnect(self: *Self, reason_code: u8) Error!void {
            try self.notify(false);

            self.target.disconnect(reason_code) catch |err| {
                self.source.disconnect(reason_code) catch {};
                return err;
            };
            try self.source.disconnect(reason_code);
        }

        pub fn hasPendingDurableQoS2(self: *Self) bool {
            if (self.durableTransaction() != null) return true;
            if (!self.inbound_qos2_enabled) return false;
            return (self.target.outgoingStats() catch return true)
                .incoming_qos2_count != 0;
        }

        /// Process at most one event from alternating source and target polls.
        /// Poll slices are capped so an idle endpoint cannot starve the other's
        /// Keep Alive or reconnect work. Once a QoS 1 source delivery arrives,
        /// this call keeps alternating both clients until the target PUBACK, expiry,
        /// or a terminal error/cancellation occurs.
        pub fn step(
            self: *Self,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!bool {
            if (self.durableTransaction() != null) {
                try self.driveDurableQoS2(poll_options);
                return true;
            }
            const source_turn = self.poll_source_next;
            self.poll_source_next = !source_turn;
            return if (source_turn)
                self.stepSource(
                    bridgeClientPollOptions(&self.source, poll_options),
                    poll_options,
                )
            else
                self.stepTarget(bridgeClientPollOptions(
                    &self.target,
                    poll_options,
                ));
        }

        fn stepSource(
            self: *Self,
            bounded: reconnect.PollOptions,
            forward_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!bool {
            var event = try self.source.pollWithOptions(bounded) orelse return false;
            defer event.deinit(self.allocator);
            switch (event) {
                .connected => |connected| try self.noteSourceConnected(connected),
                .publish => |owned| {
                    if (try self.consumeCompletedSourceRetry(&owned.publish)) {
                        return true;
                    }
                    self.forward(&owned.publish, forward_options) catch |err| {
                        self.source.disconnectTransport();
                        return err;
                    };
                    if (@hasDecl(Source, "completeQoS0")) {
                        if (owned.publish.qos == .at_most_once) try self.source.completeQoS0();
                    }
                },
                .disconnect => self.source.disconnectTransport(),
                .pingreq, .pingresp, .auth => {},
                .puback, .pubrec, .pubrel, .pubcomp => return error.UnexpectedPacket,
            }
            return true;
        }

        fn stepTarget(
            self: *Self,
            bounded: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!bool {
            if (self.once and self.target.connection() == null) return error.ConnectionClosed;
            var event = try self.pollTarget(bounded) orelse {
                if (self.target.connection() == null) try self.notifyLocal(false);
                return false;
            };
            defer event.deinit(self.allocator);
            switch (event) {
                .connected => |connected| {
                    try self.noteTargetConnected(connected);
                },
                .disconnect => {
                    self.target.disconnectTransport();
                    try self.notifyLocal(false);
                },
                .publish => |owned| try self.handleTargetPublish(
                    &owned.publish,
                ),
                .pubrel => |owned| try self.handleTargetPubRel(
                    owned.ack.packet_id,
                ),
                .pingreq, .pingresp, .auth => {},
                .puback, .pubrec, .pubcomp => {
                    self.target.disconnectTransport();
                    return error.UnexpectedPacket;
                },
            }
            return true;
        }

        pub fn run(
            self: *Self,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            return self.runLoop(poll_options, null, null);
        }

        /// Keep the active target generation alive while a lazy reload is
        /// pending, then return before the first subsequent reconnect.
        pub fn runUntilReload(
            self: *Self,
            poll_options: reconnect.PollOptions,
            reload_pending: *const std.atomic.Value(bool),
            connected: *std.atomic.Value(bool),
        ) (Error || std.Io.Cancelable)!void {
            return self.runLoop(poll_options, reload_pending, connected);
        }

        fn runLoop(
            self: *Self,
            poll_options: reconnect.PollOptions,
            reload_pending: ?*const std.atomic.Value(bool),
            connected: ?*std.atomic.Value(bool),
        ) (Error || std.Io.Cancelable)!void {
            defer self.notifyLocal(false) catch {};
            defer if (connected) |state| state.store(false, .release);
            var bounded = poll_options;
            if (reload_pending != null) {
                bounded.reconnect_after_transport_error = false;
            }
            while (true) {
                if (self.source.shutdown.isSet()) return;
                if (connected) |state| {
                    state.store(self.target.connection() != null, .release);
                }
                if (reload_pending) |pending| {
                    if (pending.load(.acquire) and
                        self.target.connection() == null) return;
                }
                _ = self.step(bounded) catch |err| {
                    if (self.source.shutdown.isSet()) return;
                    if (err == error.Canceled) return;
                    return err;
                };
            }
        }

        /// Run a broker-local source only while its durable queue has work.
        /// The first connection is deferred until `threshold` messages are
        /// pending. Once activated, the bridge drains the complete queue and
        /// disconnects after one uninterrupted idle interval.
        pub fn runLazy(
            self: *Self,
            poll_options: reconnect.PollOptions,
            threshold: usize,
            idle_timeout: std.Io.Duration,
        ) (Error || std.Io.Cancelable)!void {
            return self.runLazyLoop(
                poll_options,
                threshold,
                idle_timeout,
                null,
                null,
            );
        }

        /// Lazy lifecycle variant that adopts a pending configuration only at
        /// a disconnected boundary, including the idle state before its next
        /// threshold-triggered connection.
        pub fn runLazyUntilReload(
            self: *Self,
            poll_options: reconnect.PollOptions,
            threshold: usize,
            idle_timeout: std.Io.Duration,
            reload_pending: *const std.atomic.Value(bool),
            connected: *std.atomic.Value(bool),
        ) (Error || std.Io.Cancelable)!void {
            return self.runLazyLoop(
                poll_options,
                threshold,
                idle_timeout,
                reload_pending,
                connected,
            );
        }

        fn runLazyLoop(
            self: *Self,
            poll_options: reconnect.PollOptions,
            threshold: usize,
            idle_timeout: std.Io.Duration,
            reload_pending: ?*const std.atomic.Value(bool),
            connected: ?*std.atomic.Value(bool),
        ) (Error || std.Io.Cancelable)!void {
            if (comptime Source != local_source.Client) {
                @compileError("lazy bridge lifecycle requires a local source");
            }
            if (threshold == 0 or idle_timeout.nanoseconds <= 0 or
                poll_options.timeout.nanoseconds <= 0 or
                poll_options.cancellation_check_interval.nanoseconds <= 0)
            {
                return error.InvalidProperty;
            }
            defer self.notifyLocal(false) catch {};
            defer if (connected) |state| state.store(false, .release);
            var reactivate_after_disconnect = false;
            while (true) {
                if (self.source.shutdown.isSet()) return;
                if (connected) |state| {
                    state.store(self.target.connection() != null, .release);
                }
                if (reload_pending) |pending| {
                    if (pending.load(.acquire) and
                        self.target.connection() == null) return;
                }
                self.activateLocalSource() catch |err| switch (err) {
                    error.Canceled => return,
                    else => return err,
                };
                _ = self.source.finishPendingCompletion() catch |err| switch (err) {
                    error.Canceled => return,
                    else => return err,
                };
                if (!reactivate_after_disconnect and
                    self.target.connection() == null and
                    !self.hasPendingDurableQoS2())
                {
                    self.source.waitForPending(
                        threshold,
                    ) catch |err| switch (err) {
                        error.Canceled => return,
                        else => return err,
                    };
                }
                if (reload_pending) |pending| {
                    if (pending.load(.acquire) and
                        self.target.connection() == null) return;
                }
                reactivate_after_disconnect = false;
                _ = self.connect() catch |err| switch (err) {
                    error.Canceled => return,
                    else => return err,
                };
                if (connected) |state| state.store(true, .release);

                var observed_generation = self.source.deliveryGeneration();
                var idle_deadline: ?std.Io.Clock.Timestamp = null;
                while (true) {
                    if (self.source.shutdown.isSet()) return;
                    if (reload_pending) |pending| {
                        if (pending.load(.acquire) and
                            self.target.connection() == null) return;
                    }
                    _ = self.source.finishPendingCompletion() catch |err| switch (err) {
                        error.Canceled => return,
                        else => return err,
                    };
                    const pending = try self.source.pendingCount();
                    const generation = self.source.deliveryGeneration();
                    const has_work = pending != 0 or
                        self.hasPendingDurableQoS2();
                    if (has_work) {
                        idle_deadline = null;
                    } else if (idle_deadline == null or
                        generation != observed_generation)
                    {
                        idle_deadline = .fromNow(self.source.io, .{
                            .raw = idle_timeout,
                            .clock = .awake,
                        });
                    }
                    observed_generation = generation;

                    if (self.target.connection() == null and !has_work) {
                        try self.notifyLocal(false);
                        reactivate_after_disconnect =
                            self.source.deliveryGeneration() != generation or
                            try self.source.pendingCount() != 0;
                        break;
                    }
                    if (idle_deadline) |deadline| {
                        if (deadline.durationFromNow(
                            self.source.io,
                        ).raw.nanoseconds <= 0) {
                            try self.disconnectIdleTarget();
                            reactivate_after_disconnect =
                                self.source.deliveryGeneration() != generation or
                                try self.source.pendingCount() != 0;
                            break;
                        }
                    }
                    _ = self.step(lazyPollOptions(
                        poll_options,
                        idle_deadline,
                        self.source.io,
                    )) catch |err| switch (err) {
                        error.Canceled => return,
                        else => return err,
                    };
                    if (connected) |state| {
                        state.store(
                            self.target.connection() != null,
                            .release,
                        );
                    }
                }
            }
        }

        fn disconnectIdleTarget(self: *Self) Error!void {
            if (self.notifications) |value| {
                if (value.publish_remote) if (self.target.connection()) |active| {
                    _ = self.target.publishOneAttempt(
                        value.topic,
                        "0",
                        .{
                            .qos = .at_most_once,
                            .retain = self.preserve_retain and
                                active.peerRetainAvailable(),
                        },
                    ) catch {};
                };
            }
            self.target.disconnect(0) catch self.target.disconnectTransport();
            self.target.clearScheduledReconnectDelay();
            try self.notifyLocal(false);
        }

        pub fn requestReconnect(self: *Self) void {
            self.target.requestReconnect();
        }

        pub fn runOnce(self: *Self, poll_options: reconnect.PollOptions) (Error || std.Io.Cancelable)!void {
            return self.runOnceTracked(poll_options, null);
        }

        pub fn runOnceWithConnectionState(
            self: *Self,
            poll_options: reconnect.PollOptions,
            connected: *std.atomic.Value(bool),
        ) (Error || std.Io.Cancelable)!void {
            return self.runOnceTracked(poll_options, connected);
        }

        fn runOnceTracked(
            self: *Self,
            poll_options: reconnect.PollOptions,
            connected: ?*std.atomic.Value(bool),
        ) (Error || std.Io.Cancelable)!void {
            defer if (Source == local_source.Client) self.source.disconnectTransport();
            defer if (connected) |state| state.store(false, .release);
            _ = try self.connect();
            if (connected) |state| state.store(true, .release);
            self.once = true;
            defer self.once = false;
            defer self.notifyLocal(false) catch {};
            while (self.target.connection() != null) {
                _ = self.step(poll_options) catch |err| switch (err) {
                    error.Canceled, error.ConnectionClosed => return,
                    else => return err,
                };
                if (connected) |state| {
                    state.store(
                        self.target.connection() != null,
                        .release,
                    );
                }
            }
        }

        fn notifyLocal(self: *Self, online: bool) Error!void {
            if (Source == local_source.Client) {
                const value = self.notifications orelse return;
                if (self.local_online == online) return;
                const publish = mqtt.Publish{ .dup = false, .qos = .at_least_once, .retain = true, .topic = value.topic, .packet_id = null, .properties = &.{}, .payload = if (online) "1" else "0" };
                if (self.inbound_rules.values.len != 0 and
                    self.source.consumer != null)
                {
                    try self.source.broker.publishLocalFromConsumer(
                        &self.source.consumer.?,
                        publish,
                    );
                } else {
                    try self.source.broker.publishLocal(publish);
                }
                self.local_online = online;
            }
        }

        fn notify(self: *Self, online: bool) Error!void {
            if (self.notifications) |value| {
                if (value.publish_remote) if (self.target.connection()) |active| {
                    _ = try self.target.publishOneAttempt(value.topic, if (online) "1" else "0", .{
                        .qos = .at_most_once,
                        .retain = self.preserve_retain and
                            active.peerRetainAvailable(),
                    });
                };
                try self.notifyLocal(online);
            }
        }

        const forwarding = @import("outbound_forward.zig").Operations(Self);
        const forward = forwarding.forward;
        const publishTarget = forwarding.publishTarget;

        pub fn forwardDurableQoS2(
            self: *Self,
            source_publish: *const mqtt.Publish,
            target_topic: []const u8,
            properties: []mqtt.Property,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            if (!try self.stageDurableQoS2(
                source_publish,
                target_topic,
                properties,
            )) return;
            try self.target.flushPending();
            try self.driveDurableQoS2(poll_options);
        }

        fn stageDurableQoS2(
            self: *Self,
            source_publish: *const mqtt.Publish,
            target_topic: []const u8,
            properties: []mqtt.Property,
        ) Error!bool {
            const target_connection = self.target.connection() orelse
                return error.ConnectionUnavailable;
            if (target_connection.peerMaximumQoS() != .exactly_once) {
                const source_packet_id = source_publish.packet_id.?;
                try self.source.stageIncomingQoS2(source_packet_id);
                var staged = true;
                defer if (staged) {
                    self.source.discardStagedIncomingQoS2(
                        source_packet_id,
                    ) catch {};
                };
                if (self.sourceProtocol() != .v5) {
                    return error.InvalidQoS;
                }
                try self.source.flushStagedIncomingQoS2(
                    source_packet_id,
                    // QoS Not Supported (0x9b) describes the target's
                    // CONNACK capability but is not legal in PUBREC. Use the
                    // packet-specific Implementation Specific Error instead.
                    .{ .reason_code = 0x83 },
                );
                staged = false;
                return false;
            }
            const coordinator = &(self.coordinator orelse
                return error.QoS2RequiresDurableCoordinator);
            const source_packet_id = source_publish.packet_id.?;
            try self.source.stageIncomingQoS2(source_packet_id);
            var committed = false;
            errdefer if (!committed) {
                self.source.discardStagedIncomingQoS2(
                    source_packet_id,
                ) catch {};
            };
            self.target_delivery.reset();
            const target_packet_id = self.target.stagePublish(
                target_topic,
                source_publish.payload,
                .{
                    .qos = .exactly_once,
                    .retain = self.preserve_retain and
                        source_publish.retain and
                        target_connection.peerRetainAvailable(),
                    .properties = properties,
                },
            ) catch |err| switch (err) {
                error.OutgoingPacketTooLarge => {
                    // A negative MQTT 5 PUBREC completes the source QoS 2
                    // transaction without creating a target transaction.
                    // MQTT 3.1.1 cannot represent a negative PUBREC, so retain
                    // the previous fail-closed behavior for network sources.
                    if (self.sourceProtocol() != .v5) return err;
                    try self.source.flushStagedIncomingQoS2(
                        source_packet_id,
                        .{ .reason_code = 0x97 },
                    );
                    return false;
                },
                else => {
                    try self.source.discardStagedIncomingQoS2(
                        source_packet_id,
                    );
                    return err;
                },
            };
            errdefer if (!committed) {
                self.target.discardStagedPublish(target_packet_id) catch {};
            };
            const transaction: coordinator_mod.Transaction = .{
                .phase = .target_await_pubrec,
                .source_session_epoch = self.source_session_epoch,
                .target_session_epoch = self.target_session_epoch,
                .source_packet_id = source_packet_id,
                .target_packet_id = target_packet_id,
                .target_reason_code = 0,
                .source_retain = source_publish.retain,
                .source_topic = source_publish.topic,
                .source_payload = source_publish.payload,
                .source_properties = properties,
                .source_expiry_interval = mqtt.messageExpiryInterval(properties),
            };
            _ = try coordinator.commit(
                &self.source,
                &self.target,
                self.source_session_epoch,
                self.target_session_epoch,
                transaction,
            );
            committed = true;
            return true;
        }

        fn driveDurableQoS2(
            self: *Self,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            while (self.durableTransaction() != null) {
                try self.validateDurableSourceState();
                try self.validateDurableTargetState();
                if (try self.commitCompletedTargetDelivery()) continue;
                if (try @import("outbound_expiry.zig").completeExpiredTarget(self)) continue;
                if (try self.reconcileDurableTargetState()) continue;
                if (try self.completeDurableSourceIfReady()) continue;
                if (self.poll_source_next) {
                    self.poll_source_next = false;
                    try self.driveDurableSource(bridgeClientPollOptions(
                        &self.source,
                        poll_options,
                    ));
                } else {
                    self.poll_source_next = true;
                    try self.driveDurableTarget(bridgeClientPollOptions(
                        &self.target,
                        poll_options,
                    ));
                }
            }
        }

        fn driveDurableTarget(
            self: *Self,
            bounded: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            if (try self.commitCompletedTargetDelivery()) return;
            if (try @import("outbound_expiry.zig").completeExpiredTarget(self)) return;
            if (self.once and self.target.connection() == null) return error.ConnectionClosed;
            var event = self.pollTarget(bounded) catch |err| {
                if (err == error.PublishRefused) {
                    if (try self.commitCompletedTargetDelivery()) return;
                    self.target.disconnectTransport();
                    return error.TargetAcknowledgementMismatch;
                }
                return err;
            } orelse return;
            defer event.deinit(self.allocator);
            const transaction = self.durableTransaction() orelse return;
            switch (event) {
                .connected => |connected| {
                    try self.noteTargetConnected(connected);
                    try self.validateDurableTargetState();
                },
                .pubrec => |owned| {
                    if (transaction.phase != .target_await_pubrec or
                        owned.ack.packet_id != transaction.target_packet_id)
                    {
                        self.target.disconnectTransport();
                        return error.TargetAcknowledgementMismatch;
                    }
                    if (!owned.ack.accepted()) {
                        // The reconnect Session has already removed its target
                        // inflight entry for a terminal negative PUBREC. Persist
                        // that same terminal state before acknowledging the
                        // source; committing await_pubcomp here would describe an
                        // inflight entry that no longer exists.
                        var rejected = transaction;
                        rejected.phase = .target_rejected;
                        rejected.target_reason_code = owned.ack.reason_code;
                        try self.commitDurable(rejected);
                        self.target_delivery.reset();
                        _ = try self.completeDurableSourceIfReady();
                        return;
                    }
                    var advanced = transaction;
                    advanced.phase = .target_await_pubcomp;
                    try self.commitDurable(advanced);
                    try self.target.flushPending();
                },
                .pubcomp => |owned| {
                    if (transaction.phase != .target_await_pubcomp or
                        owned.ack.packet_id != transaction.target_packet_id)
                    {
                        self.target.disconnectTransport();
                        return error.TargetAcknowledgementMismatch;
                    }
                    var completed = transaction;
                    completed.phase = .target_complete;
                    completed.target_reason_code = owned.ack.reason_code;
                    try self.commitDurable(completed);
                    self.target_delivery.reset();
                    _ = try self.completeDurableSourceIfReady();
                },
                .disconnect => self.target.disconnectTransport(),
                .publish => |owned| try self.handleTargetPublish(
                    &owned.publish,
                ),
                .pubrel => |owned| try self.handleTargetPubRel(
                    owned.ack.packet_id,
                ),
                .pingreq, .pingresp, .auth => {},
                .puback => {
                    self.target.disconnectTransport();
                    return error.UnexpectedPacket;
                },
            }
        }

        fn commitCompletedTargetDelivery(self: *Self) Error!bool {
            if (!self.target_delivery.completed) return false;
            const transaction = self.durableTransaction() orelse
                return error.TargetAcknowledgementMismatch;
            if (self.target_delivery.packet_id != transaction.target_packet_id) {
                return error.TargetAcknowledgementMismatch;
            }
            var completed = transaction;
            if (transaction.phase == .target_await_pubrec) {
                completed.phase = .target_rejected;
                completed.target_reason_code = self.target_delivery.reason_code;
            } else {
                // A negative PUBCOMP cannot prove that the target did not accept
                // the Application Message. Finish the source handshake as success
                // rather than risk publishing it again.
                completed.phase = .target_complete;
                completed.target_reason_code = 0;
            }
            try self.commitDurable(completed);
            self.target_delivery.reset();
            _ = try self.completeDurableSourceIfReady();
            return true;
        }

        fn driveDurableSource(
            self: *Self,
            bounded: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            var event = try self.source.pollWithOptions(bounded) orelse return;
            defer event.deinit(self.allocator);
            const transaction = self.durableTransaction() orelse return;
            switch (event) {
                .connected => |connected| try self.noteSourceConnected(connected),
                .publish => |owned| {
                    if (!durablePublishMatches(transaction, owned.publish)) {
                        self.source.disconnectTransport();
                        return error.InvalidPacketIdentifier;
                    }
                    if (transaction.phase == .target_complete or
                        transaction.phase == .target_rejected)
                    {
                        if (self.source_pubrec_flushed) return;
                        try self.source.flushStagedIncomingQoS2(
                            transaction.source_packet_id,
                            .{ .reason_code = transaction.target_reason_code },
                        );
                        if (transaction.phase == .target_rejected) {
                            try self.commitDurable(null);
                        } else {
                            self.source_pubrec_flushed = true;
                        }
                    }
                },
                .pubrel => |owned| {
                    if (transaction.phase != .target_complete or
                        owned.ack.packet_id != transaction.source_packet_id)
                    {
                        self.source.disconnectTransport();
                        return error.UnexpectedPacket;
                    }
                    try self.source.stageIncomingQoS2Completion(
                        transaction.source_packet_id,
                        .{},
                    );
                    self.commitDurable(null) catch |err| {
                        try self.source.discardStagedIncomingQoS2Completion(
                            transaction.source_packet_id,
                        );
                        return err;
                    };
                    try self.source.writeStagedIncomingQoS2Completion(
                        transaction.source_packet_id,
                        .{},
                    );
                },
                .disconnect => self.source.disconnectTransport(),
                .pingreq, .pingresp, .auth => {},
                .puback, .pubrec, .pubcomp => {
                    self.source.disconnectTransport();
                    return error.UnexpectedPacket;
                },
            }
        }

        fn completeDurableSourceIfReady(self: *Self) Error!bool {
            const transaction = self.durableTransaction() orelse return false;
            if (transaction.phase != .target_complete and
                transaction.phase != .target_rejected) return false;
            if (transaction.source_session_epoch != self.source_session_epoch) {
                try self.commitDurable(null);
                return true;
            }
            if (try self.source.incomingQoS2State(
                transaction.source_packet_id,
            )) |state| {
                if (state == .release_pending) {
                    return false;
                }
                if (state == .await_pubrel) {
                    if (self.source_pubrec_flushed) return false;
                    if (self.sourceConnected()) {
                        try self.source.flushStagedIncomingQoS2(
                            transaction.source_packet_id,
                            .{ .reason_code = transaction.target_reason_code },
                        );
                        if (transaction.phase == .target_rejected) {
                            try self.commitDurable(null);
                        } else {
                            self.source_pubrec_flushed = true;
                        }
                        return true;
                    }
                    return false;
                }
                return false;
            }
            // PUBCOMP was already written and only the final clear commit failed.
            // Unknown duplicate PUBREL packets remain idempotently acknowledged by
            // the reconnect client, so dropping the coordinator record is safe.
            try self.commitDurable(null);
            return true;
        }

        fn reconcileDurableTargetState(self: *Self) Error!bool {
            const transaction = self.durableTransaction() orelse return false;
            if (transaction.phase != .target_await_pubrec) return false;
            const state = try self.target.outgoingQoSState(
                transaction.target_packet_id,
            );
            if (state != .await_pubcomp) return false;
            var advanced = transaction;
            advanced.phase = .target_await_pubcomp;
            try self.commitDurable(advanced);
            try self.target.flushPending();
            return true;
        }

        fn validateDurableTargetState(self: *Self) Error!void {
            const transaction = self.durableTransaction() orelse return;
            if (transaction.target_session_epoch != self.target_session_epoch) {
                return error.TargetSessionLost;
            }
            if (transaction.phase == .target_await_pubcomp and self.target.connection() != null) {
                try self.target.flushPending();
            }
        }

        fn validateDurableSourceState(self: *Self) Error!void {
            const transaction = self.durableTransaction() orelse return;
            if (@hasDecl(Source, "validateTransaction")) {
                if (transaction.phase != .target_complete and transaction.phase != .target_rejected) {
                    try self.source.validateTransaction(transaction.source_packet_id);
                }
            }
            if (transaction.phase != .target_complete and
                transaction.phase != .target_rejected and
                transaction.source_session_epoch != self.source_session_epoch)
            {
                return error.SourceSessionLost;
            }
        }

        pub fn noteTargetConnected(
            self: *Self,
            connected: reconnect.ConnectEvent,
        ) Error!void {
            self.target_session_present = connected.session_present;
            if (self.target_session_epoch == 0 and self.coordinator != null and connected.session_resumed) {
                self.target_session_epoch = 1;
            }
            if (!connected.session_resumed) {
                self.target_session_epoch +%= 1;
                if (self.target_session_epoch == 0) self.target_session_epoch = 1;
            }
            if (self.durableTransaction()) |transaction| {
                if (transaction.phase != .target_complete and
                    transaction.phase != .target_rejected and
                    (!connected.session_resumed or
                        transaction.target_session_epoch !=
                            self.target_session_epoch))
                {
                    return error.TargetSessionLost;
                }
                if ((transaction.phase == .target_complete or transaction.phase == .target_rejected) and
                    transaction.target_session_epoch != self.target_session_epoch)
                {
                    // The durable result no longer depends on the old target
                    // Session. Rebind that result to its new epoch before any
                    // source acknowledgement or subsequent coordinator commit.
                    var completed = transaction;
                    completed.target_session_epoch = self.target_session_epoch;
                    try self.commitDurable(completed);
                }
            }
            try self.cleanupTargetSubscriptions();
            if (self.inbound_rules.values.len != 0) {
                if (comptime Source != local_source.Client) unreachable;
                try inbound_flow.noteConnected(
                    self.allocator,
                    self.source.broker,
                    &self.target,
                    self.inbound_rules.values,
                    self.inbound_bridge_id,
                    &self.inbound_session_epoch,
                    self.inbound_qos2_enabled,
                    connected,
                );
            }
            try self.notify(true);
        }

        fn cleanupTargetSubscriptions(self: *Self) Error!void {
            if (!self.attempt_target_unsubscribe) return;
            if (self.inbound_rules.values.len == 0) {
                return self.unsubscribeTargetFilters(
                    self.rules.target_filters,
                );
            }
            var stale_filters: std.ArrayList([]const u8) = .empty;
            defer stale_filters.deinit(self.allocator);
            try stale_filters.ensureTotalCapacity(
                self.allocator,
                self.rules.target_filters.len,
            );
            for (self.rules.target_filters) |filter| {
                if (containsInboundFilter(
                    self.inbound_rules.values,
                    filter,
                )) continue;
                stale_filters.appendAssumeCapacity(filter);
            }
            if (stale_filters.items.len != 0) {
                try self.unsubscribeTargetFilters(stale_filters.items);
            }
        }

        fn unsubscribeTargetFilters(
            self: *Self,
            filters: []const []const u8,
        ) Error!void {
            var unsuback = self.target.unsubscribe(filters, .{}) catch |err|
                switch (err) {
                    error.OutgoingPacketTooLarge => {
                        if (filters.len == 1) return err;
                        const middle = filters.len / 2;
                        try self.unsubscribeTargetFilters(filters[0..middle]);
                        return self.unsubscribeTargetFilters(filters[middle..]);
                    },
                    else => return err,
                };
            defer unsuback.deinit(self.allocator);
            for (unsuback.unsuback.reason_codes) |reason_code| {
                if (reason_code >= 0x80) {
                    return error.TargetUnsubscribeRefused;
                }
            }
        }

        fn durableTransaction(
            self: *const Self,
        ) ?coordinator_mod.Transaction {
            const coordinator = if (self.coordinator) |*value| value else return null;
            return coordinator.currentTransaction();
        }

        fn commitDurable(
            self: *Self,
            transaction: ?coordinator_mod.Transaction,
        ) Error!void {
            const coordinator = &(self.coordinator orelse
                return error.QoS2RequiresDurableCoordinator);
            _ = try coordinator.commit(
                &self.source,
                &self.target,
                self.source_session_epoch,
                self.target_session_epoch,
                transaction,
            );
            if (transaction == null) self.source_pubrec_flushed = false;
        }

        pub fn connectTargetWhileServingSource(
            self: *Self,
            current: *const mqtt.Publish,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            const bounded = bridgePollOptions(poll_options);
            while (self.target.connection() == null) {
                if (self.once) return error.ConnectionClosed;
                try self.notifyLocal(false);
                var event = try self.pollTarget(
                    bridgeClientPollOptions(&self.target, poll_options),
                ) orelse {
                    try self.serviceSourceWhileWaiting(current, bounded);
                    continue;
                };
                defer event.deinit(self.allocator);
                switch (event) {
                    .connected => |connected| try self.noteTargetConnected(
                        connected,
                    ),
                    .disconnect => self.target.disconnectTransport(),
                    .pingreq, .pingresp, .auth => {},
                    .publish => |owned| try self.handleTargetPublish(
                        &owned.publish,
                    ),
                    .pubrel => |owned| try self.handleTargetPubRel(
                        owned.ack.packet_id,
                    ),
                    .puback, .pubrec, .pubcomp => {
                        self.target.disconnectTransport();
                        return error.UnexpectedPacket;
                    },
                }
                try self.serviceSourceWhileWaiting(current, bounded);
            }
        }

        pub fn handleTargetPublish(
            self: *Self,
            publish: *const mqtt.Publish,
        ) Error!void {
            if (self.inbound_rules.values.len == 0) {
                // An outbound-only remote Session can replay traffic from a
                // stale subscription before cleanup. Its automatic receive
                // policy has already acknowledged it, so discard it.
                return;
            }
            if (comptime Source != local_source.Client) unreachable;
            if (!self.source.isConnected()) {
                const connected = try self.source.connect();
                try self.noteSourceConnected(connected);
            }
            try inbound_flow.inject(
                self.allocator,
                self.source.broker,
                &self.target,
                &self.source.consumer.?,
                self.inbound_rules.values,
                self.inbound_bridge_id,
                self.inbound_session_epoch,
                self.inbound_qos2_enabled,
                publish,
            );
        }

        pub fn handleTargetPubRel(
            self: *Self,
            packet_id: u16,
        ) Error!void {
            if (self.inbound_rules.values.len == 0) return;
            if (comptime Source != local_source.Client) unreachable;
            if (!self.source.isConnected()) {
                const connected = try self.source.connect();
                try self.noteSourceConnected(connected);
            }
            try inbound_flow.releaseQoS2(
                self.source.broker,
                &self.target,
                &self.source.consumer.?,
                self.inbound_bridge_id,
                self.inbound_session_epoch,
                self.inbound_qos2_enabled,
                packet_id,
            );
        }

        pub fn acknowledgeSource(
            self: *Self,
            source_publish: *const mqtt.Publish,
            reason_code: u8,
        ) bool {
            if (source_publish.qos == .at_most_once) return true;
            const protocol_reason = if (self.sourceConnected() and self.sourceProtocol() == .v5)
                reason_code
            else
                0;
            self.source.acknowledge(
                source_publish.packet_id.?,
                .at_least_once,
                .{ .reason_code = protocol_reason },
            ) catch {
                // The target delivery is complete, but a source PUBACK write can
                // be ambiguous. Retire that transport without failing the
                // long-running bridge. A durable source Session either accepted
                // the ACK already or retransmits for another at-least-once target
                // delivery after reconnect.
                self.source.disconnectTransport();
                return false;
            };
            return true;
        }

        pub fn completeSource(
            self: *Self,
            source_publish: *const mqtt.Publish,
            source_epoch: u64,
            reason_code: u8,
        ) void {
            if (source_publish.qos == .at_most_once or
                source_epoch != self.source_session_epoch) return;
            const completed = CompletedSource.init(
                self.allocator,
                source_epoch,
                reason_code,
                source_publish.*,
            ) catch {
                self.source.disconnectTransport();
                return;
            };
            if (self.completed_source) |*previous| previous.deinit(self.allocator);
            self.completed_source = completed;
            _ = self.acknowledgeSource(source_publish, reason_code);
        }

        fn consumeCompletedSourceRetry(
            self: *Self,
            publish: *const mqtt.Publish,
        ) Error!bool {
            if (publish.qos != .at_least_once) return false;
            const completed = self.completed_source orelse return false;
            if (completed.session_epoch != self.source_session_epoch or
                completed.packet_id != publish.packet_id.?) return false;
            if (!publish.dup) {
                var retired = self.completed_source.?;
                self.completed_source = null;
                retired.deinit(self.allocator);
                return false;
            }
            if (!completed.matches(publish.*)) {
                self.source.disconnectTransport();
                return error.InvalidPacketIdentifier;
            }
            _ = self.acknowledgeSource(publish, completed.reason_code);
            return true;
        }

        pub fn serviceSourceWhileWaiting(
            self: *Self,
            current: *const mqtt.Publish,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            var event = try self.source.pollWithOptions(poll_options) orelse return;
            defer event.deinit(self.allocator);
            switch (event) {
                .connected => |connected| try self.noteSourceConnected(connected),
                .publish => |owned| {
                    const publish = &owned.publish;
                    if (publish.qos == .at_most_once) return;
                    if (try self.consumeCompletedSourceRetry(publish)) return;
                    if (publishRetryMatches(current.*, publish.*)) return;
                    if (publish.qos == .at_least_once and publish.dup and
                        publish.packet_id == current.packet_id)
                    {
                        self.source.disconnectTransport();
                        return error.InvalidPacketIdentifier;
                    }
                    // One QoS 1 transaction already owns the target boundary.
                    // Closing the persistent source Session applies backpressure
                    // without accepting another message into local memory.
                    self.source.disconnectTransport();
                },
                .disconnect => self.source.disconnectTransport(),
                .pingreq, .pingresp, .auth => {},
                .puback, .pubrec, .pubrel, .pubcomp => {
                    self.source.disconnectTransport();
                    return error.UnexpectedPacket;
                },
            }
        }

        fn noteSourceConnected(
            self: *Self,
            connected: reconnect.ConnectEvent,
        ) Error!void {
            self.source_session_present = connected.session_present;
            self.source_pubrec_flushed = false;
            if (connected.session_resumed) {
                // A new coordinator can attach to an existing network or
                // broker-local Session. Its first observed Session needs a
                // nonzero epoch before staging any cross-broker transaction.
                if (self.source_session_epoch == 0) {
                    self.source_session_epoch = 1;
                    if (self.coordinator != null) try self.commitDurable(null);
                }
                if (self.durableTransaction()) |transaction| {
                    if (transaction.source_session_epoch !=
                        self.source_session_epoch)
                    {
                        return error.SourceSessionLost;
                    }
                }
                return;
            }
            if (self.durableTransaction()) |transaction| {
                if (transaction.phase != .target_complete and
                    transaction.phase != .target_rejected)
                {
                    self.source_session_epoch +%= 1;
                    if (self.source_session_epoch == 0) {
                        self.source_session_epoch = 1;
                    }
                    return error.SourceSessionLost;
                }
            }
            self.source_session_epoch +%= 1;
            if (self.source_session_epoch == 0) self.source_session_epoch = 1;
            if (self.completed_source) |*completed| {
                completed.deinit(self.allocator);
            }
            self.completed_source = null;
            if (self.coordinator) |*coordinator| {
                const transaction = coordinator.currentTransaction();
                if (transaction) |value| {
                    if (value.phase == .target_complete or
                        value.phase == .target_rejected)
                    {
                        _ = try coordinator.commit(
                            &self.source,
                            &self.target,
                            self.source_session_epoch,
                            self.target_session_epoch,
                            null,
                        );
                        return;
                    }
                    return error.SourceSessionLost;
                }
                _ = try coordinator.commit(
                    &self.source,
                    &self.target,
                    self.source_session_epoch,
                    self.target_session_epoch,
                    transaction,
                );
            }
        }

        pub fn matchingRule(self: *const Self, topic: []const u8) ?*const OwnedRule {
            var matched: ?*const OwnedRule = null;
            for (self.rules.values) |*rule| {
                if (!mqtt.topicMatchesFilter(topic, rule.source_filter)) continue;
                if (matched != null) return null;
                matched = rule;
            }
            return matched;
        }

        pub fn sourceConnected(self: *Self) bool {
            return if (@hasDecl(Source, "isConnected")) self.source.isConnected() else self.source.connection() != null;
        }

        pub fn sourceProtocol(self: *Self) mqtt.ProtocolVersion {
            return if (@hasDecl(Source, "protocolVersion")) self.source.protocolVersion() else self.source.options.value.protocol;
        }

        fn initSource(
            allocator: std.mem.Allocator,
            io: std.Io,
            endpoint: SourceEndpoint,
            connect_options: runtime.ConnectOptions,
            policy: reconnect.ReconnectPolicy,
            shutdown: *std.Io.Event,
            client_options: reconnect.ClientOptions,
            replace_local_source_subscriptions: bool,
        ) Error!Source {
            if (Source == reconnect.Client) return initClient(allocator, io, endpoint, connect_options, policy, shutdown, client_options);
            return Source.init(
                allocator,
                io,
                endpoint.broker,
                endpoint.id,
                connect_options,
                shutdown,
                replace_local_source_subscriptions,
            );
        }
    };
}

fn initClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: Endpoint,
    connect_options: runtime.ConnectOptions,
    policy: reconnect.ReconnectPolicy,
    shutdown: *std.Io.Event,
    client_options: reconnect.ClientOptions,
) Error!reconnect.Client {
    return switch (endpoint) {
        .address => |address| reconnect.Client.initWithOptions(
            allocator,
            io,
            address,
            connect_options,
            policy,
            shutdown,
            client_options,
        ),
        .host => |host| reconnect.Client.initHostWithOptions(
            allocator,
            io,
            host.name,
            host.port,
            connect_options,
            policy,
            shutdown,
            client_options,
        ),
        .connector => |connector| reconnect.Client.initConnectorWithOptions(
            allocator,
            io,
            connector,
            connect_options,
            policy,
            shutdown,
            client_options,
        ),
    };
}

fn lazyPollOptions(
    options: reconnect.PollOptions,
    idle_deadline: ?std.Io.Clock.Timestamp,
    io: std.Io,
) reconnect.PollOptions {
    const deadline = idle_deadline orelse return options;
    const remaining_ns = deadline.durationFromNow(io).raw.nanoseconds;
    var bounded = options;
    bounded.timeout = .fromNanoseconds(@min(
        bounded.timeout.nanoseconds,
        @max(remaining_ns, 1),
    ));
    bounded.cancellation_check_interval = .fromNanoseconds(@min(
        bounded.cancellation_check_interval.nanoseconds,
        bounded.timeout.nanoseconds,
    ));
    return bounded;
}

test {
    _ = @import("outbound_tests.zig");
    _ = coordinator_mod;
    _ = delivery_values;
}

pub const testing = if (builtin.is_test) struct {
    pub fn stageNextDurableQoS2(
        bridge: anytype,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        var event = try bridge.source.pollWithOptions(poll_options) orelse
            return error.Timeout;
        defer event.deinit(bridge.allocator);
        const publish = switch (event) {
            .publish => |*owned| &owned.publish,
            else => return error.UnexpectedPacket,
        };
        const rule = bridge.matchingRule(publish.topic) orelse
            return error.TopicOutsideBridgeRule;
        if (publish.qos != .exactly_once or
            rule.value.qos != .exactly_once)
        {
            return error.InvalidBridgeQoS;
        }
        const target_topic = try rule.value.mapMatchedTopicAlloc(
            bridge.allocator,
            publish.topic,
        );
        defer bridge.allocator.free(target_topic);
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(bridge.allocator);
        try properties.ensureTotalCapacity(
            bridge.allocator,
            publish.properties.len,
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
        _ = try bridge.stageDurableQoS2(
            publish,
            target_topic,
            properties.items,
        );
    }

    pub fn flushDurableTarget(bridge: anytype) Error!void {
        try bridge.target.flushPending();
    }

    pub fn stageTargetPubRec(
        bridge: anytype,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        var event = try bridge.target.pollWithOptions(poll_options) orelse
            return error.Timeout;
        defer event.deinit(bridge.allocator);
        const ack = switch (event) {
            .pubrec => |*owned| owned.ack,
            else => return error.UnexpectedPacket,
        };
        const transaction = bridge.durableTransaction() orelse
            return error.UnexpectedPacket;
        if (transaction.phase != .target_await_pubrec or
            ack.packet_id != transaction.target_packet_id or
            !ack.accepted())
        {
            return error.TargetAcknowledgementMismatch;
        }
        var advanced = transaction;
        advanced.phase = .target_await_pubcomp;
        try bridge.commitDurable(advanced);
    }

    pub fn completeDurableTarget(
        bridge: anytype,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        try bridge.driveDurableTarget(poll_options);
    }

    pub fn stageDurableSourcePubRel(
        bridge: anytype,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        var event = try bridge.source.pollWithOptions(poll_options) orelse
            return error.Timeout;
        defer event.deinit(bridge.allocator);
        const ack = switch (event) {
            .pubrel => |*owned| owned.ack,
            else => return error.UnexpectedPacket,
        };
        const transaction = bridge.durableTransaction() orelse
            return error.UnexpectedPacket;
        if (transaction.phase != .target_complete or
            ack.packet_id != transaction.source_packet_id)
        {
            return error.UnexpectedPacket;
        }
        try bridge.source.stageIncomingQoS2Completion(
            transaction.source_packet_id,
            .{},
        );
        bridge.commitDurable(null) catch |err| {
            try bridge.source.discardStagedIncomingQoS2Completion(
                transaction.source_packet_id,
            );
            return err;
        };
    }
} else struct {};

fn rulesUseQoS1(rules: []const OwnedRule) bool {
    for (rules) |rule| {
        if (rule.value.qos == .at_least_once) return true;
    }
    return false;
}

fn rulesUseQoS2(rules: []const OwnedRule) bool {
    for (rules) |rule| {
        if (rule.value.qos == .exactly_once) return true;
    }
    return false;
}

fn containsInboundFilter(
    rules: []const InboundRule,
    filter: []const u8,
) bool {
    for (rules) |rule| {
        if (std.mem.eql(u8, rule.filter, filter)) return true;
    }
    return false;
}

fn coordinatorIdentity(
    bridge_id: [16]u8,
    source_connect: runtime.ConnectOptions,
    target_connect: runtime.ConnectOptions,
    rules: []const OwnedRule,
    inbound_rules: []const InboundRule,
    preserve_retain: bool,
) coordinator_mod.Identity {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&bridge_id);
    hashIdentityByte(&hasher, source_connect.protocol.byte());
    hashIdentityField(&hasher, source_connect.client_id);
    hashIdentityByte(&hasher, target_connect.protocol.byte());
    hashIdentityField(&hasher, target_connect.client_id);
    hashIdentityByte(&hasher, @intFromBool(preserve_retain));
    var count: [8]u8 = undefined;
    std.mem.writeInt(u64, &count, rules.len, .big);
    hasher.update(&count);
    for (rules) |rule| {
        hashIdentityField(&hasher, rule.value.filter);
        hashIdentityByte(&hasher, @intFromEnum(rule.value.qos));
        hashIdentityField(&hasher, rule.value.local_prefix);
        hashIdentityField(&hasher, rule.value.remote_prefix);
        hashIdentityByte(&hasher, @intFromBool(rule.value.no_local));
    }
    std.mem.writeInt(u64, &count, inbound_rules.len, .big);
    hasher.update(&count);
    for (inbound_rules) |rule| {
        hashIdentityField(&hasher, rule.filter);
        hashIdentityByte(&hasher, @intFromEnum(rule.qos));
        hashIdentityField(&hasher, rule.local_prefix);
        hashIdentityField(&hasher, rule.remote_prefix);
        hashIdentityByte(&hasher, @intFromBool(rule.no_local));
    }
    var identity: coordinator_mod.Identity = undefined;
    hasher.final(&identity);
    return identity;
}

fn hashIdentityField(
    hasher: *std.crypto.hash.sha2.Sha256,
    value: []const u8,
) void {
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, value.len, .big);
    hasher.update(&len);
    hasher.update(value);
}

fn hashIdentityByte(
    hasher: *std.crypto.hash.sha2.Sha256,
    value: u8,
) void {
    hasher.update(&.{value});
}

fn persistentSession(connect: runtime.ConnectOptions) bool {
    if (connect.clean_start) return false;
    return switch (connect.protocol) {
        .v3_1, .v3_1_1 => true,
        .v5 => (mqtt.sessionExpiryInterval(connect.properties) orelse 0) != 0,
    };
}

pub fn refreshMessageExpiry(
    properties: []mqtt.Property,
    original: ?u32,
    received_at_ns: i96,
    now_ns: i96,
) bool {
    const interval = original orelse return true;
    if (interval == 0) return false;
    const elapsed_ns = @max(now_ns - received_at_ns, 0);
    const expiry_ns = @as(i96, interval) * std.time.ns_per_s;
    if (elapsed_ns >= expiry_ns) return false;
    const elapsed_seconds: u32 = @intCast(
        @divTrunc(elapsed_ns, std.time.ns_per_s),
    );
    for (properties) |*property| {
        if (property.* == .four_byte and
            property.four_byte.id == .message_expiry_interval)
        {
            property.four_byte.value = interval - elapsed_seconds;
            break;
        }
    }
    return true;
}

pub fn bridgePollOptions(options: reconnect.PollOptions) reconnect.PollOptions {
    var bounded = options;
    bounded.timeout = .fromNanoseconds(@min(
        bounded.timeout.nanoseconds,
        std.time.ns_per_ms * 50,
    ));
    bounded.cancellation_check_interval = .fromNanoseconds(@min(
        bounded.cancellation_check_interval.nanoseconds,
        bounded.timeout.nanoseconds,
    ));
    // A transport failure found during this short fairness slice must not
    // force a complete TCP/TLS/MQTT reconnect into the same 50-ms budget.
    // The next bridge turn sees a disconnected endpoint and preserves the
    // caller's full timeout for that indivisible connection attempt.
    bounded.reconnect_after_transport_error = false;
    return bounded;
}

pub fn bridgeClientPollOptions(
    client: anytype,
    options: reconnect.PollOptions,
) reconnect.PollOptions {
    // A TCP/TLS/MQTT connection attempt cannot be paused at the bridge's
    // fairness boundary. Preserve the caller's complete deadline while an
    // endpoint reconnects; only established idle reads use the short slice.
    return bridgeEndpointPollOptions(if (@hasDecl(@TypeOf(client.*), "isConnected")) client.isConnected() else client.connection() != null, options);
}

fn bridgeEndpointPollOptions(
    connected: bool,
    options: reconnect.PollOptions,
) reconnect.PollOptions {
    return if (connected) bridgePollOptions(options) else options;
}

test "outbound bridge preserves reconnect budget across fairness slices" {
    const options: reconnect.PollOptions = .{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    };
    try std.testing.expectEqual(
        options.timeout.nanoseconds,
        bridgeEndpointPollOptions(false, options).timeout.nanoseconds,
    );
    try std.testing.expect(
        bridgeEndpointPollOptions(false, options)
            .reconnect_after_transport_error,
    );
    try std.testing.expectEqual(
        @as(
            @TypeOf(options.timeout.nanoseconds),
            50 * std.time.ns_per_ms,
        ),
        bridgeEndpointPollOptions(true, options).timeout.nanoseconds,
    );
    try std.testing.expect(
        !bridgeEndpointPollOptions(true, options)
            .reconnect_after_transport_error,
    );
}

//! MQTT broker bridge primitives.
//!
//! `Bridge` owns one reconnecting client, subscribes to one or more disjoint
//! remote Topic Filters, maps each incoming Topic Name beneath its rule's local
//! prefix, and injects the resulting Application Message through
//! `Broker.publishLocal`.
//! `OutboundBridge` composes a broker-local source Session with one remote
//! Session. It can also install inbound rules on that same remote Client,
//! providing bidirectional forwarding with explicit loop prevention.

const std = @import("std");
const builtin = @import("builtin");
const mqtt = @import("mod.zig");
const broker_mod = @import("broker.zig");
const reconnect = @import("reconnect.zig");
const runtime = @import("runtime.zig");
const inbound_flow = @import("bridge/inbound_flow.zig");

pub const outbound = @import("bridge/outbound.zig");
pub const OutboundBridge = outbound.Bridge;
pub const OutboundRule = outbound.Rule;
pub const Rule = inbound_flow.Rule;

const net = std.Io.net;

const Remote = union(enum) {
    address: net.IpAddress,
    host: struct {
        name: []const u8,
        port: u16,
    },
    connector: runtime.ClientConnector,
};

pub const Error = broker_mod.Error || reconnect.Error || error{
    NoBridgeRules,
    DuplicateBridgeFilter,
    OverlappingBridgeFilters,
    MissingBridgeIdentifier,
    InvalidBridgePrefix,
    InvalidBridgeQoS,
    QoS2RequiresPersistentSession,
    QoS2RequiresCommitLog,
    TopicOutsideBridgeRule,
    EmptyMappedTopic,
    BridgeNotificationWillConflict,
};

/// Optional retained bridge-state publication on the local and/or remote
/// broker. The topic is copied during construction. Remote notifications use
/// a retained QoS 1 `"0"` Will and publish retained `"1"` after setup.
pub const NotificationOptions = struct {
    topic: []const u8,
    publish_local: bool = true,
    publish_remote: bool = true,
};

pub const Options = struct {
    connect: runtime.ConnectOptions,
    reconnect_policy: reconnect.ReconnectPolicy = .{},
    rule: Rule,
    /// Stable deployment identity for durable QoS 2 transactions. Required
    /// when `rule.qos` is QoS 2 and must remain unchanged with the Client ID
    /// and rule mapping across restarts.
    bridge_id: ?[16]u8 = null,
    notifications: ?NotificationOptions = null,
};

pub const MultiOptions = struct {
    connect: runtime.ConnectOptions,
    reconnect_policy: reconnect.ReconnectPolicy = .{},
    rules: []const Rule,
    /// Stable deployment identity shared by every QoS 2 rule; it, the Client
    /// ID, and all rule mappings must remain unchanged across restarts.
    bridge_id: ?[16]u8 = null,
    notifications: ?NotificationOptions = null,
};

const OwnedRules = inbound_flow.OwnedRules;

const OwnedNotifications = struct {
    topic: []u8,
    publish_local: bool,
    publish_remote: bool,

    fn init(
        allocator: std.mem.Allocator,
        options: NotificationOptions,
    ) Error!OwnedNotifications {
        try mqtt.validateTopicName(options.topic);
        if (!options.publish_local and !options.publish_remote) {
            return error.InvalidProperty;
        }
        return .{
            .topic = try allocator.dupe(u8, options.topic),
            .publish_local = options.publish_local,
            .publish_remote = options.publish_remote,
        };
    }

    fn deinit(self: *OwnedNotifications, allocator: std.mem.Allocator) void {
        allocator.free(self.topic);
        self.* = undefined;
    }
};

pub const testing = if (builtin.is_test) struct {
    pub const InjectFault = struct {
        context: *anyopaque,
        fail_once: *const fn (
            context: *anyopaque,
            remote: *const mqtt.Publish,
        ) bool,
    };

    /// Route one already-decoded upstream publication through the bridge's
    /// production injection and acknowledgement ordering. This lets tests
    /// inspect retransmission metadata such as DUP and Packet Identifier
    /// before driving the same logic that `step` would otherwise apply.
    pub fn injectPublish(
        bridge: *Bridge,
        remote: *const mqtt.Publish,
    ) Error!void {
        try bridge.inject(remote);
    }

    pub fn injectPublishWithFault(
        bridge: *Bridge,
        remote: *const mqtt.Publish,
        fault: InjectFault,
    ) (Error || error{TestExpectedError})!void {
        if (fault.fail_once(fault.context, remote)) return error.TestExpectedError;
        try bridge.inject(remote);
    }

    pub fn validateRules(rules: []const Rule) Error!void {
        return validateBridgeRules(rules);
    }
} else struct {};

/// An inbound bridge and its reconnect/session state.
///
/// The caller owns the shutdown Event and local Broker for the entire Bridge
/// lifetime. The Bridge deeply owns its rule strings and the reconnect
/// Client's CONNECT fields but borrows `local`; `deinit` must run before either
/// dependency is destroyed. A custom connector, including its context and all
/// reachable transport/TLS option storage, is also borrowed until `deinit`.
/// All methods are single-owner, matching `reconnect.Client`: do not call
/// `run`, `step`, `connect`, or `deinit` concurrently. Another thread may only
/// set the shutdown Event (and shut down the active client connection when an
/// immediate wakeup is required).
pub const Bridge = struct {
    allocator: std.mem.Allocator,
    local: *broker_mod.Broker,
    client: reconnect.Client,
    /// Compatibility view of the first rule. Multi-rule callers should use
    /// `rules`; single-rule constructors keep both views identical.
    rule: Rule,
    rules: []const Rule,
    rule_storage: OwnedRules,
    bridge_id: ?[16]u8,
    session_epoch: u64,
    qos2_enabled: bool,
    notifications: ?OwnedNotifications,
    notification_packet_id: ?u16 = null,
    local_notification_online: bool = false,

    /// Construct a fixed-address cleartext bridge. Configuration slices are
    /// copied, so they may be released immediately after this call.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        remote_address: net.IpAddress,
        options: Options,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        return initMany(
            allocator,
            io,
            local,
            remote_address,
            .{
                .connect = options.connect,
                .reconnect_policy = options.reconnect_policy,
                .rules = &.{options.rule},
                .bridge_id = options.bridge_id,
                .notifications = options.notifications,
            },
            shutdown,
        );
    }

    /// Fixed-address counterpart accepting multiple disjoint rules. The rule
    /// slice and every nested filter/prefix are copied.
    pub fn initMany(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        remote_address: net.IpAddress,
        options: MultiOptions,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        return initRemoteMany(
            allocator,
            io,
            local,
            .{ .address = remote_address },
            options,
            shutdown,
        );
    }

    /// Construct a cleartext bridge from a DNS hostname. The hostname, rule
    /// strings, and MQTT CONNECT data are copied and may be released after this
    /// call. DNS is resolved again for every connection attempt.
    pub fn initHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        remote_host: []const u8,
        remote_port: u16,
        options: Options,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        return initHostMany(
            allocator,
            io,
            local,
            remote_host,
            remote_port,
            .{
                .connect = options.connect,
                .reconnect_policy = options.reconnect_policy,
                .rules = &.{options.rule},
                .bridge_id = options.bridge_id,
                .notifications = options.notifications,
            },
            shutdown,
        );
    }

    /// Hostname counterpart accepting multiple disjoint, deeply copied rules.
    pub fn initHostMany(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        remote_host: []const u8,
        remote_port: u16,
        options: MultiOptions,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        return initRemoteMany(
            allocator,
            io,
            local,
            .{ .host = .{ .name = remote_host, .port = remote_port } },
            options,
            shutdown,
        );
    }

    /// Construct a bridge over a caller-supplied transport connector. Rule
    /// strings and MQTT CONNECT data are copied, but the connector context and
    /// every transport-specific option it references (including TLS options)
    /// are borrowed and must remain valid until `deinit` returns.
    pub fn initConnector(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        connector: runtime.ClientConnector,
        options: Options,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        return initConnectorMany(
            allocator,
            io,
            local,
            connector,
            .{
                .connect = options.connect,
                .reconnect_policy = options.reconnect_policy,
                .rules = &.{options.rule},
                .bridge_id = options.bridge_id,
                .notifications = options.notifications,
            },
            shutdown,
        );
    }

    /// Connector counterpart accepting multiple disjoint, deeply copied rules.
    /// Connector context/configuration retain the borrowing contract above.
    pub fn initConnectorMany(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        connector: runtime.ClientConnector,
        options: MultiOptions,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        return initRemoteMany(
            allocator,
            io,
            local,
            .{ .connector = connector },
            options,
            shutdown,
        );
    }

    fn initRemoteMany(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        remote: Remote,
        options: MultiOptions,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        var owned_rules = try OwnedRules.init(allocator, options.rules);
        var owned_rules_owned = true;
        errdefer if (owned_rules_owned) owned_rules.deinit(allocator);
        var notifications = if (options.notifications) |configured|
            try OwnedNotifications.init(allocator, configured)
        else
            null;
        errdefer if (notifications) |*owned| owned.deinit(allocator);
        const qos2 = rulesUseQoS2(owned_rules.values);
        if (qos2 and options.bridge_id == null) {
            return error.MissingBridgeIdentifier;
        }
        if (qos2 and !persistentSession(options.connect)) {
            return error.QoS2RequiresPersistentSession;
        }
        if (qos2 and !local.commitLogEnabled()) {
            return error.QoS2RequiresCommitLog;
        }
        const client_options = reconnect.ClientOptions{
            .max_subscriptions = owned_rules.values.len,
            .manual_acknowledgements = true,
            .inbound_qos2_release_policy = if (qos2)
                .deferred
            else
                .automatic,
            .surface_incoming_qos2_retransmissions = qos2,
        };
        var connect_options = options.connect;
        if (notifications) |owned| {
            if (owned.publish_remote) {
                if (connect_options.will != null) {
                    return error.BridgeNotificationWillConflict;
                }
                connect_options.will = .{
                    .topic = owned.topic,
                    .payload = "0",
                    .qos = .at_least_once,
                    .retain = true,
                };
            }
        }
        var client = switch (remote) {
            .address => |address| try reconnect.Client.initWithOptions(
                allocator,
                io,
                address,
                connect_options,
                options.reconnect_policy,
                shutdown,
                client_options,
            ),
            .host => |host| try reconnect.Client.initHostWithOptions(
                allocator,
                io,
                host.name,
                host.port,
                connect_options,
                options.reconnect_policy,
                shutdown,
                client_options,
            ),
            .connector => |connector| try reconnect.Client.initConnectorWithOptions(
                allocator,
                io,
                connector,
                connect_options,
                options.reconnect_policy,
                shutdown,
                client_options,
            ),
        };
        var client_owned = true;
        errdefer if (client_owned) client.deinit();
        if (qos2) {
            for (owned_rules.values) |rule| {
                try client.seedSubscription(.{
                    .topic_filter = rule.filter,
                    .qos = rule.qos,
                    .no_local = rule.no_local,
                    .retain_as_published = client.options.value.protocol == .v5,
                }, &.{});
            }
        }
        const restored_epoch = if (qos2)
            local.latestBridgeQoS2SessionEpoch(options.bridge_id.?)
        else
            null;
        var result = Bridge{
            .allocator = allocator,
            .local = local,
            .client = client,
            .rule = owned_rules.values[0],
            .rules = owned_rules.values,
            .rule_storage = owned_rules,
            .bridge_id = options.bridge_id,
            .session_epoch = restored_epoch orelse 0,
            .qos2_enabled = qos2,
            .notifications = notifications,
        };
        owned_rules_owned = false;
        client_owned = false;
        notifications = null;
        errdefer result.deinit();
        try result.publishLocalNotification(false, true);
        return result;
    }

    pub fn deinit(self: *Bridge) void {
        self.publishLocalNotification(false, false) catch {};
        self.client.deinit();
        if (self.notifications) |*notifications| {
            notifications.deinit(self.allocator);
        }
        self.rule_storage.deinit(self.allocator);
        self.* = undefined;
    }

    /// Gracefully disconnect the upstream transport. Completed QoS 2
    /// tombstones remain durable until the upstream broker reports a fresh
    /// Session, preserving duplicate suppression across process restarts.
    pub fn disconnect(self: *Bridge, reason_code: u8) Error!void {
        _ = try self.publishRemoteNotification(false);
        try self.publishLocalNotification(false, false);
        try self.client.disconnect(reason_code);
    }

    /// Ask the owning run loop to reconnect without touching its transport
    /// from the calling thread. This is safe to call concurrently with `run`.
    pub fn requestReconnect(self: *Bridge) void {
        self.client.requestReconnect();
    }

    /// Establish the remote connection and install all inbound rules.
    pub fn connect(
        self: *Bridge,
    ) (Error || std.Io.Cancelable)!reconnect.ConnectEvent {
        const event = try self.client.connect();
        self.handleConnected(event) catch |err| {
            // A connected client without the bridge subscription cannot make
            // useful progress and would never emit another `connected` event.
            // Retire it so the next connect/step can retry the whole setup.
            self.client.disconnectTransport();
            return err;
        };
        return event;
    }

    /// Process at most one reconnect-client event within `poll_options`.
    ///
    /// There is no bridge-side delivery queue. An inbound PUBLISH remains in
    /// the reconnect client's owned event while local routing, persistence and
    /// downstream flush complete. QoS 1 is acknowledged only after all those
    /// operations succeed. On failure it remains unacknowledged, enabling
    /// redelivery while the connection survives or when the caller configured
    /// a persistent upstream Session; a clean Session may discard it.
    pub fn step(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!bool {
        const was_connected = self.client.connection() != null;
        var event = self.client.pollWithOptions(poll_options) catch |err| {
            if (was_connected and self.client.connection() == null) {
                self.publishLocalNotification(false, false) catch {};
            }
            return err;
        } orelse {
            if (was_connected and self.client.connection() == null) {
                try self.publishLocalNotification(false, false);
            }
            return false;
        };
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |connected| {
                if (was_connected) {
                    try self.publishLocalNotification(false, false);
                }
                self.handleConnected(connected) catch |err| {
                    self.client.disconnectTransport();
                    return err;
                };
            },
            .publish => |owned| try self.inject(&owned.publish),
            .pubrel => |owned| try self.releaseQoS2(owned.ack.packet_id),
            .disconnect => {
                // The reconnect client reconnects on its next poll after the
                // transport is retired. A clean server DISCONNECT otherwise
                // leaves a non-null connection that has already gone away.
                self.client.disconnectTransport();
                try self.publishLocalNotification(false, false);
            },
            .puback => |owned| {
                if (self.notification_packet_id != owned.ack.packet_id) {
                    return error.UnexpectedPacket;
                }
                self.notification_packet_id = null;
            },
            .pubrec, .pubcomp => return error.UnexpectedPacket,
            .pingreq, .pingresp, .auth => {},
        }
        return true;
    }

    /// Run until the shutdown Event supplied to `init` is set.
    pub fn run(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        return self.runLoop(poll_options, null, null);
    }

    /// Preserve an established bridge while a lazy configuration generation
    /// is pending, then return at the first disconnected boundary before the
    /// reconnect client starts another attempt.
    pub fn runUntilReload(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
        reload_pending: *const std.atomic.Value(bool),
        connected: *std.atomic.Value(bool),
    ) (Error || std.Io.Cancelable)!void {
        return self.runLoop(poll_options, reload_pending, connected);
    }

    fn runLoop(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
        reload_pending: ?*const std.atomic.Value(bool),
        connected: ?*std.atomic.Value(bool),
    ) (Error || std.Io.Cancelable)!void {
        defer self.publishLocalNotification(false, false) catch {};
        defer if (connected) |state| state.store(false, .release);
        var bounded = poll_options;
        // Give the Bridge an explicit disconnected boundary before retrying so
        // local state observers see `0` before the next `1` generation.
        bounded.reconnect_after_transport_error = false;
        while (true) {
            if (connected) |state| {
                state.store(self.client.connection() != null, .release);
            }
            if (reload_pending) |pending| {
                if (pending.load(.acquire) and
                    self.client.connection() == null) return;
            }
            _ = self.step(bounded) catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
        }
    }

    /// Connect once and process the established transport until it closes.
    /// Retry policy still governs the bounded initial connection attempts,
    /// but a later transport loss never starts another connection cycle.
    pub fn runOnce(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        return self.runOnceTracked(poll_options, null);
    }

    pub fn runOnceWithConnectionState(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
        connected: *std.atomic.Value(bool),
    ) (Error || std.Io.Cancelable)!void {
        return self.runOnceTracked(poll_options, connected);
    }

    fn runOnceTracked(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
        connected: ?*std.atomic.Value(bool),
    ) (Error || std.Io.Cancelable)!void {
        defer self.publishLocalNotification(false, false) catch {};
        defer if (connected) |state| state.store(false, .release);
        _ = try self.connect();
        if (connected) |state| state.store(true, .release);
        var bounded = poll_options;
        bounded.reconnect_after_transport_error = false;
        while (self.client.connection() != null) {
            _ = self.step(bounded) catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
            if (connected) |state| {
                state.store(self.client.connection() != null, .release);
            }
        }
    }

    fn handleConnected(
        self: *Bridge,
        event: reconnect.ConnectEvent,
    ) Error!void {
        try inbound_flow.noteConnected(
            self.allocator,
            self.local,
            &self.client,
            self.rules,
            self.bridge_id,
            &self.session_epoch,
            self.qos2_enabled,
            event,
        );
        if (try self.publishRemoteNotification(true)) {
            try self.publishLocalNotification(true, false);
        }
    }

    fn publishRemoteNotification(
        self: *Bridge,
        online: bool,
    ) Error!bool {
        const notifications = self.notifications orelse return true;
        if (!notifications.publish_remote or self.client.connection() == null) {
            return true;
        }
        if (online) if (self.notification_packet_id) |packet_id| {
            if ((try self.client.outgoingQoSState(packet_id)) != null) {
                return true;
            }
            self.notification_packet_id = null;
        };
        const active = self.client.connection().?;
        const qos: mqtt.QoS = if (online and
            active.peerMaximumQoS() != .at_most_once)
            .at_least_once
        else
            .at_most_once;
        const attempt = self.client.publishOneAttempt(
            notifications.topic,
            if (online) "1" else "0",
            .{
                .qos = qos,
                .retain = active.peerRetainAvailable(),
            },
        ) catch |err| {
            if (self.client.connection() == null) return false;
            return err;
        };
        self.notification_packet_id = attempt.packet_id;
        return !attempt.transport_interrupted;
    }

    fn publishLocalNotification(
        self: *Bridge,
        online: bool,
        force: bool,
    ) Error!void {
        const notifications = self.notifications orelse return;
        if (!notifications.publish_local or
            (!force and self.local_notification_online == online)) return;
        try self.local.publishLocal(.{
            .dup = false,
            .qos = .at_least_once,
            .retain = true,
            .topic = notifications.topic,
            .packet_id = null,
            .properties = &.{},
            .payload = if (online) "1" else "0",
        });
        self.local_notification_online = online;
    }

    fn inject(self: *Bridge, remote: *const mqtt.Publish) Error!void {
        return inbound_flow.inject(
            self.allocator,
            self.local,
            &self.client,
            null,
            self.rules,
            self.bridge_id,
            self.session_epoch,
            self.qos2_enabled,
            remote,
        );
    }

    fn releaseQoS2(self: *Bridge, packet_id: u16) Error!void {
        return inbound_flow.releaseQoS2(
            self.local,
            &self.client,
            null,
            self.bridge_id,
            self.session_epoch,
            self.qos2_enabled,
            packet_id,
        );
    }
};

fn validateBridgeRules(rules: []const Rule) Error!void {
    return inbound_flow.validateRules(rules);
}

fn rulesUseQoS2(rules: []const Rule) bool {
    return inbound_flow.rulesUseQoS2(rules);
}

fn persistentSession(connect: runtime.ConnectOptions) bool {
    if (connect.clean_start) return false;
    return switch (connect.protocol) {
        .v3_1, .v3_1_1 => true,
        .v5 => (mqtt.sessionExpiryInterval(connect.properties) orelse 0) != 0,
    };
}

test {
    _ = @import("bridge/tests.zig");
    _ = outbound;
}

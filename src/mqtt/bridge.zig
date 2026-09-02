//! One-way inbound MQTT broker bridge.
//!
//! A Bridge owns one reconnecting client, subscribes to exactly one
//! remote Topic Filter, maps each incoming Topic Name beneath a local prefix,
//! and injects the resulting Application Message through `Broker.publishLocal`.
//! There is deliberately no local-to-remote path: using one direction per
//! instance makes the topology explicit and prevents an instance from echoing
//! its own injected messages back to the source broker.

const std = @import("std");
const builtin = @import("builtin");
const mqtt = @import("mod.zig");
const broker_mod = @import("broker.zig");
const reconnect = @import("reconnect.zig");
const runtime = @import("runtime.zig");

const net = std.Io.net;

const bridge_client_options: reconnect.ClientOptions = .{
    .max_subscriptions = 1,
    .manual_acknowledgements = true,
};

const Remote = union(enum) {
    address: net.IpAddress,
    host: struct {
        name: []const u8,
        port: u16,
    },
    connector: runtime.ClientConnector,
};

/// Owned backing for the public `Rule` view retained by a Bridge. Keeping the
/// allocations together makes construction and rollback identical for every
/// transport target.
const OwnedRule = struct {
    value: Rule,
    filter: []u8,
    local_prefix: []u8,

    fn init(allocator: std.mem.Allocator, rule: Rule) Error!OwnedRule {
        try rule.validate();
        const filter = try allocator.dupe(u8, rule.filter);
        errdefer allocator.free(filter);
        const local_prefix = try allocator.dupe(u8, rule.local_prefix);
        errdefer allocator.free(local_prefix);
        return .{
            .value = .{
                .filter = filter,
                .qos = rule.qos,
                .local_prefix = local_prefix,
            },
            .filter = filter,
            .local_prefix = local_prefix,
        };
    }

    fn deinit(self: *OwnedRule, allocator: std.mem.Allocator) void {
        allocator.free(self.local_prefix);
        allocator.free(self.filter);
        self.* = undefined;
    }
};

pub const Error = broker_mod.Error || reconnect.Error || error{
    InvalidBridgeQoS,
    TopicOutsideBridgeRule,
};

/// One remote subscription mapped into a literal local Topic Name prefix.
///
/// `filter` may contain MQTT wildcards and is installed unchanged on the
/// remote broker. `local_prefix` is not a Topic Filter: it must be empty or a
/// valid literal Topic Name fragment. Mapping concatenates the prefix and the
/// complete remote Topic Name, so `local_prefix = "upstream/"` maps
/// `sensors/room` to `upstream/sensors/room`.
///
/// Only QoS 0 and 1 are accepted. QoS 2 requires a durable two-phase inbound
/// transaction across local injection failures, which this intentionally
/// minimal bridge does not claim to implement.
pub const Rule = struct {
    filter: []const u8,
    qos: mqtt.QoS = .at_most_once,
    local_prefix: []const u8 = "",

    pub fn validate(self: Rule) Error!void {
        try mqtt.validateTopicFilter(self.filter);
        if (self.qos == .exactly_once) return error.InvalidBridgeQoS;
        if (self.local_prefix.len == 0) return;
        // A trailing slash intentionally permits a caller to create a new
        // level boundary. Validate a completed Topic Name with a literal
        // suffix so `"prefix/"` remains useful while wildcard/NUL/UTF-8
        // errors are still rejected.
        if (self.local_prefix.len >= std.math.maxInt(u16)) {
            return error.InvalidTopic;
        }
        try mqtt.validateUtf8String(self.local_prefix);
        if (mqtt.hasWildcards(self.local_prefix)) return error.InvalidTopic;
    }

    /// Allocate the canonical local Topic Name for a matching remote topic.
    /// The returned slice belongs to `allocator`.
    pub fn mapTopicAlloc(
        self: Rule,
        allocator: std.mem.Allocator,
        remote_topic: []const u8,
    ) Error![]u8 {
        try self.validate();
        try mqtt.validateTopicName(remote_topic);
        if (!mqtt.topicMatchesFilter(remote_topic, self.filter)) {
            return error.TopicOutsideBridgeRule;
        }
        const mapped_len = std.math.add(
            usize,
            self.local_prefix.len,
            remote_topic.len,
        ) catch return error.InvalidTopic;
        if (mapped_len > std.math.maxInt(u16)) return error.InvalidTopic;
        const mapped = try allocator.alloc(u8, mapped_len);
        errdefer allocator.free(mapped);
        @memcpy(mapped[0..self.local_prefix.len], self.local_prefix);
        @memcpy(mapped[self.local_prefix.len..], remote_topic);
        try mqtt.validateTopicName(mapped);
        return mapped;
    }
};

pub const Options = struct {
    connect: runtime.ConnectOptions,
    reconnect_policy: reconnect.ReconnectPolicy = .{},
    rule: Rule,
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
    rule: Rule,
    rule_storage: OwnedRule,

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
        return initRemote(
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
        return initRemote(
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
        return initRemote(
            allocator,
            io,
            local,
            .{ .connector = connector },
            options,
            shutdown,
        );
    }

    fn initRemote(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *broker_mod.Broker,
        remote: Remote,
        options: Options,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        var owned_rule = try OwnedRule.init(allocator, options.rule);
        errdefer owned_rule.deinit(allocator);
        const client = switch (remote) {
            .address => |address| try reconnect.Client.initWithOptions(
                allocator,
                io,
                address,
                options.connect,
                options.reconnect_policy,
                shutdown,
                bridge_client_options,
            ),
            .host => |host| try reconnect.Client.initHostWithOptions(
                allocator,
                io,
                host.name,
                host.port,
                options.connect,
                options.reconnect_policy,
                shutdown,
                bridge_client_options,
            ),
            .connector => |connector| try reconnect.Client.initConnectorWithOptions(
                allocator,
                io,
                connector,
                options.connect,
                options.reconnect_policy,
                shutdown,
                bridge_client_options,
            ),
        };
        return .{
            .allocator = allocator,
            .local = local,
            .client = client,
            .rule = owned_rule.value,
            .rule_storage = owned_rule,
        };
    }

    pub fn deinit(self: *Bridge) void {
        self.client.deinit();
        self.rule_storage.deinit(self.allocator);
        self.* = undefined;
    }

    /// Establish the remote connection and install the single inbound rule.
    pub fn connect(
        self: *Bridge,
    ) (Error || std.Io.Cancelable)!reconnect.ConnectEvent {
        const event = try self.client.connect();
        self.ensureSubscription(event) catch |err| {
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
        var event = try self.client.pollWithOptions(poll_options) orelse
            return false;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |connected| self.ensureSubscription(connected) catch |err|
                {
                    self.client.disconnectTransport();
                    return err;
                },
            .publish => |owned| try self.inject(&owned.publish),
            .disconnect => {
                // The reconnect client reconnects on its next poll after the
                // transport is retired. A clean server DISCONNECT otherwise
                // leaves a non-null connection that has already gone away.
                self.client.disconnectTransport();
            },
            .puback, .pubrec, .pubrel, .pubcomp => return error.UnexpectedPacket,
            .pingreq, .pingresp, .auth => {},
        }
        return true;
    }

    /// Run until the shutdown Event supplied to `init` is set.
    pub fn run(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        while (true) {
            _ = self.step(poll_options) catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
        }
    }

    fn ensureSubscription(
        self: *Bridge,
        _: reconnect.ConnectEvent,
    ) Error!void {
        // `reconnect.Client` replays an accepted subscription whenever a
        // reconnect reports a fresh Session, while a surviving remote Session
        // already retains it. Install the rule only on the first connection.
        if (self.client.subscriptionCount() != 0) return;
        var suback = try self.client.subscribe(
            &.{.{
                .topic_filter = self.rule.filter,
                .qos = self.rule.qos,
                // Preserve the upstream RETAIN bit so retained publications
                // populate the local broker's retained store as well as live
                // fanout when MQTT 5 supports this subscription option. MQTT
                // 3.1.1 permits only the QoS bits and clears RETAIN on later
                // live deliveries, although the initial retained replay keeps
                // it. The reconnect client owns and replays the exact option.
                .retain_as_published = self.client.options.value.protocol == .v5,
            }},
            .{},
        );
        defer suback.deinit(self.allocator);
        if (suback.suback.reason_codes.len != 1 or
            suback.suback.reason_codes[0] >= 0x80)
        {
            return error.SubscriptionRefused;
        }
    }

    fn inject(self: *Bridge, remote: *const mqtt.Publish) Error!void {
        // A conforming remote broker sends only matching deliveries, but fail
        // closed before local injection if it violates the installed rule.
        const topic = try self.rule.mapTopicAlloc(
            self.allocator,
            remote.topic,
        );
        defer self.allocator.free(topic);
        if (remote.qos == .exactly_once) return error.InvalidBridgeQoS;

        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.ensureTotalCapacity(
            self.allocator,
            remote.properties.len,
        );
        for (remote.properties) |property| {
            // Topic Alias belongs to the remote Network Connection and has
            // already been resolved into `remote.topic`. Subscription
            // Identifier describes the remote subscription, not any local
            // subscriber, so neither crosses the broker boundary.
            if ((property == .two_byte and
                property.two_byte.id == .topic_alias) or
                (property == .varint and
                    property.varint.id == .subscription_identifier))
            {
                continue;
            }
            properties.appendAssumeCapacity(property);
        }

        try self.local.publishLocal(.{
            .dup = false,
            .qos = remote.qos,
            .retain = remote.retain,
            .topic = topic,
            .packet_id = null,
            .properties = properties.items,
            .payload = remote.payload,
        });
        if (remote.qos == .at_least_once) {
            try self.client.acknowledge(
                remote.packet_id.?,
                .at_least_once,
                .{},
            );
        }
    }
};

test {
    _ = @import("bridge/tests.zig");
}

//! MQTT broker bridge primitives.
//!
//! `Bridge` owns one reconnecting client, subscribes to one or more disjoint
//! remote Topic Filters, maps each incoming Topic Name beneath its rule's local
//! prefix, and injects the resulting Application Message through
//! `Broker.publishLocal`.
//! `OutboundBridge` instead composes two MQTT Sessions and maps publications
//! from a source broker into a target broker. Keeping each instance
//! unidirectional makes topology and loop prevention explicit.

const std = @import("std");
const builtin = @import("builtin");
const mqtt = @import("mod.zig");
const broker_mod = @import("broker.zig");
const reconnect = @import("reconnect.zig");
const runtime = @import("runtime.zig");
const rule_helpers = @import("bridge/rules.zig");

pub const outbound = @import("bridge/outbound.zig");
pub const OutboundBridge = outbound.Bridge;
pub const OutboundRule = outbound.Rule;

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
};

/// One effective remote subscription mapped between literal topic prefixes.
///
/// `filter` may contain MQTT wildcards and is installed unchanged on the
/// remote broker. `remote_prefix` must be a literal prefix of the effective
/// filter (inside a shared-subscription wrapper); it is removed from a
/// delivered Topic Name before `local_prefix` is prepended. Both prefixes are
/// empty or valid literal Topic Name fragments. For example, filter
/// `remote/sensors/#`, remote prefix `remote/`, and local prefix `local/` map
/// `remote/sensors/room` to `local/sensors/room`.
///
/// QoS 2 additionally requires `Options.bridge_id` and a persistent upstream
/// Session so the bridge can join the remote transaction to the local broker's
/// durable two-phase store. The bridge identity, Client Identifier, and rule
/// mapping must describe the same logical bridge after a process restart.
pub const Rule = struct {
    filter: []const u8,
    qos: mqtt.QoS = .at_most_once,
    local_prefix: []const u8 = "",
    remote_prefix: []const u8 = "",

    pub fn validate(self: Rule) Error!void {
        try mqtt.validateTopicFilter(self.filter);
        try validatePrefix(self.local_prefix);
        try validatePrefix(self.remote_prefix);
        if (self.remote_prefix.len != 0 and !std.mem.startsWith(
            u8,
            rule_helpers.effectiveFilter(self.filter),
            self.remote_prefix,
        )) {
            return error.InvalidBridgePrefix;
        }
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
        const visible = if (std.mem.startsWith(
            u8,
            remote_topic,
            self.remote_prefix,
        ))
            remote_topic[self.remote_prefix.len..]
        else if (self.remote_prefix.len != 0 and
            self.remote_prefix[self.remote_prefix.len - 1] == '/' and
            std.mem.eql(
                u8,
                remote_topic,
                self.remote_prefix[0 .. self.remote_prefix.len - 1],
            ))
            ""
        else
            return error.TopicOutsideBridgeRule;
        const mapped_len = std.math.add(
            usize,
            self.local_prefix.len,
            visible.len,
        ) catch return error.InvalidTopic;
        if (mapped_len == 0) return error.EmptyMappedTopic;
        if (mapped_len > std.math.maxInt(u16)) return error.InvalidTopic;
        const mapped = try allocator.alloc(u8, mapped_len);
        errdefer allocator.free(mapped);
        @memcpy(mapped[0..self.local_prefix.len], self.local_prefix);
        @memcpy(mapped[self.local_prefix.len..], visible);
        try mqtt.validateTopicName(mapped);
        return mapped;
    }

    /// Return whether two valid filters can select at least one common Topic
    /// Name under MQTT wildcard and leading-`$` matching rules. This compares
    /// shared subscriptions by their effective inner filter because either
    /// remote subscription may receive such a matching publication.
    pub fn overlaps(self: Rule, other: Rule) Error!bool {
        try self.validate();
        try other.validate();
        return rule_helpers.filtersOverlap(self.filter, other.filter);
    }
};

fn validatePrefix(prefix: []const u8) Error!void {
    if (prefix.len == 0) return;
    // A trailing slash intentionally permits a caller to create a new level
    // boundary. UTF-8 and wildcard errors remain distinguishable to callers.
    if (prefix.len >= std.math.maxInt(u16)) return error.InvalidTopic;
    try mqtt.validateUtf8String(prefix);
    if (mqtt.hasWildcards(prefix)) return error.InvalidTopic;
}

pub const Options = struct {
    connect: runtime.ConnectOptions,
    reconnect_policy: reconnect.ReconnectPolicy = .{},
    rule: Rule,
    /// Stable deployment identity for durable QoS 2 transactions. Required
    /// when `rule.qos` is QoS 2 and must remain unchanged with the Client ID
    /// and rule mapping across restarts.
    bridge_id: ?[16]u8 = null,
};

pub const MultiOptions = struct {
    connect: runtime.ConnectOptions,
    reconnect_policy: reconnect.ReconnectPolicy = .{},
    rules: []const Rule,
    /// Stable deployment identity shared by every QoS 2 rule; it, the Client
    /// ID, and all rule mappings must remain unchanged across restarts.
    bridge_id: ?[16]u8 = null,
};

/// Deep-owned backing for every public Rule view retained by a Bridge.
const OwnedRules = struct {
    values: []Rule,

    fn init(
        allocator: std.mem.Allocator,
        source: []const Rule,
    ) Error!OwnedRules {
        try validateBridgeRules(source);
        const values = try allocator.alloc(Rule, source.len);
        errdefer allocator.free(values);
        var initialized: usize = 0;
        errdefer for (values[0..initialized]) |value| {
            allocator.free(value.remote_prefix);
            allocator.free(value.local_prefix);
            allocator.free(value.filter);
        };
        for (source, values) |rule, *owned| {
            const filter = try allocator.dupe(u8, rule.filter);
            errdefer allocator.free(filter);
            const local_prefix = try allocator.dupe(u8, rule.local_prefix);
            errdefer allocator.free(local_prefix);
            const remote_prefix = try allocator.dupe(u8, rule.remote_prefix);
            owned.* = .{
                .filter = filter,
                .qos = rule.qos,
                .local_prefix = local_prefix,
                .remote_prefix = remote_prefix,
            };
            initialized += 1;
        }
        return .{ .values = values };
    }

    fn deinit(self: *OwnedRules, allocator: std.mem.Allocator) void {
        for (self.values) |value| {
            allocator.free(value.remote_prefix);
            allocator.free(value.local_prefix);
            allocator.free(value.filter);
        }
        allocator.free(self.values);
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
        errdefer owned_rules.deinit(allocator);
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
        var client = switch (remote) {
            .address => |address| try reconnect.Client.initWithOptions(
                allocator,
                io,
                address,
                options.connect,
                options.reconnect_policy,
                shutdown,
                client_options,
            ),
            .host => |host| try reconnect.Client.initHostWithOptions(
                allocator,
                io,
                host.name,
                host.port,
                options.connect,
                options.reconnect_policy,
                shutdown,
                client_options,
            ),
            .connector => |connector| try reconnect.Client.initConnectorWithOptions(
                allocator,
                io,
                connector,
                options.connect,
                options.reconnect_policy,
                shutdown,
                client_options,
            ),
        };
        errdefer client.deinit();
        if (qos2) {
            for (owned_rules.values) |rule| {
                try client.seedSubscription(.{
                    .topic_filter = rule.filter,
                    .qos = rule.qos,
                    .retain_as_published = client.options.value.protocol == .v5,
                }, &.{});
            }
        }
        const restored_epoch = if (qos2)
            local.latestBridgeQoS2SessionEpoch(options.bridge_id.?)
        else
            null;
        return .{
            .allocator = allocator,
            .local = local,
            .client = client,
            .rule = owned_rules.values[0],
            .rules = owned_rules.values,
            .rule_storage = owned_rules,
            .bridge_id = options.bridge_id,
            .session_epoch = restored_epoch orelse 0,
            .qos2_enabled = qos2,
        };
    }

    pub fn deinit(self: *Bridge) void {
        self.client.deinit();
        self.rule_storage.deinit(self.allocator);
        self.* = undefined;
    }

    /// Gracefully disconnect the upstream transport. Completed QoS 2
    /// tombstones remain durable until the upstream broker reports a fresh
    /// Session, preserving duplicate suppression across process restarts.
    pub fn disconnect(self: *Bridge, reason_code: u8) Error!void {
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
        var event = try self.client.pollWithOptions(poll_options) orelse
            return false;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |connected| self.handleConnected(connected) catch |err|
                {
                    self.client.disconnectTransport();
                    return err;
                },
            .publish => |owned| try self.inject(&owned.publish),
            .pubrel => |owned| try self.releaseQoS2(owned.ack.packet_id),
            .disconnect => {
                // The reconnect client reconnects on its next poll after the
                // transport is retired. A clean server DISCONNECT otherwise
                // leaves a non-null connection that has already gone away.
                self.client.disconnectTransport();
            },
            .puback, .pubrec, .pubcomp => return error.UnexpectedPacket,
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

    /// Connect once and process the established transport until it closes.
    /// Retry policy still governs the bounded initial connection attempts,
    /// but a later transport loss never starts another connection cycle.
    pub fn runOnce(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        _ = try self.connect();
        var bounded = poll_options;
        bounded.reconnect_after_transport_error = false;
        while (self.client.connection() != null) {
            _ = self.step(bounded) catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
        }
    }

    fn ensureSubscription(
        self: *Bridge,
        _: reconnect.ConnectEvent,
    ) Error!void {
        // A prior partial SUBACK is not a valid bridge configuration. The
        // failed setup path disconnects, and this retry submits only missing
        // rules in one packet. Existing accepted rules remain owned by the
        // reconnect client for fresh-Session replay.
        var subscriptions: std.ArrayList(mqtt.Subscription) = .empty;
        defer subscriptions.deinit(self.allocator);
        try subscriptions.ensureTotalCapacity(self.allocator, self.rules.len);
        for (self.rules) |rule| {
            if (self.client.hasSubscription(rule.filter)) continue;
            subscriptions.appendAssumeCapacity(.{
                .topic_filter = rule.filter,
                .qos = rule.qos,
                // Preserve the upstream RETAIN bit so retained publications
                // populate the local broker's retained store as well as live
                // fanout when MQTT 5 supports this subscription option. MQTT
                // 3.1.1 permits only the QoS bits and clears RETAIN on later
                // live deliveries, although the initial retained replay keeps
                // it. The reconnect client owns and replays the exact option.
                .retain_as_published = self.client.options.value.protocol == .v5,
            });
        }
        if (subscriptions.items.len == 0) return;
        var suback = try self.client.subscribe(
            subscriptions.items,
            .{},
        );
        defer suback.deinit(self.allocator);
        if (suback.suback.reason_codes.len != subscriptions.items.len) {
            return error.UnexpectedPacket;
        }
        for (suback.suback.reason_codes) |reason| {
            if (reason >= 0x80) return error.SubscriptionRefused;
        }
    }

    fn handleConnected(
        self: *Bridge,
        event: reconnect.ConnectEvent,
    ) Error!void {
        if (self.qos2_enabled) {
            const bridge_id = self.bridge_id.?;
            if (!event.session_present) {
                self.session_epoch = self.local.beginBridgeQoS2Session(
                    bridge_id,
                ) catch |err| {
                    self.session_epoch = self.local
                        .latestBridgeQoS2SessionEpoch(bridge_id) orelse
                        self.session_epoch;
                    return err;
                };
            } else {
                const transactions = try self.local
                    .bridgeQoS2SessionTransactionsAlloc(
                    self.allocator,
                    bridge_id,
                    self.session_epoch,
                );
                defer self.allocator.free(transactions);
                for (transactions) |transaction| {
                    try self.client.restoreIncomingQoS2(
                        transaction.packet_id,
                        switch (transaction.phase) {
                            .pending => .await_pubrel,
                            .released => .release_pending,
                        },
                    );
                }
            }
            return;
        }
        try self.ensureSubscription(event);
    }

    fn inject(self: *Bridge, remote: *const mqtt.Publish) Error!void {
        // A conforming remote broker sends only matching deliveries, but fail
        // closed before local injection if it violates the installed rule.
        const rule = self.matchingRule(remote.topic) orelse
            return error.TopicOutsideBridgeRule;
        if (@intFromEnum(remote.qos) > @intFromEnum(rule.qos)) {
            self.client.disconnectTransport();
            return error.InvalidBridgeQoS;
        }
        if (remote.qos == .exactly_once and !self.qos2_enabled) {
            self.client.disconnectTransport();
            return error.InvalidBridgeQoS;
        }
        const topic = try rule.mapTopicAlloc(
            self.allocator,
            remote.topic,
        );
        defer self.allocator.free(topic);
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

        const local_publish = mqtt.Publish{
            .dup = false,
            .qos = remote.qos,
            .retain = remote.retain,
            .topic = topic,
            .packet_id = null,
            .properties = properties.items,
            .payload = remote.payload,
        };
        switch (remote.qos) {
            .at_most_once => try self.local.publishLocal(local_publish),
            .at_least_once => {
                try self.local.publishLocal(local_publish);
                try self.client.acknowledge(
                    remote.packet_id.?,
                    .at_least_once,
                    .{},
                );
            },
            .exactly_once => {
                const packet_id = remote.packet_id.?;
                _ = self.local.stageBridgeQoS2(
                    self.qos2Key(packet_id),
                    local_publish,
                    .{ .duplicate = remote.dup },
                ) catch |err| {
                    // The store can have accepted the transaction before a
                    // journal append fails. Force retransmission so a later
                    // attempt can validate and persist the same message before
                    // exposing PUBREC.
                    self.client.disconnectTransport();
                    return err;
                };
                try self.client.acknowledge(
                    packet_id,
                    .exactly_once,
                    .{},
                );
            },
        }
    }

    fn releaseQoS2(self: *Bridge, packet_id: u16) Error!void {
        if (!self.qos2_enabled) return error.UnexpectedPacket;
        const key = self.qos2Key(packet_id);
        const released = self.local.releaseBridgeQoS2(key) catch |err| {
            // No PUBCOMP is visible yet. A resumed PUBREL safely retries the
            // idempotent broker release/tombstone transaction.
            self.client.disconnectTransport();
            return err;
        };
        switch (released.disposition) {
            .applied, .already_applied => {},
            // The reconnect layer surfaces PUBREL only while it owns a
            // release-pending marker. An absent broker entry therefore means
            // a completed tombstone was already pruned after restart; it can
            // never represent an unstaged Application Message here.
            .unknown => {},
        }
        // Keep the broker tombstone until PUBCOMP has been written. If the
        // transport fails first, a resumed PUBREL observes already_applied and
        // cannot inject the Application Message twice.
        try self.client.completeIncomingQoS2(packet_id, .{});
        // PUBCOMP is already on the wire. A later journal failure while
        // pruning the tombstone cannot be repaired by failing this event; the
        // Broker restores the in-memory tombstone so a later fresh Session can
        // retry cleanup without permitting Packet Identifier reuse to race the
        // older journal state.
        if (released.disposition != .unknown) {
            _ = self.local.completeBridgeQoS2(key) catch return;
        }
        // Durable admission owns any failed live destination from this point;
        // its connection cleanup or Session retransmission must not stop the
        // independent upstream bridge after PUBCOMP has completed.
        _ = released.delivery_error;
    }

    fn qos2Key(
        self: *const Bridge,
        packet_id: u16,
    ) broker_mod.BridgeQoS2Key {
        return .{
            .bridge_id = self.bridge_id.?,
            .session_epoch = self.session_epoch,
            .packet_id = packet_id,
        };
    }

    fn matchingRule(self: *const Bridge, topic: []const u8) ?Rule {
        var matched: ?Rule = null;
        for (self.rules) |rule| {
            if (!mqtt.topicMatchesFilter(topic, rule.filter)) continue;
            // Construction rejects intersections, so two matches would mean
            // memory corruption or a broken matcher invariant. Fail closed in
            // release builds rather than choosing by declaration order.
            if (matched != null) return null;
            matched = rule;
        }
        return matched;
    }
};

fn validateBridgeRules(rules: []const Rule) Error!void {
    if (rules.len == 0) return error.NoBridgeRules;
    for (rules, 0..) |rule, index| {
        try rule.validate();
        for (rules[0..index]) |previous| {
            if (std.mem.eql(u8, previous.filter, rule.filter)) {
                return error.DuplicateBridgeFilter;
            }
            if (rule_helpers.filtersOverlap(previous.filter, rule.filter)) {
                return error.OverlappingBridgeFilters;
            }
        }
    }
}

fn rulesUseQoS2(rules: []const Rule) bool {
    for (rules) |rule| {
        if (rule.qos == .exactly_once) return true;
    }
    return false;
}

fn persistentSession(connect: runtime.ConnectOptions) bool {
    if (connect.clean_start) return false;
    return switch (connect.protocol) {
        .v3_1_1 => true,
        .v5 => (mqtt.sessionExpiryInterval(connect.properties) orelse 0) != 0,
    };
}

test {
    _ = @import("bridge/tests.zig");
}

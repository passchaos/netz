//! Remote-to-local bridge delivery shared by inbound and bidirectional
//! bridges. The caller retains ownership of the reconnecting client and rule
//! storage so one remote MQTT Session can also carry outbound traffic.

const std = @import("std");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");
const reconnect = @import("../reconnect.zig");
const listener_namespace = @import("../listener_namespace.zig");
const rule_helpers = @import("rules.zig");

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

pub const Rule = struct {
    filter: []const u8,
    qos: mqtt.QoS = .at_most_once,
    local_prefix: []const u8 = "",
    remote_prefix: []const u8 = "",
    /// Suppress publications emitted by this same remote MQTT connection.
    /// Bidirectional MQTT 5 bridges use this together with local-source
    /// exclusion to prevent a message from crossing the bridge twice.
    no_local: bool = false,

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

    pub fn overlaps(self: Rule, other: Rule) Error!bool {
        try self.validate();
        try other.validate();
        return rule_helpers.filtersOverlap(self.filter, other.filter);
    }
};

fn validatePrefix(prefix: []const u8) Error!void {
    if (prefix.len == 0) return;
    if (prefix.len >= std.math.maxInt(u16)) return error.InvalidTopic;
    try mqtt.validateUtf8String(prefix);
    if (mqtt.hasWildcards(prefix)) return error.InvalidTopic;
}

pub const OwnedRules = struct {
    values: []Rule,

    pub const empty: OwnedRules = .{ .values = &.{} };

    pub fn init(
        allocator: std.mem.Allocator,
        source: []const Rule,
    ) Error!OwnedRules {
        try validateRules(source);
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
                .no_local = rule.no_local,
            };
            initialized += 1;
        }
        return .{ .values = values };
    }

    pub fn initOptional(
        allocator: std.mem.Allocator,
        source: []const Rule,
    ) Error!OwnedRules {
        if (source.len == 0) return .empty;
        return init(allocator, source);
    }

    pub fn deinit(self: *OwnedRules, allocator: std.mem.Allocator) void {
        if (self.values.len == 0) {
            self.* = undefined;
            return;
        }
        for (self.values) |value| {
            allocator.free(value.remote_prefix);
            allocator.free(value.local_prefix);
            allocator.free(value.filter);
        }
        allocator.free(self.values);
        self.* = undefined;
    }
};

pub fn validateRules(rules: []const Rule) Error!void {
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

pub fn rulesUseQoS2(rules: []const Rule) bool {
    for (rules) |rule| {
        if (rule.qos == .exactly_once) return true;
    }
    return false;
}

pub fn ensureSubscriptions(
    allocator: std.mem.Allocator,
    client: *reconnect.Client,
    rules: []const Rule,
) Error!void {
    var subscriptions: std.ArrayList(mqtt.Subscription) = .empty;
    defer subscriptions.deinit(allocator);
    try subscriptions.ensureTotalCapacity(allocator, rules.len);
    for (rules) |rule| {
        if (client.hasSubscription(rule.filter)) continue;
        subscriptions.appendAssumeCapacity(.{
            .topic_filter = rule.filter,
            .qos = rule.qos,
            .no_local = rule.no_local,
            .retain_as_published = client.options.value.protocol == .v5,
        });
    }
    if (subscriptions.items.len == 0) return;
    var suback = try client.subscribe(subscriptions.items, .{});
    defer suback.deinit(allocator);
    if (suback.suback.reason_codes.len != subscriptions.items.len) {
        return error.UnexpectedPacket;
    }
    for (suback.suback.reason_codes) |reason| {
        if (reason >= 0x80) return error.SubscriptionRefused;
    }
}

pub fn noteConnected(
    allocator: std.mem.Allocator,
    local: *broker_mod.Broker,
    client: *reconnect.Client,
    rules: []const Rule,
    bridge_id: ?[16]u8,
    session_epoch: *u64,
    qos2_enabled: bool,
    event: reconnect.ConnectEvent,
) Error!void {
    if (qos2_enabled) {
        const id = bridge_id.?;
        if (!event.session_resumed) {
            session_epoch.* = local.beginBridgeQoS2Session(id) catch |err| {
                session_epoch.* = local.latestBridgeQoS2SessionEpoch(id) orelse
                    session_epoch.*;
                return err;
            };
        } else {
            const transactions = try local.bridgeQoS2SessionTransactionsAlloc(
                allocator,
                id,
                session_epoch.*,
            );
            defer allocator.free(transactions);
            for (transactions) |transaction| {
                try client.restoreIncomingQoS2(
                    transaction.packet_id,
                    switch (transaction.phase) {
                        .pending => .await_pubrel,
                        .released => .release_pending,
                    },
                );
            }
        }
    }
    try ensureSubscriptions(allocator, client, rules);
}

pub fn inject(
    allocator: std.mem.Allocator,
    local: *broker_mod.Broker,
    client: *reconnect.Client,
    local_source: ?*broker_mod.LocalConsumer,
    rules: []const Rule,
    bridge_id: ?[16]u8,
    session_epoch: u64,
    qos2_enabled: bool,
    remote: *const mqtt.Publish,
) Error!void {
    const rule = matchingRule(rules, remote.topic) orelse
        return error.TopicOutsideBridgeRule;
    if (@intFromEnum(remote.qos) > @intFromEnum(rule.qos)) {
        client.disconnectTransport();
        return error.InvalidBridgeQoS;
    }
    if (remote.qos == .exactly_once and !qos2_enabled) {
        client.disconnectTransport();
        return error.InvalidBridgeQoS;
    }
    const topic = try rule.mapTopicAlloc(allocator, remote.topic);
    defer allocator.free(topic);
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    try properties.ensureTotalCapacity(allocator, remote.properties.len);
    for (remote.properties) |property| {
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
        .at_most_once => try publishLocal(
            local,
            local_source,
            local_publish,
        ),
        .at_least_once => {
            try publishLocal(local, local_source, local_publish);
            try client.acknowledge(
                remote.packet_id.?,
                .at_least_once,
                .{},
            );
        },
        .exactly_once => {
            const packet_id = remote.packet_id.?;
            _ = local.stageBridgeQoS2(
                qos2Key(bridge_id.?, session_epoch, packet_id),
                local_publish,
                .{ .duplicate = remote.dup },
            ) catch |err| {
                client.disconnectTransport();
                return err;
            };
            try client.acknowledge(packet_id, .exactly_once, .{});
        },
    }
}

fn publishLocal(
    local: *broker_mod.Broker,
    local_source: ?*broker_mod.LocalConsumer,
    publish: mqtt.Publish,
) Error!void {
    if (local_source) |source| {
        return local.publishLocalFromConsumer(source, publish);
    }
    return local.publishLocal(publish);
}

pub fn releaseQoS2(
    local: *broker_mod.Broker,
    client: *reconnect.Client,
    local_source: ?*broker_mod.LocalConsumer,
    bridge_id: ?[16]u8,
    session_epoch: u64,
    qos2_enabled: bool,
    packet_id: u16,
) Error!void {
    if (!qos2_enabled) return error.UnexpectedPacket;
    const key = qos2Key(bridge_id.?, session_epoch, packet_id);
    const released = if (local_source) |source|
        local.releaseBridgeQoS2FromConsumer(key, source)
    else
        local.releaseBridgeQoS2(key);
    const completed_release = released catch |err| {
        client.disconnectTransport();
        return err;
    };
    try client.completeIncomingQoS2(packet_id, .{});
    if (completed_release.disposition != .unknown) {
        _ = local.completeBridgeQoS2(key) catch return;
    }
    _ = completed_release.delivery_error;
}

pub fn matchingRule(rules: []const Rule, topic: []const u8) ?Rule {
    var matched: ?Rule = null;
    for (rules) |rule| {
        if (!mqtt.topicMatchesFilter(topic, rule.filter)) continue;
        if (matched != null) return null;
        matched = rule;
    }
    return matched;
}

fn qos2Key(
    bridge_id: [16]u8,
    session_epoch: u64,
    packet_id: u16,
) broker_mod.BridgeQoS2Key {
    return .{
        .bridge_id = bridge_id,
        .session_epoch = session_epoch,
        .packet_id = packet_id,
    };
}

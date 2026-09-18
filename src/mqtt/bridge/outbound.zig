//! Outbound MQTT broker bridge built from two reconnecting MQTT Sessions.
//!
//! The source Session subscribes to local topics and acknowledges QoS 1 only
//! after the target Session receives PUBACK. This gives transport-reconnect
//! at-least-once forwarding without coupling either broker's internal locks.
//! Cross-broker QoS 2 requires a durable transaction coordinator and is
//! deliberately rejected rather than being mislabeled as exactly once.

const std = @import("std");
const mqtt = @import("../mod.zig");
const listener_namespace = @import("../listener_namespace.zig");
const owned_properties = @import("../owned_properties.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const rule_helpers = @import("rules.zig");

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

pub const Error = reconnect.Error || listener_namespace.Error || error{
    NoBridgeRules,
    DuplicateBridgeFilter,
    OverlappingBridgeFilters,
    QoS2RequiresDurableCoordinator,
    QoS1RequiresPersistentSourceSession,
    TopicOutsideBridgeRule,
    EmptyMappedTopic,
    InvalidBridgeQoS,
    TargetAcknowledgementMismatch,
};

/// One local subscription mapped into a remote Topic Name prefix.
///
/// The source subscription is `local_prefix + filter`. A delivered Topic Name
/// has `local_prefix` removed before `remote_prefix` is prepended. Prefixes are
/// literal MQTT Topic Name fragments; `filter` may contain wildcards.
pub const Rule = struct {
    filter: []const u8,
    qos: mqtt.QoS = .at_most_once,
    local_prefix: []const u8 = "",
    remote_prefix: []const u8 = "",

    pub fn validate(self: Rule) Error!void {
        try mqtt.validateTopicFilter(self.filter);
        _ = try listener_namespace.Namespace.init(self.local_prefix);
        _ = try listener_namespace.Namespace.init(self.remote_prefix);
        if (self.qos == .exactly_once) {
            return error.QoS2RequiresDurableCoordinator;
        }
    }

    pub fn sourceFilterAlloc(
        self: Rule,
        allocator: std.mem.Allocator,
    ) Error![]u8 {
        try self.validate();
        const namespace = try listener_namespace.Namespace.init(
            self.local_prefix,
        );
        return namespace.mapFilterAlloc(allocator, self.filter);
    }

    pub fn mapTopicAlloc(
        self: Rule,
        allocator: std.mem.Allocator,
        local_topic: []const u8,
    ) Error![]u8 {
        try self.validate();
        try mqtt.validateTopicName(local_topic);
        const source_filter = try self.sourceFilterAlloc(allocator);
        defer allocator.free(source_filter);
        if (!mqtt.topicMatchesFilter(local_topic, source_filter)) {
            return error.TopicOutsideBridgeRule;
        }
        return self.mapMatchedTopicAlloc(allocator, local_topic);
    }

    fn mapMatchedTopicAlloc(
        self: Rule,
        allocator: std.mem.Allocator,
        local_topic: []const u8,
    ) Error![]u8 {
        const visible = if (std.mem.startsWith(
            u8,
            local_topic,
            self.local_prefix,
        ))
            local_topic[self.local_prefix.len..]
        else if (self.local_prefix.len != 0 and
            self.local_prefix[self.local_prefix.len - 1] == '/' and
            std.mem.eql(
                u8,
                local_topic,
                self.local_prefix[0 .. self.local_prefix.len - 1],
            ))
            ""
        else
            return error.TopicOutsideBridgeRule;
        const mapped_len = std.math.add(
            usize,
            self.remote_prefix.len,
            visible.len,
        ) catch return error.InvalidTopic;
        if (mapped_len == 0) return error.EmptyMappedTopic;
        if (mapped_len > std.math.maxInt(u16)) return error.InvalidTopic;
        const mapped = try allocator.alloc(u8, mapped_len);
        errdefer allocator.free(mapped);
        @memcpy(mapped[0..self.remote_prefix.len], self.remote_prefix);
        @memcpy(mapped[self.remote_prefix.len..], visible);
        try mqtt.validateTopicName(mapped);
        return mapped;
    }
};

pub const Options = struct {
    source_connect: runtime.ConnectOptions,
    target_connect: runtime.ConnectOptions,
    source_reconnect_policy: reconnect.ReconnectPolicy = .{},
    target_reconnect_policy: reconnect.ReconnectPolicy = .{},
    rule: Rule,
    preserve_retain: bool = true,
};

pub const MultiOptions = struct {
    source_connect: runtime.ConnectOptions,
    target_connect: runtime.ConnectOptions,
    source_reconnect_policy: reconnect.ReconnectPolicy = .{},
    target_reconnect_policy: reconnect.ReconnectPolicy = .{},
    rules: []const Rule,
    preserve_retain: bool = true,
};

pub const ConnectEvent = struct {
    source_session_present: bool,
    target_session_present: bool,
};

const OwnedRule = struct {
    value: Rule,
    source_filter: []u8,

    fn deinit(self: *OwnedRule, allocator: std.mem.Allocator) void {
        allocator.free(self.source_filter);
        allocator.free(self.value.remote_prefix);
        allocator.free(self.value.local_prefix);
        allocator.free(self.value.filter);
        self.* = undefined;
    }
};

const OwnedRules = struct {
    values: []OwnedRule,

    fn init(
        allocator: std.mem.Allocator,
        source: []const Rule,
    ) Error!OwnedRules {
        if (source.len == 0) return error.NoBridgeRules;
        const values = try allocator.alloc(OwnedRule, source.len);
        var initialized: usize = 0;
        errdefer {
            for (values[0..initialized]) |*value| value.deinit(allocator);
            allocator.free(values);
        }
        for (source, values) |rule, *owned| {
            try rule.validate();
            const filter = try allocator.dupe(u8, rule.filter);
            errdefer allocator.free(filter);
            const local_prefix = try allocator.dupe(u8, rule.local_prefix);
            errdefer allocator.free(local_prefix);
            const remote_prefix = try allocator.dupe(u8, rule.remote_prefix);
            errdefer allocator.free(remote_prefix);
            const value = Rule{
                .filter = filter,
                .qos = rule.qos,
                .local_prefix = local_prefix,
                .remote_prefix = remote_prefix,
            };
            const source_filter = try value.sourceFilterAlloc(allocator);
            errdefer allocator.free(source_filter);
            owned.* = .{
                .value = value,
                .source_filter = source_filter,
            };
            for (values[0..initialized]) |previous| {
                if (std.mem.eql(
                    u8,
                    previous.source_filter,
                    source_filter,
                )) {
                    return error.DuplicateBridgeFilter;
                }
                if (rule_helpers.filtersOverlap(
                    previous.source_filter,
                    source_filter,
                )) {
                    return error.OverlappingBridgeFilters;
                }
            }
            initialized += 1;
        }
        return .{ .values = values };
    }

    fn deinit(self: *OwnedRules, allocator: std.mem.Allocator) void {
        for (self.values) |*value| value.deinit(allocator);
        allocator.free(self.values);
        self.* = undefined;
    }
};

const TargetDeliveryState = struct {
    completed: bool = false,
    packet_id: ?u16 = null,
    reason_code: u8 = 0,

    fn reset(self: *TargetDeliveryState) void {
        self.* = .{};
    }

    fn complete(context: *anyopaque, delivery: reconnect.PublishDelivery) void {
        const self: *TargetDeliveryState = @ptrCast(@alignCast(context));
        self.completed = true;
        self.packet_id = delivery.packet_id;
        self.reason_code = delivery.reason_code;
    }
};

const TargetPublishResult = union(enum) {
    published: ?u16,
    expired,
};

const CompletedSource = struct {
    session_epoch: u64,
    packet_id: u16,
    reason_code: u8,
    retain: bool,
    topic: []u8,
    payload: []u8,
    properties: []mqtt.Property,
    expiry_interval: ?u32,

    fn init(
        allocator: std.mem.Allocator,
        session_epoch: u64,
        reason_code: u8,
        publish: mqtt.Publish,
    ) Error!CompletedSource {
        const topic = try allocator.dupe(u8, publish.topic);
        errdefer allocator.free(topic);
        const payload = try allocator.dupe(u8, publish.payload);
        errdefer allocator.free(payload);
        const copied = try owned_properties.clone(
            allocator,
            publish.properties,
            keepStableProperty,
        );
        return .{
            .session_epoch = session_epoch,
            .packet_id = publish.packet_id.?,
            .reason_code = reason_code,
            .retain = publish.retain,
            .topic = topic,
            .payload = payload,
            .properties = copied.properties,
            .expiry_interval = mqtt.messageExpiryInterval(publish.properties),
        };
    }

    fn deinit(self: *CompletedSource, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.payload);
        allocator.free(self.topic);
        self.* = undefined;
    }

    fn matches(self: CompletedSource, publish: mqtt.Publish) bool {
        if (publish.qos != .at_least_once or !publish.dup or
            self.packet_id != publish.packet_id.? or
            self.retain != publish.retain or
            !std.mem.eql(u8, self.topic, publish.topic) or
            !std.mem.eql(u8, self.payload, publish.payload) or
            !stablePropertiesEqual(self.properties, publish.properties))
        {
            return false;
        }
        const retry_expiry = mqtt.messageExpiryInterval(publish.properties);
        return if (self.expiry_interval) |original|
            retry_expiry != null and retry_expiry.? <= original
        else
            retry_expiry == null;
    }
};

/// A single-owner local-to-remote MQTT bridge.
///
/// Both MQTT clients and all rule strings are owned by the Bridge. Connector
/// contexts remain borrowed. The shutdown Event and `std.Io` backing state
/// must outlive the Bridge. QoS 1 requires a persistent source Session so an
/// unacknowledged local delivery survives either transport reconnect.
pub const Bridge = struct {
    allocator: std.mem.Allocator,
    source: reconnect.Client,
    target: reconnect.Client,
    target_delivery: *TargetDeliveryState,
    rules: OwnedRules,
    preserve_retain: bool,
    source_session_present: bool = false,
    target_session_present: bool = false,
    source_session_epoch: u64 = 0,
    completed_source: ?CompletedSource = null,
    poll_source_next: bool = true,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        source_address: net.IpAddress,
        target_address: net.IpAddress,
        options: Options,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
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
                .preserve_retain = options.preserve_retain,
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
    ) Error!Bridge {
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
    ) Error!Bridge {
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
                .preserve_retain = options.preserve_retain,
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
    ) Error!Bridge {
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
    ) Error!Bridge {
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
                .preserve_retain = options.preserve_retain,
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
    ) Error!Bridge {
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
        source_endpoint: Endpoint,
        target_endpoint: Endpoint,
        options: MultiOptions,
        shutdown: *std.Io.Event,
    ) Error!Bridge {
        var rules = try OwnedRules.init(allocator, options.rules);
        errdefer rules.deinit(allocator);
        if (rulesUseQoS1(rules.values) and
            !persistentSession(options.source_connect))
        {
            return error.QoS1RequiresPersistentSourceSession;
        }
        const target_delivery = try allocator.create(TargetDeliveryState);
        errdefer allocator.destroy(target_delivery);
        target_delivery.* = .{};
        var source = try initClient(
            allocator,
            io,
            source_endpoint,
            options.source_connect,
            options.source_reconnect_policy,
            shutdown,
            .{
                .max_subscriptions = rules.values.len,
                .manual_acknowledgements = true,
            },
        );
        errdefer source.deinit();
        for (rules.values) |rule| {
            try source.seedSubscription(.{
                .topic_filter = rule.source_filter,
                .qos = rule.value.qos,
                .retain_as_published = options.source_connect.protocol == .v5,
            }, &.{});
        }
        const target = try initClient(
            allocator,
            io,
            target_endpoint,
            options.target_connect,
            options.target_reconnect_policy,
            shutdown,
            .{ .publish_delivery = .{
                .context = target_delivery,
                .complete = TargetDeliveryState.complete,
            } },
        );
        return .{
            .allocator = allocator,
            .source = source,
            .target = target,
            .target_delivery = target_delivery,
            .rules = rules,
            .preserve_retain = options.preserve_retain,
        };
    }

    pub fn deinit(self: *Bridge) void {
        if (self.completed_source) |*completed| {
            completed.deinit(self.allocator);
        }
        self.target.deinit();
        self.source.deinit();
        self.rules.deinit(self.allocator);
        self.allocator.destroy(self.target_delivery);
        self.* = undefined;
    }

    pub fn connect(
        self: *Bridge,
    ) (Error || std.Io.Cancelable)!ConnectEvent {
        if (self.target.connection() == null) {
            const connected = try self.target.connect();
            self.target_session_present = connected.session_present;
        }
        if (self.source.connection() == null) {
            const connected = try self.source.connect();
            self.noteSourceConnected(connected);
        }
        return .{
            .source_session_present = self.source_session_present,
            .target_session_present = self.target_session_present,
        };
    }

    pub fn disconnect(self: *Bridge, reason_code: u8) Error!void {
        self.target.disconnect(reason_code) catch |err| {
            self.source.disconnect(reason_code) catch {};
            return err;
        };
        try self.source.disconnect(reason_code);
    }

    /// Process at most one event from alternating source and target polls.
    /// Poll slices are capped so an idle endpoint cannot starve the other's
    /// Keep Alive or reconnect work. Once a QoS 1 source delivery arrives,
    /// this call keeps alternating both clients until the target PUBACK, expiry,
    /// or a terminal error/cancellation occurs.
    pub fn step(
        self: *Bridge,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!bool {
        const source_turn = self.poll_source_next;
        self.poll_source_next = !source_turn;
        const bounded = bridgePollOptions(poll_options);
        return if (source_turn)
            self.stepSource(bounded, poll_options)
        else
            self.stepTarget(bounded);
    }

    fn stepSource(
        self: *Bridge,
        bounded: reconnect.PollOptions,
        forward_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!bool {
        var event = try self.source.pollWithOptions(bounded) orelse return false;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |connected| self.noteSourceConnected(connected),
            .publish => |owned| {
                if (try self.consumeCompletedSourceRetry(&owned.publish)) {
                    return true;
                }
                try self.forward(&owned.publish, forward_options);
            },
            .disconnect => self.source.disconnectTransport(),
            .pingreq, .pingresp, .auth => {},
            .puback, .pubrec, .pubrel, .pubcomp => return error.UnexpectedPacket,
        }
        return true;
    }

    fn stepTarget(
        self: *Bridge,
        bounded: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!bool {
        var event = try self.target.pollWithOptions(bounded) orelse return false;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |connected| {
                self.target_session_present = connected.session_present;
            },
            .disconnect => self.target.disconnectTransport(),
            .pingreq, .pingresp, .auth => {},
            .publish, .puback, .pubrec, .pubrel, .pubcomp => {
                self.target.disconnectTransport();
                return error.UnexpectedPacket;
            },
        }
        return true;
    }

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

    fn forward(
        self: *Bridge,
        source_publish: *const mqtt.Publish,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        const source_epoch = self.source_session_epoch;
        const rule = self.matchingRule(source_publish.topic) orelse {
            self.source.disconnectTransport();
            return error.TopicOutsideBridgeRule;
        };
        if (@intFromEnum(source_publish.qos) >
            @intFromEnum(rule.value.qos) or
            source_publish.qos == .exactly_once)
        {
            self.source.disconnectTransport();
            return error.InvalidBridgeQoS;
        }
        const target_topic = rule.value.mapMatchedTopicAlloc(
            self.allocator,
            source_publish.topic,
        ) catch |err| switch (err) {
            error.EmptyMappedTopic => {
                _ = self.acknowledgeSource(source_publish, 0);
                return;
            },
            else => |other| return other,
        };
        defer self.allocator.free(target_topic);
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.ensureTotalCapacity(
            self.allocator,
            source_publish.properties.len,
        );
        for (source_publish.properties) |property| {
            if ((property == .two_byte and
                property.two_byte.id == .topic_alias) or
                (property == .varint and
                    property.varint.id == .subscription_identifier))
            {
                continue;
            }
            properties.appendAssumeCapacity(property);
        }
        const received_at_ns = std.Io.Clock.awake.now(
            self.source.io,
        ).nanoseconds;
        const expiry_interval = mqtt.messageExpiryInterval(properties.items);
        if (self.target.connection() == null) {
            try self.connectTargetWhileServingSource(
                source_publish,
                poll_options,
            );
        }
        var target_result = self.publishTarget(
            target_topic,
            source_publish,
            &properties,
            expiry_interval,
            received_at_ns,
        ) catch |err| {
            if (source_publish.qos == .at_least_once) {
                self.source.disconnectTransport();
            }
            return err;
        };
        if (target_result == .expired) {
            _ = self.acknowledgeSource(source_publish, 0);
            return;
        }
        if (source_publish.qos == .at_most_once) return;
        errdefer self.source.disconnectTransport();
        var target_packet_id = target_result.published orelse
            return error.UnexpectedPacket;
        while (true) {
            const bounded_poll = bridgePollOptions(poll_options);
            const maybe_target_event = self.target.pollWithOptions(bounded_poll) catch |err|
                switch (err) {
                    error.PublishRefused => {
                        if (!self.target_delivery.completed or
                            self.target_delivery.packet_id != target_packet_id)
                        {
                            self.target.disconnectTransport();
                            return error.TargetAcknowledgementMismatch;
                        }
                        self.completeSource(
                            source_publish,
                            source_epoch,
                            self.target_delivery.reason_code,
                        );
                        return;
                    },
                    else => |other| {
                        self.target.disconnectTransport();
                        return other;
                    },
                };
            if (maybe_target_event) |event_value| {
                var target_event = event_value;
                defer target_event.deinit(self.allocator);
                switch (target_event) {
                    .connected => |connected| {
                        self.target_session_present = connected.session_present;
                        if (!connected.session_present) {
                            target_result = try self.publishTarget(
                                target_topic,
                                source_publish,
                                &properties,
                                expiry_interval,
                                received_at_ns,
                            );
                            if (target_result == .expired) {
                                self.completeSource(
                                    source_publish,
                                    source_epoch,
                                    0,
                                );
                                return;
                            }
                            target_packet_id = target_result.published orelse
                                return error.UnexpectedPacket;
                        } else {
                            const stats = try self.target.outgoingStats();
                            if (stats.queued_count == 0 and
                                stats.inflight_count == 0)
                            {
                                self.completeSource(
                                    source_publish,
                                    source_epoch,
                                    0,
                                );
                                return;
                            }
                        }
                    },
                    .puback => |owned| {
                        if (owned.ack.packet_id != target_packet_id) {
                            self.target.disconnectTransport();
                            return error.TargetAcknowledgementMismatch;
                        }
                        self.completeSource(
                            source_publish,
                            source_epoch,
                            owned.ack.reason_code,
                        );
                        return;
                    },
                    .disconnect => self.target.disconnectTransport(),
                    .pingreq, .pingresp, .auth => {},
                    .publish, .pubrec, .pubrel, .pubcomp => {
                        self.target.disconnectTransport();
                        return error.UnexpectedPacket;
                    },
                }
            }
            try self.serviceSourceWhileWaiting(source_publish, bounded_poll);
        }
    }

    fn publishTarget(
        self: *Bridge,
        topic: []const u8,
        source_publish: *const mqtt.Publish,
        properties: *std.ArrayList(mqtt.Property),
        expiry_interval: ?u32,
        received_at_ns: i96,
    ) (Error || std.Io.Cancelable)!TargetPublishResult {
        if (self.target.connection() == null) {
            return error.ConnectionUnavailable;
        }
        if (!refreshMessageExpiry(
            properties.items,
            expiry_interval,
            received_at_ns,
            std.Io.Clock.awake.now(self.target.io).nanoseconds,
        )) return .expired;
        self.target_delivery.reset();
        const attempt = try self.target.publishOneAttempt(
            topic,
            source_publish.payload,
            .{
                .qos = source_publish.qos,
                .retain = self.preserve_retain and source_publish.retain,
                .properties = properties.items,
            },
        );
        if (source_publish.qos == .at_least_once) {
            const stats = try self.target.outgoingStats();
            if (stats.queued_count == 0 and stats.inflight_count == 0) {
                return .expired;
            }
        }
        return .{ .published = attempt.packet_id };
    }

    fn connectTargetWhileServingSource(
        self: *Bridge,
        current: *const mqtt.Publish,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        const bounded = bridgePollOptions(poll_options);
        while (self.target.connection() == null) {
            var event = try self.target.pollWithOptions(bounded) orelse {
                try self.serviceSourceWhileWaiting(current, bounded);
                continue;
            };
            defer event.deinit(self.allocator);
            switch (event) {
                .connected => |connected| {
                    self.target_session_present = connected.session_present;
                },
                .disconnect => self.target.disconnectTransport(),
                .pingreq, .pingresp, .auth => {},
                .publish, .puback, .pubrec, .pubrel, .pubcomp => {
                    self.target.disconnectTransport();
                    return error.UnexpectedPacket;
                },
            }
            try self.serviceSourceWhileWaiting(current, bounded);
        }
    }

    fn acknowledgeSource(
        self: *Bridge,
        source_publish: *const mqtt.Publish,
        reason_code: u8,
    ) bool {
        if (source_publish.qos == .at_most_once) return true;
        const protocol_reason = if (self.source.connection()) |connection|
            if (connection.protocol == .v5) reason_code else 0
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

    fn completeSource(
        self: *Bridge,
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
        self: *Bridge,
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

    fn serviceSourceWhileWaiting(
        self: *Bridge,
        current: *const mqtt.Publish,
        poll_options: reconnect.PollOptions,
    ) (Error || std.Io.Cancelable)!void {
        var event = try self.source.pollWithOptions(poll_options) orelse return;
        defer event.deinit(self.allocator);
        switch (event) {
            .connected => |connected| self.noteSourceConnected(connected),
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
        self: *Bridge,
        connected: reconnect.ConnectEvent,
    ) void {
        self.source_session_present = connected.session_present;
        if (connected.session_present) return;
        self.source_session_epoch +%= 1;
        if (self.source_session_epoch == 0) self.source_session_epoch = 1;
        if (self.completed_source) |*completed| {
            completed.deinit(self.allocator);
        }
        self.completed_source = null;
    }

    fn matchingRule(self: *const Bridge, topic: []const u8) ?*const OwnedRule {
        var matched: ?*const OwnedRule = null;
        for (self.rules.values) |*rule| {
            if (!mqtt.topicMatchesFilter(topic, rule.source_filter)) continue;
            if (matched != null) return null;
            matched = rule;
        }
        return matched;
    }
};

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

test {
    _ = @import("outbound_tests.zig");
}

fn rulesUseQoS1(rules: []const OwnedRule) bool {
    for (rules) |rule| {
        if (rule.value.qos == .at_least_once) return true;
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

fn refreshMessageExpiry(
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

fn bridgePollOptions(options: reconnect.PollOptions) reconnect.PollOptions {
    var bounded = options;
    bounded.timeout = .fromNanoseconds(@min(
        bounded.timeout.nanoseconds,
        std.time.ns_per_ms * 50,
    ));
    bounded.cancellation_check_interval = .fromNanoseconds(@min(
        bounded.cancellation_check_interval.nanoseconds,
        bounded.timeout.nanoseconds,
    ));
    return bounded;
}

fn keepStableProperty(property: mqtt.Property) bool {
    return !((property == .two_byte and
        property.two_byte.id == .topic_alias) or
        (property == .varint and
            property.varint.id == .subscription_identifier) or
        (property == .four_byte and
            property.four_byte.id == .message_expiry_interval));
}

fn stablePropertiesEqual(
    stored: []const mqtt.Property,
    incoming: []const mqtt.Property,
) bool {
    var stored_index: usize = 0;
    for (incoming) |property| {
        if (!keepStableProperty(property)) continue;
        if (stored_index == stored.len or
            !propertyEqual(stored[stored_index], property))
        {
            return false;
        }
        stored_index += 1;
    }
    return stored_index == stored.len;
}

fn propertyEqual(left: mqtt.Property, right: mqtt.Property) bool {
    if (@intFromEnum(left) != @intFromEnum(right)) return false;
    return switch (left) {
        .byte => |value| right == .byte and
            value.id == right.byte.id and value.value == right.byte.value,
        .two_byte => |value| right == .two_byte and
            value.id == right.two_byte.id and value.value == right.two_byte.value,
        .four_byte => |value| right == .four_byte and
            value.id == right.four_byte.id and value.value == right.four_byte.value,
        .varint => |value| right == .varint and
            value.id == right.varint.id and value.value == right.varint.value,
        .binary => |value| right == .binary and
            value.id == right.binary.id and
            std.mem.eql(u8, value.value, right.binary.value),
        .utf8 => |value| right == .utf8 and
            value.id == right.utf8.id and
            std.mem.eql(u8, value.value, right.utf8.value),
        .utf8_pair => |value| right == .utf8_pair and
            value.id == right.utf8_pair.id and
            std.mem.eql(u8, value.key, right.utf8_pair.key) and
            std.mem.eql(u8, value.value, right.utf8_pair.value),
    };
}

test "outbound bridge source tombstone validates duplicate content" {
    const allocator = std.testing.allocator;
    const original_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 3 } },
        .{ .varint = .{
            .id = .subscription_identifier,
            .value = 5,
        } },
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 10,
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "source",
            .value = "stable",
        } },
    };
    const original = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = true,
        .topic = "source/tombstone",
        .packet_id = 17,
        .properties = &original_properties,
        .payload = "payload",
    };
    var completed = try CompletedSource.init(allocator, 4, 0x87, original);
    defer completed.deinit(allocator);

    const retry_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 9 } },
        .{ .varint = .{
            .id = .subscription_identifier,
            .value = 12,
        } },
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 7,
        } },
        original_properties[3],
    };
    var retry = original;
    retry.dup = true;
    retry.properties = &retry_properties;
    try std.testing.expect(completed.matches(retry));

    retry.payload = "changed";
    try std.testing.expect(!completed.matches(retry));
    retry.payload = original.payload;
    var increased_expiry = retry_properties;
    increased_expiry[2].four_byte.value = 11;
    retry.properties = &increased_expiry;
    try std.testing.expect(!completed.matches(retry));
}

fn publishRetryMatches(original: mqtt.Publish, retry: mqtt.Publish) bool {
    if (original.qos != .at_least_once or retry.qos != .at_least_once or
        !retry.dup or original.packet_id != retry.packet_id or
        original.retain != retry.retain or
        !std.mem.eql(u8, original.topic, retry.topic) or
        !std.mem.eql(u8, original.payload, retry.payload) or
        !stablePropertiesEqualFiltered(
            original.properties,
            retry.properties,
        ))
    {
        return false;
    }
    const original_expiry = mqtt.messageExpiryInterval(original.properties);
    const retry_expiry = mqtt.messageExpiryInterval(retry.properties);
    return if (original_expiry) |value|
        retry_expiry != null and retry_expiry.? <= value
    else
        retry_expiry == null;
}

fn stablePropertiesEqualFiltered(
    left: []const mqtt.Property,
    right: []const mqtt.Property,
) bool {
    var left_index: usize = 0;
    var right_index: usize = 0;
    while (true) {
        while (left_index < left.len and
            !keepStableProperty(left[left_index]))
        {
            left_index += 1;
        }
        while (right_index < right.len and
            !keepStableProperty(right[right_index]))
        {
            right_index += 1;
        }
        if (left_index == left.len or right_index == right.len) {
            return left_index == left.len and right_index == right.len;
        }
        if (!propertyEqual(left[left_index], right[right_index])) return false;
        left_index += 1;
        right_index += 1;
    }
}

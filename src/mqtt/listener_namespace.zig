//! Per-listener MQTT topic namespaces compatible with Mosquitto `mount_point`.
//!
//! The broker stores one canonical topic space. Listener adapters prepend this
//! namespace to inbound PUBLISH/Will topics and subscription filters, then
//! strip it only when a canonical publication is delivered back through the
//! same listener. Shared subscriptions keep `$share/{group}/` outside the
//! mount prefix because that wrapper is routing metadata rather than a topic.

const std = @import("std");
const mqtt = @import("mod.zig");

pub const MapError = mqtt.Error || std.mem.Allocator.Error;
pub const Error = MapError || error{
    TopicOutsideNamespace,
};

/// A validated canonical Topic Name. An empty listener namespace borrows the
/// original name; a non-empty namespace owns its prefixed representation.
pub const MappedTopic = struct {
    value: []const u8,
    allocation: ?[]u8 = null,

    pub fn deinit(self: *MappedTopic, allocator: std.mem.Allocator) void {
        if (self.allocation) |bytes| allocator.free(bytes);
        self.* = undefined;
    }
};

pub const Namespace = struct {
    prefix: []const u8 = &.{},
    owned: bool = false,

    /// Validate a listener namespace. Like Mosquitto, a mount point is a
    /// literal topic prefix rather than a filter, so `+` and `#` are forbidden.
    pub fn init(prefix: []const u8) mqtt.Error!Namespace {
        if (prefix.len > std.math.maxInt(u16)) return error.InvalidTopic;
        if (prefix.len != 0) try mqtt.validateTopicName(prefix);
        return .{ .prefix = prefix };
    }

    /// Deep-own listener configuration so a long-lived accept loop never
    /// borrows command-line/config-parser scratch storage.
    pub fn initOwned(
        allocator: std.mem.Allocator,
        prefix: []const u8,
    ) MapError!Namespace {
        const borrowed = try init(prefix);
        if (borrowed.prefix.len == 0) return .{};
        return .{
            .prefix = try allocator.dupe(u8, borrowed.prefix),
            .owned = true,
        };
    }

    pub fn deinit(self: *Namespace, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.prefix);
        self.* = undefined;
    }

    pub fn mapTopicAlloc(
        self: Namespace,
        allocator: std.mem.Allocator,
        topic: []const u8,
    ) MapError![]u8 {
        try mqtt.validateTopicName(topic);
        return self.prependAlloc(allocator, topic);
    }

    /// Map an inbound Topic Name while borrowing it for the common empty
    /// namespace. The result must not outlive `topic` and must be deinitialized
    /// so a non-empty namespace can release its owned prefix concatenation.
    pub fn mapTopic(
        self: Namespace,
        allocator: std.mem.Allocator,
        topic: []const u8,
    ) MapError!MappedTopic {
        try mqtt.validateTopicName(topic);
        if (self.prefix.len == 0) return .{ .value = topic };
        const mapped = try self.prependAlloc(allocator, topic);
        return .{ .value = mapped, .allocation = mapped };
    }

    pub fn mapFilterAlloc(
        self: Namespace,
        allocator: std.mem.Allocator,
        filter: []const u8,
    ) MapError![]u8 {
        try mqtt.validateTopicFilter(filter);
        if (sharedFilterParts(filter)) |shared| {
            const mapped_filter_len = std.math.add(
                usize,
                self.prefix.len,
                shared.filter.len,
            ) catch return error.InvalidSubscription;
            const namespaced = self.prependAlloc(
                allocator,
                shared.filter,
            ) catch |err| switch (err) {
                error.InvalidTopic => return error.InvalidSubscription,
                else => |other| return other,
            };
            defer allocator.free(namespaced);
            const wrapper_len = std.math.add(
                usize,
                "$share//".len,
                shared.group.len,
            ) catch return error.InvalidSubscription;
            const total_len = std.math.add(
                usize,
                wrapper_len,
                mapped_filter_len,
            ) catch return error.InvalidSubscription;
            if (total_len > std.math.maxInt(u16)) {
                return error.InvalidSubscription;
            }
            return std.fmt.allocPrint(
                allocator,
                "$share/{s}/{s}",
                .{ shared.group, namespaced },
            );
        }
        return self.prependAlloc(allocator, filter) catch |err| switch (err) {
            error.InvalidTopic => error.InvalidSubscription,
            else => |other| other,
        };
    }

    /// Rewrite only the Will Topic of an owned CONNECT parse tree. The packet
    /// parser owns the original topic bytes indirectly through `packet`, while
    /// this helper owns the replacement separately so callers can restore the
    /// borrowed view before normal CONNECT teardown.
    pub fn mapConnectWill(
        self: Namespace,
        allocator: std.mem.Allocator,
        connect: *mqtt.Connect,
    ) MapError!?MappedWillTopic {
        const will = &(connect.will orelse return null);
        const previous = will.topic;
        const mapped = try self.mapTopicAlloc(allocator, previous);
        will.topic = mapped;
        return .{
            .allocator = allocator,
            .will = will,
            .previous = previous,
            .mapped = mapped,
        };
    }

    /// Return the client-visible Topic Name for a canonical broker topic. A
    /// non-matching prefix is not silently exposed across listener namespaces.
    pub fn visibleTopic(
        self: Namespace,
        canonical_topic: []const u8,
    ) Error![]const u8 {
        if (self.prefix.len == 0) return canonical_topic;
        if (!std.mem.startsWith(u8, canonical_topic, self.prefix)) {
            return error.TopicOutsideNamespace;
        }
        const visible = canonical_topic[self.prefix.len..];
        // An exact-prefix canonical topic would become an invalid empty MQTT
        // Topic Name and therefore indicates mismatched broker state.
        if (visible.len == 0) return error.TopicOutsideNamespace;
        return visible;
    }

    pub fn containsTopic(
        self: Namespace,
        canonical_topic: []const u8,
    ) bool {
        _ = self.visibleTopic(canonical_topic) catch return false;
        return true;
    }

    fn prependAlloc(
        self: Namespace,
        allocator: std.mem.Allocator,
        value: []const u8,
    ) MapError![]u8 {
        const len = std.math.add(usize, self.prefix.len, value.len) catch
            return error.InvalidTopic;
        if (len > std.math.maxInt(u16)) return error.InvalidTopic;
        const result = try allocator.alloc(u8, len);
        @memcpy(result[0..self.prefix.len], self.prefix);
        @memcpy(result[self.prefix.len..], value);
        return result;
    }
};

/// Scoped mutation for feeding a listener-normalized Will into existing
/// Session/Will stores without changing `OwnedConnect`'s allocation model.
pub const MappedWillTopic = struct {
    allocator: std.mem.Allocator,
    will: *mqtt.LastWill,
    previous: []const u8,
    mapped: []u8,

    pub fn deinit(self: *MappedWillTopic) void {
        self.will.topic = self.previous;
        self.allocator.free(self.mapped);
        self.* = undefined;
    }
};

const SharedFilter = struct {
    group: []const u8,
    filter: []const u8,
};

fn sharedFilterParts(filter: []const u8) ?SharedFilter {
    const prefix = "$share/";
    if (!std.mem.startsWith(u8, filter, prefix)) return null;
    const rest = filter[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    return .{
        .group = rest[0..slash],
        .filter = rest[slash + 1 ..],
    };
}

test "listener namespace maps publish, filter, shared filter and delivery" {
    const allocator = std.testing.allocator;
    const namespace = try Namespace.init("tenant/east/");

    const topic = try namespace.mapTopicAlloc(allocator, "sensor/value");
    defer allocator.free(topic);
    try std.testing.expectEqualStrings(
        "tenant/east/sensor/value",
        topic,
    );

    const filter = try namespace.mapFilterAlloc(allocator, "sensor/+/raw/#");
    defer allocator.free(filter);
    try std.testing.expectEqualStrings(
        "tenant/east/sensor/+/raw/#",
        filter,
    );

    const shared = try namespace.mapFilterAlloc(
        allocator,
        "$share/workers/sensor/#",
    );
    defer allocator.free(shared);
    try std.testing.expectEqualStrings(
        "$share/workers/tenant/east/sensor/#",
        shared,
    );
    try std.testing.expectEqualStrings(
        "sensor/value",
        try namespace.visibleTopic(topic),
    );
}

test "listener namespace borrows identity topic and owns prefixed topic" {
    const allocator = std.testing.allocator;
    const topic = "sensor/value";
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var identity = try (Namespace{}).mapTopic(
        failing.allocator(),
        topic,
    );
    defer identity.deinit(failing.allocator());
    try std.testing.expect(identity.allocation == null);
    try std.testing.expectEqual(topic.ptr, identity.value.ptr);
    try std.testing.expectEqualStrings(topic, identity.value);
    try std.testing.expect(!failing.has_induced_failure);

    const namespace = try Namespace.init("tenant/");
    var prefixed = try namespace.mapTopic(allocator, topic);
    defer prefixed.deinit(allocator);
    try std.testing.expect(prefixed.allocation != null);
    try std.testing.expectEqualStrings("tenant/sensor/value", prefixed.value);
}

test "listener namespace rejects invalid prefixes and cross-namespace topics" {
    try std.testing.expectError(
        error.InvalidTopic,
        Namespace.init("tenant/+/"),
    );
    // Empty is the explicit global namespace and remains legal.
    const global = try Namespace.init("");
    try std.testing.expectEqualStrings(
        "outside/value",
        try global.visibleTopic("outside/value"),
    );

    const namespace = try Namespace.init("tenant/east/");
    try std.testing.expectError(
        error.TopicOutsideNamespace,
        namespace.visibleTopic("tenant/west/value"),
    );
    try std.testing.expectError(
        error.TopicOutsideNamespace,
        namespace.visibleTopic("tenant/east/"),
    );
}

test "listener namespace preserves MQTT dollar-topic wildcard isolation" {
    const allocator = std.testing.allocator;
    const namespace = try Namespace.init("mount/");
    const global_filter = try namespace.mapFilterAlloc(allocator, "#");
    defer allocator.free(global_filter);
    const system_filter = try namespace.mapFilterAlloc(allocator, "$SYS/#");
    defer allocator.free(system_filter);

    try std.testing.expect(mqtt.topicMatchesFilter(
        "mount/value",
        global_filter,
    ));
    try std.testing.expect(!mqtt.topicMatchesFilter(
        "$SYS/broker/clients/connected",
        global_filter,
    ));
    try std.testing.expect(mqtt.topicMatchesFilter(
        "mount/$SYS/broker/clients/connected",
        system_filter,
    ));
}

test "listener namespace enforces MQTT UTF-8 wire length after prefixing" {
    const allocator = std.testing.allocator;
    const namespace = try Namespace.init("p/");
    const maximum_topic = "x" ** (std.math.maxInt(u16) - 2);
    const mapped = try namespace.mapTopicAlloc(allocator, maximum_topic);
    defer allocator.free(mapped);
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(u16)),
        mapped.len,
    );
    try std.testing.expectError(
        error.InvalidTopic,
        namespace.mapTopicAlloc(allocator, maximum_topic ++ "x"),
    );
    try std.testing.expectError(
        error.InvalidSubscription,
        namespace.mapFilterAlloc(allocator, maximum_topic ++ "#"),
    );
}

test "listener namespace can own transient configuration" {
    const allocator = std.testing.allocator;
    var input = try allocator.dupe(u8, "tenant/");
    var namespace = try Namespace.initOwned(allocator, input);
    defer namespace.deinit(allocator);
    allocator.free(input);
    input = undefined;

    const mapped = try namespace.mapTopicAlloc(allocator, "value");
    defer allocator.free(mapped);
    try std.testing.expectEqualStrings("tenant/value", mapped);
}

test "listener namespace scopes an owned CONNECT Will rewrite" {
    const allocator = std.testing.allocator;
    const namespace = try Namespace.init("listener/");
    var connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 30,
        .client_id = "client",
        .will = .{
            .topic = "status",
            .payload = "offline",
        },
    };
    var mapped = (try namespace.mapConnectWill(allocator, &connect)).?;
    try std.testing.expectEqualStrings(
        "listener/status",
        connect.will.?.topic,
    );
    mapped.deinit();
    try std.testing.expectEqualStrings("status", connect.will.?.topic);
}

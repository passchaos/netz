//! Local subscription to remote Topic Name mapping.
const std = @import("std");
const mqtt = @import("../mod.zig");
const listener_namespace = @import("../listener_namespace.zig");
const Error = @import("outbound_engine.zig").Error;

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

    pub fn targetFilterAlloc(
        self: Rule,
        allocator: std.mem.Allocator,
    ) Error![]u8 {
        try self.validate();
        const namespace = try listener_namespace.Namespace.init(
            self.remote_prefix,
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

    pub fn mapMatchedTopicAlloc(
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

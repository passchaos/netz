const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");

/// Deep-owned subscription state shared by reconnect replay and queued
/// commands. Packet-scoped properties are retained here only when the value is
/// stored for replay; queued commands pass an empty property slice and own the
/// SUBSCRIBE properties once per command instead.
pub const Owned = struct {
    filter: []u8,
    qos: mqtt.QoS,
    no_local: bool,
    retain_as_published: bool,
    retain_handling: u2,
    properties: []mqtt.Property,

    pub fn clone(
        allocator: std.mem.Allocator,
        source: mqtt.Subscription,
        properties: []const mqtt.Property,
    ) !Owned {
        const filter = try allocator.dupe(u8, source.topic_filter);
        errdefer allocator.free(filter);
        const copied_properties = try owned_properties.clone(
            allocator,
            properties,
            owned_properties.keepAll,
        );
        return .{
            .filter = filter,
            .qos = source.qos,
            .no_local = source.no_local,
            .retain_as_published = source.retain_as_published,
            .retain_handling = source.retain_handling,
            .properties = copied_properties.properties,
        };
    }

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.filter);
        owned_properties.deinit(allocator, self.properties);
        self.* = undefined;
    }

    pub fn value(self: Owned) mqtt.Subscription {
        return .{
            .topic_filter = self.filter,
            .qos = self.qos,
            .no_local = self.no_local,
            .retain_as_published = self.retain_as_published,
            .retain_handling = self.retain_handling,
        };
    }
};

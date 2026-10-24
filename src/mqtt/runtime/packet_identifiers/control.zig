//! Owned request metadata for correlated subscription acknowledgements.
const std = @import("std");
const mqtt = @import("../../mod.zig");

pub const State = struct {
    const Entry = struct {
        filter_count: usize,
        requested_qos: ?[]mqtt.QoS = null,
    };

    entries: std.AutoHashMapUnmanaged(u16, Entry) = .empty,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.clearRetainingCapacity(allocator);
        self.entries.deinit(allocator);
        self.* = .{};
    }

    pub fn add(self: *State, allocator: std.mem.Allocator, packet_id: u16, filter_count: usize) std.mem.Allocator.Error!void {
        try self.entries.putNoClobber(allocator, packet_id, .{ .filter_count = filter_count });
    }

    pub fn filterCount(self: *const State, packet_id: u16) ?usize {
        const entry = self.entries.get(packet_id) orelse return null;
        return entry.filter_count;
    }

    /// Snapshot before any bytes are written. The caller's request may be
    /// modified or destroyed while an ACK remains pending after a timeout.
    pub fn rememberSubscribe(self: *State, allocator: std.mem.Allocator, packet_id: u16, subscriptions: []const mqtt.Subscription) std.mem.Allocator.Error!void {
        const entry = self.entries.getPtr(packet_id).?;
        std.debug.assert(entry.filter_count == subscriptions.len);
        std.debug.assert(entry.requested_qos == null);
        const requested = try allocator.alloc(mqtt.QoS, subscriptions.len);
        for (requested, subscriptions) |*qos, subscription| qos.* = subscription.qos;
        entry.requested_qos = requested;
    }

    /// MQTT 3.1.1/5 section 3.8.3 defines the request as a maximum QoS;
    /// section 3.8.4 permits lower grants. Failure reasons are not QoS grants.
    pub fn validateSubAck(self: *const State, packet_id: u16, reasons: []const u8) error{UnexpectedPacket}!void {
        const entry = self.entries.get(packet_id) orelse return;
        const requested = entry.requested_qos orelse return;
        if (reasons.len != requested.len) return error.UnexpectedPacket;
        for (reasons, requested) |reason, maximum| {
            if (reason < 0x80 and reason > @intFromEnum(maximum)) return error.UnexpectedPacket;
        }
    }

    pub fn remove(self: *State, allocator: std.mem.Allocator, packet_id: u16) void {
        const entry = self.entries.fetchRemove(packet_id) orelse return;
        if (entry.value.requested_qos) |requested| allocator.free(requested);
    }

    pub fn clearRetainingCapacity(self: *State, allocator: std.mem.Allocator) void {
        var entries = self.entries.valueIterator();
        while (entries.next()) |entry| {
            if (entry.requested_qos) |requested| allocator.free(requested);
        }
        self.entries.clearRetainingCapacity();
    }
};

test "MQTT SUBACK QoS metadata owns ordered request limits and releases snapshots" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);
    var subscriptions = [_]mqtt.Subscription{
        .{ .topic_filter = "zero", .qos = .at_most_once },
        .{ .topic_filter = "one", .qos = .at_least_once },
        .{ .topic_filter = "two", .qos = .exactly_once },
    };
    try state.add(allocator, 42, subscriptions.len);
    try state.rememberSubscribe(allocator, 42, &subscriptions);
    subscriptions[0].qos = .exactly_once;
    subscriptions[1].qos = .at_most_once;
    try state.validateSubAck(42, &.{ 0, 1, 2 });
    try state.validateSubAck(42, &.{ 0x80, 0, 0x87 });
    try std.testing.expectError(error.UnexpectedPacket, state.validateSubAck(42, &.{ 1, 0, 2 }));
    try std.testing.expectError(error.UnexpectedPacket, state.validateSubAck(42, &.{ 0, 2, 1 }));
    state.remove(allocator, 42);
    try std.testing.expectEqual(@as(?usize, null), state.filterCount(42));
    try state.add(allocator, 42, subscriptions.len);
    try state.rememberSubscribe(allocator, 42, &subscriptions);
    try state.validateSubAck(42, &.{ 2, 0, 1 });
    state.clearRetainingCapacity(allocator);
    try std.testing.expectEqual(@as(?usize, null), state.filterCount(42));
}

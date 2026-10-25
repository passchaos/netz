//! Expiry metadata remains bounded and detached from the monotonic clock epoch.
const std = @import("std");
const retention = @import("retention.zig");
const codec = @import("../persistence/codec.zig");
const mqtt = @import("../mod.zig");

test "MQTT reconnect retention tracks offline time and preserves infinite lifetime" {
    const now = std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s);
    var state = retention.State{ .interval = 3 };
    try std.testing.expect(!state.expired(now));
    state.disconnected(now);
    try std.testing.expect(!state.expired(.fromNanoseconds(now.nanoseconds + 2 * std.time.ns_per_s)));
    try std.testing.expect(state.expired(.fromNanoseconds(now.nanoseconds + 3 * std.time.ns_per_s)));
    try std.testing.expectEqual(@as(?u64, std.time.ns_per_s), state.view(.fromNanoseconds(now.nanoseconds + 2 * std.time.ns_per_s)).remaining_ns);
    state.connected(0);
    try std.testing.expect(!state.expired(now));
    try std.testing.expectEqual(@as(?u64, 0), state.view(now).remaining_ns);
    state.disconnected(now);
    try std.testing.expect(state.expired(now));
    state.connected(std.math.maxInt(u32));
    state.disconnected(now);
    try std.testing.expect(!state.expired(.fromNanoseconds(std.math.maxInt(i96))));
    try std.testing.expect(state.view(now).remaining_ns == null);
}

test "MQTT reconnect retention decoder validates metadata before clock conversion" {
    const cases = [_]struct { protocol: mqtt.ProtocolVersion = .v5, interval: u32, remaining: ?u64 }{
        .{ .interval = 1, .remaining = null },
        .{ .interval = 1, .remaining = std.time.ns_per_s + 1 },
        .{ .interval = 0, .remaining = 1 },
        .{ .interval = std.math.maxInt(u32), .remaining = 0 },
        .{ .protocol = .v3_1_1, .interval = 1, .remaining = 0 },
    };
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    for (cases) |case| {
        bytes.clearRetainingCapacity();
        try codec.appendInt(&bytes, std.testing.allocator, u32, case.interval);
        try codec.appendOptionalInt(&bytes, std.testing.allocator, u64, case.remaining);
        var cursor = codec.Cursor.init(bytes.items);
        try std.testing.expectError(error.CorruptSnapshot, retention.decode(&cursor, case.protocol, 0, .zero));
    }
}

test "MQTT reconnect retention subtracts downtime exactly and never renews on clock rollback" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try retention.encode(&bytes, std.testing.allocator, .v5, .{ .interval = 3, .remaining_ns = std.time.ns_per_s });
    for ([_]i96{ -1, 0, std.time.ns_per_s - 1, std.time.ns_per_s, std.time.ns_per_s + 1 }) |downtime| {
        var cursor = codec.Cursor.init(bytes.items);
        const state = try retention.decode(&cursor, .v5, downtime, .zero);
        try std.testing.expectEqual(downtime >= std.time.ns_per_s, state.expired(.zero));
        try std.testing.expectEqual(@as(?u64, @intCast(@max(0, @as(i96, std.time.ns_per_s) - @max(0, downtime)))), state.view(.zero).remaining_ns);
    }
}

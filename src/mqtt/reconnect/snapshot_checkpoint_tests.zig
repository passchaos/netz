//! Historical validation must not install or replay state discarded by expiry.
const std = @import("std");
const snapshot = @import("snapshot.zig");
const session = @import("../session/mod.zig");

test "MQTT checkpoint decode retains historical QoS markers while normal restore applies expiry" {
    const allocator = std.testing.allocator;
    var original = session.Store.init(allocator, .{ .max_sessions = 1 });
    defer original.deinit();
    const opened = try original.open("checkpoint", false, std.math.maxInt(u32), .zero);
    _ = try original.beginImmediatePublish(opened.handle, "pending", "old", .{
        .qos = .exactly_once,
        .properties = &.{.{ .four_byte = .{ .id = .message_expiry_interval, .value = 1 } }},
        .now = .zero,
    }, 8);
    _ = try original.recordIncomingQoS2(opened.handle, 77);
    for ([_]u32{ 1, 60 }) |lifetime| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try snapshot.encodeWithRetention(&original, opened.handle, .v5, "checkpoint", &bytes, allocator, .zero, .zero, .{ .values = &.{}, .replay_index = null }, .{
            .interval = lifetime,
            .remaining_ns = @as(u64, lifetime) * std.time.ns_per_s,
        });
        const realtime: std.Io.Timestamp = .fromNanoseconds(2 * std.time.ns_per_s);
        var checkpoint = try snapshot.decodeCheckpoint(allocator, bytes.items, original.options, .v5, "checkpoint", .zero, realtime, 1);
        defer checkpoint.deinit();
        var restored = try snapshot.decode(allocator, bytes.items, original.options, .v5, "checkpoint", .zero, realtime);
        defer restored.deinit();
        try std.testing.expectEqual(@as(usize, 1), (try checkpoint.store.stats(checkpoint.handle)).inflight_count);
        try std.testing.expectEqual(@as(usize, 1), (try checkpoint.store.stats(checkpoint.handle)).incoming_qos2_count);
        try std.testing.expectEqual(@as(usize, 0), (try restored.store.stats(restored.handle)).inflight_count);
        try std.testing.expectEqual(@as(usize, if (lifetime == 1) 0 else 1), (try restored.store.stats(restored.handle)).incoming_qos2_count);
        try std.testing.expectEqual(lifetime == 1, checkpoint.retention_state.?.expired(.zero));
    }
}

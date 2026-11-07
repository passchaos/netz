//! The pre-optimization v7 image remains the byte-level format oracle.
const std = @import("std");
const persistence = @import("mod.zig");

const golden = @embedFile("testdata/v7_all_sections.bin");
const monotonic = std.Io.Timestamp.zero;
const realtime = std.Io.Timestamp.fromNanoseconds(1_700_000_000 * std.time.ns_per_s);

fn roundTrip(allocator: std.mem.Allocator) !void {
    var restored = try persistence.decode(allocator, golden, .{}, .{}, .{}, 16, .{}, monotonic, realtime);
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();
    defer restored.bridge_qos2.deinit();
    const state: persistence.State = .{
        .retained = &restored.retained,
        .sessions = &restored.sessions,
        .wills = &restored.wills,
        .will_publishers = &restored.will_publishers,
        .pending_qos2 = &restored.pending_qos2,
        .bridge_qos2 = &restored.bridge_qos2,
    };
    const sessions = restored.sessions.aggregateStats();
    try std.testing.expectEqual(@as(usize, 1), sessions.session_count);
    try std.testing.expectEqual(@as(usize, 8), sessions.queued_count);
    try std.testing.expectEqual(@as(usize, 1), restored.retained.count());
    try std.testing.expectEqual(@as(usize, 1), restored.wills.count());
    try std.testing.expectEqual(@as(usize, 1), restored.will_publishers.count());
    try std.testing.expectEqual(@as(usize, 1), restored.pending_qos2.count());
    try std.testing.expectEqual(@as(usize, 1), restored.bridge_qos2.stats().entries);
    const encoded = try persistence.encode(allocator, state, monotonic, realtime);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, golden, encoded);
    const live = try persistence.encodeLive(allocator, state, monotonic, realtime);
    defer allocator.free(live);
    try std.testing.expectEqualSlices(u8, golden, live);
}

test "MQTT v7 snapshot encoding preserves all-section golden bytes" {
    try roundTrip(std.testing.allocator);
}

test "MQTT v7 snapshot encoding and decoding clean up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, roundTrip, .{});
}

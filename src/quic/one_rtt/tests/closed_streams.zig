const std = @import("std");
const Set = @import("../closed_streams.zig").Set;

test "QUIC closed stream set merges ordered and out-of-order sequences" {
    const allocator = std.testing.allocator;
    var set: Set = .{};
    defer set.deinit(allocator);
    try set.prepareInsert(allocator, 8);

    for ([_]u64{ 4, 0, 2, 1, 7, 6, 5, 3 }) |sequence| {
        set.insertAssumeCapacity(sequence);
    }
    try std.testing.expectEqual(@as(usize, 1), set.rangeCount());
    try std.testing.expectEqual(@as(usize, 0), set.sparseRangeCount());
    for (0..8) |sequence| {
        try std.testing.expect(set.contains(sequence));
    }
    try std.testing.expect(!set.contains(8));
}

test "QUIC closed stream set retains sparse gaps exactly" {
    const allocator = std.testing.allocator;
    var set: Set = .{};
    defer set.deinit(allocator);
    try set.prepareInsert(allocator, 4);

    for ([_]u64{ 1, 3, 5, 3 }) |sequence| {
        set.insertAssumeCapacity(sequence);
    }
    try std.testing.expectEqual(@as(usize, 3), set.rangeCount());
    try std.testing.expectEqual(@as(usize, 3), set.sparseRangeCount());
    for ([_]u64{ 1, 3, 5 }) |sequence| {
        try std.testing.expect(set.contains(sequence));
    }
    for ([_]u64{ 0, 2, 4, 6 }) |sequence| {
        try std.testing.expect(!set.contains(sequence));
    }
}

test "QUIC closed stream set joins sparse ranges into its prefix" {
    const allocator = std.testing.allocator;
    var set: Set = .{};
    defer set.deinit(allocator);
    try set.prepareInsert(allocator, 4);

    for ([_]u64{ 3, 2, 0 }) |sequence| set.insertAssumeCapacity(sequence);
    try std.testing.expectEqual(@as(usize, 2), set.rangeCount());
    try std.testing.expectEqual(@as(usize, 1), set.sparseRangeCount());
    set.insertAssumeCapacity(1);
    try std.testing.expectEqual(@as(usize, 1), set.rangeCount());
    try std.testing.expectEqual(@as(usize, 0), set.sparseRangeCount());
    for (0..4) |sequence| try std.testing.expect(set.contains(sequence));
}

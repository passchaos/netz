const std = @import("std");
const buffer = @import("../buffer.zig");

test "WebSocket message buffer uses bounded slab growth" {
    const allocator = std.testing.allocator;
    var storage: std.ArrayList(u8) = .empty;
    defer storage.deinit(allocator);

    const first = [_]u8{0xaa} ** 4104;
    try buffer.appendPrecise(&storage, allocator, &first);
    try std.testing.expectEqual(first.len, storage.items.len);
    try std.testing.expectEqual(@as(usize, 4352), storage.capacity);

    storage.clearRetainingCapacity();
    try buffer.appendPrecise(&storage, allocator, "small!!");
    const extra = [_]u8{0xcc} ** 4098;
    try buffer.appendPrecise(&storage, allocator, &extra);
    try std.testing.expectEqual(@as(usize, 4352), storage.capacity);

    storage.clearRetainingCapacity();
    const large = [_]u8{0xdd} ** 20_001;
    try buffer.appendPrecise(&storage, allocator, &large);
    try std.testing.expectEqual(large.len, storage.items.len);
    try std.testing.expect(storage.capacity - large.len < buffer.slab_size);
}

test "WebSocket message buffer growth is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkGrowth,
        .{},
    );
}

test "WebSocket receive window amortizes coalesced frame consumption" {
    const allocator = std.testing.allocator;
    var storage: std.ArrayList(u8) = .empty;
    defer storage.deinit(allocator);
    const frame_count: usize = 4096;
    try storage.appendNTimes(allocator, 0xaa, frame_count * 2);

    var consumed: usize = 0;
    var moved: usize = 0;
    for (0..frame_count) |_| {
        try std.testing.expectEqual(@as(usize, 2), @min(
            2,
            buffer.unreadLen(&storage, consumed),
        ));
        moved += buffer.discardPrefix(&storage, &consumed, 2);
    }
    try std.testing.expectEqual(@as(usize, 0), storage.items.len);
    try std.testing.expectEqual(@as(usize, 0), consumed);
    try std.testing.expect(moved < frame_count * 2);
}

test "WebSocket receive window compacts before append reuses capacity" {
    const allocator = std.testing.allocator;
    var storage: std.ArrayList(u8) = .empty;
    defer storage.deinit(allocator);
    try storage.ensureTotalCapacityPrecise(allocator, 512);
    try storage.appendNTimes(allocator, 0xaa, 400);
    var consumed: usize = 200;
    try buffer.appendAfterConsumed(
        &storage,
        &consumed,
        allocator,
        &([_]u8{0xbb} ** 200),
    );
    try std.testing.expectEqual(@as(usize, 0), consumed);
    try std.testing.expectEqual(@as(usize, 400), storage.items.len);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xaa} ** 200),
        storage.items[0..200],
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xbb} ** 200),
        storage.items[200..],
    );
}

test "WebSocket receive window supports direct transport fill" {
    const allocator = std.testing.allocator;
    var storage: std.ArrayList(u8) = .empty;
    defer storage.deinit(allocator);
    try storage.ensureTotalCapacityPrecise(allocator, 8);
    try storage.appendSlice(allocator, "old-data");
    var consumed: usize = 4;

    const tail = try buffer.reserveAppendAfterConsumed(
        &storage,
        &consumed,
        allocator,
        5,
    );
    try std.testing.expectEqual(@as(usize, 0), consumed);
    try std.testing.expectEqualStrings("data", storage.items);
    @memcpy(tail[0..3], "new");
    buffer.commitAppend(&storage, 3);
    try std.testing.expectEqualStrings("datanew", storage.items);

    const unused = try buffer.reserveAppendAfterConsumed(
        &storage,
        &consumed,
        allocator,
        2,
    );
    unused[0] = 0xaa;
    unused[1] = 0xbb;
    buffer.commitAppend(&storage, 0);
    try std.testing.expectEqualStrings("datanew", storage.items);
}

test "WebSocket message buffer capacity rounding rejects overflow" {
    try std.testing.expectEqual(
        @as(usize, 0),
        try buffer.roundedCapacity(0),
    );
    try std.testing.expectEqual(
        @as(usize, 256),
        try buffer.roundedCapacity(1),
    );
    try std.testing.expectEqual(
        @as(usize, 512),
        try buffer.roundedCapacity(257),
    );
    try std.testing.expectError(
        error.OutOfMemory,
        buffer.roundedCapacity(std.math.maxInt(usize)),
    );
}

fn checkGrowth(allocator: std.mem.Allocator) !void {
    var storage: std.ArrayList(u8) = .empty;
    defer storage.deinit(allocator);
    try buffer.appendPrecise(&storage, allocator, "header");
    try buffer.appendPrecise(&storage, allocator, "payload");
    try std.testing.expectEqualStrings("headerpayload", storage.items);
    try std.testing.expect(storage.capacity - storage.items.len < buffer.slab_size);
}

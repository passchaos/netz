const std = @import("std");
const Queue = @import("../datagram_queue.zig").Queue;

test "QUIC DATAGRAM receive queue drops oldest without shifting" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    try pushOwned(&queue, allocator, "one", 0, 2);
    try pushOwned(&queue, allocator, "two", 1, 2);
    const three = try allocator.dupe(u8, "three");
    const dropped = (try queue.pushDroppingOldest(
        allocator,
        three,
        2,
        2,
    )).?;
    defer allocator.free(dropped);
    try std.testing.expectEqualStrings("one", dropped);

    const first = queue.pop().?;
    defer allocator.free(first);
    try std.testing.expectEqualStrings("two", first);
    try pushOwned(&queue, allocator, "four", 3, 2);
    const second = queue.pop().?;
    defer allocator.free(second);
    const third = queue.pop().?;
    defer allocator.free(third);
    try std.testing.expectEqualStrings("three", second);
    try std.testing.expectEqualStrings("four", third);
}

test "QUIC DATAGRAM receive queue discards wrapped packet entries stably" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    try pushOwned(&queue, allocator, "a", 1, 4);
    try pushOwned(&queue, allocator, "b", 2, 4);
    try pushOwned(&queue, allocator, "c", 1, 4);
    try pushOwned(&queue, allocator, "d", 3, 4);
    const first = queue.pop().?;
    allocator.free(first);
    try pushOwned(&queue, allocator, "e", 1, 4);

    try std.testing.expectEqual(@as(usize, 2), queue.countPacket(1));
    try std.testing.expectEqual(@as(usize, 2), queue.discardPacket(allocator, 1));
    try std.testing.expectEqual(@as(usize, 2), queue.count());
    const b = queue.pop().?;
    defer allocator.free(b);
    const d = queue.pop().?;
    defer allocator.free(d);
    try std.testing.expectEqualStrings("b", b);
    try std.testing.expectEqualStrings("d", d);
}

test "QUIC DATAGRAM receive queue OOM keeps caller ownership" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    const payload = try allocator.dupe(u8, "owned");
    defer allocator.free(payload);
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        queue.pushDroppingOldest(fail.allocator(), payload, 1, 1),
    );
    try std.testing.expectEqual(@as(usize, 0), queue.count());
}

test "QUIC DATAGRAM receive queue capacity one replaces in place" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    try pushOwned(&queue, allocator, "old", 1, 1);
    const fresh = try allocator.dupe(u8, "new");
    const dropped = (try queue.pushDroppingOldest(
        allocator,
        fresh,
        2,
        1,
    )).?;
    defer allocator.free(dropped);
    try std.testing.expectEqualStrings("old", dropped);
    const kept = queue.pop().?;
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("new", kept);
}

test "QUIC DATAGRAM receive queue reserves its exact bound once" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    try pushOwned(&queue, allocator, "one", 1, 4);
    try std.testing.expectEqual(@as(usize, 4), queue.storageCapacity());

    const payload = try allocator.dupe(u8, "two");
    var owns_payload = true;
    errdefer if (owns_payload) allocator.free(payload);
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try queue.pushDroppingOldest(
            fail.allocator(),
            payload,
            2,
            4,
        ),
    );
    owns_payload = false;
    try std.testing.expect(!fail.has_induced_failure);
}

test "QUIC DATAGRAM receive queue reuses popped exact-size payload" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "first",
        1,
        2,
    ));
    var out: [8]u8 = undefined;
    try std.testing.expectEqualStrings(
        "first",
        (try queue.popInto(allocator, &out)).?,
    );

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        fail.allocator(),
        "again",
        2,
        2,
    ));
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expectEqualStrings(
        "again",
        (try queue.popInto(allocator, &out)).?,
    );
}

test "QUIC DATAGRAM receive queue safely replaces recycled size" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "old",
        1,
        1,
    ));
    var out: [8]u8 = undefined;
    try std.testing.expectEqualStrings(
        "old",
        (try queue.popInto(allocator, &out)).?,
    );
    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "longer",
        2,
        1,
    ));
    try std.testing.expectError(
        error.BufferTooSmall,
        queue.popInto(allocator, out[0..2]),
    );
    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "longer",
        3,
        1,
    ));
    try std.testing.expectEqualStrings(
        "longer",
        (try queue.popInto(allocator, &out)).?,
    );
}

test "QUIC DATAGRAM receive queue keeps drop-oldest accounting with recycle" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "one",
        1,
        1,
    ));
    try std.testing.expect(try queue.pushCopyDroppingOldest(
        allocator,
        "two",
        2,
        1,
    ));
    var out: [8]u8 = undefined;
    try std.testing.expectEqualStrings(
        "two",
        (try queue.popInto(allocator, &out)).?,
    );
}

fn pushOwned(
    queue: *Queue,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    packet_number: u64,
    capacity: usize,
) !void {
    const payload = try allocator.dupe(u8, bytes);
    errdefer allocator.free(payload);
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try queue.pushDroppingOldest(
            allocator,
            payload,
            packet_number,
            capacity,
        ),
    );
}

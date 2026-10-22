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

test "QUIC DATAGRAM receive queue bounds payload bytes and reuses eviction" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    var result = try queue.pushCopyWithinLimits(
        allocator,
        "aa",
        1,
        4,
        5,
    );
    try std.testing.expect(result.accepted);
    try std.testing.expectEqual(@as(usize, 0), result.dropped);
    result = try queue.pushCopyWithinLimits(
        allocator,
        "bb",
        2,
        4,
        5,
    );
    try std.testing.expect(result.accepted);
    try std.testing.expectEqual(@as(usize, 4), queue.payloadByteCount());

    // Four new bytes require both two-byte entries to leave the five-byte
    // budget. Count capacity alone would have retained all three payloads.
    result = try queue.pushCopyWithinLimits(
        allocator,
        "cccc",
        3,
        4,
        5,
    );
    try std.testing.expect(result.accepted);
    try std.testing.expectEqual(@as(usize, 2), result.dropped);
    try std.testing.expectEqual(@as(usize, 1), queue.count());
    try std.testing.expectEqual(@as(usize, 4), queue.payloadByteCount());

    // A payload that cannot fit by itself is dropped without evicting the
    // already-admitted FIFO contents.
    result = try queue.pushCopyWithinLimits(
        allocator,
        "123456",
        4,
        4,
        5,
    );
    try std.testing.expect(!result.accepted);
    try std.testing.expectEqual(@as(usize, 1), result.dropped);
    try std.testing.expectEqual(@as(usize, 4), queue.payloadByteCount());

    // The next equal-sized replacement reuses the evicted allocation after
    // every fallible metadata reservation has already completed.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    result = try queue.pushCopyWithinLimits(
        failing.allocator(),
        "dddd",
        5,
        4,
        5,
    );
    try std.testing.expect(result.accepted);
    try std.testing.expectEqual(@as(usize, 1), result.dropped);
    try std.testing.expect(!failing.has_induced_failure);
    const kept = queue.pop().?;
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("dddd", kept);
    try std.testing.expectEqual(@as(usize, 0), queue.payloadByteCount());
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
    try std.testing.expectEqual(@as(usize, 2), queue.payloadByteCount());
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

test "QUIC DATAGRAM byte-budget replacement is transactional on OOM" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    const admitted = try queue.pushCopyWithinLimits(
        allocator,
        "old",
        1,
        2,
        4,
    );
    try std.testing.expect(admitted.accepted);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        queue.pushCopyWithinLimits(
            failing.allocator(),
            "new!",
            2,
            2,
            4,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), queue.count());
    try std.testing.expectEqual(@as(usize, 3), queue.payloadByteCount());
    const retained = queue.pop().?;
    defer allocator.free(retained);
    try std.testing.expectEqualStrings("old", retained);
}

test "QUIC DATAGRAM receive queue OOM while reserving recycle metadata is safe" {
    var storage: [256]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    const allocator = fixed.allocator();
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    const payload = try allocator.dupe(u8, "owned");
    try std.testing.expectError(
        error.OutOfMemory,
        queue.pushDroppingOldest(
            allocator,
            payload,
            1,
            64,
        ),
    );
    allocator.free(payload);
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

test "QUIC DATAGRAM receive queue reuses a complete steady-state burst" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    const capacity = 4;

    for (0..capacity) |index| {
        try std.testing.expect(!try queue.pushCopyDroppingOldest(
            allocator,
            "burst",
            index,
            capacity,
        ));
    }
    var out: [8]u8 = undefined;
    for (0..capacity) |_| {
        try std.testing.expectEqualStrings(
            "burst",
            (try queue.popInto(allocator, &out)).?,
        );
    }

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    for (0..capacity) |index| {
        try std.testing.expect(!try queue.pushCopyDroppingOldest(
            fail.allocator(),
            "burst",
            capacity + index,
            capacity,
        ));
    }
    try std.testing.expect(!fail.has_induced_failure);
    for (0..capacity) |_| {
        try std.testing.expectEqualStrings(
            "burst",
            (try queue.popInto(allocator, &out)).?,
        );
    }
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

test "QUIC DATAGRAM receive queue overwrites full equal-size slot without allocation" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);

    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "one",
        1,
        2,
    ));
    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "two",
        2,
        2,
    ));
    const oldest_storage = queue.slots.items[queue.head].?.payload.ptr;

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expect(try queue.pushCopyDroppingOldest(
        fail.allocator(),
        "new",
        3,
        2,
    ));
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expectEqual(
        oldest_storage,
        queue.slots.items[0].?.payload.ptr,
    );
    try std.testing.expectEqual(@as(usize, 0), queue.recycled_payloads.items.len);

    var out: [8]u8 = undefined;
    try std.testing.expectEqualStrings(
        "two",
        (try queue.popInto(allocator, &out)).?,
    );
    try std.testing.expectEqualStrings(
        "new",
        (try queue.popInto(allocator, &out)).?,
    );
}

test "QUIC DATAGRAM receive queue bounds recycled and owned storage together" {
    const allocator = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(allocator);
    const capacity = 2;

    try std.testing.expect(!try queue.pushCopyDroppingOldest(
        allocator,
        "one",
        1,
        capacity,
    ));
    var out: [8]u8 = undefined;
    _ = try queue.popInto(allocator, &out);
    try std.testing.expectEqual(
        @as(usize, 1),
        queue.recycled_payloads.items.len,
    );
    try pushOwned(&queue, allocator, "two", 2, capacity);
    try pushOwned(&queue, allocator, "three", 3, capacity);
    try std.testing.expectEqual(
        @as(usize, 0),
        queue.recycled_payloads.items.len,
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

const std = @import("std");
const recovery_root = @import("../recovery.zig");

const payload_cache = @import("payload_cache.zig");
const quic = @import("../mod.zig");

const Candidate = recovery_root.Candidate;
const Queue = recovery_root.Queue;

test "QUIC recovery queue groups retransmissions and ACKs any copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(0, "stream frame bytes");
    const candidate = queue.ptoCandidate().?;
    try std.testing.expectEqual(@as(u64, 0), candidate.packet_number);
    try std.testing.expectEqualStrings("stream frame bytes", candidate.payload);

    try queue.recordRetransmission(candidate.group_index, 4);
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(@as(usize, 2), queue.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(u64, 0), queue.groupIdForPacketNumber(0).?);
    try std.testing.expectEqual(@as(u64, 0), queue.groupIdForPacketNumber(4).?);
    try std.testing.expect(queue.ackAcknowledgesGroup(0, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    }));
    try std.testing.expect(queue.ackAcknowledgesGroup(0, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    }));
    try std.testing.expect(!queue.ackAcknowledgesGroup(0, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    }));
    try std.testing.expect(!queue.ackAcknowledgesGroup(99, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    }));
    const stats = queue.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.pending_groups);
    try std.testing.expectEqual(@as(usize, 2), stats.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), stats.retransmission_copies);
    try std.testing.expectEqual("stream frame bytes".len, stats.payload_bytes);

    const ack = quic.AckFrame{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 0), queue.getStats().pending_groups);
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
    const empty_stats = queue.stats();
    try std.testing.expectEqual(@as(usize, 0), empty_stats.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 0), empty_stats.retransmission_copies);
    try std.testing.expectEqual(@as(usize, 0), empty_stats.payload_bytes);
    try std.testing.expectEqual(@as(?u64, null), queue.groupIdForPacketNumber(4));
    try std.testing.expect(queue.packetNumberCandidate(4) == null);
    try std.testing.expect(!queue.acknowledgePacketNumber(4));
    try std.testing.expect(!queue.forgetPacketNumber(4));
}

test "QUIC recovery queue keeps initial packet number allocation-free" {
    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = counting.allocator();
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try std.testing.expectError(
        error.EmptyPayload,
        queue.trackSent(41, ""),
    );
    try std.testing.expect(!counting.has_induced_failure);

    // Remove queue growth from the measurement. Tracking a new payload then
    // needs exactly one allocation for bytes that must survive caller reuse;
    // the overwhelmingly common original packet number stays inline.
    try queue.pending.ensureTotalCapacity(allocator, 1);
    const allocations_before = counting.allocations;
    _ = try queue.trackSent(42, "owned recovery payload");
    try std.testing.expectEqual(@as(usize, 1), counting.allocations - allocations_before);
    try std.testing.expectEqual(@as(?u64, 42), queue.pending.items[0].original_packet_number);
    try std.testing.expectEqual(@as(usize, 0), queue.pending.items[0].retransmission_packet_numbers.capacity);

    // Dynamic packet-number storage is deferred until a retransmission exists.
    try queue.recordRetransmission(0, 43);
    try std.testing.expectEqual(@as(usize, 2), queue.pending.items[0].packetCount());
    try std.testing.expect(queue.pending.items[0].retransmission_packet_numbers.capacity > 0);
}

test "QUIC recovery queue exposes stable uninitialized payload ownership" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const tracked = try queue.trackSentUninitialized(7, 8);
    @memcpy(tracked.payload, "direct!!");
    try std.testing.expectEqual(@as(u64, 0), tracked.group_id);
    try std.testing.expectEqualStrings(
        "direct!!",
        queue.packetNumberCandidate(7).?.payload,
    );
    // Candidate storage must alias the slice returned to the packet builder;
    // this is what removes the encode-then-copy pass on hot batch sends.
    try std.testing.expectEqual(
        tracked.payload.ptr,
        queue.packetNumberCandidate(7).?.payload.ptr,
    );
}

test "QUIC recovery queue identifies pending stream terminal frames" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .ping = {} }).write(&payload, allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 4,
        .offset = 9,
        .data = "done",
        .fin = true,
    } }).write(&payload, allocator);
    try (quic.Frame{ .reset_stream = .{
        .stream_id = 8,
        .application_error_code = 42,
        .final_size = 17,
    } }).write(&payload, allocator);
    try (quic.Frame{ .reset_stream_at = .{
        .stream_id = 12,
        .application_error_code = 43,
        .final_size = 19,
        .reliable_size = 11,
    } }).write(&payload, allocator);

    _ = try queue.trackSent(11, payload.items);
    try std.testing.expect(queue.hasPendingStreamData(4));
    try std.testing.expect(!queue.hasPendingStreamData(8));
    try std.testing.expect(queue.hasPendingResetStream(8));
    try std.testing.expect(queue.hasPendingResetStream(12));
    try std.testing.expect(!queue.hasPendingResetStream(4));
    try std.testing.expect(!queue.hasPendingStreamData(12));

    try std.testing.expect(queue.acknowledgePacketNumber(11));
    try std.testing.expect(!queue.hasPendingStreamData(4));
    try std.testing.expect(!queue.hasPendingResetStream(8));
    try std.testing.expect(!queue.hasPendingResetStream(12));
}

test "QUIC recovery abandons one stream without losing sibling frames" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var mixed: std.ArrayList(u8) = .empty;
    defer mixed.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 4,
        .data = "old",
    } }).write(&mixed, allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 8,
        .data = "keep",
        .fin = true,
    } }).write(&mixed, allocator);
    try (quic.Frame{ .ping = {} }).write(&mixed, allocator);
    _ = try queue.trackSent(7, mixed.items);

    try std.testing.expectEqual(@as(usize, 1), queue.abandonStreamData(4));
    try std.testing.expect(!queue.hasPendingStreamData(4));
    try std.testing.expect(queue.hasPendingStreamData(8));
    const candidate = queue.packetNumberCandidate(7) orelse
        return error.TestUnexpectedResult;
    const first = try quic.parseFrame(candidate.payload);
    try std.testing.expect(first.frame == .stream);
    try std.testing.expectEqual(@as(u64, 8), first.frame.stream.stream_id);
    const second = try quic.parseFrame(candidate.payload[first.consumed..]);
    try std.testing.expect(second.frame == .ping);
    try std.testing.expectEqual(
        candidate.payload.len,
        first.consumed + second.consumed,
    );

    try std.testing.expectEqual(@as(usize, 1), queue.abandonStreamData(8));
    try std.testing.expect(!queue.hasPendingStreamData(8));
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    const ping = try quic.parseFrame(queue.packetNumberCandidate(7).?.payload);
    try std.testing.expect(ping.frame == .ping);
}

test "QUIC recovery retains only frames needed by reliable reset prefix" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    for ([_]quic.Frame{
        .{ .stream = .{ .stream_id = 4, .offset = 0, .data = "abc" } },
        .{ .stream = .{ .stream_id = 4, .offset = 3, .data = "def" } },
        .{ .stream = .{ .stream_id = 4, .offset = 6, .data = "ghi" } },
        .{ .stream = .{ .stream_id = 8, .offset = 9, .data = "peer" } },
    }) |frame| try frame.write(&payload, allocator);
    _ = try queue.trackSent(13, payload.items);

    try std.testing.expectEqual(
        @as(usize, 1),
        queue.abandonStreamDataAfter(4, 5),
    );
    const kept = queue.packetNumberCandidate(13) orelse
        return error.TestUnexpectedResult;
    var remaining = kept.payload;
    const expected = [_]struct { stream_id: u64, offset: u64 }{
        .{ .stream_id = 4, .offset = 0 },
        // A frame crossing the boundary remains whole. Retransmitting the
        // suffix is permitted and avoids mutating tracked recovery payloads.
        .{ .stream_id = 4, .offset = 3 },
        .{ .stream_id = 8, .offset = 9 },
    };
    for (expected) |want| {
        const parsed = try quic.parseFrame(remaining);
        try std.testing.expect(parsed.frame == .stream);
        try std.testing.expectEqual(want.stream_id, parsed.frame.stream.stream_id);
        try std.testing.expectEqual(want.offset, parsed.frame.stream.offset);
        remaining = remaining[parsed.consumed..];
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.len);
}

test "QUIC recovery drops stale closed-stream controls only" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .max_stream_data = .{
        .stream_id = 4,
        .maximum_stream_data = 90,
    } }).write(&payload, allocator);
    try (quic.Frame{ .stop_sending = .{
        .stream_id = 4,
        .application_error_code = 7,
    } }).write(&payload, allocator);
    try (quic.Frame{ .stream_data_blocked = .{
        .stream_id = 8,
        .maximum_stream_data = 30,
    } }).write(&payload, allocator);
    _ = try queue.trackSent(9, payload.items);

    try std.testing.expectEqual(
        @as(usize, 2),
        queue.abandonClosedStreamFrames(4),
    );
    const kept = queue.packetNumberCandidate(9) orelse
        return error.TestUnexpectedResult;
    const parsed = try quic.parseFrame(kept.payload);
    try std.testing.expect(parsed.frame == .stream_data_blocked);
    try std.testing.expectEqual(@as(u64, 8), parsed.frame.stream_data_blocked.stream_id);
    try std.testing.expectEqual(kept.payload.len, parsed.consumed);
}

test "QUIC recovery delivery drain ignores pure receive credit" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var credit: std.ArrayList(u8) = .empty;
    defer credit.deinit(allocator);
    try (quic.Frame{ .max_data = .{ .maximum_data = 64 } })
        .write(&credit, allocator);
    try (quic.Frame{ .max_streams_bidi = .{ .maximum_streams = 2 } })
        .write(&credit, allocator);
    _ = try queue.trackSent(0, credit.items);
    try std.testing.expect(!queue.hasPendingDeliveryFrames());

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 0,
        .data = "response",
        .fin = true,
    } }).write(&response, allocator);
    _ = try queue.trackSent(1, response.items);
    try std.testing.expect(queue.hasPendingDeliveryFrames());
    try std.testing.expect(queue.acknowledgePacketNumber(1));
    try std.testing.expect(!queue.hasPendingDeliveryFrames());
}

test "QUIC recovery uninitialized tracking rejects empty payload transactionally" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try std.testing.expectError(
        error.EmptyPayload,
        queue.trackSentUninitialized(7, 0),
    );
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
}

test "QUIC recovery duplicate check allows rolled-back packet retry" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(7, "first");
    try std.testing.expectError(
        error.InvalidRetransmission,
        queue.trackSent(7, "duplicate"),
    );
    try std.testing.expect(queue.forgetPacketNumber(7));
    _ = try queue.trackSent(7, "retry");
    try std.testing.expectEqualStrings(
        "retry",
        queue.packetNumberCandidate(7).?.payload,
    );
    _ = try queue.trackSent(8, "next");
    try std.testing.expectEqualStrings(
        "next",
        queue.packetNumberCandidate(8).?.payload,
    );
}

test "QUIC recovery queue reuses payload buckets after ACK" {
    var counting = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = counting.allocator();
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try queue.pending.ensureTotalCapacity(allocator, 1);
    _ = try queue.trackSent(1, "eight!!!");
    const allocations_after_first = counting.allocations;
    try std.testing.expect(queue.acknowledgePacketNumber(1));
    try std.testing.expectEqual(
        @as(usize, 1),
        queue.payload_cache.stats().blocks,
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        queue.payload_cache.stats().bytes,
    );

    // Seven bytes reuse the cached eight-byte bucket, but only the logical
    // prefix may become a retransmission candidate.
    _ = try queue.trackSent(2, "second!");
    try std.testing.expectEqual(allocations_after_first, counting.allocations);
    try std.testing.expectEqualStrings(
        "second!",
        queue.ptoCandidate().?.payload,
    );
    const stats = queue.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.payload_cache_hits);
    try std.testing.expectEqual(@as(u64, 1), stats.payload_cache_misses);
}

test "QUIC recovery payload cache uses overflow and stays byte bounded" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const small_blocks = payload_cache.Cache.inline_depth + 2;
    for (0..small_blocks) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "payload");
    }
    for (0..small_blocks) |packet_number| {
        try std.testing.expect(
            queue.acknowledgePacketNumber(@intCast(packet_number)),
        );
    }
    const stats = queue.stats();
    try std.testing.expectEqual(
        small_blocks,
        stats.cached_payload_blocks,
    );
    try std.testing.expectEqual(
        small_blocks * 8,
        stats.cached_payload_bytes,
    );
    try std.testing.expect(
        stats.cached_payload_bytes <= payload_cache.Cache.max_cached_bytes,
    );
}

test "QUIC recovery queue keeps stable group identity across retransmissions" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const group_id = try queue.trackSent(4, "control");
    try std.testing.expectEqual(
        group_id,
        queue.groupIdForPacketNumber(4).?,
    );
    try std.testing.expect(queue.containsGroupId(group_id));

    try queue.recordRetransmission(0, 8);
    try std.testing.expectEqual(
        group_id,
        queue.groupIdForPacketNumber(8).?,
    );
    try std.testing.expectEqual(@as(u64, 8), queue.pending.items[0].newestPacketNumber());
    try std.testing.expectEqual(group_id, queue.groupIdForPacketNumber(4).?);
    try std.testing.expectEqual(group_id, queue.groupIdForPacketNumber(8).?);
    try std.testing.expect(queue.forgetPacketNumber(8));
    try std.testing.expectEqual(@as(u64, 4), queue.pending.items[0].newestPacketNumber());
    try queue.recordRetransmission(0, 8);
    try std.testing.expect(queue.acknowledgePacketNumber(8));
    try std.testing.expect(!queue.containsGroupId(group_id));
    try std.testing.expect(queue.groupIdForPacketNumber(4) == null);
    try std.testing.expect(queue.groupIdForPacketNumber(8) == null);
}

test "QUIC recovery queue forgets middle retransmission without losing newest" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "payload");
    try queue.recordRetransmission(0, 2);
    try queue.recordRetransmission(0, 3);
    try queue.recordRetransmission(0, 4);

    try std.testing.expect(queue.forgetPacketNumber(2));
    try std.testing.expectEqual(@as(u64, 4), queue.pending.items[0].newestPacketNumber());
    try std.testing.expectEqual(@as(usize, 3), queue.pending.items[0].packetCount());
    try std.testing.expect(queue.packetNumberCandidate(1) != null);
    try std.testing.expect(queue.packetNumberCandidate(2) == null);
    try std.testing.expect(queue.packetNumberCandidate(3) != null);
    try std.testing.expect(queue.packetNumberCandidate(4) != null);
}

test "QUIC recovery lookups survive ordered removals and ACK compaction" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const first = try queue.trackSent(10, "first");
    const second = try queue.trackSent(20, "second");
    const third = try queue.trackSent(30, "third");
    try queue.recordRetransmission(2, 31);
    // ACKing the first group uses orderedRemove to preserve PTO scheduling
    // order. Later packet-number and group lookups must survive the shift.
    try std.testing.expect(queue.acknowledgePacketNumber(10));
    try std.testing.expect(!queue.containsGroupId(first));
    try std.testing.expect(queue.containsGroupId(second));
    try std.testing.expect(queue.containsGroupId(third));
    try std.testing.expect(queue.packetNumberCandidate(20) != null);
    try std.testing.expect(queue.packetNumberCandidate(30) != null);
    try std.testing.expect(queue.packetNumberCandidate(31) != null);
    try std.testing.expectEqual(third, queue.groupIdForPacketNumber(31).?);
    const after_first_ack = queue.stats();
    try std.testing.expectEqual(@as(usize, 3), after_first_ack.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), after_first_ack.retransmission_copies);
    try std.testing.expectEqual("second".len + "third".len, after_first_ack.payload_bytes);

    try std.testing.expect(queue.forgetPacketNumber(30));
    try std.testing.expect(queue.packetNumberCandidate(30) == null);
    try std.testing.expect(queue.packetNumberCandidate(31) != null);
    try std.testing.expectEqual(@as(usize, 1), queue.pending.items[1].packetCount());
    const after_forget_original = queue.stats();
    try std.testing.expectEqual(@as(usize, 2), after_forget_original.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), after_forget_original.retransmission_copies);
    try std.testing.expectEqual("second".len + "third".len, after_forget_original.payload_bytes);

    const ack = quic.AckFrame{
        .largest_acknowledged = 31,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expect(!queue.containsGroupId(third));
    try std.testing.expect(queue.packetNumberCandidate(31) == null);
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expect(queue.containsGroupId(second));
    try std.testing.expect(queue.packetNumberCandidate(20) != null);
    const after_ack_compaction = queue.stats();
    try std.testing.expectEqual(@as(usize, 1), after_ack_compaction.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 0), after_ack_compaction.retransmission_copies);
    try std.testing.expectEqual("second".len, after_ack_compaction.payload_bytes);
}

test "QUIC recovery queue selects PTO candidates by pending group" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(0, "zero");
    _ = try queue.trackSent(1, "one");

    const first = queue.ptoCandidateAt(0).?;
    try std.testing.expectEqual(@as(usize, 0), first.group_index);
    try std.testing.expectEqualStrings("zero", first.payload);

    const second = queue.ptoCandidateAt(1).?;
    try std.testing.expectEqual(@as(usize, 1), second.group_index);
    try std.testing.expectEqualStrings("one", second.payload);
    try std.testing.expect(queue.ptoCandidateAt(2) == null);
}

test "QUIC recovery queue applies ACK ranges" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "one");
    _ = try queue.trackSent(5, "five");
    _ = try queue.trackSent(9, "nine");

    const ranges = [_]quic.AckRange{
        .{ .gap = 2, .ack_range_length = 0 }, // acknowledges packet 5 after largest 9.
    };
    const ack = quic.AckFrame{
        .largest_acknowledged = 9,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };
    try std.testing.expectEqual(@as(usize, 2), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(@as(u64, 1), queue.pending.items[0].newestPacketNumber());
}

test "QUIC recovery queue applies one contiguous ACK range" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..8) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number * 2), "payload");
    }

    try std.testing.expectEqual(
        @as(usize, 3),
        try queue.applyAck(.{
            .largest_acknowledged = 9,
            .ack_delay = 0,
            .first_ack_range = 5,
        }),
    );
    try std.testing.expectEqual(@as(usize, 5), queue.pendingCount());
    const expected = [_]u64{ 0, 2, 10, 12, 14 };
    for (queue.pending.items, expected) |entry, packet_number| {
        try std.testing.expectEqual(
            packet_number,
            entry.original_packet_number.?,
        );
    }
    try std.testing.expectEqual(@as(usize, 5), queue.stats().packet_number_copies);
    try std.testing.expectEqual(5 * "payload".len, queue.stats().payload_bytes);

    try std.testing.expectEqual(
        @as(usize, 0),
        try queue.applyAck(.{
            .largest_acknowledged = 99,
            .ack_delay = 0,
            .first_ack_range = 2,
        }),
    );
    try std.testing.expectEqual(@as(usize, 5), queue.pendingCount());
}

test "QUIC recovery single-range ACK falls back for out-of-order originals" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(10, "ten");
    _ = try queue.trackSent(2, "two");
    _ = try queue.trackSent(6, "six");

    try std.testing.expectEqual(
        @as(usize, 2),
        try queue.applyAck(.{
            .largest_acknowledged = 8,
            .ack_delay = 0,
            .first_ack_range = 6,
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(
        @as(u64, 10),
        queue.pending.items[0].original_packet_number.?,
    );
}

test "QUIC recovery single-range ACK falls back after original is forgotten" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "payload");
    try queue.recordRetransmission(0, 4);
    try std.testing.expect(queue.forgetPacketNumber(1));
    try std.testing.expectEqual(
        @as(usize, 1),
        try queue.applyAck(.{
            .largest_acknowledged = 4,
            .ack_delay = 0,
            .first_ack_range = 0,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
}

test "QUIC recovery queue compacts ACKed ranges without reordering survivors" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (1..6) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "payload");
    }

    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 }, // acknowledges packet 2 after 4.
    };
    const ack = quic.AckFrame{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    try std.testing.expectEqual(@as(usize, 2), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 3), queue.pendingCount());
    try std.testing.expectEqual(@as(u64, 1), queue.pending.items[0].newestPacketNumber());
    try std.testing.expectEqual(@as(u64, 3), queue.pending.items[1].newestPacketNumber());
    try std.testing.expectEqual(@as(u64, 5), queue.pending.items[2].newestPacketNumber());
}

test "QUIC recovery queue applies large ACK range sets in one pass" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..81) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "x");
    }

    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    } ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    try std.testing.expectEqual(@as(usize, 41), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 40), queue.pendingCount());
    for (queue.pending.items, 0..) |entry, index| {
        try std.testing.expectEqual(
            @as(u64, @intCast(index * 2 + 1)),
            entry.newestPacketNumber(),
        );
    }
}

test "QUIC recovery sorted range merge matches conservative membership scan" {
    const allocator = std.testing.allocator;
    var merged = Queue.init(allocator);
    defer merged.deinit();
    var scanned = Queue.init(allocator);
    defer scanned.deinit();

    for (0..101) |packet_number| {
        _ = try merged.trackSent(@intCast(packet_number), "payload");
        _ = try scanned.trackSent(@intCast(packet_number), "payload");
    }
    // Force only the comparison queue through the general implementation.
    scanned.originals_sorted_ascending = false;
    const ranges = [_]quic.AckRange{
        .{ .gap = 2, .ack_range_length = 4 }, // 77..81
        .{ .gap = 0, .ack_range_length = 3 }, // 72..75
        .{ .gap = 5, .ack_range_length = 7 }, // 58..65
    };
    const ack = quic.AckFrame{
        .largest_acknowledged = 90,
        .ack_delay = 0,
        .first_ack_range = 5, // 85..90
        .ranges = &ranges,
    };

    try std.testing.expectEqual(
        try scanned.applyAck(ack),
        try merged.applyAck(ack),
    );
    try std.testing.expectEqual(scanned.pendingCount(), merged.pendingCount());
    try std.testing.expectEqual(scanned.stats().payload_bytes, merged.stats().payload_bytes);
    for (scanned.pending.items, merged.pending.items) |expected, actual| {
        try std.testing.expectEqual(
            expected.original_packet_number,
            actual.original_packet_number,
        );
    }
}

test "QUIC recovery sorted range merge matches generated ACK patterns" {
    const allocator = std.testing.allocator;
    const packet_count = 101;

    for (0..64) |seed| {
        var merged = Queue.init(allocator);
        defer merged.deinit();
        var scanned = Queue.init(allocator);
        defer scanned.deinit();
        var received = quic.packet_space.ReceivedPacketTracker.init(
            allocator,
            packet_count,
        );
        defer received.deinit();

        for (0..packet_count) |packet_number| {
            const pn: u64 = @intCast(packet_number);
            _ = try merged.trackSent(pn, "payload");
            _ = try scanned.trackSent(pn, "payload");
            const selector = (packet_number * 37 + seed * 17) % 11;
            if (packet_number == packet_count - 1 or
                selector < seed % 7 + 1)
            {
                try received.record(pn);
            }
        }

        var range_storage: [packet_count]quic.AckRange = undefined;
        const ack = try received.ackFrameInto(&range_storage, 0);
        scanned.originals_sorted_ascending = false;
        try std.testing.expectEqual(
            try scanned.applyAck(ack),
            try merged.applyAck(ack),
        );
        try std.testing.expectEqual(
            scanned.pendingCount(),
            merged.pendingCount(),
        );
        try std.testing.expectEqual(scanned.stats(), merged.stats());
        for (scanned.pending.items, merged.pending.items) |expected, actual| {
            try std.testing.expectEqual(
                expected.original_packet_number,
                actual.original_packet_number,
            );
        }
    }
}

test "QUIC recovery multi-range ACK falls back for retransmission copies" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "one");
    _ = try queue.trackSent(3, "three");
    _ = try queue.trackSent(5, "five");
    try queue.recordRetransmission(1, 8);
    const ranges = [_]quic.AckRange{.{
        .gap = 2,
        .ack_range_length = 0,
    }};
    const ack = quic.AckFrame{
        .largest_acknowledged = 8,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    // Packet 8 acknowledges the retransmitted group originally sent as 3;
    // the lower range independently acknowledges packet 4, which is absent.
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 2), queue.pendingCount());
    try std.testing.expect(queue.packetNumberCandidate(3) == null);
    try std.testing.expect(queue.packetNumberCandidate(8) == null);
    try std.testing.expect(queue.packetNumberCandidate(1) != null);
    try std.testing.expect(queue.packetNumberCandidate(5) != null);
    try std.testing.expectEqual(@as(usize, 0), queue.stats().retransmission_copies);
}

test "QUIC recovery applies large ACK range sets without allocation" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = failing.allocator();
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..81) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "x");
    }
    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    } ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    // Payload recycling and index rebuilding retain their existing capacity.
    // Once tracking is complete, even an ACK with more than the historical
    // 32-range stack threshold must not consult the allocator.
    failing.fail_index = failing.alloc_index;
    try std.testing.expectEqual(@as(usize, 41), try queue.applyAck(ack));
    try std.testing.expect(!failing.has_induced_failure);
}

test "QUIC recovery rejects invalid large ACK transactionally" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();
    _ = try queue.trackSent(1, "one");
    _ = try queue.trackSent(5, "five");

    const invalid = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &.{.{
            .gap = std.math.maxInt(u64),
            .ack_range_length = 0,
        }},
    };
    try std.testing.expectError(error.InvalidAckFrame, queue.applyAck(invalid));
    try std.testing.expectEqual(@as(usize, 2), queue.pendingCount());
    try std.testing.expect(queue.packetNumberCandidate(1) != null);
    try std.testing.expect(queue.packetNumberCandidate(5) != null);
}

test "QUIC recovery queue schedules packet-threshold loss once per newest copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(0, "zero");
    _ = try queue.trackSent(2, "two");
    _ = try queue.trackSent(6, "six");

    const candidate = queue.packetThresholdCandidate(4, quic.packet_space.default_packet_threshold).?;
    try std.testing.expectEqual(@as(usize, 0), candidate.group_index);
    try std.testing.expectEqual(@as(u64, 0), candidate.packet_number);
    try std.testing.expectEqualStrings("zero", candidate.payload);

    try queue.recordRetransmission(candidate.group_index, 7);
    try std.testing.expect(queue.packetThresholdCandidate(4, quic.packet_space.default_packet_threshold) == null);
    try std.testing.expectEqualStrings(
        "zero",
        queue.pending.items[0].payload(),
    );

    const ack = quic.AckFrame{
        .largest_acknowledged = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 2), queue.pendingCount());
}

test "QUIC recovery queue locates candidate by any packet number copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "payload");
    try queue.recordRetransmission(0, 5);

    const original = queue.packetNumberCandidate(1).?;
    try std.testing.expectEqual(@as(usize, 0), original.group_index);
    try std.testing.expectEqual(@as(u64, 5), original.packet_number);
    try std.testing.expectEqualStrings("payload", original.payload);

    const newest = queue.packetNumberCandidate(5).?;
    try std.testing.expectEqual(@as(usize, 0), newest.group_index);
    try std.testing.expect(queue.packetNumberCandidate(99) == null);
}

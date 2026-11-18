const std = @import("std");
const packet_space_root = @import("../packet_space.zig");

const quic = @import("../mod.zig");

const ReceivedPacketTracker = packet_space_root.ReceivedPacketTracker;
const SentPacket = packet_space_root.SentPacket;
const SentPacketTracker = packet_space_root.SentPacketTracker;
const default_packet_threshold = packet_space_root.default_packet_threshold;

test "QUIC sent packet metadata stays compact" {
    // Work/quic-zig's historic ACK tracker stored per-stream frame arrays
    // inline, making each sent-packet record cache-unfriendly.  netz stores
    // stable recovery payloads separately; keep this metadata object small so
    // packet-number scans remain L1-cache friendly.
    try std.testing.expect(@sizeOf(SentPacket) <= 128);
}

test "QUIC packet space generates ACK ranges" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    for ([_]u64{ 1, 2, 3, 7, 8, 10 }) |pn| {
        try std.testing.expect(try received.recordFresh(pn));
    }
    try std.testing.expectEqual(@as(u64, 6), received.retained_packet_count);
    const ack = try received.ackFrame(allocator, 0);
    defer allocator.free(ack.ranges);

    try std.testing.expectEqual(@as(u64, 10), ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[0].gap); // missing packet 9
    try std.testing.expectEqual(@as(u64, 1), ack.ranges[0].ack_range_length); // 7..8
    try std.testing.expectEqual(@as(u64, 2), ack.ranges[1].gap); // missing 4..6
    try std.testing.expectEqual(@as(u64, 2), ack.ranges[1].ack_range_length); // 1..3
}

test "QUIC packet space tracks retained packet count incrementally" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    for ([_]u64{ 1, 2, 3, 7, 8, 10 }) |pn| {
        try std.testing.expect(try received.recordFresh(pn));
    }
    try std.testing.expectEqual(@as(u64, 6), received.stats().retained_packets);

    received.pruneAckedRanges(2);
    try std.testing.expectEqual(@as(u64, 4), received.retained_packet_count);
    try std.testing.expectEqual(@as(u64, 4), received.stats().retained_packets);
    try std.testing.expectEqual(@as(u64, 3), received.ranges.items[2].start);

    received.pruneAckedRanges(8);
    try std.testing.expectEqual(@as(u64, 1), received.retained_packet_count);
    try std.testing.expectEqual(@as(usize, 1), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[0].start);
}

test "QUIC packet space skips prune scan before oldest range" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(try received.recordFresh(20));
    received.pruneAckedRanges(5);
    try std.testing.expectEqual(@as(?u64, 5), received.forgotten_through);
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 2), received.retained_packet_count);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[1].start);
}

test "QUIC packet space skips Not-ECT receive ECN counters" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    try std.testing.expect(try received.recordWithEcn(1, .not_ect));
    try std.testing.expect(received.latestEcnCounts() == null);
    try std.testing.expect(!received.saw_ecn);

    try std.testing.expect(try received.recordWithEcn(2, .ect0));
    try std.testing.expectEqual(@as(u64, 1), received.latestEcnCounts().?.ect0_count);
}

test "QUIC packet space records first ACK range without scanning" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 1);
    defer received.deinit();

    try std.testing.expect(try received.wouldRecordFresh(42));
    try std.testing.expect(try received.recordFresh(42));
    try std.testing.expectEqual(@as(usize, 1), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 42), received.largestReceived().?);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const ack = try received.ackFrame(no_alloc.allocator(), 7);
    try std.testing.expectEqual(@as(u64, 42), ack.largest_acknowledged);
    try std.testing.expectEqual(@as(usize, 0), ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 7), ack.ack_delay);

    var disabled = ReceivedPacketTracker.init(allocator, 0);
    defer disabled.deinit();
    try std.testing.expect(!(try disabled.wouldRecordFresh(42)));
    try std.testing.expect(!(try disabled.recordFresh(42)));
}

test "QUIC packet space extends newest ACK range before scanning" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 4);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(try received.recordFresh(5));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);

    try std.testing.expect(try received.wouldRecordFresh(11));
    try std.testing.expect(try received.recordFresh(11));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[0].start);
    try std.testing.expectEqual(@as(u64, 11), received.ranges.items[0].end);
    try std.testing.expect(!(try received.wouldRecordFresh(11)));
    try std.testing.expect(!(try received.recordFresh(10)));
    try std.testing.expectEqual(@as(u64, 3), received.retained_packet_count);

    try std.testing.expect(try received.recordFresh(13));
    try std.testing.expectEqual(@as(usize, 3), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 13), received.ranges.items[0].start);
    try std.testing.expectEqual(@as(u64, 13), received.ranges.items[0].end);
}

test "QUIC packet space commits prevalidated ordered packets with ECN" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 4);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(try received.recordPrevalidatedWithEcn(11, .ect0));
    try std.testing.expect(try received.recordPrevalidatedWithEcn(13, .ce));
    try std.testing.expect(try received.recordPrevalidatedWithEcn(12, .ect1));

    try std.testing.expectEqual(@as(usize, 1), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[0].start);
    try std.testing.expectEqual(@as(u64, 13), received.ranges.items[0].end);
    try std.testing.expectEqual(@as(u64, 4), received.retained_packet_count);
    try std.testing.expectEqual(
        quic.EcnCounts{
            .ect0_count = 1,
            .ect1_count = 1,
            .ecn_ce_count = 1,
        },
        received.latestEcnCounts().?,
    );
    try std.testing.expect(!(try received.recordPrevalidatedWithEcn(
        12,
        .ect0,
    )));
}

test "QUIC packet space rejects oldest ACK range duplicates before scanning" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 4);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(20));
    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(try received.recordFresh(11));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(u64, 11), received.ranges.items[1].end);

    try std.testing.expect(!(try received.wouldRecordFresh(10)));
    try std.testing.expect(!(try received.wouldRecordFresh(11)));
    try std.testing.expect(!(try received.recordFresh(10)));
    try std.testing.expect(!(try received.recordFresh(11)));
    try std.testing.expectEqual(@as(u64, 3), received.retained_packet_count);

    try std.testing.expect(try received.recordFresh(9));
    try std.testing.expectEqual(@as(u64, 9), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(u64, 11), received.ranges.items[1].end);
}

test "QUIC packet space builds ACK ranges into caller storage" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    for ([_]u64{ 1, 3, 5, 6 }) |pn| {
        try std.testing.expect(try received.recordFresh(pn));
    }

    var ranges: [2]quic.AckRange = undefined;
    const ack = try received.ackFrameInto(&ranges, 7);
    try std.testing.expectEqual(@as(u64, 6), ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 7), ack.ack_delay);
    try std.testing.expectEqual(@as(u64, 1), ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), ack.ranges.len);
    try std.testing.expectEqual(@intFromPtr(ranges[0..].ptr), @intFromPtr(ack.ranges.ptr));
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[0].ack_range_length);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[1].gap);
    try std.testing.expectEqual(@as(u64, 0), ack.ranges[1].ack_range_length);

    var too_small: [1]quic.AckRange = undefined;
    try std.testing.expectError(error.TooManyAckRanges, received.ackFrameInto(&too_small, 0));
}

test "QUIC packet space drops duplicate and too-old packet numbers" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 2);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(!(try received.wouldRecordFresh(10)));
    try std.testing.expect(!(try received.recordFresh(10)));
    try std.testing.expect(try received.wouldRecordFresh(6));
    try std.testing.expect(try received.recordFresh(6));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);

    // A packet below the retained window is ignored instead of growing the ACK
    // range list without bound.
    try std.testing.expect(!(try received.wouldRecordFresh(2)));
    try std.testing.expect(!(try received.recordFresh(2)));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(?u64, 2), received.forgotten_through);

    // A newer out-of-order range evicts the oldest retained range, matching the
    // bounded ACK history used by quicz/tquic style implementations.
    try std.testing.expect(try received.wouldRecordFresh(8));
    try std.testing.expect(try received.recordFresh(8));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[0].start);
    try std.testing.expectEqual(@as(u64, 8), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(?u64, 6), received.forgotten_through);
    const stats = received.stats();
    try std.testing.expectEqual(@as(usize, 2), stats.ack_ranges);
    try std.testing.expectEqual(@as(u64, 2), stats.retained_packets);
    try std.testing.expectEqual(@as(?u64, 10), stats.largest_received);
    try std.testing.expectEqual(@as(?u64, 8), stats.oldest_retained);
    try std.testing.expectEqual(@as(?u64, 6), stats.forgotten_through);

    try std.testing.expect(!(try received.recordFresh(6)));
    try std.testing.expect(try received.recordFresh(7));
    try std.testing.expectEqual(@as(u64, 7), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(u64, 8), received.ranges.items[1].end);
}

test "QUIC packet space fast-rejects below oldest retained range" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 2);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(try received.recordFresh(20));
    try std.testing.expect(!(try received.wouldRecordFresh(8)));
    try std.testing.expect(!(try received.recordFresh(8)));
    try std.testing.expectEqual(@as(?u64, 8), received.forgotten_through);

    try std.testing.expect(try received.wouldRecordFresh(9));
    try std.testing.expect(try received.recordFresh(9));
    try std.testing.expectEqual(@as(u64, 9), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[1].end);
}

test "QUIC sent packet tracker preserves exact lookup behavior" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 100, .not_ect, 1_000);
    try sent.sentAt(1, true, 200, .not_ect, 2_000);
    try sent.sentAt(2, true, 300, .not_ect, 3_000);
    try std.testing.expectEqual(@as(usize, 0), sent.packet_index.count());
    try std.testing.expect(sent.packetsSortedAscending());
    try std.testing.expectError(
        error.DuplicatePacket,
        sent.sent(1, true, 100),
    );

    try std.testing.expect(sent.markAcknowledged(2));
    try std.testing.expect(sent.packets.items[2].acknowledged);
    try std.testing.expect(sent.forget(1));
    try std.testing.expectEqual(@as(usize, 2), sent.packets.items.len);
    try std.testing.expectEqual(@as(u64, 2), sent.packets.items[1].packet_number);
    try std.testing.expect(sent.packets.items[1].acknowledged);

    const ack = quic.AckFrame{
        .largest_acknowledged = 2,
        .ack_delay = 1,
        .first_ack_range = 0,
    };
    // The largest packet is already acknowledged above, so exact lookup still
    // finds it and correctly suppresses a duplicate RTT sample.
    try std.testing.expectEqual(
        @as(?SentPacketTracker.RttSample, null),
        try sent.ackRttSample(ack, 4_000, 3),
    );
}

test "QUIC sent packet tracker indexes only unordered packet history" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sent(10, true, 100);
    try sent.sent(12, true, 100);
    try std.testing.expectEqual(@as(usize, 0), sent.packet_index.count());

    try sent.sent(11, true, 100);
    try std.testing.expect(!sent.packetsSortedAscending());
    try std.testing.expect(sent.packet_index.get(11) != null);
    // The duplicate is above the unordered tail but already exists earlier.
    try std.testing.expectError(error.DuplicatePacket, sent.sent(12, true, 100));
    try sent.sent(13, true, 100);
    try std.testing.expect(sent.packet_index.get(13) != null);
    try std.testing.expect(sent.markAcknowledged(10));
    try std.testing.expect(sent.markAcknowledged(13));
}

test "QUIC sent packet coverage endpoint fast path preserves gap validation" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sent(10, true, 100);
    try sent.sent(11, true, 100);
    try sent.sent(12, true, 100);
    try std.testing.expect(sent.sentCoverageMatchesRange(10, 12));
    try std.testing.expect(sent.sentCoverageMatchesRange(11, 11));
    try std.testing.expect(!sent.sentCoverageMatchesRange(9, 12));
    try std.testing.expect(!sent.sentCoverageMatchesRange(10, 13));

    var gapped = SentPacketTracker.init(allocator);
    defer gapped.deinit();
    try gapped.sent(10, true, 100);
    try gapped.sent(12, true, 100);
    try std.testing.expect(!gapped.sentCoverageMatchesRange(10, 12));
}

test "QUIC sent packet tracker forgets pre-reserved tail" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.packets.ensureTotalCapacity(allocator, 2);
    try sent.sentAt(10, true, 100, .not_ect, 1_000);
    try sent.sentAt(11, true, 100, .not_ect, 2_000);
    try std.testing.expectEqual(@as(?usize, 1), sent.latest_ack_eliciting_in_flight_index);

    // Batch send paths pre-reserve packet metadata. Tail rollback should still
    // be a direct pop, not a binary/linear lookup followed by the same pop.
    try std.testing.expect(sent.forget(11));
    try std.testing.expectEqual(@as(usize, 1), sent.packets.items.len);
    try std.testing.expectEqual(@as(u64, 10), sent.packets.items[0].packet_number);
    try std.testing.expectEqual(@as(?usize, 0), sent.latest_ack_eliciting_in_flight_index);

    try std.testing.expect(sent.forget(10));
    try std.testing.expectEqual(@as(usize, 0), sent.packets.items.len);
    try std.testing.expectEqual(@as(?usize, null), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expect(!sent.forget(10));
}

test "QUIC sent packet tracker forget rolls back sent ECT counters" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(10, true, 100, .ect0, 1_000);
    try sent.sentAt(11, true, 100, .ect1, 2_000);
    try std.testing.expectEqual(@as(u64, 1), sent.stats().sent_ect0_count);
    try std.testing.expectEqual(@as(u64, 1), sent.stats().sent_ect1_count);

    try std.testing.expect(sent.forget(11));
    try std.testing.expectEqual(@as(u64, 1), sent.stats().sent_ect0_count);
    try std.testing.expectEqual(@as(u64, 0), sent.stats().sent_ect1_count);

    try std.testing.expect(sent.forget(10));
    try std.testing.expectEqual(@as(u64, 0), sent.stats().sent_ect0_count);
    try std.testing.expectEqual(@as(u64, 0), sent.stats().sent_ect1_count);
}

test "QUIC sent packet tracker exposes ACKed ECT beyond counter watermark" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentWithEcn(0, true, 1200, .ect0);
    _ = try sent.applyAckDetailed(.{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    try std.testing.expect(sent.hasAcknowledgedEctBeyondEcnWatermark());

    try sent.sentWithEcn(1, true, 1200, .ect0);
    _ = try sent.applyAckDetailed(.{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{
            .ect0_count = 2,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    });
    try std.testing.expect(!sent.hasAcknowledgedEctBeyondEcnWatermark());
}

test "QUIC sent packet tracker retains ACKed ECT watermark after metadata compaction" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    const count = SentPacketTracker.compact_acknowledged_threshold;
    for (0..count) |packet_number| {
        try sent.sentWithEcn(packet_number, true, 1200, .ect0);
    }
    const plain_ack = quic.AckFrame{
        .largest_acknowledged = count - 1,
        .ack_delay = 0,
        .first_ack_range = count - 1,
    };
    _ = try sent.applyAckDetailed(plain_ack);
    try std.testing.expectEqual(@as(usize, 0), sent.packets.items.len);
    try std.testing.expectEqual(
        @as(?u64, count - 1),
        sent.largest_acknowledged_ect,
    );
    try std.testing.expect(sent.hasAcknowledgedEctBeyondEcnWatermark());

    var baseline_ack = plain_ack;
    baseline_ack.ecn_counts = .{
        .ect0_count = count,
        .ect1_count = 0,
        .ecn_ce_count = 0,
    };
    _ = try sent.applyAckDetailed(baseline_ack);
    try std.testing.expect(!sent.hasAcknowledgedEctBeyondEcnWatermark());
}

test "QUIC sent packet tracker finds newest packet after pre-reservation" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.packets.ensureTotalCapacity(allocator, 2);
    try sent.sentAt(20, true, 100, .not_ect, 1_000);
    try sent.sentAt(21, true, 100, .not_ect, 2_000);
    // ACK processing often targets the newest packet in a packet-number
    // space. Keep that exact lookup as a direct tail check.
    try std.testing.expect(sent.markAcknowledged(21));
    try std.testing.expect(sent.packets.items[1].acknowledged);
    try std.testing.expectEqual(@as(?u64, 21), sent.largestAcknowledged());
    try std.testing.expectEqual(@as(?usize, 0), sent.latest_ack_eliciting_in_flight_index);
}

test "QUIC sent packet tracker rejects ACKs before sent metadata" {
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var sent = SentPacketTracker.init(no_alloc.allocator());
    defer sent.deinit();

    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    } ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };
    try std.testing.expectError(error.InvalidAckFrame, sent.applyAckDetailed(ack));
    try std.testing.expectError(error.InvalidAckFrame, sent.validateAckCoversSentPackets(ack));
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "QUIC sent packet tracker validates large ACK sets without allocation" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = failing.allocator();
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    for (0..81) |packet_number| {
        try sent.sent(@intCast(packet_number), true, 1200);
    }
    const ranges = [_]quic.AckRange{.{
        .gap = 0,
        .ack_range_length = 0,
    }} ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    failing.fail_index = failing.alloc_index;
    try sent.validateAckCoversSentPackets(ack);
    try std.testing.expect(!failing.has_induced_failure);
}

test "QUIC sent packet tracker streaming validation rejects generated holes" {
    const allocator = std.testing.allocator;
    const packet_count = 101;

    for (0..64) |seed| {
        var sent = SentPacketTracker.init(allocator);
        defer sent.deinit();
        var received = ReceivedPacketTracker.init(allocator, packet_count);
        defer received.deinit();

        for (0..packet_count) |packet_number| {
            const pn: u64 = @intCast(packet_number);
            try sent.sent(pn, true, 1200);
            const selector = (packet_number * 37 + seed * 17) % 11;
            if (packet_number == packet_count - 1 or
                selector < seed % 7 + 1)
            {
                try received.record(pn);
            }
        }

        var range_storage: [packet_count]quic.AckRange = undefined;
        const ack = try received.ackFrameInto(&range_storage, 0);
        try sent.validateAckCoversSentPackets(ack);

        // The largest packet is always present in the generated ACK. Removing
        // it leaves metadata sorted but must make validation fail.
        try std.testing.expect(sent.forget(packet_count - 1));
        try std.testing.expectError(
            error.InvalidAckFrame,
            sent.validateAckCoversSentPackets(ack),
        );
    }
}

test "QUIC sent packet tracker streaming validation spans retired metadata" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    const count = SentPacketTracker.compact_acknowledged_threshold + 44;
    for (0..count) |packet_number| {
        try sent.sent(@intCast(packet_number), true, 1200);
    }
    _ = try sent.applyAckDetailed(.{
        .largest_acknowledged = SentPacketTracker.compact_acknowledged_threshold - 1,
        .ack_delay = 0,
        .first_ack_range = SentPacketTracker.compact_acknowledged_threshold - 1,
    });
    try std.testing.expectEqual(
        @as(?u64, SentPacketTracker.compact_acknowledged_threshold - 1),
        sent.retired_acknowledged_through,
    );

    const crossing = quic.AckFrame{
        .largest_acknowledged = count - 1,
        .ack_delay = 0,
        .first_ack_range = 49,
    };
    try sent.validateAckCoversSentPackets(crossing);

    try std.testing.expect(sent.forget(280));
    try std.testing.expectError(
        error.InvalidAckFrame,
        sent.validateAckCoversSentPackets(crossing),
    );
    try std.testing.expectError(
        error.InvalidAckFrame,
        sent.validateAckCoversSentPackets(.{
            .largest_acknowledged = std.math.maxInt(u64),
            .ack_delay = 0,
            .first_ack_range = std.math.maxInt(u64),
        }),
    );
}

test "QUIC sent packet tracker applies ACK ranges" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    for (0..12) |pn| try sent.sent(@intCast(pn), true, 1200);
    try std.testing.expect(sent.packetsSortedAscending());
    const before = sent.stats();
    try std.testing.expectEqual(@as(usize, 12), before.tracked_packets);
    try std.testing.expectEqual(@as(usize, 12), before.ack_eliciting_packets);
    try std.testing.expectEqual(@as(usize, 12), before.in_flight_packets);
    try std.testing.expectEqual(@as(usize, 12), before.ack_eliciting_in_flight_packets);
    try std.testing.expectEqual(@as(usize, 12 * 1200), before.bytes_in_flight);

    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 1 },
        .{ .gap = 2, .ack_range_length = 2 },
    };
    const ack = quic.AckFrame{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };
    const result = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(usize, 6), result.packets);
    try std.testing.expectEqual(@as(usize, 6 * 1200), result.bytes);
    try std.testing.expectEqual(@as(u64, 10), sent.largestAcknowledged().?);
    try std.testing.expect(sent.packets.items[10].acknowledged);
    try std.testing.expect(sent.packets.items[8].acknowledged);
    try std.testing.expect(sent.packets.items[7].acknowledged);
    try std.testing.expect(sent.packets.items[3].acknowledged);
    try std.testing.expect(!sent.packets.items[9].acknowledged);
    const after = sent.getStats();
    try std.testing.expectEqual(@as(usize, 6), after.acknowledged_packets);
    try std.testing.expectEqual(@as(usize, 6), after.in_flight_packets);
    try std.testing.expectEqual(@as(usize, 6), after.ack_eliciting_in_flight_packets);
    try std.testing.expectEqual(@as(usize, 6 * 1200), after.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 0), after.lost_packets);
}

test "QUIC cumulative ACK cursor skips resolved packet prefix" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    for (0..8) |packet_number| {
        try sent.sentAt(
            packet_number,
            true,
            100,
            .not_ect,
            packet_number * 10,
        );
    }
    const first = try sent.applyAckDetailed(.{
        .largest_acknowledged = 5,
        .ack_delay = 0,
        .first_ack_range = 5,
    });
    try std.testing.expectEqual(@as(usize, 6), first.packets);
    try std.testing.expectEqual(
        @as(usize, 6),
        sent.first_unacknowledged_index,
    );

    // A cumulative ACK repeats the resolved prefix while adding one packet.
    // It remains valid, but only the new suffix contributes completion bytes.
    const second = try sent.applyAckDetailed(.{
        .largest_acknowledged = 6,
        .ack_delay = 0,
        .first_ack_range = 6,
    });
    try std.testing.expectEqual(@as(usize, 1), second.packets);
    try std.testing.expectEqual(@as(usize, 100), second.bytes);
    try std.testing.expectEqual(
        @as(usize, 7),
        sent.first_unacknowledged_index,
    );

    try std.testing.expect(sent.forget(0));
    try std.testing.expectEqual(
        @as(usize, 6),
        sent.first_unacknowledged_index,
    );
}

test "QUIC sent packet tracker validated ACK token rejects a different frame" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sent(0, true, 100);
    try sent.sent(1, true, 100);

    const first = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    const validated = try sent.validateAckForApply(first, 7);
    try std.testing.expectError(
        error.InvalidAckFrame,
        sent.applyAckDetailedForProbeValidated(
            .{
                .largest_acknowledged = 1,
                .ack_delay = 0,
                .first_ack_range = 0,
            },
            null,
            0,
            null,
            7,
            validated,
        ),
    );
    try std.testing.expect(!sent.packets.items[0].acknowledged);
    try std.testing.expect(!sent.packets.items[1].acknowledged);
}

test "QUIC sent packet tracker compacts cumulative ACK metadata" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    const count = SentPacketTracker.compact_acknowledged_threshold + 44;
    for (0..count) |packet_number| {
        try sent.sent(packet_number, true, 100);
    }
    const ack = quic.AckFrame{
        .largest_acknowledged = count - 1,
        .ack_delay = 0,
        .first_ack_range = count - 1,
    };
    const result = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(count, result.packets);
    try std.testing.expectEqual(@as(usize, 0), sent.packets.items.len);
    try std.testing.expectEqual(@as(?u64, 0), sent.retired_acknowledged_start);
    try std.testing.expectEqual(
        @as(?u64, count - 1),
        sent.retired_acknowledged_through,
    );

    // Duplicate cumulative ACKs stay valid after detailed records are gone.
    const duplicate = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(usize, 0), duplicate.packets);
    const unsent = quic.AckFrame{
        .largest_acknowledged = count,
        .ack_delay = 0,
        .first_ack_range = count,
    };
    try std.testing.expectError(
        error.InvalidAckFrame,
        sent.applyAckDetailed(unsent),
    );

    try sent.sent(count, true, 100);
    const next = try sent.applyAckDetailed(.{
        .largest_acknowledged = count,
        .ack_delay = 0,
        .first_ack_range = count,
    });
    try std.testing.expectEqual(@as(usize, 1), next.packets);
}

test "QUIC sent packet tracker preserves non-probe ACK PMTU evidence after compaction" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    const count = SentPacketTracker.compact_acknowledged_threshold + 8;
    for (0..count) |packet_number| {
        try sent.sentAtWithDatagramSize(
            packet_number,
            true,
            100,
            1300,
            .not_ect,
            @intCast(packet_number + 1),
        );
    }
    const ack = quic.AckFrame{
        .largest_acknowledged = count - 1,
        .ack_delay = 0,
        .first_ack_range = count - 1,
    };
    const result = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(?u64, count - 1), result.largest_nonprobe_packet_number);
    try std.testing.expectEqual(@as(?usize, 1300), result.largest_nonprobe_datagram_size);
    try std.testing.expectEqual(@as(usize, 0), sent.packets.items.len);
}

test "QUIC sent packet tracker ACK PMTU evidence keeps highest qualifying packet" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAtWithDatagramSizeAndPathEpoch(5, true, 100, 1300, .not_ect, 1_000, 7);
    try sent.sentAtWithDatagramSizeAndPathEpoch(10, true, 100, 1299, .not_ect, 2_000, 7);
    const result = try sent.applyAckDetailedForProbe(
        .{
            .largest_acknowledged = 10,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ranges = &.{.{ .gap = 3, .ack_range_length = 0 }},
        },
        null,
        0,
        1300,
        7,
    );
    try std.testing.expectEqual(@as(?u64, 5), result.largest_pmtu_acked_packet_number);
    try std.testing.expectEqual(@as(?usize, 1300), result.largest_pmtu_acked_datagram_size);
    try std.testing.expectEqual(@as(?u64, 10), result.largest_nonprobe_packet_number);
    try std.testing.expectEqual(@as(?usize, 1299), result.largest_nonprobe_datagram_size);
}

test "QUIC sent packet tracker ACK PMTU evidence keeps strongest datagram" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAtWithDatagramSizeAndPathEpoch(5, true, 100, 1400, .not_ect, 1_000, 7);
    try sent.sentAtWithDatagramSizeAndPathEpoch(6, true, 100, 1300, .not_ect, 2_000, 7);
    try sent.sentAtWithDatagramSizeAndPathEpoch(7, true, 100, 1400, .not_ect, 3_000, 7);
    const result = try sent.applyAckDetailedForProbe(
        .{
            .largest_acknowledged = 7,
            .ack_delay = 0,
            .first_ack_range = 2,
        },
        null,
        0,
        1200,
        7,
    );
    try std.testing.expectEqual(
        @as(?u64, 7),
        result.largest_pmtu_acked_packet_number,
    );
    try std.testing.expectEqual(
        @as(?usize, 1400),
        result.largest_pmtu_acked_datagram_size,
    );
}

test "QUIC sent packet tracker skips packet-threshold scan before first packet" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(10, true, 100, .not_ect, 1_000);
    try sent.sentAt(11, true, 100, .not_ect, 2_000);
    const lost = sent.detectPacketThresholdLoss(12, default_packet_threshold);
    try std.testing.expectEqual(@as(usize, 0), lost.packets);
    try std.testing.expect(!sent.packets.items[0].lost);
    try std.testing.expect(!sent.packets.items[1].lost);
}

test "QUIC sent packet tracker applies many ACK ranges in one decoded set" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    for (0..81) |pn| {
        try sent.sentWithEcn(
            @intCast(pn),
            true,
            100,
            if (pn % 2 == 0) .ect0 else .not_ect,
        );
    }
    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    } ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
        .ecn_counts = .{
            .ect0_count = 41,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    };

    const result = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(usize, 41), result.packets);
    try std.testing.expectEqual(@as(usize, 41), result.ack_eliciting_packets);
    try std.testing.expectEqual(@as(usize, 41 * 100), result.bytes);
    try std.testing.expectEqual(@as(usize, 41), result.ect0_packets);
    try std.testing.expectEqual(@as(u64, 41), sent.latest_ecn_counts.ect0_count);
    try std.testing.expectEqual(@as(?u64, 80), sent.largestAcknowledged());
    try std.testing.expect(sent.hasAcknowledgedAtOrAbove(80));
    try std.testing.expect(!sent.hasAcknowledgedAtOrAbove(81));
    for (sent.packets.items, 0..) |packet, index| {
        try std.testing.expectEqual(index % 2 == 0, packet.acknowledged);
    }
}

test "QUIC sent packet tracker falls back for unsorted packet metadata" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sent(2, true, 300);
    try sent.sent(0, true, 100);
    try sent.sent(1, true, 200);
    try std.testing.expect(!sent.packetsSortedAscending());

    const ack = quic.AckFrame{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 2,
    };
    try sent.validateAckCoversSentPackets(ack);
    try std.testing.expectError(
        error.InvalidAckFrame,
        sent.validateAckCoversSentPackets(.{
            .largest_acknowledged = 3,
            .ack_delay = 0,
            .first_ack_range = 3,
        }),
    );
    const result = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(usize, 3), result.packets);
    try std.testing.expectEqual(@as(usize, 600), result.bytes);
    for (sent.packets.items) |packet| {
        try std.testing.expect(packet.acknowledged);
    }
}

test "QUIC sent packet tracker rejects ACK for never-sent packets" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sent(0, true, 1200);

    const unsent_largest = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectError(error.InvalidAckFrame, sent.applyAckDetailed(unsent_largest));
    try std.testing.expect(!sent.packets.items[0].acknowledged);
    try std.testing.expectEqual(@as(?u64, null), sent.largestAcknowledged());

    try sent.sent(2, true, 1200);
    const gapless_range_with_missing_one = quic.AckFrame{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 2,
    };
    try std.testing.expectError(error.InvalidAckFrame, sent.applyAckDetailed(gapless_range_with_missing_one));
    try std.testing.expect(!sent.packets.items[0].acknowledged);
    try std.testing.expect(!sent.packets.items[1].acknowledged);
}

test "QUIC sent packet tracker derives RTT sample from largest ACK" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 1200, .not_ect, 1_000);
    try sent.sentAt(1, false, 0, .not_ect, 2_000);
    try sent.sentAt(2, true, 1200, .not_ect, 3_000);

    const sample_ack = quic.AckFrame{ .largest_acknowledged = 2, .ack_delay = 5, .first_ack_range = 0 };
    const sample = (try sent.ackRttSample(sample_ack, 10_000, 3)).?;
    try std.testing.expectEqual(@as(u64, 7_000), sample.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 5 * 8 * 1_000), sample.ack_delay_ns);
    try std.testing.expectEqual(@as(u64, 2), sample.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 3_000), sample.sent_time_ns);

    _ = sent.markAcknowledged(2);
    try std.testing.expectEqual(@as(?SentPacketTracker.RttSample, null), try sent.ackRttSample(sample_ack, 11_000, 3));

    const ack_only = quic.AckFrame{ .largest_acknowledged = 1, .ack_delay = 0, .first_ack_range = 0 };
    try std.testing.expectEqual(@as(?SentPacketTracker.RttSample, null), try sent.ackRttSample(ack_only, 10_000, 3));

    const no_time = quic.AckFrame{ .largest_acknowledged = 99, .ack_delay = 0, .first_ack_range = 0 };
    try std.testing.expectEqual(@as(?SentPacketTracker.RttSample, null), try sent.ackRttSample(no_time, 10_000, 3));
}

test "QUIC sent packet tracker skips RTT samples for old ACKs" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(1, true, 100, .not_ect, 1_000);
    try sent.sentAt(2, true, 100, .not_ect, 2_000);
    const ack = quic.AckFrame{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 1,
    };
    _ = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(
        @as(?SentPacketTracker.RttSample, null),
        try sent.ackRttSample(ack, 3_000, 3),
    );
}

test "QUIC sent packet tracker accepts non-eliciting largest ACK when range newly ACKs eliciting data" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 1200, .not_ect, 1_000);
    try sent.sentAt(1, false, 0, .not_ect, 2_000);

    const ack = quic.AckFrame{ .largest_acknowledged = 1, .ack_delay = 0, .first_ack_range = 1 };
    const sample = (try sent.ackRttSample(ack, 12_000, 3)).?;
    try std.testing.expectEqual(@as(u64, 10_000), sample.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 1), sample.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2_000), sample.sent_time_ns);
}

test "QUIC sent packet tracker lower-bounds sorted ACK RTT scans" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    for (0..64) |packet_number| {
        try sent.sentAt(@intCast(packet_number), packet_number == 63, 100, .not_ect, @intCast(1_000 + packet_number));
    }
    try std.testing.expect(sent.packetsSortedAscending());
    const ack = quic.AckFrame{
        .largest_acknowledged = 63,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    const sample = (try sent.ackRttSample(ack, 10_000, 3)).?;
    try std.testing.expectEqual(@as(u64, 63), sample.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 1_063), sample.sent_time_ns);
}

test "QUIC sent packet tracker validates ACK_ECN counters" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sentWithEcn(0, true, 1200, .ect0);

    const valid_ecn = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    };
    const acked = try sent.applyAckDetailed(valid_ecn);
    try std.testing.expectEqual(@as(usize, 1), acked.packets);
    try std.testing.expectEqual(@as(u64, 1), sent.latest_ecn_counts.ect0_count);

    try sent.sentWithEcn(1, true, 1200, .ect1);
    const excessive_ecn = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 2,
            .ecn_ce_count = 0,
        },
    };
    try std.testing.expectError(error.InvalidAckFrame, sent.applyAckDetailed(excessive_ecn));
    try std.testing.expect(!sent.packets.items[1].acknowledged);
    try std.testing.expectEqual(@as(u64, 0), sent.latest_ecn_counts.ect1_count);
}

test "QUIC sent packet tracker reports ACK_ECN CE congestion deltas" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sentWithEcn(0, true, 1200, .ect0);

    const ce_ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 1,
        },
    };
    const acked = try sent.applyAckDetailed(ce_ack);
    try std.testing.expectEqual(@as(usize, 1), acked.packets);
    try std.testing.expectEqual(@as(u64, 1), acked.ecn_ce_delta);
    try std.testing.expectEqual(@as(u64, 1), sent.latest_ecn_counts.ecn_ce_count);
    try std.testing.expectEqual(@as(?u64, 0), sent.ecn_largest_acknowledged);
}

test "QUIC sent packet tracker rejects ACK_ECN counters that miss newly acked ECT packets" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sentWithEcn(0, true, 1200, .ect0);

    const missing_ect = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    };
    try std.testing.expectError(error.InvalidAckFrame, sent.applyAckDetailed(missing_ect));
    try std.testing.expect(!sent.packets.items[0].acknowledged);
}

test "QUIC sent packet tracker rejects mixed-path ACK_ECN that only covers current-path ECT packets" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAtWithDatagramSizeAndPathEpoch(0, true, 1200, 1200, .ect0, 1_000, 1);
    try sent.sentAtWithDatagramSizeAndPathEpoch(1, true, 1200, 1200, .ect0, 2_000, 2);

    const mixed_ack = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 1,
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    };
    try std.testing.expectError(
        error.InvalidAckFrame,
        sent.validateAckEcnFrameForPathEpoch(mixed_ack, 2),
    );
}

test "QUIC sent packet tracker separates retired and current path ACK effects" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        100,
        1200,
        .not_ect,
        1_000,
        1,
    );
    try sent.sentAtWithDatagramSizeAndPathEpoch(
        1,
        true,
        200,
        1200,
        .not_ect,
        2_000,
        2,
    );

    const old_ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(
        @as(?SentPacketTracker.RttSample, null),
        try sent.ackRttSampleForPathEpoch(old_ack, 10_000, 3, 2),
    );
    const old_result = try sent.applyAckDetailedForProbe(
        old_ack,
        null,
        0,
        null,
        2,
    );
    try std.testing.expectEqual(@as(usize, 1), old_result.packets);
    try std.testing.expectEqual(@as(usize, 100), old_result.bytes);
    try std.testing.expectEqual(@as(usize, 0), old_result.current_path_bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        old_result.current_path_ack_eliciting_packets,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        old_result.current_path_largest_sent_time_ns,
    );

    const current_ack = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    const sample = (try sent.ackRttSampleForPathEpoch(
        current_ack,
        12_000,
        3,
        2,
    )).?;
    try std.testing.expectEqual(@as(u64, 10_000), sample.latest_rtt_ns);
    const current_result = try sent.applyAckDetailedForProbe(
        current_ack,
        null,
        0,
        null,
        2,
    );
    try std.testing.expectEqual(@as(usize, 200), current_result.bytes);
    try std.testing.expectEqual(
        @as(usize, 200),
        current_result.current_path_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        current_result.current_path_ack_eliciting_packets,
    );
    try std.testing.expectEqual(
        @as(?u64, 2_000),
        current_result.current_path_largest_sent_time_ns,
    );
}

test "QUIC sent packet tracker reports mixed-path ACK totals separately" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        100,
        1200,
        .not_ect,
        1_000,
        1,
    );
    try sent.sentAtWithDatagramSizeAndPathEpoch(
        1,
        true,
        200,
        1200,
        .not_ect,
        2_000,
        2,
    );
    const ack = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 1,
    };
    const sample = (try sent.ackRttSampleForPathEpoch(
        ack,
        12_000,
        3,
        2,
    )).?;
    try std.testing.expectEqual(@as(u64, 10_000), sample.latest_rtt_ns);
    const result = try sent.applyAckDetailedForProbe(
        ack,
        null,
        0,
        null,
        2,
    );
    try std.testing.expectEqual(@as(usize, 2), result.packets);
    try std.testing.expectEqual(@as(usize, 300), result.bytes);
    try std.testing.expectEqual(@as(usize, 200), result.current_path_bytes);
    try std.testing.expectEqual(
        @as(usize, 1),
        result.current_path_ack_eliciting_packets,
    );
}

test "QUIC sent packet tracker separates retired path loss effects" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        100,
        1200,
        .not_ect,
        100,
        1,
    );
    try sent.sentAtWithDatagramSizeAndPathEpoch(
        1,
        true,
        100,
        1200,
        .not_ect,
        200,
        1,
    );
    try sent.sentAtWithDatagramSizeAndPathEpoch(
        2,
        true,
        200,
        1200,
        .not_ect,
        1_000,
        2,
    );
    try sent.sentAtWithDatagramSizeAndPathEpoch(
        3,
        true,
        200,
        1200,
        .not_ect,
        1_100,
        2,
    );
    try sent.sentAtWithDatagramSizeAndPathEpoch(
        4,
        true,
        200,
        1200,
        .not_ect,
        1_200,
        2,
    );

    const packet_lost = sent.detectPacketThresholdLossForProbeAndPathEpoch(
        4,
        3,
        null,
        0,
        2,
    );
    try std.testing.expectEqual(@as(usize, 2), packet_lost.packets);
    try std.testing.expectEqual(@as(usize, 200), packet_lost.bytes);
    try std.testing.expectEqual(
        @as(usize, 0),
        packet_lost.current_path_bytes,
    );
    try std.testing.expectEqual(
        @as(?u64, 1_100),
        sent.timeThresholdLossDeadlineForProbeAndPathEpoch(
            100,
            4,
            null,
            0,
            2,
        ),
    );

    const timed_lost = sent.detectTimeThresholdLossForProbeAndPathEpoch(
        2_000,
        100,
        4,
        null,
        0,
        2,
    );
    try std.testing.expectEqual(@as(usize, 3), timed_lost.packets);
    try std.testing.expectEqual(@as(usize, 600), timed_lost.bytes);
    try std.testing.expectEqual(
        @as(usize, 600),
        timed_lost.current_path_bytes,
    );
    const all_period = sent.persistentCongestionPeriod(0, 4, null).?;
    try std.testing.expectEqual(@as(u64, 0), all_period.start_packet_number);
    const current_period = sent.persistentCongestionPeriodForPathEpoch(
        0,
        4,
        null,
        2,
    ).?;
    try std.testing.expectEqual(@as(u64, 2), current_period.start_packet_number);
    try std.testing.expectEqual(@as(u64, 4), current_period.end_packet_number);
}

test "QUIC sent packet tracker tolerates reordered ACK_ECN frames" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sentWithEcn(0, true, 1200, .ect0);
    try sent.sentWithEcn(1, true, 1200, .ect0);

    const newer = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 1, .ect1_count = 0, .ecn_ce_count = 0 },
    };
    _ = try sent.applyAckDetailed(newer);
    try std.testing.expectEqual(@as(?u64, 1), sent.ecn_largest_acknowledged);

    const reordered = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 0 },
    };
    _ = try sent.applyAckDetailed(reordered);
    try std.testing.expect(!sent.plainAckWouldFailForPathEpoch(
        .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        null,
    ));
    try std.testing.expectEqual(@as(u64, 1), sent.latest_ecn_counts.ect0_count);
}

test "QUIC sent packet tracker flags plain ACK for newly acked ECT packet" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sentWithEcn(0, true, 1200, .ect0);

    const plain_ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expect(sent.plainAckWouldFailForPathEpoch(plain_ack, null));
    const result = try sent.applyAckDetailed(plain_ack);
    try std.testing.expectEqual(@as(usize, 1), result.ect0_packets);
}

test "QUIC sent packet tracker detects time-threshold loss" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 1200, .not_ect, 100);
    try sent.sentAt(1, true, 1200, .not_ect, 180);
    try sent.sentAt(2, true, 1200, .not_ect, 260);

    try std.testing.expectEqual(@as(?u64, 250), sent.timeThresholdLossDeadline(150, 2));
    try std.testing.expectEqual(@as(?u64, 250), sent.timeThresholdLossDeadline(150, 0));

    const early = sent.detectTimeThresholdLoss(249, 150, 2);
    try std.testing.expectEqual(@as(usize, 0), early.packets);
    try std.testing.expectEqual(@as(?u64, 250), early.next_loss_time_ns);

    const lost = sent.detectTimeThresholdLoss(250, 150, 2);
    try std.testing.expectEqual(@as(usize, 1), lost.packets);
    try std.testing.expectEqual(@as(usize, 1200), lost.bytes);
    try std.testing.expectEqual(@as(?u64, 330), lost.next_loss_time_ns);
    try std.testing.expect(sent.packets.items[0].lost);
    try std.testing.expect(!sent.packets.items[1].lost);

    // Packets newer than the largest acknowledged packet are not time-threshold
    // candidates, matching RFC 9002's "earlier than largest acked" rule.
    const none_for_future = sent.detectTimeThresholdLoss(1_000, 150, 0);
    try std.testing.expectEqual(@as(usize, 0), none_for_future.packets);

    try std.testing.expectEqual(@as(?u64, 330), sent.timeThresholdLossDeadline(150, 2));
    const remaining = sent.detectTimeThresholdLoss(1_000, 150, 2);
    try std.testing.expectEqual(@as(usize, 2), remaining.packets);
    try std.testing.expectEqual(@as(?u64, null), remaining.next_loss_time_ns);
    try std.testing.expectEqual(@as(?u64, null), sent.timeThresholdLossDeadline(150, 2));
}

test "QUIC sent packet tracker skips time-threshold scan before first packet" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(10, true, 100, .not_ect, 1_000);
    try sent.sentAt(11, true, 100, .not_ect, 2_000);

    try std.testing.expectEqual(@as(?u64, null), sent.timeThresholdLossDeadline(100, 5));
    const lost = sent.detectTimeThresholdLoss(10_000, 100, 5);
    try std.testing.expectEqual(@as(usize, 0), lost.packets);
    try std.testing.expect(!sent.packets.items[0].lost);
    try std.testing.expect(!sent.packets.items[1].lost);
}

test "QUIC sent packet tracker reports latest ack-eliciting in-flight send time" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 1200, .not_ect, 100);
    try sent.sentAt(1, false, 0, .not_ect, 400);
    try sent.sentAt(2, true, 1200, .not_ect, 300);
    try sent.sentAt(3, true, 1200, .not_ect, null);
    try std.testing.expectEqual(@as(?usize, 2), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expectEqual(@as(?u64, 300), sent.latestAckElicitingInFlightSentTime());
    try std.testing.expectEqual(
        @as(?u64, 300),
        sent.stats().latest_ack_eliciting_in_flight_sent_time_ns,
    );

    _ = sent.markAcknowledged(2);
    try std.testing.expectEqual(@as(?usize, 0), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expectEqual(@as(?u64, 100), sent.latestAckElicitingInFlightSentTime());
    try std.testing.expectEqual(
        @as(?u64, 100),
        sent.stats().latest_ack_eliciting_in_flight_sent_time_ns,
    );

    sent.packets.items[0].lost = true;
    // Same-module tests can still mutate packet state directly; the cached
    // hot-path value is guarded by a correctness fallback for those cases.
    try std.testing.expectEqual(@as(?u64, null), sent.latestAckElicitingInFlightSentTime());
    try std.testing.expectEqual(
        @as(?u64, null),
        sent.stats().latest_ack_eliciting_in_flight_sent_time_ns,
    );
}

test "QUIC sent packet tracker excludes PMTU from ordinary PTO anchor" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentInFlightAtWithPmtu(
        0,
        true,
        true,
        1200,
        .not_ect,
        100,
        1400,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        sent.latestNonProbeAckElicitingInFlightSentTime(),
    );
    try sent.sentAt(1, true, 20, .not_ect, 200);
    try std.testing.expectEqual(
        @as(?u64, 200),
        sent.latestNonProbeAckElicitingInFlightSentTime(),
    );
    try sent.sentInFlightAtWithPmtu(
        2,
        true,
        true,
        1400,
        .not_ect,
        300,
        1450,
    );
    // A newer PMTU probe owns the generic latest-packet cache, so the ordinary
    // PTO query must fall back to the older application packet.
    try std.testing.expectEqual(@as(?usize, 2), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expectEqual(
        @as(?u64, 200),
        sent.latestNonProbeAckElicitingInFlightSentTime(),
    );
    _ = sent.markAcknowledged(1);
    try std.testing.expectEqual(
        @as(?u64, null),
        sent.latestNonProbeAckElicitingInFlightSentTime(),
    );
}

test "QUIC sent packet tracker repairs cached PTO base on ACK loss and forget" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(10, true, 1200, .not_ect, 100);
    try sent.sentAt(11, true, 1200, .not_ect, 200);
    try sent.sentAt(12, true, 1200, .not_ect, 300);
    try std.testing.expectEqual(@as(?usize, 2), sent.latest_ack_eliciting_in_flight_index);

    const ack_latest = quic.AckFrame{
        .largest_acknowledged = 12,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    _ = try sent.applyAckDetailed(ack_latest);
    _ = sent.markAcknowledged(10);
    try std.testing.expectEqual(@as(?usize, 1), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expectEqual(@as(?u64, 200), sent.latestAckElicitingInFlightSentTime());

    // A newer packet with an older send time must not disturb the cached PTO
    // base, but it becomes the fallback after the current base is declared lost.
    try sent.sentAt(13, true, 1200, .not_ect, 150);
    try std.testing.expectEqual(@as(?usize, 1), sent.latest_ack_eliciting_in_flight_index);

    const lost = sent.detectPacketThresholdLoss(14, 3);
    try std.testing.expectEqual(@as(usize, 1), lost.packets);
    try std.testing.expectEqual(@as(?usize, 3), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expectEqual(@as(?u64, 150), sent.latestAckElicitingInFlightSentTime());

    try std.testing.expect(sent.forget(13));
    try std.testing.expectEqual(@as(?usize, null), sent.latest_ack_eliciting_in_flight_index);
    try std.testing.expectEqual(@as(?u64, null), sent.latestAckElicitingInFlightSentTime());
}

test "QUIC sent packet tracker accounts non-eliciting in-flight packets" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    // RFC 9002 treats packets containing only PADDING as non-ack-eliciting but
    // still in flight.  Model that independently from ACK-only / close packets
    // so congestion bytes are released when such a packet is ACKed or declared
    // lost, without arming PTO as though it could elicit an ACK.
    try sent.sentInFlightAt(0, false, true, 256, .not_ect, 100);
    try std.testing.expectEqual(@as(?u64, null), sent.latestAckElicitingInFlightSentTime());

    const ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    const acked = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(usize, 1), acked.packets);
    try std.testing.expectEqual(@as(usize, 0), acked.ack_eliciting_packets);
    try std.testing.expectEqual(@as(usize, 256), acked.bytes);
    try std.testing.expect(sent.packets.items[0].acknowledged);

    var lost_sent = SentPacketTracker.init(allocator);
    defer lost_sent.deinit();
    try lost_sent.sentInFlightAt(0, false, true, 300, .not_ect, 100);
    const lost = lost_sent.detectTimeThresholdLoss(250, 150, 0);
    try std.testing.expectEqual(@as(usize, 1), lost.packets);
    try std.testing.expectEqual(@as(usize, 0), lost.ack_eliciting_packets);
    try std.testing.expectEqual(@as(usize, 300), lost.bytes);
    try std.testing.expect(lost_sent.packets.items[0].lost);
}

test "QUIC sent packet tracker finds persistent congestion periods" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 1200, .not_ect, 100); // before the first RTT sample epoch.
    try sent.sentAt(1, true, 1200, .not_ect, 1_000);
    try sent.sentAt(2, false, 0, .not_ect, 2_000);
    try sent.sentAt(3, true, 1200, .not_ect, 4_000);
    try sent.sentAt(4, true, 1200, .not_ect, 9_000);
    try sent.sentAt(5, true, 1200, .not_ect, 10_000);
    _ = sent.markAcknowledged(5);

    for (sent.packets.items[0..5]) |*packet| packet.lost = true;

    try std.testing.expectEqual(
        @as(?SentPacketTracker.PersistentCongestionPeriod, null),
        sent.persistentCongestionPeriod(null, sent.largestAcknowledged(), null),
    );

    const period = sent.persistentCongestionPeriod(500, sent.largestAcknowledged(), null).?;
    try std.testing.expectEqual(@as(u64, 1), period.start_packet_number);
    try std.testing.expectEqual(@as(u64, 4), period.end_packet_number);
    try std.testing.expectEqual(@as(u64, 1_000), period.start_time_ns);
    try std.testing.expectEqual(@as(u64, 9_000), period.end_time_ns);
    try std.testing.expectEqual(@as(u64, 8_000), period.durationNs());

    try std.testing.expect(sent.persistentCongestionPeriod(500, sent.largestAcknowledged(), 3) != null);
    try std.testing.expectEqual(
        @as(?SentPacketTracker.PersistentCongestionPeriod, null),
        sent.persistentCongestionPeriod(500, sent.largestAcknowledged(), 4),
    );
    try std.testing.expectEqual(
        @as(?SentPacketTracker.PersistentCongestionPeriod, null),
        sent.persistentCongestionPeriod(500, sent.largestAcknowledged(), sent.largestAcknowledged()),
    );
}

test "QUIC persistent congestion period requires ack-eliciting boundaries" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, false, 0, .not_ect, 1_000);
    try sent.sentAt(1, true, 1200, .not_ect, 8_000);
    try sent.sentAt(2, true, 1200, .not_ect, 9_000);
    _ = sent.markAcknowledged(2);
    sent.packets.items[0].lost = true;
    sent.packets.items[1].lost = true;

    try std.testing.expectEqual(
        @as(?SentPacketTracker.PersistentCongestionPeriod, null),
        sent.persistentCongestionPeriod(0, sent.largestAcknowledged(), null),
    );
}

test "QUIC sent packet tracker keeps unsorted loss scans conservative" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sent(5, true, 1200);
    try sent.sent(0, true, 1200);
    try sent.sent(1, true, 1200);
    try std.testing.expect(!sent.packetsSortedAscending());

    const lost = sent.detectPacketThresholdLoss(4, default_packet_threshold);
    try std.testing.expectEqual(@as(usize, 2), lost.packets);
    try std.testing.expect(!sent.packets.items[0].lost);
    try std.testing.expect(sent.packets.items[1].lost);
    try std.testing.expect(sent.packets.items[2].lost);

    var timed = SentPacketTracker.init(allocator);
    defer timed.deinit();
    try timed.sentAt(5, true, 1200, .not_ect, 100);
    try timed.sentAt(0, true, 1200, .not_ect, 100);
    try std.testing.expect(!timed.packetsSortedAscending());
    const time_lost = timed.detectTimeThresholdLoss(300, 100, 0);
    try std.testing.expectEqual(@as(usize, 1), time_lost.packets);
    try std.testing.expect(!timed.packets.items[0].lost);
    try std.testing.expect(timed.packets.items[1].lost);
}

test "QUIC sent packet tracker detects packet-threshold loss" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    for (0..6) |pn| try sent.sent(@intCast(pn), true, 1200);

    const lost = sent.detectPacketThresholdLoss(4, default_packet_threshold);
    try std.testing.expectEqual(@as(usize, 2), lost.packets);
    try std.testing.expectEqual(@as(usize, 2400), lost.bytes);
    try std.testing.expect(sent.packets.items[0].lost);
    try std.testing.expect(sent.packets.items[1].lost);
    try std.testing.expect(!sent.packets.items[2].lost);

    const ack = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 1,
    };
    const acked_after_loss = try sent.applyAckDetailed(ack);
    try std.testing.expectEqual(@as(usize, 2), acked_after_loss.packets);
    try std.testing.expectEqual(@as(usize, 0), acked_after_loss.bytes);
}

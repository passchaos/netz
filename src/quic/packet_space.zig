const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    TooManyAckRanges,
    InvalidAckFrame,
    DuplicatePacket,
    InvalidPacketNumber,
} || std.mem.Allocator.Error;

pub const default_packet_threshold: u64 = 3;

pub const PacketRange = struct {
    start: u64,
    end: u64,

    fn len(self: PacketRange) u64 {
        return self.end - self.start + 1;
    }
};

pub const ReceivedPacketTracker = struct {
    allocator: std.mem.Allocator,
    ranges: std.ArrayList(PacketRange) = .empty,
    max_ranges: usize = 64,
    forgotten_through: ?u64 = null,

    pub fn init(allocator: std.mem.Allocator, max_ranges: usize) ReceivedPacketTracker {
        return .{ .allocator = allocator, .max_ranges = max_ranges };
    }

    pub fn deinit(self: *ReceivedPacketTracker) void {
        self.ranges.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn record(self: *ReceivedPacketTracker, packet_number: u64) Error!void {
        _ = try self.recordFresh(packet_number);
    }

    /// Record a received packet number, returning whether it is new enough to
    /// process.  Duplicate packets and packet numbers that fell out of the
    /// bounded ACK history return `false`; callers should drop those packets
    /// before applying frame side effects.
    pub fn recordFresh(self: *ReceivedPacketTracker, packet_number: u64) Error!bool {
        if (packet_number > quic.varint.max_value) return error.InvalidPacketNumber;
        if (self.forgotten_through) |forgotten| {
            if (packet_number <= forgotten) return false;
        }

        for (self.ranges.items, 0..) |*range, i| {
            if (packet_number >= range.start and packet_number <= range.end) return false;
            if (isImmediatelyBefore(range.end, packet_number)) {
                range.end = packet_number;
                try self.mergeForward(i);
                return true;
            }
            if (isImmediatelyBefore(packet_number, range.start)) {
                range.start = packet_number;
                try self.mergeBackward(i);
                return true;
            }
            if (packet_number > range.end) {
                return try self.insertRange(i, .{ .start = packet_number, .end = packet_number });
            }
        }
        return try self.insertRange(self.ranges.items.len, .{ .start = packet_number, .end = packet_number });
    }

    pub fn ackFrame(self: ReceivedPacketTracker, allocator: std.mem.Allocator, ack_delay: u64) Error!quic.AckFrame {
        if (self.ranges.items.len == 0) return error.InvalidAckFrame;
        const largest = self.ranges.items[0];
        const extra_count = self.ranges.items.len - 1;
        const ack_ranges = try allocator.alloc(quic.AckRange, extra_count);
        errdefer allocator.free(ack_ranges);

        var previous = largest;
        for (self.ranges.items[1..], 0..) |range, i| {
            const next_largest_after_gap = std.math.add(u64, range.end, 2) catch return error.InvalidAckFrame;
            if (previous.start < next_largest_after_gap) return error.InvalidAckFrame;
            ack_ranges[i] = .{
                .gap = previous.start - range.end - 2,
                .ack_range_length = range.len() - 1,
            };
            previous = range;
        }

        return .{
            .largest_acknowledged = largest.end,
            .ack_delay = ack_delay,
            .first_ack_range = largest.len() - 1,
            .ranges = ack_ranges,
        };
    }

    fn insertRange(self: *ReceivedPacketTracker, index: usize, range: PacketRange) Error!bool {
        if (self.max_ranges == 0) return false;

        if (self.ranges.items.len >= self.max_ranges) {
            if (index == self.ranges.items.len) {
                self.forgetThrough(range.end);
                return false;
            }

            const oldest = self.ranges.items[self.ranges.items.len - 1];
            self.forgetThrough(oldest.end);
            _ = self.ranges.orderedRemove(self.ranges.items.len - 1);
        }

        try self.ranges.insert(self.allocator, index, range);
        return true;
    }

    fn forgetThrough(self: *ReceivedPacketTracker, packet_number: u64) void {
        self.forgotten_through = if (self.forgotten_through) |previous|
            @max(previous, packet_number)
        else
            packet_number;
    }

    fn mergeForward(self: *ReceivedPacketTracker, index: usize) Error!void {
        if (index == 0) return;
        const current = &self.ranges.items[index];
        const previous = &self.ranges.items[index - 1];
        if (rangesOverlapOrAdjacent(current.*, previous.*)) {
            previous.start = @min(previous.start, current.start);
            previous.end = @max(previous.end, current.end);
            _ = self.ranges.orderedRemove(index);
        }
    }

    fn mergeBackward(self: *ReceivedPacketTracker, index: usize) Error!void {
        if (index + 1 >= self.ranges.items.len) return;
        const current = &self.ranges.items[index];
        const next = &self.ranges.items[index + 1];
        if (rangesOverlapOrAdjacent(next.*, current.*)) {
            current.start = @min(current.start, next.start);
            current.end = @max(current.end, next.end);
            _ = self.ranges.orderedRemove(index + 1);
        }
    }
};

fn isImmediatelyBefore(previous: u64, next: u64) bool {
    if (previous == std.math.maxInt(u64)) return false;
    return previous + 1 == next;
}

fn rangesOverlapOrAdjacent(lower: PacketRange, higher: PacketRange) bool {
    return lower.end >= higher.start or isImmediatelyBefore(lower.end, higher.start);
}

pub const SentPacket = struct {
    packet_number: u64,
    ack_eliciting: bool = true,
    acknowledged: bool = false,
    lost: bool = false,
    bytes: usize = 0,
    ecn: EcnCodepoint = .not_ect,
};

pub const EcnCodepoint = enum {
    not_ect,
    ect0,
    ect1,
};

pub const SentPacketTracker = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayList(SentPacket) = .empty,
    largest_acknowledged: ?u64 = null,
    latest_ecn_counts: quic.EcnCounts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 0 },
    ecn_validation_failed: bool = false,
    sent_ect0_count: u64 = 0,
    sent_ect1_count: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) SentPacketTracker {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SentPacketTracker) void {
        self.packets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sent(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize) !void {
        try self.sentWithEcn(packet_number, ack_eliciting, bytes, .not_ect);
    }

    pub fn sentWithEcn(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, ecn: EcnCodepoint) !void {
        try self.packets.append(self.allocator, .{
            .packet_number = packet_number,
            .ack_eliciting = ack_eliciting,
            .bytes = bytes,
            .ecn = ecn,
        });
        switch (ecn) {
            .not_ect => {},
            .ect0 => self.sent_ect0_count += 1,
            .ect1 => self.sent_ect1_count += 1,
        }
    }

    pub fn forget(self: *SentPacketTracker, packet_number: u64) bool {
        for (self.packets.items, 0..) |packet, i| {
            if (packet.packet_number == packet_number) {
                _ = self.packets.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn markAcknowledged(self: *SentPacketTracker, packet_number: u64) bool {
        for (self.packets.items) |*packet| {
            if (packet.packet_number == packet_number) {
                packet.acknowledged = true;
                self.observeAcknowledged(packet_number);
                return true;
            }
        }
        return false;
    }

    pub fn largestAcknowledged(self: SentPacketTracker) ?u64 {
        return self.largest_acknowledged;
    }

    pub const AckResult = struct {
        packets: usize = 0,
        bytes: usize = 0,
        ect0_packets: usize = 0,
        ect1_packets: usize = 0,

        fn add(self: *AckResult, other: AckResult) void {
            self.packets += other.packets;
            self.bytes += other.bytes;
            self.ect0_packets += other.ect0_packets;
            self.ect1_packets += other.ect1_packets;
        }
    };

    pub fn applyAck(self: *SentPacketTracker, ack: quic.AckFrame) Error!usize {
        return (try self.applyAckDetailed(ack)).packets;
    }

    pub fn applyAckDetailed(self: *SentPacketTracker, ack: quic.AckFrame) Error!AckResult {
        try self.validateAckCoversSentPackets(ack);
        if (ack.ecn_counts) |ecn_counts| try self.validateAckEcnCounters(ecn_counts);

        var acked: AckResult = .{};
        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        acked.add(self.markRange(start, end));

        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch return error.InvalidAckFrame;
            if (start < skipped) return error.InvalidAckFrame;
            end = start - skipped;
            if (end < range.ack_range_length) return error.InvalidAckFrame;
            start = end - range.ack_range_length;
            acked.add(self.markRange(start, end));
        }
        if (ack.ecn_counts) |ecn_counts| {
            self.latest_ecn_counts = ecn_counts;
        } else if (acked.ect0_packets != 0 or acked.ect1_packets != 0) {
            // RFC 9000 ECN validation requires ECN-capable packets to be
            // acknowledged with ACK_ECN.  A plain ACK covering ECT-marked
            // packets disables ECN for the packet number space; later ACK_ECN
            // counters are rejected until a new tracker/space is used.
            self.ecn_validation_failed = true;
        }
        return acked;
    }

    /// Validate that every packet number named by an ACK range was actually
    /// sent by this packet-number space.
    ///
    /// QUIC peers are allowed to repeat ACKs, so already-acknowledged and lost
    /// packets still count as sent.  Packet numbers that were never issued are
    /// a protocol violation; rejecting them before mutating recovery/congestion
    /// mirrors mature stacks such as quicz/tquic and keeps malicious ACK ranges
    /// from advancing local state.
    pub fn validateAckCoversSentPackets(self: SentPacketTracker, ack: quic.AckFrame) Error!void {
        if (ack.largest_acknowledged < ack.first_ack_range) return error.InvalidAckFrame;

        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        try self.validateSentRange(start, end);

        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch return error.InvalidAckFrame;
            if (start < skipped) return error.InvalidAckFrame;
            end = start - skipped;
            if (end < range.ack_range_length) return error.InvalidAckFrame;
            start = end - range.ack_range_length;
            try self.validateSentRange(start, end);
        }
    }

    pub fn validateAckEcnCounters(self: SentPacketTracker, counts: quic.EcnCounts) Error!void {
        if (self.ecn_validation_failed) return error.InvalidAckFrame;
        if (counts.ect0_count < self.latest_ecn_counts.ect0_count or
            counts.ect1_count < self.latest_ecn_counts.ect1_count or
            counts.ecn_ce_count < self.latest_ecn_counts.ecn_ce_count)
        {
            return error.InvalidAckFrame;
        }

        const sent_ect0 = self.sent_ect0_count;
        const sent_ect1 = self.sent_ect1_count;
        const total_ect = std.math.add(u64, sent_ect0, sent_ect1) catch return error.InvalidAckFrame;
        if (counts.ect0_count > sent_ect0) return error.InvalidAckFrame;
        if (counts.ect1_count > sent_ect1) return error.InvalidAckFrame;
        if (counts.ecn_ce_count > total_ect) return error.InvalidAckFrame;
    }

    pub fn detectPacketThresholdLoss(self: *SentPacketTracker, largest_acknowledged: u64, packet_threshold: u64) AckResult {
        if (packet_threshold == 0 or largest_acknowledged < packet_threshold) return .{};
        const largest_lost = largest_acknowledged - packet_threshold;

        var lost: AckResult = .{};
        for (self.packets.items) |*packet| {
            if (packet.acknowledged or packet.lost or packet.packet_number > largest_lost) continue;
            packet.lost = true;
            lost.packets += 1;
            if (packet.ack_eliciting) lost.bytes += packet.bytes;
        }
        return lost;
    }

    fn markRange(self: *SentPacketTracker, start: u64, end: u64) AckResult {
        var result: AckResult = .{};
        for (self.packets.items) |*packet| {
            if (packet.packet_number >= start and packet.packet_number <= end) {
                self.observeAcknowledged(packet.packet_number);
            }
            if (!packet.acknowledged and packet.packet_number >= start and packet.packet_number <= end) {
                packet.acknowledged = true;
                result.packets += 1;
                if (packet.ack_eliciting and !packet.lost) result.bytes += packet.bytes;
                switch (packet.ecn) {
                    .not_ect => {},
                    .ect0 => result.ect0_packets += 1,
                    .ect1 => result.ect1_packets += 1,
                }
            }
        }
        return result;
    }

    fn validateSentRange(self: SentPacketTracker, start: u64, end: u64) Error!void {
        if (start > end) return error.InvalidAckFrame;
        const span = std.math.add(u64, end - start, 1) catch return error.InvalidAckFrame;
        if (span > self.packets.items.len) return error.InvalidAckFrame;

        var packet_number = start;
        while (true) {
            if (!self.hasSentPacketNumber(packet_number)) return error.InvalidAckFrame;
            if (packet_number == end) break;
            packet_number += 1;
        }
    }

    fn hasSentPacketNumber(self: SentPacketTracker, packet_number: u64) bool {
        for (self.packets.items) |packet| {
            if (packet.packet_number == packet_number) return true;
        }
        return false;
    }

    fn observeAcknowledged(self: *SentPacketTracker, packet_number: u64) void {
        if (self.largest_acknowledged == null or packet_number > self.largest_acknowledged.?) {
            self.largest_acknowledged = packet_number;
        }
    }
};

test "QUIC packet space generates ACK ranges" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    for ([_]u64{ 1, 2, 3, 7, 8, 10 }) |pn| {
        try std.testing.expect(try received.recordFresh(pn));
    }
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

test "QUIC packet space drops duplicate and too-old packet numbers" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 2);
    defer received.deinit();

    try std.testing.expect(try received.recordFresh(10));
    try std.testing.expect(!(try received.recordFresh(10)));
    try std.testing.expect(try received.recordFresh(6));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);

    // A packet below the retained window is ignored instead of growing the ACK
    // range list without bound.
    try std.testing.expect(!(try received.recordFresh(2)));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(?u64, 2), received.forgotten_through);

    // A newer out-of-order range evicts the oldest retained range, matching the
    // bounded ACK history used by quicz/tquic style implementations.
    try std.testing.expect(try received.recordFresh(8));
    try std.testing.expectEqual(@as(usize, 2), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 10), received.ranges.items[0].start);
    try std.testing.expectEqual(@as(u64, 8), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(?u64, 6), received.forgotten_through);

    try std.testing.expect(!(try received.recordFresh(6)));
    try std.testing.expect(try received.recordFresh(7));
    try std.testing.expectEqual(@as(u64, 7), received.ranges.items[1].start);
    try std.testing.expectEqual(@as(u64, 8), received.ranges.items[1].end);
}

test "QUIC sent packet tracker applies ACK ranges" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    for (0..12) |pn| try sent.sent(@intCast(pn), true, 1200);

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

test "QUIC sent packet tracker disables ECN validation on plain ACK for ECT packet" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    try sent.sentWithEcn(0, true, 1200, .ect0);

    const plain_ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    const result = try sent.applyAckDetailed(plain_ack);
    try std.testing.expectEqual(@as(usize, 1), result.ect0_packets);
    try std.testing.expect(sent.ecn_validation_failed);

    try sent.sentWithEcn(1, true, 1200, .ect0);
    const later_ecn = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 2, .ect1_count = 0, .ecn_ce_count = 0 },
    };
    try std.testing.expectError(error.InvalidAckFrame, sent.applyAckDetailed(later_ecn));
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

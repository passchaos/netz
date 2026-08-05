const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    TooManyAckRanges,
    InvalidAckFrame,
} || std.mem.Allocator.Error;

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

    pub fn init(allocator: std.mem.Allocator, max_ranges: usize) ReceivedPacketTracker {
        return .{ .allocator = allocator, .max_ranges = max_ranges };
    }

    pub fn deinit(self: *ReceivedPacketTracker) void {
        self.ranges.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn record(self: *ReceivedPacketTracker, packet_number: u64) Error!void {
        for (self.ranges.items, 0..) |*range, i| {
            if (packet_number >= range.start and packet_number <= range.end) return;
            if (packet_number == range.end + 1) {
                range.end = packet_number;
                try self.mergeForward(i);
                return;
            }
            if (range.start != 0 and packet_number + 1 == range.start) {
                range.start = packet_number;
                try self.mergeBackward(i);
                return;
            }
            if (packet_number > range.end) {
                if (self.ranges.items.len >= self.max_ranges) return error.TooManyAckRanges;
                try self.ranges.insert(self.allocator, i, .{ .start = packet_number, .end = packet_number });
                return;
            }
        }
        if (self.ranges.items.len >= self.max_ranges) return error.TooManyAckRanges;
        try self.ranges.append(self.allocator, .{ .start = packet_number, .end = packet_number });
    }

    pub fn ackFrame(self: ReceivedPacketTracker, allocator: std.mem.Allocator, ack_delay: u64) Error!quic.AckFrame {
        if (self.ranges.items.len == 0) return error.InvalidAckFrame;
        const largest = self.ranges.items[0];
        const extra_count = self.ranges.items.len - 1;
        const ack_ranges = try allocator.alloc(quic.AckRange, extra_count);
        errdefer allocator.free(ack_ranges);

        var previous = largest;
        for (self.ranges.items[1..], 0..) |range, i| {
            if (previous.start < range.end + 2) return error.InvalidAckFrame;
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

    fn mergeForward(self: *ReceivedPacketTracker, index: usize) Error!void {
        if (index == 0) return;
        const current = &self.ranges.items[index];
        const previous = &self.ranges.items[index - 1];
        if (current.end + 1 >= previous.start) {
            previous.start = @min(previous.start, current.start);
            previous.end = @max(previous.end, current.end);
            _ = self.ranges.orderedRemove(index);
        }
    }

    fn mergeBackward(self: *ReceivedPacketTracker, index: usize) Error!void {
        if (index + 1 >= self.ranges.items.len) return;
        const current = &self.ranges.items[index];
        const next = &self.ranges.items[index + 1];
        if (next.end + 1 >= current.start) {
            current.start = @min(current.start, next.start);
            current.end = @max(current.end, next.end);
            _ = self.ranges.orderedRemove(index + 1);
        }
    }
};

pub const SentPacket = struct {
    packet_number: u64,
    ack_eliciting: bool = true,
    acknowledged: bool = false,
};

pub const SentPacketTracker = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayList(SentPacket) = .empty,

    pub fn init(allocator: std.mem.Allocator) SentPacketTracker {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SentPacketTracker) void {
        self.packets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sent(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool) !void {
        try self.packets.append(self.allocator, .{ .packet_number = packet_number, .ack_eliciting = ack_eliciting });
    }

    pub fn applyAck(self: *SentPacketTracker, ack: quic.AckFrame) Error!usize {
        var acked: usize = 0;
        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        acked += self.markRange(start, end);

        for (ack.ranges) |range| {
            if (start < range.gap + 2) return error.InvalidAckFrame;
            end = start - range.gap - 2;
            if (end < range.ack_range_length) return error.InvalidAckFrame;
            start = end - range.ack_range_length;
            acked += self.markRange(start, end);
        }
        return acked;
    }

    fn markRange(self: *SentPacketTracker, start: u64, end: u64) usize {
        var count: usize = 0;
        for (self.packets.items) |*packet| {
            if (!packet.acknowledged and packet.packet_number >= start and packet.packet_number <= end) {
                packet.acknowledged = true;
                count += 1;
            }
        }
        return count;
    }
};

test "QUIC packet space generates ACK ranges" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 8);
    defer received.deinit();

    for ([_]u64{ 1, 2, 3, 7, 8, 10 }) |pn| try received.record(pn);
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

test "QUIC sent packet tracker applies ACK ranges" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();
    for (0..12) |pn| try sent.sent(@intCast(pn), true);

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
    try std.testing.expectEqual(@as(usize, 6), try sent.applyAck(ack));
    try std.testing.expect(sent.packets.items[10].acknowledged);
    try std.testing.expect(sent.packets.items[8].acknowledged);
    try std.testing.expect(sent.packets.items[7].acknowledged);
    try std.testing.expect(sent.packets.items[3].acknowledged);
    try std.testing.expect(!sent.packets.items[9].acknowledged);
}

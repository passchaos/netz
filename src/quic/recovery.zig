const std = @import("std");
const quic = @import("mod.zig");

/// Minimal recovery state for a single QUIC packet number space.
///
/// The queue stores already encoded frame payloads instead of `quic.Frame`
/// values.  Several frame variants carry slices into caller-owned buffers, so
/// keeping encoded bytes gives retransmission stable ownership and lets the
/// caller seal the same frames under a fresh packet number for PTO.
pub const Error = error{
    EmptyPayload,
    InvalidAckFrame,
    InvalidRetransmission,
} || std.mem.Allocator.Error;

pub const Candidate = struct {
    /// Index into `Queue.pending`.  The caller must pass this back to
    /// `recordRetransmission` after the bytes have been successfully sent.
    group_index: usize,
    /// The newest packet number carrying this encoded frame payload.
    packet_number: u64,
    /// Encoded QUIC frame bytes.  These bytes are ready to become the payload of
    /// a fresh protected 1-RTT packet; retransmission must use a new packet
    /// number, but the frame encoding itself is intentionally stable.
    payload: []const u8,
    retransmission_count: usize,
};

const PendingDatagram = struct {
    packet_numbers: std.ArrayList(u64) = .empty,
    payload: []u8,
    retransmission_count: usize = 0,

    fn init(allocator: std.mem.Allocator, packet_number: u64, payload: []const u8) Error!PendingDatagram {
        if (payload.len == 0) return error.EmptyPayload;

        const payload_copy = try allocator.dupe(u8, payload);
        errdefer allocator.free(payload_copy);

        var packet_numbers: std.ArrayList(u64) = .empty;
        errdefer packet_numbers.deinit(allocator);
        try packet_numbers.append(allocator, packet_number);

        return .{
            .packet_numbers = packet_numbers,
            .payload = payload_copy,
        };
    }

    fn deinit(self: *PendingDatagram, allocator: std.mem.Allocator) void {
        self.packet_numbers.deinit(allocator);
        allocator.free(self.payload);
        self.* = undefined;
    }

    fn newestPacketNumber(self: PendingDatagram) u64 {
        return self.packet_numbers.items[self.packet_numbers.items.len - 1];
    }

    fn containsRange(self: PendingDatagram, start: u64, end: u64) bool {
        for (self.packet_numbers.items) |packet_number| {
            if (packet_number >= start and packet_number <= end) return true;
        }
        return false;
    }
};

pub const Queue = struct {
    allocator: std.mem.Allocator,
    pending: std.ArrayList(PendingDatagram) = .empty,

    pub fn init(allocator: std.mem.Allocator) Queue {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Queue) void {
        for (self.pending.items) |*entry| entry.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn pendingCount(self: Queue) usize {
        return self.pending.items.len;
    }

    pub fn trackSent(self: *Queue, packet_number: u64, payload: []const u8) Error!void {
        var entry = try PendingDatagram.init(self.allocator, packet_number, payload);
        errdefer entry.deinit(self.allocator);
        try self.pending.append(self.allocator, entry);
    }

    pub fn ptoCandidate(self: *const Queue) ?Candidate {
        if (self.pending.items.len == 0) return null;
        const entry = self.pending.items[0];
        return .{
            .group_index = 0,
            .packet_number = entry.newestPacketNumber(),
            .payload = entry.payload,
            .retransmission_count = entry.retransmission_count,
        };
    }

    pub fn recordRetransmission(self: *Queue, group_index: usize, packet_number: u64) Error!void {
        if (group_index >= self.pending.items.len) return error.InvalidRetransmission;
        const entry = &self.pending.items[group_index];
        try entry.packet_numbers.append(self.allocator, packet_number);
        entry.retransmission_count += 1;
    }

    pub fn acknowledgePacketNumber(self: *Queue, packet_number: u64) bool {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (self.pending.items[i].containsRange(packet_number, packet_number)) {
                var removed = self.pending.orderedRemove(i);
                removed.deinit(self.allocator);
                return true;
            }
            i += 1;
        }
        return false;
    }

    pub fn forgetPacketNumber(self: *Queue, packet_number: u64) bool {
        var i: usize = 0;
        while (i < self.pending.items.len) : (i += 1) {
            var entry = &self.pending.items[i];
            for (entry.packet_numbers.items, 0..) |candidate, packet_index| {
                if (candidate != packet_number) continue;

                _ = entry.packet_numbers.orderedRemove(packet_index);
                if (packet_index != 0 and entry.retransmission_count > 0) {
                    entry.retransmission_count -= 1;
                }
                if (entry.packet_numbers.items.len == 0) {
                    var removed = self.pending.orderedRemove(i);
                    removed.deinit(self.allocator);
                }
                return true;
            }
        }
        return false;
    }

    pub fn applyAck(self: *Queue, ack: quic.AckFrame) Error!usize {
        if (ack.largest_acknowledged < ack.first_ack_range) return error.InvalidAckFrame;

        var removed: usize = 0;
        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        removed += self.removeRange(start, end);

        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch return error.InvalidAckFrame;
            if (start < skipped) return error.InvalidAckFrame;
            end = start - skipped;
            if (end < range.ack_range_length) return error.InvalidAckFrame;
            start = end - range.ack_range_length;
            removed += self.removeRange(start, end);
        }

        return removed;
    }

    fn removeRange(self: *Queue, start: u64, end: u64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (self.pending.items[i].containsRange(start, end)) {
                var entry = self.pending.orderedRemove(i);
                entry.deinit(self.allocator);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }
};

test "QUIC recovery queue groups retransmissions and ACKs any copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try queue.trackSent(0, "stream frame bytes");
    const candidate = queue.ptoCandidate().?;
    try std.testing.expectEqual(@as(u64, 0), candidate.packet_number);
    try std.testing.expectEqualStrings("stream frame bytes", candidate.payload);

    try queue.recordRetransmission(candidate.group_index, 4);
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(@as(usize, 2), queue.pending.items[0].packet_numbers.items.len);

    const ack = quic.AckFrame{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
}

test "QUIC recovery queue applies ACK ranges" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try queue.trackSent(1, "one");
    try queue.trackSent(5, "five");
    try queue.trackSent(9, "nine");

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

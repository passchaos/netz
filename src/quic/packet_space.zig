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

pub const ReceivedPacketStats = struct {
    ack_ranges: usize,
    retained_packets: u64,
    largest_received: ?u64,
    oldest_retained: ?u64,
    forgotten_through: ?u64,
    ecn_counts: ?quic.EcnCounts,
};

pub const ReceivedPacketTracker = struct {
    pub const stack_ack_range_capacity: usize = 64;

    allocator: std.mem.Allocator,
    ranges: std.ArrayList(PacketRange) = .empty,
    max_ranges: usize = 64,
    forgotten_through: ?u64 = null,
    retained_packet_count: u64 = 0,
    ecn_counts: quic.EcnCounts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 0 },
    saw_ecn: bool = false,

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

    pub fn recordWithEcn(self: *ReceivedPacketTracker, packet_number: u64, ecn: EcnCodepoint) Error!bool {
        const fresh = try self.recordFresh(packet_number);
        if (fresh and ecn != .not_ect) self.recordEcn(ecn);
        return fresh;
    }

    /// Commit a packet number already accepted by `wouldRecordFresh` while the
    /// tracker remained unchanged. Ordered traffic extends the newest range
    /// directly; reordered insertion retains the full bounded-range checks.
    pub fn recordPrevalidatedWithEcn(
        self: *ReceivedPacketTracker,
        packet_number: u64,
        ecn: EcnCodepoint,
    ) Error!bool {
        if (self.ranges.items.len != 0) {
            const newest = &self.ranges.items[0];
            if (isImmediatelyBefore(newest.end, packet_number)) {
                newest.end = packet_number;
                self.retained_packet_count += 1;
                if (ecn != .not_ect) self.recordEcn(ecn);
                return true;
            }
        }
        return self.recordWithEcn(packet_number, ecn);
    }

    pub fn wouldRecordFresh(self: ReceivedPacketTracker, packet_number: u64) Error!bool {
        if (packet_number > quic.varint.max_value) return error.InvalidPacketNumber;
        if (self.max_ranges == 0) return false;
        if (self.forgotten_through) |forgotten| {
            if (packet_number <= forgotten) return false;
        }
        if (self.ranges.items.len == 0) return true;
        const newest = self.ranges.items[0];
        if (packet_number > newest.end) return true;
        if (packet_number >= newest.start) return false;
        if (self.ranges.items.len != 0) {
            const oldest = self.ranges.items[self.ranges.items.len - 1];
            if (packet_number < oldest.start) {
                if (isImmediatelyBefore(packet_number, oldest.start)) return true;
                return self.ranges.items.len < self.max_ranges;
            }
            if (packet_number <= oldest.end) return false;
        }

        for (self.ranges.items) |range| {
            if (packet_number >= range.start and packet_number <= range.end) return false;
            if (isImmediatelyBefore(range.end, packet_number)) return true;
            if (isImmediatelyBefore(packet_number, range.start)) return true;
            if (packet_number > range.end) return true;
        }
        return self.ranges.items.len < self.max_ranges;
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
        if (self.ranges.items.len == 0) {
            return try self.insertRange(0, .{
                .start = packet_number,
                .end = packet_number,
            });
        }
        const newest = &self.ranges.items[0];
        if (packet_number > newest.end) {
            if (isImmediatelyBefore(newest.end, packet_number)) {
                newest.end = packet_number;
                self.retained_packet_count += 1;
                return true;
            }
            return try self.insertRange(0, .{
                .start = packet_number,
                .end = packet_number,
            });
        }
        if (packet_number >= newest.start) return false;
        if (self.ranges.items.len != 0) {
            const oldest_index = self.ranges.items.len - 1;
            const oldest = &self.ranges.items[oldest_index];
            if (packet_number < oldest.start) {
                if (isImmediatelyBefore(packet_number, oldest.start)) {
                    oldest.start = packet_number;
                    self.retained_packet_count += 1;
                    return true;
                }
                return try self.insertRange(
                    self.ranges.items.len,
                    .{ .start = packet_number, .end = packet_number },
                );
            }
            if (packet_number <= oldest.end) return false;
        }

        for (self.ranges.items, 0..) |*range, i| {
            if (packet_number >= range.start and packet_number <= range.end) return false;
            if (isImmediatelyBefore(range.end, packet_number)) {
                range.end = packet_number;
                self.retained_packet_count += 1;
                try self.mergeForward(i);
                return true;
            }
            if (isImmediatelyBefore(packet_number, range.start)) {
                range.start = packet_number;
                self.retained_packet_count += 1;
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
        const extra_count = self.ranges.items.len - 1;
        if (extra_count == 0) return self.ackFrameInto(&.{}, ack_delay);
        const ack_ranges = try allocator.alloc(quic.AckRange, extra_count);
        errdefer allocator.free(ack_ranges);
        return self.ackFrameInto(ack_ranges, ack_delay);
    }

    /// Build an ACK frame using caller-provided storage for additional ranges.
    ///
    /// ACK emission can happen on every packet-processing turn and mature QUIC
    /// stacks avoid heap traffic on this hot path.  `ackFrame` remains as the
    /// owning convenience wrapper; runtimes with bounded ACK history can pass a
    /// stack buffer here and send reordered ACK ranges allocation-free.
    pub fn ackFrameInto(self: ReceivedPacketTracker, ack_ranges: []quic.AckRange, ack_delay: u64) Error!quic.AckFrame {
        if (self.ranges.items.len == 0) return error.InvalidAckFrame;
        const largest = self.ranges.items[0];
        const extra_count = self.ranges.items.len - 1;
        if (ack_ranges.len < extra_count) return error.TooManyAckRanges;
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
            .ranges = ack_ranges[0..extra_count],
            .ecn_counts = if (self.saw_ecn) self.ecn_counts else null,
        };
    }

    pub fn recordEcn(self: *ReceivedPacketTracker, ecn: EcnCodepoint) void {
        switch (ecn) {
            .not_ect => {},
            .ect0 => {
                self.ecn_counts.ect0_count += 1;
                self.saw_ecn = true;
            },
            .ect1 => {
                self.ecn_counts.ect1_count += 1;
                self.saw_ecn = true;
            },
            .ce => {
                self.ecn_counts.ecn_ce_count += 1;
                self.saw_ecn = true;
            },
        }
    }

    pub fn latestEcnCounts(self: ReceivedPacketTracker) ?quic.EcnCounts {
        return if (self.saw_ecn) self.ecn_counts else null;
    }

    pub fn largestReceived(self: ReceivedPacketTracker) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[0].end;
    }

    pub fn stats(self: ReceivedPacketTracker) ReceivedPacketStats {
        return .{
            .ack_ranges = self.ranges.items.len,
            .retained_packets = self.retained_packet_count,
            .largest_received = self.largestReceived(),
            .oldest_retained = if (self.ranges.items.len == 0)
                null
            else
                self.ranges.items[self.ranges.items.len - 1].start,
            .forgotten_through = self.forgotten_through,
            .ecn_counts = self.latestEcnCounts(),
        };
    }

    pub fn getStats(self: ReceivedPacketTracker) ReceivedPacketStats {
        return self.stats();
    }

    pub fn pruneAckedRanges(self: *ReceivedPacketTracker, largest_acknowledged: u64) void {
        self.forgetThrough(largest_acknowledged);
        if (self.ranges.items.len == 0) return;
        const oldest = self.ranges.items[self.ranges.items.len - 1];
        if (largest_acknowledged < oldest.start) return;
        while (self.ranges.items.len != 0) {
            const last_index = self.ranges.items.len - 1;
            const oldest_range = &self.ranges.items[last_index];
            if (oldest_range.end <= largest_acknowledged) {
                self.retained_packet_count -|= oldest_range.len();
                _ = self.ranges.pop();
                continue;
            }
            if (oldest_range.start <= largest_acknowledged) {
                self.retained_packet_count -|= largest_acknowledged - oldest_range.start + 1;
                oldest_range.start = largest_acknowledged + 1;
            }
            break;
        }
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
            self.retained_packet_count -|= oldest.len();
            _ = self.ranges.pop();
        }

        if (index == self.ranges.items.len) {
            try self.ranges.append(self.allocator, range);
        } else {
            try self.ranges.insert(self.allocator, index, range);
        }
        self.retained_packet_count += range.len();
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
            if (index == self.ranges.items.len - 1) {
                _ = self.ranges.pop();
            } else {
                _ = self.ranges.orderedRemove(index);
            }
        }
    }

    fn mergeBackward(self: *ReceivedPacketTracker, index: usize) Error!void {
        if (index + 1 >= self.ranges.items.len) return;
        const current = &self.ranges.items[index];
        const next = &self.ranges.items[index + 1];
        if (rangesOverlapOrAdjacent(next.*, current.*)) {
            current.start = @min(current.start, next.start);
            current.end = @max(current.end, next.end);
            const remove_index = index + 1;
            if (remove_index == self.ranges.items.len - 1) {
                _ = self.ranges.pop();
            } else {
                _ = self.ranges.orderedRemove(remove_index);
            }
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
    in_flight: bool = true,
    acknowledged: bool = false,
    lost: bool = false,
    loss_reported: bool = false,
    bytes: usize = 0,
    /// Full protected datagram size on the wire for this packet.
    ///
    /// Recovery and congestion track only payload bytes in `bytes`, but PMTU
    /// black-hole detection needs the actual protected datagram length to
    /// determine whether an ordinary packet exercised the validated MTU.
    datagram_size: usize = 0,
    ecn: EcnCodepoint = .not_ect,
    sent_time_ns: ?u64 = null,
    pmtu_probe_size: ?usize = null,
    pmtu_probe_epoch: u32 = 0,
    /// Path-generation marker for path-local recovery and PMTU evidence.
    ///
    /// PMTU black-hole heuristics reset when the peer address changes, but ACK
    /// and loss processing can still drain old-path packets afterward. Keeping
    /// the path epoch per sent packet lets `one_rtt` retire and retransmit old
    /// packets without feeding their ACK/loss/RTT signals into the replacement
    /// path's congestion controller.
    pmtu_path_epoch: u32 = 0,
    largest_acknowledged_sent: ?u64 = null,
    lost_generation: u32 = 0,
};

test "QUIC sent packet metadata stays compact" {
    // Work/quic-zig's historic ACK tracker stored per-stream frame arrays
    // inline, making each sent-packet record cache-unfriendly.  netz stores
    // stable recovery payloads separately; keep this metadata object small so
    // packet-number scans remain L1-cache friendly.
    try std.testing.expect(@sizeOf(SentPacket) <= 128);
}

pub const EcnCodepoint = enum {
    not_ect,
    ect0,
    ect1,
    ce,
};

pub const SentPacketStats = struct {
    tracked_packets: usize,
    ack_eliciting_packets: usize,
    in_flight_packets: usize,
    ack_eliciting_in_flight_packets: usize,
    latest_ack_eliciting_in_flight_sent_time_ns: ?u64,
    acknowledged_packets: usize,
    lost_packets: usize,
    bytes_in_flight: usize,
    sent_ect0_count: u64,
    sent_ect1_count: u64,
    /// Deprecated compatibility latch for callers that used the old
    /// tracker-global ECN disable bit. Automatic ECN fallback now lives in
    /// `quic.ecn.PathState` and must not depend on this manual override.
    ecn_validation_failed: bool,
};

pub const SentPacketTracker = struct {
    const compact_acknowledged_threshold: usize = 256;

    allocator: std.mem.Allocator,
    packets: std.ArrayList(SentPacket) = .empty,
    packets_sorted_ascending: bool = true,
    /// Packet-number lookups feed RTT sampling, ack bookkeeping, and send
    /// rollback after partial writes. `packets` remains ordered for ACK/loss
    /// range scans; this index keeps exact packet operations from walking the
    /// whole sent-packet history.
    packet_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// First metadata entry not yet acknowledged by the peer.
    ///
    /// ACK ranges are cumulative in steady traffic, so rescanning the entire
    /// acknowledged prefix makes an otherwise constant-cost ACK grow with the
    /// connection lifetime. The packet array remains intact for duplicate ACK
    /// validation and diagnostics; hot ACK/loss scans start at this cursor.
    first_unacknowledged_index: usize = 0,
    /// Contiguous sent packet-number prefix whose metadata was compacted after
    /// acknowledgement. Retaining the exact inclusive bounds lets duplicate
    /// cumulative ACKs remain valid without keeping one record per packet.
    retired_acknowledged_start: ?u64 = null,
    retired_acknowledged_through: ?u64 = null,
    /// PTO scheduling needs the newest still-in-flight ack-eliciting packet on
    /// every timer query.  Keep its packet-list index cached, mirroring the
    /// last-ack-eliciting timestamp maintained by production QUIC recovery
    /// implementations, and recompute only when that exact packet is acked,
    /// lost, or removed.
    latest_ack_eliciting_in_flight_index: ?usize = null,
    largest_acknowledged: ?u64 = null,
    latest_ecn_counts: quic.EcnCounts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 0 },
    ecn_largest_acknowledged: ?u64 = null,
    /// Highest ECN-capable packet acknowledged so far. Comparing this
    /// monotonic watermark with `ecn_largest_acknowledged` answers whether a
    /// later cumulative ACK_ECN needs a baseline-only update without scanning
    /// retained packet metadata (which may already have been compacted).
    largest_acknowledged_ect: ?u64 = null,
    /// Deprecated compatibility latch preserved for older callers that
    /// explicitly disabled ECN validation on the packet-number-space tracker.
    ///
    /// The new automatic ECN sender state is path-local and lives above this
    /// tracker in `one_rtt`. Keeping this bit manual-only avoids letting
    /// legacy source-compat APIs silently influence path migration resets or
    /// automatic ECT(0) fallback decisions.
    deprecated_ecn_validation_failed: bool = false,
    sent_ect0_count: u64 = 0,
    sent_ect1_count: u64 = 0,
    loss_generation: u32 = 0,

    pub fn init(allocator: std.mem.Allocator) SentPacketTracker {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SentPacketTracker) void {
        self.packets.deinit(self.allocator);
        self.packet_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sent(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize) !void {
        try self.sentWithEcn(packet_number, ack_eliciting, bytes, .not_ect);
    }

    pub fn sentWithEcn(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, ecn: EcnCodepoint) !void {
        try self.sentAt(packet_number, ack_eliciting, bytes, ecn, null);
    }

    pub fn sentAt(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64) !void {
        try self.sentAtWithDatagramSize(packet_number, ack_eliciting, bytes, bytes, ecn, sent_time_ns);
    }

    pub fn sentAtWithPmtu(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize) !void {
        try self.sentInFlightAtWithPmtuAndDatagramSize(
            packet_number,
            ack_eliciting,
            ack_eliciting,
            bytes,
            if (pmtu_probe_size) |size| size else bytes,
            ecn,
            sent_time_ns,
            pmtu_probe_size,
            0,
        );
    }

    pub fn sentAtWithPmtuAndDatagramSize(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize) !void {
        try self.sentAtWithPmtuAndDatagramSizeAndEpoch(packet_number, ack_eliciting, bytes, datagram_size, ecn, sent_time_ns, pmtu_probe_size, 0);
    }

    pub fn sentAtWithPmtuAndDatagramSizeAndEpoch(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, pmtu_probe_epoch: u32) !void {
        try self.sentInFlightAtWithPmtuAndDatagramSizeAndEpochAndPathEpoch(
            packet_number,
            ack_eliciting,
            ack_eliciting,
            bytes,
            datagram_size,
            ecn,
            sent_time_ns,
            pmtu_probe_size,
            pmtu_probe_epoch,
            pmtu_probe_epoch,
        );
    }

    pub fn sentAtWithDatagramSize(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64) !void {
        try self.sentAtWithDatagramSizeAndPathEpoch(
            packet_number,
            ack_eliciting,
            bytes,
            datagram_size,
            ecn,
            sent_time_ns,
            0,
        );
    }

    pub fn sentAtWithDatagramSizeAndPathEpoch(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_path_epoch: u32) !void {
        try self.sentInFlightAtWithDatagramSizeAndPathEpoch(
            packet_number,
            ack_eliciting,
            ack_eliciting,
            bytes,
            datagram_size,
            ecn,
            sent_time_ns,
            pmtu_path_epoch,
        );
    }

    pub fn sentInFlightAt(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64) !void {
        try self.sentInFlightAtWithDatagramSize(packet_number, ack_eliciting, in_flight, bytes, bytes, ecn, sent_time_ns);
    }

    pub fn sentInFlightAtWithPmtu(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize) !void {
        try self.sentInFlightAtWithPmtuAndDatagramSize(
            packet_number,
            ack_eliciting,
            in_flight,
            bytes,
            if (pmtu_probe_size) |size| size else bytes,
            ecn,
            sent_time_ns,
            pmtu_probe_size,
            0,
        );
    }

    pub fn sentInFlightAtWithDatagramSize(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64) !void {
        try self.sentInFlightAtWithDatagramSizeAndPathEpoch(
            packet_number,
            ack_eliciting,
            in_flight,
            bytes,
            datagram_size,
            ecn,
            sent_time_ns,
            0,
        );
    }

    pub fn sentInFlightAtWithPmtuAndDatagramSize(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, pmtu_probe_epoch: u32) !void {
        try self.sentInFlightAtWithPmtuAndDatagramSizeAndEpochAndPathEpoch(
            packet_number,
            ack_eliciting,
            in_flight,
            bytes,
            datagram_size,
            ecn,
            sent_time_ns,
            pmtu_probe_size,
            pmtu_probe_epoch,
            pmtu_probe_epoch,
        );
    }

    pub fn sentInFlightAtWithDatagramSizeAndPathEpoch(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_path_epoch: u32) !void {
        try self.sentInFlightAtWithStoredMetadata(packet_number, ack_eliciting, in_flight, bytes, datagram_size, ecn, sent_time_ns, null, 0, pmtu_path_epoch, null);
    }

    pub fn sentInFlightAtWithPmtuAndDatagramSizeAndEpochAndPathEpoch(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, pmtu_probe_epoch: u32, pmtu_path_epoch: u32) !void {
        try self.sentInFlightAtWithStoredMetadata(packet_number, ack_eliciting, in_flight, bytes, datagram_size, ecn, sent_time_ns, pmtu_probe_size, pmtu_probe_epoch, pmtu_path_epoch, null);
    }

    pub fn sentInFlightAtWithMetadata(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, largest_acknowledged_sent: ?u64) !void {
        try self.sentInFlightAtWithExactDatagramMetadata(packet_number, ack_eliciting, in_flight, bytes, bytes, ecn, sent_time_ns, pmtu_probe_size, largest_acknowledged_sent);
    }

    pub fn sentInFlightAtWithExactDatagramMetadata(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, largest_acknowledged_sent: ?u64) !void {
        try self.sentInFlightAtWithExactDatagramMetadataAndPathEpoch(packet_number, ack_eliciting, in_flight, bytes, datagram_size, ecn, sent_time_ns, pmtu_probe_size, 0, largest_acknowledged_sent);
    }

    pub fn sentInFlightAtWithExactDatagramMetadataAndPathEpoch(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, pmtu_path_epoch: u32, largest_acknowledged_sent: ?u64) !void {
        try self.sentInFlightAtWithStoredMetadata(packet_number, ack_eliciting, in_flight, bytes, datagram_size, ecn, sent_time_ns, pmtu_probe_size, 0, pmtu_path_epoch, largest_acknowledged_sent);
    }

    pub fn rewritePacketEcn(
        self: *SentPacketTracker,
        packet_number: u64,
        ecn: EcnCodepoint,
    ) bool {
        const index = self.findPacketIndex(packet_number) orelse return false;
        const packet = &self.packets.items[index];
        if (packet.ecn == ecn) return true;
        switch (packet.ecn) {
            .not_ect, .ce => {},
            .ect0 => self.sent_ect0_count -|= 1,
            .ect1 => self.sent_ect1_count -|= 1,
        }
        switch (ecn) {
            .not_ect, .ce => {},
            .ect0 => self.sent_ect0_count +|= 1,
            .ect1 => self.sent_ect1_count +|= 1,
        }
        packet.ecn = ecn;
        return true;
    }

    fn sentInFlightAtWithStoredMetadata(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, datagram_size: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, pmtu_probe_epoch: u32, pmtu_path_epoch: u32, largest_acknowledged_sent: ?u64) !void {
        const monotonic_append = self.packets.items.len == 0 or
            packet_number > self.packets.items[self.packets.items.len - 1].packet_number;
        // Packet numbers issued by a QUIC packet number space are normally
        // strictly increasing. In that hot path, the tail comparison proves the
        // packet is new and avoids an exact-index lookup before every send.
        // Tests and rollback helpers can still insert out of order, so the
        // conservative duplicate check remains for the uncommon non-monotonic
        // path.
        if (!monotonic_append) {
            if (self.findPacketIndex(packet_number) != null) return error.DuplicatePacket;
        }
        const packet_storage_available = self.packets.items.len < self.packets.capacity;
        // Some send paths pre-reserve packet metadata and deliberately run
        // under a no-allocation guard to verify protected packet storage reuse.
        // Grow the exact lookup index only when the packet list itself is about
        // to allocate; otherwise use already-reserved map slots and let lookup
        // helpers fall back to the ordered packet list if the map is also full.
        if (!packet_storage_available) {
            try self.packet_index.ensureUnusedCapacity(self.allocator, 1);
        }
        if (!monotonic_append) {
            self.packets_sorted_ascending = false;
        }
        try self.packets.append(self.allocator, .{
            .packet_number = packet_number,
            .ack_eliciting = ack_eliciting,
            .in_flight = in_flight,
            .bytes = if (in_flight) bytes else 0,
            .datagram_size = datagram_size,
            .ecn = ecn,
            .sent_time_ns = sent_time_ns,
            .pmtu_probe_size = pmtu_probe_size,
            .pmtu_probe_epoch = pmtu_probe_epoch,
            .pmtu_path_epoch = pmtu_path_epoch,
            .largest_acknowledged_sent = largest_acknowledged_sent,
        });
        const index = self.packets.items.len - 1;
        if (self.packetIndexHasUnusedCapacity()) {
            self.packet_index.putAssumeCapacityNoClobber(packet_number, index);
        }
        self.considerLatestAckElicitingInFlight(index);
        switch (ecn) {
            .not_ect => {},
            .ect0 => self.sent_ect0_count += 1,
            .ect1 => self.sent_ect1_count += 1,
            .ce => {},
        }
    }

    pub fn forget(self: *SentPacketTracker, packet_number: u64) bool {
        if (self.packets.items.len == 0) return false;
        const tail_index = self.packets.items.len - 1;
        if (self.packets.items[tail_index].packet_number == packet_number) {
            const latest = self.latest_ack_eliciting_in_flight_index;
            self.decrementSentEcnCount(self.packets.items[tail_index].ecn);
            _ = self.packets.pop();
            _ = self.packet_index.remove(packet_number);
            self.first_unacknowledged_index = @min(
                self.first_unacknowledged_index,
                self.packets.items.len,
            );
            if (latest == tail_index) {
                self.recomputeLatestAckElicitingInFlight();
            }
            return true;
        }
        const index = self.findPacketIndex(packet_number) orelse return false;
        const latest = self.latest_ack_eliciting_in_flight_index;
        self.decrementSentEcnCount(self.packets.items[index].ecn);
        _ = self.packets.orderedRemove(index);
        _ = self.packet_index.remove(packet_number);
        if (index < self.first_unacknowledged_index) {
            self.first_unacknowledged_index -= 1;
        }
        if (index < self.packets.items.len) {
            self.refreshPacketIndexFrom(index);
        }
        if (latest == index) {
            self.recomputeLatestAckElicitingInFlight();
        } else if (latest != null and latest.? > index) {
            self.latest_ack_eliciting_in_flight_index = latest.? - 1;
        }
        self.advanceFirstUnacknowledged();
        return true;
    }

    fn decrementSentEcnCount(
        self: *SentPacketTracker,
        ecn: EcnCodepoint,
    ) void {
        switch (ecn) {
            .not_ect, .ce => {},
            .ect0 => self.sent_ect0_count -|= 1,
            .ect1 => self.sent_ect1_count -|= 1,
        }
    }

    pub fn markAcknowledged(self: *SentPacketTracker, packet_number: u64) bool {
        const index = self.findPacketIndex(packet_number) orelse return false;
        if (!self.packets.items[index].acknowledged) {
            self.packets.items[index].acknowledged = true;
            self.observeAcknowledgedEct(self.packets.items[index]);
            if (self.latest_ack_eliciting_in_flight_index == index) {
                self.recomputeLatestAckElicitingInFlight();
            }
        }
        self.observeAcknowledged(packet_number);
        self.advanceFirstUnacknowledged();
        return true;
    }

    pub fn largestAcknowledged(self: SentPacketTracker) ?u64 {
        return self.largest_acknowledged;
    }

    pub fn hasAcknowledgedAtOrAbove(self: SentPacketTracker, threshold: u64) bool {
        const largest = self.largest_acknowledged orelse return false;
        return largest >= threshold;
    }

    pub fn stats(self: SentPacketTracker) SentPacketStats {
        var ack_eliciting_packets: usize = 0;
        var in_flight_packets: usize = 0;
        var ack_eliciting_in_flight_packets: usize = 0;
        var acknowledged_packets: usize = 0;
        var lost_packets: usize = 0;
        var bytes_in_flight: usize = 0;
        for (self.packets.items) |packet| {
            if (packet.ack_eliciting) ack_eliciting_packets += 1;
            if (packet.in_flight and !packet.acknowledged and !packet.lost) {
                in_flight_packets += 1;
                bytes_in_flight += packet.bytes;
                if (packet.ack_eliciting) {
                    ack_eliciting_in_flight_packets += 1;
                }
            }
            if (packet.acknowledged) acknowledged_packets += 1;
            if (packet.lost) lost_packets += 1;
        }
        return .{
            .tracked_packets = self.packets.items.len,
            .ack_eliciting_packets = ack_eliciting_packets,
            .in_flight_packets = in_flight_packets,
            .ack_eliciting_in_flight_packets = ack_eliciting_in_flight_packets,
            .latest_ack_eliciting_in_flight_sent_time_ns = self.latestAckElicitingInFlightSentTime(),
            .acknowledged_packets = acknowledged_packets,
            .lost_packets = lost_packets,
            .bytes_in_flight = bytes_in_flight,
            .sent_ect0_count = self.sent_ect0_count,
            .sent_ect1_count = self.sent_ect1_count,
            .ecn_validation_failed = self.deprecated_ecn_validation_failed,
        };
    }

    pub fn getStats(self: SentPacketTracker) SentPacketStats {
        return self.stats();
    }

    pub const AckResult = struct {
        packets: usize = 0,
        ack_eliciting_packets: usize = 0,
        bytes: usize = 0,
        probe_bytes: usize = 0,
        /// Path-local subset of the totals above. Protocol bookkeeping still
        /// consumes every ACK/loss, while congestion state consumes only the
        /// currently selected path epoch.
        current_path_bytes: usize = 0,
        current_path_probe_bytes: usize = 0,
        current_path_ack_eliciting_packets: usize = 0,
        ect0_packets: usize = 0,
        ect1_packets: usize = 0,
        current_path_ect0_packets: usize = 0,
        current_path_ect1_packets: usize = 0,
        /// The accepted ACK_ECN advanced the packet-number-space counter
        /// baseline. Connection-level path validation uses this when draining
        /// ambiguous evidence left by a retired path.
        ecn_counts_updated: bool = false,
        largest_packet_number: ?u64 = null,
        largest_sent_time_ns: ?u64 = null,
        ecn_ce_delta: u64 = 0,
        active_pmtu_probe_packet_number: ?u64 = null,
        active_pmtu_probe_size: ?usize = null,
        active_pmtu_probe_epoch: u32 = 0,
        largest_pmtu_acked_packet_number: ?u64 = null,
        largest_pmtu_acked_datagram_size: ?usize = null,
        current_path_largest_packet_number: ?u64 = null,
        current_path_largest_sent_time_ns: ?u64 = null,
        current_path_largest_nonprobe_packet_number: ?u64 = null,
        current_path_largest_nonprobe_sent_time_ns: ?u64 = null,
        largest_nonprobe_packet_number: ?u64 = null,
        largest_nonprobe_datagram_size: ?usize = null,
        largest_nonprobe_sent_time_ns: ?u64 = null,
        largest_nonprobe_path_epoch: u32 = 0,
        largest_acknowledged_sent: ?u64 = null,
        /// Earliest still-in-flight packet eligible for a later
        /// time-threshold loss check after this detection pass.
        next_loss_time_ns: ?u64 = null,

        fn observe(self: *AckResult, packet_number: u64, sent_time_ns: ?u64) void {
            if (self.largest_packet_number == null or packet_number > self.largest_packet_number.?) {
                self.largest_packet_number = packet_number;
                self.largest_sent_time_ns = sent_time_ns;
            }
        }

        fn observeCurrentPath(
            self: *AckResult,
            packet_number: u64,
            sent_time_ns: ?u64,
        ) void {
            if (self.current_path_largest_packet_number == null or
                packet_number > self.current_path_largest_packet_number.?)
            {
                self.current_path_largest_packet_number = packet_number;
                self.current_path_largest_sent_time_ns = sent_time_ns;
            }
        }

        fn observeCurrentPathNonProbe(
            self: *AckResult,
            packet_number: u64,
            sent_time_ns: ?u64,
        ) void {
            if (self.current_path_largest_nonprobe_packet_number == null or
                packet_number >
                    self.current_path_largest_nonprobe_packet_number.?)
            {
                self.current_path_largest_nonprobe_packet_number =
                    packet_number;
                self.current_path_largest_nonprobe_sent_time_ns =
                    sent_time_ns;
            }
        }

        fn observeAckedPmtu(self: *AckResult, packet_number: u64, datagram_size: usize) void {
            if (self.largest_pmtu_acked_packet_number == null or packet_number > self.largest_pmtu_acked_packet_number.?) {
                self.largest_pmtu_acked_packet_number = packet_number;
                self.largest_pmtu_acked_datagram_size = datagram_size;
            }
        }

        fn observeNonProbe(
            self: *AckResult,
            packet_number: u64,
            datagram_size: usize,
            sent_time_ns: ?u64,
            path_epoch: u32,
        ) void {
            if (self.largest_nonprobe_packet_number == null or packet_number > self.largest_nonprobe_packet_number.?) {
                self.largest_nonprobe_packet_number = packet_number;
                self.largest_nonprobe_datagram_size = datagram_size;
                self.largest_nonprobe_sent_time_ns = sent_time_ns;
                self.largest_nonprobe_path_epoch = path_epoch;
            }
        }

        fn observeActiveProbe(self: *AckResult, packet_number: u64, probe_size: usize, probe_epoch: u32) void {
            self.active_pmtu_probe_packet_number = packet_number;
            self.active_pmtu_probe_size = probe_size;
            self.active_pmtu_probe_epoch = probe_epoch;
        }
    };

    const EcnAckValidation = struct {
        update_counts: bool = false,
        ce_delta: u64 = 0,
    };

    const NewlyAckedEctCounts = struct {
        ect0: u64 = 0,
        ect1: u64 = 0,
    };

    const AckedRange = struct {
        start: u64,
        end: u64,
    };

    const DecodedAckRanges = struct {
        ranges: []AckedRange,
        heap_allocated: bool,

        fn deinit(self: DecodedAckRanges, allocator: std.mem.Allocator) void {
            if (self.heap_allocated) allocator.free(self.ranges);
        }
    };

    const AckPrecheck = struct {
        total_span: u64 = 0,
        sent_packets: u64 = 0,
        newly_acked_packets: usize = 0,
        newly_acked_ect: NewlyAckedEctCounts = .{},
        current_path_newly_acked_ect: NewlyAckedEctCounts = .{},

        fn observeSentPacket(self: *AckPrecheck, packet: SentPacket) void {
            self.sent_packets += 1;
            self.observeNewlyAckedPacket(packet, null);
        }

        fn observeNewlyAckedPacket(
            self: *AckPrecheck,
            packet: SentPacket,
            current_path_epoch: ?u32,
        ) void {
            if (packet.acknowledged) return;
            self.newly_acked_packets += 1;
            switch (packet.ecn) {
                .not_ect => {},
                .ect0 => self.newly_acked_ect.ect0 += 1,
                .ect1 => self.newly_acked_ect.ect1 += 1,
                .ce => {},
            }
            if (current_path_epoch) |epoch| {
                if (packet.pmtu_path_epoch != epoch) return;
            }
            switch (packet.ecn) {
                .not_ect => {},
                .ect0 => self.current_path_newly_acked_ect.ect0 += 1,
                .ect1 => self.current_path_newly_acked_ect.ect1 += 1,
                .ce => {},
            }
        }
    };

    /// Summary of ACK range validation performed before packet-level side
    /// effects. The sent tracker and ACK range storage must remain unchanged
    /// until the matching apply call consumes this token.
    pub const ValidatedAck = struct {
        largest_acknowledged: u64,
        first_ack_range: u64,
        ranges_ptr: usize,
        ranges_len: usize,
        current_path_epoch: ?u32,
        precheck: AckPrecheck,

        fn matches(
            self: ValidatedAck,
            ack: quic.AckFrame,
            current_path_epoch: ?u32,
        ) bool {
            return self.largest_acknowledged == ack.largest_acknowledged and
                self.first_ack_range == ack.first_ack_range and
                self.ranges_ptr == @intFromPtr(ack.ranges.ptr) and
                self.ranges_len == ack.ranges.len and
                self.current_path_epoch == current_path_epoch;
        }
    };

    pub const RttSample = struct {
        latest_rtt_ns: u64,
        ack_delay_ns: u64,
        largest_acknowledged: u64,
        sent_time_ns: u64,
    };

    pub const PersistentCongestionPeriod = struct {
        start_packet_number: u64,
        end_packet_number: u64,
        start_time_ns: u64,
        end_time_ns: u64,

        pub fn durationNs(self: PersistentCongestionPeriod) u64 {
            return self.end_time_ns -| self.start_time_ns;
        }
    };

    const PersistentCongestionBuilder = struct {
        period: PersistentCongestionPeriod,
        previous_packet_number: u64,
    };

    pub fn applyAck(self: *SentPacketTracker, ack: quic.AckFrame) Error!usize {
        return (try self.applyAckDetailed(ack)).packets;
    }

    pub fn ackRttSample(self: SentPacketTracker, ack: quic.AckFrame, now_ns: u64, ack_delay_exponent: u64) Error!?RttSample {
        return self.ackRttSampleForPathEpoch(
            ack,
            now_ns,
            ack_delay_exponent,
            null,
        );
    }

    pub fn ackRttSampleForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        now_ns: u64,
        ack_delay_exponent: u64,
        current_path_epoch: ?u32,
    ) Error!?RttSample {
        if (self.ackDoesNotAdvanceLargest(ack.largest_acknowledged)) return null;
        const packet = self.findSentPacket(ack.largest_acknowledged) orelse return null;
        if (packet.acknowledged) return null;
        if (!packetMatchesPathEpoch(packet, current_path_epoch)) return null;
        if (!self.ackContainsNewAckElicitingForPathEpoch(
            ack,
            current_path_epoch,
        )) return null;
        const sent_time = packet.sent_time_ns orelse return null;
        const latest_rtt = now_ns -| sent_time;
        return .{
            .latest_rtt_ns = latest_rtt,
            .ack_delay_ns = quic.rtt.decodeAckDelayNanos(ack.ack_delay, ack_delay_exponent) catch return error.InvalidAckFrame,
            .largest_acknowledged = ack.largest_acknowledged,
            .sent_time_ns = sent_time,
        };
    }

    pub fn applyAckDetailed(self: *SentPacketTracker, ack: quic.AckFrame) Error!AckResult {
        return self.applyAckDetailedForProbe(ack, null, 0, null, null);
    }

    pub fn applyAckDetailedForProbe(
        self: *SentPacketTracker,
        ack: quic.AckFrame,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        pmtu_ack_threshold: ?usize,
        pmtu_path_epoch: ?u32,
    ) Error!AckResult {
        return self.applyAckDetailedForProbeValidated(
            ack,
            active_probe_packet_number,
            active_probe_epoch,
            pmtu_ack_threshold,
            pmtu_path_epoch,
            null,
        );
    }

    pub fn applyAckDetailedForProbeValidated(
        self: *SentPacketTracker,
        ack: quic.AckFrame,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        pmtu_ack_threshold: ?usize,
        pmtu_path_epoch: ?u32,
        validated: ?ValidatedAck,
    ) Error!AckResult {
        if (self.packets.items.len == 0 and
            self.retired_acknowledged_through == null)
        {
            return error.InvalidAckFrame;
        }
        var stack_ranges: [32]AckedRange = undefined;
        const decoded = try decodeAckRanges(self.allocator, ack, &stack_ranges);
        defer decoded.deinit(self.allocator);
        const sorted = self.packetsSortedAscending();
        const precheck = if (validated) |prevalidated| blk: {
            if (!prevalidated.matches(ack, pmtu_path_epoch)) {
                return error.InvalidAckFrame;
            }
            break :blk prevalidated.precheck;
        } else try self.precheckAckRanges(
            decoded.ranges,
            sorted,
            pmtu_path_epoch,
        );
        const ecn_validation = try self.validateAckEcnFrameDetailedForPrecheck(
            ack,
            precheck,
        );

        var acked: AckResult = .{};
        if (precheck.newly_acked_packets != 0) {
            acked = self.markRanges(
                decoded.ranges,
                sorted,
                active_probe_packet_number,
                active_probe_epoch,
                pmtu_ack_threshold,
                pmtu_path_epoch,
            );
        }
        acked.ecn_counts_updated = ecn_validation.update_counts;
        if (ack.ecn_counts) |ecn_counts| {
            if (ecn_validation.update_counts) {
                self.latest_ecn_counts = ecn_counts;
                self.ecn_largest_acknowledged = ack.largest_acknowledged;
                acked.ecn_ce_delta = ecn_validation.ce_delta;
            }
        }
        self.compactAcknowledgedPrefix();
        return acked;
    }

    pub fn currentLossGeneration(self: SentPacketTracker) u32 {
        return self.loss_generation;
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
        if (self.packets.items.len == 0) return error.InvalidAckFrame;
        if (self.packetsSortedAscending()) {
            return self.validateAckCoversSortedSentPackets(ack);
        }
        _ = try self.validateAckForApply(ack, null);
    }

    /// The validation-only call does not need the ECN/path/newly-acked summary
    /// produced by `precheckAckRanges`. For ordered metadata, range cardinality
    /// plus two binary searches proves every acknowledged number was sent,
    /// including the compacted acknowledged prefix, without visiting each
    /// packet record or materializing decoded ranges.
    fn validateAckCoversSortedSentPackets(
        self: SentPacketTracker,
        ack: quic.AckFrame,
    ) Error!void {
        if (ack.largest_acknowledged < ack.first_ack_range) {
            return error.InvalidAckFrame;
        }

        var range_start = ack.largest_acknowledged - ack.first_ack_range;
        var range_end = ack.largest_acknowledged;
        if (!self.sentCoverageMatchesRange(range_start, range_end)) {
            return error.InvalidAckFrame;
        }
        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch
                return error.InvalidAckFrame;
            if (range_start < skipped) return error.InvalidAckFrame;
            range_end = range_start - skipped;
            if (range_end < range.ack_range_length) {
                return error.InvalidAckFrame;
            }
            range_start = range_end - range.ack_range_length;
            if (!self.sentCoverageMatchesRange(range_start, range_end)) {
                return error.InvalidAckFrame;
            }
        }
    }

    fn sentCoverageMatchesRange(
        self: SentPacketTracker,
        range_start: u64,
        range_end: u64,
    ) bool {
        const expected = std.math.add(
            u64,
            range_end - range_start,
            1,
        ) catch return false;
        const start_index = self.lowerBoundPacketIndex(range_start);
        const end_index = self.upperBoundPacketIndex(range_end);
        const retained: u64 = @intCast(end_index - start_index);
        const retired = self.retiredIntersectionLen(.{
            .start = range_start,
            .end = range_end,
        });
        return retained + retired == expected;
    }

    pub fn validateAckForApply(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) Error!ValidatedAck {
        if (self.packets.items.len == 0) return error.InvalidAckFrame;
        var stack_ranges: [32]AckedRange = undefined;
        const decoded = try decodeAckRanges(
            self.allocator,
            ack,
            &stack_ranges,
        );
        defer decoded.deinit(self.allocator);
        const precheck = try self.precheckAckRanges(
            decoded.ranges,
            self.packetsSortedAscending(),
            current_path_epoch,
        );
        return .{
            .largest_acknowledged = ack.largest_acknowledged,
            .first_ack_range = ack.first_ack_range,
            .ranges_ptr = @intFromPtr(ack.ranges.ptr),
            .ranges_len = ack.ranges.len,
            .current_path_epoch = current_path_epoch,
            .precheck = precheck,
        };
    }

    pub fn validateAckEcnCounters(self: SentPacketTracker, counts: quic.EcnCounts) Error!void {
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

    pub fn validateAckEcnFrame(self: SentPacketTracker, ack: quic.AckFrame) Error!void {
        _ = try self.validateAckEcnFrameDetailed(ack);
    }

    pub fn validateAckEcnFrameForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) Error!void {
        _ = try self.validateAckEcnFrameDetailedForPathEpoch(
            ack,
            current_path_epoch,
        );
    }

    pub fn validateAckEcnFrameWouldFail(self: SentPacketTracker, ack: quic.AckFrame) bool {
        _ = self.validateAckEcnFrameDetailed(ack) catch return true;
        return false;
    }

    pub fn validateAckEcnFrameWouldFailForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) bool {
        _ = self.validateAckEcnFrameDetailedForPathEpoch(
            ack,
            current_path_epoch,
        ) catch return true;
        return false;
    }

    fn validateAckEcnFrameDetailed(self: SentPacketTracker, ack: quic.AckFrame) Error!EcnAckValidation {
        return self.validateAckEcnFrameDetailedForPathEpoch(ack, null);
    }

    fn validateAckEcnFrameDetailedForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) Error!EcnAckValidation {
        var stack_ranges: [32]AckedRange = undefined;
        const decoded = try decodeAckRanges(
            self.allocator,
            ack,
            &stack_ranges,
        );
        defer decoded.deinit(self.allocator);
        const precheck = try self.precheckAckRanges(
            decoded.ranges,
            self.packetsSortedAscending(),
            current_path_epoch,
        );
        return self.validateAckEcnFrameDetailedForPrecheck(ack, precheck);
    }

    fn validateAckEcnFrameDetailedForPrecheck(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        precheck: AckPrecheck,
    ) Error!EcnAckValidation {
        const counts = ack.ecn_counts orelse return .{};

        // RFC 9000 §13.4.2.1 permits reordered ACK_ECN frames.  Once ECN has
        // been validated for a larger ACK, older ACK_ECN counters are only
        // historical information; do not reject them for being lower than the
        // most recent counters, and do not generate a second CE event.
        if (self.ecn_largest_acknowledged) |previous_largest| {
            if (ack.largest_acknowledged <= previous_largest) return .{};
        }

        try self.validateAckEcnCounters(counts);
        const all_newly_acked = precheck.newly_acked_ect;
        if (all_newly_acked.ect0 == 0 and all_newly_acked.ect1 == 0) {
            // ACK_ECN counters are cumulative for the packet number space, not
            // scoped to the currently selected path. Even when this ACK only
            // advances old-path ECN history, keep the global baseline in sync
            // so a later current-path ACK_ECN cannot smuggle a stale old-path
            // increase past the delta checks.
            return .{ .update_counts = true };
        }

        const previous = self.latest_ecn_counts;
        const ect0_delta = counts.ect0_count - previous.ect0_count;
        const ect1_delta = counts.ect1_count - previous.ect1_count;
        const ce_delta = counts.ecn_ce_count - previous.ecn_ce_count;
        const covered_ect0 = std.math.add(u64, ect0_delta, ce_delta) catch return error.InvalidAckFrame;
        const covered_ect1 = std.math.add(u64, ect1_delta, ce_delta) catch return error.InvalidAckFrame;
        if (covered_ect0 < all_newly_acked.ect0 or
            covered_ect1 < all_newly_acked.ect1)
        {
            return error.InvalidAckFrame;
        }

        return .{
            .update_counts = true,
            .ce_delta = ce_delta,
        };
    }

    pub fn plainAckWouldFailForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) bool {
        const precheck = self.precheckAckForPathEpoch(
            ack,
            current_path_epoch,
        ) catch return false;
        if (precheck.current_path_newly_acked_ect.ect0 == 0 and
            precheck.current_path_newly_acked_ect.ect1 == 0)
        {
            return false;
        }
        // RFC 9000 requires ACK_ECN for newly acknowledged ECN-capable
        // packets, but reordered historical plain ACKs must not retroactively
        // disable ECN after a larger ACK_ECN already validated the space.
        return !self.ackDoesNotAdvanceEcnLargest(ack.largest_acknowledged);
    }

    /// Return whether ECN-capable packets can still be acknowledged after a
    /// path switch. Those packets make the next cumulative ACK_ECN delta
    /// ambiguous: it can contain marks from both the retired and active paths.
    pub fn hasUnacknowledgedEct(self: SentPacketTracker) bool {
        for (self.packets.items) |packet| {
            if (packet.acknowledged) continue;
            if (packet.ecn == .ect0 or packet.ecn == .ect1 or
                packet.ecn == .ce)
            {
                return true;
            }
        }
        return false;
    }

    /// True when an advancing cumulative ACK_ECN could still include an ECT
    /// packet that was acknowledged without usable ECN counters. The next
    /// valid counter update must be treated as a baseline-only sample.
    pub fn hasAcknowledgedEctBeyondEcnWatermark(
        self: SentPacketTracker,
    ) bool {
        const acknowledged = self.largest_acknowledged_ect orelse return false;
        const watermark = self.ecn_largest_acknowledged orelse return true;
        return acknowledged > watermark;
    }

    fn precheckAckForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) Error!AckPrecheck {
        var stack_ranges: [32]AckedRange = undefined;
        const decoded = try decodeAckRanges(
            self.allocator,
            ack,
            &stack_ranges,
        );
        defer decoded.deinit(self.allocator);
        return try self.precheckAckRanges(
            decoded.ranges,
            self.packetsSortedAscending(),
            current_path_epoch,
        );
    }

    /// Deprecated manual compatibility API.
    ///
    /// Older callers treated the sent-packet tracker as owning a single
    /// connection-wide ECN disable bit. Preserve that source surface as an
    /// explicit latch for diagnostics/manual policy only; path-local automatic
    /// ECN state is now tracked separately by `quic.ecn.PathState`.
    pub fn disableEcnValidation(self: *SentPacketTracker) void {
        self.deprecated_ecn_validation_failed = true;
    }

    /// Deprecated manual compatibility API.
    pub fn ecnDisabled(self: SentPacketTracker) bool {
        return self.deprecated_ecn_validation_failed;
    }

    fn nextLossGeneration(self: *SentPacketTracker) u32 {
        if (self.loss_generation == std.math.maxInt(u32)) {
            self.clearLossGenerations();
            self.loss_generation = 0;
        }
        self.loss_generation += 1;
        return self.loss_generation;
    }

    fn clearLossGenerations(self: *SentPacketTracker) void {
        for (self.packets.items) |*packet| {
            packet.lost_generation = 0;
        }
    }

    pub fn detectPacketThresholdLoss(self: *SentPacketTracker, largest_acknowledged: u64, packet_threshold: u64) AckResult {
        return self.detectPacketThresholdLossForProbe(
            largest_acknowledged,
            packet_threshold,
            null,
            0,
        );
    }

    pub fn detectPacketThresholdLossForProbe(
        self: *SentPacketTracker,
        largest_acknowledged: u64,
        packet_threshold: u64,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
    ) AckResult {
        return self.detectPacketThresholdLossForProbeAndPathEpoch(
            largest_acknowledged,
            packet_threshold,
            active_probe_packet_number,
            active_probe_epoch,
            null,
        );
    }

    pub fn detectPacketThresholdLossForProbeAndPathEpoch(
        self: *SentPacketTracker,
        largest_acknowledged: u64,
        packet_threshold: u64,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        current_path_epoch: ?u32,
    ) AckResult {
        if (packet_threshold == 0 or largest_acknowledged < packet_threshold) return .{};
        const largest_lost = largest_acknowledged - packet_threshold;

        var lost: AckResult = .{};
        const generation = self.nextLossGeneration();
        var cached_latest_lost = false;
        const sorted_packets = self.packetsSortedAscending();
        if (sorted_packets and self.packets.items.len != 0 and
            largest_lost < self.packets.items[0].packet_number)
        {
            return lost;
        }
        const scan_start = if (sorted_packets)
            self.first_unacknowledged_index
        else
            0;
        for (self.packets.items[scan_start..], scan_start..) |*packet, index| {
            if (packet.packet_number > largest_lost) {
                if (sorted_packets) break;
                continue;
            }
            if (packet.acknowledged or packet.lost or !packet.in_flight) continue;
            packet.lost = true;
            packet.lost_generation = generation;
            cached_latest_lost = cached_latest_lost or
                self.latest_ack_eliciting_in_flight_index == index;
            lost.packets += 1;
            lost.observe(packet.packet_number, packet.sent_time_ns);
            if (packet.pmtu_probe_size) |probe_size| {
                lost.probe_bytes += packet.bytes;
                if (active_probe_packet_number != null and
                    packet.packet_number == active_probe_packet_number.? and
                    packet.pmtu_probe_epoch == active_probe_epoch)
                {
                    lost.observeActiveProbe(packet.packet_number, probe_size, packet.pmtu_probe_epoch);
                }
            } else {
                lost.bytes += packet.bytes;
                lost.observeNonProbe(
                    packet.packet_number,
                    packet.datagram_size,
                    packet.sent_time_ns,
                    packet.pmtu_path_epoch,
                );
            }
            if (packet.ack_eliciting) {
                lost.ack_eliciting_packets += 1;
            }
            if (packetMatchesPathEpoch(packet.*, current_path_epoch)) {
                lost.observeCurrentPath(
                    packet.packet_number,
                    packet.sent_time_ns,
                );
                if (packet.pmtu_probe_size != null) {
                    lost.current_path_probe_bytes += packet.bytes;
                } else {
                    lost.current_path_bytes += packet.bytes;
                    lost.observeCurrentPathNonProbe(
                        packet.packet_number,
                        packet.sent_time_ns,
                    );
                }
                if (packet.ack_eliciting) {
                    lost.current_path_ack_eliciting_packets += 1;
                }
            }
        }
        if (cached_latest_lost) self.recomputeLatestAckElicitingInFlight();
        return lost;
    }

    pub fn detectTimeThresholdLoss(self: *SentPacketTracker, now_ns: u64, loss_delay_ns: u64, largest_acknowledged: ?u64) AckResult {
        return self.detectTimeThresholdLossForProbe(
            now_ns,
            loss_delay_ns,
            largest_acknowledged,
            null,
            0,
        );
    }

    pub fn detectTimeThresholdLossForProbe(
        self: *SentPacketTracker,
        now_ns: u64,
        loss_delay_ns: u64,
        largest_acknowledged: ?u64,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
    ) AckResult {
        return self.detectTimeThresholdLossForProbeAndPathEpoch(
            now_ns,
            loss_delay_ns,
            largest_acknowledged,
            active_probe_packet_number,
            active_probe_epoch,
            null,
        );
    }

    pub fn detectTimeThresholdLossForProbeAndPathEpoch(
        self: *SentPacketTracker,
        now_ns: u64,
        loss_delay_ns: u64,
        largest_acknowledged: ?u64,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        current_path_epoch: ?u32,
    ) AckResult {
        var lost: AckResult = .{};
        const generation = self.nextLossGeneration();
        var cached_latest_lost = false;
        const sorted_packets = self.packetsSortedAscending();
        if (sorted_packets and self.largestBeforeFirstPacket(largest_acknowledged)) return lost;
        const scan_start = if (sorted_packets)
            self.first_unacknowledged_index
        else
            0;
        for (self.packets.items[scan_start..], scan_start..) |*packet, index| {
            if (largest_acknowledged) |largest| {
                if (packet.packet_number > largest) {
                    if (sorted_packets) break;
                    continue;
                }
            } else {
                // Before the first ACK, RFC 9002 does not permit declaring
                // arbitrary application packets lost by time threshold. The
                // sole exception here is the explicitly identified DPLPMTUD
                // probe, whose independent search timer must still progress.
                if (active_probe_packet_number == null or
                    packet.packet_number != active_probe_packet_number.? or
                    packet.pmtu_probe_epoch != active_probe_epoch)
                {
                    continue;
                }
            }
            if (packet.acknowledged or packet.lost or !packet.in_flight) continue;
            const sent_time = packet.sent_time_ns orelse continue;
            const lost_time = std.math.add(u64, sent_time, loss_delay_ns) catch std.math.maxInt(u64);
            if (now_ns < lost_time) {
                if (lost.next_loss_time_ns == null or
                    lost_time < lost.next_loss_time_ns.?)
                {
                    lost.next_loss_time_ns = lost_time;
                }
                continue;
            }
            packet.lost = true;
            packet.lost_generation = generation;
            cached_latest_lost = cached_latest_lost or
                self.latest_ack_eliciting_in_flight_index == index;
            lost.packets += 1;
            lost.observe(packet.packet_number, packet.sent_time_ns);
            if (packet.pmtu_probe_size) |probe_size| {
                lost.probe_bytes += packet.bytes;
                if (active_probe_packet_number != null and
                    packet.packet_number == active_probe_packet_number.? and
                    packet.pmtu_probe_epoch == active_probe_epoch)
                {
                    lost.observeActiveProbe(packet.packet_number, probe_size, packet.pmtu_probe_epoch);
                }
            } else {
                lost.bytes += packet.bytes;
                lost.observeNonProbe(
                    packet.packet_number,
                    packet.datagram_size,
                    packet.sent_time_ns,
                    packet.pmtu_path_epoch,
                );
            }
            if (packet.ack_eliciting) {
                lost.ack_eliciting_packets += 1;
            }
            if (packetMatchesPathEpoch(packet.*, current_path_epoch)) {
                lost.observeCurrentPath(
                    packet.packet_number,
                    packet.sent_time_ns,
                );
                if (packet.pmtu_probe_size != null) {
                    lost.current_path_probe_bytes += packet.bytes;
                } else {
                    lost.current_path_bytes += packet.bytes;
                    lost.observeCurrentPathNonProbe(
                        packet.packet_number,
                        packet.sent_time_ns,
                    );
                }
                if (packet.ack_eliciting) {
                    lost.current_path_ack_eliciting_packets += 1;
                }
            }
        }
        if (cached_latest_lost) self.recomputeLatestAckElicitingInFlight();
        return lost;
    }

    pub fn timeThresholdLossDeadline(self: SentPacketTracker, loss_delay_ns: u64, largest_acknowledged: ?u64) ?u64 {
        return self.timeThresholdLossDeadlineForProbe(
            loss_delay_ns,
            largest_acknowledged,
            null,
            0,
        );
    }

    pub fn timeThresholdLossDeadlineForProbe(
        self: SentPacketTracker,
        loss_delay_ns: u64,
        largest_acknowledged: ?u64,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
    ) ?u64 {
        return self.timeThresholdLossDeadlineForProbeAndPathEpoch(
            loss_delay_ns,
            largest_acknowledged,
            active_probe_packet_number,
            active_probe_epoch,
            null,
        );
    }

    pub fn timeThresholdLossDeadlineForProbeAndPathEpoch(
        self: SentPacketTracker,
        loss_delay_ns: u64,
        largest_acknowledged: ?u64,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        current_path_epoch: ?u32,
    ) ?u64 {
        var deadline: ?u64 = null;
        const sorted_packets = self.packetsSortedAscending();
        if (sorted_packets and self.largestBeforeFirstPacket(largest_acknowledged)) return null;
        for (self.packets.items) |packet| {
            if (largest_acknowledged) |largest| {
                if (packet.packet_number > largest) {
                    if (sorted_packets) break;
                    continue;
                }
            } else if (active_probe_packet_number == null or
                packet.packet_number != active_probe_packet_number.? or
                packet.pmtu_probe_epoch != active_probe_epoch)
            {
                continue;
            }
            if (packet.acknowledged or packet.lost or !packet.in_flight) continue;
            if (!packetMatchesPathEpoch(packet, current_path_epoch)) continue;
            const sent_time = packet.sent_time_ns orelse continue;
            const lost_time = std.math.add(u64, sent_time, loss_delay_ns) catch std.math.maxInt(u64);
            if (deadline == null or lost_time < deadline.?) deadline = lost_time;
        }
        return deadline;
    }

    pub fn latestAckElicitingInFlightSentTime(self: SentPacketTracker) ?u64 {
        const index = self.latest_ack_eliciting_in_flight_index orelse
            return null;
        if (index < self.packets.items.len) {
            if (ackElicitingInFlightSentTime(self.packets.items[index])) |sent_time| {
                return sent_time;
            }
        }
        // Tests and same-module recovery code can still mutate packet metadata
        // directly.  Production paths update the cache transactionally, but a
        // defensive fallback keeps this query correct if an invariant is broken
        // outside the tracker API.
        return self.scanLatestAckElicitingInFlightSentTime();
    }

    pub fn latestAckElicitingInFlightSentTimeForPathEpoch(
        self: SentPacketTracker,
        path_epoch: u32,
    ) ?u64 {
        if (self.latest_ack_eliciting_in_flight_index) |index| {
            if (index < self.packets.items.len) {
                const packet = self.packets.items[index];
                if (packet.pmtu_path_epoch == path_epoch) {
                    if (ackElicitingInFlightSentTime(packet)) |sent_time| {
                        return sent_time;
                    }
                }
            }
        } else {
            return null;
        }
        return self.scanLatestAckElicitingInFlightSentTimeForPathEpoch(
            path_epoch,
            false,
        );
    }

    /// Latest ordinary ACK-eliciting packet in flight, excluding DPLPMTUD
    /// probes whose independent search timer must not trigger generic PTO
    /// retransmission. RFC 9221 DATAGRAM packets remain eligible here even
    /// though their application bytes are not retransmittable.
    pub fn latestNonProbeAckElicitingInFlightSentTime(
        self: SentPacketTracker,
    ) ?u64 {
        // The tracker already caches the latest ACK-eliciting packet for the
        // generic PTO query.  When that packet is ordinary application data it
        // is necessarily also the latest non-probe packet, which is the common
        // case.  Only a PMTU probe (or directly mutated test metadata) needs
        // the full defensive scan below.
        if (self.latest_ack_eliciting_in_flight_index) |index| {
            if (index < self.packets.items.len) {
                const packet = self.packets.items[index];
                if (packet.pmtu_probe_size == null) {
                    if (ackElicitingInFlightSentTime(packet)) |sent_time| {
                        return sent_time;
                    }
                }
            }
        } else {
            return null;
        }

        var latest: ?u64 = null;
        const scan_start = if (self.packetsSortedAscending())
            self.first_unacknowledged_index
        else
            0;
        for (self.packets.items[scan_start..]) |packet| {
            if (packet.pmtu_probe_size != null) continue;
            const sent_time = ackElicitingInFlightSentTime(packet) orelse
                continue;
            if (latest == null or sent_time > latest.?) latest = sent_time;
        }
        return latest;
    }

    pub fn latestNonProbeAckElicitingInFlightSentTimeForPathEpoch(
        self: SentPacketTracker,
        path_epoch: u32,
    ) ?u64 {
        if (self.latest_ack_eliciting_in_flight_index) |index| {
            if (index < self.packets.items.len) {
                const packet = self.packets.items[index];
                if (packet.pmtu_path_epoch == path_epoch and
                    packet.pmtu_probe_size == null)
                {
                    if (ackElicitingInFlightSentTime(packet)) |sent_time| {
                        return sent_time;
                    }
                }
            }
        } else {
            return null;
        }
        return self.scanLatestAckElicitingInFlightSentTimeForPathEpoch(
            path_epoch,
            true,
        );
    }

    /// Return the longest contiguous lost-packet period that can establish
    /// RFC 9002 persistent congestion.
    ///
    /// This mirrors the production-stack pattern used by s2n-quic/quicz:
    /// persistent congestion is based on packet send times, starts only after
    /// an RTT sample has been observed, permits non-ack-eliciting packets inside
    /// the lost run, but requires the start and end packets of the measured
    /// period to be ack-eliciting.  `after_packet_number` lets callers suppress
    /// duplicate reports after they have already applied the congestion response
    /// for a period ending at or before that packet number.
    pub fn persistentCongestionPeriod(
        self: SentPacketTracker,
        first_rtt_sample_sent_time_ns: ?u64,
        largest_acknowledged: ?u64,
        after_packet_number: ?u64,
    ) ?PersistentCongestionPeriod {
        return self.persistentCongestionPeriodForPathEpoch(
            first_rtt_sample_sent_time_ns,
            largest_acknowledged,
            after_packet_number,
            null,
        );
    }

    pub fn persistentCongestionPeriodForPathEpoch(
        self: SentPacketTracker,
        first_rtt_sample_sent_time_ns: ?u64,
        largest_acknowledged: ?u64,
        after_packet_number: ?u64,
        current_path_epoch: ?u32,
    ) ?PersistentCongestionPeriod {
        const first_sample_time = first_rtt_sample_sent_time_ns orelse return null;
        if (after_packet_number) |after| {
            if (largest_acknowledged) |largest| {
                if (after >= largest) return null;
            }
        }

        var best: ?PersistentCongestionPeriod = null;
        var current: ?PersistentCongestionBuilder = null;
        for (self.packets.items) |packet| {
            if (largest_acknowledged) |largest| {
                if (packet.packet_number > largest) break;
            }
            if (!packetMatchesPathEpoch(packet, current_path_epoch)) {
                current = null;
                continue;
            }

            if (packet.acknowledged or !packet.lost) {
                current = null;
                continue;
            }
            if (packet.pmtu_probe_size != null) {
                current = null;
                continue;
            }

            const sent_time = packet.sent_time_ns orelse {
                current = null;
                continue;
            };
            if (sent_time < first_sample_time) {
                current = null;
                continue;
            }

            if (current) |*builder| {
                if (isImmediatelyBefore(builder.previous_packet_number, packet.packet_number)) {
                    builder.previous_packet_number = packet.packet_number;
                    if (packet.ack_eliciting) {
                        builder.period.end_packet_number = packet.packet_number;
                        builder.period.end_time_ns = sent_time;
                        considerPersistentCongestionPeriod(&best, builder.period, after_packet_number);
                    }
                    continue;
                }
                current = null;
            }

            if (packet.ack_eliciting) {
                current = .{
                    .period = .{
                        .start_packet_number = packet.packet_number,
                        .end_packet_number = packet.packet_number,
                        .start_time_ns = sent_time,
                        .end_time_ns = sent_time,
                    },
                    .previous_packet_number = packet.packet_number,
                };
            }
        }

        return best;
    }

    fn decodeAckRanges(
        allocator: std.mem.Allocator,
        ack: quic.AckFrame,
        stack_ranges: *[32]AckedRange,
    ) Error!DecodedAckRanges {
        if (ack.largest_acknowledged < ack.first_ack_range) {
            return error.InvalidAckFrame;
        }
        const range_count = std.math.add(usize, ack.ranges.len, 1) catch
            return error.InvalidAckFrame;
        const ranges = if (range_count <= stack_ranges.len)
            stack_ranges[0..range_count]
        else
            try allocator.alloc(AckedRange, range_count);
        errdefer if (range_count > stack_ranges.len) allocator.free(ranges);

        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        ranges[0] = .{ .start = start, .end = end };
        for (ack.ranges, 1..) |range, range_index| {
            const skipped = std.math.add(u64, range.gap, 2) catch
                return error.InvalidAckFrame;
            if (start < skipped) return error.InvalidAckFrame;
            end = start - skipped;
            if (end < range.ack_range_length) return error.InvalidAckFrame;
            start = end - range.ack_range_length;
            ranges[range_index] = .{ .start = start, .end = end };
        }
        return .{
            .ranges = ranges,
            .heap_allocated = range_count > stack_ranges.len,
        };
    }

    fn precheckAckRanges(
        self: SentPacketTracker,
        ranges: []const AckedRange,
        sorted_packets: bool,
        current_path_epoch: ?u32,
    ) Error!AckPrecheck {
        if (ranges.len == 1 and ranges[0].start == ranges[0].end) {
            var precheck: AckPrecheck = .{ .total_span = 1 };
            if (self.findSentPacket(ranges[0].start)) |packet| {
                precheck.sent_packets += 1;
                precheck.observeNewlyAckedPacket(packet, current_path_epoch);
            } else if (self.retiredContains(ranges[0].start)) {
                precheck.sent_packets = 1;
            } else {
                return error.InvalidAckFrame;
            }
            return precheck;
        }
        var precheck: AckPrecheck = .{};
        for (ranges) |range| {
            precheck.total_span = std.math.add(
                u64,
                precheck.total_span,
                range.end - range.start + 1,
            ) catch return error.InvalidAckFrame;
        }
        const retired_count = self.retiredAcknowledgedCount();
        if (precheck.total_span > self.packets.items.len +| retired_count) {
            return error.InvalidAckFrame;
        }

        if (sorted_packets) {
            for (ranges) |range| {
                precheck.sent_packets += self.retiredIntersectionLen(range);
                const range_start = self.lowerBoundPacketIndex(range.start);
                const range_end = self.upperBoundPacketIndex(range.end);
                precheck.sent_packets += range_end - range_start;
                const unresolved_start = @max(
                    range_start,
                    self.first_unacknowledged_index,
                );
                if (unresolved_start < range_end) {
                    for (self.packets.items[unresolved_start..range_end]) |packet| {
                        precheck.observeNewlyAckedPacket(
                            packet,
                            current_path_epoch,
                        );
                    }
                }
            }
        } else {
            for (self.packets.items) |packet| {
                if (!ackRangesContain(ranges, packet.packet_number)) continue;
                precheck.sent_packets += 1;
                precheck.observeNewlyAckedPacket(packet, current_path_epoch);
            }
        }

        if (precheck.sent_packets != precheck.total_span) {
            return error.InvalidAckFrame;
        }
        return precheck;
    }

    fn markRanges(
        self: *SentPacketTracker,
        ranges: []const AckedRange,
        sorted_packets: bool,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        pmtu_ack_threshold: ?usize,
        pmtu_path_epoch: ?u32,
    ) AckResult {
        if (ranges.len == 1 and ranges[0].start == ranges[0].end) {
            const index = self.findPacketIndex(ranges[0].start) orelse
                return .{};
            var result: AckResult = .{};
            var cached_latest_acked = false;
            self.markPacketAcknowledged(
                &self.packets.items[index],
                &result,
                &cached_latest_acked,
                active_probe_packet_number,
                active_probe_epoch,
                pmtu_ack_threshold,
                pmtu_path_epoch,
            );
            if (cached_latest_acked) {
                self.recomputeLatestAckElicitingInFlight();
            }
            self.advanceFirstUnacknowledged();
            return result;
        }
        var result: AckResult = .{};
        var cached_latest_acked = false;
        if (sorted_packets) {
            for (ranges) |range| {
                const range_start = @max(
                    self.lowerBoundPacketIndex(range.start),
                    self.first_unacknowledged_index,
                );
                const range_end = self.upperBoundPacketIndex(range.end);
                if (range_start < range_end) {
                    for (self.packets.items[range_start..range_end]) |*packet| {
                        self.markPacketAcknowledged(
                            packet,
                            &result,
                            &cached_latest_acked,
                            active_probe_packet_number,
                            active_probe_epoch,
                            pmtu_ack_threshold,
                            pmtu_path_epoch,
                        );
                    }
                }
            }
            if (cached_latest_acked) self.recomputeLatestAckElicitingInFlight();
            self.advanceFirstUnacknowledged();
            return result;
        }

        for (self.packets.items) |*packet| {
            if (!ackRangesContain(ranges, packet.packet_number)) continue;
            self.markPacketAcknowledged(
                packet,
                &result,
                &cached_latest_acked,
                active_probe_packet_number,
                active_probe_epoch,
                pmtu_ack_threshold,
                pmtu_path_epoch,
            );
        }
        if (cached_latest_acked) self.recomputeLatestAckElicitingInFlight();
        self.advanceFirstUnacknowledged();
        return result;
    }

    fn markPacketAcknowledged(
        self: *SentPacketTracker,
        packet: *SentPacket,
        result: *AckResult,
        cached_latest_acked: *bool,
        active_probe_packet_number: ?u64,
        active_probe_epoch: u32,
        pmtu_ack_threshold: ?usize,
        pmtu_path_epoch: ?u32,
    ) void {
        self.observeAcknowledged(packet.packet_number);
        if (packet.acknowledged) return;
        const was_cached_latest = if (self.latest_ack_eliciting_in_flight_index) |index|
            index < self.packets.items.len and
                self.packets.items[index].packet_number == packet.packet_number
        else
            false;
        packet.acknowledged = true;
        self.observeAcknowledgedEct(packet.*);
        cached_latest_acked.* = cached_latest_acked.* or was_cached_latest;
        result.packets += 1;
        result.observe(packet.packet_number, packet.sent_time_ns);
        if (packet.in_flight and !packet.lost) result.bytes += packet.bytes;
        if (packet.pmtu_probe_size) |probe_size| {
            if (packet.in_flight and !packet.lost) result.probe_bytes += packet.bytes;
            if (active_probe_packet_number != null and
                packet.packet_number == active_probe_packet_number.? and
                packet.pmtu_probe_epoch == active_probe_epoch)
            {
                result.observeActiveProbe(packet.packet_number, probe_size, packet.pmtu_probe_epoch);
            }
        } else {
            result.observeNonProbe(
                packet.packet_number,
                packet.datagram_size,
                packet.sent_time_ns,
                packet.pmtu_path_epoch,
            );
            if (pmtu_ack_threshold) |threshold| {
                if (packet.datagram_size >= threshold and
                    (pmtu_path_epoch == null or packet.pmtu_path_epoch == pmtu_path_epoch.?))
                {
                    result.observeAckedPmtu(packet.packet_number, packet.datagram_size);
                }
            }
        }
        if (packet.ack_eliciting) {
            result.ack_eliciting_packets += 1;
        }
        if (packetMatchesPathEpoch(packet.*, pmtu_path_epoch)) {
            result.observeCurrentPath(
                packet.packet_number,
                packet.sent_time_ns,
            );
            if (packet.in_flight and !packet.lost) {
                result.current_path_bytes += packet.bytes;
                if (packet.pmtu_probe_size != null) {
                    result.current_path_probe_bytes += packet.bytes;
                }
            }
            if (packet.pmtu_probe_size == null) {
                result.observeCurrentPathNonProbe(
                    packet.packet_number,
                    packet.sent_time_ns,
                );
            }
            if (packet.ack_eliciting) {
                result.current_path_ack_eliciting_packets += 1;
            }
        }
        if (packet.largest_acknowledged_sent) |largest_acknowledged| {
            if (result.largest_acknowledged_sent == null or
                largest_acknowledged > result.largest_acknowledged_sent.?)
            {
                result.largest_acknowledged_sent = largest_acknowledged;
            }
        }
        switch (packet.ecn) {
            .not_ect => {},
            .ect0 => result.ect0_packets += 1,
            .ect1 => result.ect1_packets += 1,
            .ce => {},
        }
        if (pmtu_path_epoch) |epoch| {
            if (packet.pmtu_path_epoch == epoch) {
                switch (packet.ecn) {
                    .not_ect => {},
                    .ect0 => result.current_path_ect0_packets += 1,
                    .ect1 => result.current_path_ect1_packets += 1,
                    .ce => {},
                }
            }
        } else {
            switch (packet.ecn) {
                .not_ect => {},
                .ect0 => result.current_path_ect0_packets += 1,
                .ect1 => result.current_path_ect1_packets += 1,
                .ce => {},
            }
        }
    }

    fn ackRangesContain(ranges: []const AckedRange, packet_number: u64) bool {
        for (ranges) |range| {
            if (packet_number >= range.start and
                packet_number <= range.end)
            {
                return true;
            }
        }
        return false;
    }

    fn observeAcknowledgedEct(self: *SentPacketTracker, packet: SentPacket) void {
        switch (packet.ecn) {
            .not_ect => return,
            .ect0, .ect1, .ce => {},
        }
        if (self.largest_acknowledged_ect == null or
            packet.packet_number > self.largest_acknowledged_ect.?)
        {
            self.largest_acknowledged_ect = packet.packet_number;
        }
    }

    fn packetsSortedAscending(self: SentPacketTracker) bool {
        return self.packets_sorted_ascending;
    }

    fn findSentPacket(self: SentPacketTracker, packet_number: u64) ?SentPacket {
        const index = self.findPacketIndex(packet_number) orelse return null;
        return self.packets.items[index];
    }

    fn findPacketIndex(self: SentPacketTracker, packet_number: u64) ?usize {
        if (self.packets.items.len == 0) return null;
        const tail_index = self.packets.items.len - 1;
        if (self.packets.items[tail_index].packet_number == packet_number) {
            return tail_index;
        }
        if (self.packet_index.count() != 0) {
            if (self.packet_index.get(packet_number)) |index| return index;
        }
        if (self.packetsSortedAscending()) {
            return self.findSortedPacketIndex(packet_number);
        }
        for (self.packets.items, 0..) |packet, index| {
            if (packet.packet_number == packet_number) return index;
        }
        return null;
    }

    fn findSortedPacketIndex(self: SentPacketTracker, packet_number: u64) ?usize {
        var low: usize = 0;
        var high = self.packets.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const current = self.packets.items[mid].packet_number;
            if (current == packet_number) return mid;
            if (current < packet_number) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return null;
    }

    fn refreshPacketIndexFrom(self: *SentPacketTracker, start: usize) void {
        var index = start;
        while (index < self.packets.items.len) : (index += 1) {
            const packet_number = self.packets.items[index].packet_number;
            if (self.packet_index.getPtr(packet_number)) |indexed| {
                indexed.* = index;
            }
        }
    }

    fn considerLatestAckElicitingInFlight(self: *SentPacketTracker, index: usize) void {
        const sent_time = ackElicitingInFlightSentTime(self.packets.items[index]) orelse
            return;
        const current = self.latest_ack_eliciting_in_flight_index orelse {
            self.latest_ack_eliciting_in_flight_index = index;
            return;
        };
        const current_time = ackElicitingInFlightSentTime(self.packets.items[current]) orelse {
            self.latest_ack_eliciting_in_flight_index = index;
            return;
        };
        if (sent_time > current_time) self.latest_ack_eliciting_in_flight_index = index;
    }

    fn recomputeLatestAckElicitingInFlight(self: *SentPacketTracker) void {
        self.latest_ack_eliciting_in_flight_index = null;
        const scan_start = if (self.packetsSortedAscending())
            self.first_unacknowledged_index
        else
            0;
        for (self.packets.items[scan_start..], scan_start..) |packet, index| {
            if (ackElicitingInFlightSentTime(packet) == null) continue;
            self.considerLatestAckElicitingInFlight(index);
        }
    }

    fn scanLatestAckElicitingInFlightSentTime(self: SentPacketTracker) ?u64 {
        var latest: ?u64 = null;
        const scan_start = if (self.packetsSortedAscending())
            self.first_unacknowledged_index
        else
            0;
        for (self.packets.items[scan_start..]) |packet| {
            const sent_time = ackElicitingInFlightSentTime(packet) orelse
                continue;
            if (latest == null or sent_time > latest.?) latest = sent_time;
        }
        return latest;
    }

    fn scanLatestAckElicitingInFlightSentTimeForPathEpoch(
        self: SentPacketTracker,
        path_epoch: u32,
        exclude_probes: bool,
    ) ?u64 {
        var latest: ?u64 = null;
        const scan_start = if (self.packetsSortedAscending())
            self.first_unacknowledged_index
        else
            0;
        for (self.packets.items[scan_start..]) |packet| {
            if (packet.pmtu_path_epoch != path_epoch) continue;
            if (exclude_probes and packet.pmtu_probe_size != null) continue;
            const sent_time = ackElicitingInFlightSentTime(packet) orelse
                continue;
            if (latest == null or sent_time > latest.?) latest = sent_time;
        }
        return latest;
    }

    fn ackElicitingInFlightSentTime(packet: SentPacket) ?u64 {
        if (!packet.ack_eliciting or !packet.in_flight or packet.acknowledged or packet.lost) {
            return null;
        }
        return packet.sent_time_ns;
    }

    fn packetMatchesPathEpoch(
        packet: SentPacket,
        current_path_epoch: ?u32,
    ) bool {
        const epoch = current_path_epoch orelse return true;
        return packet.pmtu_path_epoch == epoch;
    }

    fn packetIndexHasUnusedCapacity(self: SentPacketTracker) bool {
        const capacity = self.packet_index.capacity();
        if (capacity == 0) return false;
        const max_load = (capacity * std.hash_map.default_max_load_percentage) / 100;
        return self.packet_index.count() < max_load;
    }

    fn ackContainsNewAckEliciting(self: SentPacketTracker, ack: quic.AckFrame) bool {
        return self.ackContainsNewAckElicitingForPathEpoch(ack, null);
    }

    fn ackContainsNewAckElicitingForPathEpoch(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        current_path_epoch: ?u32,
    ) bool {
        if (ack.largest_acknowledged < ack.first_ack_range) return false;

        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        if (self.rangeContainsNewAckElicitingForPathEpoch(
            start,
            end,
            current_path_epoch,
        )) return true;

        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch return false;
            if (start < skipped) return false;
            end = start - skipped;
            if (end < range.ack_range_length) return false;
            start = end - range.ack_range_length;
            if (self.rangeContainsNewAckElicitingForPathEpoch(
                start,
                end,
                current_path_epoch,
            )) return true;
        }

        return false;
    }

    fn rangeContainsNewAckEliciting(self: SentPacketTracker, start: u64, end: u64) bool {
        return self.rangeContainsNewAckElicitingForPathEpoch(
            start,
            end,
            null,
        );
    }

    fn rangeContainsNewAckElicitingForPathEpoch(
        self: SentPacketTracker,
        start: u64,
        end: u64,
        current_path_epoch: ?u32,
    ) bool {
        const sorted_packets = self.packetsSortedAscending();
        var index: usize = if (sorted_packets) self.lowerBoundPacketIndex(start) else 0;
        while (index < self.packets.items.len) : (index += 1) {
            const packet = self.packets.items[index];
            if (packet.packet_number < start) continue;
            if (packet.packet_number > end) {
                if (sorted_packets) break;
                continue;
            }
            if (packet.acknowledged or !packet.ack_eliciting) continue;
            if (!packetMatchesPathEpoch(packet, current_path_epoch)) continue;
            return true;
        }
        return false;
    }

    fn lowerBoundPacketIndex(self: SentPacketTracker, packet_number: u64) usize {
        var low: usize = 0;
        var high = self.packets.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.packets.items[mid].packet_number < packet_number) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }

    fn upperBoundPacketIndex(
        self: SentPacketTracker,
        packet_number: u64,
    ) usize {
        var low: usize = 0;
        var high = self.packets.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.packets.items[mid].packet_number <= packet_number) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }

    fn retiredContains(self: SentPacketTracker, packet_number: u64) bool {
        const start = self.retired_acknowledged_start orelse return false;
        const end = self.retired_acknowledged_through orelse return false;
        return packet_number >= start and packet_number <= end;
    }

    fn retiredAcknowledgedCount(self: SentPacketTracker) usize {
        const start = self.retired_acknowledged_start orelse return 0;
        const end = self.retired_acknowledged_through orelse return 0;
        return std.math.cast(usize, end - start + 1) orelse
            std.math.maxInt(usize);
    }

    fn retiredIntersectionLen(
        self: SentPacketTracker,
        range: AckedRange,
    ) u64 {
        const start = self.retired_acknowledged_start orelse return 0;
        const end = self.retired_acknowledged_through orelse return 0;
        const intersection_start = @max(start, range.start);
        const intersection_end = @min(end, range.end);
        if (intersection_start > intersection_end) return 0;
        return intersection_end - intersection_start + 1;
    }

    fn compactAcknowledgedPrefix(self: *SentPacketTracker) void {
        if (!self.packetsSortedAscending() or
            self.first_unacknowledged_index <
                compact_acknowledged_threshold)
        {
            return;
        }

        const expected_start = if (self.retired_acknowledged_through) |end|
            end +| 1
        else
            self.packets.items[0].packet_number;
        var compact_count: usize = 0;
        var expected = expected_start;
        while (compact_count < self.first_unacknowledged_index) {
            const packet = self.packets.items[compact_count];
            if (!packet.acknowledged or packet.packet_number != expected) {
                break;
            }
            compact_count += 1;
            expected +|= 1;
        }
        if (compact_count < compact_acknowledged_threshold) return;

        const first = self.packets.items[0].packet_number;
        const last = self.packets.items[compact_count - 1].packet_number;
        if (self.retired_acknowledged_start == null) {
            self.retired_acknowledged_start = first;
        }
        self.retired_acknowledged_through = last;
        // The exact index is only a best-effort accelerator; every lookup has
        // a sorted-array fallback. Compaction changes every retained index, so
        // discard the sparse cache in one pass instead of removing the retired
        // prefix and rewriting every survivor. Later sends repopulate it with
        // correct indices as capacity permits.
        self.packet_index.clearRetainingCapacity();
        const remaining = self.packets.items.len - compact_count;
        std.mem.copyForwards(
            SentPacket,
            self.packets.items[0..remaining],
            self.packets.items[compact_count..],
        );
        self.packets.items.len = remaining;
        self.first_unacknowledged_index -= compact_count;
        if (self.latest_ack_eliciting_in_flight_index) |index| {
            self.latest_ack_eliciting_in_flight_index =
                if (index < compact_count) null else index - compact_count;
        }
    }

    fn advanceFirstUnacknowledged(self: *SentPacketTracker) void {
        if (!self.packetsSortedAscending()) {
            self.first_unacknowledged_index = 0;
            return;
        }
        while (self.first_unacknowledged_index < self.packets.items.len and
            self.packets.items[self.first_unacknowledged_index].acknowledged)
        {
            self.first_unacknowledged_index += 1;
        }
    }

    fn largestBeforeFirstPacket(self: SentPacketTracker, largest_acknowledged: ?u64) bool {
        const largest = largest_acknowledged orelse return false;
        return self.packets.items.len != 0 and
            largest < self.packets.items[0].packet_number;
    }

    fn ackDoesNotAdvanceEcnLargest(self: SentPacketTracker, largest_acknowledged: u64) bool {
        if (self.ecn_largest_acknowledged) |previous| return largest_acknowledged <= previous;
        return false;
    }

    fn ackDoesNotAdvanceLargest(self: SentPacketTracker, largest_acknowledged: u64) bool {
        if (self.largest_acknowledged) |previous| return largest_acknowledged <= previous;
        return false;
    }

    fn observeAcknowledged(self: *SentPacketTracker, packet_number: u64) void {
        if (self.largest_acknowledged == null or packet_number > self.largest_acknowledged.?) {
            self.largest_acknowledged = packet_number;
        }
    }

    fn considerPersistentCongestionPeriod(
        best: *?PersistentCongestionPeriod,
        period: PersistentCongestionPeriod,
        after_packet_number: ?u64,
    ) void {
        if (period.start_packet_number == period.end_packet_number) return;
        if (after_packet_number) |after| {
            if (period.end_packet_number <= after) return;
        }

        const current_best = best.* orelse {
            best.* = period;
            return;
        };
        const duration = period.durationNs();
        const best_duration = current_best.durationNs();
        if (duration > best_duration or (duration == best_duration and period.end_packet_number > current_best.end_packet_number)) {
            best.* = period;
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

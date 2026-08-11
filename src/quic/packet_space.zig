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
        if (fresh) self.recordEcn(ecn);
        return fresh;
    }

    pub fn wouldRecordFresh(self: ReceivedPacketTracker, packet_number: u64) Error!bool {
        if (packet_number > quic.varint.max_value) return error.InvalidPacketNumber;
        if (self.max_ranges == 0) return false;
        if (self.forgotten_through) |forgotten| {
            if (packet_number <= forgotten) return false;
        }
        if (self.ranges.items.len == 0) return true;
        if (self.ranges.items.len != 0) {
            const oldest = self.ranges.items[self.ranges.items.len - 1];
            if (packet_number < oldest.start) {
                if (isImmediatelyBefore(packet_number, oldest.start)) return true;
                return self.ranges.items.len < self.max_ranges;
            }
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
        while (self.ranges.items.len != 0) {
            const last_index = self.ranges.items.len - 1;
            const oldest = &self.ranges.items[last_index];
            if (oldest.end <= largest_acknowledged) {
                self.retained_packet_count -|= oldest.len();
                _ = self.ranges.pop();
                continue;
            }
            if (oldest.start <= largest_acknowledged) {
                self.retained_packet_count -|= largest_acknowledged - oldest.start + 1;
                oldest.start = largest_acknowledged + 1;
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
    ecn: EcnCodepoint = .not_ect,
    sent_time_ns: ?u64 = null,
    pmtu_probe_size: ?usize = null,
    largest_acknowledged_sent: ?u64 = null,
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
    ecn_validation_failed: bool,
};

pub const SentPacketTracker = struct {
    allocator: std.mem.Allocator,
    packets: std.ArrayList(SentPacket) = .empty,
    packets_sorted_ascending: bool = true,
    /// Packet-number lookups feed RTT sampling, ack bookkeeping, and send
    /// rollback after partial writes. `packets` remains ordered for ACK/loss
    /// range scans; this index keeps exact packet operations from walking the
    /// whole sent-packet history.
    packet_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// PTO scheduling needs the newest still-in-flight ack-eliciting packet on
    /// every timer query.  Keep its packet-list index cached, mirroring the
    /// last-ack-eliciting timestamp maintained by production QUIC recovery
    /// implementations, and recompute only when that exact packet is acked,
    /// lost, or removed.
    latest_ack_eliciting_in_flight_index: ?usize = null,
    largest_acknowledged: ?u64 = null,
    latest_ecn_counts: quic.EcnCounts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 0 },
    ecn_validation_failed: bool = false,
    ecn_largest_acknowledged: ?u64 = null,
    sent_ect0_count: u64 = 0,
    sent_ect1_count: u64 = 0,

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
        try self.sentAtWithPmtu(packet_number, ack_eliciting, bytes, ecn, sent_time_ns, null);
    }

    pub fn sentAtWithPmtu(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize) !void {
        try self.sentInFlightAtWithPmtu(packet_number, ack_eliciting, ack_eliciting, bytes, ecn, sent_time_ns, pmtu_probe_size);
    }

    pub fn sentInFlightAt(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64) !void {
        try self.sentInFlightAtWithPmtu(packet_number, ack_eliciting, in_flight, bytes, ecn, sent_time_ns, null);
    }

    pub fn sentInFlightAtWithPmtu(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize) !void {
        try self.sentInFlightAtWithMetadata(packet_number, ack_eliciting, in_flight, bytes, ecn, sent_time_ns, pmtu_probe_size, null);
    }

    pub fn sentInFlightAtWithMetadata(self: *SentPacketTracker, packet_number: u64, ack_eliciting: bool, in_flight: bool, bytes: usize, ecn: EcnCodepoint, sent_time_ns: ?u64, pmtu_probe_size: ?usize, largest_acknowledged_sent: ?u64) !void {
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
            .ecn = ecn,
            .sent_time_ns = sent_time_ns,
            .pmtu_probe_size = pmtu_probe_size,
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
        const index = self.findPacketIndex(packet_number) orelse return false;
        const latest = self.latest_ack_eliciting_in_flight_index;
        if (index == self.packets.items.len - 1) {
            _ = self.packets.pop();
        } else {
            _ = self.packets.orderedRemove(index);
        }
        _ = self.packet_index.remove(packet_number);
        if (index < self.packets.items.len) {
            self.refreshPacketIndexFrom(index);
        }
        if (latest == index) {
            self.recomputeLatestAckElicitingInFlight();
        } else if (latest != null and latest.? > index) {
            self.latest_ack_eliciting_in_flight_index = latest.? - 1;
        }
        return true;
    }

    pub fn markAcknowledged(self: *SentPacketTracker, packet_number: u64) bool {
        const index = self.findPacketIndex(packet_number) orelse return false;
        if (!self.packets.items[index].acknowledged) {
            self.packets.items[index].acknowledged = true;
            if (self.latest_ack_eliciting_in_flight_index == index) {
                self.recomputeLatestAckElicitingInFlight();
            }
        }
        self.observeAcknowledged(packet_number);
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
            .ecn_validation_failed = self.ecn_validation_failed,
        };
    }

    pub fn getStats(self: SentPacketTracker) SentPacketStats {
        return self.stats();
    }

    pub const AckResult = struct {
        packets: usize = 0,
        ack_eliciting_packets: usize = 0,
        bytes: usize = 0,
        ect0_packets: usize = 0,
        ect1_packets: usize = 0,
        largest_packet_number: ?u64 = null,
        largest_sent_time_ns: ?u64 = null,
        ecn_ce_delta: u64 = 0,
        largest_pmtu_probe_size: ?usize = null,
        largest_acknowledged_sent: ?u64 = null,

        fn add(self: *AckResult, other: AckResult) void {
            self.packets += other.packets;
            self.ack_eliciting_packets += other.ack_eliciting_packets;
            self.bytes += other.bytes;
            self.ect0_packets += other.ect0_packets;
            self.ect1_packets += other.ect1_packets;
            if (other.largest_packet_number) |packet_number| self.observe(packet_number, other.largest_sent_time_ns, other.largest_pmtu_probe_size);
            if (other.largest_acknowledged_sent) |largest_acknowledged| {
                if (self.largest_acknowledged_sent == null or largest_acknowledged > self.largest_acknowledged_sent.?) {
                    self.largest_acknowledged_sent = largest_acknowledged;
                }
            }
        }

        fn observe(self: *AckResult, packet_number: u64, sent_time_ns: ?u64, pmtu_probe_size: ?usize) void {
            if (self.largest_packet_number == null or packet_number > self.largest_packet_number.?) {
                self.largest_packet_number = packet_number;
                self.largest_sent_time_ns = sent_time_ns;
                self.largest_pmtu_probe_size = pmtu_probe_size;
            }
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

        fn observeSentPacket(self: *AckPrecheck, packet: SentPacket) void {
            self.sent_packets += 1;
            if (packet.acknowledged) return;
            self.newly_acked_packets += 1;
            switch (packet.ecn) {
                .not_ect => {},
                .ect0 => self.newly_acked_ect.ect0 += 1,
                .ect1 => self.newly_acked_ect.ect1 += 1,
                .ce => {},
            }
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
        const packet = self.findSentPacket(ack.largest_acknowledged) orelse return null;
        if (packet.acknowledged) return null;
        if (!self.ackContainsNewAckEliciting(ack)) return null;
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
        var stack_ranges: [32]AckedRange = undefined;
        const decoded = try decodeAckRanges(self.allocator, ack, &stack_ranges);
        defer decoded.deinit(self.allocator);
        const sorted = self.packetsSortedAscending();
        const precheck = try self.precheckAckRanges(decoded.ranges, sorted);
        const ecn_validation = try self.validateAckEcnFrameDetailedForPrecheck(
            ack,
            precheck,
        );

        var acked: AckResult = .{};
        if (precheck.newly_acked_packets != 0) {
            acked = self.markRanges(decoded.ranges, sorted);
        }
        if (ack.ecn_counts) |ecn_counts| {
            if (ecn_validation.update_counts) {
                self.latest_ecn_counts = ecn_counts;
                self.ecn_largest_acknowledged = ack.largest_acknowledged;
                acked.ecn_ce_delta = ecn_validation.ce_delta;
            }
        } else if (acked.ect0_packets != 0 or acked.ect1_packets != 0) {
            // RFC 9000 ECN validation requires ECN-capable packets to be
            // acknowledged with ACK_ECN.  A plain ACK covering ECT-marked
            // packets disables ECN for the packet number space, unless this is
            // a reordered ACK that does not advance the largest ACK_ECN already
            // validated for this path/space.  quicz and s2n-quic both ignore
            // such historical ACKs so reordering cannot spuriously disable ECN.
            if (!self.ackDoesNotAdvanceEcnLargest(ack.largest_acknowledged)) {
                self.ecn_validation_failed = true;
            }
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
        var stack_ranges: [32]AckedRange = undefined;
        const decoded = try decodeAckRanges(
            self.allocator,
            ack,
            &stack_ranges,
        );
        defer decoded.deinit(self.allocator);
        _ = try self.precheckAckRanges(
            decoded.ranges,
            self.packetsSortedAscending(),
        );
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

    pub fn validateAckEcnFrame(self: SentPacketTracker, ack: quic.AckFrame) Error!void {
        _ = try self.validateAckEcnFrameDetailed(ack);
    }

    pub fn validateAckEcnFrameWouldFail(self: SentPacketTracker, ack: quic.AckFrame) bool {
        _ = self.validateAckEcnFrameDetailed(ack) catch return true;
        return false;
    }

    fn validateAckEcnFrameDetailed(self: SentPacketTracker, ack: quic.AckFrame) Error!EcnAckValidation {
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
        );
        return self.validateAckEcnFrameDetailedForPrecheck(ack, precheck);
    }

    fn validateAckEcnFrameDetailedForPrecheck(
        self: SentPacketTracker,
        ack: quic.AckFrame,
        precheck: AckPrecheck,
    ) Error!EcnAckValidation {
        const counts = ack.ecn_counts orelse return .{};
        if (self.ecn_validation_failed) return error.InvalidAckFrame;

        // RFC 9000 §13.4.2.1 permits reordered ACK_ECN frames.  Once ECN has
        // been validated for a larger ACK, older ACK_ECN counters are only
        // historical information; do not reject them for being lower than the
        // most recent counters, and do not generate a second CE event.
        if (self.ecn_largest_acknowledged) |previous_largest| {
            if (ack.largest_acknowledged <= previous_largest) return .{};
        }

        try self.validateAckEcnCounters(counts);
        const newly_acked = precheck.newly_acked_ect;

        const previous = self.latest_ecn_counts;
        const ect0_delta = counts.ect0_count - previous.ect0_count;
        const ect1_delta = counts.ect1_count - previous.ect1_count;
        const ce_delta = counts.ecn_ce_count - previous.ecn_ce_count;
        const covered_ect0 = std.math.add(u64, ect0_delta, ce_delta) catch return error.InvalidAckFrame;
        const covered_ect1 = std.math.add(u64, ect1_delta, ce_delta) catch return error.InvalidAckFrame;
        if (covered_ect0 < newly_acked.ect0 or covered_ect1 < newly_acked.ect1) return error.InvalidAckFrame;

        return .{ .update_counts = true, .ce_delta = ce_delta };
    }

    pub fn disableEcnValidation(self: *SentPacketTracker) void {
        self.ecn_validation_failed = true;
    }

    pub fn ecnDisabled(self: SentPacketTracker) bool {
        return self.ecn_validation_failed;
    }

    pub fn detectPacketThresholdLoss(self: *SentPacketTracker, largest_acknowledged: u64, packet_threshold: u64) AckResult {
        if (packet_threshold == 0 or largest_acknowledged < packet_threshold) return .{};
        const largest_lost = largest_acknowledged - packet_threshold;

        var lost: AckResult = .{};
        var cached_latest_lost = false;
        const sorted_packets = self.packetsSortedAscending();
        for (self.packets.items, 0..) |*packet, index| {
            if (packet.packet_number > largest_lost) {
                if (sorted_packets) break;
                continue;
            }
            if (packet.acknowledged or packet.lost or !packet.in_flight) continue;
            packet.lost = true;
            cached_latest_lost = cached_latest_lost or
                self.latest_ack_eliciting_in_flight_index == index;
            lost.packets += 1;
            lost.observe(packet.packet_number, packet.sent_time_ns, packet.pmtu_probe_size);
            lost.bytes += packet.bytes;
            if (packet.ack_eliciting) {
                lost.ack_eliciting_packets += 1;
            }
        }
        if (cached_latest_lost) self.recomputeLatestAckElicitingInFlight();
        return lost;
    }

    pub fn detectTimeThresholdLoss(self: *SentPacketTracker, now_ns: u64, loss_delay_ns: u64, largest_acknowledged: ?u64) AckResult {
        var lost: AckResult = .{};
        var cached_latest_lost = false;
        const sorted_packets = self.packetsSortedAscending();
        for (self.packets.items, 0..) |*packet, index| {
            if (largest_acknowledged) |largest| {
                if (packet.packet_number > largest) {
                    if (sorted_packets) break;
                    continue;
                }
            }
            if (packet.acknowledged or packet.lost or !packet.in_flight) continue;
            const sent_time = packet.sent_time_ns orelse continue;
            const lost_time = std.math.add(u64, sent_time, loss_delay_ns) catch std.math.maxInt(u64);
            if (now_ns < lost_time) continue;
            packet.lost = true;
            cached_latest_lost = cached_latest_lost or
                self.latest_ack_eliciting_in_flight_index == index;
            lost.packets += 1;
            lost.observe(packet.packet_number, packet.sent_time_ns, packet.pmtu_probe_size);
            lost.bytes += packet.bytes;
            if (packet.ack_eliciting) {
                lost.ack_eliciting_packets += 1;
            }
        }
        if (cached_latest_lost) self.recomputeLatestAckElicitingInFlight();
        return lost;
    }

    pub fn timeThresholdLossDeadline(self: SentPacketTracker, loss_delay_ns: u64, largest_acknowledged: ?u64) ?u64 {
        var deadline: ?u64 = null;
        const sorted_packets = self.packetsSortedAscending();
        for (self.packets.items) |packet| {
            if (largest_acknowledged) |largest| {
                if (packet.packet_number > largest) {
                    if (sorted_packets) break;
                    continue;
                }
            }
            if (packet.acknowledged or packet.lost or !packet.in_flight) continue;
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
        first_rtt_sample_time_ns: ?u64,
        largest_acknowledged: ?u64,
        after_packet_number: ?u64,
    ) ?PersistentCongestionPeriod {
        const first_sample_time = first_rtt_sample_time_ns orelse return null;

        var best: ?PersistentCongestionPeriod = null;
        var current: ?PersistentCongestionBuilder = null;
        for (self.packets.items) |packet| {
            if (largest_acknowledged) |largest| {
                if (packet.packet_number > largest) break;
            }

            if (packet.acknowledged or !packet.lost) {
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
    ) Error!AckPrecheck {
        var precheck: AckPrecheck = .{};
        for (ranges) |range| {
            precheck.total_span = std.math.add(
                u64,
                precheck.total_span,
                range.end - range.start + 1,
            ) catch return error.InvalidAckFrame;
        }
        if (precheck.total_span > self.packets.items.len) {
            return error.InvalidAckFrame;
        }

        if (sorted_packets) {
            var packet_index: usize = 0;
            var range_index = ranges.len;
            while (range_index > 0) {
                range_index -= 1;
                const range = ranges[range_index];
                while (packet_index < self.packets.items.len and
                    self.packets.items[packet_index].packet_number < range.start)
                {
                    packet_index += 1;
                }
                while (packet_index < self.packets.items.len and
                    self.packets.items[packet_index].packet_number <= range.end)
                {
                    precheck.observeSentPacket(self.packets.items[packet_index]);
                    packet_index += 1;
                }
            }
        } else {
            for (self.packets.items) |packet| {
                if (!ackRangesContain(ranges, packet.packet_number)) continue;
                precheck.observeSentPacket(packet);
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
    ) AckResult {
        var result: AckResult = .{};
        var cached_latest_acked = false;
        if (sorted_packets) {
            var packet_index: usize = 0;
            var range_index = ranges.len;
            while (range_index > 0) {
                range_index -= 1;
                const range = ranges[range_index];
                while (packet_index < self.packets.items.len and
                    self.packets.items[packet_index].packet_number < range.start)
                {
                    packet_index += 1;
                }
                while (packet_index < self.packets.items.len and
                    self.packets.items[packet_index].packet_number <= range.end)
                {
                    self.markPacketAcknowledged(
                        &self.packets.items[packet_index],
                        &result,
                        &cached_latest_acked,
                    );
                    packet_index += 1;
                }
            }
            if (cached_latest_acked) self.recomputeLatestAckElicitingInFlight();
            return result;
        }

        for (self.packets.items) |*packet| {
            if (!ackRangesContain(ranges, packet.packet_number)) continue;
            self.markPacketAcknowledged(packet, &result, &cached_latest_acked);
        }
        if (cached_latest_acked) self.recomputeLatestAckElicitingInFlight();
        return result;
    }

    fn markPacketAcknowledged(
        self: *SentPacketTracker,
        packet: *SentPacket,
        result: *AckResult,
        cached_latest_acked: *bool,
    ) void {
        self.observeAcknowledged(packet.packet_number);
        if (packet.acknowledged) return;
        const was_cached_latest = if (self.latest_ack_eliciting_in_flight_index) |index|
            index < self.packets.items.len and
                self.packets.items[index].packet_number == packet.packet_number
        else
            false;
        packet.acknowledged = true;
        cached_latest_acked.* = cached_latest_acked.* or was_cached_latest;
        result.packets += 1;
        result.observe(
            packet.packet_number,
            packet.sent_time_ns,
            packet.pmtu_probe_size,
        );
        if (packet.in_flight and !packet.lost) result.bytes += packet.bytes;
        if (packet.ack_eliciting) {
            result.ack_eliciting_packets += 1;
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

    fn packetsSortedAscending(self: SentPacketTracker) bool {
        return self.packets_sorted_ascending;
    }

    fn findSentPacket(self: SentPacketTracker, packet_number: u64) ?SentPacket {
        const index = self.findPacketIndex(packet_number) orelse return null;
        return self.packets.items[index];
    }

    fn findPacketIndex(self: SentPacketTracker, packet_number: u64) ?usize {
        if (self.packets.items.len == 0) return null;
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
        for (self.packets.items, 0..) |packet, index| {
            if (ackElicitingInFlightSentTime(packet) == null) continue;
            self.considerLatestAckElicitingInFlight(index);
        }
    }

    fn scanLatestAckElicitingInFlightSentTime(self: SentPacketTracker) ?u64 {
        var latest: ?u64 = null;
        for (self.packets.items) |packet| {
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

    fn packetIndexHasUnusedCapacity(self: SentPacketTracker) bool {
        const capacity = self.packet_index.capacity();
        if (capacity == 0) return false;
        const max_load = (capacity * std.hash_map.default_max_load_percentage) / 100;
        return self.packet_index.count() < max_load;
    }

    fn ackContainsNewAckEliciting(self: SentPacketTracker, ack: quic.AckFrame) bool {
        if (ack.largest_acknowledged < ack.first_ack_range) return false;

        var start = ack.largest_acknowledged - ack.first_ack_range;
        var end = ack.largest_acknowledged;
        if (self.rangeContainsNewAckEliciting(start, end)) return true;

        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch return false;
            if (start < skipped) return false;
            end = start - skipped;
            if (end < range.ack_range_length) return false;
            start = end - range.ack_range_length;
            if (self.rangeContainsNewAckEliciting(start, end)) return true;
        }

        return false;
    }

    fn rangeContainsNewAckEliciting(self: SentPacketTracker, start: u64, end: u64) bool {
        const sorted_packets = self.packetsSortedAscending();
        for (self.packets.items) |packet| {
            if (packet.packet_number < start) continue;
            if (packet.packet_number > end) {
                if (sorted_packets) break;
                continue;
            }
            if (packet.acknowledged or !packet.ack_eliciting) continue;
            return true;
        }
        return false;
    }

    fn ackDoesNotAdvanceEcnLargest(self: SentPacketTracker, largest_acknowledged: u64) bool {
        if (self.ecn_largest_acknowledged) |previous| return largest_acknowledged <= previous;
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

test "QUIC packet space records first ACK range without scanning" {
    const allocator = std.testing.allocator;
    var received = ReceivedPacketTracker.init(allocator, 1);
    defer received.deinit();

    try std.testing.expect(try received.wouldRecordFresh(42));
    try std.testing.expect(try received.recordFresh(42));
    try std.testing.expectEqual(@as(usize, 1), received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 42), received.largestReceived().?);

    var disabled = ReceivedPacketTracker.init(allocator, 0);
    defer disabled.deinit();
    try std.testing.expect(!(try disabled.wouldRecordFresh(42)));
    try std.testing.expect(!(try disabled.recordFresh(42)));
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

test "QUIC sent packet tracker indexes exact packet lookups" {
    const allocator = std.testing.allocator;
    var sent = SentPacketTracker.init(allocator);
    defer sent.deinit();

    try sent.sentAt(0, true, 100, .not_ect, 1_000);
    try sent.sentAt(1, true, 200, .not_ect, 2_000);
    try sent.sentAt(2, true, 300, .not_ect, 3_000);
    try std.testing.expectEqual(@as(usize, 3), sent.packet_index.count());
    try std.testing.expectEqual(@as(?usize, 0), sent.packet_index.get(0));
    try std.testing.expectEqual(@as(?usize, 1), sent.packet_index.get(1));
    try std.testing.expectEqual(@as(?usize, 2), sent.packet_index.get(2));
    try std.testing.expectError(
        error.DuplicatePacket,
        sent.sent(1, true, 100),
    );

    try std.testing.expect(sent.markAcknowledged(2));
    try std.testing.expect(sent.packets.items[sent.packet_index.get(2).?].acknowledged);
    try std.testing.expect(sent.forget(1));
    try std.testing.expect(sent.packet_index.get(1) == null);
    try std.testing.expectEqual(@as(?usize, 1), sent.packet_index.get(2));

    const ack = quic.AckFrame{
        .largest_acknowledged = 2,
        .ack_delay = 1,
        .first_ack_range = 0,
    };
    // The largest packet is already acknowledged above, so the indexed RTT
    // lookup finds it and correctly suppresses a duplicate RTT sample.
    try std.testing.expectEqual(
        @as(?SentPacketTracker.RttSample, null),
        try sent.ackRttSample(ack, 4_000, 3),
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
    try std.testing.expect(!sent.ecn_validation_failed);
    try std.testing.expectEqual(@as(u64, 1), sent.latest_ecn_counts.ect0_count);
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

    const lost = sent.detectTimeThresholdLoss(250, 150, 2);
    try std.testing.expectEqual(@as(usize, 1), lost.packets);
    try std.testing.expectEqual(@as(usize, 1200), lost.bytes);
    try std.testing.expect(sent.packets.items[0].lost);
    try std.testing.expect(!sent.packets.items[1].lost);

    // Packets newer than the largest acknowledged packet are not time-threshold
    // candidates, matching RFC 9002's "earlier than largest acked" rule.
    const none_for_future = sent.detectTimeThresholdLoss(1_000, 150, 0);
    try std.testing.expectEqual(@as(usize, 0), none_for_future.packets);

    try std.testing.expectEqual(@as(?u64, 330), sent.timeThresholdLossDeadline(150, 2));
    const remaining = sent.detectTimeThresholdLoss(1_000, 150, 2);
    try std.testing.expectEqual(@as(usize, 2), remaining.packets);
    try std.testing.expectEqual(@as(?u64, null), sent.timeThresholdLossDeadline(150, 2));
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

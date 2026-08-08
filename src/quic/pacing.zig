const std = @import("std");

/// RFC 9002 section 7.7 packet pacer.
///
/// The bucket permits an initial burst and then replenishes at 1.25*cwnd/RTT,
/// matching the local quicz/quic-zig references. All arithmetic on products is
/// widened to u128 so large clocks and windows saturate instead of wrapping.
pub const Pacer = struct {
    enabled: bool,
    max_datagram_size: usize,
    max_burst_packets: usize,
    budget: usize,
    last_sent_time_ns: ?u64 = null,

    pub const default_max_burst_packets: usize = 10;
    const rate_numerator: u128 = 5;
    const rate_denominator: u128 = 4;

    pub fn init(enabled: bool, max_datagram_size: usize, max_burst_packets: usize) Pacer {
        const burst_packets = @max(max_burst_packets, 1);
        const burst_size = std.math.mul(usize, max_datagram_size, burst_packets) catch std.math.maxInt(usize);
        return .{
            .enabled = enabled,
            .max_datagram_size = max_datagram_size,
            .max_burst_packets = burst_packets,
            .budget = burst_size,
        };
    }

    pub fn maxBurstSize(self: Pacer) usize {
        return std.math.mul(usize, self.max_datagram_size, self.max_burst_packets) catch std.math.maxInt(usize);
    }

    pub fn budgetAt(self: Pacer, now_ns: u64, congestion_window: usize, smoothed_rtt_ns: u64) usize {
        if (!self.enabled or smoothed_rtt_ns == 0) return self.maxBurstSize();
        const last_sent = self.last_sent_time_ns orelse return self.maxBurstSize();
        const elapsed_ns = now_ns -| last_sent;
        if (elapsed_ns == 0 or congestion_window == 0) return self.budget;

        const numerator = @as(u128, congestion_window) *| rate_numerator *| elapsed_ns;
        const denominator = @as(u128, smoothed_rtt_ns) * rate_denominator;
        const replenished = std.math.cast(usize, numerator / denominator) orelse std.math.maxInt(usize);
        return @min(self.maxBurstSize(), self.budget +| replenished);
    }

    /// Earliest timestamp at which `packet_size` bytes may be emitted.
    /// `null` means the packet can be sent immediately or pacing is disabled.
    pub fn deadlineAt(
        self: Pacer,
        now_ns: u64,
        packet_size: usize,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) ?u64 {
        if (!self.enabled or packet_size == 0 or smoothed_rtt_ns == 0 or congestion_window == 0) return null;
        const available = self.budgetAt(now_ns, congestion_window, smoothed_rtt_ns);
        if (packet_size <= available) return null;

        const deficit = packet_size - available;
        const numerator = @as(u128, deficit) *| smoothed_rtt_ns *| rate_denominator;
        const denominator = @as(u128, congestion_window) * rate_numerator;
        // Ceiling division ensures returning at the deadline always replenishes
        // enough whole-byte credit for the requested packet.
        const delay_ns_u128 = (numerator +| (denominator - 1)) / denominator;
        const delay_ns = std.math.cast(u64, delay_ns_u128) orelse std.math.maxInt(u64);
        return std.math.add(u64, now_ns, delay_ns) catch std.math.maxInt(u64);
    }

    pub fn canSendAt(
        self: Pacer,
        now_ns: u64,
        packet_size: usize,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) bool {
        return self.deadlineAt(now_ns, packet_size, congestion_window, smoothed_rtt_ns) == null;
    }

    /// Commit a successful packet send. Call this only after the UDP write
    /// succeeds so transient socket failures do not consume pacing credit.
    pub fn onPacketSentAt(
        self: *Pacer,
        now_ns: u64,
        packet_size: usize,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) void {
        if (!self.enabled) return;
        self.budget = self.budgetAt(now_ns, congestion_window, smoothed_rtt_ns) -| packet_size;
        self.last_sent_time_ns = now_ns;
    }

    pub fn reset(self: *Pacer) void {
        self.budget = self.maxBurstSize();
        self.last_sent_time_ns = null;
    }
};

test "QUIC pacer permits initial burst and computes exact deadline" {
    var pacer = Pacer.init(true, 1200, 10);
    try std.testing.expectEqual(@as(usize, 12_000), pacer.budget);

    var packet: usize = 0;
    while (packet < 10) : (packet += 1) {
        try std.testing.expect(pacer.canSendAt(1_000_000, 1200, 12_000, 100_000_000));
        pacer.onPacketSentAt(1_000_000, 1200, 12_000, 100_000_000);
    }
    try std.testing.expectEqual(@as(usize, 0), pacer.budget);

    // rate = 1.25 * 12,000 / 100ms = 150 bytes/ms, so 1,200 bytes
    // require exactly 8ms after the burst.
    try std.testing.expectEqual(
        @as(?u64, 9_000_000),
        pacer.deadlineAt(1_000_000, 1200, 12_000, 100_000_000),
    );
    try std.testing.expect(!pacer.canSendAt(8_999_999, 1200, 12_000, 100_000_000));
    try std.testing.expect(pacer.canSendAt(9_000_000, 1200, 12_000, 100_000_000));
}

test "QUIC pacer replenishes and caps burst credit" {
    var pacer = Pacer.init(true, 1200, 10);
    pacer.onPacketSentAt(0, 12_000, 48_000, 100_000_000);
    try std.testing.expectEqual(@as(usize, 0), pacer.budget);
    try std.testing.expectEqual(@as(usize, 600), pacer.budgetAt(1_000_000, 48_000, 100_000_000));
    try std.testing.expectEqual(@as(usize, 12_000), pacer.budgetAt(1_000_000_000, 48_000, 100_000_000));
}

test "QUIC disabled pacer never gates and reset restores burst" {
    var disabled = Pacer.init(false, 1200, 10);
    disabled.onPacketSentAt(0, 12_000, 12_000, 100_000_000);
    try std.testing.expect(disabled.deadlineAt(0, std.math.maxInt(usize), 1, 1) == null);

    var enabled = Pacer.init(true, 1200, 10);
    enabled.onPacketSentAt(10, 1200, 12_000, 100_000_000);
    enabled.reset();
    try std.testing.expectEqual(@as(usize, 12_000), enabled.budget);
    try std.testing.expectEqual(@as(?u64, null), enabled.last_sent_time_ns);
}

test "QUIC pacer saturates extreme arithmetic" {
    var pacer = Pacer.init(true, std.math.maxInt(usize), std.math.maxInt(usize));
    pacer.budget = 0;
    pacer.last_sent_time_ns = 0;
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        pacer.budgetAt(std.math.maxInt(u64), std.math.maxInt(usize), 1),
    );

    pacer.max_datagram_size = 1;
    pacer.max_burst_packets = 1;
    try std.testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        pacer.deadlineAt(
            std.math.maxInt(u64) - 1,
            std.math.maxInt(usize),
            1,
            std.math.maxInt(u64),
        ),
    );
}

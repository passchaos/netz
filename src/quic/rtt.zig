const std = @import("std");

/// RFC 9002 timer granularity: endpoints SHOULD use 1ms.
pub const timer_granularity_ns: u64 = 1_000_000;
pub const default_initial_rtt_ns: u64 = 100_000_000;
pub const default_max_ack_delay_ns: u64 = 25_000_000;
pub const default_persistent_congestion_threshold: u64 = 3;
pub const max_ack_delay_exponent: u64 = 20;

pub const Stats = struct {
    latest_rtt: u64 = 0,
    smoothed_rtt: u64 = 0,
    rtt_var: u64 = 0,
    min_rtt: u64 = 0,
    max_ack_delay: u64 = default_max_ack_delay_ns,
    has_measurement: bool = false,
    /// Receive timestamp of the first RTT sample in the current measurement
    /// epoch.  Persistent congestion detection must not begin before this
    /// point; after persistent congestion, s2n-quic resets the epoch so the
    /// next RTT sample becomes the new min/smoothed baseline.
    first_rtt_sample_time_ns: ?u64 = null,
    reset_on_next_sample: bool = false,

    pub fn init(max_ack_delay_ns: u64) Stats {
        return .{ .max_ack_delay = max_ack_delay_ns };
    }

    /// Update RTT state from an ACK sample.
    ///
    /// This follows RFC 9002 section 5.3 and mirrors the behavior in the local
    /// quic-zig/tquic/s2n-quic references: ACK delay is ignored until the
    /// handshake is confirmed, then capped by the peer's max_ack_delay and only
    /// subtracted when it cannot reduce the sample below min_rtt.
    pub fn update(self: *Stats, send_delta_ns: u64, ack_delay_ns: u64, handshake_confirmed: bool) void {
        self.updateAt(send_delta_ns, ack_delay_ns, handshake_confirmed, null);
    }

    pub fn updateAt(self: *Stats, send_delta_ns: u64, ack_delay_ns: u64, handshake_confirmed: bool, sample_time_ns: ?u64) void {
        if (send_delta_ns == 0) return;
        self.latest_rtt = send_delta_ns;

        if (!self.has_measurement or self.reset_on_next_sample) {
            if (sample_time_ns) |sample_time| self.first_rtt_sample_time_ns = sample_time;
            self.min_rtt = send_delta_ns;
            self.smoothed_rtt = send_delta_ns;
            self.rtt_var = send_delta_ns / 2;
            self.has_measurement = true;
            self.reset_on_next_sample = false;
            return;
        }
        if (self.first_rtt_sample_time_ns == null) {
            if (sample_time_ns) |sample_time| self.first_rtt_sample_time_ns = sample_time;
        }

        self.min_rtt = @min(self.min_rtt, send_delta_ns);

        var adjusted_rtt = send_delta_ns;
        if (handshake_confirmed) {
            const effective_ack_delay = @min(ack_delay_ns, self.max_ack_delay);
            if (adjusted_rtt > self.min_rtt + effective_ack_delay) {
                adjusted_rtt -= effective_ack_delay;
            }
        }

        const diff = if (self.smoothed_rtt > adjusted_rtt)
            self.smoothed_rtt - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt;
        self.rtt_var = (self.rtt_var * 3 + diff) / 4;
        self.smoothed_rtt = (self.smoothed_rtt * 7 + adjusted_rtt) / 8;
    }

    pub fn smoothedOrInitial(self: Stats) u64 {
        return if (self.has_measurement) self.smoothed_rtt else default_initial_rtt_ns;
    }

    pub fn pto(self: Stats, include_max_ack_delay: bool) u64 {
        if (!self.has_measurement) return 2 * default_initial_rtt_ns;
        const base = self.smoothed_rtt + @max(4 * self.rtt_var, timer_granularity_ns);
        return base + if (include_max_ack_delay) self.max_ack_delay else 0;
    }

    pub fn lossDelay(self: Stats) u64 {
        if (!self.has_measurement) return default_initial_rtt_ns;
        const basis = @max(self.latest_rtt, self.smoothed_rtt);
        return @max(timer_granularity_ns, (basis * 9) / 8);
    }

    pub fn persistentCongestionThreshold(self: Stats) u64 {
        return std.math.mul(u64, self.pto(true), default_persistent_congestion_threshold) catch std.math.maxInt(u64);
    }

    pub fn onPersistentCongestion(self: *Stats) void {
        self.first_rtt_sample_time_ns = null;
        self.reset_on_next_sample = true;
    }
};

pub fn decodeAckDelayMicros(encoded_ack_delay: u64, ack_delay_exponent: u64) !u64 {
    if (ack_delay_exponent > max_ack_delay_exponent) return error.InvalidAckDelayExponent;
    const multiplier = std.math.shl(u64, 1, @as(u6, @intCast(ack_delay_exponent)));
    return std.math.mul(u64, encoded_ack_delay, multiplier) catch error.AckDelayOverflow;
}

pub fn decodeAckDelayNanos(encoded_ack_delay: u64, ack_delay_exponent: u64) !u64 {
    const micros = try decodeAckDelayMicros(encoded_ack_delay, ack_delay_exponent);
    return std.math.mul(u64, micros, 1_000) catch error.AckDelayOverflow;
}

test "QUIC RTT estimator initializes and computes PTO" {
    var stats = Stats{};
    try std.testing.expect(!stats.has_measurement);
    try std.testing.expectEqual(@as(u64, 2 * default_initial_rtt_ns), stats.pto(true));
    try std.testing.expectEqual(default_initial_rtt_ns, stats.smoothedOrInitial());

    stats.update(100_000_000, 0, false);
    try std.testing.expect(stats.has_measurement);
    try std.testing.expectEqual(@as(u64, 100_000_000), stats.latest_rtt);
    try std.testing.expectEqual(@as(u64, 100_000_000), stats.smoothed_rtt);
    try std.testing.expectEqual(@as(u64, 50_000_000), stats.rtt_var);
    try std.testing.expectEqual(@as(u64, 325_000_000), stats.pto(true));
    try std.testing.expectEqual(@as(u64, 300_000_000), stats.pto(false));
}

test "QUIC RTT estimator applies capped ACK delay after handshake" {
    var stats = Stats{};
    stats.update(100_000_000, 0, false);
    stats.update(130_000_000, 20_000_000, true);

    // adjusted_rtt is 110ms, so smoothed_rtt = 7/8*100 + 1/8*110 = 101.25ms.
    try std.testing.expect(stats.smoothed_rtt > 100_000_000);
    try std.testing.expect(stats.smoothed_rtt < 102_000_000);
    try std.testing.expectEqual(@as(u64, 100_000_000), stats.min_rtt);

    stats.max_ack_delay = 10_000_000;
    stats.update(150_000_000, 50_000_000, true);
    try std.testing.expect(stats.latest_rtt == 150_000_000);
    try std.testing.expect(stats.smoothed_rtt < 110_000_000);
}

test "QUIC RTT estimator loss and persistent congestion thresholds" {
    var stats = Stats{};
    stats.update(100_000_000, 0, false);
    stats.update(120_000_000, 0, true);
    try std.testing.expect(stats.lossDelay() >= 120_000_000);
    try std.testing.expectEqual(stats.pto(true) * 3, stats.persistentCongestionThreshold());
}

test "QUIC RTT estimator tracks sample epochs across persistent congestion" {
    var stats = Stats{};
    stats.updateAt(100_000_000, 0, true, 1_000);
    try std.testing.expectEqual(@as(?u64, 1_000), stats.first_rtt_sample_time_ns);

    stats.updateAt(50_000_000, 0, true, 2_000);
    try std.testing.expectEqual(@as(u64, 50_000_000), stats.min_rtt);
    try std.testing.expectEqual(@as(?u64, 1_000), stats.first_rtt_sample_time_ns);

    stats.onPersistentCongestion();
    try std.testing.expectEqual(@as(?u64, null), stats.first_rtt_sample_time_ns);
    try std.testing.expect(stats.reset_on_next_sample);

    stats.updateAt(200_000_000, 0, true, 3_000);
    try std.testing.expectEqual(@as(u64, 200_000_000), stats.min_rtt);
    try std.testing.expectEqual(@as(u64, 200_000_000), stats.smoothed_rtt);
    try std.testing.expectEqual(@as(?u64, 3_000), stats.first_rtt_sample_time_ns);
    try std.testing.expect(!stats.reset_on_next_sample);
}

test "QUIC ACK delay decoding applies negotiated exponent" {
    try std.testing.expectEqual(@as(u64, 25 * 8), try decodeAckDelayMicros(25, 3));
    try std.testing.expectEqual(@as(u64, 25 * 8 * 1_000), try decodeAckDelayNanos(25, 3));
    try std.testing.expectError(error.InvalidAckDelayExponent, decodeAckDelayMicros(1, max_ack_delay_exponent + 1));
    try std.testing.expectError(error.AckDelayOverflow, decodeAckDelayNanos(std.math.maxInt(u64), 3));
}

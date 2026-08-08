const std = @import("std");

pub const Error = error{
    CongestionLimited,
};

pub const default_max_datagram_size: usize = 1200;

/// Congestion-control algorithms supported by the 1-RTT runtime.
///
/// CUBIC is the high-throughput default used by the 1-RTT runtime. NewReno
/// remains the low-level controller default for source/behavior compatibility
/// and is also a conservative fallback when timing context is omitted.
pub const Algorithm = enum {
    new_reno,
    cubic,
};

/// RFC 9438 state that is independent from the common bytes-in-flight and
/// recovery accounting in `Controller`.
pub const CubicState = struct {
    /// Window immediately before the most recent congestion event, in bytes.
    w_max: f64 = 0,
    /// Time required for the cubic curve to return to W_max, in seconds.
    k_seconds: f64 = 0,
    /// Start of the current congestion-avoidance epoch.
    epoch_start_time_ns: ?u64 = null,
    /// Reno-friendly window estimate from RFC 9438 section 4.3.
    w_est: f64 = 0,
    /// Fractional byte growth retained across ACK batches.
    window_increment: f64 = 0,
    /// Additive factor starts at the RFC-recommended Reno-friendly value and
    /// changes to one after W_est recovers to W_max.
    alpha: f64 = reno_friendly_alpha,

    pub const c: f64 = 0.4;
    pub const beta: f64 = 0.7;
    pub const reno_friendly_alpha: f64 = 3.0 * (1.0 - beta) / (1.0 + beta);

    pub fn reset(self: *CubicState) void {
        self.* = .{};
    }

    /// Evaluate W_cubic(t) in bytes. Keeping this deterministic and public
    /// makes congestion traces testable without relying on wall-clock time.
    pub fn windowAt(self: CubicState, elapsed_seconds: f64, max_datagram_size: usize) f64 {
        const delta = elapsed_seconds - self.k_seconds;
        const cubic_segments = c * delta * delta * delta;
        return self.w_max + cubic_segments * @as(f64, @floatFromInt(max_datagram_size));
    }
};

pub const Controller = struct {
    algorithm: Algorithm = .new_reno,
    max_datagram_size: usize = default_max_datagram_size,
    congestion_window: usize,
    slow_start_threshold: usize = std.math.maxInt(usize),
    bytes_in_flight: usize = 0,
    congestion_avoidance_bytes_acked: usize = 0,
    /// Time at which the current congestion recovery epoch started.
    /// Packets sent at or before this point are part of the same loss episode:
    /// they remove bytes-in-flight, but they must not repeatedly cut cwnd or
    /// grow cwnd when later ACKed.
    congestion_recovery_start_time_ns: ?u64 = null,
    cubic: CubicState = .{},

    pub fn init(max_datagram_size: usize) Controller {
        return initWithAlgorithm(max_datagram_size, .new_reno);
    }

    pub fn initWithAlgorithm(max_datagram_size: usize, algorithm: Algorithm) Controller {
        return .{
            .algorithm = algorithm,
            .max_datagram_size = max_datagram_size,
            .congestion_window = initialWindow(max_datagram_size),
        };
    }

    pub fn inSlowStart(self: Controller) bool {
        return self.congestion_window < self.slow_start_threshold;
    }

    pub fn available(self: Controller) usize {
        return self.congestion_window -| self.bytes_in_flight;
    }

    pub fn canSend(self: Controller, bytes: usize) bool {
        return bytes <= self.available();
    }

    pub fn reserve(self: *Controller, bytes: usize) Error!void {
        if (!self.canSend(bytes)) return error.CongestionLimited;
        self.bytes_in_flight += bytes;
    }

    pub fn onAcked(self: *Controller, bytes: usize) void {
        self.onAckedWithContext(bytes, null, null, null);
    }

    pub fn onAckedAt(self: *Controller, bytes: usize, sent_time_ns: ?u64) void {
        self.onAckedWithContext(bytes, sent_time_ns, null, null);
    }

    /// Apply an ACK with the timing context needed by CUBIC.
    ///
    /// `now_ns` is the ACK receive time and `smoothed_rtt_ns` is the path's
    /// current RTT estimate. Callers without timestamps retain safe NewReno
    /// growth, so selecting CUBIC never stalls progress on untimed APIs.
    pub fn onAckedWithContext(
        self: *Controller,
        bytes: usize,
        sent_time_ns: ?u64,
        now_ns: ?u64,
        smoothed_rtt_ns: ?u64,
    ) void {
        self.discard(bytes);
        if (bytes == 0) return;

        if (self.congestion_recovery_start_time_ns) |recovery_start| {
            const sent_time = sent_time_ns orelse return;
            if (sent_time <= recovery_start) return;
            self.congestion_recovery_start_time_ns = null;
        }

        if (self.inSlowStart()) {
            self.congestion_window +|= bytes;
            return;
        }

        switch (self.algorithm) {
            .new_reno => self.growNewReno(bytes),
            .cubic => {
                const now = now_ns orelse {
                    self.growNewReno(bytes);
                    return;
                };
                const smoothed_rtt = smoothed_rtt_ns orelse {
                    self.growNewReno(bytes);
                    return;
                };
                self.growCubic(bytes, now, smoothed_rtt);
            },
        }
    }

    fn growNewReno(self: *Controller, bytes: usize) void {
        self.congestion_avoidance_bytes_acked +|= bytes;
        while (self.congestion_avoidance_bytes_acked >= self.congestion_window) {
            self.congestion_avoidance_bytes_acked -= self.congestion_window;
            self.congestion_window +|= self.max_datagram_size;
            if (self.congestion_window == std.math.maxInt(usize)) {
                self.congestion_avoidance_bytes_acked = 0;
                return;
            }
        }
    }

    fn growCubic(self: *Controller, bytes: usize, now_ns: u64, smoothed_rtt_ns: u64) void {
        if (self.congestion_window == 0 or self.max_datagram_size == 0) return;

        if (self.cubic.epoch_start_time_ns == null) {
            self.cubic.epoch_start_time_ns = now_ns;
            if (self.cubic.w_max < @as(f64, @floatFromInt(self.congestion_window))) {
                self.cubic.w_max = @floatFromInt(self.congestion_window);
            }
            self.updateCubicK();
            self.cubic.w_est = @floatFromInt(self.congestion_window);
        }

        const epoch_start = self.cubic.epoch_start_time_ns.?;
        const elapsed_ns = now_ns -| epoch_start;
        const elapsed_seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        const rtt_seconds = @as(f64, @floatFromInt(smoothed_rtt_ns)) / std.time.ns_per_s;
        const cwnd: f64 = @floatFromInt(self.congestion_window);
        const acked: f64 = @floatFromInt(bytes);
        const max_datagram: f64 = @floatFromInt(self.max_datagram_size);

        // RFC 9438 section 4.2 evaluates the target one RTT ahead. Limiting it
        // to 1.5*cwnd follows mature tquic behavior and prevents a delayed ACK
        // or a very large timestamp jump from creating an unsafe window leap.
        const raw_target = self.cubic.windowAt(elapsed_seconds + rtt_seconds, self.max_datagram_size);
        const target = @min(@max(raw_target, cwnd), cwnd * 1.5);

        self.cubic.w_est += self.cubic.alpha * (acked / cwnd) * max_datagram;
        if (self.cubic.w_est >= self.cubic.w_max) self.cubic.alpha = 1.0;

        const cubic_now = self.cubic.windowAt(elapsed_seconds, self.max_datagram_size);
        if (cubic_now < self.cubic.w_est) {
            // In the Reno-friendly region RFC 9438 asks CUBIC to follow W_est
            // directly rather than lagging behind a competing Reno flow.
            self.congestion_window = @max(self.congestion_window, boundedWindow(self.cubic.w_est));
            return;
        }

        if (target <= cwnd) return;
        self.cubic.window_increment += ((target - cwnd) / cwnd) * acked;
        const whole_increment = boundedWindow(@floor(self.cubic.window_increment));
        if (whole_increment == 0) return;
        self.congestion_window +|= whole_increment;
        self.cubic.window_increment -= @floatFromInt(whole_increment);
        if (self.congestion_window == std.math.maxInt(usize)) {
            self.cubic.window_increment = 0;
        }
    }

    pub fn onLost(self: *Controller, bytes: usize) void {
        self.onLostAt(bytes, null, null);
    }

    pub fn onLostAt(self: *Controller, bytes: usize, lost_sent_time_ns: ?u64, now_ns: ?u64) void {
        self.discard(bytes);
        if (bytes == 0) return;

        if (self.congestion_recovery_start_time_ns) |recovery_start| {
            const lost_sent_time = lost_sent_time_ns orelse return;
            if (lost_sent_time <= recovery_start) return;
        }

        self.reduceForCongestion(now_ns orelse lost_sent_time_ns);
    }

    pub fn onExplicitCongestion(self: *Controller, event_time_ns: ?u64) void {
        // RFC 9002 treats an increase in the peer-reported ECN-CE counter as a
        // congestion signal equivalent to packet loss, but no packet bytes are
        // removed from bytes_in_flight.  If already recovering, s2n-quic/quicz
        // suppress another cutback until a later ACK exits the recovery epoch.
        if (self.congestion_recovery_start_time_ns != null) return;

        self.reduceForCongestion(event_time_ns orelse 0);
    }

    fn reduceForCongestion(self: *Controller, event_time_ns: ?u64) void {
        const previous_window = self.congestion_window;
        const minimum = minimumWindow(self.max_datagram_size);
        const reduced = switch (self.algorithm) {
            .new_reno => betaReduction(previous_window),
            .cubic => blk: {
                const previous: f64 = @floatFromInt(previous_window);
                self.cubic.w_max = if (self.cubic.w_max > previous)
                    previous * (1.0 + CubicState.beta) / 2.0
                else
                    previous;
                // beta is exactly 0.7 by default. Keep the actual window
                // reduction integer-exact; binary floating point can otherwise
                // turn 84,000 * 0.7 into 58,799 after truncation.
                break :blk betaReduction(previous_window);
            },
        };
        self.congestion_window = @max(reduced, minimum);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
        // Untimed low-level users cannot establish packet ordering relative to
        // a recovery epoch. Keep the epoch absent rather than inventing time
        // zero, which would suppress every subsequent untimed ACK forever.
        self.congestion_recovery_start_time_ns = event_time_ns;

        if (self.algorithm == .cubic) {
            self.cubic.epoch_start_time_ns = event_time_ns;
            self.cubic.w_est = @floatFromInt(self.congestion_window);
            self.cubic.alpha = CubicState.reno_friendly_alpha;
            self.cubic.window_increment = 0;
            self.updateCubicK();
        }
    }

    fn updateCubicK(self: *Controller) void {
        const current: f64 = @floatFromInt(self.congestion_window);
        const max_datagram: f64 = @floatFromInt(self.max_datagram_size);
        if (max_datagram == 0 or self.cubic.w_max <= current) {
            self.cubic.k_seconds = 0;
            return;
        }
        self.cubic.k_seconds = std.math.cbrt((self.cubic.w_max - current) / (CubicState.c * max_datagram));
    }

    pub fn onPersistentCongestion(self: *Controller) void {
        self.congestion_window = minimumWindow(self.max_datagram_size);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
        self.congestion_recovery_start_time_ns = null;
        self.cubic.reset();
    }

    pub fn onPtoProbeSent(self: *Controller, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    pub fn discard(self: *Controller, bytes: usize) void {
        self.bytes_in_flight -|= bytes;
    }
};

fn boundedWindow(value: f64) usize {
    if (std.math.isNan(value) or value <= 0) return 0;
    if (!std.math.isFinite(value) or value >= @as(f64, @floatFromInt(std.math.maxInt(usize)))) {
        return std.math.maxInt(usize);
    }
    return @intFromFloat(value);
}

fn betaReduction(window: usize) usize {
    return @intCast((@as(u128, window) * 7) / 10);
}

pub fn initialWindow(max_datagram_size: usize) usize {
    return @min(10 *| max_datagram_size, @max(@as(usize, 14_720), 2 *| max_datagram_size));
}

pub fn minimumWindow(max_datagram_size: usize) usize {
    return 2 *| max_datagram_size;
}

test "QUIC congestion controller gates sends and grows on ACK" {
    var cc = Controller.init(1200);
    try std.testing.expectEqual(@as(usize, 12_000), cc.congestion_window);
    try cc.reserve(1200);
    try std.testing.expectEqual(@as(usize, 1200), cc.bytes_in_flight);
    cc.onAcked(1200);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 13_200), cc.congestion_window);
}

test "QUIC congestion controller reduces on loss" {
    var cc = Controller.init(1200);
    try cc.reserve(6000);
    cc.onLost(1200);
    try std.testing.expectEqual(@as(usize, 4800), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 8400), cc.congestion_window);
    try std.testing.expectEqual(cc.congestion_window, cc.slow_start_threshold);
}

test "QUIC congestion controller suppresses repeated recovery losses and ACK growth" {
    var cc = Controller.init(1200);
    try cc.reserve(12_000);

    cc.onLostAt(1200, 100, 200);
    const recovery_window = cc.congestion_window;
    try std.testing.expectEqual(@as(usize, 10_800), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 200), cc.congestion_recovery_start_time_ns);

    cc.onLostAt(1200, 150, 250);
    try std.testing.expectEqual(@as(usize, 9600), cc.bytes_in_flight);
    try std.testing.expectEqual(recovery_window, cc.congestion_window);

    cc.onAckedAt(1200, 180);
    try std.testing.expectEqual(@as(usize, 8400), cc.bytes_in_flight);
    try std.testing.expectEqual(recovery_window, cc.congestion_window);

    cc.onAckedAt(8400, 300);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), cc.congestion_recovery_start_time_ns);
    try std.testing.expect(cc.congestion_window > recovery_window);
}

test "QUIC congestion controller reacts to explicit ECN congestion once per recovery" {
    var cc = Controller.init(1200);
    try cc.reserve(6000);

    cc.onExplicitCongestion(200);
    const recovery_window = cc.congestion_window;
    try std.testing.expectEqual(@as(usize, 6000), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 8400), recovery_window);
    try std.testing.expectEqual(recovery_window, cc.slow_start_threshold);
    try std.testing.expectEqual(@as(?u64, 200), cc.congestion_recovery_start_time_ns);

    cc.onExplicitCongestion(250);
    try std.testing.expectEqual(recovery_window, cc.congestion_window);

    // ACKing packets that were sent before the ECN congestion event only
    // clears bytes in flight.  It must not exit recovery or grow cwnd.
    cc.onAckedAt(6000, 100);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(recovery_window, cc.congestion_window);
    try std.testing.expectEqual(@as(?u64, 200), cc.congestion_recovery_start_time_ns);

    try cc.reserve(8400);
    cc.onAckedAt(8400, 300);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), cc.congestion_recovery_start_time_ns);
    try std.testing.expect(cc.congestion_window > recovery_window);
}

test "QUIC congestion controller resets on persistent congestion" {
    var cc = Controller.init(1200);
    cc.congestion_window = 24_000;
    cc.slow_start_threshold = 24_000;
    cc.congestion_avoidance_bytes_acked = 12_000;

    cc.onPersistentCongestion();
    try std.testing.expectEqual(minimumWindow(1200), cc.congestion_window);
    try std.testing.expectEqual(cc.congestion_window, cc.slow_start_threshold);
    try std.testing.expectEqual(@as(usize, 0), cc.congestion_avoidance_bytes_acked);
}

test "QUIC CUBIC records RFC 9438 loss state and fast convergence" {
    var cc = Controller.initWithAlgorithm(1200, .cubic);
    cc.congestion_window = 120_000;
    cc.slow_start_threshold = 120_000;

    cc.onLostAt(1200, 100, 200);
    try std.testing.expectEqual(@as(usize, 84_000), cc.congestion_window);
    try std.testing.expectEqual(@as(f64, 120_000), cc.cubic.w_max);
    try std.testing.expect(cc.cubic.k_seconds > 0);
    try std.testing.expectEqual(@as(?u64, 200), cc.cubic.epoch_start_time_ns);

    cc.congestion_recovery_start_time_ns = null;
    cc.onLostAt(1200, 300, 400);
    try std.testing.expectEqual(@as(usize, 58_800), cc.congestion_window);
    try std.testing.expectApproxEqAbs(
        @as(f64, 84_000) * (1.0 + CubicState.beta) / 2.0,
        cc.cubic.w_max,
        0.001,
    );
}

test "QUIC CUBIC outgrows NewReno on a high bandwidth-delay path" {
    var reno = Controller.initWithAlgorithm(1200, .new_reno);
    var cubic = Controller.initWithAlgorithm(1200, .cubic);
    reno.congestion_window = 1_200_000;
    cubic.congestion_window = 1_200_000;
    reno.slow_start_threshold = reno.congestion_window;
    cubic.slow_start_threshold = cubic.congestion_window;

    reno.onLostAt(1200, 100, 200);
    cubic.onLostAt(1200, 100, 200);
    try std.testing.expectEqual(reno.congestion_window, cubic.congestion_window);

    // Model one full congestion window acknowledged per 100ms RTT. Once the
    // cubic curve returns to W_max it should use the path much more efficiently
    // than NewReno's one-datagram-per-RTT additive increase.
    var round: u64 = 1;
    while (round <= 120) : (round += 1) {
        const now = 200 + round * 100_000_000;
        const sent = 200 + (round - 1) * 100_000_000 + 1;
        const reno_acked = reno.congestion_window;
        const cubic_acked = cubic.congestion_window;
        reno.onAckedWithContext(reno_acked, sent, now, 100_000_000);
        cubic.onAckedWithContext(cubic_acked, sent, now, 100_000_000);
    }

    // The model yields about 23% more available flight capacity after twelve
    // seconds. Require at least 20% so this remains a meaningful performance
    // regression gate rather than a check for an incidental one-byte gain.
    try std.testing.expect(cubic.congestion_window > reno.congestion_window + reno.congestion_window / 5);
    try std.testing.expect(cubic.congestion_window > 1_200_000);
}

test "QUIC CUBIC untimed ACKs retain conservative progress" {
    var cc = Controller.initWithAlgorithm(1200, .cubic);
    cc.congestion_window = 12_000;
    cc.slow_start_threshold = 12_000;
    cc.onAcked(12_000);
    try std.testing.expectEqual(@as(usize, 13_200), cc.congestion_window);
}

test "QUIC untimed NewReno loss keeps untimed ACK progress" {
    var cc = Controller.initWithAlgorithm(1200, .new_reno);
    cc.onLost(1200);
    try std.testing.expectEqual(@as(?u64, null), cc.congestion_recovery_start_time_ns);
    cc.onAcked(cc.congestion_window);
    try std.testing.expectEqual(@as(usize, 9_600), cc.congestion_window);
}

const std = @import("std");
const hystart_mod = @import("hystart.zig");

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
    /// Start of an interval during which the sender was not congestion-window
    /// limited. RFC 9438 excludes this wall-clock interval from the cubic
    /// epoch so an idle application cannot earn a later burst of cwnd growth.
    app_limited_start_time_ns: ?u64 = null,
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
    hystart: hystart_mod.State,

    pub fn init(max_datagram_size: usize) Controller {
        return initWithAlgorithm(max_datagram_size, .new_reno);
    }

    pub fn initWithAlgorithm(max_datagram_size: usize, algorithm: Algorithm) Controller {
        return initWithOptions(max_datagram_size, algorithm, algorithm == .cubic);
    }

    pub fn initWithOptions(max_datagram_size: usize, algorithm: Algorithm, enable_hystart: bool) Controller {
        return .{
            .algorithm = algorithm,
            .max_datagram_size = max_datagram_size,
            .congestion_window = initialWindow(max_datagram_size),
            .hystart = .init(algorithm == .cubic and enable_hystart),
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

    /// Whether the current flight is large enough to justify cwnd growth.
    ///
    /// The thresholds match the audited quicz controller: half the window in
    /// slow start and at most three datagrams of spare capacity in congestion
    /// avoidance. The caller samples this before removing ACKed bytes.
    pub fn isCongestionWindowUtilized(self: Controller) bool {
        if (self.bytes_in_flight >= self.congestion_window) return true;
        if (self.inSlowStart()) {
            return self.bytes_in_flight >= self.congestion_window / 2;
        }
        return self.available() <= 3 *| self.max_datagram_size;
    }

    pub fn reserve(self: *Controller, bytes: usize) Error!void {
        if (bytes == 0) return;
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
        self.onAckedWithContextAndUtilization(
            bytes,
            sent_time_ns,
            now_ns,
            smoothed_rtt_ns,
            true,
        );
    }

    /// Apply an ACK while preserving whether the sender was cwnd-limited.
    ///
    /// RTT sampling is owned by the connection, so this routine always removes
    /// acknowledged bytes. Only congestion-window growth is suppressed for an
    /// application- or flow-control-limited sender, as required by RFC 9002
    /// section 7.8. CUBIC additionally pauses its wall-clock epoch during that
    /// interval so resuming traffic cannot turn idle time into a cwnd jump.
    pub fn onAckedWithContextAndUtilization(
        self: *Controller,
        bytes: usize,
        sent_time_ns: ?u64,
        now_ns: ?u64,
        smoothed_rtt_ns: ?u64,
        congestion_window_utilized: bool,
    ) void {
        if (bytes == 0) return;
        self.discard(bytes);

        if (self.congestion_recovery_start_time_ns) |recovery_start| {
            const sent_time = sent_time_ns orelse return;
            if (sent_time <= recovery_start) return;
            self.congestion_recovery_start_time_ns = null;
        }

        if (!congestion_window_utilized) {
            if (self.algorithm == .cubic and
                self.cubic.app_limited_start_time_ns == null)
            {
                // The ACK only reveals that the flight was underfilled. Start
                // the excluded interval at the acknowledged packet's send
                // time, matching quicz and avoiding credit for the intervening
                // idle RTT. Fall back to receipt time when callers lack sent
                // metadata.
                self.cubic.app_limited_start_time_ns =
                    sent_time_ns orelse now_ns;
            }
            return;
        }
        if (self.algorithm == .cubic) {
            self.resumeCubicEpoch(now_ns);
        }

        if (self.inSlowStart()) {
            const increment = self.hystart.congestionWindowIncrement(bytes, self.max_datagram_size);
            self.congestion_window +|= increment;
            if (self.hystart.hasExited()) {
                self.slow_start_threshold = self.congestion_window;
            }
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

    fn resumeCubicEpoch(self: *Controller, now_ns: ?u64) void {
        const app_limited_start =
            self.cubic.app_limited_start_time_ns orelse return;
        defer self.cubic.app_limited_start_time_ns = null;
        const now = now_ns orelse return;
        if (self.cubic.epoch_start_time_ns) |epoch_start| {
            self.cubic.epoch_start_time_ns =
                epoch_start +| (now -| app_limited_start);
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
        if (bytes == 0) return;
        self.discard(bytes);

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
        self.hystart.onCongestionEvent();

        if (self.algorithm == .cubic) {
            self.cubic.epoch_start_time_ns = event_time_ns;
            self.cubic.app_limited_start_time_ns = null;
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
        const hystart_enabled = self.hystart.enabled;
        self.congestion_window = minimumWindow(self.max_datagram_size);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
        self.congestion_recovery_start_time_ns = null;
        self.cubic.reset();
        self.hystart = .init(hystart_enabled);
    }

    pub fn onPtoProbeSent(self: *Controller, bytes: usize) void {
        if (bytes == 0) return;
        self.bytes_in_flight += bytes;
    }

    pub fn discard(self: *Controller, bytes: usize) void {
        if (bytes == 0) return;
        self.bytes_in_flight -|= bytes;
    }

    pub fn onPacketSent(self: *Controller, packet_number: u64) void {
        self.hystart.onPacketSent(packet_number);
    }

    pub fn onRttSample(self: *Controller, packet_number: u64, latest_rtt_ns: u64) void {
        if (!self.inSlowStart()) return;
        self.hystart.onAck(packet_number, latest_rtt_ns);
    }

    pub fn endAck(self: *Controller) void {
        if (!self.inSlowStart()) return;
        self.hystart.endAck();
        if (self.hystart.hasExited()) {
            self.slow_start_threshold = self.congestion_window;
        }
    }

    /// Retune congestion-controller packet-size heuristics after a validated
    /// PMTU change.
    ///
    /// This controller stores the congestion window in bytes, so a PMTU update
    /// must not increase the byte window merely because probing succeeded.
    /// Preserve the existing byte window and only update the datagram-sized
    /// thresholds that interpret it: utilization tests, NewReno step size, the
    /// CUBIC byte-to-packet curve, and future minimum/initial window
    /// calculations used by later congestion events.
    pub fn onMtuUpdate(self: *Controller, new_max_datagram_size: usize) void {
        if (new_max_datagram_size == 0 or new_max_datagram_size == self.max_datagram_size) return;
        self.max_datagram_size = new_max_datagram_size;
        if (self.algorithm == .cubic) {
            self.cubic.window_increment = 0;
            self.cubic.w_est = @floatFromInt(self.congestion_window);
            self.updateCubicK();
        }
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

test {
    _ = @import("congestion/tests.zig");
}

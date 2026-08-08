const std = @import("std");

/// RFC 9406 HyStart++ phase.
pub const Phase = enum {
    standard_slow_start,
    conservative_slow_start,
    exited,
};

/// Delay-based slow-start exit with Conservative Slow Start (CSS).
///
/// Packet-number round boundaries avoid relying on ACK arrival timing. The
/// implementation follows tquic's RFC 9406 state model while using optional
/// values so packet number zero and an uninitialized round remain distinct.
pub const State = struct {
    enabled: bool,
    phase: Phase = .standard_slow_start,
    last_round_min_rtt_ns: ?u64 = null,
    current_round_min_rtt_ns: ?u64 = null,
    rtt_sample_count: u32 = 0,
    last_sent_packet_number: ?u64 = null,
    max_acked_packet_number: ?u64 = null,
    window_end: ?u64 = null,
    css_round_count: u32 = 0,
    css_baseline_min_rtt_ns: ?u64 = null,

    pub const min_rtt_threshold_ns: u64 = 4_000_000;
    pub const max_rtt_threshold_ns: u64 = 16_000_000;
    pub const min_rtt_divisor: u64 = 8;
    pub const rtt_samples_per_round: u32 = 8;
    pub const css_growth_divisor: usize = 4;
    pub const css_rounds: u32 = 5;
    pub const max_growth_datagrams: usize = 64;

    pub fn init(enabled: bool) State {
        return .{ .enabled = enabled };
    }

    pub fn hasExited(self: State) bool {
        return self.phase == .exited;
    }

    pub fn inConservativeSlowStart(self: State) bool {
        return self.phase == .conservative_slow_start;
    }

    pub fn onPacketSent(self: *State, packet_number: u64) void {
        if (!self.enabled or self.hasExited()) return;
        self.last_sent_packet_number = packet_number;
    }

    pub fn onAck(self: *State, packet_number: u64, latest_rtt_ns: u64) void {
        if (!self.enabled or self.hasExited() or latest_rtt_ns == 0) return;

        if (self.max_acked_packet_number == null or packet_number > self.max_acked_packet_number.?) {
            self.max_acked_packet_number = packet_number;
        }
        self.current_round_min_rtt_ns = @min(
            self.current_round_min_rtt_ns orelse latest_rtt_ns,
            latest_rtt_ns,
        );
        self.rtt_sample_count +|= 1;
        if (self.rtt_sample_count < rtt_samples_per_round) return;

        switch (self.phase) {
            .standard_slow_start => {
                const previous_min = self.last_round_min_rtt_ns orelse return;
                const current_min = self.current_round_min_rtt_ns orelse return;
                const threshold = std.math.clamp(
                    previous_min / min_rtt_divisor,
                    min_rtt_threshold_ns,
                    max_rtt_threshold_ns,
                );
                const exit_rtt = std.math.add(u64, previous_min, threshold) catch std.math.maxInt(u64);
                if (current_min >= exit_rtt) {
                    self.css_baseline_min_rtt_ns = current_min;
                    self.phase = .conservative_slow_start;
                    self.css_round_count = 0;
                }
            },
            .conservative_slow_start => {
                const current_min = self.current_round_min_rtt_ns orelse return;
                const baseline = self.css_baseline_min_rtt_ns orelse return;
                if (current_min < baseline) {
                    // The delay increase was jitter rather than queue growth.
                    self.phase = .standard_slow_start;
                    self.css_baseline_min_rtt_ns = null;
                    self.css_round_count = 0;
                }
            },
            .exited => unreachable,
        }
    }

    /// Finish one ACK event and advance a packet-number round if its ACK crossed
    /// the prior round boundary.
    pub fn endAck(self: *State) void {
        if (!self.enabled or self.hasExited()) return;
        const max_acked = self.max_acked_packet_number orelse return;
        if (self.window_end) |window_end| {
            if (max_acked <= window_end) return;
        }

        self.window_end = self.last_sent_packet_number;
        self.last_round_min_rtt_ns = self.current_round_min_rtt_ns;
        self.current_round_min_rtt_ns = null;
        self.rtt_sample_count = 0;

        if (self.inConservativeSlowStart()) {
            self.css_round_count += 1;
            if (self.css_round_count >= css_rounds) {
                self.css_round_count = 0;
                self.phase = .exited;
            }
        }
    }

    pub fn onCongestionEvent(self: *State) void {
        if (!self.enabled) return;
        self.phase = .exited;
        self.window_end = null;
    }

    pub fn congestionWindowIncrement(self: State, acked_bytes: usize, max_datagram_size: usize) usize {
        if (!self.enabled) return acked_bytes;
        const cap = std.math.mul(usize, max_growth_datagrams, max_datagram_size) catch std.math.maxInt(usize);
        return switch (self.phase) {
            .standard_slow_start => @min(acked_bytes, cap),
            .conservative_slow_start => @min(acked_bytes / css_growth_divisor, cap),
            .exited => 0,
        };
    }
};

test "QUIC HyStart++ enters CSS on sustained RTT growth" {
    var state = State.init(true);

    for (0..State.rtt_samples_per_round) |i| {
        state.onPacketSent(@intCast(i));
        state.onAck(@intCast(i), 30_000_000 + i);
    }
    state.endAck();
    try std.testing.expectEqual(Phase.standard_slow_start, state.phase);

    for (0..State.rtt_samples_per_round) |i| {
        const packet_number: u64 = @intCast(State.rtt_samples_per_round + i);
        state.onPacketSent(packet_number);
        state.onAck(packet_number, 38_000_000 + i);
    }
    try std.testing.expect(state.inConservativeSlowStart());
    try std.testing.expectEqual(@as(usize, 2400), state.congestionWindowIncrement(9600, 1200));
}

test "QUIC HyStart++ rejects jitter and resumes standard slow start" {
    var state = State.init(true);
    state.last_round_min_rtt_ns = 30_000_000;
    state.window_end = 7;
    state.last_sent_packet_number = 15;
    for (8..16) |packet_number| state.onAck(@intCast(packet_number), 38_000_000);
    try std.testing.expect(state.inConservativeSlowStart());
    state.endAck();

    state.last_sent_packet_number = 23;
    for (16..24) |packet_number| state.onAck(@intCast(packet_number), 35_000_000);
    try std.testing.expectEqual(Phase.standard_slow_start, state.phase);
    try std.testing.expectEqual(@as(u32, 0), state.css_round_count);
}

test "QUIC HyStart++ exits after five CSS rounds" {
    var state = State.init(true);
    state.phase = .conservative_slow_start;
    state.css_baseline_min_rtt_ns = 40_000_000;
    state.window_end = 0;

    var round: u64 = 0;
    while (round < State.css_rounds) : (round += 1) {
        const packet_number = round + 1;
        state.onPacketSent(packet_number);
        state.onAck(packet_number, 41_000_000);
        state.endAck();
    }
    try std.testing.expect(state.hasExited());
    try std.testing.expectEqual(@as(usize, 0), state.congestionWindowIncrement(1200, 1200));
}

test "QUIC disabled HyStart++ preserves regular slow-start growth" {
    var state = State.init(false);
    state.onPacketSent(1);
    state.onAck(1, 100_000_000);
    state.endAck();
    try std.testing.expectEqual(@as(usize, 100_000), state.congestionWindowIncrement(100_000, 1500));
    try std.testing.expectEqual(Phase.standard_slow_start, state.phase);
}

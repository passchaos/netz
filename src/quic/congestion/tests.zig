const std = @import("std");
const congestion_root = @import("../congestion.zig");

const hystart_mod = @import("../hystart.zig");

const Algorithm = congestion_root.Algorithm;
const Controller = congestion_root.Controller;
const CubicState = congestion_root.CubicState;
const minimumWindow = congestion_root.minimumWindow;

test "QUIC congestion controller gates sends and grows on ACK" {
    var cc = Controller.init(1200);
    try std.testing.expectEqual(@as(usize, 12_000), cc.congestion_window);
    try cc.reserve(0);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try cc.reserve(1200);
    try std.testing.expectEqual(@as(usize, 1200), cc.bytes_in_flight);
    cc.onAcked(1200);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 13_200), cc.congestion_window);
}

test "QUIC congestion controller does not grow for underutilized ACK" {
    for ([_]Algorithm{ .new_reno, .cubic }) |algorithm| {
        var cc = Controller.initWithAlgorithm(1200, algorithm);
        const initial_window = cc.congestion_window;
        try cc.reserve(1200);
        try std.testing.expect(!cc.isCongestionWindowUtilized());
        cc.onAckedWithContextAndUtilization(
            1200,
            1,
            100_000_000,
            100_000_000,
            false,
        );
        try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
        try std.testing.expectEqual(initial_window, cc.congestion_window);
    }
}

test "QUIC CUBIC excludes application-limited time from its epoch" {
    var cc = Controller.initWithAlgorithm(1200, .cubic);
    cc.slow_start_threshold = cc.congestion_window;
    try cc.reserve(cc.congestion_window);
    try std.testing.expect(cc.isCongestionWindowUtilized());
    cc.onAckedWithContextAndUtilization(
        1200,
        1,
        1_000_000_000,
        100_000_000,
        true,
    );
    try std.testing.expectEqual(
        @as(?u64, 1_000_000_000),
        cc.cubic.epoch_start_time_ns,
    );

    cc.onAckedWithContextAndUtilization(
        1200,
        1_900_000_000,
        2_000_000_000,
        100_000_000,
        false,
    );
    const before_resume = cc.congestion_window;
    try std.testing.expectEqual(
        @as(?u64, 1_900_000_000),
        cc.cubic.app_limited_start_time_ns,
    );

    cc.onAckedWithContextAndUtilization(
        1200,
        4_900_000_000,
        5_000_000_000,
        100_000_000,
        true,
    );
    try std.testing.expectEqual(
        @as(?u64, 4_100_000_000),
        cc.cubic.epoch_start_time_ns,
    );
    try std.testing.expectEqual(@as(?u64, null), cc.cubic.app_limited_start_time_ns);
    try std.testing.expect(cc.congestion_window >= before_resume);
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

test "QUIC congestion controller skips zero-byte ACK loss and PTO events" {
    var cc = Controller.init(1200);
    try cc.reserve(2400);
    cc.onLostAt(1200, 100, 200);

    const recovery_window = cc.congestion_window;
    const recovery_start = cc.congestion_recovery_start_time_ns;
    const bytes_in_flight = cc.bytes_in_flight;
    const slow_start_threshold = cc.slow_start_threshold;

    cc.onAckedWithContext(0, 300, 400, 100_000_000);
    cc.onLostAt(0, 300, 400);
    cc.onPtoProbeSent(0);
    cc.discard(0);

    try std.testing.expectEqual(bytes_in_flight, cc.bytes_in_flight);
    try std.testing.expectEqual(recovery_window, cc.congestion_window);
    try std.testing.expectEqual(slow_start_threshold, cc.slow_start_threshold);
    try std.testing.expectEqual(recovery_start, cc.congestion_recovery_start_time_ns);
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

test "QUIC CUBIC HyStart++ reduces CSS growth and exits slow start" {
    var cc = Controller.initWithOptions(1200, .cubic, true);
    cc.congestion_window = 24_000;

    // Establish a 30ms baseline round.
    for (0..hystart_mod.State.rtt_samples_per_round) |packet_number| {
        cc.onPacketSent(@intCast(packet_number));
        cc.onRttSample(@intCast(packet_number), 30_000_000);
    }
    cc.endAck();

    // A sustained 38ms round exceeds max(30/8, 4ms) and enters CSS.
    for (0..hystart_mod.State.rtt_samples_per_round) |i| {
        const packet_number: u64 = @intCast(hystart_mod.State.rtt_samples_per_round + i);
        cc.onPacketSent(packet_number);
        cc.onRttSample(packet_number, 38_000_000);
    }
    try std.testing.expect(cc.hystart.inConservativeSlowStart());
    const before_css_ack = cc.congestion_window;
    cc.onAckedWithContext(4800, 1, 2, 38_000_000);
    try std.testing.expectEqual(before_css_ack + 1200, cc.congestion_window);
    cc.endAck();

    var round: u64 = 1;
    while (!cc.hystart.hasExited() and round <= hystart_mod.State.css_rounds) : (round += 1) {
        const packet_number = 100 + round;
        cc.onPacketSent(packet_number);
        cc.onRttSample(packet_number, 39_000_000);
        cc.endAck();
    }
    try std.testing.expect(cc.hystart.hasExited());
    try std.testing.expectEqual(cc.congestion_window, cc.slow_start_threshold);
    try std.testing.expect(!cc.inSlowStart());
}

test "QUIC CUBIC can disable HyStart++" {
    var cc = Controller.initWithOptions(1200, .cubic, false);
    cc.congestion_window = 24_000;
    for (0..32) |packet_number| {
        cc.onPacketSent(@intCast(packet_number));
        cc.onRttSample(@intCast(packet_number), if (packet_number < 8) 10_000_000 else 100_000_000);
        cc.endAck();
    }
    try std.testing.expect(!cc.hystart.enabled);
    try std.testing.expect(cc.inSlowStart());
    cc.onAcked(4800);
    try std.testing.expectEqual(@as(usize, 28_800), cc.congestion_window);
    cc.onPersistentCongestion();
    try std.testing.expect(!cc.hystart.enabled);
}

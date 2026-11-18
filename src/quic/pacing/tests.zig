const std = @import("std");
const pacing_root = @import("../pacing.zig");

const Pacer = pacing_root.Pacer;

test "QUIC pacer permits initial burst and computes exact deadline" {
    var pacer = Pacer.init(true, 1200, 10);
    try std.testing.expectEqual(@as(usize, 12_000), pacer.budget);
    pacer.onPacketSentAt(1_000_000, 0, 12_000, 100_000_000);
    try std.testing.expectEqual(@as(usize, 12_000), pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), pacer.lastSentTimeNs());

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

test "QUIC pacer keeps optional rate state compact" {
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(Pacer));
    }
    const unlimited = Pacer.init(true, 1200, 10);
    try std.testing.expectEqual(
        @as(?u64, null),
        unlimited.maxPacingRateBytesPerSecond(),
    );
    const paused = Pacer.initWithRateLimit(true, 1200, 10, 0);
    try std.testing.expectEqual(
        @as(?u64, 0),
        paused.maxPacingRateBytesPerSecond(),
    );
}

test "QUIC pacer reports its effective byte rate" {
    const unlimited = Pacer.init(true, 1200, 10);
    try std.testing.expectEqual(
        @as(?u64, 150_000),
        unlimited.rateBytesPerSecond(12_000, 100_000_000),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        unlimited.rateBytesPerSecond(0, 0),
    );

    const limited = Pacer.initWithRateLimit(true, 1200, 10, 100_000);
    try std.testing.expectEqual(
        @as(?u64, 100_000),
        limited.rateBytesPerSecond(12_000, 100_000_000),
    );
    try std.testing.expectEqual(
        @as(?u64, 100_000),
        limited.rateBytesPerSecond(0, 0),
    );
    const disabled = Pacer.initWithRateLimit(false, 1200, 10, 100_000);
    try std.testing.expectEqual(
        @as(?u64, null),
        disabled.rateBytesPerSecond(12_000, 100_000_000),
    );
}

test "QUIC pacer deadline uses current budget fast path" {
    var pacer = Pacer.init(true, 1200, 10);
    pacer.budget = 2400;
    pacer.setLastSentTimeNs(0);

    try std.testing.expectEqual(
        @as(?u64, null),
        pacer.deadlineAt(1, 1200, 12_000, 100_000_000),
    );
    try std.testing.expect(pacer.canSendAt(1, 1200, 12_000, 100_000_000));
}

test "QUIC pacer deadline starts after future last-send timestamp" {
    var pacer = Pacer.init(true, 1200, 10);
    pacer.budget = 0;
    pacer.setLastSentTimeNs(10_000_000);

    try std.testing.expectEqual(
        @as(?u64, 18_000_000),
        pacer.deadlineAt(1_000_000, 1200, 12_000, 100_000_000),
    );
    try std.testing.expect(!pacer.canSendAt(
        17_999_999,
        1200,
        12_000,
        100_000_000,
    ));
    try std.testing.expect(pacer.canSendAt(
        18_000_000,
        1200,
        12_000,
        100_000_000,
    ));
}

test "QUIC pacer replenishes and caps burst credit" {
    var pacer = Pacer.init(true, 1200, 10);
    pacer.setLastSentTimeNs(0);
    try std.testing.expectEqual(@as(usize, 12_000), pacer.budgetAt(1_000_000, 48_000, 100_000_000));
    pacer.onPacketSentAt(0, 12_000, 48_000, 100_000_000);
    try std.testing.expectEqual(@as(usize, 0), pacer.budget);
    try std.testing.expectEqual(@as(usize, 600), pacer.budgetAt(1_000_000, 48_000, 100_000_000));
    try std.testing.expectEqual(@as(usize, 12_000), pacer.budgetAt(1_000_000_000, 48_000, 100_000_000));
}

test "QUIC pacer maximum rate caps credit and deadline" {
    var pacer = Pacer.initWithRateLimit(true, 1200, 10, 100_000);
    pacer.onPacketSentAt(0, 12_000, 12_000, 100_000_000);
    try std.testing.expectEqual(@as(usize, 0), pacer.budget);

    // Congestion permits 150,000 bytes/s, but the explicit 100,000-byte/s
    // ceiling replenishes only 100 bytes after 1 ms.
    try std.testing.expectEqual(
        @as(usize, 100),
        pacer.budgetAt(1_000_000, 12_000, 100_000_000),
    );
    try std.testing.expectEqual(
        @as(?u64, 12_000_000),
        pacer.deadlineAt(1_000_000, 1200, 12_000, 100_000_000),
    );
    try std.testing.expect(!pacer.canSendAt(
        11_999_999,
        1200,
        12_000,
        100_000_000,
    ));
    try std.testing.expect(pacer.canSendAt(
        12_000_000,
        1200,
        12_000,
        100_000_000,
    ));
}

test "QUIC pacer keeps congestion rate when lower than maximum rate" {
    var pacer = Pacer.initWithRateLimit(true, 1200, 10, 1_000_000);
    pacer.onPacketSentAt(0, 12_000, 48_000, 100_000_000);

    // Congestion permits 600,000 bytes/s, below the explicit ceiling.
    try std.testing.expectEqual(
        @as(usize, 600),
        pacer.budgetAt(1_000_000, 48_000, 100_000_000),
    );
    try std.testing.expectEqual(
        @as(?u64, 2_000_000),
        pacer.deadlineAt(1_000_000, 1200, 48_000, 100_000_000),
    );
}

test "QUIC pacer changes rate without repricing earned credit" {
    var lowered = Pacer.init(true, 1200, 10);
    lowered.onPacketSentAt(0, 12_000, 48_000, 100_000_000);
    lowered.setMaxPacingRateBytesPerSecondAt(
        100_000,
        1_000_000,
        48_000,
        100_000_000,
    );
    // The first millisecond was earned at 600,000 bytes/s. Only subsequent
    // credit uses the new 100,000-byte/s ceiling.
    try std.testing.expectEqual(@as(usize, 600), lowered.budget);
    try std.testing.expectEqual(
        @as(usize, 700),
        lowered.budgetAt(2_000_000, 48_000, 100_000_000),
    );

    lowered.setMaxPacingRateBytesPerSecondAt(
        null,
        2_000_000,
        48_000,
        100_000_000,
    );
    try std.testing.expectEqual(@as(usize, 700), lowered.budget);
    try std.testing.expectEqual(
        @as(usize, 1300),
        lowered.budgetAt(3_000_000, 48_000, 100_000_000),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        lowered.maxPacingRateBytesPerSecond(),
    );
}

test "QUIC pacer rate update preserves future accounting timestamp" {
    var pacer = Pacer.init(true, 1200, 10);
    pacer.budget = 0;
    pacer.setLastSentTimeNs(10_000_000);
    pacer.setMaxPacingRateBytesPerSecondAt(
        0,
        1_000_000,
        12_000,
        100_000_000,
    );
    try std.testing.expectEqual(@as(usize, 0), pacer.budget);
    try std.testing.expectEqual(
        @as(?u64, 10_000_000),
        pacer.lastSentTimeNs(),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        pacer.maxPacingRateBytesPerSecond(),
    );
    try std.testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        pacer.deadlineAt(10_000_000, 1, 12_000, 100_000_000),
    );
}

test "QUIC pacer maximum rate remains active without RTT" {
    var pacer = Pacer.initWithRateLimit(true, 1200, 10, 100_000);
    pacer.onPacketSentAt(0, 12_000, 0, 0);
    try std.testing.expectEqual(
        @as(usize, 100),
        pacer.budgetAt(1_000_000, 0, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, 12_000_000),
        pacer.deadlineAt(1_000_000, 1200, 0, 0),
    );

    var paused = Pacer.initWithRateLimit(true, 1200, 1, 0);
    paused.onPacketSentAt(0, 1200, 0, 0);
    try std.testing.expectEqual(@as(usize, 0), paused.budgetAt(
        std.math.maxInt(u64),
        0,
        0,
    ));
    try std.testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        paused.deadlineAt(1, 1, 0, 0),
    );
}

test "QUIC disabled pacer never gates and reset restores burst" {
    var disabled = Pacer.init(false, 1200, 10);
    disabled.onPacketSentAt(0, 12_000, 12_000, 100_000_000);
    try std.testing.expect(disabled.deadlineAt(0, std.math.maxInt(usize), 1, 1) == null);

    var enabled = Pacer.init(true, 1200, 10);
    enabled.onPacketSentAt(10, 1200, 12_000, 100_000_000);
    enabled.reset();
    try std.testing.expectEqual(@as(usize, 12_000), enabled.budget);
    try std.testing.expectEqual(@as(?u64, null), enabled.lastSentTimeNs());
}

test "QUIC pacer saturates extreme arithmetic" {
    var pacer = Pacer.init(true, std.math.maxInt(usize), std.math.maxInt(usize));
    pacer.budget = 0;
    pacer.setLastSentTimeNs(0);
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

    if (@sizeOf(usize) == 8) {
        const packet_size = std.math.maxInt(usize);
        const congestion_window = std.math.maxInt(usize);
        const smoothed_rtt_ns = std.math.maxInt(u64);
        const numerator = @as(u256, packet_size) * smoothed_rtt_ns *
            Pacer.congestion_rate_denominator;
        const denominator = @as(u256, congestion_window) *
            Pacer.congestion_rate_numerator;
        const expected: u64 = @intCast(
            numerator / denominator +
                @intFromBool(numerator % denominator != 0),
        );
        try std.testing.expectEqual(
            @as(?u64, expected),
            pacer.deadlineAt(
                0,
                packet_size,
                congestion_window,
                smoothed_rtt_ns,
            ),
        );
    }
}

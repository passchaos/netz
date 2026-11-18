const std = @import("std");
const pmtu_root = @import("../pmtu.zig");

const State = pmtu_root.State;
const black_hole_cooldown_ns = pmtu_root.black_hole_cooldown_ns;
const max_ipv4_udp_payload_size = pmtu_root.max_ipv4_udp_payload_size;
const max_ipv6_udp_payload_size = pmtu_root.max_ipv6_udp_payload_size;
const min_udp_payload_size = pmtu_root.min_udp_payload_size;
const pmtu_raise_timer_ns = pmtu_root.pmtu_raise_timer_ns;

test "QUIC PMTUD disabled state does not probe" {
    var state = State.init(.{ .enabled = false });
    try std.testing.expect(!state.shouldProbe());
    try std.testing.expectEqual(@as(?usize, null), state.probeSize(1500));
}

test "QUIC PMTUD disabled state still recovers from a black hole" {
    var state = State.init(.{
        .enabled = false,
        .initial_size = 1400,
        .max_probe_size = 1400,
    });
    try std.testing.expectEqual(@as(usize, 1400), state.currentSize());
    try std.testing.expect(!state.shouldProbe());

    for ([_]u64{ 0, 2, 4, 6 }) |packet_number| {
        try std.testing.expect(!state.onNonProbeLost(
            packet_number,
            1300,
            true,
            packet_number + 1,
        ).mtu_dropped);
    }
    const dropped = state.finishLossBurst(10);
    try std.testing.expect(dropped.mtu_dropped);
    try std.testing.expectEqual(min_udp_payload_size, state.currentSize());
    try std.testing.expectEqual(@as(?u64, null), state.probeDeadlineNs());
    try std.testing.expect(!state.shouldProbe());

    state.resetForPath();
    try std.testing.expectEqual(@as(usize, 1400), state.currentSize());
    try std.testing.expect(!state.shouldProbe());
}

test "QUIC PMTUD retains size-only probe API compatibility" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1300 });
    state.onProbeSent(1300);
    state.onProbeAcked(1300, 1300);
    try std.testing.expectEqual(@as(usize, 1300), state.currentSize());

    state.resetForPath();
    state.onProbeSent(1300);
    state.onProbeLost(1300, 1300);
    try std.testing.expect(state.shouldProbe());
}

test "QUIC PMTUD validates maximum probe immediately" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1200, .is_ipv6 = false });
    const size = state.probeSize(60_000).?;
    try std.testing.expectEqual(max_ipv4_udp_payload_size, size);
    state.onProbeSentWithIdentity(1, 1, size);
    state.onProbeAckedWithIdentity(1, 1, size, 60_000, 10);
    try std.testing.expectEqual(max_ipv4_udp_payload_size, state.currentSize());
    try std.testing.expect(!state.shouldProbe());
    state.onProbeAckedWithIdentity(1, 1, size, 60_000, 20);
    try std.testing.expectEqual(max_ipv4_udp_payload_size, state.currentSize());
    try std.testing.expect(!state.shouldProbe());
    state.onProbeLostWithIdentity(1, 1, size, 60_000, 30);
    try std.testing.expectEqual(max_ipv4_udp_payload_size, state.currentSize());
    try std.testing.expectEqual(@as(u8, 0), state.consecutive_failures);
    try std.testing.expect(!state.shouldProbe());
}

test "QUIC PMTUD lowers ceiling after repeated losses" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1500, .is_ipv6 = true, .max_probe_failures = 2 });
    const first = state.probeSize(max_ipv6_udp_payload_size).?;
    try std.testing.expectEqual(max_ipv6_udp_payload_size, first);
    state.onProbeSentWithIdentity(1, 1, first);
    state.onProbeLostWithIdentity(1, 1, first, max_ipv6_udp_payload_size, 10);
    try std.testing.expect(state.shouldProbe());
    try std.testing.expectEqual(first, state.probeSize(max_ipv6_udp_payload_size).?);
    state.onProbeSentWithIdentity(2, 1, first);
    state.onProbeLostWithIdentity(2, 1, first, max_ipv6_udp_payload_size, 20);
    try std.testing.expectEqual(first, state.failed_size);
    try std.testing.expect(state.shouldProbe());
    const next = state.probeSize(max_ipv6_udp_payload_size).?;
    try std.testing.expect(next < first);
    try std.testing.expect(next > min_udp_payload_size);
}

test "QUIC PMTUD converges on mid-path MTU" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1500, .is_ipv6 = true, .max_probe_failures = 2 });
    const path_mtu: usize = 1350;
    var i: usize = 0;
    while (state.shouldProbe() and i < 16) : (i += 1) {
        const size = state.probeSize(60_000) orelse break;
        const packet_number: u64 = @intCast(i * 2 + 1);
        state.onProbeSentWithIdentity(packet_number, 1, size);
        if (size <= path_mtu) {
            state.onProbeAckedWithIdentity(packet_number, 1, size, 60_000, @intCast(i + 1));
        } else {
            state.onProbeLostWithIdentity(packet_number, 1, size, 60_000, @intCast(i + 1));
            if (state.shouldProbe()) {
                const retry_packet_number: u64 = @intCast(i * 2 + 2);
                state.onProbeSentWithIdentity(retry_packet_number, 1, size);
                state.onProbeLostWithIdentity(retry_packet_number, 1, size, 60_000, @intCast(i + 101));
            }
        }
    }
    try std.testing.expect(state.currentSize() <= path_mtu);
    try std.testing.expect(state.currentSize() >= 1340);
}

test "QUIC PMTUD successful lower probe preserves failed upper bound" {
    var state = State.init(.{
        .enabled = true,
        .max_probe_size = 1500,
        .max_probe_failures = 1,
    });

    state.onProbeSentWithIdentity(1, 1, 1400);
    state.onProbeLostWithIdentity(1, 1, 1400, 1500, 10);
    try std.testing.expectEqual(@as(usize, 1400), state.failed_size);

    const lower = state.probeSize(1500).?;
    try std.testing.expect(lower < 1400);
    state.onProbeSentWithIdentity(2, 1, lower);
    state.onProbeAckedWithIdentity(2, 1, lower, 1500, 20);

    // A successful midpoint raises the floor but must not forget the failed
    // ceiling; otherwise the next search step would retry 1400 forever.
    try std.testing.expectEqual(@as(usize, 1400), state.failed_size);
    try std.testing.expect(state.probeSize(1500).? < 1400);
}

test "QUIC PMTUD reset restores search state" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    const size = state.probeSize(1400).?;
    state.onProbeSentWithIdentity(1, 1, size);
    state.onProbeAckedWithIdentity(1, 1, size, 1400, 10);
    try std.testing.expect(state.currentSize() > min_udp_payload_size);
    state.resetForPath();
    try std.testing.expectEqual(min_udp_payload_size, state.currentSize());
    try std.testing.expect(state.shouldProbe());
}

test "QUIC PMTUD black-hole detection requires four discontiguous bursts" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;

    try std.testing.expect(!state.onNonProbeLost(1, 1300, true, 10).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(2, 1300, false, 20).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(4, 1300, true, 30).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(7, 1300, true, 40).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(10, 1300, true, 50).mtu_dropped);
    const result = state.finishLossBurst(50);
    try std.testing.expect(result.mtu_dropped);
    try std.testing.expectEqual(min_udp_payload_size, result.new_size);
    try std.testing.expectEqual(min_udp_payload_size, state.currentSize());
    try std.testing.expectEqual(@as(?u64, 50 + black_hole_cooldown_ns), state.probeDeadlineNs());
}

test "QUIC PMTUD black-hole evidence clears on acknowledged MTU-sized packet" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;

    try std.testing.expect(!state.onNonProbeLost(10, 1300, true, 10).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(12, 1300, true, 20).mtu_dropped);
    try std.testing.expect(!state.finishLossBurst(20).mtu_dropped);
    state.onMtuSizedPacketAcked(13, 1300);
    try std.testing.expect(!state.onNonProbeLost(14, 1300, true, 30).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(16, 1300, true, 40).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(18, 1300, true, 50).mtu_dropped);
    try std.testing.expect(!state.finishLossBurst(50).mtu_dropped);
}

test "QUIC PMTUD successful smaller datagram prunes only disproven bursts" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1500 });
    state.current_size = 1400;

    try std.testing.expect(!state.onNonProbeLost(1, 1250, true, 10).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(3, 1350, true, 20).mtu_dropped);
    try std.testing.expect(!state.finishLossBurst(20).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 2), state.black_hole_counter);

    state.onMtuSizedPacketAcked(4, 1300);
    try std.testing.expectEqual(@as(usize, 1300), state.ackedMtu());
    try std.testing.expectEqual(@as(u8, 1), state.black_hole_counter);
    try std.testing.expectEqual(
        @as(u16, 1350),
        state.suspicious_loss_burst_sizes[0],
    );

    // An older loss smaller than the later successful datagram is ordinary
    // congestion. The same size sent after that ACK remains valid evidence.
    try std.testing.expect(!state.onNonProbeLost(2, 1240, true, 30).mtu_dropped);
    try std.testing.expect(!state.finishLossBurst(30).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 1), state.black_hole_counter);
    try std.testing.expect(!state.onNonProbeLost(5, 1240, true, 40).mtu_dropped);
    try std.testing.expect(!state.finishLossBurst(40).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 2), state.black_hole_counter);
    try std.testing.expectEqual(min_udp_payload_size, state.ackedMtu());
}

test "QUIC PMTUD completed search rearms after raise timer" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;
    state.failed_size = 1400;
    state.raise_probe_after_ns = 50 + pmtu_raise_timer_ns;
    state.should_probe = false;
    try std.testing.expect(!state.shouldProbe());
    try std.testing.expectEqual(@as(?u64, 50 + pmtu_raise_timer_ns), state.probeDeadlineNs());
    try std.testing.expect(!state.serviceRaiseTimer(49 + pmtu_raise_timer_ns, 1400));
    try std.testing.expect(state.serviceRaiseTimer(50 + pmtu_raise_timer_ns, 1400));
    try std.testing.expect(state.shouldProbe());
}

test "QUIC PMTUD rejects a burst containing a base-sized loss" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;

    try std.testing.expect(!state.onNonProbeLost(10, 1300, true, 10).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(11, 1200, false, 20).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(12, 1300, false, 30).mtu_dropped);
    try std.testing.expect(!state.finishLossBurst(30).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 0), state.black_hole_counter);
}

test "QUIC PMTUD probe loss separates ordinary loss bursts" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;

    try std.testing.expect(!state.onNonProbeLost(20, 1300, true, 10).mtu_dropped);
    try std.testing.expect(!state.onPacketLost(21, 1400, true, false, 20).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(22, 1300, false, 30).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 1), state.black_hole_counter);
    try std.testing.expect(!state.finishLossBurst(30).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 2), state.black_hole_counter);
}

test "QUIC PMTUD raise timer respects peer ceiling" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;
    state.failed_size = 1400;
    state.raise_probe_after_ns = 10;
    state.should_probe = false;

    try std.testing.expect(!state.serviceRaiseTimer(10, 1300));
    try std.testing.expect(!state.shouldProbe());
    try std.testing.expectEqual(@as(usize, 0), state.failed_size);
}

test "QUIC PMTUD raise timer retries configured ceiling after failure" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;
    state.failed_size = 1400;
    state.raise_probe_after_ns = 10;

    try std.testing.expect(state.serviceRaiseTimer(10, 0));
    try std.testing.expect(state.shouldProbe());
    try std.testing.expectEqual(@as(usize, 0), state.failed_size);
    try std.testing.expectEqual(@as(?usize, 1400), state.probeSize(0));
}

const std = @import("std");

/// QUIC's minimum allowed UDP payload size (RFC 9000 §14).
pub const min_udp_payload_size: usize = 1200;
/// Ethernet-sized UDP payload ceilings used by tquic when the peer does not
/// advertise a smaller max_udp_payload_size.
pub const max_ipv4_udp_payload_size: usize = 1472;
pub const max_ipv6_udp_payload_size: usize = 1452;
pub const default_max_probe_failures: u8 = 3;
pub const black_hole_threshold: u8 = 3;
pub const black_hole_cooldown_ns: u64 = 60 * std.time.ns_per_s;
pub const pmtu_raise_timer_ns: u64 = 600 * std.time.ns_per_s;

pub const Config = struct {
    enabled: bool = false,
    max_probe_size: usize = max_ipv4_udp_payload_size,
    is_ipv6: bool = false,
    max_probe_failures: u8 = default_max_probe_failures,
};

/// Datagram PLPMTUD state for one QUIC path.
///
/// This intentionally tracks only packet sizing state.  Packet construction is
/// left to `one_rtt`/endpoint code: a PMTU probe packet should contain an
/// ack-eliciting PING plus enough PADDING to reach `probeSize()`.
pub const State = struct {
    enabled: bool = false,
    current_size: usize = min_udp_payload_size,
    max_probe_size: usize = max_ipv4_udp_payload_size,
    probe_size: ?usize = null,
    failed_size: usize = 0,
    consecutive_failures: u8 = 0,
    max_probe_failures: u8 = default_max_probe_failures,
    should_probe: bool = false,
    black_hole_counter: u8 = 0,
    largest_acked_mtu_sized_packet: ?u64 = null,
    raise_probe_after_ns: ?u64 = null,
    active_probe_packet_number: ?u64 = null,
    active_probe_epoch: u32 = 0,
    active_probe_size: ?usize = null,
    last_loss_packet_number: ?u64 = null,
    loss_burst_signaled: bool = false,

    pub const BlackHoleResult = struct {
        mtu_dropped: bool = false,
        new_size: usize = min_udp_payload_size,
    };

    // Packet number zero and epoch zero are reserved here as the compatibility
    // identity used by the original size-only probe API. Production 1-RTT
    // paths use the explicit identity-aware variants below.

    pub fn init(config: Config) State {
        var max_probe_size = config.max_probe_size;
        if (max_probe_size <= min_udp_payload_size) {
            max_probe_size = if (config.is_ipv6) max_ipv6_udp_payload_size else max_ipv4_udp_payload_size;
        }
        max_probe_size = @max(max_probe_size, min_udp_payload_size);
        return .{
            .enabled = config.enabled,
            .max_probe_size = max_probe_size,
            .max_probe_failures = @max(config.max_probe_failures, 1),
            .should_probe = config.enabled,
        };
    }

    pub fn currentSize(self: State) usize {
        return self.current_size;
    }

    pub fn shouldProbe(self: State) bool {
        return self.enabled and self.should_probe;
    }

    pub fn probeDeadlineNs(self: State) ?u64 {
        if (!self.enabled or self.should_probe) return null;
        return self.raise_probe_after_ns;
    }

    pub fn probeSize(self: *State, peer_max_udp_payload: usize) ?usize {
        if (!self.shouldProbe()) return null;
        if (self.probe_size) |size| return size;
        const size = self.calculateProbeSize(peer_max_udp_payload);
        if (size <= self.current_size) {
            self.should_probe = false;
            return null;
        }
        self.probe_size = size;
        return size;
    }

    pub fn onProbeSent(self: *State, size: usize) void {
        self.onProbeSentWithIdentity(0, 0, size);
    }

    pub fn onProbeSentWithIdentity(self: *State, packet_number: u64, probe_epoch: u32, size: usize) void {
        if (self.probe_size == null) self.probe_size = size;
        self.active_probe_packet_number = packet_number;
        self.active_probe_epoch = probe_epoch;
        self.active_probe_size = size;
        self.should_probe = false;
        self.raise_probe_after_ns = null;
    }

    pub fn onProbeAcked(
        self: *State,
        size: usize,
        peer_max_udp_payload: usize,
    ) void {
        self.onProbeAckedWithIdentity(0, 0, size, peer_max_udp_payload, null);
    }

    pub fn onProbeAckedWithIdentity(
        self: *State,
        packet_number: u64,
        probe_epoch: u32,
        size: usize,
        peer_max_udp_payload: usize,
        now_ns: ?u64,
    ) void {
        if (self.active_probe_packet_number == null or
            self.active_probe_packet_number.? != packet_number or
            self.active_probe_epoch != probe_epoch)
        {
            return;
        }
        self.active_probe_packet_number = null;
        self.active_probe_size = null;
        self.onMtuSizedPacketAcked(packet_number, size);
        if (size <= self.current_size) return;
        self.current_size = @max(self.current_size, size);
        self.consecutive_failures = 0;
        self.probe_size = null;
        self.should_probe = !self.finished(peer_max_udp_payload);
        self.armRaiseTimer(now_ns, peer_max_udp_payload);
    }

    pub fn onProbeLost(
        self: *State,
        size: usize,
        peer_max_udp_payload: usize,
    ) void {
        self.onProbeLostWithIdentity(0, 0, size, peer_max_udp_payload, null);
    }

    pub fn onProbeLostWithIdentity(
        self: *State,
        packet_number: u64,
        probe_epoch: u32,
        size: usize,
        peer_max_udp_payload: usize,
        now_ns: ?u64,
    ) void {
        if (self.active_probe_packet_number == null or
            self.active_probe_packet_number.? != packet_number or
            self.active_probe_epoch != probe_epoch)
        {
            return;
        }
        self.active_probe_packet_number = null;
        self.active_probe_size = null;
        if (size <= self.current_size) return;
        if (self.probe_size) |probe| {
            if (probe != size) return;
        }
        self.consecutive_failures +|= 1;
        if (self.consecutive_failures < self.max_probe_failures) {
            self.should_probe = true;
            return;
        }
        self.failed_size = size;
        self.consecutive_failures = 0;
        self.probe_size = null;
        self.should_probe = !self.finished(peer_max_udp_payload);
        self.armRaiseTimer(now_ns, peer_max_udp_payload);
    }

    pub fn onMtuSizedPacketAcked(self: *State, packet_number: u64, datagram_size: usize) void {
        if (!self.enabled) return;
        if (datagram_size < self.current_size) return;
        if (self.largest_acked_mtu_sized_packet) |largest| {
            if (packet_number <= largest) return;
        }
        self.black_hole_counter = 0;
        self.largest_acked_mtu_sized_packet = packet_number;
    }

    /// Observe one ordinary packet loss for PMTU black-hole detection.
    ///
    /// Only non-probe datagrams larger than the base PLPMTU and no larger than
    /// the currently validated PMTU qualify. The caller supplies
    /// `new_loss_burst` so one congestion outage contributes at most one signal
    /// per discontiguous packet-number run.
    pub fn onNonProbeLost(
        self: *State,
        packet_number: u64,
        datagram_size: usize,
        new_loss_burst: bool,
        now_ns: u64,
    ) BlackHoleResult {
        return self.onPacketLost(
            packet_number,
            datagram_size,
            false,
            new_loss_burst,
            now_ns,
        );
    }

    /// Preserve loss-burst continuity for every packet on the current path.
    ///
    /// PMTU probes and base-sized packets never increment black-hole evidence,
    /// but they still bridge adjacent packet numbers. Without observing them,
    /// one contiguous outage split around a probe (or across two detector
    /// passes) could be counted as multiple independent loss bursts.
    pub fn onPacketLost(
        self: *State,
        packet_number: u64,
        datagram_size: usize,
        is_probe: bool,
        new_loss_burst: bool,
        now_ns: u64,
    ) BlackHoleResult {
        const contiguous_with_previous = if (self.last_loss_packet_number) |previous|
            previous +| 1 == packet_number
        else
            false;
        if (!contiguous_with_previous and new_loss_burst) {
            self.loss_burst_signaled = false;
        }
        self.last_loss_packet_number = packet_number;
        if (!self.enabled or (!new_loss_burst and !contiguous_with_previous)) return .{};
        if (is_probe) return .{};
        if (datagram_size <= min_udp_payload_size or datagram_size > self.current_size) return .{};
        if (self.largest_acked_mtu_sized_packet) |largest| {
            if (packet_number <= largest) return .{};
        }
        if (self.loss_burst_signaled) return .{};
        self.black_hole_counter +|= 1;
        self.loss_burst_signaled = true;
        if (self.black_hole_counter <= black_hole_threshold) return .{};
        self.black_hole_counter = 0;
        self.largest_acked_mtu_sized_packet = null;
        self.current_size = min_udp_payload_size;
        self.probe_size = null;
        self.failed_size = 0;
        self.consecutive_failures = 0;
        self.active_probe_packet_number = null;
        self.active_probe_size = null;
        self.should_probe = false;
        self.raise_probe_after_ns = std.math.add(u64, now_ns, black_hole_cooldown_ns) catch std.math.maxInt(u64);
        return .{ .mtu_dropped = true, .new_size = self.current_size };
    }

    pub fn serviceRaiseTimer(self: *State, now_ns: u64, peer_max_udp_payload: usize) bool {
        const deadline = self.raise_probe_after_ns orelse return false;
        if (now_ns < deadline) return false;
        self.raise_probe_after_ns = null;
        self.failed_size = 0;
        const next_size = self.calculateProbeSize(peer_max_udp_payload);
        if (next_size <= self.current_size) return false;
        self.should_probe = true;
        return true;
    }

    pub fn resetForPath(self: *State) void {
        const enabled = self.enabled;
        const max_probe_size = self.max_probe_size;
        const max_probe_failures = self.max_probe_failures;
        self.* = .{
            .enabled = enabled,
            .max_probe_size = max_probe_size,
            .max_probe_failures = max_probe_failures,
            .should_probe = enabled,
        };
    }

    fn armRaiseTimer(
        self: *State,
        now_ns: ?u64,
        peer_max_udp_payload: usize,
    ) void {
        if (!self.enabled) {
            self.raise_probe_after_ns = null;
            return;
        }
        if (!self.finished(peer_max_udp_payload) or self.should_probe) {
            self.raise_probe_after_ns = null;
            return;
        }
        const base = now_ns orelse return;
        self.raise_probe_after_ns = std.math.add(u64, base, pmtu_raise_timer_ns) catch std.math.maxInt(u64);
    }

    fn ceiling(self: State, peer_max_udp_payload: usize) usize {
        var upper = if (self.failed_size != 0) self.failed_size - 1 else self.max_probe_size;
        if (peer_max_udp_payload != 0) upper = @min(upper, peer_max_udp_payload);
        return @max(upper, min_udp_payload_size);
    }

    fn calculateProbeSize(self: State, peer_max_udp_payload: usize) usize {
        const upper = self.ceiling(peer_max_udp_payload);
        if (self.failed_size == 0 and upper <= max_ipv4_udp_payload_size) return upper;
        return self.current_size + (upper - self.current_size) / 2;
    }

    fn finished(self: State, peer_max_udp_payload: usize) bool {
        const upper = self.ceiling(peer_max_udp_payload);
        if (self.current_size >= upper) return true;
        // Match the common tquic heuristic: stop when the remaining search gap
        // is below 1%, avoiding endless one-byte probes near the ceiling.
        return self.current_size * 100 >= upper * 99;
    }
};

test "QUIC PMTUD disabled state does not probe" {
    var state = State.init(.{ .enabled = false });
    try std.testing.expect(!state.shouldProbe());
    try std.testing.expectEqual(@as(?usize, null), state.probeSize(1500));
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
    const result = state.onNonProbeLost(10, 1300, true, 50);
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
    state.onMtuSizedPacketAcked(13, 1300);
    try std.testing.expect(!state.onNonProbeLost(14, 1300, true, 30).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(16, 1300, true, 40).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(18, 1300, true, 50).mtu_dropped);
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

test "QUIC PMTUD preserves contiguous loss burst across calls and bridging losses" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    state.current_size = 1300;

    try std.testing.expect(!state.onNonProbeLost(10, 1300, true, 10).mtu_dropped);
    // A non-qualifying bridging loss still keeps the contiguous run open.
    try std.testing.expect(!state.onNonProbeLost(11, 1200, false, 20).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(12, 1300, false, 30).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 1), state.black_hole_counter);

    // Probe loss is not evidence itself, but it is part of the same packet
    // number run and must not split the surrounding ordinary losses.
    try std.testing.expect(!state.onPacketLost(13, 1400, true, true, 40).mtu_dropped);
    try std.testing.expect(!state.onNonProbeLost(14, 1300, false, 50).mtu_dropped);
    try std.testing.expectEqual(@as(u8, 1), state.black_hole_counter);
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

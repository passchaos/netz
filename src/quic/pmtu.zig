const std = @import("std");

/// QUIC's minimum allowed UDP payload size (RFC 9000 §14).
pub const min_udp_payload_size: usize = 1200;
/// Ethernet-sized UDP payload ceilings used by tquic when the peer does not
/// advertise a smaller max_udp_payload_size.
pub const max_ipv4_udp_payload_size: usize = 1472;
pub const max_ipv6_udp_payload_size: usize = 1452;
pub const default_max_probe_failures: u8 = 3;

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
        if (self.probe_size == null) self.probe_size = size;
        self.should_probe = false;
    }

    pub fn onProbeAcked(self: *State, size: usize, peer_max_udp_payload: usize) void {
        self.current_size = @max(self.current_size, size);
        self.consecutive_failures = 0;
        self.probe_size = null;
        self.should_probe = !self.finished(peer_max_udp_payload);
    }

    pub fn onProbeLost(self: *State, size: usize, peer_max_udp_payload: usize) void {
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

test "QUIC PMTUD validates maximum probe immediately" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1200, .is_ipv6 = false });
    const size = state.probeSize(60_000).?;
    try std.testing.expectEqual(max_ipv4_udp_payload_size, size);
    state.onProbeSent(size);
    state.onProbeAcked(size, 60_000);
    try std.testing.expectEqual(max_ipv4_udp_payload_size, state.currentSize());
    try std.testing.expect(!state.shouldProbe());
}

test "QUIC PMTUD lowers ceiling after repeated losses" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1500, .is_ipv6 = true, .max_probe_failures = 2 });
    const first = state.probeSize(max_ipv6_udp_payload_size).?;
    try std.testing.expectEqual(max_ipv6_udp_payload_size, first);
    state.onProbeSent(first);
    state.onProbeLost(first, max_ipv6_udp_payload_size);
    try std.testing.expect(state.shouldProbe());
    try std.testing.expectEqual(first, state.probeSize(max_ipv6_udp_payload_size).?);
    state.onProbeSent(first);
    state.onProbeLost(first, max_ipv6_udp_payload_size);
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
        state.onProbeSent(size);
        if (size <= path_mtu) {
            state.onProbeAcked(size, 60_000);
        } else {
            state.onProbeLost(size, 60_000);
            if (state.shouldProbe()) {
                state.onProbeSent(size);
                state.onProbeLost(size, 60_000);
            }
        }
    }
    try std.testing.expect(state.currentSize() <= path_mtu);
    try std.testing.expect(state.currentSize() >= 1340);
}

test "QUIC PMTUD reset restores search state" {
    var state = State.init(.{ .enabled = true, .max_probe_size = 1400 });
    const size = state.probeSize(1400).?;
    state.onProbeSent(size);
    state.onProbeAcked(size, 1400);
    try std.testing.expect(state.currentSize() > min_udp_payload_size);
    state.resetForPath();
    try std.testing.expectEqual(min_udp_payload_size, state.currentSize());
    try std.testing.expect(state.shouldProbe());
}

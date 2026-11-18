const std = @import("std");

/// QUIC's minimum allowed UDP payload size (RFC 9000 §14).
pub const min_udp_payload_size: usize = 1200;
/// Ethernet-sized UDP payload ceilings used by tquic when the peer does not
/// advertise a smaller max_udp_payload_size.
pub const max_ipv4_udp_payload_size: usize = 1472;
pub const max_ipv6_udp_payload_size: usize = 1452;
pub const default_max_probe_failures: u8 = 3;
pub const black_hole_threshold: u8 = 3;
const suspicious_loss_burst_capacity = black_hole_threshold + 1;
pub const black_hole_cooldown_ns: u64 = 60 * std.time.ns_per_s;
pub const pmtu_raise_timer_ns: u64 = 600 * std.time.ns_per_s;

pub const Config = struct {
    /// Enable active DPLPMTUD probing. Passive black-hole detection remains
    /// active when this is false so a configured larger initial size can
    /// still recover to QUIC's guaranteed minimum.
    enabled: bool = false,
    initial_size: usize = min_udp_payload_size,
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
    initial_size: u16 = min_udp_payload_size,
    current_size: usize = min_udp_payload_size,
    max_probe_size: usize = max_ipv4_udp_payload_size,
    probe_size: ?usize = null,
    failed_size: usize = 0,
    consecutive_failures: u8 = 0,
    max_probe_failures: u8 = default_max_probe_failures,
    should_probe: bool = false,
    black_hole_counter: u8 = 0,
    suspicious_loss_burst_sizes: [suspicious_loss_burst_capacity]u16 =
        [_]u16{0} ** suspicious_loss_burst_capacity,
    largest_post_loss_packet: u64 = 0,
    acked_mtu: u16 = min_udp_payload_size,
    raise_probe_after_ns: ?u64 = null,
    active_probe_packet_number: ?u64 = null,
    active_probe_epoch: u32 = 0,
    active_probe_size: ?usize = null,
    last_loss_packet_number: ?u64 = null,
    loss_burst_smallest_size: u16 = 0,

    pub const BlackHoleResult = struct {
        mtu_dropped: bool = false,
        new_size: usize = min_udp_payload_size,
    };

    // Packet number zero and epoch zero are reserved here as the compatibility
    // identity used by the original size-only probe API. Production 1-RTT
    // paths use the explicit identity-aware variants below.

    pub fn init(config: Config) State {
        const initial_size: u16 = @intCast(@min(
            @max(config.initial_size, min_udp_payload_size),
            std.math.maxInt(u16),
        ));
        var max_probe_size = config.max_probe_size;
        if (max_probe_size <= min_udp_payload_size) {
            max_probe_size = if (config.is_ipv6) max_ipv6_udp_payload_size else max_ipv4_udp_payload_size;
        }
        max_probe_size = @max(max_probe_size, min_udp_payload_size);
        return .{
            .enabled = config.enabled,
            .initial_size = initial_size,
            .current_size = initial_size,
            .max_probe_size = max_probe_size,
            .max_probe_failures = @max(config.max_probe_failures, 1),
            .should_probe = config.enabled,
        };
    }

    pub fn currentSize(self: State) usize {
        return self.current_size;
    }

    pub fn ackedMtu(self: State) usize {
        return self.acked_mtu;
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

    /// Treat a synchronous local EMSGSIZE as evidence that the attempted
    /// probe cannot leave this host/path. Unlike an asynchronously delivered
    /// ICMP error, this result belongs to the exact send operation and can
    /// safely lower the current search ceiling without terminating QUIC.
    pub fn onProbeSendTooLarge(
        self: *State,
        peer_max_udp_payload: usize,
        now_ns: ?u64,
    ) bool {
        if (!self.shouldProbe() or self.active_probe_packet_number != null) {
            return false;
        }
        const size = self.probe_size orelse return false;
        if (size <= self.current_size) return false;
        self.failed_size = if (self.failed_size == 0)
            size
        else
            @min(self.failed_size, size);
        self.consecutive_failures = 0;
        self.probe_size = null;
        self.should_probe = !self.finished(peer_max_udp_payload);
        self.armRaiseTimer(now_ns, peer_max_udp_payload);
        return true;
    }

    pub fn onMtuSizedPacketAcked(self: *State, packet_number: u64, datagram_size: usize) void {
        const bounded_size = std.math.cast(u16, datagram_size) orelse
            std.math.maxInt(u16);
        if (bounded_size < self.acked_mtu) return;
        if (bounded_size == self.acked_mtu) {
            self.largest_post_loss_packet = @max(
                self.largest_post_loss_packet,
                packet_number,
            );
            return;
        }
        self.acked_mtu = bounded_size;
        self.largest_post_loss_packet = packet_number;

        // A successful datagram disproves only bursts whose smallest member
        // was no larger. Keep larger bursts because this ACK says nothing
        // about whether the path still carries them.
        var retained: u8 = 0;
        for (self.suspicious_loss_burst_sizes[0..self.black_hole_counter]) |size| {
            if (size <= bounded_size) continue;
            self.suspicious_loss_burst_sizes[retained] = size;
            retained += 1;
        }
        @memset(
            self.suspicious_loss_burst_sizes[retained..self.black_hole_counter],
            0,
        );
        self.black_hole_counter = retained;
    }

    /// Observe one ordinary packet loss for PMTU black-hole detection.
    ///
    /// Only complete non-probe loss bursts whose smallest datagram exceeds the
    /// base PLPMTU can qualify. A later base-sized loss in the same contiguous
    /// run therefore makes the whole burst non-suspicious, matching Quinn's
    /// conservative black-hole heuristic.
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

    /// Aggregate one ordinary loss into the current packet-number burst.
    /// PMTU probes are excluded: a probe between two ordinary lost packets
    /// creates a packet-number gap and therefore separates their bursts.
    pub fn onPacketLost(
        self: *State,
        packet_number: u64,
        datagram_size: usize,
        is_probe: bool,
        new_loss_burst: bool,
        now_ns: u64,
    ) BlackHoleResult {
        _ = new_loss_burst;
        if (is_probe) return .{};
        if (self.last_loss_packet_number) |previous| {
            if (previous +| 1 != packet_number) {
                const result = self.finishLossBurst(now_ns);
                if (result.mtu_dropped) return result;
            }
        }
        self.last_loss_packet_number = packet_number;
        const bounded_size = std.math.cast(u16, datagram_size) orelse
            std.math.maxInt(u16);
        if (self.loss_burst_smallest_size == 0 or
            bounded_size < self.loss_burst_smallest_size)
        {
            self.loss_burst_smallest_size = bounded_size;
        }
        return .{};
    }

    /// Close the current loss burst and apply any resulting black-hole signal.
    /// Loss detection calls this once after each reported batch so a final
    /// burst does not remain invisible until some later packet is lost.
    pub fn finishLossBurst(
        self: *State,
        now_ns: u64,
    ) BlackHoleResult {
        const latest = self.last_loss_packet_number orelse return .{};
        const smallest = self.loss_burst_smallest_size;
        self.last_loss_packet_number = null;
        self.loss_burst_smallest_size = 0;
        if (smallest <= min_udp_payload_size or
            smallest > self.current_size)
        {
            return .{};
        }
        if (latest < self.largest_post_loss_packet and
            smallest <= self.acked_mtu)
        {
            return .{};
        }
        if (latest > self.largest_post_loss_packet) {
            self.acked_mtu = min_udp_payload_size;
        }
        std.debug.assert(
            self.black_hole_counter < suspicious_loss_burst_capacity,
        );
        self.suspicious_loss_burst_sizes[self.black_hole_counter] = smallest;
        self.black_hole_counter += 1;
        if (self.black_hole_counter <= black_hole_threshold) return .{};
        self.black_hole_counter = 0;
        @memset(&self.suspicious_loss_burst_sizes, 0);
        self.largest_post_loss_packet = 0;
        self.acked_mtu = min_udp_payload_size;
        self.current_size = min_udp_payload_size;
        self.probe_size = null;
        self.failed_size = 0;
        self.consecutive_failures = 0;
        self.active_probe_packet_number = null;
        self.active_probe_size = null;
        self.should_probe = false;
        self.raise_probe_after_ns = if (self.enabled)
            std.math.add(u64, now_ns, black_hole_cooldown_ns) catch
                std.math.maxInt(u64)
        else
            null;
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
        const initial_size = self.initial_size;
        const max_probe_size = self.max_probe_size;
        const max_probe_failures = self.max_probe_failures;
        self.* = .{
            .enabled = enabled,
            .initial_size = initial_size,
            .current_size = initial_size,
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

test {
    _ = @import("pmtu/tests.zig");
}

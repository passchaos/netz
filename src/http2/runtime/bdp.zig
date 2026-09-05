//! Allocation-free bandwidth-delay-product estimator for adaptive HTTP/2
//! receive windows. The policy follows Hyper's mature h2 ping estimator while
//! keeping time and bandwidth comparisons integer-only.

const std = @import("std");

pub const default_max_window: u32 = 16 * 1024 * 1024;
const initial_probe_delay_ns: u64 = 100 * std.time.ns_per_ms;
const max_probe_delay_ns: u64 = 10 * std.time.ns_per_s;
const ping_prefix = [4]u8{ 0x4e, 0x54, 0x5a, 0x42 }; // "NTZB"

pub const Estimator = struct {
    target: u32,
    max_target: u32,
    sample_bytes: u64 = 0,
    probe_sequence: u32 = 0,
    active_sequence: ?u32 = null,
    probe_sent_at_ns: u64 = 0,
    next_probe_at_ns: u64 = 0,
    smoothed_rtt_ns: u64 = 0,
    max_bandwidth_bytes: u64 = 0,
    max_bandwidth_rtt_ns: u64 = 1,
    probe_delay_ns: u64 = initial_probe_delay_ns,
    stable_count: u32 = 0,

    pub fn init(initial_target: u32, max_target: u32) Estimator {
        std.debug.assert(initial_target != 0);
        std.debug.assert(max_target >= initial_target);
        return .{ .target = initial_target, .max_target = max_target };
    }

    /// Account received flow-controlled bytes and start a sample when due.
    /// The returned token must be sent as a PING before more frames are read.
    pub fn recordData(
        self: *Estimator,
        bytes: usize,
        now_ns: u64,
    ) ?[8]u8 {
        if (self.target >= self.max_target or now_ns < self.next_probe_at_ns) {
            return null;
        }
        self.sample_bytes +|= std.math.cast(u64, bytes) orelse
            std.math.maxInt(u64);
        if (self.active_sequence != null) return null;
        const sequence = self.probe_sequence;
        self.probe_sequence +%= 1;
        self.active_sequence = sequence;
        self.probe_sent_at_ns = now_ns;
        return payload(sequence);
    }

    /// Roll back only the outstanding marker after a failed PING write. Bytes
    /// remain in the sample so the next DATA frame can retry without losing
    /// the bandwidth observation.
    pub fn cancelProbe(self: *Estimator, token: [8]u8) void {
        const sequence = parsePayload(token) orelse return;
        if (self.active_sequence == sequence) self.active_sequence = null;
    }

    /// Consume a matching probe ACK and return a larger target when warranted.
    /// Unknown/stale ACKs cannot mutate estimator state.
    pub const Ack = struct {
        matched: bool = false,
        target: ?u32 = null,
    };

    pub fn acknowledge(
        self: *Estimator,
        token: [8]u8,
        now_ns: u64,
    ) Ack {
        const sequence = parsePayload(token) orelse return .{};
        if (self.active_sequence == null or
            self.active_sequence.? != sequence) return .{};
        self.active_sequence = null;
        const sample_bytes = self.sample_bytes;
        self.sample_bytes = 0;
        const latest_rtt = @max(@as(u64, 1), now_ns -| self.probe_sent_at_ns);
        self.smoothed_rtt_ns = if (self.smoothed_rtt_ns == 0)
            latest_rtt
        else
            @intCast((@as(u128, self.smoothed_rtt_ns) * 7 +
                latest_rtt) / 8);

        const faster = self.max_bandwidth_bytes == 0 or
            @as(u128, sample_bytes) * self.max_bandwidth_rtt_ns >=
                @as(u128, self.max_bandwidth_bytes) * self.smoothed_rtt_ns;
        var update: ?u32 = null;
        if (faster) {
            self.max_bandwidth_bytes = sample_bytes;
            self.max_bandwidth_rtt_ns = self.smoothed_rtt_ns;
            const threshold = (@as(u64, self.target) * 2) / 3;
            const doubled = @min(sample_bytes *| 2, self.max_target);
            if (sample_bytes >= threshold and doubled > self.target) {
                self.target = @intCast(doubled);
                self.stable_count = 0;
                self.probe_delay_ns = @max(
                    @as(u64, 1),
                    self.probe_delay_ns / 2,
                );
                update = self.target;
            } else {
                self.stabilizeDelay();
            }
        } else {
            self.stabilizeDelay();
        }
        self.next_probe_at_ns = now_ns +| self.probe_delay_ns;
        return .{ .matched = true, .target = update };
    }

    fn stabilizeDelay(self: *Estimator) void {
        if (self.probe_delay_ns >= max_probe_delay_ns) return;
        self.stable_count +|= 1;
        if (self.stable_count < 2) return;
        self.stable_count = 0;
        self.probe_delay_ns = @min(
            max_probe_delay_ns,
            self.probe_delay_ns *| 4,
        );
    }
};

pub fn isProbePayload(bytes: [8]u8) bool {
    return parsePayload(bytes) != null;
}

fn payload(sequence: u32) [8]u8 {
    var result: [8]u8 = undefined;
    @memcpy(result[0..4], &ping_prefix);
    std.mem.writeInt(u32, result[4..8], sequence, .big);
    return result;
}

fn parsePayload(bytes: [8]u8) ?u32 {
    if (!std.mem.eql(u8, bytes[0..4], &ping_prefix)) return null;
    return std.mem.readInt(u32, bytes[4..8], .big);
}

test "HTTP/2 BDP estimator grows, caps, and backs off probes" {
    var estimator = Estimator.init(65_535, default_max_window);
    const first = estimator.recordData(50_000, 1_000) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(estimator.recordData(50_000, 2_000) == null);
    const first_ack = estimator.acknowledge(first, 11_000);
    try std.testing.expect(first_ack.matched);
    try std.testing.expectEqual(@as(?u32, 200_000), first_ack.target);
    try std.testing.expectEqual(@as(u64, 10_000), estimator.smoothed_rtt_ns);
    try std.testing.expect(estimator.recordData(1, 11_001) == null);

    const second_at = estimator.next_probe_at_ns;
    const second = estimator.recordData(10, second_at) orelse
        return error.TestUnexpectedResult;
    const second_ack = estimator.acknowledge(second, second_at + 18_000);
    try std.testing.expect(second_ack.matched);
    try std.testing.expectEqual(@as(?u32, null), second_ack.target);
    const third_at = estimator.next_probe_at_ns;
    const third = estimator.recordData(10, third_at) orelse
        return error.TestUnexpectedResult;
    const third_ack = estimator.acknowledge(third, third_at + 18_000);
    try std.testing.expect(third_ack.matched);
    try std.testing.expectEqual(@as(?u32, null), third_ack.target);
    try std.testing.expect(estimator.probe_delay_ns >
        initial_probe_delay_ns / 2);

    var capped = Estimator.init(65_535, 70_000);
    const capped_ping = capped.recordData(100_000, 1) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u32, 70_000), capped.acknowledge(capped_ping, 2).target);
    try std.testing.expect(capped.recordData(100_000, 3) == null);
}

test "HTTP/2 BDP estimator ignores stale and unrelated PING ACKs" {
    var estimator = Estimator.init(65_535, default_max_window);
    const current = estimator.recordData(50_000, 100) orelse
        return error.TestUnexpectedResult;
    var stale = current;
    stale[7] +%= 1;
    try std.testing.expect(!estimator.acknowledge(stale, 200).matched);
    try std.testing.expect(estimator.active_sequence != null);
    try std.testing.expect(!estimator.acknowledge(.{0} ** 8, 200).matched);
    const current_ack = estimator.acknowledge(current, 200);
    try std.testing.expect(current_ack.matched);
    try std.testing.expectEqual(@as(?u32, 100_000), current_ack.target);
    try std.testing.expect(!estimator.acknowledge(current, 300).matched);
}

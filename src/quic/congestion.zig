const std = @import("std");

pub const Error = error{
    CongestionLimited,
};

pub const default_max_datagram_size: usize = 1200;

pub const Controller = struct {
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

    pub fn init(max_datagram_size: usize) Controller {
        return .{
            .max_datagram_size = max_datagram_size,
            .congestion_window = initialWindow(max_datagram_size),
        };
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
        self.onAckedAt(bytes, null);
    }

    pub fn onAckedAt(self: *Controller, bytes: usize, sent_time_ns: ?u64) void {
        self.discard(bytes);
        if (bytes == 0) return;

        if (self.congestion_recovery_start_time_ns) |recovery_start| {
            const sent_time = sent_time_ns orelse return;
            if (sent_time <= recovery_start) return;
            self.congestion_recovery_start_time_ns = null;
        }

        if (self.congestion_window < self.slow_start_threshold) {
            self.congestion_window += bytes;
            return;
        }

        self.congestion_avoidance_bytes_acked += bytes;
        while (self.congestion_avoidance_bytes_acked >= self.congestion_window) {
            self.congestion_avoidance_bytes_acked -= self.congestion_window;
            self.congestion_window += self.max_datagram_size;
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

        const reduced = self.congestion_window * 7 / 10;
        const minimum = minimumWindow(self.max_datagram_size);
        self.congestion_window = @max(reduced, minimum);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
        self.congestion_recovery_start_time_ns = now_ns orelse lost_sent_time_ns;
    }

    pub fn onPersistentCongestion(self: *Controller) void {
        self.congestion_window = minimumWindow(self.max_datagram_size);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
        self.congestion_recovery_start_time_ns = null;
    }

    pub fn onPtoProbeSent(self: *Controller, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    pub fn discard(self: *Controller, bytes: usize) void {
        self.bytes_in_flight -|= bytes;
    }
};

pub fn initialWindow(max_datagram_size: usize) usize {
    return @min(10 * max_datagram_size, @max(@as(usize, 14_720), 2 * max_datagram_size));
}

pub fn minimumWindow(max_datagram_size: usize) usize {
    return 2 * max_datagram_size;
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

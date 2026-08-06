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
        self.discard(bytes);
        if (bytes == 0) return;

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
        self.discard(bytes);
        const reduced = self.congestion_window * 7 / 10;
        const minimum = minimumWindow(self.max_datagram_size);
        self.congestion_window = @max(reduced, minimum);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
    }

    pub fn onPersistentCongestion(self: *Controller) void {
        self.congestion_window = minimumWindow(self.max_datagram_size);
        self.slow_start_threshold = self.congestion_window;
        self.congestion_avoidance_bytes_acked = 0;
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

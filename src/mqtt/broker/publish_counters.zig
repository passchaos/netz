//! Lock-free cumulative broker PUBLISH counters.
//!
//! These counters sit on socket hot paths that run concurrently for many
//! clients. Each field is independently monotonic and saturates instead of
//! wrapping, matching the broker's previous mutex-protected arithmetic.

const std = @import("std");

pub const Snapshot = struct {
    messages_received: usize,
    payload_bytes_received: usize,
    messages_dropped: usize,
    messages_sent: usize,
    payload_bytes_sent: usize,
};

pub const Counters = struct {
    messages_received: std.atomic.Value(usize) = .init(0),
    payload_bytes_received: std.atomic.Value(usize) = .init(0),
    messages_dropped: std.atomic.Value(usize) = .init(0),
    messages_sent: std.atomic.Value(usize) = .init(0),
    payload_bytes_sent: std.atomic.Value(usize) = .init(0),

    pub fn snapshot(self: *const Counters) Snapshot {
        return .{
            .messages_received = self.messages_received.load(.monotonic),
            .payload_bytes_received = self.payload_bytes_received.load(.monotonic),
            .messages_dropped = self.messages_dropped.load(.monotonic),
            .messages_sent = self.messages_sent.load(.monotonic),
            .payload_bytes_sent = self.payload_bytes_sent.load(.monotonic),
        };
    }

    pub fn recordReceived(self: *Counters, payload_len: usize) void {
        saturatingAdd(&self.messages_received, 1);
        saturatingAdd(&self.payload_bytes_received, payload_len);
    }

    pub fn recordDropped(self: *Counters) void {
        saturatingAdd(&self.messages_dropped, 1);
    }

    pub fn recordSent(self: *Counters, payload_len: usize) void {
        saturatingAdd(&self.messages_sent, 1);
        saturatingAdd(&self.payload_bytes_sent, payload_len);
    }
};

fn saturatingAdd(value: *std.atomic.Value(usize), amount: usize) void {
    var current = value.load(.monotonic);
    while (current != std.math.maxInt(usize)) {
        const next = current +| amount;
        current = value.cmpxchgWeak(
            current,
            next,
            .monotonic,
            .monotonic,
        ) orelse return;
    }
}

test "MQTT publish counters record a snapshot" {
    var counters: Counters = .{};
    counters.recordReceived(17);
    counters.recordReceived(5);
    counters.recordDropped();
    counters.recordSent(9);

    const result = counters.snapshot();
    try std.testing.expectEqual(@as(usize, 2), result.messages_received);
    try std.testing.expectEqual(@as(usize, 22), result.payload_bytes_received);
    try std.testing.expectEqual(@as(usize, 1), result.messages_dropped);
    try std.testing.expectEqual(@as(usize, 1), result.messages_sent);
    try std.testing.expectEqual(@as(usize, 9), result.payload_bytes_sent);
}

test "MQTT publish counters saturate" {
    var counters: Counters = .{};
    counters.messages_received.store(std.math.maxInt(usize) - 1, .monotonic);
    counters.payload_bytes_received.store(std.math.maxInt(usize) - 2, .monotonic);
    counters.messages_dropped.store(std.math.maxInt(usize), .monotonic);
    counters.messages_sent.store(std.math.maxInt(usize) - 1, .monotonic);
    counters.payload_bytes_sent.store(std.math.maxInt(usize) - 2, .monotonic);

    counters.recordReceived(8);
    counters.recordDropped();
    counters.recordSent(8);

    const result = counters.snapshot();
    inline for (@typeInfo(Snapshot).@"struct".fields) |field| {
        try std.testing.expectEqual(
            @as(usize, std.math.maxInt(usize)),
            @field(result, field.name),
        );
    }
}

test "MQTT publish counters accept concurrent updates" {
    const Worker = struct {
        counters: *Counters,

        fn run(self: @This()) void {
            for (0..10_000) |_| {
                self.counters.recordReceived(3);
                self.counters.recordSent(5);
                self.counters.recordDropped();
            }
        }
    };

    var counters: Counters = .{};
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(
            .{},
            Worker.run,
            .{Worker{ .counters = &counters }},
        );
    }
    for (threads) |thread| thread.join();

    const result = counters.snapshot();
    try std.testing.expectEqual(@as(usize, 40_000), result.messages_received);
    try std.testing.expectEqual(@as(usize, 120_000), result.payload_bytes_received);
    try std.testing.expectEqual(@as(usize, 40_000), result.messages_dropped);
    try std.testing.expectEqual(@as(usize, 40_000), result.messages_sent);
    try std.testing.expectEqual(@as(usize, 200_000), result.payload_bytes_sent);
}

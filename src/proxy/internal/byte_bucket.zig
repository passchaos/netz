//! Bounded byte-rate token bucket used for Hysteria bandwidth negotiation.
//!
//! A zero rate means unlimited. Capacity is one second of bytes, so a burst
//! cannot exceed the configured rate by more than a short window.

const std = @import("std");

pub const ByteBucket = struct {
    rate: u64,
    tokens: u64,
    last_refill_ns: i64,

    pub fn init(rate: u64, now_ns: i64) ByteBucket {
        return .{
            .rate = rate,
            .tokens = if (rate == 0) 0 else rate,
            .last_refill_ns = now_ns,
        };
    }

    pub fn tryConsume(self: *ByteBucket, bytes: u64, now_ns: i64) bool {
        if (self.rate == 0) return true;
        self.refill(now_ns);
        if (self.tokens < bytes) return false;
        self.tokens -= bytes;
        return true;
    }

    /// Wait until `bytes` tokens are available. Sleeps in bounded slices so a
    /// very low configured rate cannot turn into one unbounded sleep.
    pub fn wait(self: *ByteBucket, bytes: u64, io: std.Io) void {
        if (self.rate == 0 or bytes == 0) return;
        const max_slice_ns: u64 = 100 * std.time.ns_per_ms;
        while (true) {
            const now: i64 = @intCast(
                std.Io.Timestamp.now(io, .awake).nanoseconds,
            );
            self.refill(now);
            if (self.tokens >= bytes) {
                self.tokens -= bytes;
                return;
            }
            const needed = bytes - self.tokens;
            const wait_ns = @min(
                max_slice_ns,
                @max(
                    @as(u64, 1),
                    needed * std.time.ns_per_s / self.rate,
                ),
            );
            std.Io.sleep(
                io,
                .fromNanoseconds(@intCast(wait_ns)),
                .awake,
            ) catch {};
        }
    }

    fn refill(self: *ByteBucket, now_ns: i64) void {
        if (self.rate == 0) return;
        if (now_ns <= self.last_refill_ns) return;
        const elapsed: u64 = @intCast(now_ns - self.last_refill_ns);
        const added = elapsed * self.rate / std.time.ns_per_s;
        self.tokens = @min(self.rate, self.tokens + added);
        self.last_refill_ns = now_ns;
    }
};

test "byte bucket enforces a rate and refills over time" {
    var bucket = ByteBucket.init(1000, 0);
    try std.testing.expect(bucket.tryConsume(1000, 0));
    try std.testing.expect(!bucket.tryConsume(1000, 0));
    try std.testing.expect(bucket.tryConsume(500, std.time.ns_per_s / 2));
    try std.testing.expect(bucket.tryConsume(500, std.time.ns_per_s));
    try std.testing.expect(bucket.tryConsume(1000, 2 * std.time.ns_per_s));
}

test "byte bucket with zero rate is unlimited" {
    var bucket = ByteBucket.init(0, 0);
    try std.testing.expect(bucket.tryConsume(1_000_000, 0));
    try std.testing.expect(bucket.tryConsume(1_000_000, 1));
}

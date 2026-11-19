//! Bounded byte-rate token bucket used for Hysteria bandwidth negotiation.
//!
//! A zero rate means unlimited. The default burst is one second of bytes;
//! stream owners can choose another bounded burst independently of the rate.

const std = @import("std");

pub const ByteBucket = struct {
    rate: u64,
    capacity: u64,
    tokens: u64,
    last_refill_ns: i64,
    /// Byte-nanoseconds carried between sub-byte refill intervals.
    fractional_credit: u32 = 0,

    pub fn init(rate: u64, now_ns: i64) ByteBucket {
        return initWithBurst(rate, rate, now_ns);
    }

    pub fn initWithBurst(rate: u64, capacity: u64, now_ns: i64) ByteBucket {
        const burst = if (rate == 0) 0 else @max(@as(u64, 1), capacity);
        return .{
            .rate = rate,
            .capacity = burst,
            .tokens = burst,
            .last_refill_ns = now_ns,
        };
    }

    /// Inspect the available prefix without charging a send that may block.
    pub fn available(self: *ByteBucket, maximum: u64, now_ns: i64) u64 {
        if (self.rate == 0) return maximum;
        self.refill(now_ns);
        return @min(maximum, self.tokens);
    }

    pub fn tryConsume(self: *ByteBucket, bytes: u64, now_ns: i64) bool {
        if (self.rate == 0) return true;
        if (self.available(bytes, now_ns) != bytes) return false;
        self.tokens -= bytes;
        return true;
    }

    /// Return an uncommitted reservation without exceeding the burst budget.
    pub fn refund(self: *ByteBucket, bytes: u64) void {
        if (self.rate == 0) return;
        self.tokens += @min(bytes, self.capacity - self.tokens);
    }

    pub fn wait(self: *ByteBucket, bytes: u64, io: std.Io) (std.Io.Cancelable || error{Timeout})!void {
        return self.waitWithDeadline(bytes, io, null);
    }

    /// Wait for a usable prefix without reserving bytes before transport I/O.
    pub fn waitAvailable(
        self: *ByteBucket,
        maximum: u64,
        io: std.Io,
        deadline: ?std.Io.Clock.Timestamp,
    ) (std.Io.Cancelable || error{Timeout})!u64 {
        while (true) {
            try io.checkCancel();
            if (deadline) |absolute| {
                if (absolute.clock != .awake or absolute.durationFromNow(io).raw.nanoseconds <= 0) {
                    return error.Timeout;
                }
            }
            if (maximum == 0) return 0;
            const now: i64 = @intCast(
                std.Io.Timestamp.now(io, .awake).nanoseconds,
            );
            const count = self.available(maximum, now);
            if (count != 0) return count;
            // Wait for one byte, not for a chunk that exceeds capacity.
            const numerator = @as(u128, std.time.ns_per_s) - self.fractional_credit;
            var wait_ns: u64 = @intCast(@min(
                100 * std.time.ns_per_ms,
                (numerator + self.rate - 1) / self.rate,
            ));
            if (deadline) |absolute| {
                wait_ns = @intCast(@min(@as(i96, wait_ns), @max(
                    @as(i96, 1),
                    absolute.durationFromNow(io).raw.nanoseconds,
                )));
            }
            try std.Io.sleep(
                io,
                .fromNanoseconds(@intCast(wait_ns)),
                .awake,
            );
        }
    }

    /// Reserve arbitrarily large logical writes in burst-sized increments.
    /// Cancellation/timeout refunds the reservation and never swallows errors.
    pub fn waitWithDeadline(
        self: *ByteBucket,
        bytes: u64,
        io: std.Io,
        deadline: ?std.Io.Clock.Timestamp,
    ) (std.Io.Cancelable || error{Timeout})!void {
        var remaining = bytes;
        errdefer self.refund(bytes - remaining);
        while (true) {
            const count = try self.waitAvailable(remaining, io, deadline);
            if (remaining == 0) return;
            if (self.rate != 0) self.tokens -= count;
            remaining -= count;
        }
    }

    fn refill(self: *ByteBucket, now_ns: i64) void {
        if (self.rate == 0) return;
        if (now_ns <= self.last_refill_ns) return;
        const elapsed: u64 = @intCast(@as(i128, now_ns) - self.last_refill_ns);
        const credit = @as(u128, elapsed) * self.rate + self.fractional_credit;
        const added = credit / std.time.ns_per_s;
        const space = self.capacity - self.tokens;
        if (added >= space) {
            self.tokens = self.capacity;
            self.fractional_credit = 0;
        } else {
            self.tokens += @intCast(added);
            self.fractional_credit = @intCast(credit % std.time.ns_per_s);
        }
        self.last_refill_ns = now_ns;
    }
};

test {
    _ = @import("byte_bucket/tests.zig");
    _ = @import("byte_bucket/stream.zig");
}

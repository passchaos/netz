//! Reconnect delay policies and stateful retry scheduling.
const std = @import("std");

pub const Error = error{InvalidReconnectPolicy};

pub const Backoff = enum {
    fixed,
    linear,
    exponential,
};

pub const Jitter = enum {
    none,
    /// Uniformly choose a delay in [0, backoff]. This is the AWS-style full
    /// jitter strategy and minimizes synchronized reconnect storms.
    full,
    /// Uniformly choose a delay in [backoff/2, backoff]. Equal jitter retains
    /// a minimum cooldown while still spreading reconnect attempts.
    equal,
    /// Choose min(max, random(initial, previous * 3)). This is the AWS
    /// decorrelated-jitter strategy used by Mosquitto bridges.
    decorrelated,
};

/// Retry delays are bounded and saturating. `max_delay` may equal
/// `initial_delay`, yielding a fixed delay independently of `backoff`.
pub const Policy = struct {
    initial_delay: std.Io.Duration = .fromSeconds(1),
    max_delay: std.Io.Duration = .fromSeconds(30),
    backoff: Backoff = .exponential,
    jitter: Jitter = .none,
    /// Reset stateful decorrelated jitter after a connection remains alive for
    /// at least this duration. Zero resets after every successful connection.
    stable_connection_period: std.Io.Duration = .zero,
    /// Delay the first attempt after an established transport is retired.
    /// Generic clients preserve their historical immediate-reconnect default;
    /// configured bridges enable this to match broker bridge scheduling.
    delay_after_disconnect: bool = false,
    /// Zero means retry until cancellation, matching long-lived client loops.
    max_attempts: usize = 0,

    pub fn validate(self: Policy) Error!void {
        if (self.initial_delay.nanoseconds <= 0 or
            self.max_delay.nanoseconds < self.initial_delay.nanoseconds or
            self.stable_connection_period.nanoseconds < 0)
        {
            return error.InvalidReconnectPolicy;
        }
    }

    pub fn delay(self: Policy, failed_attempts: usize) std.Io.Duration {
        if (failed_attempts == 0) return .zero;
        const initial = self.initial_delay.nanoseconds;
        const maximum = self.max_delay.nanoseconds;
        if (initial >= maximum) return self.max_delay;
        const scaled = switch (self.backoff) {
            .fixed => initial,
            .linear => blk: {
                const attempts: i96 = std.math.cast(
                    i96,
                    failed_attempts,
                ) orelse break :blk maximum;
                break :blk std.math.mul(i96, initial, attempts) catch maximum;
            },
            .exponential => blk: {
                const shift = @min(failed_attempts - 1, 95);
                const factor = @as(i96, 1) << @intCast(shift);
                break :blk std.math.mul(i96, initial, factor) catch maximum;
            },
        };
        return .fromNanoseconds(@min(scaled, maximum));
    }

    /// Apply the configured stateless jitter using an explicit sample.
    pub fn jitteredDelay(
        self: Policy,
        failed_attempts: usize,
        random_sample: u64,
    ) std.Io.Duration {
        if (failed_attempts == 0) return .zero;
        if (self.jitter == .decorrelated) {
            return self.decorrelatedDelay(self.initial_delay, random_sample);
        }
        const base = self.delay(failed_attempts).nanoseconds;
        if (base <= 0 or self.jitter == .none) {
            return .fromNanoseconds(base);
        }
        const base_unsigned: u128 = @intCast(base);
        const minimum: u128 = switch (self.jitter) {
            .none, .decorrelated => unreachable,
            .full => 0,
            .equal => base_unsigned / 2,
        };
        const width = base_unsigned - minimum;
        // Multiplication-high maps every u64 sample into an inclusive bounded
        // interval without modulo bias. `width + 1` is safe because durations
        // are positive i96 values.
        const offset: u128 = if (random_sample == std.math.maxInt(u64))
            width
        else
            @intCast(
                (@as(u192, random_sample) * @as(u192, width + 1)) >> 64,
            );
        return .fromNanoseconds(@intCast(minimum + offset));
    }

    /// Calculate one stateful decorrelated-jitter delay. The random interval
    /// has an inclusive lower and exclusive upper bound before the cap, as in
    /// `random(base, previous * 3)`.
    pub fn decorrelatedDelay(
        self: Policy,
        previous_delay: std.Io.Duration,
        random_sample: u64,
    ) std.Io.Duration {
        const initial = self.initial_delay.nanoseconds;
        const previous = @max(previous_delay.nanoseconds, initial);
        const upper = std.math.mul(i96, previous, 3) catch
            std.math.maxInt(i96);
        if (upper <= initial) return self.initial_delay;
        const width: u128 = @intCast(upper - initial);
        const offset: u128 = @intCast(
            (@as(u192, random_sample) * @as(u192, width)) >> 64,
        );
        const candidate = std.math.add(
            u128,
            @as(u128, @intCast(initial)),
            offset,
        ) catch std.math.maxInt(u128);
        return .fromNanoseconds(@intCast(@min(
            candidate,
            @as(u128, @intCast(self.max_delay.nanoseconds)),
        )));
    }
};

/// Mutable timing state kept by one reconnecting client.
pub const Schedule = struct {
    previous_delay: std.Io.Duration,
    connected_at: ?std.Io.Timestamp = null,
    next_attempt_at: ?std.Io.Timestamp = null,

    pub fn init(policy: Policy) Schedule {
        return .{ .previous_delay = policy.initial_delay };
    }

    pub fn noteConnected(self: *Schedule, now: std.Io.Timestamp) void {
        self.connected_at = now;
        self.next_attempt_at = null;
    }

    pub fn scheduleFailure(
        self: *Schedule,
        policy: Policy,
        failed_attempts: usize,
        now: std.Io.Timestamp,
        random_sample: u64,
    ) std.Io.Duration {
        const value = self.nextDelay(policy, failed_attempts, random_sample);
        self.scheduleAt(now, value);
        return value;
    }

    pub fn noteDisconnected(
        self: *Schedule,
        policy: Policy,
        now: std.Io.Timestamp,
        random_sample: u64,
    ) void {
        const connected_at = self.connected_at orelse return;
        self.connected_at = null;
        if (!policy.delay_after_disconnect) return;
        const elapsed = @max(now.nanoseconds - connected_at.nanoseconds, 0);
        const stable = elapsed >= policy.stable_connection_period.nanoseconds;
        const value = if (stable) blk: {
            self.previous_delay = policy.initial_delay;
            break :blk policy.initial_delay;
        } else self.nextDelay(policy, 1, random_sample);
        self.scheduleAt(now, value);
    }

    pub fn remaining(
        self: *const Schedule,
        now: std.Io.Timestamp,
    ) ?std.Io.Duration {
        const target = self.next_attempt_at orelse return null;
        if (target.nanoseconds <= now.nanoseconds) return .zero;
        return .fromNanoseconds(target.nanoseconds - now.nanoseconds);
    }

    pub fn clearScheduled(self: *Schedule) void {
        self.next_attempt_at = null;
    }

    pub fn reset(self: *Schedule, policy: Policy) void {
        self.previous_delay = policy.initial_delay;
        self.connected_at = null;
        self.next_attempt_at = null;
    }

    fn nextDelay(
        self: *Schedule,
        policy: Policy,
        failed_attempts: usize,
        random_sample: u64,
    ) std.Io.Duration {
        const value = if (policy.jitter == .decorrelated)
            policy.decorrelatedDelay(self.previous_delay, random_sample)
        else if (policy.jitter == .none)
            policy.delay(failed_attempts)
        else
            policy.jitteredDelay(failed_attempts, random_sample);
        if (policy.jitter == .decorrelated) self.previous_delay = value;
        return value;
    }

    fn scheduleAt(
        self: *Schedule,
        now: std.Io.Timestamp,
        delay: std.Io.Duration,
    ) void {
        const deadline = std.math.add(
            i96,
            now.nanoseconds,
            delay.nanoseconds,
        ) catch std.math.maxInt(i96);
        self.next_attempt_at = .fromNanoseconds(deadline);
    }
};

test "MQTT reconnect policy bounds fixed linear and exponential delays" {
    const initial = std.Io.Duration.fromMilliseconds(100);
    const maximum = std.Io.Duration.fromMilliseconds(450);
    const fixed = Policy{
        .initial_delay = initial,
        .max_delay = maximum,
        .backoff = .fixed,
    };
    try std.testing.expectEqual(@as(i96, 100_000_000), fixed.delay(3).nanoseconds);
    const linear = Policy{
        .initial_delay = initial,
        .max_delay = maximum,
        .backoff = .linear,
    };
    try std.testing.expectEqual(@as(i96, 300_000_000), linear.delay(3).nanoseconds);
    const exponential = Policy{
        .initial_delay = initial,
        .max_delay = maximum,
    };
    try std.testing.expectEqual(@as(i96, 400_000_000), exponential.delay(3).nanoseconds);
    try std.testing.expectEqual(@as(i96, 450_000_000), exponential.delay(99).nanoseconds);
    try std.testing.expectError(error.InvalidReconnectPolicy, (Policy{
        .initial_delay = .fromMilliseconds(2),
        .max_delay = .fromMilliseconds(1),
    }).validate());
    try std.testing.expectError(error.InvalidReconnectPolicy, (Policy{
        .stable_connection_period = .fromNanoseconds(-1),
    }).validate());
}

test "MQTT reconnect jitter remains inside policy bounds" {
    const base = Policy{
        .initial_delay = .fromMilliseconds(100),
        .max_delay = .fromMilliseconds(800),
        .jitter = .full,
    };
    try std.testing.expectEqual(
        @as(i96, 0),
        base.jitteredDelay(3, 0).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 400_000_000),
        base.jitteredDelay(3, std.math.maxInt(u64)).nanoseconds,
    );

    var equal = base;
    equal.jitter = .equal;
    try std.testing.expectEqual(
        @as(i96, 200_000_000),
        equal.jitteredDelay(3, 0).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 400_000_000),
        equal.jitteredDelay(3, std.math.maxInt(u64)).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 0),
        equal.jitteredDelay(0, std.math.maxInt(u64)).nanoseconds,
    );

    var none = base;
    none.jitter = .none;
    try std.testing.expectEqual(
        @as(i96, 400_000_000),
        none.jitteredDelay(3, 0).nanoseconds,
    );

    const huge_ns = std.math.maxInt(i96) - 1;
    const huge = Policy{
        .initial_delay = .fromNanoseconds(huge_ns),
        .max_delay = .fromNanoseconds(huge_ns),
        .backoff = .fixed,
        .jitter = .full,
    };
    try std.testing.expectEqual(
        huge_ns,
        huge.jitteredDelay(1, std.math.maxInt(u64)).nanoseconds,
    );
}

test "MQTT decorrelated jitter carries state and resets after stability" {
    const policy = Policy{
        .initial_delay = .fromMilliseconds(100),
        .max_delay = .fromMilliseconds(800),
        .backoff = .fixed,
        .jitter = .decorrelated,
        .stable_connection_period = .fromMilliseconds(500),
        .delay_after_disconnect = true,
    };
    var schedule = Schedule.init(policy);
    const first = schedule.scheduleFailure(
        policy,
        1,
        .fromNanoseconds(1_000),
        std.math.maxInt(u64),
    );
    try std.testing.expectEqual(@as(i96, 299_999_999), first.nanoseconds);
    const second = schedule.scheduleFailure(
        policy,
        2,
        .fromNanoseconds(2_000),
        std.math.maxInt(u64),
    );
    try std.testing.expectEqual(@as(i96, 800_000_000), second.nanoseconds);

    schedule.noteConnected(.fromNanoseconds(1_000_000_000));
    schedule.noteDisconnected(
        policy,
        .fromNanoseconds(1_600_000_000),
        std.math.maxInt(u64),
    );
    try std.testing.expectEqual(
        @as(i96, 100_000_000),
        schedule.previous_delay.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 100_000_000),
        schedule.remaining(.fromNanoseconds(1_600_000_000)).?.nanoseconds,
    );

    schedule.clearScheduled();
    schedule.previous_delay = .fromMilliseconds(400);
    schedule.noteConnected(.fromNanoseconds(2_000_000_000));
    schedule.noteDisconnected(
        policy,
        .fromNanoseconds(2_100_000_000),
        std.math.maxInt(u64),
    );
    try std.testing.expectEqual(
        @as(i96, 800_000_000),
        schedule.previous_delay.nanoseconds,
    );
}

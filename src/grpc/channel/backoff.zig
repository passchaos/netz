//! gRPC connection backoff from the upstream connection-backoff protocol.
const std = @import("std");

pub const Error = error{InvalidChannelOptions};

pub const Policy = struct {
    initial_backoff: std.Io.Duration = .fromSeconds(1),
    multiplier: f64 = 1.6,
    jitter: f64 = 0.2,
    max_backoff: std.Io.Duration = .fromSeconds(120),
    min_connect_timeout: std.Io.Duration = .fromSeconds(20),

    pub fn validate(self: Policy) Error!void {
        if (self.initial_backoff.nanoseconds <= 0 or
            self.max_backoff.nanoseconds < self.initial_backoff.nanoseconds or
            self.min_connect_timeout.nanoseconds <= 0 or
            !std.math.isFinite(self.multiplier) or self.multiplier < 1 or
            !std.math.isFinite(self.jitter) or self.jitter < 0 or
            self.jitter > 1)
        {
            return error.InvalidChannelOptions;
        }
    }

    /// Delay after `failures` consecutive failed connection attempts.
    /// `sample` maps uniformly across gRPC's `[1-jitter, 1+jitter]` range.
    pub fn delay(
        self: Policy,
        failures: usize,
        sample: u64,
    ) std.Io.Duration {
        std.debug.assert(failures != 0);
        var base: f64 = @floatFromInt(self.initial_backoff.nanoseconds);
        const maximum: f64 = @floatFromInt(self.max_backoff.nanoseconds);
        var remaining = failures - 1;
        while (remaining != 0 and base < maximum) : (remaining -= 1) {
            base *= self.multiplier;
            if (!std.math.isFinite(base) or base >= maximum) {
                base = maximum;
                break;
            }
        }
        base = @min(base, maximum);
        const unit: f64 = if (sample == 0)
            0
        else if (sample == std.math.maxInt(u64))
            1
        else
            @as(f64, @floatFromInt(sample)) /
                @as(f64, @floatFromInt(std.math.maxInt(u64)));
        const factor = (1.0 - self.jitter) + 2.0 * self.jitter * unit;
        const jittered = base * factor;
        return .fromNanoseconds(@intFromFloat(@max(jittered, 1)));
    }
};

test "gRPC channel backoff follows bounded upstream defaults" {
    const policy: Policy = .{};
    try policy.validate();
    try std.testing.expectEqual(
        @as(i96, 800 * std.time.ns_per_ms),
        policy.delay(1, 0).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 144 * std.time.ns_per_s),
        policy.delay(99, std.math.maxInt(u64)).nanoseconds,
    );
    try std.testing.expectError(
        error.InvalidChannelOptions,
        (Policy{ .jitter = 1.1 }).validate(),
    );
}

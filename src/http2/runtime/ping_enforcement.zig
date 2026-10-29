//! Optional server-side HTTP/2 PING abuse enforcement.
const std = @import("std");

/// gRPC Core-compatible defaults. Generic HTTP/2 leaves the containing Limits
/// field null; protocol adapters opt in explicitly.
pub const Policy = struct {
    min_interval: std.Io.Duration = .fromSeconds(5 * 60),
    idle_interval: std.Io.Duration = .fromSeconds(2 * 60 * 60),
    /// Use the active interval even when no RPC streams are open.
    permit_without_calls: bool = false,
    /// Zero records strikes but never closes the connection.
    max_strikes: usize = 2,

    pub fn validate(self: Policy) error{InvalidSetting}!void {
        if (self.min_interval.nanoseconds < 0 or
            self.idle_interval.nanoseconds < 0)
        {
            return error.InvalidSetting;
        }
    }
};

pub const Stats = struct {
    pings_received: u64,
    current_strikes: usize,
    violations: u64,
};

pub const State = struct {
    last_ping_at: ?std.Io.Timestamp = null,
    pings_received: u64 = 0,
    strikes: usize = 0,
    violations: u64 = 0,

    /// Returns true when the caller must emit the terminal GOAWAY. The first
    /// PING after connection setup or a qualifying output reset is always
    /// permitted, matching grpc-core's InfPast clock initialization.
    pub fn receive(
        self: *State,
        policy: Policy,
        now: std.Io.Timestamp,
        idle: bool,
    ) bool {
        self.pings_received +|= 1;
        const previous = self.last_ping_at orelse {
            self.last_ping_at = now;
            return false;
        };
        self.last_ping_at = now;
        const interval = if (idle and !policy.permit_without_calls)
            policy.idle_interval
        else
            policy.min_interval;
        if (now.nanoseconds >= previous.addDuration(interval).nanoseconds) {
            return false;
        }
        self.strikes +|= 1;
        if (policy.max_strikes == 0 or self.strikes <= policy.max_strikes) {
            return false;
        }
        self.violations +|= 1;
        return true;
    }

    pub fn reset(self: *State) void {
        self.last_ping_at = null;
        self.strikes = 0;
    }

    pub fn snapshot(self: State) Stats {
        return .{
            .pings_received = self.pings_received,
            .current_strikes = self.strikes,
            .violations = self.violations,
        };
    }
};

test "HTTP/2 PING enforcement distinguishes active and idle intervals" {
    const policy: Policy = .{
        .min_interval = .fromMilliseconds(10),
        .idle_interval = .fromMilliseconds(100),
        .max_strikes = 1,
    };
    try policy.validate();
    var state: State = .{};
    try std.testing.expect(!state.receive(policy, .fromNanoseconds(0), true));
    try std.testing.expect(!state.receive(
        policy,
        .fromNanoseconds(20 * std.time.ns_per_ms),
        true,
    ));
    try std.testing.expectEqual(@as(usize, 1), state.strikes);
    try std.testing.expect(state.receive(
        policy,
        .fromNanoseconds(40 * std.time.ns_per_ms),
        true,
    ));

    state.reset();
    try std.testing.expect(!state.receive(policy, .fromNanoseconds(0), false));
    try std.testing.expect(!state.receive(
        policy,
        .fromNanoseconds(20 * std.time.ns_per_ms),
        false,
    ));
    try std.testing.expectEqual(@as(usize, 0), state.strikes);
    try std.testing.expectEqual(@as(u64, 5), state.pings_received);
    try std.testing.expectEqual(@as(u64, 1), state.violations);

    var permitted = policy;
    permitted.permit_without_calls = true;
    state.reset();
    try std.testing.expect(!state.receive(permitted, .fromNanoseconds(0), true));
    try std.testing.expect(!state.receive(
        permitted,
        .fromNanoseconds(20 * std.time.ns_per_ms),
        true,
    ));
    try std.testing.expectEqual(@as(usize, 0), state.strikes);
}

test "HTTP/2 PING enforcement output reset and unlimited strikes" {
    const policy: Policy = .{
        .min_interval = .fromSeconds(1),
        .idle_interval = .fromSeconds(1),
        .max_strikes = 0,
    };
    var state: State = .{};
    for (0..100) |index| {
        try std.testing.expect(!state.receive(
            policy,
            .fromNanoseconds(@intCast(index)),
            false,
        ));
    }
    try std.testing.expectEqual(@as(usize, 99), state.strikes);
    state.reset();
    try std.testing.expectEqual(@as(usize, 0), state.strikes);
    try std.testing.expect(state.last_ping_at == null);
}

test "HTTP/2 PING enforcement rejects negative intervals" {
    try std.testing.expectError(
        error.InvalidSetting,
        (Policy{ .min_interval = .fromNanoseconds(-1) }).validate(),
    );
    try std.testing.expectError(
        error.InvalidSetting,
        (Policy{ .idle_interval = .fromNanoseconds(-1) }).validate(),
    );
}

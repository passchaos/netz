//! Lock-free gRFC A6 hedging telemetry owned by one SharedChannel.

const std = @import("std");

pub const Snapshot = struct {
    calls: u64,
    attempts_started: u64,
    delayed_attempts: u64,
    accelerated_attempts: u64,
    throttled_attempts: u64,
    pushback_delays: u64,
    pushback_stops: u64,
    ok_winners: u64,
    fatal_winners: u64,
    exhausted_non_fatal: u64,
    backend_failures: u64,
    deadline_expirations: u64,
    canceled_losers: u64,
};

pub const Launch = enum {
    original,
    delayed,
    accelerated,
};

pub const Counters = struct {
    calls: std.atomic.Value(u64) = .init(0),
    attempts_started: std.atomic.Value(u64) = .init(0),
    delayed_attempts: std.atomic.Value(u64) = .init(0),
    accelerated_attempts: std.atomic.Value(u64) = .init(0),
    throttled_attempts: std.atomic.Value(u64) = .init(0),
    pushback_delays: std.atomic.Value(u64) = .init(0),
    pushback_stops: std.atomic.Value(u64) = .init(0),
    ok_winners: std.atomic.Value(u64) = .init(0),
    fatal_winners: std.atomic.Value(u64) = .init(0),
    exhausted_non_fatal: std.atomic.Value(u64) = .init(0),
    backend_failures: std.atomic.Value(u64) = .init(0),
    deadline_expirations: std.atomic.Value(u64) = .init(0),
    canceled_losers: std.atomic.Value(u64) = .init(0),

    pub fn snapshot(self: *const Counters) Snapshot {
        return .{
            .calls = self.calls.load(.acquire),
            .attempts_started = self.attempts_started.load(.acquire),
            .delayed_attempts = self.delayed_attempts.load(.acquire),
            .accelerated_attempts = self.accelerated_attempts.load(.acquire),
            .throttled_attempts = self.throttled_attempts.load(.acquire),
            .pushback_delays = self.pushback_delays.load(.acquire),
            .pushback_stops = self.pushback_stops.load(.acquire),
            .ok_winners = self.ok_winners.load(.acquire),
            .fatal_winners = self.fatal_winners.load(.acquire),
            .exhausted_non_fatal = self.exhausted_non_fatal.load(.acquire),
            .backend_failures = self.backend_failures.load(.acquire),
            .deadline_expirations = self.deadline_expirations.load(.acquire),
            .canceled_losers = self.canceled_losers.load(.acquire),
        };
    }

    pub fn recordCall(self: *Counters) void {
        increment(&self.calls);
    }
    pub fn recordLaunch(self: *Counters, launch: Launch) void {
        increment(&self.attempts_started);
        switch (launch) {
            .original => {},
            .delayed => increment(&self.delayed_attempts),
            .accelerated => increment(&self.accelerated_attempts),
        }
    }
    pub fn recordThrottle(self: *Counters) void {
        increment(&self.throttled_attempts);
    }
    pub fn recordPushbackDelay(self: *Counters) void {
        increment(&self.pushback_delays);
    }
    pub fn recordPushbackStop(self: *Counters) void {
        increment(&self.pushback_stops);
    }
    pub fn recordOkWinner(self: *Counters) void {
        increment(&self.ok_winners);
    }
    pub fn recordFatalWinner(self: *Counters) void {
        increment(&self.fatal_winners);
    }
    pub fn recordExhausted(self: *Counters) void {
        increment(&self.exhausted_non_fatal);
    }
    pub fn recordBackendFailure(self: *Counters) void {
        increment(&self.backend_failures);
    }
    pub fn recordDeadline(self: *Counters) void {
        increment(&self.deadline_expirations);
    }
    pub fn recordCanceledLoser(self: *Counters) void {
        increment(&self.canceled_losers);
    }
};

fn increment(value: *std.atomic.Value(u64)) void {
    _ = value.fetchAdd(1, .monotonic);
}

test "gRPC hedging stats snapshot is exact" {
    var counters: Counters = .{};
    counters.recordCall();
    counters.recordLaunch(.original);
    counters.recordLaunch(.delayed);
    counters.recordLaunch(.accelerated);
    counters.recordThrottle();
    counters.recordPushbackDelay();
    counters.recordPushbackStop();
    counters.recordOkWinner();
    counters.recordFatalWinner();
    counters.recordExhausted();
    counters.recordBackendFailure();
    counters.recordDeadline();
    counters.recordCanceledLoser();
    try std.testing.expectEqualDeep(Snapshot{
        .calls = 1,
        .attempts_started = 3,
        .delayed_attempts = 1,
        .accelerated_attempts = 1,
        .throttled_attempts = 1,
        .pushback_delays = 1,
        .pushback_stops = 1,
        .ok_winners = 1,
        .fatal_winners = 1,
        .exhausted_non_fatal = 1,
        .backend_failures = 1,
        .deadline_expirations = 1,
        .canceled_losers = 1,
    }, counters.snapshot());
}

//! gRFC A6 concurrent unary hedging for the background SharedChannel owner.

const std = @import("std");
const call = @import("../../call.zig");
const retry = @import("../../call/retry.zig");
const wire = @import("../../wire.zig");
const stats = @import("hedging/stats.zig");
const control_mod = @import("hedging/control.zig");
const Control = control_mod.Control;
const transparent = @import("../../call/transparent_retry.zig");

pub fn run(
    state: anytype,
    options: call.UnaryCallOptions,
    policy: call.HedgingPolicy,
    deadline: ?std.Io.Clock.Timestamp,
) @TypeOf(state.*).Failure!call.UnaryResponse {
    const State = @TypeOf(state.*);
    const AttemptResult = State.Failure!call.UnaryResponse;
    const AttemptOutcome = struct {
        index: u8,
        result: AttemptResult,
    };
    const TimerOutcome = struct {
        generation: u64,
        deadline: bool,
        committed: bool = false,
    };
    const TimerResult = std.Io.Cancelable!TimerOutcome;
    const Wake = union(enum) {
        attempt: AttemptOutcome,
        timer: TimerResult,
        commit: std.Io.Cancelable!u8,
    };
    const Attempt = struct {
        fn execute(
            owner: *State,
            request: call.UnaryCallOptions,
            overall: ?std.Io.Clock.Timestamp,
            index: u8,
            control: *Control,
        ) AttemptOutcome {
            while (true) {
                if (control.isLoser(index)) return .{ .index = index, .result = error.Canceled };
                const timeout_header: ?wire.Timeout = if (overall) |absolute| blk: {
                    const remaining = absolute.durationFromNow(owner.io).raw;
                    if (remaining.nanoseconds <= 0) {
                        break :blk null;
                    }
                    break :blk wire.Timeout.fromDuration(remaining) catch
                        break :blk null;
                } else null;
                if (overall != null and timeout_header == null) {
                    return .{ .index = index, .result = error.Timeout };
                }
                var response = owner.attemptHedged(
                    request,
                    overall,
                    timeout_header,
                    index,
                    control,
                ) catch |err| {
                    if (control.isLoser(index)) return .{ .index = index, .result = error.Canceled };
                    if (transparent.replayableError(err) and control.takeTransparent(request.transparent_retry)) continue;
                    if (control.errorIsFatal(err)) owner.commitHedge(control, index);
                    return .{ .index = index, .result = err };
                };
                if (control.isLoser(index)) {
                    response.deinit();
                    return .{ .index = index, .result = error.Canceled };
                }
                if (transparent.replayableResponse(response) and control.takeTransparent(request.transparent_retry)) {
                    response.deinit();
                    continue;
                }
                if (control.responseIsFatal(response)) owner.commitHedge(control, index);
                return .{ .index = index, .result = response };
            }
        }
    };
    const Timer = struct {
        fn wait(
            io: std.Io,
            delay: std.Io.Duration,
            overall: ?std.Io.Clock.Timestamp,
            generation: u64,
            control: *Control,
        ) TimerResult {
            var target = std.Io.Clock.Timestamp.fromNow(io, .{
                .raw = delay,
                .clock = .awake,
            });
            var is_deadline = false;
            if (overall) |absolute| {
                if (std.Io.Clock.Timestamp.compare(absolute, .lte, target)) {
                    target = absolute;
                    is_deadline = true;
                }
            }
            while (control.winner() == null) {
                control.committed.waitTimeout(io, .{ .deadline = target }) catch |err| {
                    if (err == error.Canceled) return error.Canceled;
                    if (target.durationFromNow(io).raw.nanoseconds > 0) continue;
                    return .{ .generation = generation, .deadline = is_deadline };
                };
            }
            return .{
                .generation = generation,
                .deadline = false,
                .committed = true,
            };
        }
    };
    const Commitment = struct {
        fn wait(control: *Control) std.Io.Cancelable!u8 {
            try control.committed.wait(control.io);
            return control.winner().?;
        }
    };
    const Scheduler = struct {
        fn launch(
            select: *std.Io.Select(Wake),
            owner: *State,
            control: *Control,
            request: call.UnaryCallOptions,
            overall: ?std.Io.Clock.Timestamp,
            launched: *u8,
            active: *u8,
            counters: *stats.Counters,
            reason: stats.Launch,
        ) State.Failure!void {
            if (control.winner() != null) return;
            const index = launched.*;
            try select.concurrent(
                .attempt,
                Attempt.execute,
                .{ owner, request, overall, index, control },
            );
            launched.* += 1;
            active.* += 1;
            counters.recordLaunch(reason);
        }

        fn timer(
            select: *std.Io.Select(Wake),
            io: std.Io,
            control: *Control,
            delay: std.Io.Duration,
            overall: ?std.Io.Clock.Timestamp,
            generation: *u64,
            pending: *bool,
        ) State.Failure!void {
            generation.* +%= 1;
            try select.concurrent(
                .timer,
                Timer.wait,
                .{ io, delay, overall, generation.*, control },
            );
            pending.* = true;
        }

        fn invalidate(generation: *u64, pending: *bool) void {
            generation.* +%= 1;
            pending.* = false;
        }

        fn drain(
            select: *std.Io.Select(Wake),
            counters: *stats.Counters,
        ) void {
            while (select.cancel()) |wake| switch (wake) {
                .attempt => |outcome| {
                    if (outcome.result) |response_value| {
                        var response = response_value;
                        response.deinit();
                    } else |err| {
                        if (err == error.Canceled) {
                            counters.recordCanceledLoser();
                        }
                    }
                },
                .timer => |result| _ = result catch {},
                .commit => |result| _ = result catch {},
            };
        }
    };

    try policy.validate();
    const counters = &state.hedging_counters;
    counters.recordCall();
    const control = try Control.create(state.allocator, state.io, policy);
    defer control.release();
    var storage: [12]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(state.io, &storage);
    defer Scheduler.drain(&select, counters);
    try select.concurrent(.commit, Commitment.wait, .{control});
    var launched: u8 = 0;
    var active: u8 = 0;
    var timer_generation: u64 = 0;
    var timer_pending = false;
    var scheduling_stopped = false;
    var last_non_fatal: ?call.UnaryResponse = null;
    var last_error: ?anyerror = null;
    defer if (last_non_fatal) |*response| response.deinit();

    try Scheduler.launch(
        &select,
        state,
        control,
        options,
        deadline,
        &launched,
        &active,
        counters,
        .original,
    );
    if (policy.max_attempts > 1 and hedgingAllowed(policy)) {
        try Scheduler.timer(
            &select,
            state.io,
            control,
            policy.hedging_delay,
            deadline,
            &timer_generation,
            &timer_pending,
        );
    } else {
        if (policy.max_attempts > 1) counters.recordThrottle();
        scheduling_stopped = true;
    }

    while (true) {
        if (control.winner() != null and !scheduling_stopped) {
            scheduling_stopped = true;
            Scheduler.invalidate(&timer_generation, &timer_pending);
        }
        if (active == 0 and
            (scheduling_stopped or launched >= policy.max_attempts) and
            !timer_pending)
        {
            if (last_non_fatal) |response| {
                counters.recordExhausted();
                last_non_fatal = null;
                return response;
            }
            if (last_error) |err| {
                counters.recordExhausted();
                return @errorCast(err);
            }
            return error.ConnectionUnavailable;
        }
        const wake = select.await() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
        switch (wake) {
            .commit => |result| {
                _ = try result;
                scheduling_stopped = true;
                Scheduler.invalidate(&timer_generation, &timer_pending);
            },
            .timer => |result| {
                const timer = try result;
                if (timer.committed or control.winner() != null) {
                    scheduling_stopped = true;
                    Scheduler.invalidate(&timer_generation, &timer_pending);
                    continue;
                }
                if (timer.generation != timer_generation) continue;
                timer_pending = false;
                if (timer.deadline) {
                    counters.recordDeadline();
                    return error.Timeout;
                }
                if (scheduling_stopped or launched >= policy.max_attempts) {
                    scheduling_stopped = true;
                    continue;
                }
                if (!hedgingAllowed(policy)) {
                    counters.recordThrottle();
                    scheduling_stopped = true;
                    continue;
                }
                try Scheduler.launch(
                    &select,
                    state,
                    control,
                    options,
                    deadline,
                    &launched,
                    &active,
                    counters,
                    .delayed,
                );
                if (launched < policy.max_attempts) {
                    try Scheduler.timer(
                        &select,
                        state.io,
                        control,
                        policy.hedging_delay,
                        deadline,
                        &timer_generation,
                        &timer_pending,
                    );
                } else {
                    scheduling_stopped = true;
                }
            },
            .attempt => |outcome| {
                std.debug.assert(active != 0);
                active -= 1;
                if (control.isLoser(outcome.index)) {
                    if (outcome.result) |value| {
                        var discarded = value;
                        discarded.deinit();
                    } else |err| if (err == error.Canceled) counters.recordCanceledLoser();
                    continue;
                }
                const response = outcome.result catch |err| {
                    if (err == error.Timeout) counters.recordDeadline();
                    if (control.winner() == outcome.index or control.errorIsFatal(err)) {
                        return @errorCast(err);
                    }
                    counters.recordBackendFailure();
                    last_error = err;
                    const throttle_allows = if (policy.throttler) |throttler|
                        throttler.recordFailure()
                    else
                        true;
                    Scheduler.invalidate(&timer_generation, &timer_pending);
                    if (!throttle_allows or launched >= policy.max_attempts) {
                        if (!throttle_allows) counters.recordThrottle();
                        scheduling_stopped = true;
                        continue;
                    }
                    try Scheduler.launch(
                        &select,
                        state,
                        control,
                        options,
                        deadline,
                        &launched,
                        &active,
                        counters,
                        .accelerated,
                    );
                    if (launched < policy.max_attempts) {
                        try Scheduler.timer(
                            &select,
                            state.io,
                            control,
                            policy.hedging_delay,
                            deadline,
                            &timer_generation,
                            &timer_pending,
                        );
                    } else {
                        scheduling_stopped = true;
                    }
                    continue;
                };
                if (control.winner() == outcome.index or control.responseIsFatal(response)) {
                    if (response.status == .ok) {
                        counters.recordOkWinner();
                        if (policy.throttler) |throttler| {
                            throttler.recordSuccess();
                        }
                    } else {
                        counters.recordFatalWinner();
                        if (!response.was_dropped and policy.isNonFatal(response.status)) {
                            if (policy.throttler) |throttler| _ = throttler.recordFailure();
                        }
                    }
                    return response;
                }

                const pushback = retry.responsePushback(response);
                if (last_non_fatal) |*previous| previous.deinit();
                last_non_fatal = response;
                const throttle_allows = if (policy.throttler) |throttler|
                    throttler.recordFailure()
                else
                    true;
                Scheduler.invalidate(&timer_generation, &timer_pending);
                if (!throttle_allows or launched >= policy.max_attempts or
                    pushback == .stop)
                {
                    if (!throttle_allows) counters.recordThrottle();
                    if (pushback == .stop) counters.recordPushbackStop();
                    scheduling_stopped = true;
                    continue;
                }
                switch (pushback) {
                    .stop => unreachable,
                    .delay => |delay| {
                        counters.recordPushbackDelay();
                        try Scheduler.timer(
                            &select,
                            state.io,
                            control,
                            delay,
                            deadline,
                            &timer_generation,
                            &timer_pending,
                        );
                    },
                    .absent => {
                        try Scheduler.launch(
                            &select,
                            state,
                            control,
                            options,
                            deadline,
                            &launched,
                            &active,
                            counters,
                            .accelerated,
                        );
                        if (launched < policy.max_attempts) {
                            try Scheduler.timer(
                                &select,
                                state.io,
                                control,
                                policy.hedging_delay,
                                deadline,
                                &timer_generation,
                                &timer_pending,
                            );
                        } else {
                            scheduling_stopped = true;
                        }
                    },
                }
            },
        }
    }
}

fn hedgingAllowed(policy: call.HedgingPolicy) bool {
    const throttler = policy.throttler orelse return true;
    return throttler.hedgingAllowed();
}

fn hedgeableAttemptError(err: anyerror) bool {
    return control_mod.canHedgeError(err);
}

test "gRPC hedging classifies backend-local attempt errors" {
    try std.testing.expect(hedgeableAttemptError(error.ConnectionRefused));
    try std.testing.expect(hedgeableAttemptError(error.ConnectionResetByPeer));
    try std.testing.expect(!hedgeableAttemptError(error.OutOfMemory));
    try std.testing.expect(!hedgeableAttemptError(error.InvalidMetadata));
}

//! gRFC A6 concurrent unary hedging for the background SharedChannel owner.

const std = @import("std");
const call = @import("../../call.zig");
const retry = @import("../../call/retry.zig");
const wire = @import("../../wire.zig");
const stats = @import("hedging/stats.zig");

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
    };
    const TimerResult = std.Io.Cancelable!TimerOutcome;
    const Wake = union(enum) {
        attempt: AttemptOutcome,
        timer: TimerResult,
    };
    const Attempt = struct {
        fn execute(
            owner: *State,
            request: call.UnaryCallOptions,
            overall: ?std.Io.Clock.Timestamp,
            index: u8,
        ) AttemptOutcome {
            var transparent_used = false;
            while (true) {
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
                var response = owner.attempt(
                    owner.allocator,
                    request,
                    overall,
                    overall,
                    timeout_header,
                    if (index == 0) null else index,
                ) catch |err| return .{ .index = index, .result = err };
                if (request.transparent_retry and !transparent_used and
                    !response.response_committed and response.reset != null and
                    response.reset.?.error_code == .refused_stream)
                {
                    transparent_used = true;
                    response.deinit();
                    continue;
                }
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
            try target.wait(io);
            return .{
                .generation = generation,
                .deadline = is_deadline,
            };
        }
    };
    const Scheduler = struct {
        fn launch(
            select: *std.Io.Select(Wake),
            owner: *State,
            request: call.UnaryCallOptions,
            overall: ?std.Io.Clock.Timestamp,
            launched: *u8,
            active: *u8,
            counters: *stats.Counters,
            reason: stats.Launch,
        ) State.Failure!void {
            const index = launched.*;
            try select.concurrent(
                .attempt,
                Attempt.execute,
                .{ owner, request, overall, index },
            );
            launched.* += 1;
            active.* += 1;
            counters.recordLaunch(reason);
        }

        fn timer(
            select: *std.Io.Select(Wake),
            io: std.Io,
            delay: std.Io.Duration,
            overall: ?std.Io.Clock.Timestamp,
            generation: *u64,
            pending: *bool,
        ) State.Failure!void {
            generation.* +%= 1;
            try select.concurrent(
                .timer,
                Timer.wait,
                .{ io, delay, overall, generation.* },
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
            };
        }
    };

    try policy.validate();
    const counters = &state.hedging_counters;
    counters.recordCall();
    var storage: [12]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(state.io, &storage);
    defer Scheduler.drain(&select, counters);
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
            .timer => |result| {
                const timer = try result;
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
                const response = outcome.result catch |err| {
                    if (err == error.Timeout) counters.recordDeadline();
                    if (!policy.isNonFatal(.unavailable) or
                        !hedgeableAttemptError(err))
                    {
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
                if (response.status == .ok or
                    !policy.isNonFatal(response.status))
                {
                    if (response.status == .ok) {
                        counters.recordOkWinner();
                        if (policy.throttler) |throttler| {
                            throttler.recordSuccess();
                        }
                    } else counters.recordFatalWinner();
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
    return switch (err) {
        error.AddressUnavailable,
        error.BrokenPipe,
        error.ConnectionClosed,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.ConnectionUnavailable,
        error.HostUnreachable,
        error.NameServerFailure,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.NoAddressReturned,
        error.ReadFailed,
        error.SocketUnconnected,
        error.UnexpectedEof,
        error.UnknownHostName,
        error.WriteFailed,
        => true,
        else => false,
    };
}

test "gRPC hedging classifies backend-local attempt errors" {
    try std.testing.expect(hedgeableAttemptError(error.ConnectionRefused));
    try std.testing.expect(hedgeableAttemptError(error.ConnectionResetByPeer));
    try std.testing.expect(!hedgeableAttemptError(error.OutOfMemory));
    try std.testing.expect(!hedgeableAttemptError(error.InvalidMetadata));
}

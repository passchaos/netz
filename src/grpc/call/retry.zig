//! Unary retry lifecycle: one transparent refusal, explicit replay, and budget.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const call = @import("../call.zig");
const Timeout = @import("../wire.zig").Timeout;
const Error = call.Error;
const UnaryResponse = call.UnaryResponse;
const RetryPolicy = call.RetryPolicy;

pub fn run(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: call.UnaryCallOptions, policy: ?RetryPolicy, comptime attempt: anytype) Error!UnaryResponse {
    const deadline: ?std.Io.Clock.Timestamp = if (options.timeout) |timeout|
        std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = timeout.duration(), .clock = .awake })
    else
        null;
    return runWithDeadline(
        connection,
        allocator,
        options,
        policy,
        deadline,
        attempt,
    );
}

pub fn runWithDeadline(connection: anytype, allocator: std.mem.Allocator, options: call.UnaryCallOptions, policy: ?RetryPolicy, deadline: ?std.Io.Clock.Timestamp, comptime attempt: anytype) @TypeOf(attempt(connection, allocator, options, deadline, deadline, @as(?Timeout, null), @as(?u8, null))) {
    if (policy) |configured| try configured.validate();
    var attempts: u8 = 0;
    var transparent_used = false;
    var backoff = if (policy) |configured| cappedBackoff(configured.initial_backoff, configured.max_backoff) else std.Io.Duration.zero;
    while (true) {
        const timeout_header: ?Timeout = if (deadline) |absolute| blk: {
            const remaining = absolute.durationFromNow(connection.io).raw;
            if (remaining.nanoseconds <= 0) return error.Timeout;
            break :blk try Timeout.fromDuration(remaining);
        } else null;
        const attempt_boundary = perAttemptDeadline(
            connection.io,
            deadline,
            policy,
        );
        var response = attempt(
            connection,
            allocator,
            options,
            attempt_boundary.deadline,
            deadline,
            timeout_header,
            if (attempts == 0) null else attempts,
        ) catch |err| {
            // A GOAWAY above this stream's ID means the peer never processed
            // it, so one transparent replay is safe just like REFUSED_STREAM.
            const any_err: anyerror = err;
            if (any_err == error.ConnectionGoAway and options.transparent_retry and !transparent_used) {
                transparent_used = true;
                continue;
            }
            if (err != error.Timeout or !attempt_boundary.limited) return err;
            attempts += 1;
            const configured = policy.?;
            const retry_allowed = if (configured.throttler) |throttler|
                throttler.recordFailure()
            else
                true;
            if (!retry_allowed or attempts >= configured.max_attempts) {
                return call.perAttemptTimeoutResponse(allocator);
            }
            const delay = jitteredBackoff(connection.io, backoff);
            backoff = nextBackoff(backoff, configured);
            try sleepForRetry(connection.io, delay, deadline);
            continue;
        };
        if (response.reset != null and
            response.reset.?.error_code == .cancel and
            attempt_boundary.deadline != null and
            attempt_boundary.deadline.?.durationFromNow(connection.io).raw.nanoseconds <= 0)
        {
            response.deinit();
            if (!attempt_boundary.limited) return error.Timeout;
            attempts += 1;
            const configured = policy.?;
            const retry_allowed = if (configured.throttler) |throttler|
                throttler.recordFailure()
            else
                true;
            if (!retry_allowed or attempts >= configured.max_attempts) {
                return call.perAttemptTimeoutResponse(allocator);
            }
            const delay = jitteredBackoff(connection.io, backoff);
            backoff = nextBackoff(backoff, configured);
            try sleepForRetry(connection.io, delay, deadline);
            continue;
        }
        if (response.was_dropped) return response;
        if (options.transparent_retry and !transparent_used and !response.response_committed and
            response.reset != null and response.reset.?.error_code == .refused_stream)
        {
            transparent_used = true;
            response.deinit();
            continue;
        }
        attempts += 1;
        const configured = policy orelse return response;
        if (response.status == .ok) {
            if (configured.throttler) |throttler| throttler.recordSuccess();
            return response;
        }
        if (!retryableStatus(response, configured)) return response;
        if (configured.throttler) |throttler| if (!throttler.recordFailure()) return response;
        if (attempts >= configured.max_attempts or !retryEligible(response)) return response;
        const pushback = responsePushback(response);
        if (pushback == .stop) return response;
        const delay = switch (pushback) {
            .stop => unreachable,
            .delay => |value| blk: {
                backoff = cappedBackoff(configured.initial_backoff, configured.max_backoff);
                break :blk value;
            },
            .absent => blk: {
                const value = jitteredBackoff(connection.io, backoff);
                backoff = nextBackoff(backoff, configured);
                break :blk value;
            },
        };
        response.deinit();
        try sleepForRetry(connection.io, delay, deadline);
    }
}

const AttemptBoundary = struct {
    deadline: ?std.Io.Clock.Timestamp,
    limited: bool,
};

fn perAttemptDeadline(
    io: std.Io,
    overall: ?std.Io.Clock.Timestamp,
    policy: ?RetryPolicy,
) AttemptBoundary {
    const configured = policy orelse return .{
        .deadline = overall,
        .limited = false,
    };
    const duration = configured.per_attempt_recv_timeout orelse return .{
        .deadline = overall,
        .limited = false,
    };
    const attempt = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = duration,
        .clock = .awake,
    });
    const outer = overall orelse return .{
        .deadline = attempt,
        .limited = true,
    };
    if (std.Io.Clock.Timestamp.compare(attempt, .lt, outer)) {
        return .{ .deadline = attempt, .limited = true };
    }
    return .{ .deadline = outer, .limited = false };
}

pub const Pushback = union(enum) {
    absent,
    stop,
    delay: std.Io.Duration,
};

fn retryEligible(
    response: UnaryResponse,
) bool {
    if (response.reset != null) return !response.response_committed;
    const transport = response.transport orelse return false;
    return transport.trailers_only and
        call.headerValue(transport.headers, "grpc-status") != null;
}

fn retryableStatus(response: UnaryResponse, policy: RetryPolicy) bool {
    if (response.transport == null and response.reset == null) return false;
    for (policy.retryable_status_codes) |status| if (status == response.status) return true;
    return false;
}

pub fn responsePushback(response: UnaryResponse) Pushback {
    const transport = response.transport orelse return .absent;
    return retryPushbackFields(transport.headers);
}

/// gRPC Core models pushback as known, non-repeatable metadata. Its metadata
/// map applies fields in wire order, so the last value replaces any earlier
/// value. Match that behavior instead of letting an intermediary-prepended
/// value override the server's terminal retry decision.
fn retryPushbackFields(
    headers: []const http2.Hpack.HeaderField,
) Pushback {
    var raw: ?[]const u8 = null;
    for (headers) |field| {
        if (std.mem.eql(u8, field.name, "grpc-retry-pushback-ms")) {
            raw = field.value;
        }
    }
    const value = raw orelse return .absent;
    const milliseconds = parsePushbackMilliseconds(value) orelse return .stop;
    if (milliseconds < 0) return .stop;
    return .{ .delay = .fromMilliseconds(milliseconds) };
}

fn parsePushbackMilliseconds(value: []const u8) ?i32 {
    if (value.len == 0 or value[0] == '+') return null;
    const digits = if (value[0] == '-') value[1..] else value;
    if (digits.len == 0 or (digits.len > 1 and digits[0] == '0')) return null;
    for (digits) |byte| if (byte < '0' or byte > '9') return null;
    const parsed = std.fmt.parseInt(i32, value, 10) catch return null;
    if (parsed == 0 and value[0] == '-') return null;
    return parsed;
}

test "gRPC retry pushback uses the final non-repeatable metadata value" {
    const stop = retryPushbackFields(&.{
        .{ .name = "grpc-retry-pushback-ms", .value = "0" },
        .{ .name = "grpc-retry-pushback-ms", .value = "-1" },
    });
    try std.testing.expect(stop == .stop);

    const delay = retryPushbackFields(&.{
        .{ .name = "grpc-retry-pushback-ms", .value = "-1" },
        .{ .name = "grpc-retry-pushback-ms", .value = "7" },
    });
    try std.testing.expectEqual(
        @as(i96, 7 * std.time.ns_per_ms),
        delay.delay.nanoseconds,
    );

    try std.testing.expect(retryPushbackFields(&.{.{
        .name = "grpc-retry-pushback-ms",
        .value = "invalid",
    }}) == .stop);
    try std.testing.expect(retryPushbackFields(&.{}) == .absent);
    for ([_][]const u8{
        "01",
        "-0",
        "+1",
        "2147483648",
        "-2147483649",
    }) |value| {
        try std.testing.expect(retryPushbackFields(&.{.{
            .name = "grpc-retry-pushback-ms",
            .value = value,
        }}) == .stop);
    }
    try std.testing.expectEqual(
        @as(i96, std.math.maxInt(i32) * std.time.ns_per_ms),
        retryPushbackFields(&.{.{
            .name = "grpc-retry-pushback-ms",
            .value = "2147483647",
        }}).delay.nanoseconds,
    );
}

fn cappedBackoff(
    value: std.Io.Duration,
    maximum: std.Io.Duration,
) std.Io.Duration {
    return if (value.nanoseconds < maximum.nanoseconds) value else maximum;
}

fn nextBackoff(
    current: std.Io.Duration,
    policy: RetryPolicy,
) std.Io.Duration {
    const scaled = @as(f64, @floatFromInt(current.nanoseconds)) *
        policy.backoff_multiplier;
    const maximum: f64 = @floatFromInt(policy.max_backoff.nanoseconds);
    if (!std.math.isFinite(scaled) or scaled >= maximum) {
        return policy.max_backoff;
    }
    return .fromNanoseconds(@intFromFloat(@ceil(scaled)));
}

fn jitteredBackoff(io: std.Io, backoff: std.Io.Duration) std.Io.Duration {
    var random_bytes: [2]u8 = undefined;
    std.Io.random(io, &random_bytes);
    const per_mille: u16 = 800 +
        std.mem.readInt(u16, &random_bytes, .little) % 401;
    const scaled = @as(f64, @floatFromInt(backoff.nanoseconds)) *
        @as(f64, @floatFromInt(per_mille)) / 1000.0;
    const maximum: f64 = @floatFromInt(std.math.maxInt(i96));
    if (!std.math.isFinite(scaled) or scaled >= maximum) {
        return std.Io.Duration.max;
    }
    return .fromNanoseconds(@intFromFloat(scaled));
}

fn sleepForRetry(
    io: std.Io,
    delay: std.Io.Duration,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    if (deadline) |absolute| {
        const remaining = absolute.durationFromNow(io).raw;
        if (remaining.nanoseconds <= 0) return error.Timeout;
        if (delay.nanoseconds >= remaining.nanoseconds) {
            try std.Io.sleep(io, remaining, .awake);
            return error.Timeout;
        }
    }
    if (delay.nanoseconds > 0) {
        try std.Io.sleep(io, delay, .awake);
    }
}

test "gRPC retry transparently replays one GOAWAY-unprocessed attempt" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Context = struct {
        io: std.Io,
        calls: usize,
        fn attempt(self: *@This(), _: std.mem.Allocator, _: call.UnaryCallOptions, _: ?std.Io.Clock.Timestamp, _: ?std.Io.Clock.Timestamp, _: ?Timeout, _: ?u8) (Error || error{ConnectionGoAway})!UnaryResponse {
            self.calls += 1;
            if (self.calls == 1) return error.ConnectionGoAway;
            return .{ .allocator = std.testing.allocator, .transport = null, .status = .ok, .status_message = try std.testing.allocator.dupe(u8, ""), .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
        }
    };
    var context = Context{ .io = io, .calls = 0 };
    var response = try runWithDeadline(&context, std.testing.allocator, .{ .path = "/svc/Op", .message = "body" }, null, null, Context.attempt);
    defer response.deinit();
    try std.testing.expectEqual(@as(usize, 2), context.calls);
    try std.testing.expectEqual(@import("../wire.zig").Status.ok, response.status);
}

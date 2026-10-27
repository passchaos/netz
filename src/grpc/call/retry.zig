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

pub fn runWithDeadline(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: call.UnaryCallOptions, policy: ?RetryPolicy, deadline: ?std.Io.Clock.Timestamp, comptime attempt: anytype) Error!UnaryResponse {
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
        var response = try attempt(connection, allocator, options, deadline, timeout_header, if (attempts == 0) null else attempts);
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
        const pushback = retryPushback(response);
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

const RetryPushback = union(enum) {
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

fn retryPushback(response: UnaryResponse) RetryPushback {
    const transport = response.transport orelse return .absent;
    return retryPushbackFields(transport.headers);
}

/// gRPC Core models pushback as known, non-repeatable metadata. Its metadata
/// map applies fields in wire order, so the last value replaces any earlier
/// value. Match that behavior instead of letting an intermediary-prepended
/// value override the server's terminal retry decision.
fn retryPushbackFields(
    headers: []const http2.Hpack.HeaderField,
) RetryPushback {
    var raw: ?[]const u8 = null;
    for (headers) |field| {
        if (std.mem.eql(u8, field.name, "grpc-retry-pushback-ms")) {
            raw = field.value;
        }
    }
    const value = raw orelse return .absent;
    const milliseconds = std.fmt.parseInt(i64, value, 10) catch return .stop;
    if (milliseconds < 0) return .stop;
    return .{ .delay = .fromMilliseconds(milliseconds) };
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

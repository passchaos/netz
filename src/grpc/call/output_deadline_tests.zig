//! Unary RPC deadlines include complete HTTP/2 upload output and flow control.
const std = @import("std");
const builtin = @import("builtin");
const call = @import("../call.zig");
const BlockedOutput = @import("../../http2/runtime/testing/blocked_output.zig").BlockedOutput;

test "gRPC unary deadline bounds blocked request HEADERS and DATA" {
    if (comptime builtin.os.tag != .linux) return;
    for ([_]bool{ false, true }) |retry| {
        for ([_]bool{ false, true }) |body| try exercise(retry, body, false);
    }
}

test "gRPC unary deadline bounds upload flow control without retry renewal" {
    if (comptime builtin.os.tag != .linux) return;
    for ([_]bool{ false, true }) |retry| try exercise(retry, true, true);
}

fn exercise(retry: bool, body: bool, flow: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    if (flow) fixture.connection.peer_initial_stream_window = 1;
    try fixture.startRescue();
    const large = "x" ** (256 * 1024);
    const options: call.UnaryCallOptions = .{
        .path = "/fixture.Deadline/Unary",
        .authority = "localhost",
        .message = if (body) large else "small",
        .metadata = if (body) &.{} else &.{.{ .name = "x-large", .value = large }},
        .timeout = .{ .value = 30, .unit = .millisecond },
    };
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    const result = if (retry)
        call.unaryCallWithRetry(&fixture.connection, allocator, options, .{
            .max_attempts = 5,
            .initial_backoff = .fromMilliseconds(1),
            .max_backoff = .fromMilliseconds(10),
            .backoff_multiplier = 2,
            .retryable_status_codes = &.{.unavailable},
        })
    else
        call.unaryCall(&fixture.connection, allocator, options);
    if (result) |value| {
        var response = value;
        response.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(u31, 3), fixture.connection.next_client_stream_id);
}

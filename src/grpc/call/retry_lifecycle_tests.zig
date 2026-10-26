const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const scripted = @import("retry_peer.zig");

const Case = struct {
    steps: []const scripted.Step,
    previous: []const []const u8,
    expected: grpc.Status = .ok,
    committed: ?bool = null,
    transparent: bool = true,
    configured: bool = false,
    statuses: []const grpc.Status = &.{.unavailable},
    healthy: bool = false,
    stalled: bool = false,
    throttle: bool = false,
    tokens: []const u64 = &.{},
    deadline: bool = false,
};

fn exercise(config: Case) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_concurrent_streams = 1, .initial_window_size = if (config.stalled) 1 else 65_535 });
    defer server.deinit();
    var throttler = try grpc.RetryThrottler.init(4, 1);
    var peer: scripted.Peer = .{
        .server = &server,
        .steps = config.steps,
        .previous = config.previous,
        .upload_stalled = config.stalled,
        .first_delay = if (config.deadline) .fromMilliseconds(10) else .zero,
        .throttler = if (config.throttle) &throttler else null,
        .tokens = config.tokens,
    };
    const thread = try std.Thread.spawn(.{}, scripted.Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try grpc.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.deinit();
    const options: grpc.UnaryCallOptions = .{ .path = "/fixture.Retry/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = if (config.deadline) 30 else 2000, .unit = .millisecond }, .transparent_retry = config.transparent };
    const started = std.Io.Clock.awake.now(io);
    const result = if (config.configured)
        client.unaryWithRetry(options, .{ .max_attempts = 2, .initial_backoff = .fromMilliseconds(1), .max_backoff = .fromMilliseconds(10), .backoff_multiplier = 2, .retryable_status_codes = config.statuses, .throttler = if (config.throttle) &throttler else null })
    else
        client.unary(options);
    if (config.deadline) {
        try std.testing.expectError(error.Timeout, result);
        try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    } else {
        var response = try result;
        defer response.deinit();
        try std.testing.expectEqual(config.expected, response.status);
        if (config.committed) |committed| try std.testing.expectEqual(committed, response.response_committed);
        if (config.healthy) {
            var next = try client.unary(options);
            defer next.deinit();
            try std.testing.expectEqual(grpc.Status.ok, next.status);
        }
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    try std.testing.expectEqual(config.steps.len, peer.attempts);
    if (config.deadline) try std.testing.expect(peer.timeouts[1] < peer.timeouts[0]);
    if (config.throttle) try std.testing.expectEqual(@as(u64, 4000), throttler.milliTokens());
}

test "gRPC retry lifecycle bounds repeated transparent refusal and supports opt out" {
    try exercise(.{ .steps = &.{ .refused, .refused }, .previous = &.{ "-", "-" }, .expected = .unavailable, .committed = false });
    try exercise(.{ .steps = &.{ .refused, .ok }, .previous = &.{ "-", "-" }, .expected = .unavailable, .committed = false, .transparent = false, .healthy = true });
}
test "gRPC retry lifecycle excludes transparent attempts from policy and throttle accounting" {
    try exercise(.{ .steps = &.{ .refused, .unavailable, .ok }, .previous = &.{ "-", "-", "1" }, .configured = true, .throttle = true, .tokens = &.{ 4000, 4000, 3000 } });
    try exercise(.{ .steps = &.{ .refused, .refused, .ok }, .previous = &.{ "-", "-", "1" }, .configured = true });
}
test "gRPC retry lifecycle preserves committed response heads and informational evidence" {
    try exercise(.{ .steps = &.{ .head_refused, .ok }, .previous = &.{ "-", "-" }, .expected = .unavailable, .committed = true, .configured = true, .healthy = true });
    try exercise(.{ .steps = &.{ .interim_refused, .ok }, .previous = &.{ "-", "-" }, .expected = .unavailable, .committed = true, .configured = true, .healthy = true });
}
test "gRPC retry lifecycle recovers upload refusal without replay after response commitment" {
    try exercise(.{ .steps = &.{ .refused, .ok, .ok }, .previous = &.{ "-", "-", "-" }, .stalled = true, .healthy = true });
    try exercise(.{ .steps = &.{ .head_refused, .ok }, .previous = &.{ "-", "-" }, .expected = .unavailable, .committed = true, .configured = true, .stalled = true, .healthy = true });
    try exercise(.{ .steps = &.{ .interim_refused, .ok }, .previous = &.{ "-", "-" }, .expected = .unavailable, .committed = true, .configured = true, .stalled = true, .healthy = true });
}
test "gRPC retry lifecycle uses explicit policy for uncommitted CANCEL" {
    try exercise(.{ .steps = &.{ .canceled, .ok }, .previous = &.{ "-", "1" }, .configured = true, .statuses = &.{.cancelled} });
    try exercise(.{ .steps = &.{ .canceled, .ok }, .previous = &.{ "-", "-" }, .expected = .cancelled, .healthy = true });
}
test "gRPC retry lifecycle keeps one deadline across transparent refusal" {
    try exercise(.{ .steps = &.{ .refused, .silent }, .previous = &.{ "-", "-" }, .deadline = true });
}

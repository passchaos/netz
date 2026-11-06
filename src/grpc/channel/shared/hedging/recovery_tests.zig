//! Real HTTP/2 failure sequences for transparent hedging recovery.
const std = @import("std");
const grpc = @import("../../../mod.zig");
const http2 = @import("../../../../http2/mod.zig");
const shared = @import("../../shared.zig");
const allocator = std.testing.allocator;

const Step = enum { goaway, refused, unavailable, ok, silent, head_goaway, interim_goaway, accepted_goaway, local_goaway, local_reset_goaway };
const Case = struct {
    steps: []const Step,
    previous: []const ?[]const u8,
    tokens: []const u64,
    transparent: bool = true,
    failure: ?anyerror = null,
    status: grpc.Status = .ok,
    logical_attempts: u64 = 1,
    deadline: bool = false,
    hedging: bool = true,
    local_reset_limit: bool = false,
};

const Peer = struct {
    server: *http2.runtime.Server,
    throttler: *grpc.RetryThrottler,
    config: Case,
    requests: usize = 0,
    first_timeout: ?i96 = null,

    fn run(self: *Peer) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(5));
        var connection_live = true;
        defer if (connection_live) connection.close();
        for (self.config.steps, 0..) |step, index| {
            var request = try connection.readRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(allocator);
            self.requests += 1;
            const previous = grpc.call.headerValue(request.headers, "grpc-previous-rpc-attempts");
            if (self.config.previous[index]) |expected|
                try std.testing.expectEqualStrings(expected, previous.?)
            else
                try std.testing.expect(previous == null);
            try std.testing.expectEqual(self.config.tokens[index], self.throttler.milliTokens());
            try std.testing.expectEqualStrings("preserved", grpc.call.headerValue(request.headers, "x-recovery").?);
            const timeout = (try grpc.Timeout.parse(grpc.call.headerValue(request.headers, "grpc-timeout").?)).duration().nanoseconds;
            if (self.first_timeout) |first| {
                try std.testing.expect(timeout < first);
            } else self.first_timeout = timeout;
            var parsed = try grpc.parseUnaryRequest(allocator, &request, 4096);
            defer parsed.deinit();
            try std.testing.expectEqualStrings("request", parsed.message.payload);
            if (index == 0) try std.Io.sleep(connection.io, .fromMilliseconds(20), .awake);
            switch (step) {
                .refused => try connection.sendResetStream(request.stream_id, .refused_stream),
                .unavailable => try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{
                    .status = .unavailable,
                    .trailers_only = true,
                }),
                .ok => try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{ .message = "reply" }),
                .silent => try canceled(&connection, request.stream_id),
                .accepted_goaway => {
                    try connection.sendGoAway(request.stream_id, .no_error, "accepted");
                    try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{ .message = "reply" });
                },
                .local_goaway, .local_reset_goaway => {
                    // The peer accepted this request. Overflow forces the
                    // client to send its own GOAWAY and is no replay evidence.
                    try http2.runtime.testing.writeRawFrame(&connection, .window_update, 0, if (step == .local_goaway) 0 else request.stream_id, &.{ 0x7f, 0xff, 0xff, 0xff });
                    var goaway = try connection.readGoAwayWithTimeout(.fromSeconds(5));
                    defer goaway.deinit(allocator);
                    try std.testing.expectEqual(if (step == .local_goaway) http2.ErrorCode.flow_control_error else http2.ErrorCode.enhance_your_calm, goaway.goaway.error_code);
                    try std.testing.expectEqualStrings(if (step == .local_goaway) "connection-window-overflow" else "too_many_internal_resets", goaway.goaway.debug_data);
                },
                .goaway, .head_goaway, .interim_goaway => {
                    if (step == .head_goaway) {
                        var writer = try connection.startResponseWithTimeout(request.stream_id, .{
                            .headers = &.{.{ .name = "content-type", .value = "application/grpc" }},
                        }, .fromSeconds(5));
                        writer.finished = true;
                    }
                    if (step == .interim_goaway) try connection.writeInformationalResponseWithTimeout(request.stream_id, 103, &.{}, .fromSeconds(5));
                    try connection.sendGoAway(0, .no_error, "unprocessed");
                    connection.close();
                    connection_live = false;
                    if (index + 1 < self.config.steps.len) {
                        connection = try self.server.acceptWithTimeout(.fromSeconds(5));
                        connection_live = true;
                    } else return;
                },
            }
        }
    }

    fn canceled(connection: *http2.runtime.Connection, id: u31) !void {
        var reset = try connection.readResetStreamWithTimeout(.fromSeconds(5));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(id, reset.reset.stream_id);
        try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
    }
};

fn exercise(config: Case) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var throttler = try grpc.RetryThrottler.init(4, 1);
    var peer: Peer = .{ .server = &server, .throttler = &throttler, .config = config };
    var task = io.async(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var limits: http2.runtime.Limits = .{};
    if (config.local_reset_limit) limits.max_local_error_reset_streams = 0;
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address(), .limits = limits } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const options: grpc.UnaryCallOptions = .{
        .path = "/demo.Recovery/Unary",
        .authority = "localhost",
        .message = "request",
        .metadata = &.{.{ .name = "x-recovery", .value = "preserved" }},
        .wait_for_ready = true,
        .transparent_retry = config.transparent,
        .timeout = .{ .value = if (config.deadline) 200 else 5000, .unit = .millisecond },
    };
    const result = if (config.hedging) sender.unaryWithHedging(options, .{
        .max_attempts = 2,
        .hedging_delay = .fromSeconds(10),
        .non_fatal_status_codes = &.{.unavailable},
        .throttler = &throttler,
    }) else sender.unary(options);
    task.await(io) catch |err| {
        if (result) |value| {
            var response = value;
            response.deinit();
        } else |_| {}
        return err;
    };
    if (config.failure) |expected| {
        if (result) |value| {
            var response = value;
            defer response.deinit();
            return error.ExpectedRecoveryFailure;
        } else |err| try std.testing.expectEqual(expected, @as(anyerror, err));
    } else {
        var response = try result;
        defer response.deinit();
        try std.testing.expectEqual(config.status, response.status);
        if (config.status == .ok) try std.testing.expectEqualStrings("reply", response.message.?.payload);
    }
    try std.testing.expectEqual(config.steps.len, peer.requests);
    const stats = client.hedgingStats();
    if (!config.hedging) {
        try std.testing.expectEqual(@as(u64, 0), stats.calls);
        try std.testing.expectEqual(@as(u64, 0), stats.attempts_started);
        return;
    }
    try std.testing.expectEqual(@as(u64, 1), stats.calls);
    try std.testing.expectEqual(config.logical_attempts, stats.attempts_started);
    try std.testing.expectEqual(config.logical_attempts - 1, stats.accelerated_attempts);
    try std.testing.expectEqual(@as(u64, 0), stats.delayed_attempts);
    try std.testing.expectEqual(@as(u64, 0), stats.backend_failures);
    if (config.status == .ok and config.failure == null) try std.testing.expectEqual(@as(u64, 4000), throttler.milliTokens());
}

test "gRPC hedging GOAWAY recovery preserves original request and attempt accounting" {
    try exercise(.{ .steps = &.{ .goaway, .ok }, .previous = &.{ null, null }, .tokens = &.{ 4000, 4000 } });
    try exercise(.{ .steps = &.{ .unavailable, .goaway, .ok }, .previous = &.{ null, "1", "1" }, .tokens = &.{ 4000, 3000, 3000 }, .logical_attempts = 2 });
}

test "gRPC hedging GOAWAY recovery shares one transparent budget with refusal" {
    try exercise(.{ .steps = &.{ .goaway, .goaway }, .previous = &.{ null, null }, .tokens = &.{ 4000, 4000 }, .failure = error.ConnectionGoAway });
    try exercise(.{ .steps = &.{ .refused, .goaway }, .previous = &.{ null, null }, .tokens = &.{ 4000, 4000 }, .failure = error.ConnectionGoAway });
    // A refused replay can still trigger a configured logical hedge, but it
    // must advertise attempt 1 and debit throttling instead of replaying for free.
    try exercise(.{ .steps = &.{ .goaway, .refused, .ok }, .previous = &.{ null, null, "1" }, .tokens = &.{ 4000, 4000, 3000 }, .logical_attempts = 2 });
}

test "gRPC hedging GOAWAY recovery honors opt out and original deadline" {
    try exercise(.{ .steps = &.{.goaway}, .previous = &.{null}, .tokens = &.{4000}, .transparent = false, .failure = error.ConnectionGoAway });
    try exercise(.{ .steps = &.{ .goaway, .silent }, .previous = &.{ null, null }, .tokens = &.{ 4000, 4000 }, .deadline = true, .failure = error.Timeout });
}

test "gRPC hedging GOAWAY recovery keeps accepted streams and rejects contradicted heads" {
    try exercise(.{ .steps = &.{.accepted_goaway}, .previous = &.{null}, .tokens = &.{4000} });
    try exercise(.{ .steps = &.{.head_goaway}, .previous = &.{null}, .tokens = &.{4000}, .failure = error.InvalidFrame });
    try exercise(.{ .steps = &.{.interim_goaway}, .previous = &.{null}, .tokens = &.{4000}, .failure = error.InvalidFrame });
}

test "gRPC shared unary GOAWAY recovery retains response commitment without hedging" {
    try exercise(.{ .steps = &.{ .goaway, .ok }, .previous = &.{ null, null }, .tokens = &.{ 4000, 4000 }, .hedging = false });
    try exercise(.{ .steps = &.{.head_goaway}, .previous = &.{null}, .tokens = &.{4000}, .failure = error.InvalidFrame, .hedging = false });
    try exercise(.{ .steps = &.{.interim_goaway}, .previous = &.{null}, .tokens = &.{4000}, .failure = error.InvalidFrame, .hedging = false });
}

test "gRPC shared unary GOAWAY recovery never replays local protocol failures" {
    for ([_]bool{ false, true }) |hedging| {
        try exercise(.{ .steps = &.{.local_goaway}, .previous = &.{null}, .tokens = &.{4000}, .failure = error.InvalidFrame, .hedging = hedging });
        try exercise(.{ .steps = &.{.local_reset_goaway}, .previous = &.{null}, .tokens = &.{4000}, .failure = error.InvalidFrame, .hedging = hedging, .local_reset_limit = true });
    }
}

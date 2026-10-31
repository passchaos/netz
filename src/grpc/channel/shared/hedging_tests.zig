const std = @import("std");
const grpc = @import("../../mod.zig");
const channel = @import("../../channel.zig");
const connectivity = @import("../connectivity.zig");
const shared = @import("../shared.zig");

const allocator = std.testing.allocator;

test "gRPC ordinary Channel rejects concurrent hedging policy" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":
        \\ {"maxAttempts":2,"hedgingDelay":"0s"}}]}
    );
    defer config.deinit();
    var client = try channel.Channel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{},
    );
    defer client.deinit();
    try std.testing.expectError(
        error.InvalidChannelOptions,
        client.unaryWithServiceConfig(request(), &config),
    );
    try std.testing.expectError(
        error.InvalidChannelOptions,
        client.startDuplexWithServiceConfig(.{
            .path = "/demo.Hedge/Stream",
        }, &config),
    );
}

test "gRPC SharedChannel hedging delay races endpoints and cancels the loser" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var slow_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer slow_server.deinit();
    var fast_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer fast_server.deinit();
    var slow_seen: std.Io.Event = .unset;
    var slow = io.async(HedgePeer.slow, .{ &slow_server, &slow_seen });
    defer _ = slow.cancel(io) catch {};
    var fast = io.async(HedgePeer.ok, .{ &fast_server, "fast" });
    defer _ = fast.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = slow_server.address() } },
        .{ .cleartext_ip = .{ .address = fast_server.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{},
    );
    defer client.deinit();
    try waitReady(&client, 0);
    try waitReady(&client, 1);
    var sender = client.sender();
    defer sender.deinit();
    const started = std.Io.Clock.awake.now(io);
    var response = try sender.unaryWithHedging(request(), .{
        .max_attempts = 2,
        .hedging_delay = .fromMilliseconds(50),
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("fast", response.message.?.payload);
    const elapsed_ns = std.Io.Clock.awake.now(io).nanoseconds -
        started.nanoseconds;
    try std.testing.expect(elapsed_ns >= 30 * std.time.ns_per_ms);
    try std.testing.expect(elapsed_ns < std.time.ns_per_s);
    try slow_seen.waitTimeout(io, .{
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    });
    try slow.await(io);
    try fast.await(io);
    const stats = client.hedgingStats();
    try std.testing.expectEqual(@as(u64, 1), stats.calls);
    try std.testing.expectEqual(@as(u64, 2), stats.attempts_started);
    try std.testing.expectEqual(@as(u64, 1), stats.delayed_attempts);
    try std.testing.expectEqual(@as(u64, 1), stats.ok_winners);
    try std.testing.expectEqual(@as(u64, 1), stats.canceled_losers);
}

test "gRPC SharedChannel non-fatal hedge accelerates and honors positive pushback" {
    try runNonFatal(null, 0, 800 * std.time.ns_per_ms);
    try runNonFatal(150, 100 * std.time.ns_per_ms, std.time.ns_per_s);
}

test "gRPC SharedChannel negative pushback and throttle suppress new hedges" {
    try runSuppressed(.negative_pushback);
    try runSuppressed(.throttled);
}

test "gRPC SharedChannel returns the last non-fatal hedge after exhaustion" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer first_server.deinit();
    var second_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer second_server.deinit();
    var first = io.async(HedgePeer.nonFatalNamed, .{
        &first_server,
        "first",
        std.Io.Duration.zero,
    });
    defer _ = first.cancel(io) catch {};
    var second = io.async(HedgePeer.nonFatalNamed, .{
        &second_server,
        "last",
        std.Io.Duration.fromMilliseconds(50),
    });
    defer _ = second.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = first_server.address() } },
        .{ .cleartext_ip = .{ .address = second_server.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{},
    );
    defer client.deinit();
    try waitReady(&client, 0);
    try waitReady(&client, 1);
    var sender = client.sender();
    defer sender.deinit();
    var response = try sender.unaryWithHedging(request(), .{
        .max_attempts = 2,
        .hedging_delay = .zero,
        .non_fatal_status_codes = &.{.unavailable},
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);
    try std.testing.expectEqualStrings("last", response.status_message);
    try first.await(io);
    try second.await(io);
    const stats = client.hedgingStats();
    try std.testing.expectEqual(@as(u64, 1), stats.calls);
    try std.testing.expectEqual(@as(u64, 2), stats.attempts_started);
    try std.testing.expectEqual(@as(u64, 1), stats.exhausted_non_fatal);
}

const Suppression = enum {
    negative_pushback,
    throttled,
};

fn runSuppressed(mode: Suppression) !void {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer first_server.deinit();
    var second_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer second_server.deinit();
    var first = io.async(HedgePeer.suppressed, .{ &first_server, mode });
    defer _ = first.cancel(io) catch {};
    var second_seen: std.atomic.Value(bool) = .init(false);
    var second = io.async(HedgePeer.noRequest, .{
        &second_server,
        &second_seen,
    });
    defer _ = second.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = first_server.address() } },
        .{ .cleartext_ip = .{ .address = second_server.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{},
    );
    defer client.deinit();
    try waitReady(&client, 0);
    try waitReady(&client, 1);
    var sender = client.sender();
    defer sender.deinit();
    var throttler = try grpc.RetryThrottler.init(2, 1);
    const policy: grpc.HedgingPolicy = switch (mode) {
        .negative_pushback => .{
            .max_attempts = 2,
            .hedging_delay = .fromSeconds(1),
            .non_fatal_status_codes = &.{.unavailable},
        },
        .throttled => blk: {
            try std.testing.expect(!throttler.recordFailure());
            break :blk .{
                .max_attempts = 2,
                .hedging_delay = .fromMilliseconds(10),
                .throttler = &throttler,
            };
        },
    };
    var response = try sender.unaryWithHedging(request(), policy);
    defer response.deinit();
    switch (mode) {
        .negative_pushback => try std.testing.expectEqual(
            grpc.Status.unavailable,
            response.status,
        ),
        .throttled => try std.testing.expectEqualStrings(
            "original",
            response.message.?.payload,
        ),
    }
    try first.await(io);
    try second.await(io);
    try std.testing.expect(!second_seen.load(.acquire));
    const stats = client.hedgingStats();
    try std.testing.expectEqual(@as(u64, 1), stats.calls);
    try std.testing.expectEqual(@as(u64, 1), stats.attempts_started);
    switch (mode) {
        .negative_pushback => {
            try std.testing.expectEqual(@as(u64, 1), stats.pushback_stops);
            try std.testing.expectEqual(@as(u64, 1), stats.exhausted_non_fatal);
        },
        .throttled => {
            try std.testing.expectEqual(@as(u64, 1), stats.throttled_attempts);
            try std.testing.expectEqual(@as(u64, 1), stats.ok_winners);
        },
    }
}

fn runNonFatal(
    pushback_ms: ?i64,
    minimum_ns: i96,
    maximum_ns: i96,
) !void {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer first_server.deinit();
    var second_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer second_server.deinit();
    var first = io.async(HedgePeer.nonFatal, .{
        &first_server,
        pushback_ms,
    });
    defer _ = first.cancel(io) catch {};
    var second = io.async(HedgePeer.ok, .{ &second_server, "winner" });
    defer _ = second.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = first_server.address() } },
        .{ .cleartext_ip = .{ .address = second_server.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{ .service_config_json =
        \\{"methodConfig":[{"name":[{"service":"demo.Hedge",
        \\ "method":"Unary"}],"hedgingPolicy":{"maxAttempts":2,
        \\ "hedgingDelay":"2s","nonFatalStatusCodes":["UNAVAILABLE"]}}]}
        },
    );
    defer client.deinit();
    try waitReady(&client, 0);
    try waitReady(&client, 1);
    var sender = client.sender();
    defer sender.deinit();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.InvalidSharedOptions,
        sender.startDuplex(.{ .path = "/demo.Hedge/Unary" }),
    );
    var response = try sender.unary(request());
    defer response.deinit();
    try std.testing.expectEqualStrings("winner", response.message.?.payload);
    const elapsed_ns = std.Io.Clock.awake.now(io).nanoseconds -
        started.nanoseconds;
    try std.testing.expect(elapsed_ns >= minimum_ns);
    try std.testing.expect(elapsed_ns < maximum_ns);
    try first.await(io);
    try second.await(io);
    const stats = client.hedgingStats();
    try std.testing.expectEqual(@as(u64, 1), stats.calls);
    try std.testing.expectEqual(@as(u64, 2), stats.attempts_started);
    try std.testing.expectEqual(@as(u64, 1), stats.ok_winners);
    if (pushback_ms == null) {
        try std.testing.expectEqual(@as(u64, 1), stats.accelerated_attempts);
    } else {
        try std.testing.expectEqual(@as(u64, 1), stats.delayed_attempts);
        try std.testing.expectEqual(@as(u64, 1), stats.pushback_delays);
    }
}

fn request() grpc.UnaryCallOptions {
    return .{
        .path = "/demo.Hedge/Unary",
        .authority = "localhost",
        .message = "request",
        .wait_for_ready = true,
        .timeout = grpc.Timeout.init(5, .second) catch unreachable,
    };
}

fn waitReady(client: *shared.SharedChannel, index: usize) !void {
    var watch = client.watchEndpointConnectivity(index).?;
    defer watch.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        watch.tracker.io,
        .{ .raw = .fromSeconds(5), .clock = .awake },
    );
    client.connect();
    while (watch.snapshot().state != connectivity.State.ready) {
        const snapshot = try watch.nextWithDeadline(deadline);
        if (snapshot.state == .ready) return;
    }
}

const HedgePeer = struct {
    fn suppressed(
        listener: *grpc.runtime.Server,
        mode: Suppression,
    ) anyerror!void {
        return switch (mode) {
            .negative_pushback => nonFatal(listener, -1),
            .throttled => delayedOk(
                listener,
                "original",
                .fromMilliseconds(80),
            ),
        };
    }

    fn slow(
        listener: *grpc.runtime.Server,
        seen: *std.Io.Event,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var request_value = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer request_value.deinit();
        seen.set(connection.connection.io);
        var reset = try connection.connection.readResetStreamWithTimeout(
            .fromSeconds(5),
        );
        defer reset.deinit(allocator);
        try std.testing.expectEqual(
            request_value.request.stream_id,
            reset.reset.stream_id,
        );
        try std.testing.expectEqual(
            @import("../../../http2/mod.zig").ErrorCode.cancel,
            reset.reset.error_code,
        );
    }

    fn ok(listener: *grpc.runtime.Server, label: []const u8) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var request_value = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer request_value.deinit();
        try connection.writeUnary(request_value.request.stream_id, .{
            .message = label,
        });
    }

    fn nonFatal(
        listener: *grpc.runtime.Server,
        pushback_ms: ?i64,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var request_value = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer request_value.deinit();
        try connection.writeUnary(request_value.request.stream_id, .{
            .status = .unavailable,
            .status_message = "hedge",
            .retry_pushback_ms = pushback_ms,
            .trailers_only = true,
        });
    }

    fn nonFatalNamed(
        listener: *grpc.runtime.Server,
        status_message: []const u8,
        delay: std.Io.Duration,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var request_value = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer request_value.deinit();
        if (delay.nanoseconds != 0) {
            try std.Io.sleep(connection.connection.io, delay, .awake);
        }
        try connection.writeUnary(request_value.request.stream_id, .{
            .status = .unavailable,
            .status_message = status_message,
            .trailers_only = true,
        });
    }

    fn delayedOk(
        listener: *grpc.runtime.Server,
        label: []const u8,
        delay: std.Io.Duration,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var request_value = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer request_value.deinit();
        try std.Io.sleep(connection.connection.io, delay, .awake);
        try connection.writeUnary(request_value.request.stream_id, .{
            .message = label,
        });
    }

    fn noRequest(
        listener: *grpc.runtime.Server,
        observed: *std.atomic.Value(bool),
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var request_value = connection.readUnaryWithTimeout(
            .fromMilliseconds(250),
        ) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
        defer request_value.deinit();
        observed.store(true, .release);
        try connection.writeUnary(request_value.request.stream_id, .{
            .message = "unexpected",
        });
    }
};

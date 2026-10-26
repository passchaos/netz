//! PUSH_PROMISE and its reserved response share one caller-owned output budget.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;
const fragmented_request_value = "0123456789abcdef" ** 2048;

fn requestFields(path: []const u8) [4]http2.Hpack.HeaderField {
    return .{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = path },
    };
}

test "HTTP/2 push output deadlines bound blocked promise and response writes" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    {
        var fixture = try BlockedOutput.init(io, .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        try fixture.saturate();
        try fixture.startRescue();
        const fields = requestFields("/blocked-promise");
        const started = std.Io.Clock.awake.now(io);
        try std.testing.expectError(
            error.Timeout,
            fixture.connection.promisePushWithTimeout(
                1,
                &fields,
                .fromMilliseconds(30),
            ),
        );
        try std.testing.expect(
            started.untilNow(io, .awake).nanoseconds <
                400 * std.time.ns_per_ms,
        );
        try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(
            @as(usize, 0),
            fixture.connection.activeLocalStreamCount(),
        );
    }

    {
        var fixture = try BlockedOutput.init(io, .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        const fields = requestFields("/blocked-response");
        const promised = try fixture.connection.promisePushWithTimeout(
            1,
            &fields,
            .fromSeconds(1),
        );
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(io);
        try std.testing.expectError(
            error.Timeout,
            fixture.connection.writePushedResponseWithTimeout(
                promised,
                .{ .body = "blocked" },
                .fromMilliseconds(30),
            ),
        );
        try std.testing.expect(
            started.untilNow(io, .awake).nanoseconds <
                400 * std.time.ns_per_ms,
        );
        try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(
            @as(usize, 0),
            fixture.connection.activeLocalStreamCount(),
        );
    }
}

test "HTTP/2 push output deadlines validate before reservation or activation" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try runtime.testing.addActivePeerStream(connection, 1);
    const fields = requestFields("/retry");
    try std.testing.expectError(
        error.Timeout,
        connection.promisePushWithTimeout(1, &fields, .zero),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);

    const promised = try connection.promisePushWithTimeout(
        1,
        &fields,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(@as(u31, 2), promised);
    try std.testing.expectError(
        error.Timeout,
        connection.writePushedResponseWithDeadline(
            promised,
            .{ .body = "push" },
            .{
                .clock = .real,
                .raw = std.Io.Clock.real.now(connection.io).addDuration(
                    .fromSeconds(1),
                ),
            },
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try connection.writePushedResponseWithTimeout(
        promised,
        .{ .body = "push" },
        .fromSeconds(1),
    );
    try connection.writeResponseWithTimeout(
        1,
        .{ .body = "parent" },
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
}

test "HTTP/2 pushed response deadline retires a promise after committed HEADERS" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try runtime.testing.addActivePeerStream(connection, 1);
    const fields = requestFields("/flow-blocked");
    const promised = try connection.promisePushWithTimeout(
        1,
        &fields,
        .fromSeconds(1),
    );
    runtime.testing.setSendConnectionWindow(connection, 0);
    try std.testing.expectError(
        error.Timeout,
        connection.writePushedResponseWithTimeout(
            promised,
            .{ .body = "cannot-send" },
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        connection.writePushedResponseWithTimeout(
            promised,
            .{ .body = "must-not-retry" },
            .fromSeconds(1),
        ),
    );
    try connection.writeResponseWithTimeout(
        1,
        .{},
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
}

test "HTTP/2 push deadline allocation failure keeps reservation and HPACK retryable" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var failures: usize = 0;
    for (0..64) |fail_index| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        const connection = &fixture.connection;
        try runtime.testing.addActivePeerStream(connection, 1);
        const fields = requestFields("/allocation");
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = fail_index },
        );
        connection.allocator = failing.allocator();
        const result = connection.promisePushWithTimeout(
            1,
            &fields,
            .fromSeconds(1),
        );
        connection.allocator = allocator;
        if (result) |promised| {
            try std.testing.expect(failures != 0);
            try connection.writePushedResponseWithTimeout(
                promised,
                .{},
                .fromSeconds(1),
            );
            try connection.writeResponseWithTimeout(
                1,
                .{},
                .fromSeconds(1),
            );
            return;
        } else |err| {
            failures += 1;
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expect(!connection.aggregate_timeout_unusable);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activeLocalStreamCount(),
            );
            const retry = try connection.promisePushWithTimeout(
                1,
                &fields,
                .fromSeconds(1),
            );
            try connection.writePushedResponseWithTimeout(
                retry,
                .{},
                .fromSeconds(1),
            );
            try connection.writeResponseWithTimeout(
                1,
                .{},
                .fromSeconds(1),
            );
        }
    }
    return error.TestUnexpectedResult;
}

test "HTTP/2 push deadline APIs round trip promised response" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(
                .fromSeconds(2),
            );
            defer connection.close();
            var request = try connection.readRequestWithTimeout(
                .fromSeconds(2),
            );
            defer request.deinit(allocator);
            const deadline = std.Io.Clock.Timestamp.fromNow(
                connection.io,
                .{ .clock = .awake, .raw = .fromSeconds(2) },
            );
            const fields = [_]http2.Hpack.HeaderField{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" },
                .{ .name = ":path", .value = "/asset" },
                .{
                    .name = "x-push-request",
                    .value = fragmented_request_value,
                },
            };
            const promised = try connection.promisePushWithDeadline(
                request.stream_id,
                &fields,
                deadline,
            );
            try connection.writePushedResponseWithDeadline(
                promised,
                .{
                    .headers = &.{.{
                        .name = "x-push-deadline",
                        .value = "yes",
                    }},
                    .body = "asset",
                },
                deadline,
            );
            try connection.writeResponseWithDeadline(
                request.stream_id,
                .{ .body = "parent" },
                deadline,
            );
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .enable_push = true,
            .max_header_list_size = 64 * 1024,
        },
    );
    defer client.close();
    var parent = try client.requestWithTimeout(
        .{ .authority = "localhost" },
        .fromSeconds(2),
    );
    defer parent.deinit(allocator);
    try std.testing.expectEqualStrings("parent", parent.body);
    var promise = client.takePromisedRequest() orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/asset",
        runtime.testing.findHeader(promise.headers, ":path").?,
    );
    try std.testing.expectEqualStrings(
        fragmented_request_value,
        runtime.testing.findHeader(
            promise.headers,
            "x-push-request",
        ).?,
    );
    var pushed = try client.readPushedResponseWithTimeout(
        promise,
        .fromSeconds(2),
    );
    defer pushed.deinit(allocator);
    try std.testing.expectEqualStrings("asset", pushed.body);
    try std.testing.expectEqualStrings(
        "yes",
        runtime.testing.findHeader(pushed.headers, "x-push-deadline").?,
    );
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

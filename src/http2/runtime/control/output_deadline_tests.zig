//! Connection and stream terminal control writes have explicit output budgets.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

test "HTTP/2 control output deadlines bound blocked GOAWAY and RST_STREAM" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    {
        var fixture = try BlockedOutput.init(io, .server);
        defer fixture.deinit();
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(io);
        try std.testing.expectError(
            error.Timeout,
            fixture.connection.sendGoAwayWithTimeout(
                0,
                .no_error,
                "blocked",
                .fromMilliseconds(30),
            ),
        );
        try std.testing.expect(
            started.untilNow(io, .awake).nanoseconds <
                400 * std.time.ns_per_ms,
        );
        try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    }

    {
        var fixture = try BlockedOutput.init(io, .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(io);
        try std.testing.expectError(
            error.Timeout,
            fixture.connection.sendResetStreamWithTimeout(
                1,
                .cancel,
                .fromMilliseconds(30),
            ),
        );
        try std.testing.expect(
            started.untilNow(io, .awake).nanoseconds <
                400 * std.time.ns_per_ms,
        );
        try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(
            @as(usize, 1),
            fixture.connection.activePeerStreamCount(),
        );
    }
}

test "HTTP/2 control output deadlines validate and allocate before state commit" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try runtime.testing.addActivePeerStream(connection, 1);
    const wrong_clock = std.Io.Clock.Timestamp{
        .clock = .real,
        .raw = std.Io.Clock.real.now(connection.io).addDuration(
            .fromSeconds(1),
        ),
    };
    try std.testing.expectError(
        error.Timeout,
        connection.sendGoAwayWithDeadline(
            1,
            .no_error,
            "invalid-clock",
            wrong_clock,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.sendResetStreamWithDeadline(
            1,
            .cancel,
            wrong_clock,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.activePeerStreamCount(),
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    const allocation_result = connection.sendGoAwayWithTimeout(
        1,
        .no_error,
        "x" ** 512,
        .fromSeconds(1),
    );
    connection.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, allocation_result);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(!connection.aggregate_timeout_unusable);

    // The failed Last-Stream-ID=1 attempts did not commit a monotonic
    // boundary, so a larger first successful value remains legal.
    try connection.sendGoAwayWithTimeout(
        3,
        .no_error,
        "committed",
        .fromSeconds(1),
    );
    try std.testing.expectError(
        error.InvalidFrame,
        connection.sendGoAwayWithTimeout(
            5,
            .no_error,
            "increase",
            .fromSeconds(1),
        ),
    );
    try connection.sendResetStreamWithTimeout(
        1,
        .cancel,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
}

test "HTTP/2 control deadline APIs deliver RST_STREAM before GOAWAY" {
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
            try connection.sendResetStreamWithDeadline(
                request.stream_id,
                .cancel,
                deadline,
            );
            try connection.sendGoAwayWithDeadline(
                request.stream_id,
                .no_error,
                "done",
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
        .{},
    );
    defer client.close();
    const pending = try runtime.testing.sendCompleteRequest(
        &client,
        .{ .authority = "localhost" },
    );
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(pending.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
    var goaway = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(pending.stream_id, goaway.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

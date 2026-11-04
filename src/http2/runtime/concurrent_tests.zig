const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

test "HTTP/2 continuous concurrent serving multiplexes streams on one connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        seen: [2]bool = .{ false, false },
        lengths: [2]usize = .{ 0, 0 },
        bodies: [2][64]u8 = undefined,
        io: std.Io,
        first_written: std.Io.Event = .unset,
    };
    var context = Context{ .io = io };

    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Connection.ConcurrentStream) anyerror!void {
            const head = stream.head();
            const index: usize = if (std.mem.eql(u8, head.path, "/first"))
                0
            else if (std.mem.eql(u8, head.path, "/second"))
                1
            else
                return error.TestUnexpectedResult;
            ctx.seen[index] = true;
            while (try stream.nextBody(
                ctx.bodies[index][ctx.lengths[index]..],
                futureDeadline(ctx.io),
            )) |count| {
                ctx.lengths[index] += count;
            }
            try std.testing.expectEqualStrings(
                if (index == 0) "alpha-request" else "beta-request",
                ctx.bodies[index][0..ctx.lengths[index]],
            );
            // Serialize response order so the non-multiplexed test client can
            // read stream 1 before stream 3; handlers still run concurrently.
            if (index == 1) try ctx.first_written.wait(ctx.io);
            try stream.startResponse(.{ .status = 200 });
            try stream.writeData("response-", false);
            try stream.writeData(if (index == 0) "first" else "second", true);
            if (index == 0) ctx.first_written.set(ctx.io);
        }
    };

    const ServerTask = struct {
        server: *runtime.Server,
        context: *Context,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const summary = try connection.serveConcurrentStreams(
                Context,
                self.context,
                Handler.run,
                .{ .max_streams = 2, .shutdown = self.shutdown },
            );
            try std.testing.expectEqual(@as(usize, 2), summary.accepted);
            try std.testing.expectEqual(@as(usize, 2), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };

    var shutdown: std.Io.Event = .unset;
    var server_task = ServerTask{ .server = &server, .context = &context, .shutdown = &shutdown };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&server_task});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };

    var client = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        .fromSeconds(3),
    );
    defer client.close();
    const first = try runtime.testing.sendCompleteRequest(&client, .{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
        .body = "alpha-request",
    });
    const second = try runtime.testing.sendCompleteRequest(&client, .{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
        .body = "beta-request",
    });
    var first_response = try client.readResponseWithTimeout(
        first.stream_id,
        first.request_method,
        first.extended_connect,
        .fromSeconds(3),
    );
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), first_response.status);
    try std.testing.expectEqualStrings("response-first", first_response.body);
    var second_response = try client.readResponseWithTimeout(
        second.stream_id,
        second.request_method,
        second.extended_connect,
        .fromSeconds(3),
    );
    defer second_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), second_response.status);
    try std.testing.expectEqualStrings("response-second", second_response.body);

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
    try std.testing.expect(context.seen[0] and context.seen[1]);
}

test "HTTP/2 continuous concurrent serving writes head and body in one command" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {};
    var context: Context = .{};
    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Connection.ConcurrentStream) anyerror!void {
            _ = ctx;
            try stream.startResponseWithBody(.{ .status = 200 }, "ok", true);
        }
    };

    const ServerTask = struct {
        server: *runtime.Server,
        context: *Context,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const summary = try connection.serveConcurrentStreams(
                Context,
                self.context,
                Handler.run,
                .{ .max_streams = 1, .shutdown = self.shutdown },
            );
            try std.testing.expectEqual(@as(usize, 1), summary.accepted);
            try std.testing.expectEqual(@as(usize, 1), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };

    var shutdown: std.Io.Event = .unset;
    var server_task = ServerTask{ .server = &server, .context = &context, .shutdown = &shutdown };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&server_task});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.requestWithTimeout(.{ .path = "/combined" }, .fromSeconds(3));
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
}

test "HTTP/2 continuous concurrent serving handles repeated 32-stream batches" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct { responses: std.atomic.Value(usize) = .init(0) };
    var context: Context = .{};

    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Connection.ConcurrentStream) anyerror!void {
            try stream.startResponse(.{ .status = 200 });
            try stream.writeData("ok", true);
            _ = ctx.responses.fetchAdd(1, .monotonic);
        }
    };

    const ServerTask = struct {
        server: *runtime.Server,
        context: *Context,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const summary = try connection.serveConcurrentStreams(
                Context,
                self.context,
                Handler.run,
                .{
                    .max_streams = 32,
                    .shutdown = self.shutdown,
                },
            );
            try std.testing.expectEqual(@as(usize, 3_200), summary.accepted);
            try std.testing.expectEqual(@as(usize, 3_200), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };

    var shutdown: std.Io.Event = .unset;
    var server_task = ServerTask{ .server = &server, .context = &context, .shutdown = &shutdown };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&server_task});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();

    var requests: [32]runtime.RequestOptions = undefined;
    for (&requests) |*request| request.* = .{};
    var responses: [32]runtime.OwnedResponse = undefined;
    var batch: usize = 0;
    while (batch < 100) : (batch += 1) {
        try client.requestBatchInto(&requests, &responses);
        for (&responses) |*response| {
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings("ok", response.body);
        }
    }

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 3_200),
        context.responses.load(.monotonic),
    );
}

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
}

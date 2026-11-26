const std = @import("std");
test {
    _ = @import("concurrent/informational_tests.zig");
    _ = @import("concurrent/completion_tests.zig");
    _ = @import("concurrent/body_retry_tests.zig");
}
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

test "HTTP/2 combined response command suppresses HEAD bodies" {
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
            const head = stream.head();
            // The engine must reject a body for a suppress-body response
            // instead of emitting DATA after END_STREAM.
            if (std.mem.eql(u8, head.method, "HEAD")) {
                // A HEAD response declares the representation length and the
                // transport suppresses the bytes. The contribution still has
                // to match the declared length, exactly like writeData.
                try stream.startResponseWithBody(.{
                    .status = 200,
                    .request_method = "HEAD",
                    .headers = &.{.{ .name = "content-length", .value = "5" }},
                }, "", true);
            } else {
                try stream.startResponseWithBody(.{ .status = 200 }, "ok", true);
            }
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
            // Both requests must have been served; the client-side
            // assertions above already prove the responses arrived.
            try std.testing.expect(summary.accepted >= 1);
            try std.testing.expect(summary.completed >= 1);
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

    var head_response = try client.requestWithTimeout(
        .{ .method = "HEAD", .path = "/head" },
        .fromSeconds(3),
    );
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.status);
    try std.testing.expectEqualStrings("", head_response.body);

    var get_response = try client.requestWithTimeout(.{ .path = "/get" }, .fromSeconds(3));
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.status);
    try std.testing.expectEqualStrings("ok", get_response.body);

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

test "HTTP/2 concurrent oversize declared body stays stream-scoped" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        // Server-wide request cap. The client is configured higher so it can
        // actually put the oversize body on the wire.
        .{ .max_frame_payload = 4096, .max_body_bytes = 1024 },
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        oversize: std.atomic.Value(usize) = .init(0),
        normal: std.atomic.Value(usize) = .init(0),
    };
    var context = Context{ .io = io };

    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Connection.ConcurrentStream) anyerror!void {
            const head = stream.head();
            if (std.mem.eql(u8, head.path, "/oversize")) {
                var scratch: [64]u8 = undefined;
                // The stream reports the server-wide cap as a body error; the
                // connection must not be torn down for this one request.
                try std.testing.expectError(
                    error.PayloadTooLarge,
                    stream.nextBody(&scratch, futureDeadline(ctx.io)),
                );
                _ = ctx.oversize.fetchAdd(1, .monotonic);
                try stream.startResponseWithBody(.{ .status = 413 }, "too large", true);
                return;
            }
            _ = ctx.normal.fetchAdd(1, .monotonic);
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
                .{ .max_streams = 4, .max_worker_threads = 1, .shutdown = self.shutdown },
            );
            try std.testing.expectEqual(@as(usize, 3), summary.accepted);
            try std.testing.expectEqual(@as(usize, 3), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
            try std.testing.expect(summary.workers_spawned <= 1);
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

    var oversize_body: [2048]u8 = undefined;
    @memset(oversize_body[0..], 'x');
    const oversize = try runtime.testing.sendCompleteRequest(&client, .{
        .method = "POST",
        .path = "/oversize",
        .authority = "localhost",
        .body = oversize_body[0..],
    });
    const sibling = try runtime.testing.sendCompleteRequest(&client, .{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    });

    var oversize_response = try client.readResponseWithTimeout(
        oversize.stream_id,
        oversize.request_method,
        oversize.extended_connect,
        .fromSeconds(3),
    );
    defer oversize_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 413), oversize_response.status);
    try std.testing.expectEqualStrings("too large", oversize_response.body);

    var sibling_response = try client.readResponseWithTimeout(
        sibling.stream_id,
        sibling.request_method,
        sibling.extended_connect,
        .fromSeconds(3),
    );
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), sibling_response.status);
    try std.testing.expectEqualStrings("ok", sibling_response.body);

    // The connection must remain usable after the rejected stream.
    var after = try client.requestWithTimeout(.{ .path = "/after" }, .fromSeconds(3));
    defer after.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), after.status);
    try std.testing.expectEqualStrings("ok", after.body);

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), context.oversize.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 2), context.normal.load(.monotonic));
}

test "HTTP/2 concurrent bodyless request observes body EOF without waiting" {
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
        io: std.Io,
        saw_finished: bool = false,
        body_calls: usize = 0,
    };
    var context = Context{ .io = io };

    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Connection.ConcurrentStream) anyerror!void {
            const head = stream.head();
            try std.testing.expectEqualStrings("GET", head.method);
            try std.testing.expect(stream.bodyFinished());
            var scratch: [16]u8 = undefined;
            const body = try stream.nextBody(&scratch, futureDeadline(ctx.io));
            try std.testing.expectEqual(@as(?usize, null), body);
            ctx.body_calls += 1;
            ctx.saw_finished = true;
            try stream.startResponse(.{ .status = 200 });
            try stream.writeData("bodyless", true);
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
    const pending = try runtime.testing.sendCompleteRequest(&client, .{
        .method = "GET",
        .path = "/bodyless",
        .authority = "localhost",
    });
    var response = try client.readResponseWithTimeout(
        pending.stream_id,
        pending.request_method,
        pending.extended_connect,
        .fromSeconds(3),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("bodyless", response.body);

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
    try std.testing.expect(context.saw_finished);
    try std.testing.expectEqual(@as(usize, 1), context.body_calls);
}

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
}

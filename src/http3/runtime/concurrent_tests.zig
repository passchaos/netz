const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

const test_limits: runtime.Limits = .{
    .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    },
    .max_stream_frame_data = 7,
};

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
}

test "HTTP/3 continuous concurrent serving streams bodies and responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var first = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer first.deinit();
    var second = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer second.deinit();

    const request_bodies = [_][]const u8{
        "alpha-stream-body",
        "beta-stream-body",
    };
    const response_bodies = [_][]const u8{
        "response-for-alpha",
        "response-for-beta",
    };

    const Context = struct {
        io: std.Io,
        seen: [2]bool = .{ false, false },
        bodies: [2][64]u8 = undefined,
        lengths: [2]usize = .{ 0, 0 },
    };
    var context = Context{ .io = io };

    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Server.ConcurrentStream) anyerror!void {
            const path = stream.head().path;
            const index: usize = if (std.mem.eql(u8, path, "/first"))
                0
            else if (std.mem.eql(u8, path, "/second"))
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
                request_bodies[index],
                ctx.bodies[index][0..ctx.lengths[index]],
            );
            const response = response_bodies[index];
            try stream.startResponse(.{ .status = 200 }, response.len);
            try stream.writeData(response[0..6], false);
            try stream.writeData(response[6..], true);
        }
    };

    const ServerTask = struct {
        server: *runtime.Server,
        context: *Context,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const summary = self.server.serveConcurrentStreams(
                Context,
                self.context,
                Handler.run,
                .{
                    .max_streams = 2,
                    .shutdown = self.shutdown,
                },
            ) catch |err| {
                self.err = err;
                return;
            };
            std.testing.expectEqual(@as(usize, 2), summary.accepted) catch |err| {
                self.err = err;
                return;
            };
            std.testing.expectEqual(@as(usize, 2), summary.completed) catch |err| {
                self.err = err;
                return;
            };
            std.testing.expectEqual(@as(usize, 0), summary.failed) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var shutdown: std.Io.Event = .unset;
    var server_task = ServerTask{
        .server = &server,
        .context = &context,
        .shutdown = &shutdown,
    };
    const thread = try std.Thread.spawn(.{}, ServerTask.run, .{&server_task});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };

    const first_id = try first.startRequest(.{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
    }, request_bodies[0].len);
    const second_id = try second.startRequest(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
    }, request_bodies[1].len);
    try first.sendRequestBody(first_id, request_bodies[0][0..5], false);
    try first.sendRequestBody(first_id, request_bodies[0][5..], true);
    try second.sendRequestBody(second_id, request_bodies[1][0..4], false);
    try second.sendRequestBody(second_id, request_bodies[1][4..], true);

    try expectStreamedResponse(
        allocator,
        io,
        &first,
        first_id,
        response_bodies[0],
    );
    try expectStreamedResponse(
        allocator,
        io,
        &second,
        second_id,
        response_bodies[1],
    );

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
    try std.testing.expect(context.seen[0] and context.seen[1]);
}

fn expectStreamedResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *runtime.Client,
    stream_id: u62,
    expected_body: []const u8,
) !void {
    var body: [128]u8 = undefined;
    var body_len: usize = 0;
    var saw_head = false;
    var finished = false;
    const deadline = futureDeadline(io);
    while (!finished) {
        var event = (try client.receiveResponseEventWithDeadline(
            stream_id,
            deadline,
        )) orelse continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => |head| switch (head) {
                .response => |response| {
                    try std.testing.expect(!saw_head);
                    try std.testing.expectEqual(@as(u16, 200), response.status);
                    saw_head = true;
                },
                .request => return error.TestUnexpectedResult,
            },
            .data_available => {
                body_len += try client.readResponseData(stream_id, body[body_len..]);
            },
            .finished => finished = true,
            .push_promise, .trailers => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expectEqualStrings(expected_body, body[0..body_len]);
}

test "HTTP/3 continuous concurrent serving emits response trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();

    const Context = struct { io: std.Io };
    var context = Context{ .io = io };
    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Server.ConcurrentStream) anyerror!void {
            var body: [32]u8 = undefined;
            var length: usize = 0;
            while (try stream.nextBody(body[length..], futureDeadline(ctx.io))) |count| {
                length += count;
            }
            try std.testing.expectEqualStrings("body", body[0..length]);
            try stream.startResponse(.{ .status = 200 }, "body".len);
            try stream.writeData("body", false);
            try stream.finishWithTrailers(&.{.{ .name = "x-trailer", .value = "done" }});
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
            const summary = try self.server.serveConcurrentStreams(
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

    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer client.deinit();
    var response = try client.requestWithTimeout(.{
        .method = "POST",
        .path = "/trailers",
        .authority = "localhost",
        .body = "body",
    }, .fromSeconds(3));
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("body", response.response.body);
    try std.testing.expectEqual(@as(usize, 1), response.response.trailers.len);
    try std.testing.expectEqualStrings("x-trailer", response.response.trailers[0].name);
    try std.testing.expectEqualStrings("done", response.response.trailers[0].value);

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
}

test "HTTP/3 continuous concurrent serving suppress-body responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();

    const Context = struct { io: std.Io };
    var context = Context{ .io = io };
    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Server.ConcurrentStream) anyerror!void {
            var body: [32]u8 = undefined;
            var length: usize = 0;
            while (try stream.nextBody(body[length..], futureDeadline(ctx.io))) |count| {
                length += count;
            }
            const path = stream.head().path;
            if (std.mem.eql(u8, path, "/head")) {
                try stream.startResponse(.{
                    .status = 200,
                    .request_method = "HEAD",
                    .headers = &.{.{ .name = "content-length", .value = "4" }},
                }, 4);
            } else if (std.mem.eql(u8, path, "/empty")) {
                try stream.startResponse(.{ .status = 204 }, null);
            } else return error.TestUnexpectedResult;
            try stream.finish();
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
            const summary = try self.server.serveConcurrentStreams(
                Context,
                self.context,
                Handler.run,
                .{ .max_streams = 2, .shutdown = self.shutdown },
            );
            try std.testing.expectEqual(@as(usize, 2), summary.accepted);
            try std.testing.expectEqual(@as(usize, 2), summary.completed);
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

    var head_client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer head_client.deinit();
    var head_response = try head_client.requestWithTimeout(.{
        .method = "HEAD",
        .path = "/head",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.response.status);
    try std.testing.expectEqualStrings("", head_response.response.body);
    var content_length: ?[]const u8 = null;
    for (head_response.response.headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) content_length = header.value;
    }
    try std.testing.expectEqualStrings("4", content_length.?);

    var empty_client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits,
    );
    defer empty_client.deinit();
    var empty_response = try empty_client.requestWithTimeout(.{
        .method = "GET",
        .path = "/empty",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer empty_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), empty_response.response.status);
    try std.testing.expectEqualStrings("", empty_response.response.body);

    shutdown.set(io);
    thread.join();
    joined = true;
    if (server_task.err) |err| return err;
}


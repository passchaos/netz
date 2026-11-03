const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

test "HTTP/2 continuous concurrent serving streams bodies and responses" {
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
            try stream.startResponse(.{ .status = 200 });
            try stream.writeData("response-", false);
            try stream.writeData(if (index == 0) "first" else "second", true);
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
    var first_server = ServerTask{ .server = &server, .context = &context, .shutdown = &shutdown };
    var second_server = ServerTask{ .server = &server, .context = &context, .shutdown = &shutdown };
    const first_server_thread = try std.Thread.spawn(.{}, ServerTask.run, .{&first_server});
    const second_server_thread = try std.Thread.spawn(.{}, ServerTask.run, .{&second_server});
    var servers_joined = false;
    defer if (!servers_joined) {
        shutdown.set(io);
        first_server_thread.join();
        second_server_thread.join();
    };

    const ClientTask = struct {
        io: std.Io,
        server: *runtime.Server,
        path: []const u8,
        body: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.Client.connectWithTimeout(
                allocator,
                self.io,
                self.server.address(),
                .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
                .fromSeconds(3),
            );
            defer client.close();
            var response = try client.requestWithTimeout(.{
                .method = "POST",
                .path = self.path,
                .authority = "localhost",
                .body = self.body,
            }, .fromSeconds(3));
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
            const expected = if (std.mem.eql(u8, self.path, "/first"))
                "response-first"
            else
                "response-second";
            try std.testing.expectEqualStrings(expected, response.body);
        }
    };

    var first_client = ClientTask{ .io = io, .server = &server, .path = "/first", .body = "alpha-request" };
    var second_client = ClientTask{ .io = io, .server = &server, .path = "/second", .body = "beta-request" };
    const first_client_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&first_client});
    const second_client_thread = try std.Thread.spawn(.{}, ClientTask.run, .{&second_client});
    first_client_thread.join();
    second_client_thread.join();
    if (first_client.err) |err| return err;
    if (second_client.err) |err| return err;

    shutdown.set(io);
    first_server_thread.join();
    second_server_thread.join();
    servers_joined = true;
    if (first_server.err) |err| return err;
    if (second_server.err) |err| return err;
    try std.testing.expect(context.seen[0] and context.seen[1]);
}

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
}

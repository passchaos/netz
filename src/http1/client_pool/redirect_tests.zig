const std = @import("std");
const pool_mod = @import("../client_pool.zig");
const runtime = @import("../runtime.zig");

test "HTTP1 pool follows redirect on one reused connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        io: std.Io,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try connection.readRequest(.{});
            defer first.deinit(allocator);
            try std.testing.expectEqualStrings("POST", first.request.method.string());
            try std.testing.expectEqualStrings("payload", first.request.body);
            try connection.writeResponse(.{
                .status = 303,
                .reason = "See Other",
                .headers = &.{.{ .name = "Location", .value = "/final" }},
                .request_method = first.request.method,
            });
            var second = try connection.readRequest(.{});
            defer second.deinit(allocator);
            try std.testing.expectEqualStrings("GET", second.request.method.string());
            try std.testing.expectEqualStrings("/final", second.request.target);
            try std.testing.expectEqual(@as(usize, 0), second.request.body.len);
            try connection.writeResponse(.{
                .status = 200,
                .body = "pooled-final",
                .request_method = second.request.method,
            });
            try self.release.wait(self.io);
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
        .limits = .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/start",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var result = try pool.requestUriFollowingRedirectsDetailedWithTimeout(
        uri,
        .{
            .method = .POST,
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            .body = "payload",
        },
        .{},
        .fromSeconds(3),
    );
    defer result.deinit();
    try std.testing.expectEqualStrings("pooled-final", result.response.response.body);
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 pool redirect rejects zero timeout before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{},
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriFollowingRedirectsWithTimeout(
            "http://127.0.0.1:1/",
            .{},
            .{},
            .zero,
        ),
    );
}

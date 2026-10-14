const std = @import("std");
const http2 = @import("../mod.zig");
const pool_mod = @import("../client_pool.zig");
const runtime = @import("../runtime.zig");

fn findHeader(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "HTTP2 pool redirects across authorities and retains both connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer redirector.deinit();
    var destination = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer destination.deinit();
    const destination_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/final",
        .{destination.address().getPort()},
    );
    defer allocator.free(destination_uri);

    const Shared = struct {
        redirector: *runtime.Server,
        destination: *runtime.Server,
        destination_uri: []const u8,
        io: std.Io,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first_connection = try self.redirector.accept();
            defer first_connection.close();
            var first = try first_connection.readRequest();
            defer first.deinit(allocator);
            try std.testing.expectEqualStrings("POST", first.method);
            try std.testing.expectEqualStrings("payload", first.body);
            try std.testing.expectEqualStrings(
                "Bearer first-origin",
                findHeader(first.headers, "authorization").?,
            );
            try first_connection.writeResponse(first.stream_id, .{
                .status = 307,
                .headers = &.{.{
                    .name = "location",
                    .value = self.destination_uri,
                }},
                .request_method = first.method,
            });

            var second_connection = try self.destination.accept();
            defer second_connection.close();
            var second = try second_connection.readRequest();
            defer second.deinit(allocator);
            try std.testing.expectEqualStrings("POST", second.method);
            try std.testing.expectEqualStrings("payload", second.body);
            try std.testing.expect(findHeader(second.headers, "authorization") == null);
            try std.testing.expectEqualStrings(
                "application/json",
                findHeader(second.headers, "accept").?,
            );
            try second_connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "pooled-final",
                .request_method = second.method,
            });
            try self.release.wait(self.io);
        }
    };
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
        .io = io,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 2,
        .max_idle_connections = 2,
        .max_idle_per_authority = 1,
        .limits = .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    });
    defer pool.deinit();
    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/start",
        .{redirector.address().getPort()},
    );
    defer allocator.free(initial_uri);
    var result = try pool.requestUriFollowingRedirectsDetailedWithTimeout(
        initial_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer first-origin" },
                .{ .name = "accept", .value = "application/json" },
            },
            .body = "payload",
        },
        .{},
        .fromSeconds(3),
    );
    defer result.deinit();
    try std.testing.expectEqualStrings("pooled-final", result.response.body);
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP2 pool redirect rejects zero timeout before I/O" {
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

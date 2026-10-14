const std = @import("std");
const http2 = @import("../mod.zig");
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

fn uri(
    allocator: std.mem.Allocator,
    port: u16,
    path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}{s}",
        .{ port, path },
    );
}

test "HTTP2 URI redirect rewrites POST 303 to credential-preserving GET" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first_connection = try self.server.accept();
            defer first_connection.close();
            var first = try first_connection.readRequest();
            defer first.deinit(allocator);
            try std.testing.expectEqualStrings("POST", first.method);
            try std.testing.expectEqualStrings("/a/start", first.path);
            try std.testing.expectEqualStrings("payload", first.body);
            try std.testing.expectEqualStrings(
                "Bearer same-origin",
                findHeader(first.headers, "authorization").?,
            );
            try first_connection.writeResponse(first.stream_id, .{
                .status = 303,
                .headers = &.{.{
                    .name = "location",
                    .value = "../final?q=1#not-on-wire",
                }},
                .body = "redirect",
                .request_method = first.method,
            });

            var second_connection = try self.server.accept();
            defer second_connection.close();
            var second = try second_connection.readRequest();
            defer second.deinit(allocator);
            try std.testing.expectEqualStrings("GET", second.method);
            try std.testing.expectEqualStrings("/final?q=1", second.path);
            try std.testing.expectEqual(@as(usize, 0), second.body.len);
            try std.testing.expectEqualStrings(
                "Bearer same-origin",
                findHeader(second.headers, "authorization").?,
            );
            try std.testing.expect(findHeader(second.headers, "content-type") == null);
            try std.testing.expect(findHeader(second.headers, "content-digest") == null);
            try second_connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "accepted",
                .request_method = second.method,
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try uri(
        allocator,
        server.address().getPort(),
        "/a/start#initial",
    );
    defer allocator.free(initial_uri);
    var result = try runtime.Client
        .requestUriFollowingRedirectsDetailedWithTimeout(
        allocator,
        io,
        initial_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer same-origin" },
                .{ .name = "content-type", .value = "text/plain" },
                .{ .name = "content-digest", .value = "sha-256=:AAAA:" },
            },
            .body = "payload",
        },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        .{},
        .fromSeconds(3),
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqualStrings("accepted", result.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP2 cross-origin 307 preserves body and drops credentials and trailers" {
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
    const destination_uri = try uri(
        allocator,
        destination.address().getPort(),
        "/final",
    );
    defer allocator.free(destination_uri);

    const Shared = struct {
        redirector: *runtime.Server,
        destination: *runtime.Server,
        destination_uri: []const u8,
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
            try std.testing.expectEqualStrings("payload", first.body);
            try std.testing.expectEqualStrings(
                "secret",
                findHeader(first.trailers, "x-secret").?,
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
            try std.testing.expect(findHeader(second.headers, "cookie") == null);
            try std.testing.expectEqualStrings(
                "application/json",
                findHeader(second.headers, "accept").?,
            );
            try std.testing.expectEqual(@as(usize, 0), second.trailers.len);
            try second_connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "done",
                .request_method = second.method,
            });
        }
    };
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .destination_uri = destination_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try uri(
        allocator,
        redirector.address().getPort(),
        "/start",
    );
    defer allocator.free(initial_uri);
    var response = try runtime.Client.requestUriFollowingRedirects(
        allocator,
        io,
        initial_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer secret" },
                .{ .name = "cookie", .value = "session=secret" },
                .{ .name = "accept", .value = "application/json" },
            },
            .body = "payload",
            .trailers = &.{.{ .name = "x-secret", .value = "secret" }},
        },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("done", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP2 redirect timeout rejects zero budget before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.requestUriFollowingRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://127.0.0.1:1/",
            .{},
            .{},
            .{},
            .zero,
        ),
    );
}

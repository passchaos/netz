const std = @import("std");
const runtime = @import("../runtime.zig");
const websocket = @import("../mod.zig");

test "WebSocket client sends custom HTTP upgrade headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        saw_headers: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var http_connection = try self.server.http.accept();
            defer http_connection.close();

            var request = try http_connection.readRequest(.{});
            defer request.deinit(self.server.http.allocator);
            try std.testing.expectEqualStrings(
                "Bearer websocket-token",
                request.request.header("authorization").?,
            );
            try std.testing.expectEqualStrings(
                "session=abc123",
                request.request.header("cookie").?,
            );
            self.saw_headers = true;

            const key = request.request.header("sec-websocket-key") orelse
                return error.MissingHeader;
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(self.server.http.allocator);
            try websocket.writeServerHandshake(
                &response,
                self.server.http.allocator,
                key,
                &.{},
            );
            var writer = http_connection.stream.writer(
                http_connection.io,
                &.{},
            );
            try writer.interface.writeAll(response.items);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .target = "/authenticated",
            .extra_headers = &.{
                .{
                    .name = "Authorization",
                    .value = "Bearer websocket-token",
                },
                .{ .name = "Cookie", .value = "session=abc123" },
            },
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
            },
        },
    );
    client.close();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_headers);
}

test "WebSocket client rejects unsafe custom HTTP upgrade headers" {
    const forbidden = [_][]const u8{
        "Host",
        "Upgrade",
        "Connection",
        "Sec-WebSocket-Key",
        "sEc-WeBsOcKeT-aCcEpT",
        "Sec-WebSocket-Version",
        "Sec-WebSocket-Protocol",
        "Sec-WebSocket-Extensions",
        "Origin",
        "Content-Length",
        "Transfer-Encoding",
        "Trailer",
    };
    for (forbidden) |name| {
        try std.testing.expectError(
            error.InvalidHandshake,
            runtime.testing.validateHttp1ClientExtraHeaders(&.{.{
                .name = name,
                .value = "test",
            }}),
        );
    }

    try std.testing.expectError(
        error.MalformedHeader,
        runtime.testing.validateHttp1ClientExtraHeaders(&.{.{
            .name = "X-Test",
            .value = "injected\r\nHeader: value",
        }}),
    );
    try runtime.testing.validateHttp1ClientExtraHeaders(&.{
        .{ .name = "Authorization", .value = "Bearer token" },
        .{ .name = "Cookie", .value = "session=abc" },
    });
}

test "WebSocket client bounds custom HTTP upgrade headers before writing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        received_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            var buffer: [1]u8 = undefined;
            var slices = [_][]u8{&buffer};
            self.received_bytes = self.io.vtable.netRead(
                self.io.userdata,
                stream.socket.handle,
                &slices,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.HeadersTooLarge,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{
                .host = "127.0.0.1",
                .extra_headers = &.{.{
                    .name = "Authorization",
                    .value = "Bearer value-that-exceeds-the-head-limit",
                }},
                .limits = .{ .max_head_bytes = 64 },
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.received_bytes);
}

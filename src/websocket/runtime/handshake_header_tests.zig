const std = @import("std");
const http1_runtime = @import("../../http1/runtime.zig");
const runtime = @import("../runtime.zig");
const websocket = @import("../mod.zig");

const net = std.Io.net;

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

fn appendExtraHeaderLines(
    headers: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    count: usize,
) !void {
    for (0..count) |index| {
        var buffer: [64]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try writer.print("X-Test-{d}: value\r\n", .{index});
        try headers.appendSlice(allocator, writer.buffered());
    }
}

fn buildClientUpgradeRequest(
    allocator: std.mem.Allocator,
    extra_headers: usize,
) ![]u8 {
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try request.appendSlice(
        allocator,
        "GET /limit HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n",
    );
    try appendExtraHeaderLines(&request, allocator, extra_headers);
    try request.appendSlice(allocator, "\r\n");
    return request.toOwnedSlice(allocator);
}

fn writeServerUpgradeResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    key: []const u8,
    extra_headers: usize,
) !void {
    const accept = websocket.acceptKey(key);
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try response.appendSlice(
        allocator,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: ",
    );
    try response.appendSlice(allocator, &accept);
    try response.appendSlice(allocator, "\r\n");
    try appendExtraHeaderLines(&response, allocator, extra_headers);
    try response.appendSlice(allocator, "\r\n");
    try writeAll(io, stream, response.items);
}

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

test "WebSocket server enforces HTTP upgrade request header counts" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        name: []const u8,
        extra_headers: usize,
        max_request_headers: usize,
        expect_server_error: ?anyerror,
    }{
        .{
            .name = "below limit",
            .extra_headers = 2,
            .max_request_headers = 8,
            .expect_server_error = null,
        },
        .{
            .name = "exact limit",
            .extra_headers = 3,
            .max_request_headers = 8,
            .expect_server_error = null,
        },
        .{
            .name = "over limit",
            .extra_headers = 4,
            .max_request_headers = 8,
            .expect_server_error = error.TooManyHeaders,
        },
    };

    for (cases) |case| {
        errdefer std.log.err("WebSocket request header-count case failed: {s}", .{case.name});
        var threaded = std.Io.Threaded.init(allocator, .{
            .async_limit = .unlimited,
        });
        defer threaded.deinit();
        const io = threaded.io();

        var server = try runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .max_head_bytes = 4096,
                .max_request_headers = case.max_request_headers,
                .max_frame_bytes = 4096,
                .http1_handshake_timeout = .fromMilliseconds(250),
            },
        );
        defer server.deinit();

        const Shared = struct {
            server: *runtime.Server,
            accepted: bool = false,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                var connection = self.server.acceptWithTimeout(
                    .{},
                    .fromMilliseconds(250),
                ) catch |err| {
                    self.err = err;
                    return;
                };
                self.accepted = true;
                connection.close();
            }
        };

        var shared = Shared{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();

        const request = try buildClientUpgradeRequest(
            allocator,
            case.extra_headers,
        );
        defer allocator.free(request);

        const stream = try server.address().connect(io, .{ .mode = .stream });
        defer stream.close(io);
        try writeAll(io, stream, request);

        if (case.expect_server_error == null) {
            var response =
                try http1_runtime.readResponseFromStreamForRequestWithTimeout(
                    allocator,
                    io,
                    stream,
                    .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
                    .{ .max_headers = 32 },
                    .GET,
                    .fromMilliseconds(250),
                );
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 101), response.response.status);
        } else {
            try std.testing.expectError(
                error.ConnectionClosed,
                http1_runtime.readResponseFromStreamForRequestWithTimeout(
                    allocator,
                    io,
                    stream,
                    .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
                    .{ .max_headers = 32 },
                    .GET,
                    .fromMilliseconds(250),
                ),
            );
        }

        thread.join();
        joined = true;
        if (case.expect_server_error) |expected| {
            try std.testing.expectEqual(expected, shared.err.?);
            try std.testing.expect(!shared.accepted);
        } else {
            if (shared.err) |err| return err;
            try std.testing.expect(shared.accepted);
        }
    }
}

test "WebSocket client enforces HTTP upgrade response header counts" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        name: []const u8,
        extra_headers: usize,
        max_response_headers: usize,
        expect_client_error: ?anyerror,
    }{
        .{
            .name = "below limit",
            .extra_headers = 1,
            .max_response_headers = 5,
            .expect_client_error = null,
        },
        .{
            .name = "exact limit",
            .extra_headers = 2,
            .max_response_headers = 5,
            .expect_client_error = null,
        },
        .{
            .name = "over limit",
            .extra_headers = 3,
            .max_response_headers = 5,
            .expect_client_error = error.TooManyHeaders,
        },
    };

    for (cases) |case| {
        errdefer std.log.err("WebSocket response header-count case failed: {s}", .{case.name});
        var threaded = std.Io.Threaded.init(allocator, .{
            .async_limit = .unlimited,
        });
        defer threaded.deinit();
        const io = threaded.io();

        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
            io,
            .{ .reuse_address = true },
        );
        defer listener.deinit(io);

        const Shared = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            listener: *net.Server,
            extra_headers: usize,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                };
            }

            fn runFallible(self: *@This()) !void {
                const stream = try self.listener.accept(self.io);
                defer stream.close(self.io);

                var request =
                    try http1_runtime.readRequestFromStreamWithTimeout(
                        self.allocator,
                        self.io,
                        stream,
                        .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
                        .{ .max_headers = 32 },
                        .fromMilliseconds(250),
                    );
                defer request.deinit(self.allocator);

                const key = request.request.header("sec-websocket-key") orelse
                    return error.MissingHeader;
                try writeServerUpgradeResponse(
                    self.allocator,
                    self.io,
                    stream,
                    key,
                    self.extra_headers,
                );
            }
        };

        var shared = Shared{
            .allocator = allocator,
            .io = io,
            .listener = &listener,
            .extra_headers = case.extra_headers,
        };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();

        const result = runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{
                .host = "127.0.0.1",
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_response_headers = case.max_response_headers,
                    .max_frame_bytes = 4096,
                    .http1_handshake_timeout = .fromMilliseconds(250),
                },
            },
        );
        if (case.expect_client_error) |expected| {
            try std.testing.expectError(expected, result);
        } else {
            var connection = try result;
            connection.close();
        }

        thread.join();
        joined = true;
        if (shared.err) |err| return err;
    }
}

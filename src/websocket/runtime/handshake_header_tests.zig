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

fn readSomeWithDeadline(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) !usize {
    var buffers = [_][]u8{buffer};
    const result = try io.operateTimeout(
        .{ .file_read_streaming = .{
            .file = .{
                .handle = stream.socket.handle,
                .flags = .{ .nonblocking = false },
            },
            .data = &buffers,
        } },
        .{ .deadline = deadline },
    );
    return result.file_read_streaming catch |err| switch (err) {
        error.EndOfStream => 0,
        else => return @errorCast(err),
    };
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

test "WebSocket server admits an inspected upgrade before sending 101" {
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
        request_inspected: std.Io.Event = .unset,
        permit_upgrade: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.request_inspected.set(self.server.http.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequest(.{
                .protocols = &.{"chat.v1"},
                .require_subprotocol = true,
            });
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/authorized?room=7",
                pending.target(),
            );
            try std.testing.expectEqualStrings(
                "Bearer websocket-token",
                pending.header("authorization").?,
            );
            try std.testing.expectEqualStrings(
                "session=abc123",
                pending.header("cookie").?,
            );
            try std.testing.expect(pending.peerCertificates() == null);
            try std.testing.expect(pending.negotiatedCipherSuite() == null);
            try std.testing.expect(
                pending.negotiatedTranscriptHash() == null,
            );
            try std.testing.expect(pending.headers().len >= 7);
            self.request_inspected.set(self.server.http.io);
            try self.permit_upgrade.wait(self.server.http.io);

            var connection = try pending.acceptWithHeaders(&.{.{
                .name = "X-Admission",
                .value = "accepted",
            }});
            pending_owned = false;
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("authorized", message.payload);
            try connection.sendText("accepted");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.permit_upgrade.set(io);
        thread.join();
    };

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(
        io,
        stream,
        "GET /authorized?room=7 HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Protocol: chat.v1\r\n" ++
            "Authorization: Bearer websocket-token\r\n" ++
            "Cookie: session=abc123\r\n" ++
            "\r\n",
    );
    try shared.request_inspected.wait(io);
    var before_response: [1]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        readSomeWithDeadline(
            io,
            stream,
            &before_response,
            .fromNow(
                io,
                .{ .raw = .fromMilliseconds(20), .clock = .awake },
            ),
        ),
    );
    shared.permit_upgrade.set(io);

    var response =
        try http1_runtime.readResponseFromStreamForRequestWithTimeout(
            allocator,
            io,
            stream,
            .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
            .{ .max_headers = 16 },
            .GET,
            .fromSeconds(1),
        );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 101), response.response.status);
    try std.testing.expectEqualStrings(
        "accepted",
        response.response.header("x-admission").?,
    );
    try std.testing.expectEqualStrings(
        "chat.v1",
        response.response.header("sec-websocket-protocol").?,
    );

    var frame_bytes: std.ArrayList(u8) = .empty;
    defer frame_bytes.deinit(allocator);
    try websocket.writeFrame(
        &frame_bytes,
        allocator,
        .text,
        "authorized",
        .{ .mask_key = .{ 1, 2, 3, 4 } },
    );
    try writeAll(io, stream, frame_bytes.items);
    var reply_storage: [10]u8 = undefined;
    var reply_len: usize = 0;
    while (reply_len < reply_storage.len) {
        const count = try readSomeWithDeadline(
            io,
            stream,
            reply_storage[reply_len..],
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        if (count == 0) return error.ConnectionClosed;
        reply_len += count;
        const header = websocket.FrameHeader.parse(
            reply_storage[0..reply_len],
        ) catch |err| switch (err) {
            error.BufferTooShort => continue,
            else => return err,
        };
        if (reply_len < header.header_len + header.payload_len) continue;
        var reply = try websocket.parseFrameOptions(
            allocator,
            reply_storage[0 .. header.header_len + header.payload_len],
            .{ .expect_mask = .unmasked },
        );
        defer reply.deinit(allocator);
        try std.testing.expectEqualStrings("accepted", reply.payload);
        break;
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket server sends inspected HTTP rejection without 101" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequest(.{});
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/private",
                pending.target(),
            );
            try pending.reject(
                401,
                "Unauthorized",
                &.{.{
                    .name = "WWW-Authenticate",
                    .value = "Bearer realm=chat",
                }},
                "denied",
            );
            pending_owned = false;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var http_client = try http1_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer http_client.close();
    var response = try http_client.request(.{
        .target = "/private",
        .host = "localhost",
        .headers = &.{
            .{ .name = "Upgrade", .value = "websocket" },
            .{ .name = "Connection", .value = "Upgrade" },
            .{
                .name = "Sec-WebSocket-Key",
                .value = "dGhlIHNhbXBsZSBub25jZQ==",
            },
            .{ .name = "Sec-WebSocket-Version", .value = "13" },
            .{ .name = "Authorization", .value = "Bearer denied" },
        },
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 401), response.response.status);
    try std.testing.expectEqualStrings(
        "Bearer realm=chat",
        response.response.header("www-authenticate").?,
    );
    try std.testing.expectEqualStrings("denied", response.response.body);
    try std.testing.expect(response.response.header("upgrade") == null);
    try std.testing.expect(!response.response.keepAlive());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket pending upgrade rejects unsafe response fields transactionally" {
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
        validation_finished: std.Io.Event = .unset,
        release_pending: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.validation_finished.set(self.server.http.io);
                self.release_pending.set(self.server.http.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequest(.{});
            defer pending.deinit();
            try std.testing.expectError(
                error.InvalidHandshake,
                pending.acceptWithHeaders(&.{.{
                    .name = "Sec-WebSocket-Accept",
                    .value = "duplicate",
                }}),
            );
            try std.testing.expectError(
                error.InvalidHandshake,
                pending.reject(401, "Unauthorized", &.{.{
                    .name = "Content-Length",
                    .value = "999",
                }}, "denied"),
            );
            try std.testing.expectEqualStrings(
                "Bearer retained",
                pending.header("authorization").?,
            );
            self.validation_finished.set(self.server.http.io);
            try self.release_pending.wait(self.server.http.io);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release_pending.set(io);
        thread.join();
    };

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(
        io,
        stream,
        "GET /transactional HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Authorization: Bearer retained\r\n" ++
            "\r\n",
    );
    try shared.validation_finished.wait(io);
    if (shared.err) |err| return err;
    var response_byte: [1]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        readSomeWithDeadline(
            io,
            stream,
            &response_byte,
            .fromNow(
                io,
                .{ .raw = .fromMilliseconds(20), .clock = .awake },
            ),
        ),
    );
    shared.release_pending.set(io);

    thread.join();
    joined = true;
}

test "WebSocket pending upgrade preserves one handshake deadline" {
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
        request_received: std.Io.Event = .unset,
        try_accept: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.request_received.set(self.server.http.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromMilliseconds(40),
            );
            defer pending.deinit();
            self.request_received.set(self.server.http.io);
            try self.try_accept.wait(self.server.http.io);
            try std.testing.expectError(error.Timeout, pending.accept());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.try_accept.set(io);
        thread.join();
    };

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(
        io,
        stream,
        "GET /deadline HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    try shared.request_received.wait(io);
    try std.Io.sleep(io, .fromMilliseconds(60), .awake);
    shared.try_accept.set(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket pending listener closes an accepted stream after deadline" {
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
        waiting: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const deadline = std.Io.Clock.Timestamp.fromNow(
                self.server.http.io,
                .{
                    .raw = .fromMilliseconds(40),
                    .clock = .awake,
                },
            );
            self.waiting.set(self.server.http.io);
            var pending = self.server.receiveUpgradeRequestWithDeadline(
                .{},
                deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
            defer pending.deinit();
            self.err = error.UnexpectedUpgrade;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try shared.waiting.wait(io);
    try std.Io.sleep(io, .fromMilliseconds(60), .awake);
    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        try readSomeWithDeadline(
            io,
            stream,
            &byte,
            .fromNow(
                io,
                .{ .raw = .fromSeconds(1), .clock = .awake },
            ),
        ),
    );

    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WebSocket pending upgrade validates decisions before consuming ownership" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequest(.{});
            defer pending.deinit();
            try std.testing.expectError(
                error.InvalidStatus,
                pending.reject(299, "Not a rejection", &.{}, &.{}),
            );
            try std.testing.expectEqualStrings(
                "/still-pending",
                pending.target(),
            );
            try std.testing.expectError(
                error.InvalidHandshake,
                pending.acceptWithHeaders(&.{.{
                    .name = "Content-Length",
                    .value = "0",
                }}),
            );
            try std.testing.expectEqualStrings(
                "/still-pending",
                pending.target(),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(
        io,
        client,
        "GET /still-pending HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );

    thread.join();
    if (shared.err) |err| return err;
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

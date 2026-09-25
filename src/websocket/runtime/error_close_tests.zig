const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http2_runtime = @import("../../http2/mod.zig").runtime;

const Server = runtime.Server;
const Client = runtime.Client;
const H2Server = runtime.H2Server;
const H2Client = runtime.H2Client;

fn testNetworkStreams(io: std.Io) ![2]std.Io.net.Stream {
    var listener = try (std.Io.net.IpAddress{
        .ip4 = .loopback(0),
    }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const first = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    errdefer first.close(io);
    const second = try listener.accept(io);
    return .{ first, second };
}

const invalid_masked_text = [_]u8{
    0x81, 0x82,
    0x01, 0x02,
    0x03, 0x04,
    0xc1, 0x82,
};

const UnboundedWriteOperation = enum { text, ping, in_place };

fn expectCloseCode(
    allocator: std.mem.Allocator,
    connection: anytype,
    expected: websocket.CloseCode,
) !void {
    var close = try connection.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqual(
        expected,
        (try websocket.parseClosePayload(close.payload)).?.code,
    );
}

test "WebSocket TCP receiver closes on protocol error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.receiveFrame() catch |err| {
                if (err != error.UnmaskedClientFrame) shared.err = err;
                if (!runtime.testing.receiveStorageReleased(&connection)) {
                    shared.err = error.ProtocolFailure;
                    return;
                }
                _ = connection.receiveFrame() catch |next_err| {
                    if (next_err != error.ConnectionClosed) {
                        shared.err = next_err;
                    }
                    return;
                };
                shared.err = error.ProtocolFailure;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/protocol-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    // Client frames must be masked. Bypass the normal writer to exercise the
    // receiving endpoint's RFC 6455 failure handshake.
    try writeAllToStream(io, client.stream, &.{ 0x81, 0x00 });
    try expectCloseCode(allocator, &client, .protocol_error);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket caller-buffer receiver closes on invalid UTF-8" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            var storage: [32]u8 = undefined;
            _ = connection.receiveMessageInto(&storage) catch |err| {
                if (err != error.InvalidUtf8) shared.err = err;
                if (!runtime.testing.receiveStorageReleased(&connection)) {
                    shared.err = error.ProtocolFailure;
                    return;
                }
                _ = connection.receiveMessageInto(&storage) catch |next_err| {
                    if (next_err != error.ConnectionClosed) {
                        shared.err = next_err;
                    }
                    return;
                };
                shared.err = error.ProtocolFailure;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/utf8-close",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    });
    defer client.close();

    try writeAllToStream(io, client.stream, &invalid_masked_text);
    try expectCloseCode(allocator, &client, .invalid_payload_data);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiver rejects invalid UTF-8 before a frame finishes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.receiveMessage() catch |err| {
                if (err != error.InvalidUtf8) shared.err = err;
                if (!runtime.testing.receiveStorageReleased(&connection)) {
                    shared.err = error.ProtocolFailure;
                    return;
                }
                _ = connection.receiveMessage() catch |next_err| {
                    if (next_err != error.ConnectionClosed) {
                        shared.err = next_err;
                    }
                    return;
                };
                shared.err = error.ProtocolFailure;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/utf8-fail-fast",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    });
    defer client.close();

    // Announce a longer masked frame but stop writing immediately after the
    // second byte proves F4 90 cannot encode a Unicode scalar. A receiver that
    // waits for the remaining payload bytes deadlocks instead of failing fast.
    const prefix = [_]u8{
        0x81, 0x88,
        0x00, 0x00,
        0x00, 0x00,
        0xf4, 0x90,
    };
    try writeAllToStream(io, client.stream, &prefix);
    try expectCloseCode(allocator, &client, .invalid_payload_data);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 receiver closes on invalid UTF-8" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var h2 = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer h2.close();
            var connection = H2Server.accept(
                shared.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 32,
                    .max_message_bytes = 32,
                } },
            ) catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.receiveMessage() catch |err| {
                if (err != error.InvalidUtf8) shared.err = err;
                if (!runtime.testing.receiveStorageReleased(&connection)) {
                    shared.err = error.ProtocolFailure;
                    return;
                }
                _ = connection.receiveMessage() catch |next_err| {
                    if (next_err != error.ConnectionClosed) {
                        shared.err = next_err;
                    }
                    return;
                };
                shared.err = error.ProtocolFailure;
                return;
            };
            shared.err = error.ProtocolFailure;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-utf8-close",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    });
    defer client.close();

    try client.tunnel.write(&invalid_masked_text, false);
    try expectCloseCode(allocator, &client, .invalid_payload_data);
    thread.join();
    if (shared.err) |err| return err;
}

fn expectHttp1FatalPendingAbort(opcode: websocket.Opcode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[1].close(io);

    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{},
    );
    defer connection.close();
    const payload = if (opcode == .close) "\x03\xe8" else "retained outbound payload";
    switch (opcode) {
        .binary => try runtime.testing.beginPendingMessage(
            &connection,
            .binary,
            payload,
        ),
        .ping, .close => try runtime.testing.beginPendingControl(
            &connection,
            opcode,
            payload,
        ),
        .pong => try runtime.testing.queueAutomaticControl(
            &connection,
            .pong,
            payload,
        ),
        else => unreachable,
    }
    switch (opcode) {
        .binary => runtime.testing.markPendingMessageCommitted(&connection, 1),
        .ping, .close => runtime.testing.markPendingControlCommitted(
            &connection,
            opcode,
            1,
        ),
        .pong => {},
        else => unreachable,
    }

    runtime.testing.failReceiveAndFinish(
        &connection,
        .protocol_error,
    );
    try std.testing.expect(runtime.testing.writeAborted(&connection));
    try std.testing.expect(runtime.testing.outboundStorageReleased(&connection));
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendClose(.normal_closure, ""),
    );
}

test "WebSocket fatal receive aborts pending HTTP1 frame transactions" {
    try expectHttp1FatalPendingAbort(.binary);
    try expectHttp1FatalPendingAbort(.ping);
    try expectHttp1FatalPendingAbort(.close);
    try expectHttp1FatalPendingAbort(.pong);
}

test "WebSocket HTTP1 unbounded write failure is terminal" {
    if (comptime @import("builtin").os.tag == .windows) return;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for ([_]UnboundedWriteOperation{ .text, .ping, .in_place }) |operation| {
        const streams = try testNetworkStreams(io);
        const abortive: std.posix.linger = .{ .onoff = 1, .linger = 0 };
        try std.posix.setsockopt(
            streams[1].socket.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.LINGER,
            std.mem.asBytes(&abortive),
        );
        streams[1].close(io);
        var byte: [1]u8 = undefined;
        var buffers = [_][]u8{&byte};
        try std.testing.expectError(
            error.ConnectionResetByPeer,
            io.vtable.netRead(
                io.userdata,
                streams[0].socket.handle,
                &buffers,
            ),
        );

        var connection = runtime.testing.initDirectConnection(
            allocator,
            io,
            streams[0],
            .client,
            .{},
        );
        defer connection.close();
        var mutable = [_]u8{ 1, 2, 3, 4 };
        const result = switch (operation) {
            .text => connection.sendText("terminal-write"),
            .ping => connection.sendPing("terminal-write"),
            .in_place => connection.sendBinaryInPlace(&mutable),
        };
        try std.testing.expectError(error.SocketUnconnected, result);
        try std.testing.expect(runtime.testing.writeAborted(&connection));
        try std.testing.expect(
            runtime.testing.outboundStorageReleased(&connection),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            connection.sendText("must-not-write"),
        );
    }
}

fn expectH2FatalPendingAbort(opcode: websocket.Opcode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(self.server.allocator, &h2, .{});
            defer ws.close();
            var reset = try h2.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(ws.tunnel.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                @import("../../http2/mod.zig").ErrorCode.cancel,
                reset.reset.error_code,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .enable_connect_protocol = true },
    );
    defer h2.close();
    var client = try H2Client.open(allocator, &h2, .{
        .authority = "localhost",
        .path = "/fatal-pending",
    });
    defer client.close();
    const payload = if (opcode == .close) "\x03\xe8" else "retained h2 payload";
    switch (opcode) {
        .binary => try runtime.testing.beginPendingH2Message(
            &client,
            .binary,
            payload,
        ),
        .ping, .close => try runtime.testing.beginPendingH2Control(
            &client,
            opcode,
            payload,
        ),
        .pong => try runtime.testing.queueH2AutomaticControl(
            &client,
            .pong,
            payload,
        ),
        else => unreachable,
    }
    switch (opcode) {
        .binary => runtime.testing.markPendingMessageCommitted(&client, 1),
        .ping, .close => runtime.testing.markPendingControlCommitted(
            &client,
            opcode,
            1,
        ),
        .pong => {},
        else => unreachable,
    }

    runtime.testing.failReceiveAndFinish(
        &client,
        .invalid_payload_data,
    );
    try std.testing.expect(runtime.testing.writeAborted(&client));
    try std.testing.expect(runtime.testing.outboundStorageReleased(&client));
    try std.testing.expect(h2.isReusable());
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.ConnectionClosed,
        client.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        client.sendClose(.normal_closure, ""),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket fatal receive resets pending HTTP2 tunnel transactions" {
    try expectH2FatalPendingAbort(.binary);
    try expectH2FatalPendingAbort(.ping);
    try expectH2FatalPendingAbort(.close);
    try expectH2FatalPendingAbort(.pong);
}

test "WebSocket HTTP2 unbounded writes fail closed per tunnel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            for (0..3) |_| {
                var ws = try H2Server.accept(self.server.allocator, &h2, .{});
                defer ws.close();
                var reset = try h2.readResetStreamWithTimeout(
                    .fromSeconds(2),
                );
                defer reset.deinit(self.server.allocator);
                try std.testing.expectEqual(
                    ws.tunnel.stream_id,
                    reset.reset.stream_id,
                );
                try std.testing.expectEqual(
                    @import("../../http2/mod.zig").ErrorCode.cancel,
                    reset.reset.error_code,
                );
            }
            var sibling = try h2.readRequest();
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/after-failed-writes",
                sibling.path,
            );
            try h2.writeResponse(sibling.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .enable_connect_protocol = true },
    );
    defer h2.close();
    inline for ([_]UnboundedWriteOperation{ .text, .ping, .in_place }) |operation| {
        var client = try H2Client.open(allocator, &h2, .{
            .authority = "localhost",
            .path = "/failed-write",
        });
        defer client.close();
        client.tunnel.abort(null);
        var mutable = [_]u8{ 1, 2, 3, 4 };
        const result = switch (operation) {
            .text => client.sendText("terminal-write"),
            .ping => client.sendPing("terminal-write"),
            .in_place => client.sendBinaryInPlace(&mutable),
        };
        try std.testing.expectError(error.ConnectionClosed, result);
        try std.testing.expect(runtime.testing.writeAborted(&client));
        try std.testing.expect(runtime.testing.outboundStorageReleased(&client));
        try std.testing.expectError(
            error.ConnectionClosed,
            client.sendText("must-not-write"),
        );
    }
    var sibling = try h2.request(.{
        .method = "GET",
        .path = "/after-failed-writes",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);
    try std.testing.expect(h2.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 fatal Close obeys receive deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(self.server.allocator, &h2, .{
                .limits = .{
                    .max_frame_bytes = 32,
                    .max_message_bytes = 32,
                },
            });
            defer ws.close();
            http2_runtime.testing.setSendConnectionWindow(&h2, 0);
            (try http2_runtime.testing.sendStreamWindow(
                &h2,
                ws.tunnel.stream_id,
            )).value = 0;

            var storage: [32]u8 = undefined;
            try std.testing.expectError(
                error.InvalidUtf8,
                ws.receiveMessageIntoWithTimeout(
                    &storage,
                    .fromMilliseconds(50),
                ),
            );
            try std.testing.expect(runtime.testing.writeAborted(&ws));
            try std.testing.expect(runtime.testing.outboundStorageReleased(&ws));
            try std.testing.expect(!h2.isReusable());
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .enable_connect_protocol = true },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/fatal-close-deadline",
        .limits = .{
            .max_frame_bytes = 32,
            .max_message_bytes = 32,
        },
    });
    defer client.close();
    try client.tunnel.write(&invalid_masked_text, false);

    thread.join();
    if (shared.err) |err| return err;
}

fn writeAllToStream(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

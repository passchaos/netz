const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http2_runtime = @import("../../http2/mod.zig").runtime;
const tls_testing = @import("../../tls/testing.zig");

test "WebSocket close handshake times out on a silent peer" {
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
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            std.Io.sleep(
                self.server.http.io,
                .fromMilliseconds(200),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .host = "localhost" },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(
            .{ .code = .normal_closure, .reason = "done" },
            .fromMilliseconds(75),
        ),
    );
    try std.testing.expect(client.close_sent);
    try std.testing.expect(!client.close_received);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket close handshake validates timeout before writing" {
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.closeWithTimeout(null, .zero),
    );
    try std.testing.expect(!connection.close_sent);

    var h2 = runtime.H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        h2.closeWithTimeout(null, .zero),
    );
    try std.testing.expect(!h2.close_sent);
}

test "WebSocket close handshake is absolute across control frames" {
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
        .{},
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            var close = try connection.receiveFrame();
            defer close.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(self.server.http.allocator);
            try websocket.writeFrame(
                &encoded,
                self.server.http.allocator,
                .ping,
                "still-closing",
                .{},
            );
            try websocket.writeFrame(
                &encoded,
                self.server.http.allocator,
                .pong,
                "noise",
                .{},
            );
            // Send both control frames in one write so the client necessarily
            // processes them before its next timed transport read.
            try writeAll(self.server.http.io, connection.stream, encoded.items);
            try std.Io.sleep(
                self.server.http.io,
                .fromMilliseconds(250),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .host = "localhost" },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(
            .{ .code = .normal_closure, .reason = "done" },
            .fromMilliseconds(150),
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

fn writeAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
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

test "WebSocket typed close receive resumes a partial frame" {
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
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        prefix_received: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prefix_received.set(self.server.http.io);
                self.timed_out.set(self.server.http.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            self.prefix_received.set(self.server.http.io);
            try std.testing.expectError(
                error.Timeout,
                connection.receiveCloseFrameWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.timed_out.set(self.server.http.io);
            var close = (try connection.receiveCloseFrameWithDeadline(
                .fromNow(
                    self.server.http.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                ),
            )).?;
            defer close.deinit(self.server.http.allocator);
            try std.testing.expectEqual(
                websocket.CloseCode.going_away,
                close.code,
            );
            try std.testing.expectEqualStrings("restart", close.reason);
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
        .{ .host = "localhost" },
    );
    defer client.close();
    var payload_storage: [125]u8 = undefined;
    const payload = try websocket.writeClosePayloadInto(
        &payload_storage,
        .{ .code = .going_away, .reason = "restart" },
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try websocket.writeFrame(
        &encoded,
        allocator,
        .close,
        payload,
        .{ .mask_key = .{ 1, 2, 3, 4 } },
    );
    const header = try websocket.FrameHeader.parse(encoded.items);
    const split = header.header_len + 1;
    try writeAll(io, client.stream, encoded.items[0..split]);
    try shared.prefix_received.wait(io);
    try shared.timed_out.wait(io);
    try writeAll(io, client.stream, encoded.items[split..]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket close handshake returns in-flight data before peer close" {
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
        .{},
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            try connection.sendText("already-in-flight");
            var close = try connection.receiveFrameAuto();
            defer close.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .host = "localhost" },
    );
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    var application = try client.closeWithDeadline(
        .{ .code = .normal_closure, .reason = "done" },
        deadline,
    );
    defer application.deinit(allocator);
    try std.testing.expectEqual(
        websocket.Opcode.text,
        application.application.header.opcode,
    );
    try std.testing.expectEqualStrings(
        "already-in-flight",
        application.application.payload,
    );
    var closed = try client.continueCloseWithTimeout(.fromSeconds(1));
    defer closed.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings("done", closed.closed.?.reason);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket close handshake returns peer close details" {
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
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var close = connection.receiveFrameAuto() catch |err| {
                self.err = err;
                return;
            };
            defer close.deinit(self.server.http.allocator);
            if (close.header.opcode != .close) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .host = "localhost" },
    );
    defer client.close();
    var event = try client.closeWithTimeout(
        .{ .code = .going_away, .reason = "restart" },
        .fromSeconds(1),
    );
    defer event.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.going_away,
        event.closed.?.code,
    );
    try std.testing.expectEqualStrings("restart", event.closed.?.reason);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket WSS close handshake is deadline bounded" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(200),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{ .host = "localhost" },
        .{ .verify_host = false },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(null, .fromMilliseconds(75)),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 close handshake is deadline bounded" {
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
            var h2 = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer h2.close();
            var ws = runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            ) catch |err| {
                self.err = err;
                return;
            };
            defer ws.close();
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(200),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2_client,
        .{ .authority = "localhost" },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(null, .fromMilliseconds(75)),
    );

    thread.join();
    if (shared.err) |err| return err;
}

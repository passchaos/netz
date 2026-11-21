const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http2_runtime = @import("../../http2/mod.zig").runtime;
const tls_testing = @import("../../tls/testing.zig");

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
    try std.testing.expect(client.close_sent.load(.acquire));
    try std.testing.expect(!client.close_received.load(.acquire));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP1 bounded client frame keeps one mask across suffix chunks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    const payload = "stable-http1-message";
    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );
    try runtime.testing.beginPendingMessage(
        &connection,
        .binary,
        payload,
    );
    const pending = runtime.testing.pendingMessageProgress(&connection) orelse
        return error.TestUnexpectedResult;
    const encoded = try allocator.alloc(u8, pending.total_bytes);
    defer allocator.free(encoded);
    const split = 7;
    const prefix = try runtime.testing.copyPendingMessageChunk(
        &connection,
        payload,
        0,
        encoded[0..split],
    );
    try std.testing.expectEqual(split, prefix.len);
    const suffix = try runtime.testing.copyPendingMessageChunk(
        &connection,
        payload,
        split,
        encoded[split..],
    );
    try std.testing.expectEqual(encoded.len - split, suffix.len);

    var parsed = try websocket.parseFrameOptions(allocator, encoded, .{
        .expect_mask = .masked,
    });
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, parsed.header.opcode);
    try std.testing.expectEqualStrings(payload, parsed.payload);
}

test "HTTP1 bounded Ping and Close retain one encoded frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{},
    );
    try runtime.testing.beginPendingControl(&connection, .ping, "probe");
    const ping = runtime.testing.pendingControlBytes(
        &connection,
        .ping,
    ) orelse return error.TestUnexpectedResult;
    var parsed_ping = try websocket.parseFrameOptions(allocator, ping, .{
        .expect_mask = .masked,
    });
    defer parsed_ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, parsed_ping.header.opcode);
    try std.testing.expectEqualStrings("probe", parsed_ping.payload);
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendText("blocked"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.receiveFrameWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.continuePingWithTimeout("different", .fromSeconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.continueCloseWithTimeout(.fromSeconds(1)),
    );
    var receive_storage: [1]u8 = undefined;
    try std.testing.expectError(
        error.WriteInProgress,
        connection.receiveMessageIntoWithTimeout(
            &receive_storage,
            .fromMilliseconds(1),
        ),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.updateTrafficKeys(false),
    );

    runtime.testing.clearPendingControlForTest(&connection, .ping);
    var close_payload: [125]u8 = undefined;
    const close = try websocket.writeClosePayloadInto(
        &close_payload,
        .{ .code = .normal_closure, .reason = "done" },
    );
    try runtime.testing.beginPendingControl(&connection, .close, close);
    const encoded_close = runtime.testing.pendingControlBytes(
        &connection,
        .close,
    ) orelse return error.TestUnexpectedResult;
    var parsed_close = try websocket.parseFrameOptions(
        allocator,
        encoded_close,
        .{ .expect_mask = .masked },
    );
    defer parsed_close.deinit(allocator);
    var close_frame = (try websocket.parseClosePayloadOwned(
        allocator,
        parsed_close.payload,
    )) orelse return error.TestUnexpectedResult;
    defer close_frame.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        close_frame.code,
    );
    try std.testing.expectEqualStrings("done", close_frame.reason);
    try std.testing.expect(!connection.close_sent.load(.acquire));
    try std.testing.expectError(
        error.WriteInProgress,
        connection.closeWithTimeout(
            .{ .code = .going_away, .reason = "different" },
            .fromSeconds(1),
        ),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendFragmented(.text, &.{ "blocked", "too" }),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.receiveMessageWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.updateTrafficKeys(false),
    );
    try std.testing.expect(!connection.close_sent.load(.acquire));
}

test "HTTP1 bounded TCP Ping resumes exact retained suffix" {
    const allocator = std.testing.allocator;
    const payload = "0123456789" ** 12;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
    try runtime.testing.beginPendingControl(&connection, .ping, payload);
    const retained = runtime.testing.pendingControlBytes(
        &connection,
        .ping,
    ) orelse return error.TestUnexpectedResult;
    var expected_storage: [websocket.max_frame_header_len + 125]u8 = undefined;
    @memcpy(expected_storage[0..retained.len], retained);
    const expected = expected_storage[0..retained.len];
    const split = 9;
    try std.testing.expect(split < expected.len);

    try runtime.testing.writePendingControlPrefix(
        &connection,
        .ping,
        split,
    );
    const before_retry = runtime.testing.pendingPingProgress(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectError(
        error.WriteInProgress,
        connection.continuePingWithTimeout(
            "different",
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        before_retry,
        runtime.testing.pendingPingProgress(&connection).?,
    );

    const Shared = struct {
        io: std.Io,
        stream: std.Io.net.Stream,
        expected: []const u8,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var received: [websocket.max_frame_header_len + 125]u8 = undefined;
            try readExact(
                self.io,
                self.stream,
                received[0..self.expected.len],
            );
            try std.testing.expectEqualSlices(
                u8,
                self.expected,
                received[0..self.expected.len],
            );
            var frame = try websocket.parseFrameOptions(
                std.testing.allocator,
                received[0..self.expected.len],
                .{ .expect_mask = .masked },
            );
            defer frame.deinit(std.testing.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, frame.header.opcode);
            try std.testing.expectEqual(self.expected.len, frame.consumed);
            try std.testing.expectEqualStrings(self.payload, frame.payload);

            var pong_storage: [websocket.max_frame_header_len + 125]u8 = undefined;
            const pong = try websocket.writeFrameInto(
                &pong_storage,
                .pong,
                self.payload,
                .{},
            );
            try writeAll(self.io, self.stream, pong);
        }
    };
    var shared = Shared{
        .io = io,
        .stream = streams[1],
        .expected = expected,
        .payload = payload,
    };
    const peer = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) peer.join();
    defer connection.close();

    var pong = try connection.continuePingWithTimeout(
        payload,
        .fromSeconds(2),
    );
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    try std.testing.expect(
        runtime.testing.pendingPingProgress(&connection) == null,
    );

    peer.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 bounded TCP Close resumes exact retained suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
    var close_payload_storage: [125]u8 = undefined;
    const close_payload = try websocket.writeClosePayloadInto(
        &close_payload_storage,
        .{ .code = .normal_closure, .reason = "retained-close" },
    );
    try runtime.testing.beginPendingControl(
        &connection,
        .close,
        close_payload,
    );
    const retained = runtime.testing.pendingControlBytes(
        &connection,
        .close,
    ) orelse return error.TestUnexpectedResult;
    var expected_storage: [websocket.max_frame_header_len + 125]u8 = undefined;
    @memcpy(expected_storage[0..retained.len], retained);
    const expected = expected_storage[0..retained.len];
    const split = 8;
    try std.testing.expect(split < expected.len);

    try runtime.testing.writePendingControlPrefix(
        &connection,
        .close,
        split,
    );
    try std.testing.expect(!connection.close_sent.load(.acquire));
    const before_retry = runtime.testing.pendingCloseProgress(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectError(
        error.WriteInProgress,
        connection.closeWithTimeout(
            .{ .code = .going_away, .reason = "different" },
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        before_retry,
        runtime.testing.pendingCloseProgress(&connection).?,
    );
    try std.testing.expect(!connection.close_sent.load(.acquire));

    const Shared = struct {
        io: std.Io,
        stream: std.Io.net.Stream,
        expected: []const u8,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var received: [websocket.max_frame_header_len + 125]u8 = undefined;
            try readExact(
                self.io,
                self.stream,
                received[0..self.expected.len],
            );
            try std.testing.expectEqualSlices(
                u8,
                self.expected,
                received[0..self.expected.len],
            );
            var frame = try websocket.parseFrameOptions(
                std.testing.allocator,
                received[0..self.expected.len],
                .{ .expect_mask = .masked },
            );
            defer frame.deinit(std.testing.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, frame.header.opcode);
            try std.testing.expectEqual(self.expected.len, frame.consumed);
            const detail = (try websocket.parseClosePayload(frame.payload)) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                detail.code,
            );
            try std.testing.expectEqualStrings("retained-close", detail.reason);

            var close_storage: [websocket.max_frame_header_len + 125]u8 = undefined;
            const close = try websocket.writeFrameInto(
                &close_storage,
                .close,
                self.payload,
                .{},
            );
            try writeAll(self.io, self.stream, close);
        }
    };
    var shared = Shared{
        .io = io,
        .stream = streams[1],
        .expected = expected,
        .payload = close_payload,
    };
    const peer = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) peer.join();
    defer connection.close();

    var closed = try connection.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "retained-close" },
        .fromSeconds(2),
    );
    defer closed.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings(
        "retained-close",
        closed.closed.?.reason,
    );
    try std.testing.expect(connection.close_sent.load(.acquire));
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&connection) == null,
    );

    peer.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 bounded WSS Ping and Close resume retained suffixes" {
    const allocator = std.testing.allocator;
    const ping_payload = "tls-retained-ping";
    const close_reason = "tls-retained-close";
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
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrameWithTimeout(.fromSeconds(2));
            defer ping.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings(ping_payload, ping.payload);
            try connection.sendPong(ping.payload);

            var close = try connection.receiveFrameWithTimeout(.fromSeconds(2));
            defer close.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            const detail = (try websocket.parseClosePayload(close.payload)) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                detail.code,
            );
            try std.testing.expectEqualStrings(close_reason, detail.reason);
            try connection.sendClose(.normal_closure, close_reason);
        }
    };
    var shared = Shared{ .server = &server };
    const peer = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) peer.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{ .host = "localhost" },
        .{ .verify_host = false },
    );
    defer client.close();

    try runtime.testing.beginPendingControl(&client, .ping, ping_payload);
    const ping_progress = runtime.testing.pendingPingProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(ping_progress.total > 7);
    try runtime.testing.writePendingControlPrefix(&client, .ping, 7);
    var pong = try client.continuePingWithTimeout(
        ping_payload,
        .fromSeconds(2),
    );
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    try std.testing.expect(
        runtime.testing.pendingPingProgress(&client) == null,
    );

    var close_payload_storage: [125]u8 = undefined;
    const close_payload = try websocket.writeClosePayloadInto(
        &close_payload_storage,
        .{ .code = .normal_closure, .reason = close_reason },
    );
    try runtime.testing.beginPendingControl(&client, .close, close_payload);
    const close_progress = runtime.testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(close_progress.total > 8);
    try runtime.testing.writePendingControlPrefix(&client, .close, 8);
    try std.testing.expect(!client.close_sent.load(.acquire));
    var closed = try client.closeWithTimeout(
        .{ .code = .normal_closure, .reason = close_reason },
        .fromSeconds(2),
    );
    defer closed.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings(close_reason, closed.closed.?.reason);
    try std.testing.expect(client.close_sent.load(.acquire));
    try std.testing.expect(
        runtime.testing.pendingCloseProgress(&client) == null,
    );

    peer.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 bounded send rejects stale deadline without starting frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{},
    );
    var progress: runtime.MessageWriteProgress = .{
        .committed_bytes = 99,
        .total_bytes = 99,
        .frame_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.sendTextWithDeadline("late", &progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(runtime.MessageWriteProgress{}, progress);
    try std.testing.expect(
        runtime.testing.pendingMessageProgress(&connection) == null,
    );
}

test "HTTP1 bounded TCP send resumes exact suffix after backpressure" {
    if (comptime @import("builtin").os.tag == .windows) return;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        streams[0].socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    const payload = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);
    const payload_parts = [_][]const u8{
        payload[0..131_071],
        &.{},
        payload[131_071..524_289],
        payload[524_289..],
    };

    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        connection.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    const committed_before_retry = progress.committed_bytes;
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendBinaryWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        committed_before_retry,
        progress.committed_bytes,
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.receiveFrameWithTimeout(.fromMilliseconds(1)),
    );

    const expected_total = progress.total_bytes;
    const received = try allocator.alloc(u8, expected_total);
    defer allocator.free(received);
    const Shared = struct {
        io: std.Io,
        stream: std.Io.net.Stream,
        out: []u8,
        read: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            while (self.read < self.out.len) {
                var parts = [_][]u8{self.out[self.read..]};
                const count = self.io.vtable.netRead(
                    self.io.userdata,
                    self.stream.socket.handle,
                    &parts,
                ) catch |err| {
                    self.err = err;
                    return;
                };
                if (count == 0) {
                    self.err = error.TestUnexpectedResult;
                    return;
                }
                self.read += count;
            }
        }
    };
    var shared = Shared{
        .io = io,
        .stream = streams[1],
        .out = received,
    };
    const reader = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try connection.sendBinaryWithTimeout(
        payload,
        &progress,
        .fromSeconds(3),
    );
    reader.join();
    if (shared.err) |err| return err;
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(expected_total, progress.committed_bytes);
    try std.testing.expectEqual(expected_total, shared.read);
    var parsed = try websocket.parseFrameOptions(allocator, received, .{
        .expect_mask = .masked,
    });
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings(payload, parsed.payload);

    var slices_progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        connection.sendBinarySlicesWithTimeout(
            &payload_parts,
            &slices_progress,
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(slices_progress.committed_bytes > 0);
    try std.testing.expect(
        slices_progress.committed_bytes < slices_progress.total_bytes,
    );
    try std.testing.expect(!slices_progress.frame_committed);
    const different_parts = [_][]const u8{payload};
    const slices_committed = slices_progress.committed_bytes;
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendBinarySlicesWithTimeout(
            &different_parts,
            &slices_progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        slices_committed,
        slices_progress.committed_bytes,
    );

    const slices_total = slices_progress.total_bytes;
    const slices_received = try allocator.alloc(u8, slices_total);
    defer allocator.free(slices_received);
    var slices_shared = Shared{
        .io = io,
        .stream = streams[1],
        .out = slices_received,
    };
    const slices_reader = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&slices_shared},
    );
    try connection.sendBinarySlicesWithTimeout(
        &payload_parts,
        &slices_progress,
        .fromSeconds(3),
    );
    slices_reader.join();
    if (slices_shared.err) |err| return err;
    try std.testing.expect(slices_progress.frame_committed);
    try std.testing.expectEqual(
        slices_total,
        slices_progress.committed_bytes,
    );
    var parsed_slices = try websocket.parseFrameOptions(
        allocator,
        slices_received,
        .{ .expect_mask = .masked },
    );
    defer parsed_slices.deinit(allocator);
    try std.testing.expectEqualSlices(u8, payload, parsed_slices.payload);
}

test "HTTP1 context takeover commits only after bounded send completes" {
    if (comptime @import("builtin").os.tag == .windows) return;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[1].close(io);

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        streams[0].socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    const history_len = 16 * 1024;
    const payload = try allocator.alloc(u8, history_len * 32);
    defer allocator.free(payload);
    var random_state: u64 = 0xd1b5_4a32_d192_ed03;
    const block_len = 1024;
    var offset: usize = 0;
    while (offset < payload.len) : (offset += block_len * 2) {
        for (payload[offset..][0..block_len]) |*byte| {
            random_state ^= random_state << 13;
            random_state ^= random_state >> 7;
            random_state ^= random_state << 17;
            byte.* = @truncate(random_state);
        }
        @memcpy(
            payload[offset + block_len ..][0..block_len],
            payload[offset..][0..block_len],
        );
    }

    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );
    defer connection.close();
    connection.permessage_deflate = true;
    connection.compression_send_context_takeover = true;
    connection.compression_threshold = 0;

    var progress: runtime.MessageWriteProgress = .{};
    // Allow the Debug compressor to prepare this 512-KiB representation. The
    // unread peer then forces a partial socket write, which is the transaction
    // boundary this test exercises.
    const timed_out = blk: {
        connection.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromSeconds(1),
        ) catch |err| switch (err) {
            error.Timeout => break :blk true,
            else => return err,
        };
        break :blk false;
    };
    if (!timed_out) {
        // Some kernels/loopback configurations absorb the complete compressed
        // frame even with a small sender buffer. The partial-write contract
        // cannot be exercised on this host; keep the assertion on platforms
        // where the write blocks.
        return error.SkipZigTest;
    }
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(connection.compression_send.previewPending());

    const first_wire = try allocator.alloc(u8, progress.total_bytes);
    defer allocator.free(first_wire);
    const Shared = struct {
        io: std.Io,
        stream: std.Io.net.Stream,
        out: []u8,
        read: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            while (self.read < self.out.len) {
                var parts = [_][]u8{self.out[self.read..]};
                const count = self.io.vtable.netRead(
                    self.io.userdata,
                    self.stream.socket.handle,
                    &parts,
                ) catch |err| {
                    self.err = err;
                    return;
                };
                if (count == 0) {
                    self.err = error.TestUnexpectedResult;
                    return;
                }
                self.read += count;
            }
        }
    };
    var shared = Shared{
        .io = io,
        .stream = streams[1],
        .out = first_wire,
    };
    const reader = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var reader_joined = false;
    defer if (!reader_joined) {
        connection.stream.shutdown(io, .both) catch {};
        reader.join();
    };
    try connection.sendBinaryWithTimeout(
        payload,
        &progress,
        .fromSeconds(3),
    );
    reader.join();
    reader_joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(progress.frame_committed);
    try std.testing.expect(!connection.compression_send.previewPending());

    var first = try websocket.parseFrameOptions(allocator, first_wire, .{
        .expect_mask = .masked,
        .allow_rsv1 = true,
    });
    defer first.deinit(allocator);
    try std.testing.expect(first.header.rsv1);
    var decoder = try websocket.DecompressionContext.init(allocator, 15);
    defer decoder.deinit();
    const decoded = try allocator.alloc(u8, payload.len);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(
        u8,
        payload,
        try decoder.decompressToSlice(decoded, first.payload),
    );

    try connection.sendBinary(payload[payload.len - history_len ..]);
    const second_payload_len = connection.compression_send.payload.items.len;
    var header_storage: [websocket.max_frame_header_len]u8 = undefined;
    const second_header = try websocket.writeFrameHeaderForLengthInto(
        &header_storage,
        .binary,
        second_payload_len,
        .{ .mask_key = .{ 0, 0, 0, 0 }, .rsv1 = true },
    );
    const second_wire = try allocator.alloc(
        u8,
        second_header.len + second_payload_len,
    );
    defer allocator.free(second_wire);
    try readExact(io, streams[1], second_wire);
    var second = try websocket.parseFrameOptions(allocator, second_wire, .{
        .expect_mask = .masked,
        .allow_rsv1 = true,
    });
    defer second.deinit(allocator);
    try std.testing.expect(second.header.rsv1);
    try std.testing.expectError(
        error.InvalidFrame,
        websocket.decompressMessage(
            allocator,
            second.payload,
            history_len,
        ),
    );
    var second_decoded: [history_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        payload[payload.len - history_len ..],
        try decoder.decompressToSlice(&second_decoded, second.payload),
    );
}

test "HTTP1 bounded in-place send masks once and resumes exact suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);
    var payload = [_]u8{ 4, 8, 15, 16, 23, 42, 99, 7, 5, 3, 1 };
    const original = payload;
    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        connection.sendBinaryInPlaceWithDeadline(
            &payload,
            &progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(original, payload);
    try runtime.testing.beginPendingInPlace(&connection, &payload);
    try std.testing.expect(!std.mem.eql(u8, &original, &payload));
    const pending = runtime.testing.pendingMessageProgress(&connection) orelse
        return error.TestUnexpectedResult;
    var wire: [64]u8 = undefined;
    const split = 7;
    const prefix = try runtime.testing.copyPendingInPlaceSuffix(
        &connection,
        &payload,
        0,
        wire[0..split],
    );
    const suffix = try runtime.testing.copyPendingInPlaceSuffix(
        &connection,
        &payload,
        split,
        wire[split..pending.total_bytes],
    );
    try std.testing.expectEqual(split, prefix.len);
    try std.testing.expectEqual(pending.total_bytes - split, suffix.len);
    var parsed = try websocket.parseFrameOptions(
        allocator,
        wire[0..pending.total_bytes],
        .{
            .expect_mask = .masked,
        },
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &original, parsed.payload);
}

test "HTTP1 fragmented deadline resumes exact multi-frame suffix" {
    if (comptime @import("builtin").os.tag == .windows) return;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        streams[0].socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    const payload = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index *% 29 +% 7);
    const fragments = [_][]const u8{
        payload[0..131_071],
        payload[131_071..524_289],
        payload[524_289..],
    };
    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );

    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        connection.sendFragmentedWithTimeout(
            .binary,
            &fragments,
            &progress,
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    const committed = progress.committed_bytes;
    const different = [_][]const u8{payload};
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendFragmentedWithTimeout(
            .binary,
            &different,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(committed, progress.committed_bytes);

    const wire = try allocator.alloc(u8, progress.total_bytes);
    defer allocator.free(wire);
    const Shared = struct {
        io: std.Io,
        stream: std.Io.net.Stream,
        out: []u8,
        read: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            while (self.read < self.out.len) {
                var parts = [_][]u8{self.out[self.read..]};
                const count = self.io.vtable.netRead(
                    self.io.userdata,
                    self.stream.socket.handle,
                    &parts,
                ) catch |err| {
                    self.err = err;
                    return;
                };
                if (count == 0) {
                    self.err = error.TestUnexpectedResult;
                    return;
                }
                self.read += count;
            }
        }
    };
    var shared = Shared{ .io = io, .stream = streams[1], .out = wire };
    const reader = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try connection.sendFragmentedWithTimeout(
        .binary,
        &fragments,
        &progress,
        .fromSeconds(3),
    );
    reader.join();
    if (shared.err) |err| return err;
    try std.testing.expect(progress.frame_committed);

    var offset: usize = 0;
    for (fragments, 0..) |expected, index| {
        var frame = try websocket.parseFrameOptions(allocator, wire[offset..], .{
            .expect_mask = .masked,
        });
        defer frame.deinit(allocator);
        try std.testing.expectEqual(
            if (index == 0) websocket.Opcode.binary else .continuation,
            frame.header.opcode,
        );
        try std.testing.expectEqual(index + 1 == fragments.len, frame.header.fin);
        try std.testing.expectEqualSlices(u8, expected, frame.payload);
        offset += frame.consumed;
    }
    try std.testing.expectEqual(wire.len, offset);
}

test "HTTP1 bounded WSS send resumes retained ciphertext record" {
    if (comptime @import("builtin").os.tag == .windows) return;
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
    const payload = try allocator.alloc(u8, 2 * 1024 * 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);

    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_bytes = payload.len,
                .max_message_bytes = payload.len,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        release: std.Io.Event = .unset,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            try self.release.wait(self.server.io);
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer message.deinit(connection.allocator);
            try std.testing.expectEqualStrings(
                self.payload,
                message.payload,
            );
        }
    };
    var shared = Shared{ .server = &server, .payload = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .host = "localhost",
            .limits = .{
                .max_frame_bytes = payload.len,
                .max_message_bytes = payload.len,
            },
        },
        .{ .verify_host = false },
    );
    defer client.close();
    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        client.stream.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );

    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    shared.release.set(io);
    try client.sendBinaryWithTimeout(
        payload,
        &progress,
        .fromSeconds(5),
    );
    try std.testing.expect(progress.frame_committed);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP1 bounded vail WSS send resumes retained ciphertext record" {
    if (comptime @import("builtin").os.tag == .windows) return;
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
    const public_key = key_pair.public_key.toUncompressedSec1();
    const payload = try allocator.alloc(u8, 2 * 1024 * 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);

    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_bytes = payload.len,
                .max_message_bytes = payload.len,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        release: std.Io.Event = .unset,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            try self.release.wait(self.server.io);
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer message.deinit(connection.allocator);
            try std.testing.expectEqualStrings(
                self.payload,
                message.payload,
            );
        }
    };
    var shared = Shared{ .server = &server, .payload = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .host = "localhost",
            .vail_tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
            .limits = .{
                .max_frame_bytes = payload.len,
                .max_message_bytes = payload.len,
            },
        },
        .{ .verify_host = false },
    );
    defer client.close();
    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        client.stream.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expectError(
        error.WriteInProgress,
        client.updateTrafficKeys(false),
    );
    shared.release.set(io);
    try client.sendBinaryWithTimeout(
        payload,
        &progress,
        .fromSeconds(5),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(
        progress.total_bytes,
        progress.committed_bytes,
    );
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
    try std.testing.expect(!connection.close_sent.load(.acquire));

    var h2 = runtime.H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        h2.closeWithTimeout(null, .zero),
    );
    try std.testing.expect(!h2.close_sent.load(.acquire));
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

fn readExact(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []u8,
) !void {
    var read: usize = 0;
    while (read < bytes.len) {
        var parts = [_][]u8{bytes[read..]};
        const count = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &parts,
        );
        if (count == 0) return error.SocketUnconnected;
        read += count;
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

test "WebSocket RFC 8441 close deadline resumes a partially sent frame" {
    const allocator = std.testing.allocator;
    const reason = "0123456789" ** 12;
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
        timeout_done: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer ws.close();
            try self.timeout_done.wait(self.server.io);

            var encoded: [256]u8 = undefined;
            var encoded_len: usize = 0;
            var first = try ws.tunnel.readWithTimeout(.fromSeconds(2));
            defer first.deinit(self.server.allocator);
            try std.testing.expect(!first.end_stream);
            try std.testing.expectEqual(@as(usize, 5), first.data.len);
            @memcpy(encoded[0..first.data.len], first.data);
            encoded_len += first.data.len;
            try h2.releaseReceivedCapacity(
                ws.tunnel.stream_id,
                first.data.len,
            );
            self.credit_sent.set(self.server.io);

            var ended = false;
            while (!ended) {
                var data = try ws.tunnel.readWithTimeout(.fromSeconds(2));
                defer data.deinit(self.server.allocator);
                try std.testing.expect(
                    data.data.len <= encoded.len - encoded_len,
                );
                @memcpy(encoded[encoded_len..][0..data.data.len], data.data);
                encoded_len += data.data.len;
                ended = data.end_stream;
                if (data.data.len != 0) {
                    try h2.releaseReceivedCapacity(
                        ws.tunnel.stream_id,
                        data.data.len,
                    );
                }
            }

            var close = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[0..encoded_len],
                .{ .expect_mask = .masked },
            );
            defer close.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            try std.testing.expectEqual(encoded_len, close.consumed);
            const detail = (try websocket.parseClosePayload(close.payload)) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                detail.code,
            );
            try std.testing.expectEqualStrings(reason, detail.reason);
            try ws.sendClose(.normal_closure, reason);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timeout_done.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{ .authority = "localhost" },
    );
    defer client.close();
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;

    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(
            .{ .code = .normal_closure, .reason = reason },
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expect(!client.close_sent.load(.acquire));
    try std.testing.expect(
        runtime.testing.pendingH2CloseProgress(&client) == null,
    );

    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(
            .{ .code = .normal_closure, .reason = reason },
            .fromMilliseconds(80),
        ),
    );
    const progress = runtime.testing.pendingH2CloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 5), progress.committed);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(!client.close_sent.load(.acquire));
    try std.testing.expectError(
        error.WriteInProgress,
        client.closeWithTimeout(
            .{ .code = .going_away, .reason = "different" },
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        progress,
        runtime.testing.pendingH2CloseProgress(&client).?,
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.updateTrafficKeys(false),
    );

    shared.timeout_done.set(io);
    try shared.credit_sent.wait(io);
    var closed = try client.closeWithTimeout(
        .{ .code = .normal_closure, .reason = reason },
        .fromSeconds(2),
    );
    defer closed.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings(reason, closed.closed.?.reason);
    try std.testing.expect(client.close_sent.load(.acquire));
    try std.testing.expect(
        runtime.testing.pendingH2CloseProgress(&client) == null,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 ping deadline resumes a partially sent frame" {
    const allocator = std.testing.allocator;
    const payload = "0123456789" ** 12;
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
        timeout_done: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer ws.close();
            try self.timeout_done.wait(self.server.io);

            var encoded: [256]u8 = undefined;
            var encoded_len: usize = 0;
            var first = try ws.tunnel.readWithTimeout(.fromSeconds(2));
            defer first.deinit(self.server.allocator);
            try std.testing.expect(!first.end_stream);
            try std.testing.expectEqual(@as(usize, 5), first.data.len);
            @memcpy(encoded[0..first.data.len], first.data);
            encoded_len += first.data.len;
            try h2.releaseReceivedCapacity(
                ws.tunnel.stream_id,
                first.data.len,
            );
            self.credit_sent.set(self.server.io);

            while (encoded_len < payload.len + 6) {
                var data = try ws.tunnel.readWithTimeout(.fromSeconds(2));
                defer data.deinit(self.server.allocator);
                try std.testing.expect(!data.end_stream);
                try std.testing.expect(
                    data.data.len <= encoded.len - encoded_len,
                );
                @memcpy(encoded[encoded_len..][0..data.data.len], data.data);
                encoded_len += data.data.len;
                if (data.data.len != 0) {
                    try h2.releaseReceivedCapacity(
                        ws.tunnel.stream_id,
                        data.data.len,
                    );
                }
            }

            var ping = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[0..encoded_len],
                .{ .expect_mask = .masked },
            );
            defer ping.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqual(encoded_len, ping.consumed);
            try std.testing.expectEqualStrings(payload, ping.payload);
            try ws.sendPong(payload);

            var message = try ws.receiveMessageWithTimeout(.fromSeconds(2));
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("after-ping", message.payload);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timeout_done.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{ .authority = "localhost" },
    );
    defer client.close();
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;

    try std.testing.expectError(
        error.Timeout,
        client.pingWithDeadline(payload, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expect(
        runtime.testing.pendingH2PingProgress(&client) == null,
    );

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(payload, .fromMilliseconds(80)),
    );
    const progress = runtime.testing.pendingH2PingProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 5), progress.committed);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expectError(
        error.WriteInProgress,
        client.pingWithTimeout("different", .fromSeconds(1)),
    );
    try std.testing.expectEqual(
        progress,
        runtime.testing.pendingH2PingProgress(&client).?,
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.updateTrafficKeys(false),
    );

    shared.timeout_done.set(io);
    try shared.credit_sent.wait(io);
    var pong = try client.pingWithTimeout(
        payload,
        .fromSeconds(2),
    );
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    try std.testing.expect(
        runtime.testing.pendingH2PingProgress(&client) == null,
    );
    http2_runtime.testing.setSendConnectionWindow(&h2, 1024);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 1024;
    try client.sendText("after-ping");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 Pong deadline resumes a partially sent frame" {
    const allocator = std.testing.allocator;
    const payload = "0123456789" ** 12;
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
        timed_out: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer ws.close();
            try self.timed_out.wait(self.server.io);
            var encoded: [256]u8 = undefined;
            var encoded_len: usize = 0;
            var first = try ws.tunnel.readWithTimeout(.fromSeconds(2));
            defer first.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(usize, 5), first.data.len);
            @memcpy(encoded[0..first.data.len], first.data);
            encoded_len += first.data.len;
            try h2.releaseReceivedCapacity(
                ws.tunnel.stream_id,
                first.data.len,
            );
            self.credit_sent.set(self.server.io);
            while (encoded_len < payload.len + 6) {
                var data = try ws.tunnel.readWithTimeout(.fromSeconds(2));
                defer data.deinit(self.server.allocator);
                @memcpy(encoded[encoded_len..][0..data.data.len], data.data);
                encoded_len += data.data.len;
                if (data.data.len != 0) {
                    try h2.releaseReceivedCapacity(
                        ws.tunnel.stream_id,
                        data.data.len,
                    );
                }
            }
            var pong = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[0..encoded_len],
                .{ .expect_mask = .masked },
            );
            defer pong.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings(payload, pong.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timed_out.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{ .authority = "localhost" },
    );
    defer client.close();
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;

    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendPongWithTimeout(
            payload,
            &progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendPongWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    shared.timed_out.set(io);
    try shared.credit_sent.wait(io);
    try client.sendPongWithTimeout(payload, &progress, .fromSeconds(2));
    try std.testing.expect(progress.frame_committed);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 bounded in-place send masks once" {
    const allocator = std.testing.allocator;
    const plain = "0123456789" ** 12;
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
        timed_out: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer ws.close();
            try self.timed_out.wait(self.server.io);
            var encoded: [256]u8 = undefined;
            var encoded_len: usize = 0;
            var first = try ws.tunnel.readWithTimeout(.fromSeconds(2));
            defer first.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(usize, 5), first.data.len);
            @memcpy(encoded[0..first.data.len], first.data);
            encoded_len += first.data.len;
            try h2.releaseReceivedCapacity(ws.tunnel.stream_id, 1024);
            self.credit_sent.set(self.server.io);
            while (encoded_len < plain.len + 6) {
                var data = try ws.tunnel.readWithTimeout(.fromSeconds(2));
                defer data.deinit(self.server.allocator);
                @memcpy(encoded[encoded_len..][0..data.data.len], data.data);
                encoded_len += data.data.len;
                if (data.data.len != 0) {
                    try h2.releaseReceivedCapacity(
                        ws.tunnel.stream_id,
                        data.data.len,
                    );
                }
            }
            var frame = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[0..encoded_len],
                .{ .expect_mask = .masked },
            );
            defer frame.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
            try std.testing.expectEqualStrings(plain, frame.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timed_out.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{ .authority = "localhost" },
    );
    defer client.close();
    var payload: [plain.len]u8 = undefined;
    @memcpy(&payload, plain);
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryInPlaceWithDeadline(&payload, &progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqualStrings(plain, &payload);
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryInPlaceWithTimeout(
            &payload,
            &progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    try std.testing.expect(!std.mem.eql(u8, plain, &payload));
    const committed = progress.committed_bytes;
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinaryInPlaceWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(committed, progress.committed_bytes);
    shared.timed_out.set(io);
    try shared.credit_sent.wait(io);
    try client.sendBinaryInPlaceWithTimeout(
        &payload,
        &progress,
        .fromSeconds(2),
    );
    try std.testing.expect(progress.frame_committed);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket RFC 8441 bounded auto Pong resumes and returns one Ping" {
    const allocator = std.testing.allocator;
    const payload = "automatic-pong-" ** 8;
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
        timed_out: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        close_requested: std.Io.Event = .unset,
        close_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer ws.close();
            try ws.sendPing(payload);
            try self.timed_out.wait(self.server.io);

            var encoded: [256]u8 = undefined;
            var encoded_len: usize = 0;
            while (encoded_len < payload.len + 6) {
                var data = try ws.tunnel.readWithTimeout(.fromSeconds(2));
                defer data.deinit(self.server.allocator);
                try std.testing.expect(!data.end_stream);
                try std.testing.expect(
                    data.data.len <= encoded.len - encoded_len,
                );
                @memcpy(encoded[encoded_len..][0..data.data.len], data.data);
                encoded_len += data.data.len;
                if (data.data.len != 0) {
                    try h2.releaseReceivedCapacity(
                        ws.tunnel.stream_id,
                        data.data.len,
                    );
                    self.credit_sent.set(self.server.io);
                }
            }

            var pong = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[0..encoded_len],
                .{ .expect_mask = .masked },
            );
            defer pong.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqual(encoded_len, pong.consumed);
            try std.testing.expectEqualStrings(payload, pong.payload);
            try ws.sendText("after-auto-pong");
            try self.close_requested.wait(self.server.io);
            try ws.sendClose(.going_away, "restart");
            self.close_sent.set(self.server.io);
            var close = try ws.receiveFrameWithTimeout(.fromSeconds(2));
            defer close.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timed_out.set(io);
        shared.close_requested.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{ .authority = "localhost" },
    );
    defer client.close();
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;

    try std.testing.expectError(
        error.Timeout,
        client.receiveFrameAutoWithTimeout(.fromMilliseconds(80)),
    );
    const progress = runtime.testing
        .pendingH2AutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, progress.opcode);
    try std.testing.expectEqual(@as(usize, 5), progress.committed);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(progress.retains_frame);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );

    shared.timed_out.set(io);
    try shared.credit_sent.wait(io);
    var ping = try client.receiveFrameAutoWithTimeout(.fromSeconds(2));
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings(payload, ping.payload);
    try std.testing.expect(
        runtime.testing.pendingH2AutomaticControlProgress(&client) == null,
    );
    var message = try client.receiveMessageWithTimeout(.fromSeconds(2));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("after-auto-pong", message.payload);

    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;
    shared.close_requested.set(io);
    try shared.close_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveFrameAutoWithTimeout(.fromMilliseconds(80)),
    );
    const close_progress = runtime.testing
        .pendingH2AutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.close, close_progress.opcode);
    try std.testing.expectEqual(@as(usize, 5), close_progress.committed);
    try std.testing.expect(close_progress.committed < close_progress.total);
    try std.testing.expect(close_progress.retains_frame);
    try std.testing.expect(!client.close_sent.load(.acquire));

    http2_runtime.testing.setSendConnectionWindow(&h2, 1024);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 1024;
    var close = try client.receiveFrameAutoWithTimeout(.fromSeconds(2));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    const detail = (try websocket.parseClosePayload(close.payload)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.CloseCode.going_away, detail.code);
    try std.testing.expectEqualStrings("restart", detail.reason);
    try std.testing.expect(client.close_sent.load(.acquire));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 bounded auto Pong retains Ping after timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
    const payload = "automatic-pong";
    var encoded_ping: [websocket.max_frame_header_len + 125]u8 = undefined;
    const ping_bytes = try websocket.writeFrameInto(
        &encoded_ping,
        .ping,
        payload,
        .{},
    );
    try runtime.testing.bufferInitial(&connection, ping_bytes);

    try std.testing.expectError(
        error.Timeout,
        runtime.testing.receiveFrameAutoInternal(&connection, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    const progress = runtime.testing
        .pendingAutomaticControlProgress(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, progress.opcode);
    try std.testing.expectEqual(@as(usize, 0), progress.committed);
    try std.testing.expect(progress.retains_frame);
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendText("must-not-interleave"),
    );

    var ping = try connection.receiveFrameAutoWithTimeout(.fromSeconds(1));
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings(payload, ping.payload);
    try std.testing.expect(
        runtime.testing.pendingAutomaticControlProgress(&connection) == null,
    );

    var wire: [websocket.max_frame_header_len + 125]u8 = undefined;
    const wire_len = progress.total;
    try readExact(io, streams[1], wire[0..wire_len]);
    var pong = try websocket.parseFrameOptions(
        allocator,
        wire[0..wire_len],
        .{ .expect_mask = .masked },
    );
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings(payload, pong.payload);
}

test "WebSocket HTTP1 message receive resumes pending auto Pong" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
    var encoded: [2 * (websocket.max_frame_header_len + 125)]u8 = undefined;
    const ping = try websocket.writeFrameInto(
        &encoded,
        .ping,
        "hidden",
        .{},
    );
    const message = try websocket.writeFrameInto(
        encoded[ping.len..],
        .text,
        "visible",
        .{},
    );
    try runtime.testing.bufferInitial(
        &connection,
        encoded[0 .. ping.len + message.len],
    );

    try std.testing.expectError(
        error.Timeout,
        runtime.testing.receiveMessageInternal(&connection, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    const progress = runtime.testing
        .pendingAutomaticControlProgress(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, progress.opcode);
    try std.testing.expect(!progress.retains_frame);

    var received = try connection.receiveMessageWithTimeout(
        .fromSeconds(1),
    );
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings("visible", received.payload);

    var wire: [websocket.max_frame_header_len + 125]u8 = undefined;
    try readExact(io, streams[1], wire[0..progress.total]);
    var pong = try websocket.parseFrameOptions(
        allocator,
        wire[0..progress.total],
        .{ .expect_mask = .masked },
    );
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("hidden", pong.payload);
}

test "WebSocket HTTP1 queued auto Pong follows bounded message suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[1].close(io);

    const payload = "preceding-message";
    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{},
    );
    defer connection.close();
    try runtime.testing.beginPendingMessage(
        &connection,
        .text,
        payload,
    );
    try runtime.testing.queueAutomaticControl(
        &connection,
        .pong,
        "queued",
    );

    var progress: runtime.MessageWriteProgress = .{};
    try connection.sendTextWithTimeout(
        payload,
        &progress,
        .fromSeconds(1),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expect(
        runtime.testing.pendingAutomaticControlProgress(&connection) != null,
    );
    try std.testing.expectError(
        error.WriteInProgress,
        connection.sendText("must-not-overtake"),
    );

    var encoded_message: [64]u8 = undefined;
    try readExact(
        io,
        streams[1],
        encoded_message[0..progress.total_bytes],
    );
    var parsed_message = try websocket.parseFrameOptions(
        allocator,
        encoded_message[0..progress.total_bytes],
        .{ .expect_mask = .masked },
    );
    defer parsed_message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, parsed_message.header.opcode);
    try std.testing.expectEqualStrings(payload, parsed_message.payload);

    try std.testing.expectError(
        error.Timeout,
        runtime.testing.receiveMessageInternal(&connection, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    const auto_progress = runtime.testing
        .pendingAutomaticControlProgress(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), auto_progress.committed);
}

test "WebSocket HTTP1 Pong deadline keeps one mask across suffixes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const streams = try testNetworkStreams(io);
    defer streams[0].close(io);
    defer streams[1].close(io);

    const payload = "stable-pong";
    var connection = runtime.testing.initDirectConnection(
        allocator,
        io,
        streams[0],
        .client,
        .{},
    );
    try runtime.testing.beginPendingMessage(
        &connection,
        .pong,
        payload,
    );
    const pending = runtime.testing.pendingMessageProgress(&connection) orelse
        return error.TestUnexpectedResult;
    const encoded = try allocator.alloc(u8, pending.total_bytes);
    defer allocator.free(encoded);
    const split = 7;
    const prefix = try runtime.testing.copyPendingMessageChunk(
        &connection,
        payload,
        0,
        encoded[0..split],
    );
    const suffix = try runtime.testing.copyPendingMessageChunk(
        &connection,
        payload,
        split,
        encoded[split..],
    );
    try std.testing.expectEqual(split, prefix.len);
    try std.testing.expectEqual(encoded.len - split, suffix.len);
    var parsed = try websocket.parseFrameOptions(allocator, encoded, .{
        .expect_mask = .masked,
    });
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, parsed.header.opcode);
    try std.testing.expectEqualStrings(payload, parsed.payload);
}

test "WebSocket RFC 8441 queued auto Pong follows bounded message suffix" {
    const allocator = std.testing.allocator;
    const payload = "0123456789" ** 12;
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
        resume_send: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer ws.close();
            try self.resume_send.wait(self.server.io);

            var encoded: [256]u8 = undefined;
            var encoded_len: usize = 0;
            var first = try ws.tunnel.readWithTimeout(.fromSeconds(2));
            defer first.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(usize, 5), first.data.len);
            @memcpy(encoded[0..first.data.len], first.data);
            encoded_len += first.data.len;
            try h2.releaseReceivedCapacity(
                ws.tunnel.stream_id,
                first.data.len,
            );
            self.credit_sent.set(self.server.io);

            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const message_header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                .text,
                payload.len,
                .{ .mask_key = .{ 0, 0, 0, 0 } },
            );
            const message_total = payload.len + message_header.len;
            const pong_total = "queued".len + 6;
            while (encoded_len < message_total + pong_total) {
                var data = try ws.tunnel.readWithTimeout(.fromSeconds(2));
                defer data.deinit(self.server.allocator);
                @memcpy(encoded[encoded_len..][0..data.data.len], data.data);
                encoded_len += data.data.len;
                if (data.data.len != 0) {
                    try h2.releaseReceivedCapacity(
                        ws.tunnel.stream_id,
                        data.data.len,
                    );
                }
            }
            var message = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[0..message_total],
                .{ .expect_mask = .masked },
            );
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.header.opcode);
            try std.testing.expectEqualStrings(payload, message.payload);
            var pong = try websocket.parseFrameOptions(
                self.server.allocator,
                encoded[message_total..encoded_len],
                .{ .expect_mask = .masked },
            );
            defer pong.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings("queued", pong.payload);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(250),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.resume_send.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{ .authority = "localhost" },
    );
    defer client.close();
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;
    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendTextWithTimeout(
            payload,
            &progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    try runtime.testing.queueH2AutomaticControl(
        &client,
        .pong,
        "queued",
    );

    shared.resume_send.set(io);
    try shared.credit_sent.wait(io);
    try client.sendTextWithTimeout(payload, &progress, .fromSeconds(2));
    try std.testing.expect(progress.frame_committed);
    const auto_progress = runtime.testing
        .pendingH2AutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), auto_progress.committed);
    http2_runtime.testing.setSendConnectionWindow(&h2, 1024);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 1024;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageWithTimeout(.fromMilliseconds(100)),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 bounded automatic Close retains peer frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
    var close_payload_storage: [125]u8 = undefined;
    const close_payload = try websocket.writeClosePayloadInto(
        &close_payload_storage,
        .{ .code = .going_away, .reason = "restart" },
    );
    var encoded_close: [websocket.max_frame_header_len + 125]u8 = undefined;
    const close_bytes = try websocket.writeFrameInto(
        &encoded_close,
        .close,
        close_payload,
        .{},
    );
    try runtime.testing.bufferInitial(&connection, close_bytes);

    try std.testing.expectError(
        error.Timeout,
        runtime.testing.receiveFrameAutoInternal(&connection, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    const progress = runtime.testing
        .pendingAutomaticControlProgress(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.close, progress.opcode);
    try std.testing.expect(progress.retains_frame);
    try std.testing.expect(!connection.close_sent.load(.acquire));

    var close = try connection.receiveFrameAutoWithTimeout(.fromSeconds(1));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    const detail = (try websocket.parseClosePayload(close.payload)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.CloseCode.going_away, detail.code);
    try std.testing.expectEqualStrings("restart", detail.reason);
    try std.testing.expect(connection.close_sent.load(.acquire));

    var wire: [websocket.max_frame_header_len + 125]u8 = undefined;
    try readExact(io, streams[1], wire[0..progress.total]);
    var echoed = try websocket.parseFrameOptions(
        allocator,
        wire[0..progress.total],
        .{ .expect_mask = .masked },
    );
    defer echoed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, close_payload, echoed.payload);
}

test "WebSocket RFC 8441 message deadline resumes one masked frame" {
    const allocator = std.testing.allocator;
    const payload = "0123456789" ** 12;
    const payload_parts = [_][]const u8{
        payload[0..31],
        &.{},
        payload[31..79],
        payload[79..],
    };
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
        timeout_done: std.Io.Event = .unset,
        credit_sent: std.Io.Event = .unset,
        slices_timeout_done: std.Io.Event = .unset,
        slices_credit_sent: std.Io.Event = .unset,
        fragmented_timeout_done: std.Io.Event = .unset,
        fragmented_credit_sent: std.Io.Event = .unset,
        client_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.credit_sent.set(self.server.io);
                self.slices_credit_sent.set(self.server.io);
                self.fragmented_credit_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try runtime.H2Server.accept(
                self.server.allocator,
                &h2,
                .{
                    .enable_permessage_deflate = true,
                    .allow_context_takeover = true,
                    .compression_threshold = 1,
                    .limits = .{
                        .max_frame_bytes = payload.len,
                        .max_message_bytes = payload.len,
                    },
                },
            );
            defer ws.close();
            try std.testing.expect(ws.compression_send_context_takeover);
            try std.testing.expect(ws.compression_receive_context_takeover);
            try self.timeout_done.wait(self.server.io);

            var first = try ws.tunnel.readWithTimeout(.fromSeconds(2));
            defer first.deinit(self.server.allocator);
            try std.testing.expect(!first.end_stream);
            try std.testing.expectEqual(@as(usize, 5), first.data.len);
            try ws.inbuf.appendSlice(self.server.allocator, first.data);
            try h2.releaseReceivedCapacity(
                ws.tunnel.stream_id,
                1024,
            );
            self.credit_sent.set(self.server.io);

            var message = try ws.receiveMessageWithTimeout(
                .fromSeconds(2),
            );
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expect(message.was_compressed);
            try std.testing.expectEqualStrings(payload, message.payload);

            try self.slices_timeout_done.wait(self.server.io);
            var slices_first = try ws.tunnel.readWithTimeout(
                .fromSeconds(2),
            );
            defer slices_first.deinit(self.server.allocator);
            try std.testing.expect(!slices_first.end_stream);
            try std.testing.expectEqual(@as(usize, 5), slices_first.data.len);
            try ws.inbuf.appendSlice(
                self.server.allocator,
                slices_first.data,
            );
            try h2.releaseReceivedCapacity(ws.tunnel.stream_id, 1024);
            self.slices_credit_sent.set(self.server.io);

            var slices_message = try ws.receiveMessageWithTimeout(
                .fromSeconds(2),
            );
            defer slices_message.deinit(self.server.allocator);
            try std.testing.expectEqual(
                websocket.Opcode.binary,
                slices_message.opcode,
            );
            try std.testing.expect(slices_message.was_compressed);
            try std.testing.expectEqualStrings(payload, slices_message.payload);

            try self.fragmented_timeout_done.wait(self.server.io);
            var fragmented_first = try ws.tunnel.readWithTimeout(
                .fromSeconds(2),
            );
            defer fragmented_first.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(usize, 5), fragmented_first.data.len);
            try ws.inbuf.appendSlice(
                self.server.allocator,
                fragmented_first.data,
            );
            try h2.releaseReceivedCapacity(ws.tunnel.stream_id, 1024);
            self.fragmented_credit_sent.set(self.server.io);
            var fragmented = try ws.receiveMessageWithTimeout(
                .fromSeconds(2),
            );
            defer fragmented.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, fragmented.opcode);
            try std.testing.expect(fragmented.was_compressed);
            try std.testing.expectEqualStrings(payload, fragmented.payload);
            const response_parts = [_][]const u8{
                payload[0..29],
                &.{},
                payload[29..83],
                payload[83..],
            };
            var response_progress: runtime.MessageWriteProgress = .{};
            try ws.sendBinarySlicesWithTimeout(
                &response_parts,
                &response_progress,
                .fromSeconds(2),
            );
            try std.testing.expect(response_progress.frame_committed);
            try self.client_done.wait(self.server.io);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.timeout_done.set(io);
        shared.slices_timeout_done.set(io);
        shared.slices_credit_sent.set(io);
        shared.fragmented_timeout_done.set(io);
        shared.fragmented_credit_sent.set(io);
        shared.client_done.set(io);
        thread.join();
    };

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2.close();
    var client = try runtime.H2Client.open(
        allocator,
        &h2,
        .{
            .authority = "localhost",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 1,
            .limits = .{
                .max_frame_bytes = payload.len,
                .max_message_bytes = payload.len,
            },
        },
    );
    defer client.close();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);
    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;

    var invalid_progress: runtime.MessageWriteProgress = .{
        .committed_bytes = 99,
        .total_bytes = 99,
        .frame_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithDeadline(payload, &invalid_progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(
        runtime.MessageWriteProgress{},
        invalid_progress,
    );

    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithTimeout(
            payload,
            &progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinaryWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    const pending = runtime.testing.pendingH2MessageProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(pending.committed_bytes, progress.committed_bytes);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromSeconds(1)),
    );

    shared.timeout_done.set(io);
    try shared.credit_sent.wait(io);
    try client.sendBinaryWithTimeout(payload, &progress, .fromSeconds(2));
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(!client.compression_send.previewPending());
    try std.testing.expect(
        runtime.testing.pendingH2MessageProgress(&client) == null,
    );

    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;
    progress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinarySlicesWithTimeout(
            &payload_parts,
            &progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    const different_parts = [_][]const u8{payload};
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinarySlicesWithTimeout(
            &different_parts,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    shared.slices_timeout_done.set(io);
    try shared.slices_credit_sent.wait(io);
    try client.sendBinarySlicesWithDeadline(
        &payload_parts,
        &progress,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(!client.compression_send.previewPending());
    try std.testing.expect(
        runtime.testing.pendingH2MessageProgress(&client) == null,
    );

    http2_runtime.testing.setSendConnectionWindow(&h2, 5);
    (try http2_runtime.testing.sendStreamWindow(
        &h2,
        client.tunnel.stream_id,
    )).value = 5;
    progress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendFragmentedWithTimeout(
            .binary,
            &payload_parts,
            &progress,
            .fromMilliseconds(80),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), progress.committed_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendFragmentedWithTimeout(
            .binary,
            &different_parts,
            &progress,
            .fromSeconds(1),
        ),
    );
    shared.fragmented_timeout_done.set(io);
    try shared.fragmented_credit_sent.wait(io);
    try client.sendFragmentedWithTimeout(
        .binary,
        &payload_parts,
        &progress,
        .fromSeconds(2),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(!client.compression_send.previewPending());
    var response = try client.receiveMessageWithTimeout(.fromSeconds(2));
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
    try std.testing.expect(response.was_compressed);
    try std.testing.expectEqualStrings(payload, response.payload);
    shared.client_done.set(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket generic message timeout validates and commits one bounded frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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

    var progress: runtime.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.InvalidFrame,
        connection.sendMessageWithTimeout(
            .ping,
            "control",
            &progress,
            .fromMilliseconds(50),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expectError(
        error.Timeout,
        connection.sendMessageWithTimeout(.binary, "expired", &progress, .zero),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);

    try connection.sendMessageWithTimeout(
        .binary,
        "generic",
        &progress,
        .fromMilliseconds(500),
    );
    try std.testing.expect(progress.frame_committed);
    const expected_len = 2 + 4 + "generic".len;
    try std.testing.expectEqual(@as(usize, expected_len), progress.total_bytes);

    // The peer observes exactly one masked binary frame with the payload.
    var frame_bytes: [64]u8 = undefined;
    var reader_buffer: [64]u8 = undefined;
    var reader = streams[1].reader(io, &reader_buffer);
    try reader.interface.readSliceAll(frame_bytes[0..expected_len]);
    var parsed = try websocket.parseFrameOptions(
        allocator,
        frame_bytes[0..expected_len],
        .{ .expect_mask = .masked },
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, parsed.header.opcode);
    try std.testing.expectEqualStrings("generic", parsed.payload);
}

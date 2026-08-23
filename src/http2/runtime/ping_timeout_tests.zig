const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;
const flag_ack: u8 = 0x1;

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

fn writeFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        },
        .payload = payload,
    }).write(&encoded, allocator);
    try writeAll(io, stream, encoded.items);
}

fn readPeerPing(connection: *runtime.Connection) ![8]u8 {
    while (true) {
        var frame = try runtime.testing.readOwnedFrame(connection);
        defer frame.deinit(connection.allocator);
        if (frame.frame.header.frame_type == .ping) {
            if ((frame.frame.header.flags & flag_ack) != 0) continue;
            return (try http2.PingPayload.parse(frame.frame)).data;
        }
        if (try runtime.testing.handleConnectionFrame(
            connection,
            frame.frame,
        )) continue;
        return error.UnexpectedFrame;
    }
}

test "HTTP/2 bounded PING times out when the peer stays silent" {
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            // Keep TCP open without pumping frames. The probe must expire
            // independently rather than relying on peer closure.
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

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(
            .{ 1, 2, 3, 4, 5, 6, 7, 8 },
            .fromMilliseconds(75),
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING uses one deadline across control frames" {
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

    const payload = [8]u8{ 1, 3, 3, 7, 9, 9, 4, 2 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try std.testing.expectEqualSlices(
                u8,
                &self.expected,
                &(try readPeerPing(&connection)),
            );

            // Neither a stale ACK nor useful connection credit extends the
            // caller's original 150 ms budget. A relative timeout restarted
            // after each frame would incorrectly accept the final ACK.
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .ping,
                flag_ack,
                0,
                &.{ 8, 8, 8, 8, 8, 8, 8, 8 },
            );
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .settings,
                0,
                0,
                &.{},
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            );
            try connection.sendWindowUpdate(0, 17);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            );
            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .ping,
                flag_ack,
                0,
                &self.expected,
            );
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(payload, .fromMilliseconds(150)),
    );
    try std.testing.expectEqual(
        @as(i64, 65_535 + 17),
        client.send_connection_window.value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING preserves interleaved response frames" {
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

    const payload = [8]u8{ 4, 8, 15, 16, 23, 42, 0, 1 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(request.stream_id, .{
                .body = "response-before-pong",
            });
            try std.testing.expectEqualSlices(
                u8,
                &self.expected,
                &(try connection.readPing()),
            );
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = "GET",
        .path = "/before-pong",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();

    const ack = try client.pingWithTimeout(
        payload,
        .fromSeconds(1),
    );
    try std.testing.expectEqualSlices(u8, &payload, &ack);
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings(
        "response-before-pong",
        response.body,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING preserves interleaved request frames" {
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

    const payload = [8]u8{ 9, 2, 6, 5, 3, 5, 8, 9 };
    const Shared = struct {
        server: *runtime.Server,
        expected: [8]u8,
        ready: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.ready.set(self.server.io);
            const ack = try connection.pingWithTimeout(
                self.expected,
                .fromSeconds(1),
            );
            try std.testing.expectEqualSlices(u8, &self.expected, &ack);
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/during-ping", request.path);
            try std.testing.expectEqualStrings("request-body", request.body);
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    try shared.ready.wait(io);
    var writer = try client.startRequest(.{
        .method = "POST",
        .path = "/during-ping",
        .body_length = "request-body".len,
    });
    defer writer.deinit();
    try writer.finishData("request-body");
    const observed = try client.readPing();
    try std.testing.expectEqualSlices(u8, &payload, &observed);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 bounded PING rejects non-positive durations before writing" {
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.pingWithTimeout(.{0} ** 8, .zero),
    );
}

test "HTTP/2 PING queue overflow preserves the consumed frame" {
    const allocator = std.testing.allocator;
    var connection = runtime.Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_pending_ping_frames = 1 },
    };
    defer runtime.testing.deinitPendingApplicationFrames(&connection);

    var first = runtime.OwnedFrame{
        .bytes = try allocator.dupe(u8, "first"),
        .frame = .{
            .header = .{
                .length = 5,
                .frame_type = .data,
                .flags = 0,
                .stream_id = 1,
            },
            .payload = undefined,
        },
    };
    first.frame.payload = first.bytes;
    try runtime.testing.queuePendingApplicationFrame(&connection, first);

    var overflow = runtime.OwnedFrame{
        .bytes = try allocator.dupe(u8, "second"),
        .frame = .{
            .header = .{
                .length = 6,
                .frame_type = .data,
                .flags = 0,
                .stream_id = 3,
            },
            .payload = undefined,
        },
    };
    overflow.frame.payload = overflow.bytes;
    try std.testing.expectError(
        error.MessageTooLarge,
        runtime.testing.queuePendingApplicationFrame(&connection, overflow),
    );
    runtime.testing.recoverPendingApplicationFrameAfterQueueFailure(
        &connection,
        overflow,
    );

    var observed_first = try runtime.testing.readOwnedFrame(&connection);
    defer observed_first.deinit(allocator);
    try std.testing.expectEqualStrings("first", observed_first.frame.payload);
    var observed_second = try runtime.testing.readOwnedFrame(&connection);
    defer observed_second.deinit(allocator);
    try std.testing.expectEqualStrings("second", observed_second.frame.payload);
}

test "HTTP/2 bounded PING succeeds over TLS" {
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

    const payload = [8]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
    const Shared = struct {
        server: *runtime.TlsServer,
        expected: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            const observed = connection.readPing() catch |err| {
                self.err = err;
                return;
            };
            if (!std.mem.eql(u8, &observed, &self.expected)) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server, .expected = payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    );
    defer client.close();
    const ack = try client.pingWithTimeout(
        payload,
        .fromSeconds(1),
    );
    try std.testing.expectEqualSlices(u8, &payload, &ack);

    thread.join();
    if (shared.err) |err| return err;
}

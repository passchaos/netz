const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const mqtt_tls = @import("../tls_runtime.zig");
const mqtt_ws = @import("../websocket_runtime.zig");
const tls_testing = @import("../../tls/testing.zig");
const websocket_runtime = @import("../../websocket/mod.zig").runtime;

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

fn acceptTcpClient(
    server: *runtime.Server,
    sleep_for: std.Io.Duration,
) !void {
    var accepted = try server.accept(.{});
    defer accepted.deinit(server.allocator);
    try accepted.connection.readPingReq();
    try std.Io.sleep(server.io, sleep_for, .awake);
}

test "MQTT client PING timeout bounds a silent TCP broker" {
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
            acceptTcpClient(
                self.server,
                .fromMilliseconds(200),
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
        .{ .client_id = "ping-timeout-tcp" },
    );
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(75)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client PING absolute deadline preserves queued publish" {
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
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.readPingReq();
            try accepted.connection.publish(
                "deadline/queued",
                "preserved",
                .{},
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(80),
                .awake,
            );
            try accepted.connection.writePingResp();
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
        .{ .client_id = "ping-absolute-deadline" },
    );
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithDeadline(.fromNow(
            io,
            .{ .raw = .fromMilliseconds(30), .clock = .awake },
        )),
    );
    var publish = try client.readClientPacketEventWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer publish.deinit(allocator);
    try std.testing.expect(publish == .publish);
    try std.testing.expectEqualStrings(
        "deadline/queued",
        publish.publish.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "preserved",
        publish.publish.publish.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT connection deadlines reject a non-awake clock before state changes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);
    var connection = runtime.Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var connection_open = true;
    defer if (connection_open) connection.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .real },
    );

    try std.testing.expectError(
        error.Timeout,
        connection.pingWithDeadline(deadline),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readBrokerEventWithDeadline(deadline),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.readClientPacketEventWithDeadline(deadline),
    );

    connection.close();
    connection_open = false;
    var received: [2]u8 = undefined;
    var buffers = [_][]u8{&received};
    const count = try io.vtable.netRead(
        io.userdata,
        server_stream.socket.handle,
        &buffers,
    );
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "MQTT broker event timeout and deadline resume partial publish" {
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
        .{ .max_packet_size = 4096 },
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
                self.prefix_received.set(self.server.io);
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            self.prefix_received.set(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                accepted.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            try std.testing.expect(accepted.connection.isUsable());
            self.timed_out.set(self.server.io);
            var event = try accepted.connection.readBrokerEventWithDeadline(
                .fromNow(
                    self.server.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                ),
            );
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .publish);
            try std.testing.expectEqualStrings(
                "deadline/broker",
                event.publish.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "payload",
                event.publish.publish.payload,
            );
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
        .{ .client_id = "broker-event-deadline" },
    );
    defer client.close();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.writePublish(
        &encoded,
        allocator,
        .v5,
        "deadline/broker",
        "payload",
        .{},
    );
    const tcp = client.transport.tcp;
    try writeAll(io, tcp.stream, encoded.items[0..2]);
    try shared.prefix_received.wait(io);
    try shared.timed_out.wait(io);
    try writeAll(io, tcp.stream, encoded.items[2..]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT client PING timeout covers the complete TCP response" {
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
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.readPingReq();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(80),
                .awake,
            );
            const tcp = accepted.connection.transport.tcp;
            _ = try tcp.io.vtable.netWrite(
                tcp.io.userdata,
                tcp.stream.socket.handle,
                &.{0xd0},
                &.{""},
                0,
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            );
            _ = tcp.io.vtable.netWrite(
                tcp.io.userdata,
                tcp.stream.socket.handle,
                &.{0x00},
                &.{""},
                0,
            ) catch |err| switch (err) {
                error.ConnectionResetByPeer, error.SocketUnconnected => 0,
                else => return err,
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .client_id = "ping-fragment-tcp" },
    );
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(150)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client PING preserves interleaved packets in wire order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.readPingReq();
            try accepted.connection.publish(
                "ping/interleaved/first",
                "one",
                .{},
            );
            try accepted.connection.publish(
                "ping/interleaved/second",
                "two",
                .{},
            );
            try accepted.connection.writePingResp();
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .client_id = "ping-interleaved" },
    );
    defer client.close();

    try client.pingWithTimeout(.fromSeconds(1));
    var first = try client.readPublish();
    defer first.deinit(allocator);
    var second = try client.readPublish();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings(
        "ping/interleaved/first",
        first.publish.topic,
    );
    try std.testing.expectEqualStrings("one", first.publish.payload);
    try std.testing.expectEqualStrings(
        "ping/interleaved/second",
        second.publish.topic,
    );
    try std.testing.expectEqualStrings("two", second.publish.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client PING timeout retains an interleaved packet" {
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
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.readPingReq();
            try accepted.connection.publish(
                "ping/timeout/interleaved",
                "retained",
                .{},
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(200),
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
        .{ .client_id = "ping-timeout-interleaved" },
    );
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(75)),
    );
    var publish = try client.readPublish();
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings(
        "ping/timeout/interleaved",
        publish.publish.topic,
    );
    try std.testing.expectEqualStrings("retained", publish.publish.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client PING bounds retained interleaved packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.readPingReq();
            try accepted.connection.publish("ping/cap/first", "one", .{});
            try accepted.connection.publish("ping/cap/second", "two", .{});
            // Keep the peer alive briefly after the overflowing packet so the
            // client failure is caused by its queue policy rather than EOF.
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
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
        .{
            .client_id = "ping-cap",
            .limits = .{ .max_pending_ping_packets = 1 },
        },
    );
    defer client.close();

    try std.testing.expectError(
        error.TooManyPendingPackets,
        client.pingWithTimeout(.fromSeconds(1)),
    );
    var first = try client.readPublish();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings(
        "ping/cap/first",
        first.publish.topic,
    );
    var second = try client.readPublish();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings(
        "ping/cap/second",
        second.publish.topic,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client PING rejects a zero pending-packet limit before writing" {
    var connection = runtime.Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .limits = .{ .max_pending_ping_packets = 0 },
    };
    try std.testing.expectError(
        error.TooManyPendingPackets,
        connection.pingWithTimeout(.fromSeconds(1)),
    );
}

test "MQTT client PING timeout permits a timely TCP response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
            var accepted = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            accepted.connection.readPingReq() catch |err| {
                self.err = err;
                return;
            };
            accepted.connection.writePingResp() catch |err| {
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
        .{ .client_id = "ping-success-tcp" },
    );
    defer client.close();

    try client.pingWithTimeout(.fromSeconds(1));
    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client PING rejects a non-positive timeout before writing" {
    var connection = runtime.Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.pingWithTimeout(.zero),
    );
}

test "MQTT TLS client PING timeout bounds a silent broker" {
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
    var server = try mqtt_tls.Server.listen(
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
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            accepted.connection.readPingReq() catch |err| {
                self.err = err;
                return;
            };
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
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{ .client_id = "ping-timeout-tls" },
            .tls = .{ .verify_host = false },
        },
    );
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(75)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT mTLS client PING timeout bounds a silent broker" {
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
    var server = try mqtt_tls.Server.listen(
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
            .client_auth = .{ .verifier = .{
                .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
            } },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            accepted.connection.readPingReq() catch |err| {
                self.err = err;
                return;
            };
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
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{ .client_id = "ping-timeout-mtls" },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(75)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket client PING timeout ignores control frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.readPingReq();
            for (0..3) |index| {
                try std.Io.sleep(
                    self.server.websocket_server.http.io,
                    .fromMilliseconds(50),
                    .awake,
                );
                accepted.connection.transport.websocket.connection.sendPing(
                    &.{@intCast(index)},
                ) catch |err| switch (err) {
                    error.ConnectionResetByPeer, error.SocketUnconnected => return,
                    else => return err,
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try mqtt_ws.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .mqtt = .{ .client_id = "ping-timeout-ws" },
            .host = "localhost",
        },
    );
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(125)),
    );
    thread.join();
    if (shared.err) |err| return err;
    client.close();
}

test "MQTT WSS client PING timeout bounds a silent broker" {
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
    var server = try mqtt_ws.TlsServer.listen(
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
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            accepted.connection.readPingReq() catch |err| {
                self.err = err;
                return;
            };
            std.Io.sleep(
                self.server.websocket_server.io,
                .fromMilliseconds(200),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_ws.Client.connectUri(allocator, io, uri, .{
        .mqtt = .{ .client_id = "ping-timeout-wss" },
        .tls = .{ .verify_host = false },
    });
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout(.fromMilliseconds(75)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

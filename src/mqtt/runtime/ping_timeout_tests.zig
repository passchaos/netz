const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const mqtt_tls = @import("../tls_runtime.zig");
const mqtt_ws = @import("../websocket_runtime.zig");
const tls_testing = @import("../../tls/testing.zig");
const websocket_runtime = @import("../../websocket/mod.zig").runtime;

const net = std.Io.net;

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

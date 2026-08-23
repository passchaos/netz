const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        offset += count;
    }
}

fn encodedConnect(
    allocator: std.mem.Allocator,
    client_id: []const u8,
) ![]u8 {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.writeConnectPacket(
        &encoded,
        allocator,
        .v5,
        .{ .client_id = client_id },
    );
    return encoded.toOwnedSlice(allocator);
}

test "MQTT CONNECT timeout starts before first byte" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.acceptPending(.{
                .connect_timeout = .fromMilliseconds(75),
            }) catch |err| {
                self.err = err;
                return;
            };
            pending.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT zero CONNECT timeout fails before reading" {
    var connection = runtime.Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.readConnectWithTimeout(.zero),
    );
}

test "MQTT CONNECT timeout is absolute across packet fragments" {
    const allocator = std.testing.allocator;
    const connect = try encodedConnect(allocator, "slow-connect");
    defer allocator.free(connect);
    try std.testing.expect(connect.len > 4);

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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.acceptPending(.{
                .connect_timeout = .fromMilliseconds(150),
            }) catch |err| {
                self.err = err;
                return;
            };
            pending.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(io, client, connect[0..2]);
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    try writeAll(io, client, connect[2..4]);
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    writeAll(io, client, connect[4..]) catch |err| switch (err) {
        error.SocketUnconnected, error.ConnectionResetByPeer => {},
        else => return err,
    };

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT CONNECT timeout allows a complete packet" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{
                .connect_timeout = .fromSeconds(1),
            }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
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
        .{ .client_id = "timely-connect" },
    );
    defer client.close();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT client bounds CONNACK wait" {
    const allocator = std.testing.allocator;
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
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try std.Io.sleep(self.io, .fromMilliseconds(150), .awake);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{
                .client_id = "silent-server",
                .connect_timeout = .fromMilliseconds(75),
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT client CONNACK timeout is absolute across packet fragments" {
    const allocator = std.testing.allocator;
    var connack: std.ArrayList(u8) = .empty;
    defer connack.deinit(allocator);
    try mqtt.ConnAck.write(&connack, allocator, .v5, false, 0, &.{});
    try std.testing.expect(connack.items.len > 3);

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
        io: std.Io,
        listener: *net.Server,
        connack: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var first: [1]u8 = undefined;
            var parts = [_][]u8{&first};
            if (try self.io.vtable.netRead(
                self.io.userdata,
                stream.socket.handle,
                &parts,
            ) == 0) return error.ConnectionClosed;
            try writeAll(self.io, stream, self.connack[0..2]);
            try std.Io.sleep(self.io, .fromMilliseconds(80), .awake);
            try writeAll(self.io, stream, self.connack[2..3]);
            try std.Io.sleep(self.io, .fromMilliseconds(80), .awake);
            writeAll(self.io, stream, self.connack[3..]) catch |err| switch (err) {
                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                else => return err,
            };
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .connack = connack.items,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{
                .client_id = "slow-connack",
                .connect_timeout = .fromMilliseconds(150),
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket CONNECT timeout starts after HTTP Upgrade" {
    const allocator = std.testing.allocator;
    const mqtt_ws = @import("../websocket_runtime.zig");
    const websocket_runtime = @import("../../websocket/mod.zig").runtime;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = 4096 } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{
                .connect_timeout = .fromMilliseconds(75),
            }) catch |err| {
                self.err = err;
                return;
            };
            accepted.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ws = try websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "localhost",
            .protocols = &.{"mqtt"},
        },
    );
    defer ws.close();

    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT WSS CONNECT timeout starts after TLS and HTTP handshakes" {
    const allocator = std.testing.allocator;
    const mqtt_ws = @import("../websocket_runtime.zig");
    const websocket_runtime = @import("../../websocket/mod.zig").runtime;

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
            .limits = .{ .max_packet_size = 4096 },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{
                .connect_timeout = .fromMilliseconds(75),
            }) catch |err| {
                self.err = err;
                return;
            };
            accepted.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var ws = try websocket_runtime.Client.connectUriTls(
        allocator,
        io,
        uri,
        .{ .protocols = &.{"mqtt"} },
        .{ .verify_host = false },
    );
    defer ws.close();

    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

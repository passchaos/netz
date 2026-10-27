//! Peers that stop reading cleartext, TLS, or h2c bootstrap output cannot
//! extend the HTTP/2 handshake past its deadline.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const tls = @import("../../../tls/mod.zig");
const blocked = @import("../testing/blocked_tls_write.zig");
const BlockedTlsWrite = blocked.BlockedTlsWrite;
const allocator = std.testing.allocator;

test "HTTP/2 server accept bounds blocked cleartext initial SETTINGS output" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .handshake_timeout = .fromMilliseconds(200),
        .terminal_cleanup_timeout = .fromMilliseconds(20),
    });
    defer server.deinit();
    const peer = try server.address().connect(io, .{ .mode = .stream });
    defer peer.close(io);

    var writer = BlockedTlsWrite{ .io = io, .mode = .blocked, .socket = null };
    var vtable: std.Io.VTable = undefined;
    server.io = writer.install(&vtable, io);
    defer {
        server.io = io;
        BlockedTlsWrite.clear();
    }
    const Shared = struct {
        server: *runtime.Server,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        writer.wait.set(io);
        peer.shutdown(io, .both) catch {};
        thread.join();
    };
    try writeAll(
        io,
        peer,
        http2.connection_preface ++
            "\x00\x00\x00\x04\x00\x00\x00\x00\x00",
    );
    const started = std.Io.Clock.awake.now(io);
    try shared.done.wait(io);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 1000 * std.time.ns_per_ms);
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
    try std.testing.expect(writer.canceled.load(.acquire));
}

test "HTTP/2 client connect bounds blocked cleartext preface output" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var peer = PlainPeer{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, PlainPeer.run, .{&peer});
    defer peer_thread.join();

    var writer = BlockedTlsWrite{ .io = io, .mode = .blocked, .socket = null };
    var vtable: std.Io.VTable = undefined;
    const client_io = writer.install(&vtable, io);
    defer BlockedTlsWrite.clear();
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, runtime.Client.connect(
        allocator,
        client_io,
        listener.socket.address,
        .{ .handshake_timeout = .fromMilliseconds(200) },
    ));
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 1000 * std.time.ns_per_ms);
    try std.testing.expect(writer.canceled.load(.acquire));
}

test "HTTP/2 h2c server bounds blocked switching response output" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .handshake_timeout = .fromMilliseconds(200),
        .terminal_cleanup_timeout = .fromMilliseconds(20),
    });
    defer server.deinit();
    const peer = try server.address().connect(io, .{ .mode = .stream });
    defer peer.close(io);

    var writer = BlockedTlsWrite{ .io = io, .mode = .blocked, .socket = null };
    var vtable: std.Io.VTable = undefined;
    server.io = writer.install(&vtable, io);
    defer {
        server.io = io;
        BlockedTlsWrite.clear();
    }
    const Shared = struct {
        server: *runtime.Server,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            var request = self.server.acceptUpgrade() catch |err| {
                self.err = err;
                return;
            };
            request.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        writer.wait.set(io);
        peer.shutdown(io, .both) catch {};
        thread.join();
    };
    try writeH2cUpgradeRequest(io, peer);
    const started = std.Io.Clock.awake.now(io);
    try shared.done.wait(io);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 1000 * std.time.ns_per_ms);
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
    try std.testing.expect(writer.canceled.load(.acquire));
}

test "HTTP/2 h2c client bounds blocked upgrade request output" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var peer = PlainPeer{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, PlainPeer.run, .{&peer});
    defer peer_thread.join();
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });

    var writer = BlockedTlsWrite{ .io = io, .mode = .blocked, .socket = null };
    var vtable: std.Io.VTable = undefined;
    const client_io = writer.install(&vtable, io);
    defer BlockedTlsWrite.clear();
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, runtime.Client.connectStreamUpgrade(
        allocator,
        client_io,
        stream,
        .{ .handshake_timeout = .fromMilliseconds(200) },
        .{ .authority = "localhost" },
    ));
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 1000 * std.time.ns_per_ms);
    try std.testing.expect(writer.canceled.load(.acquire));
}

test "HTTP/2 server accept bounds blocked initial SETTINGS output" {
    if (comptime builtin.os.tag != .linux) return;
    for ([_]bool{ false, true }) |tls12| try exerciseServer(tls12);
}

fn exerciseServer(tls12: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        .limits = .{
            .handshake_timeout = .fromMilliseconds(200),
            .terminal_cleanup_timeout = .fromMilliseconds(20),
        },
    });
    defer server.deinit();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var peer_owned = true;
    defer if (peer_owned) stream.close(io);
    const accepted = try server.listener.accept(io);
    var writer = BlockedTlsWrite{
        .io = io,
        .mode = .post_handshake_blocked,
        .socket = accepted.socket.handle,
        .post_hello_writes_to_pass = if (tls12) 0 else 1,
    };
    var vtable: std.Io.VTable = undefined;
    server.io = writer.install(&vtable, io);
    defer {
        server.io = io;
        BlockedTlsWrite.clear();
    }
    const Shared = struct {
        server: *runtime.TlsServer,
        stream: std.Io.net.Stream,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            var connection = self.server.acceptStream(self.stream) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server, .stream = accepted };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        writer.wait.set(io);
        accepted.shutdown(io, .both) catch {};
        thread.join();
    };
    const peer = try tls.stream.ClientConnection.initWithDeadline(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .alpn_protocols = &.{"h2"},
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
    }, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    peer_owned = false;
    defer peer.deinit();
    var handshake: [http2.connection_preface.len + 9]u8 = undefined;
    @memcpy(
        handshake[0..http2.connection_preface.len],
        http2.connection_preface[0..http2.connection_preface.len],
    );
    // Empty client SETTINGS frame.
    handshake[http2.connection_preface.len..][0..9].* = .{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    try peer.writeAll(&handshake);
    const started = std.Io.Clock.awake.now(io);
    try shared.done.wait(io);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 1000 * std.time.ns_per_ms);
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
    try std.testing.expect(writer.canceled.load(.acquire));
}

test "HTTP/2 client connect bounds blocked preface output" {
    if (comptime builtin.os.tag != .linux) return;
    for ([_]bool{ false, true }) |tls12| try exerciseClient(tls12);
}

fn exerciseClient(tls12: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    const policy = if (tls12) tls.stream.VersionPolicy.tls12_only else tls.stream.VersionPolicy.tls13_only;

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const Peer = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        certificate: []const u8,
        key: @TypeOf(key),
        policy: tls.stream.VersionPolicy,
        done: std.Io.Event = .unset,

        fn run(self: *@This()) void {
            defer self.done.set(self.io);
            const raw = self.listener.accept(self.io) catch return;
            // Complete the TLS handshake, then never read application data:
            // the client's preface write must hit its handshake deadline.
            var server = tls.stream.ServerConnection.init(self.allocator, self.io, raw, .{
                .identity = .{
                    .certificate_chain = &.{self.certificate},
                    .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = self.key } },
                },
                .alpn_protocols = &.{"h2"},
                .protocol_policy = self.policy,
            }) catch return;
            defer server.deinit();
            var buffer: [256]u8 = undefined;
            _ = server.readWithDeadline(
                &buffer,
                .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(3) }),
            ) catch {};
        }
    };
    var peer = Peer{
        .io = io,
        .allocator = allocator,
        .listener = &listener,
        .certificate = &certificate,
        .key = key,
        .policy = policy,
    };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    defer thread.join();

    var writer = BlockedTlsWrite{
        .io = io,
        .mode = .post_handshake_blocked,
        .socket = null,
        .post_hello_writes_to_pass = if (tls12) 0 else 1,
    };
    var vtable: std.Io.VTable = undefined;
    const client_io = writer.install(&vtable, io);
    defer BlockedTlsWrite.clear();
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const started = std.Io.Clock.awake.now(io);
    const result = runtime.Client.connectTlsHost(
        allocator,
        client_io,
        "localhost",
        listener.socket.address.ip4.port,
        .{ .handshake_timeout = .fromMilliseconds(200) },
        .{
            .verify_host = false,
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = policy,
        },
    );
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 1000 * std.time.ns_per_ms);
    try std.testing.expect(writer.canceled.load(.acquire));
    try peer.done.wait(io);
}

const PlainPeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,

    fn run(self: *@This()) void {
        const stream = self.listener.accept(self.io) catch return;
        defer stream.close(self.io);
        var buffer: [256]u8 = undefined;
        var buffers = [_][]u8{&buffer};
        _ = self.io.vtable.netRead(
            self.io.userdata,
            stream.socket.handle,
            &buffers,
        ) catch {};
    }
};

fn writeH2cUpgradeRequest(io: std.Io, stream: std.Io.net.Stream) !void {
    try writeAll(
        io,
        stream,
        "GET /timeout HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Connection: Upgrade, HTTP2-Settings\r\n" ++
            "Upgrade: h2c\r\n" ++
            "HTTP2-Settings: AAEAABAAAAQAAP__AAYAAEAAAAIAAAAA\r\n\r\n",
    );
}

fn writeAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
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

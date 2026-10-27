//! Established-connection teardown bounds TLS close_notify; only the alert is
//! terminal here, so every blocked write is the first armed write.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const tls = @import("../../../tls/mod.zig");
const blocked = @import("../testing/blocked_tls_write.zig");
const BlockedTlsWrite = blocked.BlockedTlsWrite;
const Mode = blocked.Mode;
const allocator = std.testing.allocator;

test "HTTP/2 connection close bounds TLS12 and TLS13 close notify" {
    if (comptime builtin.os.tag != .linux) return;
    // Teardown emits only close_notify, so close_blocked (pass first write,
    // block the second) is indistinguishable from healthy here and is omitted.
    const modes = [_]Mode{ .healthy, .disabled, .blocked, .partial };
    for ([_]bool{ false, true }) |tls12| {
        for (modes) |mode| try exercise(tls12, mode);
    }
}

fn exercise(tls12: bool, mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        .limits = .{ .terminal_cleanup_timeout = if (mode == .disabled) .zero else .fromMilliseconds(20) },
    });
    defer server.deinit();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var peer_owned = true;
    defer if (peer_owned) stream.close(io);
    const accepted = try server.listener.accept(io);
    var writer = BlockedTlsWrite{ .io = io, .mode = mode, .socket = accepted.socket.handle };
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
        connection: ?runtime.Connection = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            const connection = self.server.acceptStream(self.stream) catch |err| {
                self.err = err;
                return;
            };
            self.connection = connection;
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
    try std.testing.expectEqualStrings("h2", peer.selected_alpn.?);
    var handshake: [http2.connection_preface.len + 9]u8 = undefined;
    @memcpy(
        handshake[0..http2.connection_preface.len],
        http2.connection_preface[0..http2.connection_preface.len],
    );
    // Empty client SETTINGS frame.
    handshake[http2.connection_preface.len..][0..9].* = .{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    try peer.writeAll(&handshake);
    try shared.done.wait(io);
    thread.join();
    joined = true;
    try std.testing.expect(shared.err == null);

    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const started = std.Io.Clock.awake.now(io);
    shared.connection.?.close();
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, switch (mode) {
        .disabled => 0,
        .partial => 2,
        .healthy, .blocked => 1,
        .close_blocked, .post_handshake_blocked => unreachable,
    }), writer.calls.load(.acquire));
    if (mode == .blocked) {
        try std.testing.expect(writer.canceled.load(.acquire));
    } else {
        try std.testing.expect(!writer.canceled.load(.acquire));
    }
    if (mode == .healthy) {
        var buffer: [128]u8 = undefined;
        while (!switch (peer.records) {
            inline else => |records| records.receivedCloseNotify(),
        }) {
            const len = try peer.readWithDeadline(&buffer, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
            if (len == 0) break;
        }
        try std.testing.expect(switch (peer.records) {
            inline else => |records| records.receivedCloseNotify(),
        });
    }
}

test "HTTP/2 TLS connect without h2 ALPN bounds rejected close notify" {
    if (comptime builtin.os.tag != .linux) return;
    const modes = [_]Mode{ .healthy, .post_handshake_blocked, .disabled };
    for ([_]bool{ false, true }) |tls12| {
        for (modes) |mode| try exerciseAlpnRejection(tls12, mode);
    }
}

fn exerciseAlpnRejection(tls12: bool, mode: Mode) !void {
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
        received_close_notify: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.io);
            const raw = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            var raw_owned = true;
            defer if (raw_owned) raw.close(self.io);
            var server = tls.stream.ServerConnection.init(self.allocator, self.io, raw, .{
                .identity = .{
                    .certificate_chain = &.{self.certificate},
                    .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = self.key } },
                },
                .alpn_protocols = &.{},
                .require_alpn = false,
                .protocol_policy = self.policy,
            }) catch |err| {
                self.err = err;
                return;
            };
            raw_owned = false;
            defer server.deinit();
            var buffer: [256]u8 = undefined;
            while (true) {
                const len = server.readWithDeadline(
                    &buffer,
                    .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(2) }),
                ) catch break;
                if (len == 0) break;
            }
            self.received_close_notify = server.receivedCloseNotify();
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
        .mode = mode,
        .socket = @as(std.Io.net.Socket.Handle, std.math.maxInt(std.posix.fd_t)),
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
        .{
            .terminal_cleanup_timeout = if (mode == .disabled) .zero else .fromMilliseconds(20),
        },
        .{
            .verify_host = false,
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = policy,
        },
    );
    try std.testing.expectError(error.InvalidAlpn, result);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    if (mode == .post_handshake_blocked) {
        try std.testing.expect(writer.canceled.load(.acquire));
    }
    try peer.done.wait(io);
    if (peer.err) |err| return err;
    try std.testing.expectEqual(mode == .healthy, peer.received_close_notify);
}

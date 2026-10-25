//! Bounded WS/WSS writes retain their transaction across executor rejection.
const std = @import("std");
const runtime = @import("../runtime.zig");
const websocket = @import("../mod.zig");
const tls_testing = @import("../../tls/testing.zig");
const support = @import("../../internal/testing/write_interruption.zig");
const allocator = std.testing.allocator;
const Backend = enum { tcp, vail_tls12, vail_tls13, standard_tls13 };
const Mode = enum { binary, slices, in_place, compressed, ping, pong, close, automatic_pong, automatic_close };
const payload = "retained payload/" ** 32;
const limits: runtime.Limits = .{ .max_frame_bytes = 1024, .max_message_bytes = 1024 };

const Listener = union(enum) {
    plain: runtime.Server,
    secure: runtime.TlsServer,

    fn accept(self: *Listener, mode: Mode) !runtime.Connection {
        const options: runtime.AcceptOptions = .{
            .enable_permessage_deflate = mode == .compressed,
            .allow_context_takeover = true,
            .compression_threshold = 1,
        };
        return switch (self.*) {
            inline else => |*server| server.accept(options),
        };
    }

    fn address(self: *Listener) std.Io.net.IpAddress {
        return switch (self.*) {
            inline else => |*server| server.address(),
        };
    }

    fn deinit(self: *Listener) void {
        switch (self.*) {
            inline else => |*server| server.deinit(),
        }
    }
};

test "WebSocket bounded write interruptions retain masks controls and compression over TCP and all WSS backends" {
    for (std.enums.values(Backend)) |backend| {
        for (std.enums.values(Mode)) |mode| {
            for (std.enums.values(support.Stage)) |stage| try exercise(backend, mode, stage);
        }
    }
}

fn exercise(backend: Backend, mode: Mode, stage: support.Stage) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var probe = support.Probe{ .delegate = base, .stage = stage, .prefix_len = if (stage == .before_write) 0 else 6, .armed = false };
    support.Probe.active = &probe;
    var vtable = base.vtable.*;
    vtable.groupConcurrent = support.Probe.groupConcurrent;
    vtable.netWrite = support.Probe.netWrite;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var listener: Listener = if (backend == .tcp)
        .{ .plain = try runtime.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, limits) }
    else
        .{ .secure = try runtime.TlsServer.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{
            .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
            .protocol_policy = if (backend == .vail_tls12) .tls12_only else .tls13_only,
            .limits = limits,
        }) };
    defer listener.deinit();
    const Peer = struct {
        listener: *Listener,
        io: std.Io,
        mode: Mode,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.listener.accept(self.mode);
            defer connection.close();
            try self.release.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
            switch (self.mode) {
                .binary, .slices, .in_place, .compressed => {
                    var message = try connection.receiveMessageWithTimeout(.fromSeconds(2));
                    defer message.deinit(allocator);
                    try std.testing.expectEqualStrings(payload, message.payload);
                    try std.testing.expectEqual(self.mode == .compressed, message.was_compressed);
                },
                .ping, .pong, .close, .automatic_pong, .automatic_close => {
                    var frame = try connection.receiveFrameWithTimeout(.fromSeconds(2));
                    defer frame.deinit(allocator);
                    const expected_opcode: websocket.Opcode = switch (self.mode) {
                        .ping => .ping,
                        .pong, .automatic_pong => .pong,
                        .close, .automatic_close => .close,
                        else => unreachable,
                    };
                    try std.testing.expectEqual(expected_opcode, frame.header.opcode);
                    try std.testing.expectEqualStrings(if (isClose(self.mode)) "\x03\xe8done" else "probe", frame.payload);
                },
            }
            if (isClose(self.mode)) return;
            try connection.sendBinary("ack");
            var following = try connection.receiveMessageWithTimeout(.fromSeconds(2));
            defer following.deinit(allocator);
            try std.testing.expectEqualStrings(if (self.mode == .compressed) payload else "following", following.payload);
            try std.testing.expectEqual(self.mode == .compressed, following.was_compressed);
            try connection.sendBinary("following ack");
        }
    };
    var peer = Peer{ .listener = &listener, .io = base, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(base);
        thread.join();
    };
    const options: runtime.ConnectOptions = .{
        .host = "localhost",
        .enable_permessage_deflate = mode == .compressed,
        .allow_context_takeover = true,
        .compression_threshold = 1,
        .limits = limits,
        .vail_tls = if (backend == .tcp or backend == .standard_tls13) null else .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = if (backend == .vail_tls12) .tls12_only else .tls13_only,
        },
    };
    var client = if (backend == .tcp)
        try runtime.Client.connect(allocator, io, listener.address(), options)
    else
        try runtime.Client.connectTlsHost(allocator, io, "localhost", listener.address().ip4.port, options, .{ .verify_host = false });
    defer client.close();
    if (isAutomatic(mode)) {
        try websocket.writeFrame(&client.inbuf, allocator, if (isClose(mode)) .close else .ping, if (isClose(mode)) "\x03\xe8done" else "probe", .{});
    }
    var mutable: [payload.len]u8 = payload.*;
    var progress: runtime.MessageWriteProgress = .{};
    probe.submissions = 0;
    probe.written = 0;
    probe.armed = true;
    try std.testing.expectError(error.ConcurrencyUnavailable, send(&client, mode, &mutable, &progress));
    try std.testing.expectEqual(probe.prefix_len, probe.written);
    try std.testing.expectEqual(if (backend == .tcp) probe.prefix_len else 0, progress.committed_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(if (isAutomatic(mode)) client.pending_auto_control != null else !client.pending_write.isNone());
    try std.testing.expect(!client.close_sent.load(.acquire));
    try std.testing.expect(!client.write_aborted.load(.acquire));
    try std.testing.expect(!client.receive_failed.load(.acquire));
    try std.testing.expectError(if (mode == .automatic_close) error.ConnectionClosed else error.WriteInProgress, client.sendBinary("different operation"));
    probe.armed = false;
    peer.release.set(base);
    try send(&client, mode, &mutable, &progress);
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(client.pending_write.isNone());
    if (isClose(mode)) {
        try std.testing.expect(client.close_sent.load(.acquire));
    } else {
        try client.sendBinary(if (mode == .compressed) payload else "following");
        var ack = try client.receiveMessageWithTimeout(.fromSeconds(2));
        defer ack.deinit(allocator);
        try std.testing.expectEqualStrings("ack", ack.payload);
        var following_ack = try client.receiveMessageWithTimeout(.fromSeconds(2));
        defer following_ack.deinit(allocator);
        try std.testing.expectEqualStrings("following ack", following_ack.payload);
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn send(connection: *runtime.Connection, mode: Mode, mutable: []u8, progress: *runtime.MessageWriteProgress) !void {
    switch (mode) {
        .binary, .compressed => try connection.sendBinaryWithTimeout(payload, progress, .fromSeconds(2)),
        .slices => try connection.sendBinarySlicesWithTimeout(&.{ payload[0..3], "", payload[3..] }, progress, .fromSeconds(2)),
        .in_place => try connection.sendBinaryInPlaceWithTimeout(mutable, progress, .fromSeconds(2)),
        .ping => try connection.sendPingWithTimeout("probe", progress, .fromSeconds(2)),
        .pong => try connection.sendPongWithTimeout("probe", progress, .fromSeconds(2)),
        .close => try connection.sendCloseWithTimeout(.normal_closure, "done", progress, .fromSeconds(2)),
        .automatic_pong, .automatic_close => {
            errdefer if (connection.pending_auto_control) |pending| {
                progress.* = .{ .total_bytes = pending.len, .committed_bytes = pending.committed };
            };
            var frame = try connection.receiveFrameAutoWithTimeout(.fromSeconds(2));
            defer frame.deinit(allocator);
            try std.testing.expectEqual(if (isClose(mode)) websocket.Opcode.close else websocket.Opcode.ping, frame.header.opcode);
            try std.testing.expectEqualStrings(if (isClose(mode)) "\x03\xe8done" else "probe", frame.payload);
            try std.testing.expect(connection.pending_auto_control == null);
            const total = 6 + frame.payload.len;
            progress.* = .{ .total_bytes = total, .committed_bytes = total, .frame_committed = true };
        },
    }
}

fn isAutomatic(mode: Mode) bool {
    return mode == .automatic_pong or mode == .automatic_close;
}

fn isClose(mode: Mode) bool {
    return mode == .close or mode == .automatic_close;
}

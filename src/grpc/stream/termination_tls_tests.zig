//! Real authenticated TLS output must also obey the stream cleanup budget.
const std = @import("std");
const builtin = @import("builtin");
const grpc = @import("mod.zig");
const http2 = @import("../../http2/mod.zig");
const tls = @import("../../tls/mod.zig");
const frame_wire = @import("../../http2/runtime/frame/wire.zig");
const allocator = std.testing.allocator;

const BlockedWrite = struct {
    var active: std.atomic.Value(?*BlockedWrite) = .init(null);
    io: std.Io,
    calls: std.atomic.Value(usize) = .init(0),
    cancelled: std.atomic.Value(bool) = .init(false),
    record_len: usize = 0,
    wait: std.Io.Event = .unset,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, bytes: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        _ = self.calls.fetchAdd(1, .monotonic);
        self.record_len = bytes.len;
        self.wait.wait(self.io) catch |err| {
            self.cancelled.store(true, .release);
            return err;
        };
        return bytes.len;
    }

    fn rescue(self: *BlockedWrite) void {
        std.Io.sleep(self.io, .fromMilliseconds(500), .awake) catch {};
        self.wait.set(self.io);
    }
};

test "gRPC streaming terminal cleanup bounds real TLS12 and TLS13 writes" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |tls12| {
        exercise(tls12, false) catch |err| {
            std.debug.print("TLS terminal cleanup failed: tls12={} terminal=false error={s}\n", .{ tls12, @errorName(err) });
            return err;
        };
        exercise(tls12, true) catch |err| {
            std.debug.print("TLS terminal cleanup failed: tls12={} terminal=true error={s}\n", .{ tls12, @errorName(err) });
            return err;
        };
    }
}

fn exercise(tls12: bool, comptime terminal: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    var server = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        .tls_handshake_timeout = .fromSeconds(2),
    });
    defer server.deinit();
    const Peer = struct {
        server: *http2.runtime.TlsServer,
        err: ?anyerror = null,
        finished: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            // Keep the authenticated peer alive until the client finishes,
            // independently of write-task scheduling and TCP ACK timing.
            try self.finished.wait(connection.io);
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.finished.set(io);
        thread.join();
    };
    var client = try http2.runtime.Client.connectTlsAddress(allocator, io, server.address(), "localhost", "localhost", .{ .terminal_cleanup_timeout = .fromMilliseconds(20) }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
    });
    defer client.close();
    const options: grpc.RequestOptions = .{ .path = "/fixture.Termination/Stream", .authority = "localhost" };
    var stream = if (terminal) try grpc.startDuplex(&client, allocator, options) else try grpc.startClient(&client, allocator, options);
    var stream_live = true;
    defer if (stream_live) stream.deinit();
    // Hold the actual ciphertext write after a real pinned TLS handshake.
    // Socket-buffer saturation alone can let a tiny FIN/reset through when
    // an ACK opens a few bytes of space between the fill and the write.
    var blocked: BlockedWrite = .{ .io = io };
    BlockedWrite.active.store(&blocked, .release);
    defer BlockedWrite.active.store(null, .release);
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.write;
    const tls_connection = switch (client.transport.?) {
        .tls_client => |connection| connection,
        else => return error.TestUnexpectedResult,
    };
    tls_connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer tls_connection.io = io;
    const rescue = try std.Thread.spawn(.{}, BlockedWrite.rescue, .{&blocked});
    defer rescue.join();
    if (terminal) {
        const fields = [_]http2.Hpack.HeaderField{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "application/grpc" },
            .{ .name = "grpc-status", .value = "7" },
        };
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &fields);
        try frame_wire.appendFrame(&client.frame_reader.buffer, allocator, .headers, 5, stream.streamId(), encoded.items);
    }
    const started = std.Io.Clock.awake.now(io);
    if (terminal) {
        const Consumer = struct {
            fn consume(_: void, _: grpc.DecodedMessage) !void {
                return error.UnexpectedMessage;
            }
        };
        var event = try stream.readResponseEvent({}, Consumer.consume);
        defer event.deinit(allocator);
        try std.testing.expect(event == .terminal);
        try std.testing.expectEqual(@as(@TypeOf(event.terminal.status), .permission_denied), event.terminal.status);
    } else {
        try std.testing.expectError(error.Timeout, stream.cancel());
        try std.testing.expect(stream.transport.completed);
    }
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(client.aggregate_timeout_unusable);
    try std.testing.expect(client.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), client.recv_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_windows.items.len);
    try std.testing.expect(!client.duplex_reader_active);
    try std.testing.expect(blocked.cancelled.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), blocked.calls.load(.acquire));
    const pending = switch (tls_connection.records) {
        inline else => |records| records.pending_write_len,
    };
    try std.testing.expectEqual(blocked.record_len, pending);
    try std.testing.expect(pending >= (if (terminal) @as(usize, 9) else 13) + 16 + 5);
    stream.deinit();
    stream_live = false;
    try std.testing.expectEqual(@as(usize, 1), blocked.calls.load(.acquire));
    try std.testing.expectEqual(pending, switch (tls_connection.records) {
        inline else => |records| records.pending_write_len,
    });
    peer.finished.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

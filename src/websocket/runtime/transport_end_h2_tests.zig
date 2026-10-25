//! A fatal underlying TLS record also terminates RFC 8441 WebSocket ownership.
const std = @import("std");
const runtime = @import("../runtime.zig");
const http2 = @import("../../http2/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");
const stream_io = @import("../../internal/stream_io.zig");

test "WebSocket HTTP2 TLS truncation retires allocating and caller-buffer messages" {
    for ([_]bool{ false, true }) |caller_buffer| {
        for ([_]bool{ false, true }) |tls12| {
            for ([_]bool{ false, true }) |truncated| try exercise(caller_buffer, tls12, truncated);
        }
    }
}

fn exercise(caller_buffer: bool, tls12: bool, truncated: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    const policy = if (tls12) @import("../../tls/mod.zig").stream.VersionPolicy.tls12_only else .tls13_only;
    const h2_limits = http2.Limits{ .enable_connect_protocol = true };
    var server = try http2.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate_der}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } } },
        .protocol_policy = policy,
        .limits = h2_limits,
    });
    defer server.deinit();
    const Peer = struct {
        server: *http2.TlsServer,
        truncated: bool,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var parent = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer parent.close();
            var connection = try runtime.H2Server.acceptWithTimeout(self.server.allocator, &parent, .{}, .fromSeconds(3));
            defer connection.close();
            try runtime.testing.writeFrame(&connection, .text, "partial", false);
            if (self.truncated) try stream_io.writeAllSlices(parent.io, parent.stream, &.{&.{0x17}});
            try parent.stream.shutdown(parent.io, .send);
            try self.release.waitTimeout(parent.io, .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } });
        }
    };
    var peer = Peer{ .server = &server, .truncated = truncated };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    defer peer.release.set(io);
    var parent = try http2.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", h2_limits, .{
        .protocol_policy = policy,
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() },
    }, .fromSeconds(3));
    defer parent.close();
    var connection = try runtime.H2Client.openWithTimeout(allocator, &parent, .{ .authority = "localhost", .limits = .{ .max_message_bytes = 64 } }, .fromSeconds(3));
    defer connection.close();
    const expected = if (truncated) error.TruncatedRecord else error.UnexpectedEof;
    if (caller_buffer) {
        var output: [64]u8 = undefined;
        try std.testing.expectError(expected, connection.receiveMessageIntoWithTimeout(&output, .fromSeconds(2)));
    } else try std.testing.expectError(expected, connection.receiveMessageWithTimeout(.fromSeconds(2)));
    try std.testing.expect(runtime.testing.receiveStorageReleased(&connection));
    try std.testing.expect(runtime.testing.outboundStorageReleased(&connection));
    try std.testing.expect(runtime.testing.writeAborted(&connection));
    try std.testing.expect(!connection.close_sent.load(.acquire));
    try std.testing.expectError(error.ConnectionClosed, connection.sendText("late"));
    peer.release.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

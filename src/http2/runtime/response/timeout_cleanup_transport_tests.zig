const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const Transport = enum { tcp, tls12, tls13 };

test "HTTP/2 response timeout sends cancellation after partial body over TCP and TLS" {
    inline for (std.enums.values(Transport)) |transport| {
        try exercise(transport, false);
        try exercise(transport, true);
    }
}

fn exercise(comptime transport: Transport, streaming: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    const Server = if (transport == .tcp) runtime.Server else runtime.TlsServer;
    var server = if (transport == .tcp)
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{})
    else
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
            .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
        });
    defer server.deinit();
    const Peer = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            try runtime.testing.writeRawFrame(&connection, .headers, 4, request.stream_id, &.{0x88});
            try runtime.testing.writeRawFrame(&connection, .data, 0, request.stream_id, "prefix");
            var refunded: usize = 0;
            while (true) {
                var frame = try runtime.testing.readOwnedFrame(&connection);
                defer frame.deinit(allocator);
                if (frame.frame.header.frame_type == .window_update) {
                    const update = try http2.WindowUpdatePayload.parse(frame.frame);
                    try std.testing.expectEqual(@as(u31, 0), update.stream_id);
                    refunded += update.increment;
                    continue;
                }
                if (frame.frame.header.frame_type == .rst_stream) {
                    const reset = try http2.ResetStreamPayload.parse(frame.frame);
                    try std.testing.expectEqual(request.stream_id, reset.stream_id);
                    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
                    break;
                }
                if (!try runtime.testing.handleConnectionFrame(&connection, frame.frame)) return error.UnexpectedFrame;
            }
            try std.testing.expectEqual(@as(usize, 6), refunded);
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (transport == .tcp)
        try runtime.Client.connect(allocator, io, server.address(), .{})
    else
        try runtime.Client.connectTlsHost(allocator, io, "localhost", server.address().ip4.port, .{}, .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
        });
    var closed = false;
    defer if (!closed) client.close();
    const options: runtime.RequestOptions = .{ .method = "POST", .path = "/timeout", .authority = "localhost", .body = "request" };
    const Counter = struct {
        len: usize = 0,
        fn consume(self: *@This(), bytes: []const u8) !void {
            self.len += bytes.len;
        }
    };
    var counter: Counter = .{};
    if (streaming) {
        try std.testing.expectError(error.Timeout, client.requestStreamingWithTimeout(options, .fromMilliseconds(100), &counter, Counter.consume));
        try std.testing.expectEqual(@as(usize, 6), counter.len);
    } else {
        try std.testing.expectError(error.Timeout, client.requestWithTimeout(options, .fromMilliseconds(100)));
    }
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.active_local_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.recv_stream_windows.items.len);
    try std.testing.expectEqual(window.default_value, client.recv_connection_window.value);
    client.close();
    closed = true;
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;

const Transport = enum { tcp, tls12, tls13 };

test "HTTP/2 forbidden response body restores four-byte windows over TCP and TLS" {
    inline for (std.enums.values(Transport)) |transport| {
        try exercise(transport, false);
        try exercise(transport, true);
    }
}

fn exercise(comptime transport: Transport, streaming: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    const Server = if (transport == .tcp) runtime.Server else runtime.TlsServer;
    const limits = runtime.Limits{ .initial_window_size = 4 };
    var server = if (transport == .tcp)
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits)
    else
        try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .identity = .{
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            },
            .limits = limits,
            .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
            .tls_handshake_timeout = .fromSeconds(2),
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

        fn sendData(connection: *runtime.Connection, id: u31, flags: u8, bytes: []const u8) !void {
            try connection.send_connection_window.reserve(bytes.len);
            try (try runtime.testing.sendStreamWindow(connection, id)).reserve(bytes.len);
            try runtime.testing.writeRawFrame(connection, .data, flags, id, bytes);
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            for (0..5) |index| {
                var request = try connection.readRequestWithTimeout(.fromSeconds(2));
                defer request.deinit(allocator);
                const id = request.stream_id;
                const code: []const u8 = if (index == 1) "204" else if (index == 2) "304" else "200";
                const head = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{ .name = ":status", .value = code }});
                try runtime.testing.writeRawFrame(&connection, .headers, 4, id, head);
                // Exhaust the peer's four-byte stream window using padding.
                // Without a stream WINDOW_UPDATE the final DATA cannot follow.
                try sendData(&connection, id, 8, "\x03\x00\x00\x00");
                var refunded: usize = 0;
                while ((try runtime.testing.sendStreamWindow(&connection, id)).available() == 0) {
                    var update = try connection.readWindowUpdateWithTimeout(.fromSeconds(2));
                    defer update.deinit(allocator);
                    if (update.window_update.stream_id == 0) refunded += update.window_update.increment;
                }
                try std.testing.expectEqual(@as(usize, 4), refunded);
                if (index < 3) {
                    try sendData(&connection, id, 9, "\x02\x00\x00");
                    var update = try connection.readWindowUpdateWithTimeout(.fromSeconds(2));
                    defer update.deinit(allocator);
                    try std.testing.expectEqual(@as(u31, 0), update.window_update.stream_id);
                    try std.testing.expectEqual(@as(u31, 3), update.window_update.increment);
                } else {
                    const trailer = "\x40\x01x\x01y";
                    try runtime.testing.writeRawFrame(&connection, .headers, if (index == 3) 5 else 1, id, if (index == 3) trailer else trailer[0..2]);
                    if (index == 4) try runtime.testing.writeRawFrame(&connection, .continuation, 4, id, trailer[2..]);
                    var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
                    defer reset.deinit(allocator);
                    try std.testing.expectEqual(id, reset.reset.stream_id);
                    try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
                }
                try std.testing.expectEqual(window.default_value, connection.send_connection_window.value);
            }
            var healthy = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer healthy.deinit(allocator);
            // The ignored trailers still inserted x=y into the peer's table.
            try runtime.testing.writeRawFrame(&connection, .headers, 5, healthy.stream_id, "\x88\xbe");
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (transport == .tcp)
        try runtime.Client.connectWithTimeout(allocator, io, server.address(), limits, .fromSeconds(2))
    else
        try runtime.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", limits, .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
            .tls_handshake_timeout = .fromSeconds(2),
        }, .fromSeconds(2));
    defer client.close();
    var delivered: usize = 0;
    for (0..5) |index| {
        const options = runtime.RequestOptions{ .method = if (index == 1 or index == 2) "GET" else "HEAD", .authority = "localhost" };
        if (streaming) {
            const result = client.requestStreamingWithTimeout(options, .fromSeconds(2), &delivered, consume);
            if (index < 3) {
                var response = try result;
                defer response.deinit(allocator);
                try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
            } else try std.testing.expectError(error.InvalidContentLength, result);
        } else {
            const result = client.requestWithTimeout(options, .fromSeconds(2));
            if (index < 3) {
                var response = try result;
                defer response.deinit(allocator);
                try std.testing.expectEqual(@as(usize, 0), response.body.len);
            } else try std.testing.expectError(error.InvalidContentLength, result);
        }
        try std.testing.expect(!client.aggregate_timeout_unusable);
        try std.testing.expectEqual(window.default_value, client.recv_connection_window.value);
    }
    var healthy = try client.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("y", runtime.testing.findHeader(healthy.headers, "x").?);
    try std.testing.expectEqual(@as(usize, 0), delivered);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn consume(delivered: *usize, bytes: []const u8) !void {
    delivered.* += bytes.len;
}

const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const Transport = enum { tcp, tls12, tls13 };
const Failure = enum { reset, malformed, cancel, quota, late_data };

test "HTTP/2 push failures refund wire credit over TCP and authenticated TLS" {
    inline for (std.enums.values(Transport)) |transport| {
        for (std.enums.values(Failure)) |failure| try exercise(transport, failure);
    }
}

fn exercise(comptime transport: Transport, failure: Failure) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    const Server = if (transport == .tcp) runtime.Server else runtime.TlsServer;
    var server = if (transport == .tcp) try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}) else try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
        .tls_handshake_timeout = .fromSeconds(2),
    });
    defer server.deinit();
    const Peer = struct {
        server: *Server,
        failure: Failure,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn sendData(connection: *runtime.Connection, id: u31, flags: u8, data: []const u8) !void {
            try connection.send_connection_window.reserve(data.len);
            try (try runtime.testing.sendStreamWindow(connection, id)).reserve(data.len);
            try runtime.testing.writeRawFrame(connection, .data, flags, id, data);
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var parent = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer parent.deinit(allocator);
            const fields = [_]http2.Hpack.HeaderField{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/push" }, .{ .name = ":authority", .value = "localhost" } };
            const bad = try connection.promisePush(parent.stream_id, &fields);
            const good = try connection.promisePush(parent.stream_id, &fields);
            const head = try connection.hpack_encoder.encodeBlockRetained(allocator, if (self.failure == .malformed) &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-length", .value = "3" } } else &.{.{ .name = ":status", .value = "200" }});
            try runtime.testing.writeRawFrame(&connection, .headers, 4, bad, head);
            try sendData(&connection, bad, if (self.failure == .late_data) 9 else 8, "\x02ab\x00\x00");
            try connection.writePushedResponse(good, .{ .body = "xyz" });
            try connection.writeResponse(parent.stream_id, .{});
            switch (self.failure) {
                .reset => try runtime.testing.writeRawFrame(&connection, .rst_stream, 0, bad, &.{ 0, 0, 0, 8 }),
                .malformed => try sendData(&connection, bad, 9, "\x00cd"),
                .quota => try sendData(&connection, bad, 0, "a" ** 512),
                .late_data => try sendData(&connection, bad, 9, "\x00late"),
                .cancel => {},
            }
            if (self.failure != .reset) {
                var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
                defer reset.deinit(allocator);
                try std.testing.expectEqual(bad, reset.reset.stream_id);
                try std.testing.expectEqual(if (self.failure == .late_data) http2.ErrorCode.stream_closed else if (self.failure == .malformed) http2.ErrorCode.protocol_error else http2.ErrorCode.cancel, reset.reset.error_code);
            }
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(allocator);
            // Parsing the next request drains all earlier WINDOW_UPDATEs.
            // Late DATA leaves both committed responses intact. Other failures
            // retain only the healthy push's three content bytes.
            try std.testing.expectEqual(window.default_value - @as(i64, if (self.failure == .late_data) 5 else 3), connection.send_connection_window.value);
            try connection.writeResponse(next.stream_id, .{});
        }
    };
    var peer = Peer{ .server = &server, .failure = failure };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const limits = runtime.Limits{ .enable_push = true, .max_buffered_push_bytes = if (failure == .quota) 256 else 1024 * 1024 };
    var client = if (transport == .tcp) try runtime.Client.connectWithTimeout(allocator, io, server.address(), limits, .fromSeconds(2)) else try runtime.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", limits, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = if (transport == .tls12) .tls12_only else .tls13_only,
        .tls_handshake_timeout = .fromSeconds(2),
    }, .fromSeconds(2));
    defer client.close();
    var parent = try client.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(2));
    defer parent.deinit(allocator);
    var bad = client.takePromisedRequest() orelse return error.MissingPromise;
    var bad_owned = true;
    defer if (bad_owned) bad.deinit(allocator);
    var good = client.takePromisedRequest() orelse return error.MissingPromise;
    defer good.deinit(allocator);
    if (failure == .late_data) {
        _ = try client.pingWithTimeout(.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .fromSeconds(2));
        var committed = try client.readPushedResponseWithTimeout(bad, .fromSeconds(2));
        defer committed.deinit(allocator);
        try std.testing.expectEqualStrings("ab", committed.body);
    } else if (failure == .cancel) {
        try client.cancelPush(&bad);
        bad_owned = false;
    } else try std.testing.expectError(switch (failure) {
        .reset => error.StreamReset,
        .malformed => error.InvalidContentLength,
        .quota => error.PushBufferFull,
        else => unreachable,
    }, client.readPushedResponseWithTimeout(bad, .fromSeconds(2)));
    try std.testing.expectEqual(window.default_value - @as(i64, if (failure == .late_data) 5 else 3), client.recv_connection_window.value);
    var sibling = try client.readPushedResponseWithTimeout(good, .fromSeconds(2));
    defer sibling.deinit(allocator);
    try std.testing.expectEqualStrings("xyz", sibling.body);
    var next = try client.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(2));
    defer next.deinit(allocator);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

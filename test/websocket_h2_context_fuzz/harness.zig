//! Shared cleartext and authenticated RFC 8441 WebSocket fuzz harness.

const std = @import("std");
const netz = @import("netz");
const support = @import("../websocket_live_context_support.zig");

const http2 = netz.http2.runtime;
const websocket = netz.websocket.runtime;

pub fn runSequence(bytes: []const u8) !support.Summary {
    return runSequenceWithTransport(bytes, false);
}

pub fn runTlsSequence(bytes: []const u8) !support.Summary {
    return runSequenceWithTransport(bytes, true);
}

fn runSequenceWithTransport(
    bytes: []const u8,
    comptime tls: bool,
) !support.Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const h2_limits: http2.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 16 * 1024,
        .initial_window_size = 16 * 1024,
        .initial_connection_window_size = 65_535,
        .enable_connect_protocol = true,
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const Server = if (tls) http2.TlsServer else http2.Server;
    var server: Server = if (tls)
        try http2.TlsServer.listen(
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
                .limits = h2_limits,
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .tls_handshake_timeout = support.io_timeout,
            },
        )
    else
        try http2.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            h2_limits,
        );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        bytes: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.acceptWithTimeout(support.io_timeout);
            defer h2.close();
            if (tls) try validateTls(&h2);
            var connection = try websocket.H2Server.acceptWithTimeout(
                self.server.allocator,
                &h2,
                .{
                    .enable_permessage_deflate = true,
                    .allow_context_takeover = true,
                    .compression_threshold = 0,
                    .limits = websocketLimits(),
                },
                support.io_timeout,
            );
            defer connection.close();
            if (tls) try validateTls(&connection);
            try support.runServer(
                self.server.allocator,
                &connection,
                self.bytes,
            );
            if (tls) try validateKeyUpdate(&connection);
        }
    };

    var shared = Shared{ .server = &server, .bytes = bytes };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = if (tls)
        try http2.Client.connectTlsAddressWithTimeout(
            allocator,
            io,
            server.address(),
            "localhost",
            "localhost",
            h2_limits,
            .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .tls_handshake_timeout = support.io_timeout,
            },
            support.io_timeout,
        )
    else
        try http2.Client.connectWithTimeout(
            allocator,
            io,
            server.address(),
            h2_limits,
            support.io_timeout,
        );
    defer h2_client.close();
    if (tls) try validateTls(&h2_client);
    var client = try websocket.H2Client.openWithTimeout(
        allocator,
        &h2_client,
        .{
            .authority = "localhost",
            .path = "/fuzz-context-takeover",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 0,
            .limits = websocketLimits(),
        },
        support.io_timeout,
    );
    defer client.close();
    if (tls) {
        try validateTls(&client);
        const chain = client.peerCertificates() orelse
            return error.MissingPeerCertificate;
        try std.testing.expectEqualSlices(u8, &certificate_der, chain[0]);
        try client.updateTrafficKeys(true);
    }
    const summary = try support.runClient(allocator, &client, bytes);
    if (tls) try validateKeyUpdate(&client);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    return summary;
}

fn websocketLimits() websocket.Limits {
    return .{
        .max_head_bytes = 4096,
        .max_frame_bytes = 2048,
        .max_message_bytes = support.max_message_bytes,
    };
}

fn validateTls(connection: anytype) !void {
    try std.testing.expectEqualStrings(
        "h2",
        connection.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.CipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        connection.negotiatedTranscriptHash().?,
    );
}

fn validateKeyUpdate(connection: anytype) !void {
    const counts = connection.keyUpdateCounts() orelse
        return error.MissingTlsState;
    try std.testing.expectEqual(@as(u64, 1), counts.sent);
    try std.testing.expectEqual(@as(u64, 1), counts.received);
    try std.testing.expect(!counts.awaiting_peer_response);
}

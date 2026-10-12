const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const bridge_mod = mqtt.bridge;
const runtime = mqtt.runtime;

pub fn Server(comptime tls: bool) type {
    return if (tls) mqtt.tls_runtime.Server else runtime.Server;
}

pub fn listen(
    comptime tls: bool,
    allocator: std.mem.Allocator,
    io: std.Io,
    certificate_chain: []const []const u8,
    key_pair: anytype,
) !Server(tls) {
    return if (tls)
        mqtt.tls_runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .identity = .{
                    .certificate_chain = certificate_chain,
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = .{ .max_packet_size = 4096 },
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"mqtt"},
                .tls_handshake_timeout = model.packet_timeout,
            },
        )
    else
        runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_packet_size = 4096 },
        );
}

pub fn tlsConnector(
    address: std.Io.net.IpAddress,
    public_key: [65]u8,
) mqtt.tls_runtime.ReconnectConnector {
    return .{
        .address = address,
        .tls_host = "localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = model.packet_timeout,
        },
    };
}

pub fn validateBridge(
    bridge: *bridge_mod.Bridge,
    certificate_der: []const u8,
) !void {
    const connection = bridge.client.connection() orelse
        return error.MissingRemoteConnection;
    try std.testing.expectEqualStrings(
        "mqtt",
        connection.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        connection.negotiatedTranscriptHash().?,
    );
    const chain = connection.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqual(@as(usize, 1), chain.len);
    try std.testing.expectEqualSlices(u8, certificate_der, chain[0]);
}

pub fn shutdownListener(server: anytype, io: std.Io) void {
    const stream: std.Io.net.Stream = .{ .socket = server.listener.socket };
    stream.shutdown(io, .both) catch {};
}

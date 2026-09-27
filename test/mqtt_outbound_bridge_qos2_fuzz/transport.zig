const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const mqtt = netz.mqtt;
const outbound = mqtt.bridge.outbound;
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

pub fn connect(
    comptime tls: bool,
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    client_id: []const u8,
    public_key: [65]u8,
) !runtime.Connection {
    const options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = client_id,
        .topic_alias_maximum = 0,
    };
    var connection = if (tls)
        try mqtt.tls_runtime.Client.connectAddressWithTimeout(
            allocator,
            io,
            address,
            "localhost",
            .{
                .mqtt = options,
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .alpn_protocols = &.{"mqtt"},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .tls_handshake_timeout = model.packet_timeout,
            },
            model.packet_timeout,
        )
    else
        try runtime.Client.connectWithTimeout(
            allocator,
            io,
            address,
            options,
            model.packet_timeout,
        );
    errdefer connection.close();
    if (tls) try validateConnection(&connection);
    return connection;
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

pub fn validateBridge(bridge: *outbound.Bridge) !void {
    try validateConnection(bridge.source.connection() orelse
        return error.MissingSourceConnection);
    try validateConnection(bridge.target.connection() orelse
        return error.MissingTargetConnection);
}

fn validateConnection(connection: *const runtime.Connection) !void {
    try std.testing.expectEqualStrings(
        "mqtt",
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

//! Raw server fixture for inspecting client-side TLS rejection on the wire.
const std = @import("std");
const quic = @import("../mod.zig");

pub const Mode = enum { alpn, finished, cipher, parameters, close };

pub const Server = struct {
    endpoint: *quic.runtime.Endpoint,
    mode: Mode,
    version: quic.Version,
    err: ?anyerror = null,

    pub fn run(self: *@This()) void {
        self.exchange() catch |err| {
            self.err = err;
        };
    }

    fn exchange(self: *@This()) !void {
        const allocator = std.testing.allocator;
        const keys = try quic.protection.deriveInitialSecretsForVersion(self.version.wireValue(), "peer-origin");
        var received = try quic.initial_exchange.receiveInitialCryptoFlight(self.endpoint, keys.client, .{
            .expected_packet_number = 0,
            .max_crypto_buffer = 4096,
            .deadline = .fromNow(self.endpoint.io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        });
        defer received.deinit(allocator);
        var parsed = try quic.tls_client_hello.parseClientHello(received.crypto_data);
        defer parsed.deinit(allocator);
        const server_secret = [_]u8{0x74} ** 32;
        const public_key = try @import("../tls/key_exchange.zig").x25519PublicKey(server_secret);
        var hello: std.ArrayList(u8) = .empty;
        defer hello.deinit(allocator);
        try quic.tls_client_hello.writeServerHello(&hello, allocator, .{
            .random = [_]u8{0x73} ** 32,
            .x25519_public_key = public_key,
            .cipher_suite = if (self.mode == .cipher) .aes_256_gcm_sha384 else .aes_128_gcm_sha256,
        });
        const shared = try @import("../tls/key_exchange.zig").x25519SharedSecret(server_secret, parsed.x25519_public_key);
        const transcript = quic.tls.transcript.hashFor(.sha256, &.{ received.crypto_data, hello.items });
        const handshake = try quic.tls_client_hello.deriveRuntimeHandshakeSecretsForVersion(self.version.wireValue(), .aes_128_gcm_sha256, shared, transcript, null);
        var parameters: std.ArrayList(u8) = .empty;
        defer parameters.deinit(allocator);
        var local = quic.practical_transport_parameters;
        local.original_destination_connection_id = "peer-origin";
        local.initial_source_connection_id = if (self.mode == .parameters) "wrong-server" else "peer-server";
        try quic.encodeTransportParametersForSource(&parameters, allocator, local, .server);
        var flight: std.ArrayList(u8) = .empty;
        defer flight.deinit(allocator);
        if (self.mode == .close) {
            try (quic.Frame{ .connection_close = .{ .error_code = 0x133, .frame_type = 0, .reason_phrase = "peer-close" } }).write(&flight, allocator);
            const close = try quic.protection.sealHandshakePacket(allocator, handshake.server_quic, .{
                .version = self.version.wireValue(),
                .destination_connection_id = "peer-client",
                .source_connection_id = "peer-server",
                .packet_number = 0,
                .payload = flight.items,
            });
            defer allocator.free(close);
            _ = try quic.initial_exchange.sendInitialCryptoFlight(self.endpoint, received.from, keys.server, .{
                .initial = .{ .version = self.version.wireValue(), .destination_connection_id = "peer-client", .source_connection_id = "peer-server", .packet_number = 0, .crypto_data = hello.items, .min_datagram_size = 1200 },
                .max_datagram_size = 1280,
            });
            const forged = try allocator.dupe(u8, close);
            defer allocator.free(forged);
            forged[forged.len - 1] ^= 0x80;
            try self.endpoint.sendBytes(received.from, forged);
            try self.endpoint.sendBytes(received.from, close);
            return;
        }
        try quic.tls_client_hello.writeEncryptedExtensions(&flight, allocator, if (self.mode == .alpn) "unsupported" else "h3", parameters.items);
        try quic.tls_client_hello.writeFinished(&flight, allocator, [_]u8{0} ** 32);
        if (self.mode == .cipher) {
            _ = try quic.initial_exchange.sendInitialCryptoFlight(self.endpoint, received.from, keys.server, .{
                .initial = .{ .version = self.version.wireValue(), .destination_connection_id = "peer-client", .source_connection_id = "peer-server", .packet_number = 0, .crypto_data = hello.items, .min_datagram_size = 1200 },
                .max_datagram_size = 1280,
            });
        } else {
            _ = try quic.initial_exchange.sendInitialThenHandshakeCrypto(self.endpoint, received.from, keys.server, .{
                .initial = .{ .version = self.version.wireValue(), .destination_connection_id = "peer-client", .source_connection_id = "peer-server", .packet_number = 0, .crypto_data = hello.items, .min_datagram_size = 1200 },
                .max_datagram_size = 1280,
            }, handshake.server_quic, .{
                .packet_number = 0,
                .version = self.version.wireValue(),
                .destination_connection_id = "peer-client",
                .source_connection_id = "peer-server",
                .crypto_data = flight.items,
            });
        }
        var bytes = try self.endpoint.receiveBytesWithTimeout(.fromSeconds(2));
        defer bytes.deinit(allocator);
        const expected_code: u64 = switch (self.mode) {
            .alpn => 0x178,
            .finished => 0x133,
            .cipher => 0x12f,
            .parameters => 0x08,
            .close => unreachable,
        };
        if (self.mode == .cipher) {
            try std.testing.expect(bytes.bytes.len >= 1200);
            var packet = try quic.protection.openInitialPacket(allocator, keys.client, bytes.bytes, received.next_expected_packet_number);
            defer packet.deinit(allocator);
            try std.testing.expectEqual(received.next_expected_packet_number, packet.packet_number);
            try std.testing.expectEqual(expected_code, (try quic.parseFrame(packet.payload)).frame.connection_close.error_code);
        } else {
            var packet = try quic.protection.openHandshakePacket(allocator, handshake.client_quic, bytes.bytes, 0);
            defer packet.deinit(allocator);
            try std.testing.expectEqual(expected_code, (try quic.parseFrame(packet.payload)).frame.connection_close.error_code);
        }
    }
};

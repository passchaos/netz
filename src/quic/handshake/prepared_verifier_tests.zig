const std = @import("std");
const vail = @import("vail");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");
const tls_testing = @import("../../tls/testing.zig");

const PreparedP256Mode = enum {
    matching,
    mismatched,
};

fn expectPreparedP256Handshake(mode: PreparedP256Mode) !void {
    const allocator = std.testing.allocator;
    const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const server_key = try tls_testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    const prepared = switch (mode) {
        .matching => try vail.crypto.p256.PreparedVerifier.init(
            server_key.public_key.p,
        ),
        .mismatched => mismatch: {
            const other_key = try EcdsaP256Sha256.KeyPair.generateDeterministic(
                [_]u8{0x97} ** EcdsaP256Sha256.KeyPair.seed_length,
            );
            break :mismatch try vail.crypto.p256.PreparedVerifier.init(
                other_key.public_key.p,
            );
        },
    };

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        server_public: []const u8,
        server_key: EcdsaP256Sha256.KeyPair,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var established = handshake.acceptWithTimeout(
                self.endpoint,
                .{
                    .local_connection_id = "prepared-server",
                    .alpn_protocol = "prepared-p256",
                    .identity = .{
                        .certificate_chain = &.{self.server_public},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = self.server_key,
                        } },
                    },
                    .random = [_]u8{0x91} ** 32,
                    .x25519_secret_key = [_]u8{0x92} ** 32,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 500,
                    },
                },
                .fromMilliseconds(500),
            ) catch |err| {
                self.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .server_public = &server_public,
        .server_key = server_key,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_err: ?anyerror = null;
    var established: ?handshake.EstablishedConnection =
        handshake.connectWithTimeout(
            &client_endpoint,
            server_endpoint.address(),
            .{
                .original_destination_connection_id = "prepared",
                .local_connection_id = "client",
                .server_name = "localhost",
                .alpn_protocols = &.{"prepared-p256"},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = server_public,
                    .prepared_p256_verifier = &prepared,
                },
                .random = [_]u8{0x93} ** 32,
                .x25519_secret_key = [_]u8{0x94} ** 32,
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 500,
                },
            },
            .fromMilliseconds(500),
        ) catch |err| failed: {
            client_err = err;
            break :failed null;
        };
    defer if (established) |*connection| connection.deinit();

    thread.join();
    switch (mode) {
        .matching => {
            if (client_err) |err| return err;
            try std.testing.expect(established != null);
            if (shared.err) |err| return err;
        },
        .mismatched => {
            try std.testing.expectEqual(
                @as(?anyerror, error.InvalidCertificate),
                client_err,
            );
            try std.testing.expect(established == null);
            try std.testing.expectEqual(
                @as(?anyerror, error.ConnectionClosed),
                shared.err,
            );
        },
    }
}

test "QUIC handshake uses matching prepared P-256 verifier" {
    try expectPreparedP256Handshake(.matching);
}

test "QUIC handshake rejects mismatched prepared P-256 verifier" {
    try expectPreparedP256Handshake(.mismatched);
}

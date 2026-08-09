const std = @import("std");
const tls = @import("mod.zig");
const quic = @import("../mod.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const IntegratedResult = struct {
    client_err: ?anyerror,
    server_err: ?anyerror,
};

test "TLS Certificate and Ed25519 CertificateVerify round-trip" {
    const allocator = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x42} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();

    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try tls.auth.writeCertificate(
        &certificate,
        allocator,
        &.{&public_key},
    );
    var parsed_certificate = try tls.auth.parseCertificate(
        allocator,
        certificate.items,
    );
    defer parsed_certificate.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), parsed_certificate.entries.len);
    try std.testing.expectEqualSlices(
        u8,
        &public_key,
        parsed_certificate.entries[0],
    );

    const transcript_hash = [_]u8{0x33} ** 32;
    var certificate_verify: std.ArrayList(u8) = .empty;
    defer certificate_verify.deinit(allocator);
    try tls.auth.writeCertificateVerify(
        &certificate_verify,
        allocator,
        key_pair,
        transcript_hash,
        null,
    );
    const parsed_verify = try tls.auth.parseCertificateVerify(
        certificate_verify.items,
    );
    try tls.auth.verifyCertificateVerify(
        parsed_certificate.entries[0],
        parsed_verify,
        transcript_hash,
    );

    var wrong_hash = transcript_hash;
    wrong_hash[0] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        tls.auth.verifyCertificateVerify(
            parsed_certificate.entries[0],
            parsed_verify,
            wrong_hash,
        ),
    );
    var tampered_signature = parsed_verify.signature[0..64].*;
    tampered_signature[0] ^= 1;
    try std.testing.expectError(
        error.BadCertificateVerify,
        tls.auth.verifyCertificateVerify(
            parsed_certificate.entries[0],
            .{
                .scheme = parsed_verify.scheme,
                .signature = &tampered_signature,
            },
            transcript_hash,
        ),
    );
}

test "TLS Certificate codec rejects malformed vectors" {
    try std.testing.expectError(
        error.EmptyCertificateChain,
        tls.auth.parseCertificate(std.testing.allocator, &.{
            tls.auth.handshake_type_certificate,
            0,
            0,
            4,
            0,
            0,
            0,
            0,
        }),
    );
    try std.testing.expectError(
        error.InvalidCertificateVerify,
        tls.auth.parseCertificateVerify(&.{
            tls.auth.handshake_type_certificate_verify,
            0,
            0,
            4,
            0x08,
            0x07,
            0,
            0,
        }),
    );
}

fn checkAuthAllocationFailure(allocator: std.mem.Allocator) !void {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x55} ** Ed25519.KeyPair.seed_length,
    );
    const public_key = key_pair.public_key.toBytes();
    var certificate: std.ArrayList(u8) = .empty;
    defer certificate.deinit(allocator);
    try tls.auth.writeCertificate(
        &certificate,
        allocator,
        &.{&public_key},
    );
    var parsed = try tls.auth.parseCertificate(
        allocator,
        certificate.items,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &public_key, parsed.entries[0]);
}

test "TLS Certificate codec is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAuthAllocationFailure,
        .{},
    );
}

test "TLS pinned Ed25519 verifier rejects a different leaf key" {
    const trusted = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x61} ** Ed25519.KeyPair.seed_length,
    );
    const untrusted = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x62} ** Ed25519.KeyPair.seed_length,
    );
    const trusted_key = trusted.public_key.toBytes();
    const untrusted_key = untrusted.public_key.toBytes();
    const verifier = tls.auth.ClientVerifier{
        .pinned_ed25519_public_key = trusted_key,
    };
    try verifier.verifyTrust("example.test", &.{&trusted_key});
    try std.testing.expectError(
        error.CertificateUntrusted,
        verifier.verifyTrust("example.test", &.{&untrusted_key}),
    );
}

test "QUIC integrated handshake authenticates Ed25519 CertificateVerify" {
    const result = try runIntegratedAuth(.valid);
    if (result.server_err) |err| return err;
    if (result.client_err) |err| return err;
}

test "QUIC integrated handshake rejects a mismatched pinned identity" {
    const result = try runIntegratedAuth(.wrong_pin);
    try std.testing.expectEqualStrings(
        "CertificateUntrusted",
        @errorName(result.client_err orelse return error.TestUnexpectedResult),
    );
    try std.testing.expect(result.server_err != null);
}

test "TLS X509 bundle verifies chain hostname and validity" {
    const server_der = @embedFile("testdata/server.der");
    const ca_der = @embedFile("testdata/ca.der");
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, ca_der);
    try bundle.parseCert(
        std.testing.allocator,
        0,
        1_900_000_000,
    );
    const verifier = tls.trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 1_900_000_000,
    };
    try verifier.verify(.{
        .server_name = "localhost",
        .chain = &.{server_der},
    });
    try std.testing.expectError(
        error.CertificateHostMismatch,
        verifier.verify(.{
            .server_name = "other.example",
            .chain = &.{server_der},
        }),
    );
    const expired = tls.trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = 2_200_000_000,
    };
    try std.testing.expectError(
        error.CertificateExpired,
        expired.verify(.{
            .server_name = "localhost",
            .chain = &.{server_der},
        }),
    );
}

const IntegratedMode = enum {
    valid,
    wrong_pin,
};

fn runIntegratedAuth(mode: IntegratedMode) !IntegratedResult {
    const allocator = std.testing.allocator;
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

    const trusted = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x71} ** Ed25519.KeyPair.seed_length,
    );
    const other = try Ed25519.KeyPair.generateDeterministic(
        [_]u8{0x72} ** Ed25519.KeyPair.seed_length,
    );
    const trusted_public = trusted.public_key.toBytes();
    const other_public = other.public_key.toBytes();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        certificate: *const [Ed25519.PublicKey.encoded_length]u8,
        signing_key: Ed25519.KeyPair,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x73} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
                .identity = .{
                    .certificate_chain = &.{shared.certificate},
                    .signing_key = shared.signing_key,
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .certificate = &trusted_public,
        .signing_key = trusted,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const pin = if (mode == .wrong_pin) other_public else trusted_public;
    var client_err: ?anyerror = null;
    var established = quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "auth0001",
            .local_connection_id = "client",
            .server_name = "example.test",
            .random = [_]u8{0x75} ** 32,
            .x25519_secret_key = [_]u8{0x76} ** 32,
            .server_auth = .{
                .pinned_ed25519_public_key = pin,
            },
        },
    ) catch |err| blk: {
        client_err = err;
        // The server waits for client Finished after an authentication error.
        try client_endpoint.sendBytes(server_endpoint.address(), "invalid");
        break :blk null;
    };
    if (established) |*connection| connection.deinit();
    thread.join();
    return .{
        .client_err = client_err,
        .server_err = shared.err,
    };
}

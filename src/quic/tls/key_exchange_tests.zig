const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("../tls_client_hello.zig");

test "QUIC TLS secp384r1 key shares round-trip without truncation" {
    const allocator = std.testing.allocator;
    const x25519_secret = [_]u8{0x41} ** 32;
    const x25519_public = try target.x25519PublicKey(x25519_secret);
    const p256_secret = [_]u8{0} ** 31 ++ [_]u8{1};
    const p256_public = try target.p256PublicKey(p256_secret);
    const client_secret = [_]u8{0} ** 47 ++ [_]u8{1};
    const server_secret = [_]u8{0} ** 47 ++ [_]u8{2};
    const client_public = try target.p384PublicKey(client_secret);
    const server_public = try target.p384PublicKey(server_secret);
    const shares = [_]target.KeyShare{
        .{ .x25519 = x25519_public },
        .{ .secp256r1 = p256_public },
        .{ .secp384r1 = client_public },
    };

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try target.writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x42} ** 32,
        .x25519_public_key = x25519_public,
        .key_shares = &shares,
        .transport_parameters = &.{},
    });
    var parsed_client = try target.parseClientHello(
        allocator,
        client_hello.items,
    );
    defer parsed_client.deinit(allocator);
    try std.testing.expect(parsed_client.supports_secp384r1);
    try std.testing.expectEqualSlices(
        u8,
        &client_public,
        parsed_client.keyShare(.secp384r1).?,
    );
    try std.testing.expectEqual(
        target.NamedGroup.secp384r1,
        try target.selectKeyShare(parsed_client, &.{.secp384r1}),
    );
    var invalid_client_hello = try client_hello.clone(allocator);
    defer invalid_client_hello.deinit(allocator);
    const client_public_offset = std.mem.indexOf(
        u8,
        invalid_client_hello.items,
        &client_public,
    ) orelse return error.TestUnexpectedResult;
    invalid_client_hello.items[client_public_offset] = 0x02;
    try std.testing.expectError(
        error.InvalidClientHello,
        target.parseClientHello(allocator, invalid_client_hello.items),
    );

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x43} ** 32,
        .x25519_public_key = [_]u8{0} ** 32,
        .key_share = .{ .secp384r1 = server_public },
        .cipher_suite = .aes_256_gcm_sha384,
    });
    const parsed_server = try target.parseServerHello(server_hello.items);
    try std.testing.expectEqual(
        target.NamedGroup.secp384r1,
        parsed_server.selected_group,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_public,
        parsed_server.keyShare(),
    );
    var invalid_server_hello = try server_hello.clone(allocator);
    defer invalid_server_hello.deinit(allocator);
    const server_public_offset = std.mem.indexOf(
        u8,
        invalid_server_hello.items,
        &server_public,
    ) orelse return error.TestUnexpectedResult;
    invalid_server_hello.items[server_public_offset] = 0x02;
    try std.testing.expectError(
        error.MissingKeyShare,
        target.parseServerHello(invalid_server_hello.items),
    );

    const client_shared = try target.p384SharedSecret(
        client_secret,
        parsed_server.keyShare(),
    );
    const server_shared = try target.p384SharedSecret(
        server_secret,
        parsed_client.keyShare(.secp384r1).?,
    );
    try std.testing.expectEqual(@as(usize, 48), client_shared.len);
    try std.testing.expectEqualSlices(
        u8,
        &client_shared,
        &server_shared,
    );

    // Exercise the runtime key-schedule boundary with all 48 ECDH bytes.
    const transcript_hash = quic.tls.transcript.hashFor(
        .sha384,
        &.{ client_hello.items, server_hello.items },
    );
    const client_handshake =
        try target.deriveRuntimeHandshakeSecretsFromSliceForVersion(
            quic.Version.version_1.wireValue(),
            .aes_256_gcm_sha384,
            &client_shared,
            transcript_hash,
            null,
        );
    const server_handshake =
        try target.deriveRuntimeHandshakeSecretsFromSliceForVersion(
            quic.Version.version_1.wireValue(),
            .aes_256_gcm_sha384,
            &server_shared,
            transcript_hash,
            null,
        );
    try std.testing.expect(
        client_handshake.handshake_secret.eql(
            &server_handshake.handshake_secret,
        ),
    );
}

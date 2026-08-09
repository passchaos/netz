const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("../tls_client_hello.zig");
const adapter = @import("key_exchange.zig");

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

test "QUIC TLS X25519MLKEM768 codecs enforce asymmetric share lengths" {
    const allocator = std.testing.allocator;
    const Hybrid = quic.tls.key_exchange.x25519_mlkem768;
    var client = try target.x25519MlKem768ClientStart(
        [_]u8{0x61} ** Hybrid.x25519_secret_len,
        [_]u8{0x62} ** Hybrid.mlkem_seed_len,
    );
    defer client.secret.wipe();
    var response = try target.x25519MlKem768ServerRespond(
        &client.share,
        [_]u8{0x63} ** Hybrid.x25519_secret_len,
        [_]u8{0x64} ** Hybrid.encaps_seed_len,
    );
    defer response.wipeSharedSecret();
    const client_shared = try target.x25519MlKem768ClientSharedSecret(
        &client.secret,
        &response.share,
    );
    try std.testing.expectEqualSlices(
        u8,
        &response.shared_secret,
        &client_shared,
    );

    const shares = [_]target.KeyShare{
        .{ .x25519_mlkem768_client = client.share },
    };
    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try target.writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x65} ** 32,
        .x25519_public_key = [_]u8{0} ** 32,
        .key_shares = &shares,
        .transport_parameters = &.{},
    });
    var parsed_client = try target.parseClientHello(
        allocator,
        client_hello.items,
    );
    defer parsed_client.deinit(allocator);
    try std.testing.expect(parsed_client.supports_x25519_mlkem768);
    try std.testing.expectEqualSlices(
        u8,
        &client.share,
        parsed_client.keyShare(.x25519_mlkem768).?,
    );

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x66} ** 32,
        .x25519_public_key = [_]u8{0} ** 32,
        .key_share = .{ .x25519_mlkem768_server = response.share },
    });
    const parsed_server = try target.parseServerHello(server_hello.items);
    try std.testing.expectEqual(
        target.NamedGroup.x25519_mlkem768,
        parsed_server.selected_group,
    );
    try std.testing.expectEqualSlices(
        u8,
        &response.share,
        parsed_server.keyShare(),
    );

    // The two role-specific shares have different lengths. Writers reject a
    // share in the wrong Hello instead of producing a locally consistent but
    // non-interoperable handshake.
    const wrong_client_share = [_]target.KeyShare{
        .{ .x25519_mlkem768_server = response.share },
    };
    var wrong_client: std.ArrayList(u8) = .empty;
    defer wrong_client.deinit(allocator);
    try std.testing.expectError(
        error.InvalidClientHello,
        target.writeClientHello(&wrong_client, allocator, .{
            .random = [_]u8{0x67} ** 32,
            .x25519_public_key = [_]u8{0} ** 32,
            .key_shares = &wrong_client_share,
            .transport_parameters = &.{},
        }),
    );
    var wrong_server: std.ArrayList(u8) = .empty;
    defer wrong_server.deinit(allocator);
    try std.testing.expectError(
        error.InvalidServerHello,
        target.writeServerHello(&wrong_server, allocator, .{
            .random = [_]u8{0x68} ** 32,
            .x25519_public_key = [_]u8{0} ** 32,
            .key_share = .{ .x25519_mlkem768_client = client.share },
        }),
    );

    var malformed_client = try client_hello.clone(allocator);
    defer malformed_client.deinit(allocator);
    const client_share_offset = std.mem.indexOf(
        u8,
        malformed_client.items,
        &client.share,
    ) orelse return error.TestUnexpectedResult;
    const client_share_length_offset = client_share_offset - 2;
    std.mem.writeInt(
        u16,
        malformed_client.items[client_share_length_offset..][0..2],
        Hybrid.client_share_len - 1,
        .big,
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        target.parseClientHello(allocator, malformed_client.items),
    );

    var malformed_server = try server_hello.clone(allocator);
    defer malformed_server.deinit(allocator);
    const server_share_offset = std.mem.indexOf(
        u8,
        malformed_server.items,
        &response.share,
    ) orelse return error.TestUnexpectedResult;
    const server_share_length_offset = server_share_offset - 2;
    std.mem.writeInt(
        u16,
        malformed_server.items[server_share_length_offset..][0..2],
        Hybrid.server_share_len - 1,
        .big,
    );
    try std.testing.expectError(
        error.InvalidServerHello,
        target.parseServerHello(malformed_server.items),
    );
}

fn testNistHybridCodecs(
    comptime Hybrid: type,
    comptime group: target.NamedGroup,
    comptime client_share_field: []const u8,
    comptime server_share_field: []const u8,
    client_curve_secret: [Hybrid.curve_secret_len]u8,
    server_curve_secret: [Hybrid.curve_secret_len]u8,
    mlkem_seed: [Hybrid.mlkem_seed_len]u8,
    encaps_seed: [Hybrid.encaps_seed_len]u8,
) !void {
    const allocator = std.testing.allocator;
    var client = try adapter.hybridClientStart(
        Hybrid,
        client_curve_secret,
        mlkem_seed,
    );
    defer client.secret.wipe();
    var response = try adapter.hybridServerRespond(
        Hybrid,
        &client.share,
        server_curve_secret,
        encaps_seed,
    );
    defer response.wipeSharedSecret();
    var client_shared = try adapter.hybridClientSharedSecret(
        Hybrid,
        &client.secret,
        &response.share,
    );
    defer std.crypto.secureZero(u8, &client_shared);
    try std.testing.expectEqualSlices(
        u8,
        &response.shared_secret,
        &client_shared,
    );
    try std.testing.expectEqual(Hybrid.client_share_len, client.share.len);
    try std.testing.expectEqual(Hybrid.server_share_len, response.share.len);
    try std.testing.expectEqual(Hybrid.shared_len, client_shared.len);
    // Both registered NIST hybrids are classical-first. Enforcing the SEC1
    // marker at the QUIC/TLS codec boundary catches accidental use of the
    // ML-KEM-first X25519MLKEM768 layout before Vail performs curve parsing.
    try std.testing.expectEqual(@as(u8, 0x04), client.share[0]);
    try std.testing.expectEqual(@as(u8, 0x04), response.share[0]);

    const client_key_share = @unionInit(
        target.KeyShare,
        client_share_field,
        client.share,
    );
    const client_shares = [_]target.KeyShare{client_key_share};
    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try target.writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x71} ** 32,
        .x25519_public_key = [_]u8{0} ** 32,
        .key_shares = &client_shares,
        .transport_parameters = &.{},
    });
    var parsed_client = try target.parseClientHello(
        allocator,
        client_hello.items,
    );
    defer parsed_client.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &client.share,
        parsed_client.keyShare(group).?,
    );
    try std.testing.expectEqual(
        group,
        try target.selectKeyShare(parsed_client, &.{group}),
    );

    const server_key_share = @unionInit(
        target.KeyShare,
        server_share_field,
        response.share,
    );
    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x72} ** 32,
        .x25519_public_key = [_]u8{0} ** 32,
        .key_share = server_key_share,
    });
    const parsed_server = try target.parseServerHello(server_hello.items);
    try std.testing.expectEqual(group, parsed_server.selected_group);
    try std.testing.expectEqualSlices(
        u8,
        &response.share,
        parsed_server.keyShare(),
    );

    // Hybrid client and server shares are role-specific even when a group
    // happens to use equal lengths (secp384r1MLKEM1024 does). Writers must not
    // infer the role from size and emit a semantically invalid Hello.
    const wrong_client_shares = [_]target.KeyShare{server_key_share};
    var wrong_client: std.ArrayList(u8) = .empty;
    defer wrong_client.deinit(allocator);
    try std.testing.expectError(
        error.InvalidClientHello,
        target.writeClientHello(&wrong_client, allocator, .{
            .random = [_]u8{0x73} ** 32,
            .x25519_public_key = [_]u8{0} ** 32,
            .key_shares = &wrong_client_shares,
            .transport_parameters = &.{},
        }),
    );
    var wrong_server: std.ArrayList(u8) = .empty;
    defer wrong_server.deinit(allocator);
    try std.testing.expectError(
        error.InvalidServerHello,
        target.writeServerHello(&wrong_server, allocator, .{
            .random = [_]u8{0x74} ** 32,
            .x25519_public_key = [_]u8{0} ** 32,
            .key_share = client_key_share,
        }),
    );

    var malformed_client = try client_hello.clone(allocator);
    defer malformed_client.deinit(allocator);
    const client_share_offset = std.mem.indexOf(
        u8,
        malformed_client.items,
        &client.share,
    ) orelse return error.TestUnexpectedResult;
    std.mem.writeInt(
        u16,
        malformed_client.items[client_share_offset - 2 ..][0..2],
        @intCast(Hybrid.client_share_len - 1),
        .big,
    );
    try std.testing.expectError(
        error.InvalidClientHello,
        target.parseClientHello(allocator, malformed_client.items),
    );

    var malformed_server = try server_hello.clone(allocator);
    defer malformed_server.deinit(allocator);
    const server_share_offset = std.mem.indexOf(
        u8,
        malformed_server.items,
        &response.share,
    ) orelse return error.TestUnexpectedResult;
    std.mem.writeInt(
        u16,
        malformed_server.items[server_share_offset - 2 ..][0..2],
        @intCast(Hybrid.server_share_len - 1),
        .big,
    );
    try std.testing.expectError(
        error.InvalidServerHello,
        target.parseServerHello(malformed_server.items),
    );

    var invalid_sec1_client = try client_hello.clone(allocator);
    defer invalid_sec1_client.deinit(allocator);
    const invalid_client_offset = std.mem.indexOf(
        u8,
        invalid_sec1_client.items,
        &client.share,
    ) orelse return error.TestUnexpectedResult;
    invalid_sec1_client.items[invalid_client_offset] = 0x02;
    try std.testing.expectError(
        error.InvalidClientHello,
        target.parseClientHello(allocator, invalid_sec1_client.items),
    );

    var invalid_sec1_server = try server_hello.clone(allocator);
    defer invalid_sec1_server.deinit(allocator);
    const invalid_server_offset = std.mem.indexOf(
        u8,
        invalid_sec1_server.items,
        &response.share,
    ) orelse return error.TestUnexpectedResult;
    invalid_sec1_server.items[invalid_server_offset] = 0x02;
    try std.testing.expectError(
        error.MissingKeyShare,
        target.parseServerHello(invalid_sec1_server.items),
    );
}

test "QUIC TLS secp256r1MLKEM768 codecs preserve registered layout" {
    const Hybrid = quic.tls.key_exchange.secp256r1_mlkem768;
    try std.testing.expectEqual(@as(u16, 0x11eb), Hybrid.named_group);
    try testNistHybridCodecs(
        Hybrid,
        .secp256r1_mlkem768,
        "secp256r1_mlkem768_client",
        "secp256r1_mlkem768_server",
        [_]u8{0} ** 31 ++ [_]u8{1},
        [_]u8{0} ** 31 ++ [_]u8{2},
        [_]u8{0x75} ** Hybrid.mlkem_seed_len,
        [_]u8{0x76} ** Hybrid.encaps_seed_len,
    );
}

test "QUIC TLS secp384r1MLKEM1024 codecs preserve registered layout" {
    const Hybrid = quic.tls.key_exchange.secp384r1_mlkem1024;
    try std.testing.expectEqual(@as(u16, 0x11ed), Hybrid.named_group);
    try testNistHybridCodecs(
        Hybrid,
        .secp384r1_mlkem1024,
        "secp384r1_mlkem1024_client",
        "secp384r1_mlkem1024_server",
        [_]u8{0} ** 47 ++ [_]u8{1},
        [_]u8{0} ** 47 ++ [_]u8{2},
        [_]u8{0x77} ** Hybrid.mlkem_seed_len,
        [_]u8{0x78} ** Hybrid.encaps_seed_len,
    );
}

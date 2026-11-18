const std = @import("std");
const server_identity_file_root = @import("../server_identity_file.zig");

const vail = @import("vail");

const Ed25519 = server_identity_file_root.Ed25519;
const certificate_pem = server_identity_file_root.certificate_pem;
const encodePemForTest = server_identity_file_root.encodePemForTest;
const encodePrivateKeyForTest = server_identity_file_root.encodePrivateKeyForTest;
const load = server_identity_file_root.load;
const parse = server_identity_file_root.parse;
const parsePrivateKeyDer = server_identity_file_root.parsePrivateKeyDer;
const pkcs8_private_key_pem = server_identity_file_root.pkcs8_private_key_pem;
const sec1_private_key_pem = server_identity_file_root.sec1_private_key_pem;

test "server identity file parses SEC1 and PKCS8 P-256 keys" {
    inline for (.{ sec1_private_key_pem, pkcs8_private_key_pem }) |key_pem| {
        var identity = try parse(std.testing.allocator, certificate_pem, key_pem);
        defer identity.deinit();
        try std.testing.expectEqual(@as(usize, 1), identity.certificate_chain.len);
        try identity.serverIdentity().validate();
    }
}

test "server identity file parses P-384 and Ed25519 PKCS8 keys" {
    const p384_der_hex =
        "3081b6020100301006072a8648ce3d020106052b8104002204819e" ++
        "30819b0201010430f70d151aad5ced2202849b19e262d2bfa65ead" ++
        "11d8a025e7657c6e8b004ea0b37f79ac927be2bc1c06a0ce607da" ++
        "62b46a164036200046221b2d856a7fe4295357509134a3eabae4f7" ++
        "8889e1244a2158c19c10dab58c3269cc5b467396a2093b5dfa3e3" ++
        "635106215c5586c1d99be9087fb2448f2dd4e4a061f5556884e028" ++
        "ee2b5d095ec2a897f3a588e1238e7c62160313e6cd8c65d8";
    var p384_der: [p384_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p384_der, p384_der_hex);
    var p384 = try parsePrivateKeyDer(
        std.testing.allocator,
        .pkcs8,
        &p384_der,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&p384));
    try std.testing.expect(p384 == .ecdsa_p384_sha384);

    const ed25519_der_hex =
        "302e020100300506032b657004220420" ++
        "85aefc9f41a80df3cad89138c8dfa7f4f33b3b8485a60092b833a08640c903b6";
    var ed25519_der: [ed25519_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ed25519_der, ed25519_der_hex);
    var ed25519 = try parsePrivateKeyDer(
        std.testing.allocator,
        .pkcs8,
        &ed25519_der,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ed25519));
    try std.testing.expect(ed25519 == .ed25519);
}

test "server identity file parses RSA PKCS8 and PKCS1 keys" {
    const allocator = std.testing.allocator;
    const vectors = vail.crypto.testing.rsa_signing;
    var certificate_der: [vectors.certificate_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&certificate_der, vectors.certificate_hex);
    const certificate = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        &certificate_der,
    );
    defer allocator.free(certificate);

    for ([_]struct {
        label: []const u8,
        encoded: []const u8,
    }{
        .{ .label = "PRIVATE KEY", .encoded = vectors.private_key_pkcs8_hex },
        .{ .label = "RSA PRIVATE KEY", .encoded = vectors.private_key_pkcs1_hex },
    }) |case| {
        const der = try allocator.alloc(u8, case.encoded.len / 2);
        defer {
            std.crypto.secureZero(u8, der);
            allocator.free(der);
        }
        _ = try std.fmt.hexToBytes(der, case.encoded);
        const private_key = try encodePemForTest(allocator, case.label, der);
        defer {
            std.crypto.secureZero(u8, private_key);
            allocator.free(private_key);
        }
        var identity = try parse(allocator, certificate, private_key);
        defer identity.deinit();
        try std.testing.expect(identity.key_pair == .rsa_pss);
        try std.testing.expectEqual(
            @as(usize, 256),
            identity.key_pair.rsa_pss.prepared.signatureLength(),
        );
        try identity.serverIdentity().validate();
    }
}

test "server identity file rejects an RSA key for an EC certificate" {
    const allocator = std.testing.allocator;
    const encoded = vail.crypto.testing.rsa_signing.private_key_pkcs8_hex;
    const der = try allocator.alloc(u8, encoded.len / 2);
    defer {
        std.crypto.secureZero(u8, der);
        allocator.free(der);
    }
    _ = try std.fmt.hexToBytes(der, encoded);
    const private_key = try encodePemForTest(allocator, "PRIVATE KEY", der);
    defer {
        std.crypto.secureZero(u8, private_key);
        allocator.free(private_key);
    }
    try std.testing.expectError(
        error.CertificateKeyMismatch,
        parse(allocator, certificate_pem, private_key),
    );
}

test "server identity file parses a constrained RSA-PSS PKCS8 key" {
    const allocator = std.testing.allocator;
    const certificate = try encodePemForTest(
        allocator,
        "CERTIFICATE",
        vail.x509.testing.rsa_pss_constrained_leaf,
    );
    defer allocator.free(certificate);
    const private_key = try encodePemForTest(
        allocator,
        "PRIVATE KEY",
        vail.x509.testing.rsa_pss_constrained_private_key,
    );
    defer {
        std.crypto.secureZero(u8, private_key);
        allocator.free(private_key);
    }
    var identity = try parse(allocator, certificate, private_key);
    defer identity.deinit();
    try std.testing.expect(identity.key_pair == .rsa_pss);
    try identity.serverIdentity().validate();
}

test "server identity file parses a P-384 SEC1 key" {
    const der_hex =
        "3081a40201010430fd54b21ecf364a932c6e4aff7c014767c08ee4c2" ++
        "133451524423b6192bcb8088d097018dd6cd279fe8589841aac20167" ++
        "a00706052b81040022a164036200049aedd7293ee3a6be895ecc021a" ++
        "ee391ce0951a360c26f58b863cb8fa0a815d7f6ab1dc2a67858a55" ++
        "3b1e084f698abaafc841f103b475ec7eb33a4f1e1041d18d92008c" ++
        "5b10de8d6317bd44ff1214f00a6da9acc864a16dc14293bb380497c" ++
        "48d";
    var der: [der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&der, der_hex);
    var key = try parsePrivateKeyDer(
        std.testing.allocator,
        .sec1,
        &der,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    try std.testing.expect(key == .ecdsa_p384_sha384);
}

test "server identity file rejects unsupported and malformed modern private keys" {
    const ed25519_der_hex =
        "302e020100300506032b657004220420" ++
        "85aefc9f41a80df3cad89138c8dfa7f4f33b3b8485a60092b833a08640c903b6";
    var ed25519_der: [ed25519_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ed25519_der, ed25519_der_hex);
    ed25519_der[10] = 0x05;
    try std.testing.expectError(
        error.UnsupportedPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .pkcs8, &ed25519_der),
    );

    const p384_der_hex =
        "3081b6020100301006072a8648ce3d020106052b8104002204819e" ++
        "30819b0201010430f70d151aad5ced2202849b19e262d2bfa65ead" ++
        "11d8a025e7657c6e8b004ea0b37f79ac927be2bc1c06a0ce607da" ++
        "62b46a164036200046221b2d856a7fe4295357509134a3eabae4f7" ++
        "8889e1244a2158c19c10dab58c3269cc5b467396a2093b5dfa3e3" ++
        "635106215c5586c1d99be9087fb2448f2dd4e4a061f5556884e028" ++
        "ee2b5d095ec2a897f3a588e1238e7c62160313e6cd8c65d8";
    var p384_der: [p384_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p384_der, p384_der_hex);
    p384_der[33] ^= 1;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .pkcs8, &p384_der),
    );
}

test "server identity file preserves a leaf-first certificate chain" {
    const chain_pem = certificate_pem ++ "\n" ++ certificate_pem;
    var identity = try parse(
        std.testing.allocator,
        chain_pem,
        sec1_private_key_pem,
    );
    defer identity.deinit();
    try std.testing.expectEqual(@as(usize, 2), identity.certificate_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        identity.certificate_chain[0],
        identity.certificate_chain[1],
    );
}

test "server identity file loads certificate and key files" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "server.crt",
        .data = certificate_pem,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "server.key",
        .data = pkcs8_private_key_pem,
    });
    var identity = try load(
        std.testing.allocator,
        io,
        tmp.dir,
        "server.crt",
        "server.key",
    );
    defer identity.deinit();
    try identity.serverIdentity().validate();
}

test "server identity file rejects mismatched certificate and key" {
    const mismatched_key =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MDECAQEEIBI0VniavN7xI0VniavN7xI0VniavN7xI0VniavN7xI1oAoG
        \\CCqGSM49AwEH
        \\-----END EC PRIVATE KEY-----
    ;
    try std.testing.expectError(
        error.CertificateKeyMismatch,
        parse(std.testing.allocator, certificate_pem, mismatched_key),
    );
}

test "server identity file rejects malformed PEM and unsupported labels" {
    try std.testing.expectError(
        error.EmptyCertificateChain,
        parse(std.testing.allocator, "", sec1_private_key_pem),
    );
    try std.testing.expectError(
        error.InvalidCertificate,
        parse(
            std.testing.allocator,
            "-----BEGIN CERTIFICATE-----\nAA==\n" ++
                "-----END CERTIFICATE-----\n",
            sec1_private_key_pem,
        ),
    );
    try std.testing.expectError(
        error.InvalidPem,
        parse(std.testing.allocator, certificate_pem, "-----BEGIN PRIVATE KEY-----\nAA==\n"),
    );
    try std.testing.expectError(
        error.EncryptedPrivateKeyPasswordRequired,
        parse(std.testing.allocator, certificate_pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n" ++
            "-----END ENCRYPTED PRIVATE KEY-----\n"),
    );
    try std.testing.expectError(
        error.InvalidPem,
        parse(std.testing.allocator, certificate_pem, sec1_private_key_pem ++ sec1_private_key_pem),
    );
}

test "server identity file rejects ambiguous private key DER" {
    const valid_sec1 = [_]u8{
        0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0xa0,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    };
    _ = try parsePrivateKeyDer(std.testing.allocator, .sec1, &valid_sec1);

    var wrong_curve = valid_sec1;
    wrong_curve[wrong_curve.len - 1] = 0x08;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .sec1, &wrong_curve),
    );

    const trailing = valid_sec1 ++ .{0x00};
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(std.testing.allocator, .sec1, &trailing),
    );

    const non_canonical_length = [_]u8{ 0x30, 0x81, 0x31 } ++
        valid_sec1[2..].*;
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parsePrivateKeyDer(
            std.testing.allocator,
            .sec1,
            &non_canonical_length,
        ),
    );
}

test "server identity file rejects zero and non-canonical P-256 scalars" {
    const template = [_]u8{
        0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0xa0,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    };
    var zero = template;
    @memset(zero[7..39], 0);
    const zero_pem = try encodePrivateKeyForTest(std.testing.allocator, &zero);
    defer std.testing.allocator.free(zero_pem);
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parse(std.testing.allocator, certificate_pem, zero_pem),
    );

    var non_canonical = template;
    @memset(non_canonical[7..39], 0xff);
    const non_canonical_pem = try encodePrivateKeyForTest(
        std.testing.allocator,
        &non_canonical,
    );
    defer std.testing.allocator.free(non_canonical_pem);
    try std.testing.expectError(
        error.InvalidPrivateKey,
        parse(std.testing.allocator, certificate_pem, non_canonical_pem),
    );
}

//! TLS protocol-version and cipher-suite metadata shared by stream adapters.

const std = @import("std");
const vail = @import("vail");

/// TLS versions supported by TCP-based netz transports. QUIC remains TLS 1.3
/// only as required by RFC 9001.
pub const Protocol = enum(u16) {
    tls12 = 0x0303,
    tls13 = 0x0304,
};

/// Explicit protocol policy. Keeping TLS 1.3-only as the default preserves
/// the existing security boundary; callers that need legacy interoperability
/// can enable TLS 1.2 without enabling TLS 1.0/1.1.
pub const Policy = enum {
    tls13_only,
    tls12_and_tls13,
    tls12_only,

    pub fn offersTls12(self: Policy) bool {
        return self != .tls13_only;
    }

    pub fn offersTls13(self: Policy) bool {
        return self != .tls12_only;
    }
};

/// Version-qualified negotiated cipher-suite identifier. Values are the IANA
/// wire identifiers, so logging and policy code never mistakes a TLS 1.2
/// ECDHE suite for a TLS 1.3 AEAD suite with a similar primitive.
pub const NegotiatedCipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    aes_128_ccm_sha256 = 0x1304,
    aes_128_ccm_8_sha256 = 0x1305,
    sm4_gcm_sm3 = 0x00c6,
    sm4_ccm_sm3 = 0x00c7,

    ecdhe_ecdsa_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_chacha20_poly1305_sha256 = 0xcca9,

    pub fn fromTls13(suite: vail.tls.cipher_suite.Suite) NegotiatedCipherSuite {
        return @enumFromInt(suite.wireValue());
    }

    pub fn fromTls12(suite: vail.tls.tls12.Suite) NegotiatedCipherSuite {
        return @enumFromInt(@intFromEnum(suite));
    }
};

pub const default_tls12_cipher_suites = [_]vail.tls.tls12.Suite{
    .ecdhe_ecdsa_aes_128_gcm_sha256,
    .ecdhe_rsa_aes_128_gcm_sha256,
    .ecdhe_ecdsa_aes_256_gcm_sha384,
    .ecdhe_rsa_aes_256_gcm_sha384,
    .ecdhe_ecdsa_chacha20_poly1305_sha256,
    .ecdhe_rsa_chacha20_poly1305_sha256,
};

pub const default_tls12_groups = [_]u16{
    // Match modern OpenSSL/rustls preference while retaining P-256 fallback.
    vail.tls.key_exchange.named_group_x25519,
    vail.tls.key_exchange.named_group_secp256r1,
};

pub fn transcriptHash(
    suite: vail.tls.tls12.Suite,
) vail.tls.secret.Hash {
    return switch (suite.prfHash()) {
        .sha256 => .sha256,
        .sha384 => .sha384,
    };
}

test "version policy never enables pre-TLS-1.2 protocols" {
    try std.testing.expect(!Policy.tls13_only.offersTls12());
    try std.testing.expect(Policy.tls13_only.offersTls13());
    try std.testing.expect(Policy.tls12_and_tls13.offersTls12());
    try std.testing.expect(Policy.tls12_and_tls13.offersTls13());
    try std.testing.expect(Policy.tls12_only.offersTls12());
    try std.testing.expect(!Policy.tls12_only.offersTls13());
}

test "TLS 1.2 defaults prefer X25519 with P-256 fallback" {
    try std.testing.expectEqualSlices(
        u16,
        &.{
            vail.tls.key_exchange.named_group_x25519,
            vail.tls.key_exchange.named_group_secp256r1,
        },
        &default_tls12_groups,
    );
}

//! Typed optional entropy inputs for QUIC TLS key-share generation.
//!
//! These values exist for deterministic tests and embedding environments that
//! supply their own entropy. The handshake adapter replaces every null field
//! with fresh secure randomness; Vail remains responsible for all curve and
//! ML-KEM operations.

const tls_key_exchange = @import("../../tls/mod.zig").key_exchange;

const X25519Hybrid = tls_key_exchange.x25519_mlkem768;
const P256Hybrid = tls_key_exchange.secp256r1_mlkem768;
const P384Hybrid = tls_key_exchange.secp384r1_mlkem1024;

pub fn ClientHybrid(comptime Hybrid: type) type {
    return struct {
        curve_secret: ?[Hybrid.curve_secret_len]u8 = null,
        mlkem_seed: ?[Hybrid.mlkem_seed_len]u8 = null,
    };
}

pub fn ServerHybrid(comptime Hybrid: type) type {
    return struct {
        curve_secret: ?[Hybrid.curve_secret_len]u8 = null,
        encaps_seed: ?[Hybrid.encaps_seed_len]u8 = null,
    };
}

/// Deterministic inputs for the registered NIST ECDHE-ML-KEM client groups.
pub const ClientNistHybrid = struct {
    secp256r1_mlkem768: ClientHybrid(P256Hybrid) = .{},
    secp384r1_mlkem1024: ClientHybrid(P384Hybrid) = .{},
};

/// Deterministic inputs for the registered NIST ECDHE-ML-KEM server groups.
pub const ServerNistHybrid = struct {
    secp256r1_mlkem768: ServerHybrid(P256Hybrid) = .{},
    secp384r1_mlkem1024: ServerHybrid(P384Hybrid) = .{},
};

pub const Client = struct {
    x25519_secret: ?[32]u8 = null,
    p256_secret: ?[tls_key_exchange.p256.secret_len]u8 = null,
    p384_secret: ?[tls_key_exchange.p384.secret_len]u8 = null,
    x25519_hybrid_curve_secret: ?[X25519Hybrid.x25519_secret_len]u8 = null,
    x25519_hybrid_mlkem_seed: ?[X25519Hybrid.mlkem_seed_len]u8 = null,
    nist_hybrid: ClientNistHybrid = .{},
};

pub const Server = struct {
    x25519_secret: ?[32]u8 = null,
    p256_secret: ?[tls_key_exchange.p256.secret_len]u8 = null,
    p384_secret: ?[tls_key_exchange.p384.secret_len]u8 = null,
    x25519_hybrid_curve_secret: ?[X25519Hybrid.x25519_secret_len]u8 = null,
    x25519_hybrid_encaps_seed: ?[X25519Hybrid.encaps_seed_len]u8 = null,
    nist_hybrid: ServerNistHybrid = .{},
};

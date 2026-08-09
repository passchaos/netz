//! QUIC handshake ownership and dispatch for Vail TLS key-exchange keys.
//!
//! Curve arithmetic remains in Vail. This adapter only generates ephemeral
//! private values, keeps each value paired with its TLS named group, and
//! presents variable-length shared secrets to the handshake key schedule.

const std = @import("std");
const tls = @import("../tls_client_hello.zig");

pub const Error = tls.Error || std.Io.RandomSecureError;

const PrivateKey = union(tls.NamedGroup) {
    secp256r1: [tls_key_exchange.p256.secret_len]u8,
    secp384r1: [tls_key_exchange.p384.secret_len]u8,
    x25519: [32]u8,

    fn sharedSecret(
        self: PrivateKey,
        peer_public: []const u8,
    ) Error!SharedSecret {
        return switch (self) {
            .x25519 => |secret| x25519: {
                const shared = try tls.x25519SharedSecret(
                    secret,
                    peer_public,
                );
                break :x25519 SharedSecret.init(&shared);
            },
            .secp256r1 => |secret| p256: {
                const shared = try tls.p256SharedSecret(
                    secret,
                    peer_public,
                );
                break :p256 SharedSecret.init(&shared);
            },
            .secp384r1 => |secret| p384: {
                const shared = try tls.p384SharedSecret(
                    secret,
                    peer_public,
                );
                break :p384 SharedSecret.init(&shared);
            },
        };
    }
};

const tls_key_exchange = @import("../tls/mod.zig").key_exchange;

/// Owns the longest shared secret supported by the configured named groups.
/// The explicit length prevents a P-384 secret from being truncated to the
/// historical 32-byte X25519/P-256 size before HKDF-Extract.
pub const SharedSecret = struct {
    storage: [tls_key_exchange.p384.shared_len]u8 = undefined,
    len: usize,

    fn init(secret_bytes: []const u8) SharedSecret {
        std.debug.assert(
            secret_bytes.len <= tls_key_exchange.p384.shared_len,
        );
        var result = SharedSecret{ .len = secret_bytes.len };
        @memcpy(result.storage[0..secret_bytes.len], secret_bytes);
        return result;
    }

    pub fn bytes(self: *const SharedSecret) []const u8 {
        return self.storage[0..self.len];
    }
};

pub const LocalKeyShares = struct {
    x25519_secret: ?[32]u8 = null,
    p256_secret: ?[tls_key_exchange.p256.secret_len]u8 = null,
    p384_secret: ?[tls_key_exchange.p384.secret_len]u8 = null,
    shares: [3]tls.KeyShare = undefined,
    len: usize = 0,

    pub fn slice(self: *const LocalKeyShares) []const tls.KeyShare {
        return self.shares[0..self.len];
    }

    pub fn sharedSecret(
        self: LocalKeyShares,
        group: tls.NamedGroup,
        peer_public: []const u8,
    ) Error!SharedSecret {
        const private: PrivateKey = switch (group) {
            .x25519 => .{
                .x25519 = self.x25519_secret orelse
                    return error.MissingKeyShare,
            },
            .secp256r1 => .{
                .secp256r1 = self.p256_secret orelse
                    return error.MissingKeyShare,
            },
            .secp384r1 => .{
                .secp384r1 = self.p384_secret orelse
                    return error.MissingKeyShare,
            },
        };
        return private.sharedSecret(peer_public);
    }
};

pub fn make(
    io: std.Io,
    groups: []const tls.NamedGroup,
    x25519_provided: ?[32]u8,
    p256_provided: ?[tls_key_exchange.p256.secret_len]u8,
    p384_provided: ?[tls_key_exchange.p384.secret_len]u8,
) Error!LocalKeyShares {
    if (groups.len == 0 or groups.len > 3) return error.MissingKeyShare;
    var result = LocalKeyShares{};
    for (groups, 0..) |group, index| {
        for (groups[0..index]) |previous| {
            if (group == previous) return error.InvalidClientHello;
        }
        switch (group) {
            .x25519 => {
                const private = try x25519SecretKey(io, x25519_provided);
                result.x25519_secret = private;
                result.shares[result.len] = .{
                    .x25519 = try tls.x25519PublicKey(private),
                };
            },
            .secp256r1 => {
                const private = try p256SecretKey(io, p256_provided);
                result.p256_secret = private;
                result.shares[result.len] = .{
                    .secp256r1 = try tls.p256PublicKey(private),
                };
            },
            .secp384r1 => {
                const private = try p384SecretKey(io, p384_provided);
                result.p384_secret = private;
                result.shares[result.len] = .{
                    .secp384r1 = try tls.p384PublicKey(private),
                };
            },
        }
        result.len += 1;
    }
    return result;
}

fn randomArray(
    comptime len: usize,
    io: std.Io,
) std.Io.RandomSecureError![len]u8 {
    var out: [len]u8 = undefined;
    try std.Io.randomSecure(io, &out);
    return out;
}

fn x25519SecretKey(
    io: std.Io,
    provided: ?[32]u8,
) std.Io.RandomSecureError![32]u8 {
    var secret = provided orelse try randomArray(32, io);
    // Clamp here so deterministic caller-provided keys and generated ephemeral
    // keys follow the same X25519 scalar-shape invariant.
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
}

fn p256SecretKey(
    io: std.Io,
    provided: ?[tls_key_exchange.p256.secret_len]u8,
) Error![tls_key_exchange.p256.secret_len]u8 {
    if (provided) |value| {
        _ = try tls.p256PublicKey(value);
        return value;
    }
    while (true) {
        const candidate = try randomArray(
            tls_key_exchange.p256.secret_len,
            io,
        );
        _ = tls.p256PublicKey(candidate) catch continue;
        return candidate;
    }
}

fn p384SecretKey(
    io: std.Io,
    provided: ?[tls_key_exchange.p384.secret_len]u8,
) Error![tls_key_exchange.p384.secret_len]u8 {
    if (provided) |value| {
        _ = try tls.p384PublicKey(value);
        return value;
    }
    while (true) {
        const candidate = try randomArray(
            tls_key_exchange.p384.secret_len,
            io,
        );
        _ = tls.p384PublicKey(candidate) catch continue;
        return candidate;
    }
}

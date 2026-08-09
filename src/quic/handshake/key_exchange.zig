//! QUIC handshake ownership and dispatch for Vail TLS key-exchange keys.
//!
//! Curve arithmetic remains in Vail. This adapter only generates ephemeral
//! private values, keeps each value paired with its TLS named group, and
//! presents variable-length shared secrets to the handshake key schedule.

const std = @import("std");
const tls = @import("../tls_client_hello.zig");
const tls_crypto = @import("../tls/key_exchange.zig");
const tls_key_exchange = @import("../tls/mod.zig").key_exchange;
const material = @import("key_exchange/material.zig");

pub const Error = tls.Error || std.Io.RandomSecureError;
const X25519Hybrid = tls_key_exchange.x25519_mlkem768;
const P256Hybrid = tls_key_exchange.secp256r1_mlkem768;
const P384Hybrid = tls_key_exchange.secp384r1_mlkem1024;
const max_shared_secret_len = @max(
    X25519Hybrid.shared_len,
    @max(P256Hybrid.shared_len, P384Hybrid.shared_len),
);

const PrivateKey = union(tls.NamedGroup) {
    secp256r1: [tls_key_exchange.p256.secret_len]u8,
    secp384r1: [tls_key_exchange.p384.secret_len]u8,
    x25519: [32]u8,
    secp256r1_mlkem768: void,
    x25519_mlkem768: void,
    secp384r1_mlkem1024: void,

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
            .x25519_mlkem768 => unreachable,
            .secp256r1_mlkem768 => unreachable,
            .secp384r1_mlkem1024 => unreachable,
        };
    }
};

/// Owns the longest shared secret supported by the configured named groups.
/// The explicit length preserves all 80 bytes of secp384r1MLKEM1024's
/// classical-first IKM before HKDF-Extract.
pub const SharedSecret = struct {
    storage: [max_shared_secret_len]u8 = undefined,
    len: usize,

    fn init(secret_bytes: []const u8) SharedSecret {
        std.debug.assert(secret_bytes.len <= max_shared_secret_len);
        var result = SharedSecret{ .len = secret_bytes.len };
        @memcpy(result.storage[0..secret_bytes.len], secret_bytes);
        return result;
    }

    pub fn bytes(self: *const SharedSecret) []const u8 {
        return self.storage[0..self.len];
    }

    pub fn wipe(self: *SharedSecret) void {
        std.crypto.secureZero(u8, &self.storage);
        self.len = 0;
    }
};

pub const LocalKeyShares = struct {
    x25519_secret: ?[32]u8 = null,
    p256_secret: ?[tls_key_exchange.p256.secret_len]u8 = null,
    p384_secret: ?[tls_key_exchange.p384.secret_len]u8 = null,
    x25519_hybrid_secret: ?X25519Hybrid.ClientSecret = null,
    p256_hybrid_secret: ?P256Hybrid.ClientSecret = null,
    p384_hybrid_secret: ?P384Hybrid.ClientSecret = null,
    shares: [6]tls.KeyShare = undefined,
    len: usize = 0,

    pub fn slice(self: *const LocalKeyShares) []const tls.KeyShare {
        return self.shares[0..self.len];
    }

    pub fn clientSharedSecret(
        self: *const LocalKeyShares,
        group: tls.NamedGroup,
        peer_public: []const u8,
    ) Error!SharedSecret {
        return switch (group) {
            .x25519_mlkem768 => hybridClientSharedSecret(
                X25519Hybrid,
                &self.x25519_hybrid_secret,
                peer_public,
            ),
            .secp256r1_mlkem768 => hybridClientSharedSecret(
                P256Hybrid,
                &self.p256_hybrid_secret,
                peer_public,
            ),
            .secp384r1_mlkem1024 => hybridClientSharedSecret(
                P384Hybrid,
                &self.p384_hybrid_secret,
                peer_public,
            ),
            .x25519 => (PrivateKey{
                .x25519 = self.x25519_secret orelse
                    return error.MissingKeyShare,
            }).sharedSecret(peer_public),
            .secp256r1 => (PrivateKey{
                .secp256r1 = self.p256_secret orelse
                    return error.MissingKeyShare,
            }).sharedSecret(peer_public),
            .secp384r1 => (PrivateKey{
                .secp384r1 = self.p384_secret orelse
                    return error.MissingKeyShare,
            }).sharedSecret(peer_public),
        };
    }

    pub fn deinit(self: *LocalKeyShares) void {
        if (self.x25519_secret) |*secret| wipe(secret);
        if (self.p256_secret) |*secret| wipe(secret);
        if (self.p384_secret) |*secret| wipe(secret);
        if (self.x25519_hybrid_secret) |*secret| secret.wipe();
        if (self.p256_hybrid_secret) |*secret| secret.wipe();
        if (self.p384_hybrid_secret) |*secret| secret.wipe();
        self.* = undefined;
    }
};

pub const ClientKeyMaterial = material.Client;
pub const ServerKeyMaterial = material.Server;
pub const ClientNistHybridKeyMaterial = material.ClientNistHybrid;
pub const ServerNistHybridKeyMaterial = material.ServerNistHybrid;

pub fn make(
    io: std.Io,
    groups: []const tls.NamedGroup,
    provided: ClientKeyMaterial,
) Error!LocalKeyShares {
    if (groups.len == 0 or groups.len > 6) return error.MissingKeyShare;
    var result = LocalKeyShares{};
    errdefer result.deinit();
    for (groups, 0..) |group, index| {
        for (groups[0..index]) |previous| {
            if (group == previous) return error.InvalidClientHello;
        }
        switch (group) {
            .x25519 => {
                var private = try x25519SecretKey(
                    io,
                    provided.x25519_secret,
                );
                defer wipe(&private);
                result.x25519_secret = private;
                result.shares[result.len] = .{
                    .x25519 = try tls.x25519PublicKey(private),
                };
            },
            .secp256r1 => {
                var private = try p256SecretKey(
                    io,
                    provided.p256_secret,
                );
                defer wipe(&private);
                result.p256_secret = private;
                result.shares[result.len] = .{
                    .secp256r1 = try tls.p256PublicKey(private),
                };
            },
            .secp384r1 => {
                var private = try p384SecretKey(
                    io,
                    provided.p384_secret,
                );
                defer wipe(&private);
                result.p384_secret = private;
                result.shares[result.len] = .{
                    .secp384r1 = try tls.p384PublicKey(private),
                };
            },
            .x25519_mlkem768 => {
                var curve_secret = try x25519SecretKey(
                    io,
                    provided.x25519_hybrid_curve_secret,
                );
                defer wipe(&curve_secret);
                var mlkem_seed =
                    provided.x25519_hybrid_mlkem_seed orelse
                    try randomArray(X25519Hybrid.mlkem_seed_len, io);
                defer wipe(&mlkem_seed);
                var started = try tls.x25519MlKem768ClientStart(
                    curve_secret,
                    mlkem_seed,
                );
                result.x25519_hybrid_secret = started.secret;
                started.secret.wipe();
                result.shares[result.len] = .{
                    .x25519_mlkem768_client = started.share,
                };
            },
            .secp256r1_mlkem768 => {
                var curve_secret = try p256SecretKey(
                    io,
                    provided.nist_hybrid
                        .secp256r1_mlkem768.curve_secret,
                );
                defer wipe(&curve_secret);
                var mlkem_seed =
                    provided.nist_hybrid
                        .secp256r1_mlkem768.mlkem_seed orelse
                    try randomArray(P256Hybrid.mlkem_seed_len, io);
                defer wipe(&mlkem_seed);
                var started = try tls_crypto.hybridClientStart(
                    P256Hybrid,
                    curve_secret,
                    mlkem_seed,
                );
                result.p256_hybrid_secret = started.secret;
                started.secret.wipe();
                result.shares[result.len] = .{
                    .secp256r1_mlkem768_client = started.share,
                };
            },
            .secp384r1_mlkem1024 => {
                var curve_secret = try p384SecretKey(
                    io,
                    provided.nist_hybrid
                        .secp384r1_mlkem1024.curve_secret,
                );
                defer wipe(&curve_secret);
                var mlkem_seed =
                    provided.nist_hybrid
                        .secp384r1_mlkem1024.mlkem_seed orelse
                    try randomArray(P384Hybrid.mlkem_seed_len, io);
                defer wipe(&mlkem_seed);
                var started = try tls_crypto.hybridClientStart(
                    P384Hybrid,
                    curve_secret,
                    mlkem_seed,
                );
                result.p384_hybrid_secret = started.secret;
                started.secret.wipe();
                result.shares[result.len] = .{
                    .secp384r1_mlkem1024_client = started.share,
                };
            },
        }
        result.len += 1;
    }
    return result;
}

pub fn serverRespond(
    io: std.Io,
    group: tls.NamedGroup,
    client_share: []const u8,
    provided: ServerKeyMaterial,
) Error!ServerResult {
    return switch (group) {
        .x25519 => classicalServerResult(
            .{
                .x25519 = try x25519SecretKey(
                    io,
                    provided.x25519_secret,
                ),
            },
            client_share,
        ),
        .secp256r1 => classicalServerResult(
            .{
                .secp256r1 = try p256SecretKey(
                    io,
                    provided.p256_secret,
                ),
            },
            client_share,
        ),
        .secp384r1 => classicalServerResult(
            .{
                .secp384r1 = try p384SecretKey(
                    io,
                    provided.p384_secret,
                ),
            },
            client_share,
        ),
        .x25519_mlkem768 => hybrid: {
            var curve_secret = try x25519SecretKey(
                io,
                provided.x25519_hybrid_curve_secret,
            );
            defer wipe(&curve_secret);
            var encaps_seed =
                provided.x25519_hybrid_encaps_seed orelse
                try randomArray(X25519Hybrid.encaps_seed_len, io);
            defer wipe(&encaps_seed);
            var response = try tls.x25519MlKem768ServerRespond(
                client_share,
                curve_secret,
                encaps_seed,
            );
            defer response.wipeSharedSecret();
            break :hybrid .{
                .share = .{
                    .x25519_mlkem768_server = response.share,
                },
                .shared_secret = SharedSecret.init(
                    &response.shared_secret,
                ),
            };
        },
        .secp256r1_mlkem768 => hybridServerResult(
            P256Hybrid,
            "secp256r1_mlkem768_server",
            client_share,
            try p256SecretKey(
                io,
                provided.nist_hybrid
                    .secp256r1_mlkem768.curve_secret,
            ),
            provided.nist_hybrid
                .secp256r1_mlkem768.encaps_seed orelse
                try randomArray(P256Hybrid.encaps_seed_len, io),
        ),
        .secp384r1_mlkem1024 => hybridServerResult(
            P384Hybrid,
            "secp384r1_mlkem1024_server",
            client_share,
            try p384SecretKey(
                io,
                provided.nist_hybrid
                    .secp384r1_mlkem1024.curve_secret,
            ),
            provided.nist_hybrid
                .secp384r1_mlkem1024.encaps_seed orelse
                try randomArray(P384Hybrid.encaps_seed_len, io),
        ),
    };
}

fn hybridClientSharedSecret(
    comptime Hybrid: type,
    optional_secret: *const ?Hybrid.ClientSecret,
    server_share: []const u8,
) Error!SharedSecret {
    const secret = if (optional_secret.*) |*value|
        value
    else
        return error.MissingKeyShare;
    var shared = if (Hybrid == X25519Hybrid)
        try tls.x25519MlKem768ClientSharedSecret(
            secret,
            server_share,
        )
    else
        try tls_crypto.hybridClientSharedSecret(
            Hybrid,
            secret,
            server_share,
        );
    defer wipe(&shared);
    return SharedSecret.init(&shared);
}

fn hybridServerResult(
    comptime Hybrid: type,
    comptime share_field: []const u8,
    client_share: []const u8,
    curve_secret_value: [Hybrid.curve_secret_len]u8,
    encaps_seed_value: [Hybrid.encaps_seed_len]u8,
) Error!ServerResult {
    var curve_secret = curve_secret_value;
    defer wipe(&curve_secret);
    var encaps_seed = encaps_seed_value;
    defer wipe(&encaps_seed);
    var response = try tls_crypto.hybridServerRespond(
        Hybrid,
        client_share,
        curve_secret,
        encaps_seed,
    );
    defer response.wipeSharedSecret();
    return .{
        .share = @unionInit(
            tls.KeyShare,
            share_field,
            response.share,
        ),
        .shared_secret = SharedSecret.init(&response.shared_secret),
    };
}

pub const ServerResult = struct {
    share: tls.KeyShare,
    shared_secret: SharedSecret,
};

fn classicalServerResult(
    private_value: PrivateKey,
    client_share: []const u8,
) Error!ServerResult {
    var private = private_value;
    defer wipe(&private);
    const share: tls.KeyShare = switch (private) {
        .x25519 => |secret| .{
            .x25519 = try tls.x25519PublicKey(secret),
        },
        .secp256r1 => |secret| .{
            .secp256r1 = try tls.p256PublicKey(secret),
        },
        .secp384r1 => |secret| .{
            .secp384r1 = try tls.p384PublicKey(secret),
        },
        .x25519_mlkem768 => unreachable,
        .secp256r1_mlkem768 => unreachable,
        .secp384r1_mlkem1024 => unreachable,
    };
    return .{
        .share = share,
        .shared_secret = try private.sharedSecret(client_share),
    };
}

fn randomArray(
    comptime len: usize,
    io: std.Io,
) std.Io.RandomSecureError![len]u8 {
    var out: [len]u8 = undefined;
    try std.Io.randomSecure(io, &out);
    return out;
}

fn wipe(value: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(value));
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

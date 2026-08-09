//! TLS key-exchange adapters for QUIC handshake orchestration.
//!
//! Cryptographic operations and key ownership live in Vail. This module only
//! maps Vail's detailed errors into the compact QUIC TLS codec error surface.

const quic = @import("../mod.zig");

pub const Error = error{
    MissingKeyShare,
    KeyExchangeFailed,
};

pub const X25519MlKem768ClientStart =
    quic.tls.key_exchange.x25519_mlkem768.ClientStart;
pub const X25519MlKem768ClientSecret =
    quic.tls.key_exchange.x25519_mlkem768.ClientSecret;
pub const X25519MlKem768ServerResponse =
    quic.tls.key_exchange.x25519_mlkem768.ServerResponse;

pub fn hybridClientStart(
    comptime Hybrid: type,
    curve_secret: [Hybrid.curve_secret_len]u8,
    mlkem_seed: [Hybrid.mlkem_seed_len]u8,
) Error!Hybrid.ClientStart {
    return Hybrid.clientStart(curve_secret, mlkem_seed) catch
        return error.KeyExchangeFailed;
}

pub fn hybridServerRespond(
    comptime Hybrid: type,
    client_share: []const u8,
    curve_secret: [Hybrid.curve_secret_len]u8,
    encaps_seed: [Hybrid.encaps_seed_len]u8,
) Error!Hybrid.ServerResponse {
    return Hybrid.serverRespond(
        client_share,
        curve_secret,
        encaps_seed,
    ) catch |err| switch (err) {
        error.InvalidClientShare => error.MissingKeyShare,
        error.InvalidServerShare,
        error.InvalidSecretKey,
        error.KeyExchangeFailed,
        => error.KeyExchangeFailed,
    };
}

pub fn hybridClientSharedSecret(
    comptime Hybrid: type,
    secret: *const Hybrid.ClientSecret,
    server_share: []const u8,
) Error![Hybrid.shared_len]u8 {
    return Hybrid.clientSharedSecret(secret, server_share) catch |err|
        switch (err) {
            error.InvalidServerShare => error.MissingKeyShare,
            error.InvalidClientShare,
            error.InvalidSecretKey,
            error.KeyExchangeFailed,
            => error.KeyExchangeFailed,
        };
}

pub fn x25519PublicKey(secret_key: [32]u8) Error![32]u8 {
    return quic.tls.key_exchange.publicKey(secret_key) catch
        return error.KeyExchangeFailed;
}

pub fn x25519SharedSecret(
    secret_key: [32]u8,
    peer_public_key: []const u8,
) Error![32]u8 {
    return quic.tls.key_exchange.sharedSecret(
        secret_key,
        peer_public_key,
    ) catch |err| switch (err) {
        error.InvalidSecretKey => error.KeyExchangeFailed,
        error.InvalidPublicKey => error.MissingKeyShare,
        error.KeyExchangeFailed => error.KeyExchangeFailed,
    };
}

pub fn p256PublicKey(secret_key: [32]u8) Error![65]u8 {
    return quic.tls.key_exchange.p256.publicKey(secret_key) catch
        return error.KeyExchangeFailed;
}

pub fn p256SharedSecret(
    secret_key: [32]u8,
    peer_public_key: []const u8,
) Error![32]u8 {
    return quic.tls.key_exchange.p256.sharedSecret(
        secret_key,
        peer_public_key,
    ) catch |err| switch (err) {
        error.InvalidSecretKey => error.KeyExchangeFailed,
        error.InvalidPublicKey => error.MissingKeyShare,
        error.KeyExchangeFailed => error.KeyExchangeFailed,
    };
}

pub fn p384PublicKey(
    secret_key: [quic.tls.key_exchange.p384.secret_len]u8,
) Error![quic.tls.key_exchange.p384.public_len]u8 {
    return quic.tls.key_exchange.p384.publicKey(secret_key) catch
        return error.KeyExchangeFailed;
}

pub fn p384SharedSecret(
    secret_key: [quic.tls.key_exchange.p384.secret_len]u8,
    peer_public_key: []const u8,
) Error![quic.tls.key_exchange.p384.shared_len]u8 {
    return quic.tls.key_exchange.p384.sharedSecret(
        secret_key,
        peer_public_key,
    ) catch |err| switch (err) {
        error.InvalidSecretKey => error.KeyExchangeFailed,
        error.InvalidPublicKey => error.MissingKeyShare,
        error.KeyExchangeFailed => error.KeyExchangeFailed,
    };
}

pub fn x25519MlKem768ClientStart(
    x25519_secret: [
        quic.tls.key_exchange.x25519_mlkem768
            .x25519_secret_len
    ]u8,
    mlkem_seed: [
        quic.tls.key_exchange.x25519_mlkem768
            .mlkem_seed_len
    ]u8,
) Error!X25519MlKem768ClientStart {
    return quic.tls.key_exchange.x25519_mlkem768.clientStart(
        x25519_secret,
        mlkem_seed,
    ) catch return error.KeyExchangeFailed;
}

pub fn x25519MlKem768ServerRespond(
    client_share: []const u8,
    x25519_secret: [
        quic.tls.key_exchange.x25519_mlkem768
            .x25519_secret_len
    ]u8,
    encaps_seed: [
        quic.tls.key_exchange.x25519_mlkem768
            .encaps_seed_len
    ]u8,
) Error!X25519MlKem768ServerResponse {
    return quic.tls.key_exchange.x25519_mlkem768.serverRespond(
        client_share,
        x25519_secret,
        encaps_seed,
    ) catch |err| switch (err) {
        error.InvalidClientShare => error.MissingKeyShare,
        error.InvalidServerShare,
        error.InvalidSecretKey,
        error.KeyExchangeFailed,
        => error.KeyExchangeFailed,
    };
}

pub fn x25519MlKem768ClientSharedSecret(
    secret: *const X25519MlKem768ClientSecret,
    server_share: []const u8,
) Error![quic.tls.key_exchange.x25519_mlkem768.shared_len]u8 {
    return quic.tls.key_exchange.x25519_mlkem768.clientSharedSecret(
        secret,
        server_share,
    ) catch |err| switch (err) {
        error.InvalidServerShare => error.MissingKeyShare,
        error.InvalidClientShare,
        error.InvalidSecretKey,
        error.KeyExchangeFailed,
        => error.KeyExchangeFailed,
    };
}

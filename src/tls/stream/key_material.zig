//! Single-use classical ECDHE private material for stream TLS wrappers.

const std = @import("std");
const vail = @import("vail");

pub fn randomX25519(
    io: std.Io,
) std.Io.RandomSecureError![vail.tls.key_exchange.secret_len]u8 {
    var secret: [vail.tls.key_exchange.secret_len]u8 = undefined;
    try std.Io.randomSecure(io, &secret);
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
}

pub fn randomP256(
    io: std.Io,
) (std.Io.RandomSecureError || error{InvalidSecretKey})![
    vail.tls.key_exchange.p256.secret_len
]u8 {
    return randomNist(
        vail.tls.key_exchange.p256,
        io,
        0xff,
        validP256,
    );
}

pub fn randomP384(
    io: std.Io,
) (std.Io.RandomSecureError || error{InvalidSecretKey})![
    vail.tls.key_exchange.p384.secret_len
]u8 {
    return randomNist(
        vail.tls.key_exchange.p384,
        io,
        0xff,
        validP384,
    );
}

pub fn randomP521(
    io: std.Io,
) (std.Io.RandomSecureError || error{InvalidSecretKey})![
    vail.tls.key_exchange.p521.secret_len
]u8 {
    return randomNist(
        vail.tls.key_exchange.p521,
        io,
        0x01,
        validP521,
    );
}

fn randomNist(
    comptime group: type,
    io: std.Io,
    comptime high_mask: u8,
    comptime validate: anytype,
) (std.Io.RandomSecureError || error{InvalidSecretKey})![group.secret_len]u8 {
    var secret: [group.secret_len]u8 = undefined;
    var attempts: usize = 0;
    while (attempts < 16) : (attempts += 1) {
        try std.Io.randomSecure(io, &secret);
        secret[0] &= high_mask;
        if (!validate(secret)) continue;
        return secret;
    }
    std.crypto.secureZero(u8, &secret);
    return error.InvalidSecretKey;
}

fn validP256(secret: [vail.tls.key_exchange.p256.secret_len]u8) bool {
    const Scalar = std.crypto.ecc.P256.scalar.Scalar;
    var scalar = Scalar.fromBytes(secret, .big) catch return false;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    return !scalar.isZero();
}

fn validP384(secret: [vail.tls.key_exchange.p384.secret_len]u8) bool {
    const Scalar = std.crypto.ecc.P384.scalar.Scalar;
    var scalar = Scalar.fromBytes(secret, .big) catch return false;
    defer std.crypto.secureZero(Scalar, (&scalar)[0..1]);
    return !scalar.isZero();
}

fn validP521(secret: [vail.tls.key_exchange.p521.secret_len]u8) bool {
    var key = vail.crypto.p521.SecretKey.fromBytes(secret) catch return false;
    key.deinit();
    return true;
}

test "stream TLS key material produces valid classical public keys" {
    var x25519 = try randomX25519(std.testing.io);
    defer std.crypto.secureZero(u8, &x25519);
    _ = try vail.tls.key_exchange.publicKey(x25519);

    var p256 = try randomP256(std.testing.io);
    defer std.crypto.secureZero(u8, &p256);
    _ = try vail.tls.key_exchange.p256.publicKey(p256);

    var p384 = try randomP384(std.testing.io);
    defer std.crypto.secureZero(u8, &p384);
    _ = try vail.tls.key_exchange.p384.publicKey(p384);

    var p521 = try randomP521(std.testing.io);
    defer std.crypto.secureZero(u8, &p521);
    _ = try vail.tls.key_exchange.p521.publicKey(p521);
}

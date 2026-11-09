//! WireGuard static and ephemeral X25519 key material.
//!
//! Secret keys are zeroed explicitly. Key generation takes a caller-supplied
//! `std.Random` so tests can be deterministic and platform layers can choose
//! their own entropy source.

const std = @import("std");
const vail = @import("vail");

const X25519 = vail.crypto.x25519.X25519;

pub const public_key_length = 32;
pub const secret_key_length = 32;
pub const key_length = public_key_length;
pub const base64_length = 44;

/// Decodes a WireGuard `PresharedKey` value.
///
/// PSKs are arbitrary 256-bit values used verbatim in the Noise handshake.
/// They must not be X25519-clamped, unlike long-term static secret keys.
pub fn presharedKeyFromBase64(
    text: []const u8,
) KeyError![secret_key_length]u8 {
    if (text.len != base64_length) return error.InvalidLength;
    var decoded: [secret_key_length]u8 = undefined;
    std.base64.standard.Decoder.decode(
        &decoded,
        text,
    ) catch return error.InvalidEncoding;
    return decoded;
}

pub const KeyError = error{
    InvalidLength,
    InvalidEncoding,
    InvalidSecretKey,
    InvalidPublicKey,
    IdentityElement,
};

/// A Curve25519 public key. Public keys are not secret and need no erasure.
pub const PublicKey = struct {
    bytes: [public_key_length]u8,

    pub fn fromBytes(bytes: [public_key_length]u8) PublicKey {
        return .{ .bytes = bytes };
    }

    pub fn fromSlice(bytes: []const u8) KeyError!PublicKey {
        if (bytes.len != public_key_length) return error.InvalidLength;
        return .{ .bytes = bytes[0..public_key_length].* };
    }

    /// Parses the canonical 44-character WireGuard base64 representation.
    pub fn fromBase64(text: []const u8) KeyError!PublicKey {
        if (text.len != base64_length) return error.InvalidLength;
        var decoded: [public_key_length]u8 = undefined;
        std.base64.standard.Decoder.decode(
            &decoded,
            text,
        ) catch return error.InvalidEncoding;
        return .{ .bytes = decoded };
    }

    pub fn toBase64(self: PublicKey) [base64_length]u8 {
        var encoded: [base64_length]u8 = undefined;
        const written = std.base64.standard.Encoder.encode(
            &encoded,
            &self.bytes,
        );
        std.debug.assert(written.len == base64_length);
        return encoded;
    }

    pub fn eql(self: PublicKey, other: PublicKey) bool {
        return std.crypto.timing_safe.eql(
            [public_key_length]u8,
            self.bytes,
            other.bytes,
        );
    }
};

/// A Curve25519 secret key. `deinit` erases the bytes.
pub const SecretKey = struct {
    bytes: [secret_key_length]u8,

    pub fn fromBytes(bytes: [secret_key_length]u8) SecretKey {
        return .{ .bytes = bytes };
    }

    /// Parses a base64-encoded 32-byte secret key and clamps it.
    pub fn fromBase64(text: []const u8) KeyError!SecretKey {
        if (text.len != base64_length) return error.InvalidLength;
        var decoded: [secret_key_length]u8 = undefined;
        std.base64.standard.Decoder.decode(
            &decoded,
            text,
        ) catch return error.InvalidEncoding;
        var key = SecretKey.fromBytes(decoded);
        std.crypto.secureZero(u8, &decoded);
        key.clamp();
        return key;
    }

    pub fn toBase64(self: *const SecretKey) [base64_length]u8 {
        var encoded: [base64_length]u8 = undefined;
        const written = std.base64.standard.Encoder.encode(
            &encoded,
            &self.bytes,
        );
        std.debug.assert(written.len == base64_length);
        return encoded;
    }

    /// Applies the X25519 clamping required by WireGuard.
    pub fn clamp(self: *SecretKey) void {
        self.bytes[0] &= 248;
        self.bytes[31] = (self.bytes[31] & 127) | 64;
    }

    pub fn publicKey(self: *const SecretKey) KeyError!PublicKey {
        const bytes = X25519.recoverPublicKey(self.bytes) catch
            return error.IdentityElement;
        return .{ .bytes = bytes };
    }

    /// Computes the raw X25519 shared secret with `peer`.
    pub fn sharedSecret(
        self: *const SecretKey,
        peer: PublicKey,
    ) KeyError![32]u8 {
        var shared = X25519.scalarmult(
            self.bytes,
            peer.bytes,
        ) catch return error.IdentityElement;
        defer std.crypto.secureZero(u8, &shared);
        return shared;
    }

    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.bytes = undefined;
    }
};

pub const KeyPair = struct {
    secret: SecretKey,
    public: PublicKey,

    pub fn generate(rng: std.Random) KeyPair {
        var secret: [secret_key_length]u8 = undefined;
        rng.bytes(&secret);
        var key = SecretKey.fromBytes(secret);
        std.crypto.secureZero(u8, &secret);
        key.clamp();
        const public = key.publicKey() catch unreachable;
        return .{ .secret = key, .public = public };
    }

    pub fn fromSecret(secret: SecretKey) KeyError!KeyPair {
        var key = secret;
        key.clamp();
        const public = try key.publicKey();
        return .{ .secret = key, .public = public };
    }

    pub fn deinit(self: *KeyPair) void {
        self.secret.deinit();
        self.public.bytes = undefined;
    }
};

/// A pair of transport keys derived after a completed handshake.
pub const SessionKeys = struct {
    send: [32]u8,
    receive: [32]u8,

    pub fn deinit(self: *SessionKeys) void {
        std.crypto.secureZero(u8, &self.send);
        std.crypto.secureZero(u8, &self.receive);
        self.* = undefined;
    }
};

test "key pair derives stable public key" {
    const secret_bytes = [_]u8{0x11} ** secret_key_length;
    const pair = try KeyPair.fromSecret(SecretKey.fromBytes(secret_bytes));
    const again = try SecretKey.fromBytes(secret_bytes).publicKey();
    try std.testing.expect(pair.public.eql(again));

    // Clamping is idempotent.
    var clamped = SecretKey.fromBytes(secret_bytes);
    clamped.clamp();
    try std.testing.expectEqual(@as(u8, 0x10), clamped.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x51), clamped.bytes[31]);
}

test "base64 round trip" {
    var prng = std.Random.DefaultPrng.init(7);
    const pair = KeyPair.generate(prng.random());
    const encoded = pair.public.toBase64();
    const decoded = try PublicKey.fromBase64(&encoded);
    try std.testing.expect(pair.public.eql(decoded));

    var secret = pair.secret;
    const encoded_secret = secret.toBase64();
    const decoded_secret = try SecretKey.fromBase64(&encoded_secret);
    try std.testing.expectEqualSlices(
        u8,
        &pair.secret.bytes,
        &decoded_secret.bytes,
    );
}

test "preshared keys are decoded without clamping" {
    const encoded = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const psk = try presharedKeyFromBase64(encoded);
    try std.testing.expectEqual([_]u8{1} ** 32, psk);

    // A long-term secret with the same bytes is clamped, which is why the
    // config parser must not reuse `SecretKey.fromBase64` for PSKs.
    const secret = try SecretKey.fromBase64(encoded);
    try std.testing.expectEqual(@as(u8, 0), secret.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x41), secret.bytes[31]);
}

test "shared secret is symmetric" {
    var prng = std.Random.DefaultPrng.init(99);
    const alice = KeyPair.generate(prng.random());
    const bob = KeyPair.generate(prng.random());
    const a = try alice.secret.sharedSecret(bob.public);
    const b = try bob.secret.sharedSecret(alice.public);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

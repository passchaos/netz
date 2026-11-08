//! Shadowsocks AEAD cipher selection, password derivation and subkeys.

const std = @import("std");

const vail = @import("vail");
const aes_gcm = vail.crypto.aes_gcm;
const chacha20_poly1305 = vail.crypto.chacha20_poly1305;

pub const Algorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_ietf_poly1305,

    pub fn keyLength(self: Algorithm) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_ietf_poly1305 => 32,
        };
    }

    pub fn saltLength(self: Algorithm) usize {
        return self.keyLength();
    }

    pub fn tagLength(_: Algorithm) usize {
        return 16;
    }

    pub fn fromName(name: []const u8) ?Algorithm {
        if (std.mem.eql(u8, name, "aes-128-gcm")) return .aes_128_gcm;
        if (std.mem.eql(u8, name, "aes-256-gcm")) return .aes_256_gcm;
        if (std.mem.eql(u8, name, "chacha20-ietf-poly1305")) {
            return .chacha20_ietf_poly1305;
        }
        return null;
    }
};

pub const max_salt_len: usize = 32;

pub const Error = error{
    InvalidKeyLength,
    UnsupportedAlgorithm,
};

pub const Nonce = struct {
    bytes: [12]u8 = @splat(0),

    pub fn increment(self: *Nonce) void {
        for (&self.bytes) |*byte| {
            byte.* +%= 1;
            if (byte.* != 0) return;
        }
    }
};

pub const Aead = union(enum) {
    aes_128: aes_gcm.Aes128Gcm,
    aes_256: aes_gcm.Aes256Gcm,
    chacha20: chacha20_poly1305.Context,

    pub fn init(algorithm: Algorithm, key: []const u8) Error!Aead {
        return switch (algorithm) {
            .aes_128_gcm => blk: {
                if (key.len != 16) return error.InvalidKeyLength;
                break :blk .{ .aes_128 = aes_gcm.Aes128Gcm.init(key[0..16].*) };
            },
            .aes_256_gcm => blk: {
                if (key.len != 32) return error.InvalidKeyLength;
                break :blk .{ .aes_256 = aes_gcm.Aes256Gcm.init(key[0..32].*) };
            },
            .chacha20_ietf_poly1305 => blk: {
                if (key.len != 32) return error.InvalidKeyLength;
                break :blk .{ .chacha20 = chacha20_poly1305.Context.init(
                    key[0..32].*,
                ) };
            },
        };
    }

    pub fn deinit(self: *Aead) void {
        switch (self.*) {
            .aes_128 => |*context| context.deinit(),
            .aes_256 => |*context| context.deinit(),
            .chacha20 => |*context| context.deinit(),
        }
        self.* = undefined;
    }

    pub fn encrypt(
        self: *const Aead,
        ciphertext: []u8,
        tag: *[16]u8,
        plaintext: []const u8,
        associated_data: []const u8,
        nonce: [12]u8,
    ) void {
        switch (self.*) {
            .aes_128 => |*context| context.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
            ),
            .aes_256 => |*context| context.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
            ),
            .chacha20 => |*context| context.encrypt(
                ciphertext,
                tag,
                plaintext,
                associated_data,
                nonce,
            ),
        }
    }

    pub fn decrypt(
        self: *const Aead,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [16]u8,
        associated_data: []const u8,
        nonce: [12]u8,
    ) std.crypto.errors.AuthenticationError!void {
        switch (self.*) {
            .aes_128 => |*context| try context.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
            ),
            .aes_256 => |*context| try context.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
            ),
            .chacha20 => |*context| try context.decrypt(
                plaintext,
                ciphertext,
                tag,
                associated_data,
                nonce,
            ),
        }
    }
};

/// Shadowsocks uses OpenSSL's `EVP_BytesToKey` with MD5 and one iteration.
pub fn deriveMasterKey(
    password: []const u8,
    key_length: usize,
    output: *[32]u8,
) Error![]const u8 {
    if (key_length != 16 and key_length != 32) {
        return error.InvalidKeyLength;
    }
    if (password.len == 0) return error.InvalidKeyLength;

    var previous: [16]u8 = undefined;
    var have_previous = false;
    var offset: usize = 0;
    while (offset < key_length) {
        var digest = std.crypto.hash.Md5.init(.{});
        if (have_previous) digest.update(&previous);
        digest.update(password);
        digest.final(&previous);
        have_previous = true;
        const take = @min(16, key_length - offset);
        @memcpy(output[offset..][0..take], previous[0..take]);
        offset += take;
    }
    return output[0..key_length];
}

/// HKDF-SHA1 with info `ss-subkey` and the connection salt.
pub fn deriveSubkey(
    algorithm: Algorithm,
    master_key: []const u8,
    salt: []const u8,
    output: []u8,
) Error!void {
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.HmacSha1);
    if (salt.len != algorithm.saltLength() or
        master_key.len != algorithm.keyLength() or
        output.len != algorithm.keyLength())
    {
        return error.InvalidKeyLength;
    }
    const prk = Hkdf.extract(salt, master_key);
    Hkdf.expand(output, "ss-subkey", prk);
}

test "password derivation matches EVP_BytesToKey reference vectors" {
    var output: [32]u8 = undefined;
    const key16 = try deriveMasterKey("test", 16, &output);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x09, 0x8f, 0x6b, 0xcd, 0x46, 0x21, 0xd3, 0x73,
            0xca, 0xde, 0x4e, 0x83, 0x26, 0x27, 0xb4, 0xf6,
        },
        key16,
    );

    const key32 = try deriveMasterKey("test", 32, &output);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x09, 0x8f, 0x6b, 0xcd, 0x46, 0x21, 0xd3, 0x73,
            0xca, 0xde, 0x4e, 0x83, 0x26, 0x27, 0xb4, 0xf6,
            0x0a, 0x91, 0x72, 0x71, 0x6a, 0xe6, 0x42, 0x84,
            0x09, 0x88, 0x5b, 0x8b, 0x82, 0x9c, 0xcb, 0x05,
        },
        key32,
    );
}

test "HKDF-SHA1 subkeys match reference vectors" {
    var output: [32]u8 = undefined;
    const master16 = try deriveMasterKey("test", 16, &output);
    var salt16: [16]u8 = undefined;
    for (&salt16, 0..) |*byte, index| byte.* = @intCast(index);
    var subkey16: [16]u8 = undefined;
    try deriveSubkey(.aes_128_gcm, master16, &salt16, &subkey16);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x96, 0xb2, 0x49, 0xba, 0xa3, 0xb4, 0xe0, 0x0f,
            0x50, 0x2f, 0x84, 0xa5, 0xa9, 0x0a, 0xc7, 0x84,
        },
        &subkey16,
    );

    const master32 = try deriveMasterKey("test", 32, &output);
    var salt32: [32]u8 = undefined;
    for (&salt32, 0..) |*byte, index| byte.* = @intCast(index);
    var subkey32: [32]u8 = undefined;
    try deriveSubkey(.aes_256_gcm, master32, &salt32, &subkey32);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x02, 0x05, 0xfa, 0x48, 0x6a, 0xab, 0xee, 0x35,
            0xab, 0x86, 0xfc, 0x1f, 0xa0, 0x15, 0xf3, 0xa9,
            0xfc, 0x5c, 0x8c, 0xe7, 0x65, 0x7d, 0xb4, 0x27,
            0xd9, 0xba, 0x55, 0xb4, 0x9e, 0x71, 0x89, 0x53,
        },
        &subkey32,
    );
}

test "AEAD round trips for every supported cipher" {
    const algorithms = [_]Algorithm{
        .aes_128_gcm,
        .aes_256_gcm,
        .chacha20_ietf_poly1305,
    };
    for (algorithms) |algorithm| {
        const key = [_]u8{0x42} ** 32;
        var aead = try Aead.init(algorithm, key[0..algorithm.keyLength()]);
        defer aead.deinit();

        const plaintext = "shadowsocks chunk";
        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        var nonce: [12]u8 = @splat(0);
        aead.encrypt(&ciphertext, &tag, plaintext, "", nonce);
        var opened: [plaintext.len]u8 = undefined;
        try aead.decrypt(&opened, &ciphertext, tag, "", nonce);
        try std.testing.expectEqualStrings(plaintext, &opened);

        nonce[0] = 1;
        aead.encrypt(&ciphertext, &tag, plaintext, "", nonce);
        try aead.decrypt(&opened, &ciphertext, tag, "", nonce);
        try std.testing.expectEqualStrings(plaintext, &opened);

        ciphertext[0] ^= 1;
        try std.testing.expectError(
            error.AuthenticationFailed,
            aead.decrypt(&opened, &ciphertext, tag, "", nonce),
        );
    }
}

test "nonce increments as a little-endian counter" {
    var nonce: Nonce = .{};
    nonce.increment();
    try std.testing.expectEqual(@as(u8, 1), nonce.bytes[0]);
    for (0..255) |_| nonce.increment();
    try std.testing.expectEqual(@as(u8, 0), nonce.bytes[0]);
    try std.testing.expectEqual(@as(u8, 1), nonce.bytes[1]);
}

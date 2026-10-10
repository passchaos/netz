//! Bounded PBES2 decryption for encrypted PKCS#8 private keys.
//!
//! Supported inputs use PBKDF2 with HMAC-SHA1/SHA-256/SHA-384/SHA-512 and
//! AES-128-CBC or AES-256-CBC. The parser rejects non-canonical DER and bounds
//! both input sizes and KDF work before deriving a key.

const std = @import("std");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

const block_len: usize = 16;

pub const minimum_iterations: u32 = 1_000;
pub const maximum_iterations: u32 = 10_000_000;
pub const maximum_salt_bytes: usize = 64;
pub const maximum_encrypted_bytes: usize = 16 * 1024 + block_len;

pub const Error = std.mem.Allocator.Error || error{
    InvalidEncryptedPrivateKey,
    UnsupportedEncryption,
    WeakKdfParameters,
    KdfTooExpensive,
    EncryptedPrivateKeyTooLarge,
    InvalidPasswordOrCiphertext,
};

pub const Plaintext = struct {
    allocator: std.mem.Allocator,
    allocation: []u8,
    bytes: []const u8,

    pub fn deinit(self: *Plaintext) void {
        std.crypto.secureZero(u8, self.allocation);
        self.allocator.free(self.allocation);
        self.* = undefined;
    }
};

const Prf = enum { sha1, sha256, sha384, sha512 };
const Cipher = enum { aes128_cbc, aes256_cbc };

const Parameters = struct {
    salt: []const u8,
    iterations: u32,
    prf: Prf,
    cipher: Cipher,
    iv: [block_len]u8,
    ciphertext: []const u8,
};

const oid_pbes2 = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d";
const oid_pbkdf2 = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c";
const oid_hmac_sha1 = "\x2a\x86\x48\x86\xf7\x0d\x02\x07";
const oid_hmac_sha256 = "\x2a\x86\x48\x86\xf7\x0d\x02\x09";
const oid_hmac_sha384 = "\x2a\x86\x48\x86\xf7\x0d\x02\x0a";
const oid_hmac_sha512 = "\x2a\x86\x48\x86\xf7\x0d\x02\x0b";
const oid_aes128_cbc = "\x60\x86\x48\x01\x65\x03\x04\x01\x02";
const oid_aes256_cbc = "\x60\x86\x48\x01\x65\x03\x04\x01\x2a";

pub fn decryptAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    password: []const u8,
) Error!Plaintext {
    if (encoded.len > maximum_encrypted_bytes) {
        return error.EncryptedPrivateKeyTooLarge;
    }
    const parameters = try parseParameters(encoded);
    const plaintext = try allocator.dupe(u8, parameters.ciphertext);
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }
    var key = [_]u8{0} ** 32;
    defer std.crypto.secureZero(u8, &key);
    const key_len: usize = switch (parameters.cipher) {
        .aes128_cbc => 16,
        .aes256_cbc => 32,
    };
    deriveKey(
        key[0..key_len],
        password,
        parameters.salt,
        parameters.iterations,
        parameters.prf,
    );
    switch (parameters.cipher) {
        .aes128_cbc => decryptCbc(
            Aes128,
            plaintext,
            parameters.iv,
            key[0..16].*,
        ),
        .aes256_cbc => decryptCbc(
            Aes256,
            plaintext,
            parameters.iv,
            key,
        ),
    }
    const padding_len = validPaddingLength(plaintext) orelse
        return error.InvalidPasswordOrCiphertext;
    return .{
        .allocator = allocator,
        .allocation = plaintext,
        .bytes = plaintext[0 .. plaintext.len - padding_len],
    };
}

fn deriveKey(
    output: []u8,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    prf: Prf,
) void {
    switch (prf) {
        .sha1 => std.crypto.pwhash.pbkdf2(
            output,
            password,
            salt,
            iterations,
            HmacSha1,
        ) catch unreachable,
        .sha256 => std.crypto.pwhash.pbkdf2(
            output,
            password,
            salt,
            iterations,
            HmacSha256,
        ) catch unreachable,
        .sha384 => std.crypto.pwhash.pbkdf2(
            output,
            password,
            salt,
            iterations,
            HmacSha384,
        ) catch unreachable,
        .sha512 => std.crypto.pwhash.pbkdf2(
            output,
            password,
            salt,
            iterations,
            HmacSha512,
        ) catch unreachable,
    }
}

fn decryptCbc(
    comptime Aes: type,
    plaintext: []u8,
    iv: [block_len]u8,
    key: [Aes.key_bits / 8]u8,
) void {
    var context = Aes.initDec(key);
    defer std.crypto.secureZero(@TypeOf(context), (&context)[0..1]);
    var previous = iv;
    var clear: [block_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &clear);
    var offset: usize = 0;
    while (offset < plaintext.len) : (offset += block_len) {
        const ciphertext = plaintext[offset..][0..block_len].*;
        context.decrypt(&clear, &ciphertext);
        for (&clear, previous) |*byte, prior| byte.* ^= prior;
        @memcpy(plaintext[offset..][0..block_len], &clear);
        previous = ciphertext;
    }
}

fn validPaddingLength(plaintext: []const u8) ?usize {
    if (plaintext.len == 0 or plaintext.len % block_len != 0) return null;
    const padding: usize = plaintext[plaintext.len - 1];
    if (padding == 0 or padding > block_len) return null;
    var difference: u8 = 0;
    for (0..block_len) |index| {
        const mask: u8 = 0 -% @as(u8, @intFromBool(index < padding));
        difference |= (plaintext[plaintext.len - 1 - index] ^
            @as(u8, @intCast(padding))) & mask;
    }
    if (difference != 0) return null;
    return padding;
}

fn parseParameters(encoded: []const u8) Error!Parameters {
    var outer = Reader{ .bytes = encoded };
    const envelope = try outer.require(0x30);
    if (!outer.done()) return error.InvalidEncryptedPrivateKey;
    var fields = Reader{ .bytes = envelope };
    const algorithm = try fields.require(0x30);
    const ciphertext = try fields.require(0x04);
    if (!fields.done() or ciphertext.len == 0 or
        ciphertext.len > maximum_encrypted_bytes or
        ciphertext.len % block_len != 0)
    {
        return error.InvalidEncryptedPrivateKey;
    }

    var algorithm_fields = Reader{ .bytes = algorithm };
    if (!std.mem.eql(u8, try algorithm_fields.require(0x06), oid_pbes2)) {
        return error.UnsupportedEncryption;
    }
    const pbes2_parameters = try algorithm_fields.require(0x30);
    if (!algorithm_fields.done()) return error.InvalidEncryptedPrivateKey;
    var pbes2 = Reader{ .bytes = pbes2_parameters };
    const kdf = try pbes2.require(0x30);
    const encryption = try pbes2.require(0x30);
    if (!pbes2.done()) return error.InvalidEncryptedPrivateKey;

    const derivation = try parseKdf(kdf);
    const cipher = try parseCipher(encryption);
    if (derivation.key_len) |length| {
        const expected: usize = switch (cipher.kind) {
            .aes128_cbc => 16,
            .aes256_cbc => 32,
        };
        if (length != expected) return error.InvalidEncryptedPrivateKey;
    }
    return .{
        .salt = derivation.salt,
        .iterations = derivation.iterations,
        .prf = derivation.prf,
        .cipher = cipher.kind,
        .iv = cipher.iv,
        .ciphertext = ciphertext,
    };
}

const Kdf = struct {
    salt: []const u8,
    iterations: u32,
    key_len: ?usize,
    prf: Prf,
};

fn parseKdf(encoded: []const u8) Error!Kdf {
    var algorithm = Reader{ .bytes = encoded };
    if (!std.mem.eql(u8, try algorithm.require(0x06), oid_pbkdf2)) {
        return error.UnsupportedEncryption;
    }
    const encoded_parameters = try algorithm.require(0x30);
    if (!algorithm.done()) return error.InvalidEncryptedPrivateKey;
    var parameters = Reader{ .bytes = encoded_parameters };
    const salt = try parameters.require(0x04);
    if (salt.len < 8) return error.WeakKdfParameters;
    if (salt.len > maximum_salt_bytes) return error.InvalidEncryptedPrivateKey;
    const iterations = try positiveIntegerU32(
        try parameters.require(0x02),
    );
    if (iterations < minimum_iterations) return error.WeakKdfParameters;
    if (iterations > maximum_iterations) return error.KdfTooExpensive;

    var key_len: ?usize = null;
    if (parameters.peekTag() == 0x02) {
        key_len = try positiveIntegerU32(try parameters.require(0x02));
    }
    const prf = if (!parameters.done())
        try parsePrf(try parameters.require(0x30))
    else
        .sha1;
    if (!parameters.done()) return error.InvalidEncryptedPrivateKey;
    return .{
        .salt = salt,
        .iterations = iterations,
        .key_len = key_len,
        .prf = prf,
    };
}

fn parsePrf(encoded: []const u8) Error!Prf {
    var fields = Reader{ .bytes = encoded };
    const oid = try fields.require(0x06);
    if (!fields.done()) {
        const parameters = try fields.require(0x05);
        if (parameters.len != 0 or !fields.done()) {
            return error.InvalidEncryptedPrivateKey;
        }
    }
    if (std.mem.eql(u8, oid, oid_hmac_sha1)) return .sha1;
    if (std.mem.eql(u8, oid, oid_hmac_sha256)) return .sha256;
    if (std.mem.eql(u8, oid, oid_hmac_sha384)) return .sha384;
    if (std.mem.eql(u8, oid, oid_hmac_sha512)) return .sha512;
    return error.UnsupportedEncryption;
}

const CipherParameters = struct {
    kind: Cipher,
    iv: [block_len]u8,
};

fn parseCipher(encoded: []const u8) Error!CipherParameters {
    var fields = Reader{ .bytes = encoded };
    const oid = try fields.require(0x06);
    const kind: Cipher = if (std.mem.eql(u8, oid, oid_aes128_cbc))
        .aes128_cbc
    else if (std.mem.eql(u8, oid, oid_aes256_cbc))
        .aes256_cbc
    else
        return error.UnsupportedEncryption;
    const encoded_iv = try fields.require(0x04);
    if (encoded_iv.len != block_len or !fields.done()) {
        return error.InvalidEncryptedPrivateKey;
    }
    return .{ .kind = kind, .iv = encoded_iv[0..block_len].* };
}

fn positiveIntegerU32(encoded: []const u8) Error!u32 {
    if (encoded.len == 0 or encoded[0] & 0x80 != 0) {
        return error.InvalidEncryptedPrivateKey;
    }
    var bytes = encoded;
    if (bytes.len > 1 and bytes[0] == 0) {
        if (bytes[1] & 0x80 == 0) return error.InvalidEncryptedPrivateKey;
        bytes = bytes[1..];
    }
    if (bytes.len > @sizeOf(u32)) return error.InvalidEncryptedPrivateKey;
    var value: u32 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    if (value == 0) return error.InvalidEncryptedPrivateKey;
    return value;
}

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn require(self: *Reader, expected_tag: u8) Error![]const u8 {
        if (self.offset + 2 > self.bytes.len or
            self.bytes[self.offset] != expected_tag)
        {
            return error.InvalidEncryptedPrivateKey;
        }
        self.offset += 1;
        const first = self.bytes[self.offset];
        self.offset += 1;
        var length: usize = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or
                count > self.bytes.len - self.offset or
                self.bytes[self.offset] == 0)
            {
                return error.InvalidEncryptedPrivateKey;
            }
            for (self.bytes[self.offset .. self.offset + count]) |byte| {
                length = std.math.mul(usize, length, 256) catch
                    return error.InvalidEncryptedPrivateKey;
                length = std.math.add(usize, length, byte) catch
                    return error.InvalidEncryptedPrivateKey;
            }
            self.offset += count;
            if (length < 0x80) return error.InvalidEncryptedPrivateKey;
        }
        if (length > self.bytes.len - self.offset) {
            return error.InvalidEncryptedPrivateKey;
        }
        const value = self.bytes[self.offset .. self.offset + length];
        self.offset += length;
        return value;
    }

    fn peekTag(self: Reader) ?u8 {
        return if (self.offset < self.bytes.len) self.bytes[self.offset] else null;
    }

    fn done(self: Reader) bool {
        return self.offset == self.bytes.len;
    }
};

test "encrypted private key rejects malformed input and invalid padding" {
    try std.testing.expectError(
        error.InvalidEncryptedPrivateKey,
        decryptAlloc(std.testing.allocator, &.{}, "password"),
    );
    try std.testing.expectEqual(@as(?usize, 16), validPaddingLength(
        &([_]u8{16} ** 16),
    ));
    try std.testing.expect(validPaddingLength(&([_]u8{0} ** 16)) == null);
    var invalid = [_]u8{4} ** 16;
    invalid[14] = 3;
    try std.testing.expect(validPaddingLength(&invalid) == null);
    try std.testing.expectEqual(
        @as(u32, minimum_iterations),
        try positiveIntegerU32(&.{ 0x03, 0xe8 }),
    );
    try std.testing.expectError(
        error.InvalidEncryptedPrivateKey,
        positiveIntegerU32(&.{ 0x00, 0x01 }),
    );
}

test "encrypted private key decrypts PBES2 PBKDF2 AES-128-CBC" {
    const allocator = std.testing.allocator;
    const password = "test password";
    const salt = [_]u8{ 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87 };
    const iv = [_]u8{
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
    };
    var key: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    deriveKey(&key, password, &salt, minimum_iterations, .sha256);
    var padded = [_]u8{12} ** block_len;
    @memcpy(padded[0..4], "test");
    for (&padded, iv) |*byte, prior| byte.* ^= prior;
    var ciphertext: [block_len]u8 = undefined;
    var context = Aes128.initEnc(key);
    defer std.crypto.secureZero(@TypeOf(context), (&context)[0..1]);
    context.encrypt(&ciphertext, &padded);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, &.{ 0x30, 0x6b, 0x30, 0x57, 0x06, 0x09 });
    try encoded.appendSlice(allocator, oid_pbes2);
    try encoded.appendSlice(allocator, &.{ 0x30, 0x4a, 0x30, 0x29, 0x06, 0x09 });
    try encoded.appendSlice(allocator, oid_pbkdf2);
    try encoded.appendSlice(allocator, &.{ 0x30, 0x1c, 0x04, 0x08 });
    try encoded.appendSlice(allocator, &salt);
    try encoded.appendSlice(allocator, &.{ 0x02, 0x02, 0x03, 0xe8, 0x30, 0x0c, 0x06, 0x08 });
    try encoded.appendSlice(allocator, oid_hmac_sha256);
    try encoded.appendSlice(allocator, &.{ 0x05, 0x00, 0x30, 0x1d, 0x06, 0x09 });
    try encoded.appendSlice(allocator, oid_aes128_cbc);
    try encoded.appendSlice(allocator, &.{ 0x04, 0x10 });
    try encoded.appendSlice(allocator, &iv);
    try encoded.appendSlice(allocator, &.{ 0x04, 0x10 });
    try encoded.appendSlice(allocator, &ciphertext);
    try std.testing.expectEqual(@as(usize, 109), encoded.items.len);

    var plaintext = try decryptAlloc(allocator, encoded.items, password);
    defer plaintext.deinit();
    try std.testing.expectEqualStrings("test", plaintext.bytes);
    try std.testing.expectError(
        error.InvalidPasswordOrCiphertext,
        decryptAlloc(allocator, encoded.items, "wrong password"),
    );
}

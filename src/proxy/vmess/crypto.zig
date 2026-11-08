//! VMess legacy key derivation, authentication, AES-CFB, and checksum.

const std = @import("std");

pub const cmd_key_salt = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

pub fn cmdKey(uuid: [16]u8, output: *[16]u8) void {
    var hash = std.crypto.hash.Md5.init(.{});
    hash.update(&uuid);
    hash.update(cmd_key_salt);
    hash.final(output);
}

pub fn timestampMessage(timestamp: i64) [32]u8 {
    var message: [32]u8 = undefined;
    const seconds: u64 = @intCast(timestamp);
    for (0..4) |index| {
        std.mem.writeInt(
            u64,
            message[index * 8 ..][0..8],
            seconds,
            .big,
        );
    }
    return message;
}

pub fn timestampIv(timestamp: i64) [16]u8 {
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(&timestampMessage(timestamp), &digest, .{});
    return digest;
}

pub fn timestampAuth(uuid: [16]u8, timestamp: i64) [16]u8 {
    var digest: [16]u8 = undefined;
    std.crypto.auth.hmac.HmacMd5.create(
        &digest,
        &timestampMessage(timestamp),
        &uuid,
    );
    return digest;
}

pub fn fnv1a32(bytes: []const u8) u32 {
    var hash = std.hash.Fnv1a_32.init();
    hash.update(bytes);
    return hash.final();
}

pub const Cfb = struct {
    aes: std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128),
    next: [16]u8,
    out: [16]u8,
    out_used: usize = 16,
    decrypt: bool,

    pub fn initDecrypt(key: [16]u8, iv: [16]u8) Cfb {
        return .{
            .aes = std.crypto.core.aes.Aes128.initEnc(key),
            .next = iv,
            .out = undefined,
            .decrypt = true,
        };
    }

    pub fn initEncrypt(key: [16]u8, iv: [16]u8) Cfb {
        return .{
            .aes = std.crypto.core.aes.Aes128.initEnc(key),
            .next = iv,
            .out = undefined,
            .decrypt = false,
        };
    }

    pub fn process(self: *Cfb, output: []u8, input: []const u8) void {
        var offset: usize = 0;
        while (offset < input.len) {
            if (self.out_used == self.out.len) {
                self.aes.encrypt(&self.out, &self.next);
                self.out_used = 0;
            }
            const take = @min(input.len - offset, self.out.len - self.out_used);
            if (self.decrypt) {
                @memcpy(
                    self.next[self.out_used..][0..take],
                    input[offset..][0..take],
                );
            }
            for (0..take) |index| {
                output[offset + index] =
                    input[offset + index] ^ self.out[self.out_used + index];
            }
            if (!self.decrypt) {
                @memcpy(
                    self.next[self.out_used..][0..take],
                    output[offset..][0..take],
                );
            }
            self.out_used += take;
            offset += take;
        }
    }
};

test "VMess command keys and timestamps match reference vectors" {
    const uuid: [16]u8 = .{
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
        0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
    };
    var key: [16]u8 = undefined;
    cmdKey(uuid, &key);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0xb5, 0x0d, 0x91, 0x6a, 0xc0, 0xce, 0xc0, 0x67,
            0x98, 0x1a, 0xf8, 0xe5, 0xf3, 0x8a, 0x75, 0x8f,
        },
        &key,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x7a, 0x29, 0xd7, 0xbd, 0xc9, 0x72, 0xaa, 0xef,
            0xb1, 0xf5, 0x4e, 0x52, 0x05, 0x58, 0x9e, 0x78,
        },
        &timestampIv(1700000000),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x60, 0xc7, 0x31, 0xe7, 0x3e, 0x09, 0x66, 0x6d,
            0x7c, 0x5f, 0xea, 0x9d, 0xcd, 0x35, 0x3d, 0x4e,
        },
        &timestampAuth(uuid, 1700000000),
    );
}

test "AES-CFB encrypts and decrypts arbitrary lengths" {
    const key = [_]u8{0x42} ** 16;
    const iv = [_]u8{0x24} ** 16;
    const plaintext = "vmess legacy header payload with an odd length";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decryptor = Cfb.initDecrypt(key, iv);
    var encryptor = Cfb.initEncrypt(key, iv);
    encryptor.process(&ciphertext, plaintext);
    var opened: [plaintext.len]u8 = undefined;
    decryptor.process(&opened, &ciphertext);
    try std.testing.expectEqualStrings(plaintext, &opened);
}

test "FNV-1a matches the VMess checksum reference" {
    try std.testing.expectEqual(
        @as(u32, 0x811c9dc5),
        fnv1a32(""),
    );
    try std.testing.expectEqual(
        @as(u32, 0xe40c292c),
        fnv1a32("a"),
    );
}

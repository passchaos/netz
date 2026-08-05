const std = @import("std");

pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const secret_len = HkdfSha256.prk_length;
pub const aes_128_key_len = Aes128Gcm.key_length;
pub const iv_len = Aes128Gcm.nonce_length;
pub const hp_key_len = aes_128_key_len;
pub const aead_tag_len = Aes128Gcm.tag_length;
pub const header_protection_sample_len = 16;
pub const header_protection_mask_len = 5;

pub const Error = error{
    InvalidPacketNumber,
    InvalidPacketNumberLength,
    InvalidPayloadLength,
} || std.crypto.errors.AuthenticationError;

pub const HeaderForm = enum {
    long,
    short,
};

pub const PacketProtectionKeys = struct {
    secret: [secret_len]u8,
    key: [aes_128_key_len]u8,
    iv: [iv_len]u8,
    hp: [hp_key_len]u8,
};

pub const InitialSecrets = struct {
    initial_secret: [secret_len]u8,
    client: PacketProtectionKeys,
    server: PacketProtectionKeys,
};

pub fn deriveInitialSecrets(client_initial_dcid: []const u8) InitialSecrets {
    const initial_secret = HkdfSha256.extract(&initial_salt_v1, client_initial_dcid);
    const client_secret = hkdfExpandLabel(initial_secret, "client in", secret_len);
    const server_secret = hkdfExpandLabel(initial_secret, "server in", secret_len);
    return .{
        .initial_secret = initial_secret,
        .client = deriveAes128Keys(client_secret),
        .server = deriveAes128Keys(server_secret),
    };
}

pub fn deriveAes128Keys(secret: [secret_len]u8) PacketProtectionKeys {
    return .{
        .secret = secret,
        .key = hkdfExpandLabel(secret, "quic key", aes_128_key_len),
        .iv = hkdfExpandLabel(secret, "quic iv", iv_len),
        .hp = hkdfExpandLabel(secret, "quic hp", hp_key_len),
    };
}

pub fn hkdfExpandLabel(secret: [secret_len]u8, label: []const u8, comptime len: usize) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, "", len);
}

pub fn packetProtectionNonce(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    var nonce = iv;
    var packet_number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &packet_number_bytes, packet_number, .big);
    for (packet_number_bytes, 0..) |byte, i| {
        nonce[iv_len - packet_number_bytes.len + i] ^= byte;
    }
    return nonce;
}

pub fn aes128HeaderProtectionMask(hp_key: [hp_key_len]u8, sample: [header_protection_sample_len]u8) [header_protection_mask_len]u8 {
    const aes = std.crypto.core.aes.Aes128.initEnc(hp_key);
    var encrypted: [header_protection_sample_len]u8 = undefined;
    aes.encrypt(&encrypted, &sample);
    return encrypted[0..header_protection_mask_len].*;
}

pub fn applyHeaderProtectionMask(
    header_form: HeaderForm,
    first_byte: *u8,
    packet_number_bytes: []u8,
    mask: [header_protection_mask_len]u8,
) Error!void {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    const first_byte_mask: u8 = switch (header_form) {
        .long => 0x0f,
        .short => 0x1f,
    };
    first_byte.* ^= mask[0] & first_byte_mask;
    for (packet_number_bytes, 0..) |*byte, i| {
        byte.* ^= mask[i + 1];
    }
}

pub fn protectAes128Payload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
) Error!void {
    if (ciphertext.len != plaintext.len) return error.InvalidPayloadLength;
    const nonce = packetProtectionNonce(keys.iv, packet_number);
    Aes128Gcm.encrypt(ciphertext, tag, plaintext, associated_data, nonce, keys.key);
}

pub fn openAes128Payload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [aead_tag_len]u8,
    plaintext: []u8,
) Error!void {
    if (plaintext.len != ciphertext.len) return error.InvalidPayloadLength;
    const nonce = packetProtectionNonce(keys.iv, packet_number);
    try Aes128Gcm.decrypt(plaintext, ciphertext, tag, associated_data, nonce, keys.key);
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected_buf: [128]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_buf, expected_hex);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "QUIC initial secrets match RFC 9001 Appendix A.1" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = deriveInitialSecrets(&dcid);

    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial_secret);
    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", &secrets.client.secret);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &secrets.client.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &secrets.client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &secrets.client.hp);
    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", &secrets.server.secret);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", &secrets.server.key);
    try expectHex("0ac1493ca1905853b0bba03e", &secrets.server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", &secrets.server.hp);
}

test "QUIC AES header protection mask matches RFC 9001 Appendix A.2 sample" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = deriveInitialSecrets(&dcid);
    var sample: [header_protection_sample_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = aes128HeaderProtectionMask(secrets.client.hp, sample);
    try expectHex("437b9aec36", &mask);

    var first_byte: u8 = 0xc3;
    var packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc0), first_byte);
    try expectHex("7b9aec34", &packet_number);
    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc3), first_byte);
    try expectHex("00000002", &packet_number);
}

test "QUIC AES payload protection roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = deriveInitialSecrets(&dcid).client;
    const ad = "initial header pn";
    const plaintext = "crypto frame bytes";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(keys, 2, ad, plaintext, &ciphertext, &tag);

    var opened: [plaintext.len]u8 = undefined;
    try openAes128Payload(keys, 2, ad, &ciphertext, tag, &opened);
    try std.testing.expectEqualStrings(plaintext, &opened);

    var bad_tag = tag;
    bad_tag[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, openAes128Payload(keys, 2, ad, &ciphertext, bad_tag, &opened));
}

const std = @import("std");
const varint = @import("varint.zig");
const wire = @import("../internal/wire.zig");

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
    InvalidInitialPacket,
    InvalidHeaderProtectionSample,
    InvalidPacketNumber,
    InvalidPacketNumberLength,
    InvalidPayloadLength,
    VarIntTooLarge,
    BufferTooShort,
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

pub const InitialPacketOptions = struct {
    version: u32 = 0x00000001,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{},
    packet_number: u64,
    packet_number_len: u8 = 4,
    payload: []const u8,
};

pub const OpenedInitialPacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    token: []u8,
    packet_number: u64,
    payload: []u8,

    pub fn deinit(self: *OpenedInitialPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.source_connection_id);
        allocator.free(self.token);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const HandshakePacketOptions = struct {
    version: u32 = 0x00000001,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    payload: []const u8,
};

pub const OpenedHandshakePacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    packet_number: u64,
    payload: []u8,

    pub fn deinit(self: *OpenedHandshakePacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.source_connection_id);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const ShortPacketOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    key_phase: bool = false,
    payload: []const u8,
};

pub const OpenedShortPacket = struct {
    destination_connection_id: []u8,
    packet_number: u64,
    key_phase: bool,
    payload: []u8,

    pub fn deinit(self: *OpenedShortPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.payload);
        self.* = undefined;
    }
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

pub fn sealInitialPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: InitialPacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = 0xc0 | @as(u8, @intCast(pn_len - 1));
    try out.append(allocator, first_byte);
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_bytes, options.version, .big);
    try out.appendSlice(allocator, &version_bytes);
    try out.append(allocator, @intCast(options.destination_connection_id.len));
    try out.appendSlice(allocator, options.destination_connection_id);
    try out.append(allocator, @intCast(options.source_connection_id.len));
    try out.appendSlice(allocator, options.source_connection_id);
    try varint.encode(&out, allocator, options.token.len);
    try out.appendSlice(allocator, options.token);

    const protected_payload_len = options.payload.len + aead_tag_len;
    try varint.encode(&out, allocator, pn_len + protected_payload_len);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtection(keys.hp, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openInitialPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedInitialPacket {
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    _ = try cursor.readByte();
    const version = try cursor.readInt(u32, .big);
    const dcid_len = try cursor.readByte();
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    const scid = try cursor.readSlice(scid_len);
    const token_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const token = try cursor.readSlice(token_len);
    const protected_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const pn_offset = cursor.pos;
    if (bytes.len < pn_offset + protected_len) return error.BufferTooShort;

    try removeHeaderProtection(keys.hp, .long, bytes, pn_offset);
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    if (protected_len < pn_len + aead_tag_len) return error.InvalidInitialPacket;
    const payload_offset = pn_offset + pn_len;
    const packet_number = reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const packet_end = pn_offset + protected_len;
    const ciphertext = bytes[payload_offset .. packet_end - aead_tag_len];
    const tag = bytes[packet_end - aead_tag_len .. packet_end][0..aead_tag_len].*;

    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);
    const token_owned = try allocator.dupe(u8, token);
    errdefer allocator.free(token_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .token = token_owned,
        .packet_number = packet_number,
        .payload = payload,
    };
}

pub fn sealHandshakePacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: HandshakePacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = 0xe0 | @as(u8, @intCast(pn_len - 1));
    try out.append(allocator, first_byte);
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_bytes, options.version, .big);
    try out.appendSlice(allocator, &version_bytes);
    try out.append(allocator, @intCast(options.destination_connection_id.len));
    try out.appendSlice(allocator, options.destination_connection_id);
    try out.append(allocator, @intCast(options.source_connection_id.len));
    try out.appendSlice(allocator, options.source_connection_id);

    const protected_payload_len = options.payload.len + aead_tag_len;
    try varint.encode(&out, allocator, pn_len + protected_payload_len);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtection(keys.hp, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openHandshakePacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedHandshakePacket {
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0xf0) != 0xe0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    _ = try cursor.readByte();
    const version = try cursor.readInt(u32, .big);
    const dcid_len = try cursor.readByte();
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    const scid = try cursor.readSlice(scid_len);
    const protected_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const pn_offset = cursor.pos;
    if (bytes.len < pn_offset + protected_len) return error.BufferTooShort;

    try removeHeaderProtection(keys.hp, .long, bytes, pn_offset);
    if ((bytes[0] & 0xf0) != 0xe0) return error.InvalidInitialPacket;
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    if (protected_len < pn_len + aead_tag_len) return error.InvalidInitialPacket;
    const payload_offset = pn_offset + pn_len;
    const packet_number = reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const packet_end = pn_offset + protected_len;
    const ciphertext = bytes[payload_offset .. packet_end - aead_tag_len];
    const tag = bytes[packet_end - aead_tag_len .. packet_end][0..aead_tag_len].*;

    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .packet_number = packet_number,
        .payload = payload,
    };
}

pub fn sealShortPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: ShortPacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = 0x40 |
        (if (options.key_phase) @as(u8, 0x04) else 0) |
        @as(u8, @intCast(pn_len - 1));
    try out.append(allocator, first_byte);
    try out.appendSlice(allocator, options.destination_connection_id);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);
    try applyHeaderProtection(keys.hp, .short, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openShortPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
) Error!OpenedShortPacket {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 1 + destination_connection_id_len + 1 + aead_tag_len or (bytes[0] & 0x80) != 0 or (bytes[0] & 0x40) == 0) {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    try removeHeaderProtection(keys.hp, .short, bytes, pn_offset);
    if ((bytes[0] & 0x80) != 0 or (bytes[0] & 0x40) == 0) return error.InvalidInitialPacket;
    const key_phase = (bytes[0] & 0x04) != 0;
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    const payload_offset = pn_offset + pn_len;
    if (bytes.len < payload_offset + aead_tag_len) return error.InvalidInitialPacket;
    const packet_number = reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const ciphertext = bytes[payload_offset .. bytes.len - aead_tag_len];
    const tag = bytes[bytes.len - aead_tag_len ..][0..aead_tag_len].*;
    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);
    const dcid = try allocator.dupe(u8, bytes[1..pn_offset]);
    errdefer allocator.free(dcid);
    return .{
        .destination_connection_id = dcid,
        .packet_number = packet_number,
        .key_phase = key_phase,
        .payload = payload,
    };
}

pub fn applyHeaderProtection(
    hp_key: [hp_key_len]u8,
    header_form: HeaderForm,
    packet: []u8,
    pn_offset: usize,
) Error!void {
    if (pn_offset + 4 + header_protection_sample_len > packet.len) return error.InvalidHeaderProtectionSample;
    const sample = packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = aes128HeaderProtectionMask(hp_key, sample);
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    try applyHeaderProtectionMask(header_form, &packet[0], packet[pn_offset .. pn_offset + pn_len], mask);
}

pub fn removeHeaderProtection(
    hp_key: [hp_key_len]u8,
    header_form: HeaderForm,
    packet: []u8,
    pn_offset: usize,
) Error!void {
    if (pn_offset + 4 + header_protection_sample_len > packet.len) return error.InvalidHeaderProtectionSample;
    const sample = packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = aes128HeaderProtectionMask(hp_key, sample);
    packet[0] ^= mask[0] & switch (header_form) {
        .long => @as(u8, 0x0f),
        .short => @as(u8, 0x1f),
    };
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    if (pn_offset + pn_len > packet.len) return error.InvalidPacketNumberLength;
    for (packet[pn_offset .. pn_offset + pn_len], 0..) |*byte, i| {
        byte.* ^= mask[i + 1];
    }
}

fn validatePacketNumberLen(packet_number_len: u8) Error!void {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacketNumberLength;
}

fn appendTruncatedPacketNumber(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet_number: u64, packet_number_len: u8) Error!void {
    try validatePacketNumberLen(packet_number_len);
    var full: [8]u8 = undefined;
    std.mem.writeInt(u64, &full, packet_number, .big);
    try list.appendSlice(allocator, full[8 - packet_number_len ..]);
}

fn reconstructPacketNumber(expected_packet_number: u64, packet_number_bytes: []const u8) u64 {
    var truncated: u64 = 0;
    for (packet_number_bytes) |byte| truncated = (truncated << 8) | byte;
    const pn_nbits: u6 = @intCast(packet_number_bytes.len * 8);
    const pn_win = @as(u64, 1) << pn_nbits;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    var candidate = (expected_packet_number & ~pn_mask) | truncated;
    if (candidate + pn_hwin <= expected_packet_number and candidate < (std.math.maxInt(u62) - pn_win)) {
        candidate += pn_win;
    } else if (candidate > expected_packet_number + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }
    return candidate;
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

test "QUIC Initial packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const keys = deriveInitialSecrets(&dcid).client;
    const payload = "initial crypto payload";

    const sealed = try sealInitialPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 2,
        .packet_number_len = 4,
        .payload = payload,
    });
    defer allocator.free(sealed);
    try std.testing.expect(sealed.len > payload.len + dcid.len + scid.len);
    try std.testing.expect(sealed[0] != 0xc3); // Header protection changed the first byte for this vector.

    var opened = try openInitialPacket(allocator, keys, sealed, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), opened.version);
    try std.testing.expectEqual(@as(u64, 2), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);

    var tampered = try allocator.dupe(u8, sealed);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, openInitialPacket(allocator, keys, tampered, 0));
}

test "QUIC Handshake packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0x42} ** secret_len);
    const dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const payload = "encrypted extensions and finished";

    const sealed = try sealHandshakePacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 3,
        .packet_number_len = 2,
        .payload = payload,
    });
    defer allocator.free(sealed);

    var opened = try openHandshakePacket(allocator, keys, sealed, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);
}

test "QUIC 1-RTT short packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0x99} ** secret_len);
    const dcid = [_]u8{ 1, 3, 3, 7 };
    const payload = "stream frame payload";
    const sealed = try sealShortPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .packet_number = 9,
        .packet_number_len = 2,
        .key_phase = false,
        .payload = payload,
    });
    defer allocator.free(sealed);

    var opened = try openShortPacket(allocator, keys, sealed, dcid.len, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 9), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);
}

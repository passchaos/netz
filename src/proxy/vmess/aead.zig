//! VMess AEAD header protection.
//!
//! Implements the v2fly VMess AEAD KDF, AuthID creation/validation, and
//! AEAD-sealed request headers used by modern VMess clients.

const std = @import("std");
const vail = @import("vail");

const aes_gcm = vail.crypto.aes_gcm;
const crypto = @import("crypto.zig");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128 = std.crypto.core.aes.Aes128;

pub const kdf_base = "VMess AEAD KDF";
pub const salt_auth_id_key = "AES Auth ID Encryption";
pub const salt_header_length_key = "VMess Header AEAD Key_Length";
pub const salt_header_length_iv = "VMess Header AEAD Nonce_Length";
pub const salt_header_payload_key = "VMess Header AEAD Key";
pub const salt_header_payload_iv = "VMess Header AEAD Nonce";
pub const salt_resp_len_key = "AEAD Resp Header Len Key";
pub const salt_resp_len_iv = "AEAD Resp Header Len IV";
pub const salt_resp_payload_key = "AEAD Resp Header Key";
pub const salt_resp_payload_iv = "AEAD Resp Header IV";

pub const Error = error{
    InvalidAuthID,
    AuthenticationFailed,
    InvalidLength,
    BufferTooSmall,
};

/// Nested HMAC-SHA256 KDF used by VMess AEAD.
pub fn kdf(key: []const u8, path: []const []const u8) [32]u8 {
    return eval(path, key);
}

pub fn kdf16(key: []const u8, path: []const []const u8) [16]u8 {
    const full = kdf(key, path);
    return full[0..16].*;
}

fn eval(chain: []const []const u8, data: []const u8) [32]u8 {
    if (chain.len == 0) {
        var output: [32]u8 = undefined;
        Hmac.create(&output, data, kdf_base);
        return output;
    }
    const outer_key = chain[chain.len - 1];
    var keypad: [64]u8 = @splat(0);
    normalizeKey(outer_key, &keypad);

    var inner_input: [64 + 512]u8 = undefined;
    var ipad: [64]u8 = undefined;
    for (keypad, 0..) |byte, index| ipad[index] = byte ^ 0x36;
    @memcpy(inner_input[0..64], &ipad);
    @memcpy(inner_input[64..][0..data.len], data);
    const inner = eval(
        chain[0 .. chain.len - 1],
        inner_input[0 .. 64 + data.len],
    );

    var outer_input: [64 + 32]u8 = undefined;
    var opad: [64]u8 = undefined;
    for (keypad, 0..) |byte, index| opad[index] = byte ^ 0x5c;
    @memcpy(outer_input[0..64], &opad);
    @memcpy(outer_input[64..][0..32], &inner);
    return eval(chain[0 .. chain.len - 1], outer_input[0..96]);
}

fn normalizeKey(key: []const u8, output: *[64]u8) void {
    @memset(output, 0);
    if (key.len > output.len) {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
        @memcpy(output[0..32], &digest);
        return;
    }
    @memcpy(output[0..key.len], key);
}

/// Encrypt a 12-byte AuthID payload with AES-128-ECB.
pub fn createAuthID(
    cmd_key: [16]u8,
    timestamp: i64,
    random: [4]u8,
) [16]u8 {
    var plain: [16]u8 = undefined;
    std.mem.writeInt(i64, plain[0..8], timestamp, .big);
    @memcpy(plain[8..12], &random);
    const checksum = std.hash.Crc32.hash(plain[0..12]);
    std.mem.writeInt(u32, plain[12..16], checksum, .big);
    const key = kdf16(&cmd_key, &.{salt_auth_id_key});
    var encrypted: [16]u8 = undefined;
    const context = Aes128.initEnc(key);
    context.encrypt(&encrypted, &plain);
    return encrypted;
}

pub const DecodedAuthID = struct {
    timestamp: i64,
    valid_checksum: bool,
};

pub fn decodeAuthID(cmd_key: [16]u8, auth_id: [16]u8) DecodedAuthID {
    const key = kdf16(&cmd_key, &.{salt_auth_id_key});
    var plain: [16]u8 = undefined;
    const context = Aes128.initDec(key);
    context.decrypt(&plain, &auth_id);
    const timestamp = std.mem.readInt(i64, plain[0..8], .big);
    const expected = std.mem.readInt(u32, plain[12..16], .big);
    return .{
        .timestamp = timestamp,
        .valid_checksum = std.hash.Crc32.hash(plain[0..12]) == expected,
    };
}

pub const SealedHeader = struct {
    auth_id: [16]u8,
    wire: []u8,
};

/// Seal one VMess AEAD request header. `data` is the plaintext request header
/// produced by the VMess request builder.
pub fn sealHeader(
    allocator: std.mem.Allocator,
    cmd_key: [16]u8,
    timestamp: i64,
    random_auth: [4]u8,
    nonce: [8]u8,
    data: []const u8,
) !SealedHeader {
    if (data.len > 0xffff) return error.InvalidLength;
    const auth_id = createAuthID(cmd_key, timestamp, random_auth);

    var length_plain: [2]u8 = undefined;
    std.mem.writeInt(u16, &length_plain, @intCast(data.len), .big);

    const length_key = kdf16(&cmd_key, &.{
        salt_header_length_key,
        &auth_id,
        &nonce,
    });
    const length_nonce_full = kdf(&cmd_key, &.{
        salt_header_length_iv,
        &auth_id,
        &nonce,
    });
    const length_nonce: [12]u8 = length_nonce_full[0..12].*;

    const payload_key = kdf16(&cmd_key, &.{
        salt_header_payload_key,
        &auth_id,
        &nonce,
    });
    const payload_nonce_full = kdf(&cmd_key, &.{
        salt_header_payload_iv,
        &auth_id,
        &nonce,
    });
    const payload_nonce: [12]u8 = payload_nonce_full[0..12].*;

    const length_cipher = try allocator.alloc(u8, 2 + 16);
    defer allocator.free(length_cipher);
    var length_tag: [16]u8 = undefined;
    var length_context = aes_gcm.Aes128Gcm.init(length_key);
    defer length_context.deinit();
    length_context.encrypt(
        length_cipher[0..2],
        &length_tag,
        &length_plain,
        &auth_id,
        length_nonce,
    );
    @memcpy(length_cipher[2..18], &length_tag);

    const payload_cipher = try allocator.alloc(u8, data.len + 16);
    defer allocator.free(payload_cipher);
    var payload_tag: [16]u8 = undefined;
    var payload_context = aes_gcm.Aes128Gcm.init(payload_key);
    defer payload_context.deinit();
    payload_context.encrypt(
        payload_cipher[0..data.len],
        &payload_tag,
        data,
        &auth_id,
        payload_nonce,
    );
    @memcpy(payload_cipher[data.len..][0..16], &payload_tag);

    const wire = try allocator.alloc(u8, 18 + 8 + payload_cipher.len);
    errdefer allocator.free(wire);
    @memcpy(wire[0..18], length_cipher);
    @memcpy(wire[18..26], &nonce);
    @memcpy(wire[26..], payload_cipher);
    return .{ .auth_id = auth_id, .wire = wire };
}

pub const OpenResult = struct {
    data: []u8,
    auth_id: [16]u8,
    timestamp: i64,
};

/// Open an AEAD header after the caller has read the 16-byte AuthID.
pub fn openHeader(
    allocator: std.mem.Allocator,
    cmd_key: [16]u8,
    auth_id: [16]u8,
    connection: anytype,
) !OpenResult {
    const decoded = decodeAuthID(cmd_key, auth_id);
    if (!decoded.valid_checksum) return error.InvalidAuthID;

    var length_cipher: [18]u8 = undefined;
    try readExact(connection, &length_cipher);
    var nonce: [8]u8 = undefined;
    try readExact(connection, &nonce);

    const length_key = kdf16(&cmd_key, &.{
        salt_header_length_key,
        &auth_id,
        &nonce,
    });
    const length_nonce_full = kdf(&cmd_key, &.{
        salt_header_length_iv,
        &auth_id,
        &nonce,
    });
    const length_nonce: [12]u8 = length_nonce_full[0..12].*;
    var length_context = aes_gcm.Aes128Gcm.init(length_key);
    defer length_context.deinit();
    var length_plain: [2]u8 = undefined;
    length_context.decrypt(
        &length_plain,
        length_cipher[0..2],
        length_cipher[2..18].*,
        &auth_id,
        length_nonce,
    ) catch return error.AuthenticationFailed;
    const length = std.mem.readInt(u16, &length_plain, .big);

    const payload_key = kdf16(&cmd_key, &.{
        salt_header_payload_key,
        &auth_id,
        &nonce,
    });
    const payload_nonce_full = kdf(&cmd_key, &.{
        salt_header_payload_iv,
        &auth_id,
        &nonce,
    });
    const payload_nonce: [12]u8 = payload_nonce_full[0..12].*;

    const cipher = try allocator.alloc(u8, @as(usize, length) + 16);
    defer allocator.free(cipher);
    try readExact(connection, cipher);
    const data = try allocator.alloc(u8, length);
    errdefer allocator.free(data);
    var payload_context = aes_gcm.Aes128Gcm.init(payload_key);
    defer payload_context.deinit();
    payload_context.decrypt(
        data,
        cipher[0..length],
        cipher[length..][0..16].*,
        &auth_id,
        payload_nonce,
    ) catch return error.AuthenticationFailed;
    return .{
        .data = data,
        .auth_id = auth_id,
        .timestamp = decoded.timestamp,
    };
}

/// Encode the AEAD response header. The response body remains protocol-defined
/// (plaintext for security NONE).
pub fn encodeResponseHeader(
    body_key: [16]u8,
    body_iv: [16]u8,
    response_header: u8,
    connection: anytype,
) !void {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&body_key, &key_digest, .{});
    const response_key: [16]u8 = key_digest[0..16].*;
    var iv_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&body_iv, &iv_digest, .{});
    const response_iv: [16]u8 = iv_digest[0..16].*;

    var plain = [4]u8{ response_header, 0, 0, 0 };
    var encrypted_header: [4]u8 = undefined;
    var encryptor = crypto.Cfb.initEncrypt(response_key, response_iv);
    encryptor.process(&encrypted_header, &plain);

    const length_plain: [2]u8 = .{ 0, 4 };
    const length_key = kdf16(&response_key, &.{salt_resp_len_key});
    const length_iv_full = kdf(&response_iv, &.{salt_resp_len_iv});
    const length_iv: [12]u8 = length_iv_full[0..12].*;
    var length_context = aes_gcm.Aes128Gcm.init(length_key);
    defer length_context.deinit();
    var length_wire: [18]u8 = undefined;
    var length_tag: [16]u8 = undefined;
    length_context.encrypt(
        length_wire[0..2],
        &length_tag,
        &length_plain,
        "",
        length_iv,
    );
    @memcpy(length_wire[2..18], &length_tag);

    const payload_key = kdf16(&response_key, &.{salt_resp_payload_key});
    const payload_iv_full = kdf(&response_iv, &.{salt_resp_payload_iv});
    const payload_iv: [12]u8 = payload_iv_full[0..12].*;
    var payload_context = aes_gcm.Aes128Gcm.init(payload_key);
    defer payload_context.deinit();
    var payload_wire: [20]u8 = undefined;
    var payload_tag: [16]u8 = undefined;
    payload_context.encrypt(
        payload_wire[0..4],
        &payload_tag,
        &encrypted_header,
        "",
        payload_iv,
    );
    @memcpy(payload_wire[4..20], &payload_tag);

    try connection.writeAll(&length_wire);
    try connection.writeAll(&payload_wire);
}

/// Decode the AEAD response header on the client side.
pub fn decodeResponseHeader(
    body_key: [16]u8,
    body_iv: [16]u8,
    response_header: u8,
    connection: anytype,
) !void {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&body_key, &key_digest, .{});
    const response_key: [16]u8 = key_digest[0..16].*;
    var iv_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&body_iv, &iv_digest, .{});
    const response_iv: [16]u8 = iv_digest[0..16].*;

    var length_wire: [18]u8 = undefined;
    try readExact(connection, &length_wire);
    const length_key = kdf16(&response_key, &.{salt_resp_len_key});
    const length_iv_full = kdf(&response_iv, &.{salt_resp_len_iv});
    const length_iv: [12]u8 = length_iv_full[0..12].*;
    var length_context = aes_gcm.Aes128Gcm.init(length_key);
    defer length_context.deinit();
    var length_plain: [2]u8 = undefined;
    length_context.decrypt(
        &length_plain,
        length_wire[0..2],
        length_wire[2..18].*,
        "",
        length_iv,
    ) catch return error.AuthenticationFailed;
    const length = std.mem.readInt(u16, &length_plain, .big);
    if (length == 0 or length > 255) return error.InvalidLength;

    var payload_wire: [255 + 16]u8 = undefined;
    try readExact(connection, payload_wire[0 .. length + 16]);
    const payload_key = kdf16(&response_key, &.{salt_resp_payload_key});
    const payload_iv_full = kdf(&response_iv, &.{salt_resp_payload_iv});
    const payload_iv: [12]u8 = payload_iv_full[0..12].*;
    var payload_context = aes_gcm.Aes128Gcm.init(payload_key);
    defer payload_context.deinit();
    var payload_plain: [255]u8 = undefined;
    payload_context.decrypt(
        payload_plain[0..length],
        payload_wire[0..length],
        payload_wire[length..][0..16].*,
        "",
        payload_iv,
    ) catch return error.AuthenticationFailed;

    var decryptor = crypto.Cfb.initDecrypt(response_key, response_iv);
    var header_plain: [255]u8 = undefined;
    decryptor.process(header_plain[0..length], payload_plain[0..length]);
    if (header_plain[0] != response_header) return error.InvalidAuthID;
    if (length >= 3 and header_plain[2] != 0) {
        const command_len = header_plain[3];
        if (length < 4 + command_len) return error.InvalidLength;
    }
}

fn readExact(connection: anytype, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.AuthenticationFailed;
        offset += count;
    }
}

test "VMess AEAD KDF matches the upstream reference vector" {
    const key = kdf(
        "Demo Key for KDF Value Test",
        &.{
            "Demo Path for KDF Value Test",
            "Demo Path for KDF Value Test2",
            "Demo Path for KDF Value Test3",
        },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x53, 0xe9, 0xd7, 0xe1, 0xbd, 0x7b, 0xd2, 0x50,
            0x22, 0xb7, 0x1e, 0xad, 0x07, 0xd8, 0xa5, 0x96,
            0xef, 0xc8, 0xa8, 0x45, 0xc7, 0x88, 0x86, 0x52,
            0xfd, 0x68, 0x4b, 0x49, 0x03, 0xdc, 0x88, 0x92,
        },
        &key,
    );
}

test "VMess AEAD AuthID round trips and rejects corruption" {
    const cmd_key = kdf16(
        "Demo Key for Auth ID Test",
        &.{"Demo Path for Auth ID Test"},
    );
    const timestamp: i64 = 1700000000;
    const auth_id = createAuthID(cmd_key, timestamp, .{ 1, 2, 3, 4 });
    const decoded = decodeAuthID(cmd_key, auth_id);
    try std.testing.expect(decoded.valid_checksum);
    try std.testing.expectEqual(timestamp, decoded.timestamp);

    var corrupted = auth_id;
    corrupted[0] ^= 1;
    try std.testing.expect(!decodeAuthID(cmd_key, corrupted).valid_checksum);
}

test "VMess AEAD header seals and opens" {
    const allocator = std.testing.allocator;
    const cmd_key = kdf16(
        "Demo Key for Auth ID Test",
        &.{"Demo Path for Auth ID Test"},
    );
    const data = "Test Header";
    const sealed = try sealHeader(
        allocator,
        cmd_key,
        1700000000,
        .{ 1, 2, 3, 4 },
        .{ 5, 6, 7, 8, 9, 10, 11, 12 },
        data,
    );
    defer allocator.free(sealed.wire);

    var connection = MemoryConnection{ .bytes = sealed.wire };
    const opened = try openHeader(
        allocator,
        cmd_key,
        sealed.auth_id,
        &connection,
    );
    defer allocator.free(opened.data);
    try std.testing.expectEqualStrings(data, opened.data);
    try std.testing.expectEqual(@as(i64, 1700000000), opened.timestamp);
}

test "VMess AEAD header rejects a modified ciphertext" {
    const allocator = std.testing.allocator;
    const cmd_key = kdf16(
        "Demo Key for Auth ID Test",
        &.{"Demo Path for Auth ID Test"},
    );
    const sealed = try sealHeader(
        allocator,
        cmd_key,
        1700000000,
        .{ 1, 2, 3, 4 },
        .{ 5, 6, 7, 8, 9, 10, 11, 12 },
        "Test Header",
    );
    defer allocator.free(sealed.wire);
    sealed.wire[0] ^= 0xff;
    var connection = MemoryConnection{ .bytes = sealed.wire };
    try std.testing.expectError(
        error.AuthenticationFailed,
        openHeader(allocator, cmd_key, sealed.auth_id, &connection),
    );
}

test "VMess AEAD response header round trips" {
    const body_key = [_]u8{0x11} ** 16;
    const body_iv = [_]u8{0x22} ** 16;
    var output = MemoryConnection{};
    try encodeResponseHeader(body_key, body_iv, 0x42, &output);
    var input = MemoryConnection{ .bytes = output.written[0..output.written_len] };
    try decodeResponseHeader(body_key, body_iv, 0x42, &input);
}

const MemoryConnection = struct {
    bytes: []const u8 = &.{},
    offset: usize = 0,
    written: [512]u8 = undefined,
    written_len: usize = 0,

    fn read(self: *@This(), output: []u8) !usize {
        const available = self.bytes.len - self.offset;
        const take = @min(available, output.len);
        @memcpy(output[0..take], self.bytes[self.offset..][0..take]);
        self.offset += take;
        return take;
    }

    fn writeAll(self: *@This(), bytes: []const u8) !void {
        @memcpy(self.written[self.written_len..][0..bytes.len], bytes);
        self.written_len += bytes.len;
    }
};

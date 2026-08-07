const std = @import("std");
const quic = @import("mod.zig");
const wire = @import("../internal/wire.zig");

pub const Error = error{
    InvalidClientHello,
    InvalidServerHello,
    InvalidEncryptedExtensions,
    InvalidFinished,
    MissingKeyShare,
    MissingSupportedVersions,
    MissingTransportParameters,
    MissingAlpn,
    KeyExchangeFailed,
    BadFinished,
} || wire.Error || std.mem.Allocator.Error;

const handshake_type_client_hello: u8 = 0x01;
const handshake_type_server_hello: u8 = 0x02;
const handshake_type_encrypted_extensions: u8 = 0x08;
const handshake_type_finished: u8 = 0x14;
const tls_1_2: u16 = 0x0303;
const tls_1_3: u16 = 0x0304;
const cipher_tls_aes_128_gcm_sha256: u16 = 0x1301;
const group_x25519: u16 = 0x001d;

const ext_server_name: u16 = 0x0000;
const ext_supported_groups: u16 = 0x000a;
const ext_signature_algorithms: u16 = 0x000d;
const ext_alpn: u16 = 0x0010;
const ext_supported_versions: u16 = 0x002b;
const ext_key_share: u16 = 0x0033;
const ext_quic_transport_parameters: u16 = 0x0039;

pub const ClientHelloOptions = struct {
    random: [32]u8,
    x25519_public_key: [32]u8,
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &.{"h3"},
    transport_parameters: []const u8 = &.{},
};

pub const ParsedClientHello = struct {
    random: [32]u8,
    server_name: ?[]const u8,
    alpn_protocols: [][]const u8,
    x25519_public_key: []const u8,
    transport_parameters: []const u8,

    pub fn deinit(self: *ParsedClientHello, allocator: std.mem.Allocator) void {
        allocator.free(self.alpn_protocols);
        self.* = undefined;
    }
};

pub const ServerHelloOptions = struct {
    random: [32]u8,
    x25519_public_key: [32]u8,
};

pub const ParsedServerHello = struct {
    random: [32]u8,
    x25519_public_key: []const u8,
};

pub const HandshakeSecrets = struct {
    handshake_secret: [quic.protection.secret_len]u8,
    client_handshake_traffic_secret: [quic.protection.secret_len]u8,
    server_handshake_traffic_secret: [quic.protection.secret_len]u8,
    client_quic: quic.protection.PacketProtectionKeys,
    server_quic: quic.protection.PacketProtectionKeys,
};

pub const ApplicationSecrets = struct {
    master_secret: [quic.protection.secret_len]u8,
    client_application_traffic_secret: [quic.protection.secret_len]u8,
    server_application_traffic_secret: [quic.protection.secret_len]u8,
    client_quic: quic.protection.PacketProtectionKeys,
    server_quic: quic.protection.PacketProtectionKeys,
};

pub const ParsedEncryptedExtensions = struct {
    alpn: []const u8,
    transport_parameters: []const u8,
};

pub fn writeClientHello(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: ClientHelloOptions) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    try appendInt(&body, allocator, u16, tls_1_2);
    try body.appendSlice(allocator, &options.random);
    try body.append(allocator, 0); // legacy_session_id
    try appendInt(&body, allocator, u16, 2);
    try appendInt(&body, allocator, u16, cipher_tls_aes_128_gcm_sha256);
    try body.append(allocator, 1);
    try body.append(allocator, 0); // null compression

    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    if (options.server_name) |name| try writeServerNameExtension(&extensions, allocator, name);
    try writeSupportedGroupsExtension(&extensions, allocator);
    try writeSignatureAlgorithmsExtension(&extensions, allocator);
    try writeAlpnExtension(&extensions, allocator, options.alpn_protocols);
    try writeSupportedVersionsExtension(&extensions, allocator);
    try writeKeyShareExtension(&extensions, allocator, options.x25519_public_key);
    try writeExtension(&extensions, allocator, ext_quic_transport_parameters, options.transport_parameters);

    try appendU16Len(&body, allocator, extensions.items.len, error.InvalidClientHello);
    try body.appendSlice(allocator, extensions.items);

    try list.append(allocator, handshake_type_client_hello);
    try appendU24Len(list, allocator, body.items.len, error.InvalidClientHello);
    try list.appendSlice(allocator, body.items);
}

pub fn writeServerHello(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: ServerHelloOptions) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    try appendInt(&body, allocator, u16, tls_1_2);
    try body.appendSlice(allocator, &options.random);
    try body.append(allocator, 0); // legacy_session_id_echo
    try appendInt(&body, allocator, u16, cipher_tls_aes_128_gcm_sha256);
    try body.append(allocator, 0); // legacy_compression_method

    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    const supported_versions = [_]u8{ 0x03, 0x04 };
    try writeExtension(&extensions, allocator, ext_supported_versions, &supported_versions);

    var key_share: std.ArrayList(u8) = .empty;
    defer key_share.deinit(allocator);
    try appendInt(&key_share, allocator, u16, group_x25519);
    try appendInt(&key_share, allocator, u16, options.x25519_public_key.len);
    try key_share.appendSlice(allocator, &options.x25519_public_key);
    try writeExtension(&extensions, allocator, ext_key_share, key_share.items);

    try appendU16Len(&body, allocator, extensions.items.len, error.InvalidServerHello);
    try body.appendSlice(allocator, extensions.items);

    try list.append(allocator, handshake_type_server_hello);
    try appendU24Len(list, allocator, body.items.len, error.InvalidServerHello);
    try list.appendSlice(allocator, body.items);
}

pub fn writeEncryptedExtensions(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    alpn: []const u8,
    transport_parameters: []const u8,
) Error!void {
    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    if (alpn.len != 0) try writeAlpnExtension(&extensions, allocator, &.{alpn});
    try writeExtension(&extensions, allocator, ext_quic_transport_parameters, transport_parameters);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendU16Len(&body, allocator, extensions.items.len, error.InvalidEncryptedExtensions);
    try body.appendSlice(allocator, extensions.items);

    try list.append(allocator, handshake_type_encrypted_extensions);
    try appendU24Len(list, allocator, body.items.len, error.InvalidEncryptedExtensions);
    try list.appendSlice(allocator, body.items);
}

pub fn writeFinished(list: *std.ArrayList(u8), allocator: std.mem.Allocator, verify_data: [32]u8) Error!void {
    try list.append(allocator, handshake_type_finished);
    try appendU24(list, allocator, verify_data.len);
    try list.appendSlice(allocator, &verify_data);
}

pub fn parseClientHello(allocator: std.mem.Allocator, bytes: []const u8) Error!ParsedClientHello {
    var cursor = wire.Cursor.init(bytes);
    if (try cursor.readByte() != handshake_type_client_hello) return error.InvalidClientHello;
    const body_len = try readU24(&cursor);
    const body = try cursor.readSlice(body_len);
    if (!cursor.eof()) return error.InvalidClientHello;

    var body_cursor = wire.Cursor.init(body);
    if (try body_cursor.readInt(u16, .big) != tls_1_2) return error.InvalidClientHello;
    const random = (try body_cursor.readSlice(32))[0..32].*;
    const session_id_len = try body_cursor.readByte();
    try body_cursor.skip(session_id_len);

    const cipher_suites_len = try body_cursor.readInt(u16, .big);
    if (cipher_suites_len == 0 or cipher_suites_len % 2 != 0) return error.InvalidClientHello;
    try body_cursor.skip(cipher_suites_len);
    const compression_len = try body_cursor.readByte();
    if (compression_len == 0) return error.InvalidClientHello;
    try body_cursor.skip(compression_len);

    const extensions_len = try body_cursor.readInt(u16, .big);
    const extensions = try body_cursor.readSlice(extensions_len);
    if (!body_cursor.eof()) return error.InvalidClientHello;

    var server_name: ?[]const u8 = null;
    var x25519: ?[]const u8 = null;
    var transport_parameters: ?[]const u8 = null;
    var saw_supported_versions = false;
    var alpn_list: std.ArrayList([]const u8) = .empty;
    errdefer alpn_list.deinit(allocator);

    var ext_cursor = wire.Cursor.init(extensions);
    while (!ext_cursor.eof()) {
        const typ = try ext_cursor.readInt(u16, .big);
        const len = try ext_cursor.readInt(u16, .big);
        const payload = try ext_cursor.readSlice(len);
        switch (typ) {
            ext_server_name => server_name = try parseServerName(payload),
            ext_alpn => try parseAlpn(allocator, &alpn_list, payload),
            ext_supported_versions => {
                if (payload.len != 3 or payload[0] != 2 or std.mem.readInt(u16, payload[1..3], .big) != tls_1_3) {
                    return error.InvalidClientHello;
                }
                saw_supported_versions = true;
            },
            ext_key_share => x25519 = try parseX25519KeyShare(payload),
            ext_quic_transport_parameters => transport_parameters = payload,
            else => {},
        }
    }

    if (!saw_supported_versions) return error.MissingSupportedVersions;
    if (x25519 == null) return error.MissingKeyShare;
    if (transport_parameters == null) return error.MissingTransportParameters;
    if (alpn_list.items.len == 0) return error.MissingAlpn;

    return .{
        .random = random,
        .server_name = server_name,
        .alpn_protocols = try alpn_list.toOwnedSlice(allocator),
        .x25519_public_key = x25519.?,
        .transport_parameters = transport_parameters.?,
    };
}

pub fn parseServerHello(bytes: []const u8) Error!ParsedServerHello {
    var cursor = wire.Cursor.init(bytes);
    if (try cursor.readByte() != handshake_type_server_hello) return error.InvalidServerHello;
    const body_len = try readU24(&cursor);
    const body = try cursor.readSlice(body_len);
    if (!cursor.eof()) return error.InvalidServerHello;

    var body_cursor = wire.Cursor.init(body);
    if (try body_cursor.readInt(u16, .big) != tls_1_2) return error.InvalidServerHello;
    const random = (try body_cursor.readSlice(32))[0..32].*;
    const session_id_len = try body_cursor.readByte();
    try body_cursor.skip(session_id_len);
    if (try body_cursor.readInt(u16, .big) != cipher_tls_aes_128_gcm_sha256) return error.InvalidServerHello;
    if (try body_cursor.readByte() != 0) return error.InvalidServerHello;
    const extensions_len = try body_cursor.readInt(u16, .big);
    const extensions = try body_cursor.readSlice(extensions_len);
    if (!body_cursor.eof()) return error.InvalidServerHello;

    var saw_supported_versions = false;
    var x25519: ?[]const u8 = null;
    var ext_cursor = wire.Cursor.init(extensions);
    while (!ext_cursor.eof()) {
        const typ = try ext_cursor.readInt(u16, .big);
        const len = try ext_cursor.readInt(u16, .big);
        const payload = try ext_cursor.readSlice(len);
        switch (typ) {
            ext_supported_versions => {
                if (payload.len != 2 or std.mem.readInt(u16, payload[0..2], .big) != tls_1_3) return error.InvalidServerHello;
                saw_supported_versions = true;
            },
            ext_key_share => x25519 = try parseServerX25519KeyShare(payload),
            else => {},
        }
    }
    if (!saw_supported_versions) return error.MissingSupportedVersions;
    if (x25519 == null) return error.MissingKeyShare;
    return .{ .random = random, .x25519_public_key = x25519.? };
}

pub fn parseEncryptedExtensions(bytes: []const u8) Error!ParsedEncryptedExtensions {
    var cursor = wire.Cursor.init(bytes);
    if (try cursor.readByte() != handshake_type_encrypted_extensions) return error.InvalidEncryptedExtensions;
    const body_len = try readU24(&cursor);
    const body = try cursor.readSlice(body_len);
    if (!cursor.eof()) return error.InvalidEncryptedExtensions;

    var body_cursor = wire.Cursor.init(body);
    const extensions_len = try body_cursor.readInt(u16, .big);
    const extensions = try body_cursor.readSlice(extensions_len);
    if (!body_cursor.eof()) return error.InvalidEncryptedExtensions;

    var alpn: ?[]const u8 = null;
    var transport_parameters: ?[]const u8 = null;
    var ext_cursor = wire.Cursor.init(extensions);
    while (!ext_cursor.eof()) {
        const typ = try ext_cursor.readInt(u16, .big);
        const len = try ext_cursor.readInt(u16, .big);
        const payload = try ext_cursor.readSlice(len);
        switch (typ) {
            ext_alpn => {
                alpn = try parseSingleAlpn(payload);
            },
            ext_quic_transport_parameters => transport_parameters = payload,
            else => return error.InvalidEncryptedExtensions,
        }
    }
    return .{
        .alpn = alpn orelse return error.MissingAlpn,
        .transport_parameters = transport_parameters orelse return error.MissingTransportParameters,
    };
}

pub fn parseFinished(bytes: []const u8) Error![32]u8 {
    var cursor = wire.Cursor.init(bytes);
    if (try cursor.readByte() != handshake_type_finished) return error.InvalidFinished;
    const body_len = try readU24(&cursor);
    if (body_len != 32) return error.InvalidFinished;
    const verify_data = (try cursor.readSlice(32))[0..32].*;
    if (!cursor.eof()) return error.InvalidFinished;
    return verify_data;
}

pub fn x25519PublicKey(secret_key: [32]u8) Error![32]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(secret_key) catch return error.KeyExchangeFailed;
}

pub fn x25519SharedSecret(secret_key: [32]u8, peer_public_key: []const u8) Error![32]u8 {
    if (peer_public_key.len != 32) return error.MissingKeyShare;
    return std.crypto.dh.X25519.scalarmult(secret_key, peer_public_key[0..32].*) catch return error.KeyExchangeFailed;
}

pub fn transcriptHash(client_hello: []const u8, server_hello: []const u8) [32]u8 {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(client_hello);
    sha.update(server_hello);
    var out: [32]u8 = undefined;
    sha.final(&out);
    return out;
}

pub fn deriveHandshakeSecrets(shared_secret: [32]u8, transcript_hash: [32]u8) HandshakeSecrets {
    return deriveHandshakeSecretsForVersion(quic.Version.version_1.wireValue(), shared_secret, transcript_hash);
}

pub fn deriveHandshakeSecretsForVersion(version: u32, shared_secret: [32]u8, transcript_hash: [32]u8) HandshakeSecrets {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const zero_secret = [_]u8{0} ** quic.protection.secret_len;
    const early_secret = HkdfSha256.extract(&zero_secret, &.{});
    const empty_hash = std.crypto.tls.emptyHash(std.crypto.hash.sha2.Sha256);
    const derived_secret = std.crypto.tls.hkdfExpandLabel(HkdfSha256, early_secret, "derived", &empty_hash, quic.protection.secret_len);
    const handshake_secret = HkdfSha256.extract(&derived_secret, &shared_secret);
    const client_hs = std.crypto.tls.hkdfExpandLabel(HkdfSha256, handshake_secret, "c hs traffic", &transcript_hash, quic.protection.secret_len);
    const server_hs = std.crypto.tls.hkdfExpandLabel(HkdfSha256, handshake_secret, "s hs traffic", &transcript_hash, quic.protection.secret_len);
    return .{
        .handshake_secret = handshake_secret,
        .client_handshake_traffic_secret = client_hs,
        .server_handshake_traffic_secret = server_hs,
        .client_quic = quic.protection.deriveAes128KeysForVersion(version, client_hs),
        .server_quic = quic.protection.deriveAes128KeysForVersion(version, server_hs),
    };
}

pub fn deriveApplicationSecrets(handshake_secret: [32]u8, transcript_hash: [32]u8) ApplicationSecrets {
    return deriveApplicationSecretsForVersion(quic.Version.version_1.wireValue(), handshake_secret, transcript_hash);
}

pub fn deriveApplicationSecretsForVersion(version: u32, handshake_secret: [32]u8, transcript_hash: [32]u8) ApplicationSecrets {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const zero_secret = [_]u8{0} ** quic.protection.secret_len;
    const empty_hash = std.crypto.tls.emptyHash(std.crypto.hash.sha2.Sha256);
    const derived_secret = std.crypto.tls.hkdfExpandLabel(HkdfSha256, handshake_secret, "derived", &empty_hash, quic.protection.secret_len);
    const master_secret = HkdfSha256.extract(&derived_secret, &zero_secret);
    const client_ap = std.crypto.tls.hkdfExpandLabel(HkdfSha256, master_secret, "c ap traffic", &transcript_hash, quic.protection.secret_len);
    const server_ap = std.crypto.tls.hkdfExpandLabel(HkdfSha256, master_secret, "s ap traffic", &transcript_hash, quic.protection.secret_len);
    return .{
        .master_secret = master_secret,
        .client_application_traffic_secret = client_ap,
        .server_application_traffic_secret = server_ap,
        .client_quic = quic.protection.deriveAes128KeysForVersion(version, client_ap),
        .server_quic = quic.protection.deriveAes128KeysForVersion(version, server_ap),
    };
}

pub fn computeFinishedVerifyData(base_key: [32]u8, transcript_hash: [32]u8) [32]u8 {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const finished_key = std.crypto.tls.hkdfExpandLabel(HkdfSha256, base_key, "finished", "", 32);
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, &transcript_hash, &finished_key);
    return out;
}

pub fn verifyFinished(base_key: [32]u8, transcript_hash: [32]u8, verify_data: [32]u8) Error!void {
    const expected = computeFinishedVerifyData(base_key, transcript_hash);
    if (!std.crypto.timing_safe.eql([32]u8, expected, verify_data)) return error.BadFinished;
}

fn writeServerNameExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8) Error!void {
    const server_name_len = std.math.add(usize, 1 + 2, name.len) catch return error.InvalidClientHello;
    if (name.len > std.math.maxInt(u16) or server_name_len > std.math.maxInt(u16)) return error.InvalidClientHello;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try appendInt(&payload, allocator, u16, @intCast(server_name_len));
    try payload.append(allocator, 0);
    try appendInt(&payload, allocator, u16, @intCast(name.len));
    try payload.appendSlice(allocator, name);
    try writeExtension(list, allocator, ext_server_name, payload.items);
}

fn writeSupportedGroupsExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 2, .big);
    std.mem.writeInt(u16, payload[2..4], group_x25519, .big);
    try writeExtension(list, allocator, ext_supported_groups, &payload);
}

fn writeSignatureAlgorithmsExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    // ecdsa_secp256r1_sha256 + rsa_pss_rsae_sha256 are enough for a minimal offer.
    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 4, .big);
    std.mem.writeInt(u16, payload[2..4], 0x0403, .big);
    std.mem.writeInt(u16, payload[4..6], 0x0804, .big);
    try writeExtension(list, allocator, ext_signature_algorithms, &payload);
}

fn writeAlpnExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator, protocols: []const []const u8) Error!void {
    var names: std.ArrayList(u8) = .empty;
    defer names.deinit(allocator);
    for (protocols) |protocol| {
        if (protocol.len == 0 or protocol.len > 255) return error.InvalidClientHello;
        try names.append(allocator, @intCast(protocol.len));
        try names.appendSlice(allocator, protocol);
    }
    if (names.items.len > std.math.maxInt(u16)) return error.InvalidClientHello;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try appendInt(&payload, allocator, u16, @intCast(names.items.len));
    try payload.appendSlice(allocator, names.items);
    try writeExtension(list, allocator, ext_alpn, payload.items);
}

fn writeSupportedVersionsExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    const payload = [_]u8{ 2, 0x03, 0x04 };
    try writeExtension(list, allocator, ext_supported_versions, &payload);
}

fn writeKeyShareExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator, key: [32]u8) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try appendInt(&payload, allocator, u16, 2 + 2 + key.len);
    try appendInt(&payload, allocator, u16, group_x25519);
    try appendInt(&payload, allocator, u16, key.len);
    try payload.appendSlice(allocator, &key);
    try writeExtension(list, allocator, ext_key_share, payload.items);
}

fn writeExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator, typ: u16, payload: []const u8) Error!void {
    if (payload.len > std.math.maxInt(u16)) return error.InvalidClientHello;
    try appendInt(list, allocator, u16, typ);
    try appendInt(list, allocator, u16, @intCast(payload.len));
    try list.appendSlice(allocator, payload);
}

fn parseServerName(payload: []const u8) Error![]const u8 {
    var cursor = wire.Cursor.init(payload);
    const list_len = try cursor.readInt(u16, .big);
    const list = try cursor.readSlice(list_len);
    if (!cursor.eof()) return error.InvalidClientHello;
    var list_cursor = wire.Cursor.init(list);
    if (try list_cursor.readByte() != 0) return error.InvalidClientHello;
    const name_len = try list_cursor.readInt(u16, .big);
    const name = try list_cursor.readSlice(name_len);
    if (!list_cursor.eof()) return error.InvalidClientHello;
    return name;
}

fn parseAlpn(allocator: std.mem.Allocator, out: *std.ArrayList([]const u8), payload: []const u8) Error!void {
    var cursor = wire.Cursor.init(payload);
    const list_len = try cursor.readInt(u16, .big);
    const list = try cursor.readSlice(list_len);
    if (!cursor.eof()) return error.InvalidClientHello;
    var list_cursor = wire.Cursor.init(list);
    while (!list_cursor.eof()) {
        const len = try list_cursor.readByte();
        if (len == 0) return error.InvalidClientHello;
        try out.append(allocator, try list_cursor.readSlice(len));
    }
}

fn parseSingleAlpn(payload: []const u8) Error![]const u8 {
    var cursor = wire.Cursor.init(payload);
    const list_len = try cursor.readInt(u16, .big);
    const list = try cursor.readSlice(list_len);
    if (!cursor.eof()) return error.InvalidEncryptedExtensions;
    var list_cursor = wire.Cursor.init(list);
    const len = try list_cursor.readByte();
    if (len == 0) return error.InvalidEncryptedExtensions;
    const protocol = try list_cursor.readSlice(len);
    if (!list_cursor.eof()) return error.InvalidEncryptedExtensions;
    return protocol;
}

fn parseX25519KeyShare(payload: []const u8) Error![]const u8 {
    var cursor = wire.Cursor.init(payload);
    const shares_len = try cursor.readInt(u16, .big);
    const shares = try cursor.readSlice(shares_len);
    if (!cursor.eof()) return error.InvalidClientHello;
    var shares_cursor = wire.Cursor.init(shares);
    while (!shares_cursor.eof()) {
        const group = try shares_cursor.readInt(u16, .big);
        const key_len = try shares_cursor.readInt(u16, .big);
        const key = try shares_cursor.readSlice(key_len);
        if (group == group_x25519) {
            if (key.len != 32) return error.InvalidClientHello;
            return key;
        }
    }
    return error.MissingKeyShare;
}

fn parseServerX25519KeyShare(payload: []const u8) Error![]const u8 {
    var cursor = wire.Cursor.init(payload);
    const group = try cursor.readInt(u16, .big);
    const key_len = try cursor.readInt(u16, .big);
    const key = try cursor.readSlice(key_len);
    if (!cursor.eof()) return error.InvalidServerHello;
    if (group != group_x25519 or key.len != 32) return error.MissingKeyShare;
    return key;
}

fn appendInt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var tmp: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &tmp, value, .big);
    try list.appendSlice(allocator, &tmp);
}

fn appendU24(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u24) !void {
    try list.append(allocator, @truncate(value >> 16));
    try list.append(allocator, @truncate(value >> 8));
    try list.append(allocator, @truncate(value));
}

fn appendU16Len(list: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize, err: Error) Error!void {
    if (len > std.math.maxInt(u16)) return err;
    try appendInt(list, allocator, u16, @intCast(len));
}

fn appendU24Len(list: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize, err: Error) Error!void {
    if (len > std.math.maxInt(u24)) return err;
    try appendU24(list, allocator, @intCast(len));
}

fn readU24(cursor: *wire.Cursor) !usize {
    const bytes = try cursor.readSlice(3);
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
}

test "QUIC TLS ClientHello encodes and parses QUIC extensions" {
    const allocator = std.testing.allocator;
    const random = [_]u8{0x11} ** 32;
    const key = [_]u8{0x22} ** 32;
    var tp: std.ArrayList(u8) = .empty;
    defer tp.deinit(allocator);
    try quic.encodeTransportParameter(&tp, allocator, @intFromEnum(quic.TransportParameterId.initial_max_data), &.{ 0x40, 0x64 });

    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .server_name = "example.com",
        .alpn_protocols = &.{ "h3", "h3-29" },
        .transport_parameters = tp.items,
    });

    var parsed = try parseClientHello(allocator, hello.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &random, &parsed.random);
    try std.testing.expectEqualStrings("example.com", parsed.server_name.?);
    try std.testing.expectEqualStrings("h3", parsed.alpn_protocols[0]);
    try std.testing.expectEqualStrings("h3-29", parsed.alpn_protocols[1]);
    try std.testing.expectEqualSlices(u8, &key, parsed.x25519_public_key);

    const params = try quic.parseTransportParameters(allocator, parsed.transport_parameters);
    defer allocator.free(params);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.TransportParameterId.initial_max_data)), params[0].id);

    const huge_transport_parameters = try allocator.alloc(u8, @as(usize, std.math.maxInt(u16)) + 1);
    defer allocator.free(huge_transport_parameters);
    try std.testing.expectError(error.InvalidClientHello, writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .transport_parameters = huge_transport_parameters,
    }));

    const huge_sni = try allocator.alloc(u8, @as(usize, std.math.maxInt(u16)) - 1);
    defer allocator.free(huge_sni);
    @memset(huge_sni, 'a');
    try std.testing.expectError(error.InvalidClientHello, writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .server_name = huge_sni,
    }));

    const long_proto = try allocator.alloc(u8, 255);
    defer allocator.free(long_proto);
    @memset(long_proto, 'h');
    const too_many_protocols = try allocator.alloc([]const u8, 257);
    defer allocator.free(too_many_protocols);
    for (too_many_protocols) |*protocol| protocol.* = long_proto;
    try std.testing.expectError(error.InvalidClientHello, writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .alpn_protocols = too_many_protocols,
    }));
}

test "QUIC TLS ClientHello travels over Initial CRYPTO exchange" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const original_dcid = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    const client_scid = [_]u8{ 1, 1, 1, 1 };
    const secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try writeClientHello(&hello, allocator, .{
        .random = [_]u8{0x33} ** 32,
        .x25519_public_key = [_]u8{0x44} ** 32,
        .server_name = "localhost",
        .transport_parameters = &.{},
    });

    try quic.initial_exchange.sendInitialCrypto(&client.endpoint, server.address(), secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var received = try quic.initial_exchange.receiveInitialCrypto(&server.endpoint, secrets.client, 0, 4096);
    defer received.deinit(allocator);
    var parsed = try parseClientHello(allocator, received.crypto_data);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("localhost", parsed.server_name.?);
    try std.testing.expectEqualStrings("h3", parsed.alpn_protocols[0]);
}

test "QUIC TLS ServerHello and handshake secrets derive on both sides" {
    const allocator = std.testing.allocator;
    const client_secret = [_]u8{0x11} ** 32;
    const server_secret = [_]u8{0x22} ** 32;
    const client_public = try x25519PublicKey(client_secret);
    const server_public = try x25519PublicKey(server_secret);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x33} ** 32,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .transport_parameters = &.{},
    });

    var parsed_client = try parseClientHello(allocator, client_hello.items);
    defer parsed_client.deinit(allocator);
    const server_shared = try x25519SharedSecret(server_secret, parsed_client.x25519_public_key);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x44} ** 32,
        .x25519_public_key = server_public,
    });
    const parsed_server = try parseServerHello(server_hello.items);
    const client_shared = try x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);

    const th = transcriptHash(client_hello.items, server_hello.items);
    const client_keys = deriveHandshakeSecrets(client_shared, th);
    const server_keys = deriveHandshakeSecrets(server_shared, th);
    try std.testing.expectEqualSlices(u8, &client_keys.handshake_secret, &server_keys.handshake_secret);
    try std.testing.expectEqualSlices(u8, &client_keys.client_quic.key, &server_keys.client_quic.key);
    try std.testing.expectEqualSlices(u8, &client_keys.server_quic.key, &server_keys.server_quic.key);
    try std.testing.expect(!std.mem.eql(u8, &client_keys.client_quic.key, &client_keys.server_quic.key));
}

test "QUIC TLS QUIC keys use version-specific packet-protection labels" {
    const shared = [_]u8{0x33} ** 32;
    const transcript = [_]u8{0x44} ** 32;
    const v1 = deriveHandshakeSecretsForVersion(quic.Version.version_1.wireValue(), shared, transcript);
    const v2 = deriveHandshakeSecretsForVersion(quic.Version.version_2.wireValue(), shared, transcript);

    try std.testing.expectEqualSlices(u8, &v1.handshake_secret, &v2.handshake_secret);
    try std.testing.expectEqualSlices(u8, &v1.client_handshake_traffic_secret, &v2.client_handshake_traffic_secret);
    try std.testing.expect(!std.mem.eql(u8, &v1.client_quic.key, &v2.client_quic.key));

    const app_v1 = deriveApplicationSecretsForVersion(quic.Version.version_1.wireValue(), v1.handshake_secret, transcript);
    const app_v2 = deriveApplicationSecretsForVersion(quic.Version.version_2.wireValue(), v1.handshake_secret, transcript);
    try std.testing.expectEqualSlices(u8, &app_v1.master_secret, &app_v2.master_secret);
    try std.testing.expect(!std.mem.eql(u8, &app_v1.client_quic.key, &app_v2.client_quic.key));
}

test "QUIC TLS ClientHello and ServerHello exchange over protected Initial packets" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const original_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04 };
    const client_scid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const server_scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const initial_secrets = quic.protection.deriveInitialSecrets(&original_dcid);

    const client_secret = [_]u8{0x45} ** 32;
    const server_secret = [_]u8{0x46} ** 32;
    const client_public = try x25519PublicKey(client_secret);
    const server_public = try x25519PublicKey(server_secret);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x47} ** 32,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .alpn_protocols = &.{"h3"},
        .transport_parameters = &.{},
    });

    try quic.initial_exchange.sendInitialCrypto(&client.endpoint, server.address(), initial_secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = client_hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var server_received = try quic.initial_exchange.receiveInitialCrypto(&server.endpoint, initial_secrets.client, 0, 4096);
    defer server_received.deinit(allocator);
    var parsed_client = try parseClientHello(allocator, server_received.crypto_data);
    defer parsed_client.deinit(allocator);
    const server_shared = try x25519SharedSecret(server_secret, parsed_client.x25519_public_key);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x48} ** 32,
        .x25519_public_key = server_public,
    });
    const server_transcript = transcriptHash(client_hello.items, server_hello.items);
    const server_handshake = deriveHandshakeSecrets(server_shared, server_transcript);

    try quic.initial_exchange.sendInitialCrypto(&server.endpoint, server_received.from, initial_secrets.server, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &server_scid,
        .packet_number = 0,
        .crypto_data = server_hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var client_received = try quic.initial_exchange.receiveInitialCrypto(&client.endpoint, initial_secrets.server, 0, 4096);
    defer client_received.deinit(allocator);
    const parsed_server = try parseServerHello(client_received.crypto_data);
    const client_shared = try x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const client_transcript = transcriptHash(client_hello.items, client_received.crypto_data);
    const client_handshake = deriveHandshakeSecrets(client_shared, client_transcript);

    try std.testing.expectEqualSlices(u8, &server_shared, &client_shared);
    try std.testing.expectEqualSlices(u8, &server_handshake.client_quic.key, &client_handshake.client_quic.key);
    try std.testing.expectEqualSlices(u8, &server_handshake.server_quic.key, &client_handshake.server_quic.key);
}

test "QUIC TLS EncryptedExtensions and Finished verify data" {
    const allocator = std.testing.allocator;
    var tp: std.ArrayList(u8) = .empty;
    defer tp.deinit(allocator);
    try quic.encodeTransportParameter(&tp, allocator, @intFromEnum(quic.TransportParameterId.initial_max_data), &.{ 0x40, 0x64 });

    var ee: std.ArrayList(u8) = .empty;
    defer ee.deinit(allocator);
    try writeEncryptedExtensions(&ee, allocator, "h3", tp.items);
    const parsed_ee = try parseEncryptedExtensions(ee.items);
    try std.testing.expectEqualStrings("h3", parsed_ee.alpn);
    const params = try quic.parseTransportParameters(allocator, parsed_ee.transport_parameters);
    defer allocator.free(params);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.TransportParameterId.initial_max_data)), params[0].id);

    const base_key = [_]u8{0x5a} ** 32;
    var transcript_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ee.items, &transcript_hash, .{});
    const verify_data = computeFinishedVerifyData(base_key, transcript_hash);

    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try writeFinished(&finished, allocator, verify_data);
    const parsed_finished = try parseFinished(finished.items);
    try verifyFinished(base_key, transcript_hash, parsed_finished);

    var wrong_hash = transcript_hash;
    wrong_hash[0] ^= 0xff;
    try std.testing.expectError(error.BadFinished, verifyFinished(base_key, wrong_hash, parsed_finished));
}

test "QUIC TLS server handshake flight travels over Handshake packet" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const original_dcid = [_]u8{ 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87 };
    const client_scid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const server_scid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const initial_secrets = quic.protection.deriveInitialSecrets(&original_dcid);

    const client_secret = [_]u8{0x51} ** 32;
    const server_secret = [_]u8{0x52} ** 32;
    const client_public = try x25519PublicKey(client_secret);
    const server_public = try x25519PublicKey(server_secret);

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x53} ** 32,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .transport_parameters = &.{},
    });
    try quic.initial_exchange.sendInitialCrypto(&client.endpoint, server.address(), initial_secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = client_hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var server_received = try quic.initial_exchange.receiveInitialCrypto(&server.endpoint, initial_secrets.client, 0, 4096);
    defer server_received.deinit(allocator);
    var parsed_client = try parseClientHello(allocator, server_received.crypto_data);
    defer parsed_client.deinit(allocator);
    const server_shared = try x25519SharedSecret(server_secret, parsed_client.x25519_public_key);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x54} ** 32,
        .x25519_public_key = server_public,
    });
    const hs_hash = transcriptHash(client_hello.items, server_hello.items);
    const server_keys = deriveHandshakeSecrets(server_shared, hs_hash);

    var ee: std.ArrayList(u8) = .empty;
    defer ee.deinit(allocator);
    try writeEncryptedExtensions(&ee, allocator, "h3", &.{});
    var transcript = std.crypto.hash.sha2.Sha256.init(.{});
    transcript.update(client_hello.items);
    transcript.update(server_hello.items);
    transcript.update(ee.items);
    var server_finished_hash: [32]u8 = undefined;
    transcript.final(&server_finished_hash);
    const verify_data = computeFinishedVerifyData(server_keys.server_handshake_traffic_secret, server_finished_hash);

    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try writeFinished(&finished, allocator, verify_data);

    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(allocator);
    try server_flight.appendSlice(allocator, ee.items);
    try server_flight.appendSlice(allocator, finished.items);
    try quic.initial_exchange.sendHandshakeCrypto(&server.endpoint, server_received.from, server_keys.server_quic, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &server_scid,
        .packet_number = 0,
        .crypto_data = server_flight.items,
        .max_crypto_frame_data_len = 64,
    });

    var client_received = try quic.initial_exchange.receiveHandshakeCrypto(&client.endpoint, server_keys.server_quic, 0, 4096);
    defer client_received.deinit(allocator);
    const ee_len = handshakeMessageLen(client_received.crypto_data);
    const parsed_ee = try parseEncryptedExtensions(client_received.crypto_data[0..ee_len]);
    try std.testing.expectEqualStrings("h3", parsed_ee.alpn);
    const parsed_finished = try parseFinished(client_received.crypto_data[ee_len..]);

    const parsed_server = try parseServerHello(server_hello.items);
    const client_shared = try x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const client_keys = deriveHandshakeSecrets(client_shared, hs_hash);
    try verifyFinished(client_keys.server_handshake_traffic_secret, server_finished_hash, parsed_finished);

    var through_server_finished = std.crypto.hash.sha2.Sha256.init(.{});
    through_server_finished.update(client_hello.items);
    through_server_finished.update(server_hello.items);
    through_server_finished.update(ee.items);
    through_server_finished.update(finished.items);
    var client_finished_hash: [32]u8 = undefined;
    through_server_finished.final(&client_finished_hash);
    const client_verify = computeFinishedVerifyData(client_keys.client_handshake_traffic_secret, client_finished_hash);

    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(allocator);
    try writeFinished(&client_finished, allocator, client_verify);
    try quic.initial_exchange.sendHandshakeCrypto(&client.endpoint, server.address(), client_keys.client_quic, .{
        .destination_connection_id = &server_scid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = client_finished.items,
        .max_crypto_frame_data_len = 64,
    });

    var server_client_finished = try quic.initial_exchange.receiveHandshakeCrypto(&server.endpoint, server_keys.client_quic, 0, 4096);
    defer server_client_finished.deinit(allocator);
    const parsed_client_finished = try parseFinished(server_client_finished.crypto_data);
    try verifyFinished(server_keys.client_handshake_traffic_secret, client_finished_hash, parsed_client_finished);

    var full_transcript = std.crypto.hash.sha2.Sha256.init(.{});
    full_transcript.update(client_hello.items);
    full_transcript.update(server_hello.items);
    full_transcript.update(ee.items);
    full_transcript.update(finished.items);
    full_transcript.update(client_finished.items);
    var app_hash: [32]u8 = undefined;
    full_transcript.final(&app_hash);
    const client_app = deriveApplicationSecrets(client_keys.handshake_secret, app_hash);
    const server_app = deriveApplicationSecrets(server_keys.handshake_secret, app_hash);
    try std.testing.expectEqualSlices(u8, &client_app.client_quic.key, &server_app.client_quic.key);
    try std.testing.expectEqualSlices(u8, &client_app.server_quic.key, &server_app.server_quic.key);
    try std.testing.expect(!std.mem.eql(u8, &client_app.client_quic.key, &client_app.server_quic.key));
}

fn handshakeMessageLen(bytes: []const u8) usize {
    return 4 + ((@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3]);
}

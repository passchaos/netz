const std = @import("std");
const quic = @import("mod.zig");
const wire = @import("../internal/wire.zig");

pub const Error = error{
    InvalidClientHello,
    InvalidServerHello,
    InvalidCipherSuite,
    NoSharedCipherSuite,
    InvalidEncryptedExtensions,
    InvalidFinished,
    MissingKeyShare,
    MissingSupportedVersions,
    MissingTransportParameters,
    MissingAlpn,
    KeyExchangeFailed,
    BadFinished,
} || wire.Error || quic.protection.VersionError ||
    quic.resumption.tls_psk.Error || quic.tls.key_schedule.Error ||
    std.mem.Allocator.Error;

const handshake_type_client_hello: u8 = 0x01;
const handshake_type_server_hello: u8 = 0x02;
const handshake_type_encrypted_extensions: u8 = 0x08;
const handshake_type_finished: u8 = 0x14;
const tls_1_2: u16 = 0x0303;
const tls_1_3: u16 = 0x0304;
const group_x25519: u16 = 0x001d;
pub const CipherSuite = quic.tls.cipher_suite.Suite;
pub const CipherSuiteSelectionPolicy =
    quic.tls.cipher_suite.SelectionPolicy;
pub const default_cipher_suites =
    quic.tls.cipher_suite.default_preference;

const ext_server_name: u16 = 0x0000;
const ext_supported_groups: u16 = 0x000a;
const ext_signature_algorithms: u16 = 0x000d;
const ext_alpn: u16 = 0x0010;
const ext_supported_versions: u16 = 0x002b;
const ext_key_share: u16 = 0x0033;
const ext_quic_transport_parameters: u16 = 0x0039;
const ext_pre_shared_key = quic.resumption.tls_psk.ext_pre_shared_key;

pub const ClientHelloOptions = struct {
    random: [32]u8,
    x25519_public_key: [32]u8,
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &.{"h3"},
    transport_parameters: []const u8 = &.{},
    cipher_suites: []const CipherSuite = &default_cipher_suites,
};

pub const ParsedClientHello = struct {
    random: [32]u8,
    server_name: ?[]const u8,
    alpn_protocols: [][]const u8,
    x25519_public_key: []const u8,
    transport_parameters: []const u8,
    cipher_suites: []const u8,
    supports_ed25519: bool = false,
    supports_ecdsa_p256_sha256: bool = false,
    psk_offer: ?quic.resumption.tls_psk.Offer = null,

    pub fn deinit(self: *ParsedClientHello, allocator: std.mem.Allocator) void {
        allocator.free(self.alpn_protocols);
        self.* = undefined;
    }
};

pub const ServerHelloOptions = struct {
    random: [32]u8,
    x25519_public_key: [32]u8,
    select_psk: bool = false,
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,
};

pub const ParsedServerHello = struct {
    random: [32]u8,
    x25519_public_key: []const u8,
    selected_psk: bool = false,
    cipher_suite: CipherSuite,
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

pub const RuntimeHandshakeSecrets = struct {
    handshake_secret: quic.tls.secret.Secret,
    client_handshake_traffic_secret: quic.tls.secret.Secret,
    server_handshake_traffic_secret: quic.tls.secret.Secret,
    client_quic: quic.protection.PacketProtectionKeys,
    server_quic: quic.protection.PacketProtectionKeys,
};

pub const RuntimeApplicationSecrets = struct {
    master_secret: quic.tls.secret.Secret,
    client_application_traffic_secret: quic.tls.secret.Secret,
    server_application_traffic_secret: quic.tls.secret.Secret,
    client_quic: quic.protection.PacketProtectionKeys,
    server_quic: quic.protection.PacketProtectionKeys,
};

pub const ParsedEncryptedExtensions = struct {
    alpn: []const u8,
    transport_parameters: []const u8,
    early_data_accepted: bool = false,
};

pub fn writeClientHello(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: ClientHelloOptions) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    try appendInt(&body, allocator, u16, tls_1_2);
    try body.appendSlice(allocator, &options.random);
    try body.append(allocator, 0); // legacy_session_id
    try writeCipherSuites(
        &body,
        allocator,
        options.cipher_suites,
    );
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
    try appendInt(
        &body,
        allocator,
        u16,
        options.cipher_suite.wireValue(),
    );
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
    if (options.select_psk) {
        try quic.resumption.tls_psk.appendServerSelection(
            &extensions,
            allocator,
        );
    }

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
    return writeEncryptedExtensionsWithEarlyData(
        list,
        allocator,
        alpn,
        transport_parameters,
        false,
    );
}

pub fn writeEncryptedExtensionsWithEarlyData(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    alpn: []const u8,
    transport_parameters: []const u8,
    early_data_accepted: bool,
) Error!void {
    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    if (alpn.len != 0) try writeAlpnExtension(&extensions, allocator, &.{alpn});
    try writeExtension(&extensions, allocator, ext_quic_transport_parameters, transport_parameters);
    if (early_data_accepted) {
        try writeExtension(
            &extensions,
            allocator,
            quic.resumption.tls_psk.ext_early_data,
            &.{},
        );
    }

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
    const cipher_suites = try body_cursor.readSlice(cipher_suites_len);
    const compression_len = try body_cursor.readByte();
    if (compression_len != 1) return error.InvalidClientHello;
    if (try body_cursor.readByte() != 0) return error.InvalidClientHello;

    const extensions_len = try body_cursor.readInt(u16, .big);
    const extensions = try body_cursor.readSlice(extensions_len);
    if (!body_cursor.eof()) return error.InvalidClientHello;

    var server_name: ?[]const u8 = null;
    var x25519: ?[]const u8 = null;
    var transport_parameters: ?[]const u8 = null;
    var saw_supported_versions = false;
    var supports_ed25519 = false;
    var supports_ecdsa_p256_sha256 = false;
    var alpn_list: std.ArrayList([]const u8) = .empty;
    errdefer alpn_list.deinit(allocator);
    var seen_extensions = SeenExtensions{};

    var ext_cursor = wire.Cursor.init(extensions);
    while (!ext_cursor.eof()) {
        const typ = try ext_cursor.readInt(u16, .big);
        const len = try ext_cursor.readInt(u16, .big);
        const payload = try ext_cursor.readSlice(len);
        try seen_extensions.note(typ, error.InvalidClientHello);
        switch (typ) {
            ext_server_name => server_name = try parseServerName(payload),
            ext_alpn => try parseAlpn(allocator, &alpn_list, payload),
            ext_supported_versions => {
                try validateClientSupportedVersions(payload);
                saw_supported_versions = true;
            },
            ext_signature_algorithms => {
                supports_ed25519 = try signatureAlgorithmsContain(
                    payload,
                    quic.tls.auth.signature_scheme_ed25519,
                );
                supports_ecdsa_p256_sha256 = try signatureAlgorithmsContain(
                    payload,
                    quic.tls.auth
                        .signature_scheme_ecdsa_secp256r1_sha256,
                );
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
    const psk_offer = quic.resumption.tls_psk.parseClientOffer(bytes) catch |err| switch (err) {
        error.MissingPskOffer => null,
        else => return error.InvalidClientHello,
    };

    return .{
        .random = random,
        .server_name = server_name,
        .alpn_protocols = try alpn_list.toOwnedSlice(allocator),
        .x25519_public_key = x25519.?,
        .transport_parameters = transport_parameters.?,
        .cipher_suites = cipher_suites,
        .supports_ed25519 = supports_ed25519,
        .supports_ecdsa_p256_sha256 = supports_ecdsa_p256_sha256,
        .psk_offer = psk_offer,
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
    const cipher_suite = CipherSuite.fromWire(
        try body_cursor.readInt(u16, .big),
    ) orelse return error.InvalidCipherSuite;
    if (try body_cursor.readByte() != 0) return error.InvalidServerHello;
    const extensions_len = try body_cursor.readInt(u16, .big);
    const extensions = try body_cursor.readSlice(extensions_len);
    if (!body_cursor.eof()) return error.InvalidServerHello;

    var saw_supported_versions = false;
    var x25519: ?[]const u8 = null;
    var selected_psk = false;
    var seen_extensions = SeenExtensions{};
    var ext_cursor = wire.Cursor.init(extensions);
    while (!ext_cursor.eof()) {
        const typ = try ext_cursor.readInt(u16, .big);
        const len = try ext_cursor.readInt(u16, .big);
        const payload = try ext_cursor.readSlice(len);
        try seen_extensions.note(typ, error.InvalidServerHello);
        switch (typ) {
            ext_supported_versions => {
                if (payload.len != 2 or std.mem.readInt(u16, payload[0..2], .big) != tls_1_3) return error.InvalidServerHello;
                saw_supported_versions = true;
            },
            ext_key_share => x25519 = try parseServerX25519KeyShare(payload),
            ext_pre_shared_key => {
                _ = quic.resumption.tls_psk.parseServerSelection(payload) catch
                    return error.InvalidServerHello;
                selected_psk = true;
            },
            else => {},
        }
    }
    if (!saw_supported_versions) return error.MissingSupportedVersions;
    if (x25519 == null) return error.MissingKeyShare;
    return .{
        .random = random,
        .x25519_public_key = x25519.?,
        .selected_psk = selected_psk,
        .cipher_suite = cipher_suite,
    };
}

pub fn selectCipherSuite(
    client_wire: []const u8,
    server_preference: []const CipherSuite,
    policy: CipherSuiteSelectionPolicy,
) Error!CipherSuite {
    return quic.tls.cipher_suite.selectFromWire(
        client_wire,
        server_preference,
        policy,
    ) catch |err| switch (err) {
        error.NoSharedCipherSuite => error.NoSharedCipherSuite,
        error.InvalidCipherSuiteList,
        error.InvalidServerPreference,
        => error.InvalidCipherSuite,
    };
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
    var early_data_accepted = false;
    var seen_extensions = SeenExtensions{};
    var ext_cursor = wire.Cursor.init(extensions);
    while (!ext_cursor.eof()) {
        const typ = try ext_cursor.readInt(u16, .big);
        const len = try ext_cursor.readInt(u16, .big);
        const payload = try ext_cursor.readSlice(len);
        try seen_extensions.note(typ, error.InvalidEncryptedExtensions);
        switch (typ) {
            ext_alpn => {
                alpn = try parseSingleAlpn(payload);
            },
            ext_quic_transport_parameters => transport_parameters = payload,
            quic.resumption.tls_psk.ext_early_data => {
                if (payload.len != 0) return error.InvalidEncryptedExtensions;
                early_data_accepted = true;
            },
            else => return error.InvalidEncryptedExtensions,
        }
    }
    return .{
        .alpn = alpn orelse return error.MissingAlpn,
        .transport_parameters = transport_parameters orelse return error.MissingTransportParameters,
        .early_data_accepted = early_data_accepted,
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

pub fn writeFinishedForHash(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    verify_data: quic.tls.secret.Secret,
) Error!void {
    try list.append(allocator, handshake_type_finished);
    try appendU24Len(
        list,
        allocator,
        verify_data.bytes().len,
        error.InvalidFinished,
    );
    try list.appendSlice(allocator, verify_data.bytes());
}

pub fn parseFinishedForHash(
    bytes: []const u8,
    hash: quic.tls.secret.Hash,
) Error!quic.tls.secret.Secret {
    var cursor = wire.Cursor.init(bytes);
    if (try cursor.readByte() != handshake_type_finished) {
        return error.InvalidFinished;
    }
    const body_len = try readU24(&cursor);
    if (body_len != hash.len()) return error.InvalidFinished;
    const verify_data = try cursor.readSlice(body_len);
    if (!cursor.eof()) return error.InvalidFinished;
    return quic.tls.secret.Secret.init(hash, verify_data) catch
        return error.InvalidFinished;
}

pub fn x25519PublicKey(secret_key: [32]u8) Error![32]u8 {
    return quic.tls.key_exchange.publicKey(secret_key) catch
        return error.KeyExchangeFailed;
}

pub fn x25519SharedSecret(secret_key: [32]u8, peer_public_key: []const u8) Error![32]u8 {
    return quic.tls.key_exchange.sharedSecret(
        secret_key,
        peer_public_key,
    ) catch |err| switch (err) {
        error.InvalidPublicKey => error.MissingKeyShare,
        error.KeyExchangeFailed => error.KeyExchangeFailed,
    };
}

pub fn transcriptHash(client_hello: []const u8, server_hello: []const u8) [32]u8 {
    return quic.tls.transcript.hash(&.{ client_hello, server_hello });
}

pub fn deriveHandshakeSecrets(shared_secret: [32]u8, transcript_hash: [32]u8) HandshakeSecrets {
    return deriveHandshakeSecretsForVersion(quic.Version.version_1.wireValue(), shared_secret, transcript_hash) catch unreachable;
}

pub fn deriveHandshakeSecretsForVersion(version: u32, shared_secret: [32]u8, transcript_hash: [32]u8) quic.protection.VersionError!HandshakeSecrets {
    return deriveHandshakeSecretsWithPskForVersion(
        version,
        shared_secret,
        transcript_hash,
        null,
    );
}

pub fn deriveHandshakeSecretsWithPskForVersion(
    version: u32,
    shared_secret: [32]u8,
    transcript_hash: [32]u8,
    psk: ?[32]u8,
) quic.protection.VersionError!HandshakeSecrets {
    return deriveHandshakeSecretsWithPskAndSuiteForVersion(
        version,
        .aes_128_gcm_sha256,
        shared_secret,
        transcript_hash,
        psk,
    );
}

pub fn deriveHandshakeSecretsWithPskAndSuiteForVersion(
    version: u32,
    cipher_suite: CipherSuite,
    shared_secret: [32]u8,
    transcript_hash: [32]u8,
    psk: ?[32]u8,
) quic.protection.VersionError!HandshakeSecrets {
    const secrets = quic.tls.key_schedule.deriveHandshake(
        shared_secret,
        transcript_hash,
        psk,
    );
    return .{
        .handshake_secret = secrets.handshake_secret,
        .client_handshake_traffic_secret = secrets.client_traffic_secret,
        .server_handshake_traffic_secret = secrets.server_traffic_secret,
        .client_quic = try quic.protection.deriveKeysForVersion(
            version,
            cipher_suite,
            secrets.client_traffic_secret,
        ),
        .server_quic = try quic.protection.deriveKeysForVersion(
            version,
            cipher_suite,
            secrets.server_traffic_secret,
        ),
    };
}

pub fn deriveRuntimeHandshakeSecretsForVersion(
    version: u32,
    cipher_suite: CipherSuite,
    shared_secret: [32]u8,
    transcript_hash: quic.tls.transcript.Digest,
    psk: ?quic.tls.secret.Secret,
) (quic.protection.VersionError ||
    quic.tls.key_schedule.Error ||
    error{HashMismatch})!RuntimeHandshakeSecrets {
    const hash = cipher_suite.hash();
    if (transcript_hash.hash != hash) return error.HashMismatch;
    const secrets = try quic.tls.key_schedule.deriveHandshakeFor(
        hash,
        &shared_secret,
        transcript_hash,
        psk,
    );
    return .{
        .handshake_secret = secrets.handshake_secret,
        .client_handshake_traffic_secret = secrets.client_traffic_secret,
        .server_handshake_traffic_secret = secrets.server_traffic_secret,
        .client_quic = try quic.protection.deriveKeysForSecretForVersion(
            version,
            cipher_suite,
            secrets.client_traffic_secret,
        ),
        .server_quic = try quic.protection.deriveKeysForSecretForVersion(
            version,
            cipher_suite,
            secrets.server_traffic_secret,
        ),
    };
}

pub fn deriveApplicationSecrets(handshake_secret: [32]u8, transcript_hash: [32]u8) ApplicationSecrets {
    return deriveApplicationSecretsForVersion(quic.Version.version_1.wireValue(), handshake_secret, transcript_hash) catch unreachable;
}

pub fn deriveApplicationSecretsForVersion(version: u32, handshake_secret: [32]u8, transcript_hash: [32]u8) quic.protection.VersionError!ApplicationSecrets {
    return deriveApplicationSecretsWithSuiteForVersion(
        version,
        .aes_128_gcm_sha256,
        handshake_secret,
        transcript_hash,
    );
}

pub fn deriveApplicationSecretsWithSuiteForVersion(
    version: u32,
    cipher_suite: CipherSuite,
    handshake_secret: [32]u8,
    transcript_hash: [32]u8,
) quic.protection.VersionError!ApplicationSecrets {
    const secrets = quic.tls.key_schedule.deriveApplication(
        handshake_secret,
        transcript_hash,
    );
    return .{
        .master_secret = secrets.master_secret,
        .client_application_traffic_secret = secrets.client_traffic_secret,
        .server_application_traffic_secret = secrets.server_traffic_secret,
        .client_quic = try quic.protection.deriveKeysForVersion(
            version,
            cipher_suite,
            secrets.client_traffic_secret,
        ),
        .server_quic = try quic.protection.deriveKeysForVersion(
            version,
            cipher_suite,
            secrets.server_traffic_secret,
        ),
    };
}

pub fn deriveRuntimeApplicationSecretsForVersion(
    version: u32,
    cipher_suite: CipherSuite,
    handshake_secret: quic.tls.secret.Secret,
    transcript_hash: quic.tls.transcript.Digest,
) (quic.protection.VersionError ||
    quic.tls.key_schedule.Error ||
    error{HashMismatch})!RuntimeApplicationSecrets {
    if (handshake_secret.hash != cipher_suite.hash() or
        transcript_hash.hash != cipher_suite.hash())
    {
        return error.HashMismatch;
    }
    const secrets = try quic.tls.key_schedule.deriveApplicationFor(
        handshake_secret,
        transcript_hash,
    );
    return .{
        .master_secret = secrets.master_secret,
        .client_application_traffic_secret = secrets.client_traffic_secret,
        .server_application_traffic_secret = secrets.server_traffic_secret,
        .client_quic = try quic.protection.deriveKeysForSecretForVersion(
            version,
            cipher_suite,
            secrets.client_traffic_secret,
        ),
        .server_quic = try quic.protection.deriveKeysForSecretForVersion(
            version,
            cipher_suite,
            secrets.server_traffic_secret,
        ),
    };
}

pub fn computeFinishedVerifyData(base_key: [32]u8, transcript_hash: [32]u8) [32]u8 {
    return quic.tls.key_schedule.computeFinished(base_key, transcript_hash);
}

pub fn verifyFinished(base_key: [32]u8, transcript_hash: [32]u8, verify_data: [32]u8) Error!void {
    quic.tls.key_schedule.verifyFinished(
        base_key,
        transcript_hash,
        verify_data,
    ) catch return error.BadFinished;
}

pub fn computeFinishedVerifyDataForHash(
    base_key: quic.tls.secret.Secret,
    transcript_hash: quic.tls.transcript.Digest,
) Error!quic.tls.secret.Secret {
    return quic.tls.key_schedule.computeFinishedFor(
        base_key,
        transcript_hash,
    ) catch return error.BadFinished;
}

pub fn verifyFinishedForHash(
    base_key: quic.tls.secret.Secret,
    transcript_hash: quic.tls.transcript.Digest,
    verify_data: quic.tls.secret.Secret,
) Error!void {
    quic.tls.key_schedule.verifyFinishedFor(
        base_key,
        transcript_hash,
        verify_data,
    ) catch return error.BadFinished;
}

const SeenExtensions = struct {
    values: [64]u16 = [_]u16{0} ** 64,
    len: usize = 0,

    fn note(self: *SeenExtensions, typ: u16, err: Error) Error!void {
        for (self.values[0..self.len]) |existing| {
            if (existing == typ) return err;
        }
        if (self.len == self.values.len) return err;
        self.values[self.len] = typ;
        self.len += 1;
    }
};

fn writeCipherSuites(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    suites: []const CipherSuite,
) Error!void {
    if (suites.len == 0 or
        suites.len > std.math.maxInt(u16) / @sizeOf(u16))
    {
        return error.InvalidCipherSuite;
    }
    for (suites, 0..) |suite, index| {
        for (suites[0..index]) |previous| {
            if (suite == previous) return error.InvalidCipherSuite;
        }
    }
    try appendInt(
        list,
        allocator,
        u16,
        @intCast(suites.len * @sizeOf(u16)),
    );
    for (suites) |suite| {
        try appendInt(
            list,
            allocator,
            u16,
            suite.wireValue(),
        );
    }
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
    // Ed25519 is the built-in CertificateVerify implementation. Keep ECDSA
    // and RSA-PSS advertised for future/custom authenticators.
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 6, .big);
    std.mem.writeInt(u16, payload[2..4], 0x0403, .big);
    std.mem.writeInt(u16, payload[4..6], 0x0804, .big);
    std.mem.writeInt(u16, payload[6..8], 0x0807, .big);
    try writeExtension(list, allocator, ext_signature_algorithms, &payload);
}

fn signatureAlgorithmsContain(payload: []const u8, wanted: u16) Error!bool {
    if (payload.len < 4) return error.InvalidClientHello;
    const list_len = std.mem.readInt(u16, payload[0..2], .big);
    if (list_len == 0 or list_len % 2 != 0 or
        list_len + 2 != payload.len)
    {
        return error.InvalidClientHello;
    }
    var found = false;
    var pos: usize = 2;
    while (pos < payload.len) : (pos += 2) {
        const scheme = std.mem.readInt(u16, payload[pos..][0..2], .big);
        var previous: usize = 2;
        while (previous < pos) : (previous += 2) {
            if (std.mem.readInt(
                u16,
                payload[previous..][0..2],
                .big,
            ) == scheme) return error.InvalidClientHello;
        }
        if (scheme == wanted) found = true;
    }
    return found;
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

fn validateClientSupportedVersions(payload: []const u8) Error!void {
    if (payload.len < 3) return error.InvalidClientHello;
    const list_len = payload[0];
    if (list_len == 0 or (list_len % 2) != 0 or payload.len != 1 + @as(usize, list_len)) return error.InvalidClientHello;
    var pos: usize = 1;
    while (pos < payload.len) : (pos += 2) {
        if (std.mem.readInt(u16, payload[pos..][0..2], .big) == tls_1_3) return;
    }
    return error.InvalidClientHello;
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

test {
    _ = @import("tls/client_hello_tests.zig");
}

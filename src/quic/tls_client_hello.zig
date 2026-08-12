const std = @import("std");
const quic = @import("mod.zig");
const key_exchange = @import("tls/key_exchange.zig");
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
pub const CipherSuite = quic.tls.cipher_suite.Suite;
pub const CipherSuiteSelectionPolicy =
    quic.tls.cipher_suite.SelectionPolicy;
pub const default_cipher_suites =
    quic.tls.cipher_suite.default_preference;

pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    x25519 = 0x001d,
    secp256r1_mlkem768 =
        quic.tls.key_exchange.secp256r1_mlkem768.named_group,
    x25519_mlkem768 =
        quic.tls.key_exchange.x25519_mlkem768.named_group,
    secp384r1_mlkem1024 =
        quic.tls.key_exchange.secp384r1_mlkem1024.named_group,
};

pub const KeyShare = union(enum) {
    secp256r1: [quic.tls.key_exchange.p256.public_len]u8,
    secp384r1: [quic.tls.key_exchange.p384.public_len]u8,
    x25519: [quic.tls.key_exchange.public_len]u8,
    x25519_mlkem768_client: [
        quic.tls.key_exchange
            .x25519_mlkem768.client_share_len
    ]u8,
    x25519_mlkem768_server: [
        quic.tls.key_exchange
            .x25519_mlkem768.server_share_len
    ]u8,
    secp256r1_mlkem768_client: [
        quic.tls.key_exchange
            .secp256r1_mlkem768.client_share_len
    ]u8,
    secp256r1_mlkem768_server: [
        quic.tls.key_exchange
            .secp256r1_mlkem768.server_share_len
    ]u8,
    secp384r1_mlkem1024_client: [
        quic.tls.key_exchange
            .secp384r1_mlkem1024.client_share_len
    ]u8,
    secp384r1_mlkem1024_server: [
        quic.tls.key_exchange
            .secp384r1_mlkem1024.server_share_len
    ]u8,

    pub fn group(self: KeyShare) NamedGroup {
        return switch (self) {
            .secp256r1 => .secp256r1,
            .secp384r1 => .secp384r1,
            .x25519 => .x25519,
            .x25519_mlkem768_client,
            .x25519_mlkem768_server,
            => .x25519_mlkem768,
            .secp256r1_mlkem768_client,
            .secp256r1_mlkem768_server,
            => .secp256r1_mlkem768,
            .secp384r1_mlkem1024_client,
            .secp384r1_mlkem1024_server,
            => .secp384r1_mlkem1024,
        };
    }

    pub fn bytes(self: *const KeyShare) []const u8 {
        return switch (self.*) {
            inline else => |*key| key,
        };
    }

    fn validForClientHello(self: KeyShare) bool {
        return switch (self) {
            .x25519_mlkem768_server,
            .secp256r1_mlkem768_server,
            .secp384r1_mlkem1024_server,
            => false,
            else => true,
        };
    }

    fn validForServerHello(self: KeyShare) bool {
        return switch (self) {
            .x25519_mlkem768_client,
            .secp256r1_mlkem768_client,
            .secp384r1_mlkem1024_client,
            => false,
            else => true,
        };
    }
};

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
    /// When null, emit only the source-compatible X25519 share above.
    key_shares: ?[]const KeyShare = null,
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
    secp256r1_public_key: ?[]const u8 = null,
    secp384r1_public_key: ?[]const u8 = null,
    x25519_mlkem768_public_key: ?[]const u8 = null,
    secp256r1_mlkem768_public_key: ?[]const u8 = null,
    secp384r1_mlkem1024_public_key: ?[]const u8 = null,
    transport_parameters: []const u8,
    cipher_suites: []const u8,
    supports_ed25519: bool = false,
    supports_ecdsa_p256_sha256: bool = false,
    supports_ecdsa_p384_sha384: bool = false,
    supports_rsa_pss_rsae_sha256: bool = false,
    supports_rsa_pss_rsae_sha384: bool = false,
    supports_rsa_pss_rsae_sha512: bool = false,
    supports_rsa_pss_pss_sha256: bool = false,
    supports_rsa_pss_pss_sha384: bool = false,
    supports_rsa_pss_pss_sha512: bool = false,
    supports_x25519: bool = false,
    supports_secp256r1: bool = false,
    supports_secp384r1: bool = false,
    supports_x25519_mlkem768: bool = false,
    supports_secp256r1_mlkem768: bool = false,
    supports_secp384r1_mlkem1024: bool = false,
    psk_offer: ?quic.resumption.tls_psk.Offer = null,

    pub fn keyShare(
        self: ParsedClientHello,
        group: NamedGroup,
    ) ?[]const u8 {
        return switch (group) {
            .x25519 => if (self.x25519_public_key.len == 0)
                null
            else
                self.x25519_public_key,
            .secp256r1 => self.secp256r1_public_key,
            .secp384r1 => self.secp384r1_public_key,
            .x25519_mlkem768 => self.x25519_mlkem768_public_key,
            .secp256r1_mlkem768 => self.secp256r1_mlkem768_public_key,
            .secp384r1_mlkem1024 => self.secp384r1_mlkem1024_public_key,
        };
    }

    pub fn deinit(self: *ParsedClientHello, allocator: std.mem.Allocator) void {
        allocator.free(self.alpn_protocols);
        self.* = undefined;
    }
};

pub const ServerHelloOptions = struct {
    random: [32]u8,
    x25519_public_key: [32]u8,
    /// When present, this selected share replaces the legacy X25519 field.
    key_share: ?KeyShare = null,
    select_psk: bool = false,
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,
};

pub const ParsedServerHello = struct {
    random: [32]u8,
    x25519_public_key: []const u8,
    selected_group: NamedGroup = .x25519,
    selected_key_share: []const u8 = &.{},
    selected_psk: bool = false,
    cipher_suite: CipherSuite,

    pub fn keyShare(self: ParsedServerHello) []const u8 {
        return if (self.selected_key_share.len != 0)
            self.selected_key_share
        else
            self.x25519_public_key;
    }
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
    const legacy_share = KeyShare{
        .x25519 = options.x25519_public_key,
    };
    const key_shares = options.key_shares orelse
        @as([]const KeyShare, &.{legacy_share});
    if (options.server_name) |name| try writeServerNameExtension(&extensions, allocator, name);
    try writeSupportedGroupsExtension(
        &extensions,
        allocator,
        key_shares,
    );
    try writeSignatureAlgorithmsExtension(&extensions, allocator);
    try writeAlpnExtension(&extensions, allocator, options.alpn_protocols);
    try writeSupportedVersionsExtension(&extensions, allocator);
    try writeKeyShareExtension(&extensions, allocator, key_shares);
    try writeExtension(&extensions, allocator, ext_quic_transport_parameters, options.transport_parameters);

    try appendU16Len(&body, allocator, extensions.items.len, error.InvalidClientHello);
    try body.appendSlice(allocator, extensions.items);

    try writeHandshakeMessage(
        list,
        allocator,
        handshake_type_client_hello,
        body.items,
        error.InvalidClientHello,
    );
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

    const legacy_share = KeyShare{
        .x25519 = options.x25519_public_key,
    };
    try writeServerKeyShareExtension(
        &extensions,
        allocator,
        options.key_share orelse legacy_share,
    );
    if (options.select_psk) {
        try quic.resumption.tls_psk.appendServerSelection(
            &extensions,
            allocator,
        );
    }

    try appendU16Len(&body, allocator, extensions.items.len, error.InvalidServerHello);
    try body.appendSlice(allocator, extensions.items);

    try writeHandshakeMessage(
        list,
        allocator,
        handshake_type_server_hello,
        body.items,
        error.InvalidServerHello,
    );
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

    try writeHandshakeMessage(
        list,
        allocator,
        handshake_type_encrypted_extensions,
        body.items,
        error.InvalidEncryptedExtensions,
    );
}

pub fn writeFinished(list: *std.ArrayList(u8), allocator: std.mem.Allocator, verify_data: [32]u8) Error!void {
    try writeHandshakeMessage(
        list,
        allocator,
        handshake_type_finished,
        &verify_data,
        error.InvalidFinished,
    );
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
    var secp256r1: ?[]const u8 = null;
    var secp384r1: ?[]const u8 = null;
    var x25519_mlkem768: ?[]const u8 = null;
    var secp256r1_mlkem768: ?[]const u8 = null;
    var secp384r1_mlkem1024: ?[]const u8 = null;
    var transport_parameters: ?[]const u8 = null;
    var saw_supported_versions = false;
    var saw_supported_groups = false;
    var supports_x25519 = false;
    var supports_secp256r1 = false;
    var supports_secp384r1 = false;
    var supports_x25519_mlkem768 = false;
    var supports_secp256r1_mlkem768 = false;
    var supports_secp384r1_mlkem1024 = false;
    var supports_ed25519 = false;
    var supports_ecdsa_p256_sha256 = false;
    var supports_ecdsa_p384_sha384 = false;
    var supports_rsa_pss_rsae_sha256 = false;
    var supports_rsa_pss_rsae_sha384 = false;
    var supports_rsa_pss_rsae_sha512 = false;
    var supports_rsa_pss_pss_sha256 = false;
    var supports_rsa_pss_pss_sha384 = false;
    var supports_rsa_pss_pss_sha512 = false;
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
            ext_supported_groups => {
                const groups = try parseSupportedGroups(payload);
                supports_x25519 = groups.x25519;
                supports_secp256r1 = groups.secp256r1;
                supports_secp384r1 = groups.secp384r1;
                supports_x25519_mlkem768 = groups.x25519_mlkem768;
                supports_secp256r1_mlkem768 =
                    groups.secp256r1_mlkem768;
                supports_secp384r1_mlkem1024 =
                    groups.secp384r1_mlkem1024;
                saw_supported_groups = true;
            },
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
                supports_ecdsa_p384_sha384 = try signatureAlgorithmsContain(
                    payload,
                    quic.tls.auth
                        .signature_scheme_ecdsa_secp384r1_sha384,
                );
                supports_rsa_pss_rsae_sha256 =
                    try signatureAlgorithmsContain(
                        payload,
                        quic.tls.auth
                            .signature_scheme_rsa_pss_rsae_sha256,
                    );
                supports_rsa_pss_rsae_sha384 =
                    try signatureAlgorithmsContain(
                        payload,
                        quic.tls.auth
                            .signature_scheme_rsa_pss_rsae_sha384,
                    );
                supports_rsa_pss_rsae_sha512 =
                    try signatureAlgorithmsContain(
                        payload,
                        quic.tls.auth
                            .signature_scheme_rsa_pss_rsae_sha512,
                    );
                supports_rsa_pss_pss_sha256 =
                    try signatureAlgorithmsContain(
                        payload,
                        quic.tls.auth
                            .signature_scheme_rsa_pss_pss_sha256,
                    );
                supports_rsa_pss_pss_sha384 =
                    try signatureAlgorithmsContain(
                        payload,
                        quic.tls.auth
                            .signature_scheme_rsa_pss_pss_sha384,
                    );
                supports_rsa_pss_pss_sha512 =
                    try signatureAlgorithmsContain(
                        payload,
                        quic.tls.auth
                            .signature_scheme_rsa_pss_pss_sha512,
                    );
            },
            ext_key_share => {
                const shares = try parseClientKeyShares(payload);
                x25519 = shares.x25519;
                secp256r1 = shares.secp256r1;
                secp384r1 = shares.secp384r1;
                x25519_mlkem768 = shares.x25519_mlkem768;
                secp256r1_mlkem768 = shares.secp256r1_mlkem768;
                secp384r1_mlkem1024 = shares.secp384r1_mlkem1024;
            },
            ext_quic_transport_parameters => transport_parameters = payload,
            else => {},
        }
    }

    if (!saw_supported_versions) return error.MissingSupportedVersions;
    if (!saw_supported_groups) return error.MissingKeyShare;
    if (x25519 == null and
        secp256r1 == null and
        secp384r1 == null and
        x25519_mlkem768 == null and
        secp256r1_mlkem768 == null and
        secp384r1_mlkem1024 == null)
    {
        return error.MissingKeyShare;
    }
    if ((x25519 != null and !supports_x25519) or
        (secp256r1 != null and !supports_secp256r1) or
        (secp384r1 != null and !supports_secp384r1) or
        (x25519_mlkem768 != null and !supports_x25519_mlkem768) or
        (secp256r1_mlkem768 != null and
            !supports_secp256r1_mlkem768) or
        (secp384r1_mlkem1024 != null and
            !supports_secp384r1_mlkem1024))
    {
        return error.InvalidClientHello;
    }
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
        .x25519_public_key = x25519 orelse &.{},
        .secp256r1_public_key = secp256r1,
        .secp384r1_public_key = secp384r1,
        .x25519_mlkem768_public_key = x25519_mlkem768,
        .secp256r1_mlkem768_public_key = secp256r1_mlkem768,
        .secp384r1_mlkem1024_public_key = secp384r1_mlkem1024,
        .transport_parameters = transport_parameters.?,
        .cipher_suites = cipher_suites,
        .supports_ed25519 = supports_ed25519,
        .supports_ecdsa_p256_sha256 = supports_ecdsa_p256_sha256,
        .supports_ecdsa_p384_sha384 = supports_ecdsa_p384_sha384,
        .supports_rsa_pss_rsae_sha256 = supports_rsa_pss_rsae_sha256,
        .supports_rsa_pss_rsae_sha384 = supports_rsa_pss_rsae_sha384,
        .supports_rsa_pss_rsae_sha512 = supports_rsa_pss_rsae_sha512,
        .supports_rsa_pss_pss_sha256 = supports_rsa_pss_pss_sha256,
        .supports_rsa_pss_pss_sha384 = supports_rsa_pss_pss_sha384,
        .supports_rsa_pss_pss_sha512 = supports_rsa_pss_pss_sha512,
        .supports_x25519 = supports_x25519,
        .supports_secp256r1 = supports_secp256r1,
        .supports_secp384r1 = supports_secp384r1,
        .supports_x25519_mlkem768 = supports_x25519_mlkem768,
        .supports_secp256r1_mlkem768 = supports_secp256r1_mlkem768,
        .supports_secp384r1_mlkem1024 = supports_secp384r1_mlkem1024,
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
    var selected_share: ?ParsedKeyShare = null;
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
            ext_key_share => selected_share =
                try parseServerKeyShare(payload),
            ext_pre_shared_key => {
                _ = quic.resumption.tls_psk.parseServerSelection(payload) catch
                    return error.InvalidServerHello;
                selected_psk = true;
            },
            else => {},
        }
    }
    if (!saw_supported_versions) return error.MissingSupportedVersions;
    const key_share = selected_share orelse return error.MissingKeyShare;
    return .{
        .random = random,
        .x25519_public_key = if (key_share.group == .x25519)
            key_share.key
        else
            &.{},
        .selected_group = key_share.group,
        .selected_key_share = key_share.key,
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

pub fn selectKeyShare(
    client: ParsedClientHello,
    server_preference: []const NamedGroup,
) Error!NamedGroup {
    if (server_preference.len == 0) return error.MissingKeyShare;
    for (server_preference, 0..) |group, index| {
        for (server_preference[0..index]) |previous| {
            if (group == previous) return error.InvalidServerHello;
        }
        if (client.keyShare(group) != null) return group;
    }
    return error.MissingKeyShare;
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
            else => {},
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
    return key_exchange.x25519PublicKey(secret_key);
}

pub fn x25519SharedSecret(secret_key: [32]u8, peer_public_key: []const u8) Error![32]u8 {
    return key_exchange.x25519SharedSecret(
        secret_key,
        peer_public_key,
    );
}

pub fn p256PublicKey(secret_key: [32]u8) Error![65]u8 {
    return key_exchange.p256PublicKey(secret_key);
}

pub fn p256SharedSecret(
    secret_key: [32]u8,
    peer_public_key: []const u8,
) Error![32]u8 {
    return key_exchange.p256SharedSecret(
        secret_key,
        peer_public_key,
    );
}

pub fn p384PublicKey(
    secret_key: [quic.tls.key_exchange.p384.secret_len]u8,
) Error![quic.tls.key_exchange.p384.public_len]u8 {
    return key_exchange.p384PublicKey(secret_key);
}

pub fn p384SharedSecret(
    secret_key: [quic.tls.key_exchange.p384.secret_len]u8,
    peer_public_key: []const u8,
) Error![quic.tls.key_exchange.p384.shared_len]u8 {
    return key_exchange.p384SharedSecret(
        secret_key,
        peer_public_key,
    );
}

pub const X25519MlKem768ClientStart =
    key_exchange.X25519MlKem768ClientStart;
pub const X25519MlKem768ClientSecret =
    key_exchange.X25519MlKem768ClientSecret;
pub const X25519MlKem768ServerResponse =
    key_exchange.X25519MlKem768ServerResponse;

pub fn x25519MlKem768ClientStart(
    x25519_secret: [
        quic.tls.key_exchange.x25519_mlkem768
            .x25519_secret_len
    ]u8,
    mlkem_seed: [
        quic.tls.key_exchange.x25519_mlkem768
            .mlkem_seed_len
    ]u8,
) Error!X25519MlKem768ClientStart {
    return key_exchange.x25519MlKem768ClientStart(
        x25519_secret,
        mlkem_seed,
    );
}

pub fn x25519MlKem768ServerRespond(
    client_share: []const u8,
    x25519_secret: [
        quic.tls.key_exchange.x25519_mlkem768
            .x25519_secret_len
    ]u8,
    encaps_seed: [
        quic.tls.key_exchange.x25519_mlkem768
            .encaps_seed_len
    ]u8,
) Error!X25519MlKem768ServerResponse {
    return key_exchange.x25519MlKem768ServerRespond(
        client_share,
        x25519_secret,
        encaps_seed,
    );
}

pub fn x25519MlKem768ClientSharedSecret(
    secret: *const X25519MlKem768ClientSecret,
    server_share: []const u8,
) Error![quic.tls.key_exchange.x25519_mlkem768.shared_len]u8 {
    return key_exchange.x25519MlKem768ClientSharedSecret(
        secret,
        server_share,
    );
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
    return deriveRuntimeHandshakeSecretsFromSliceForVersion(
        version,
        cipher_suite,
        &shared_secret,
        transcript_hash,
        psk,
    );
}

/// Derives runtime TLS secrets from a named group's complete ECDHE output.
/// Unlike the source-compatible 32-byte entry point above, this accepts the
/// 48-byte x-coordinate produced by secp384r1 without truncation.
pub fn deriveRuntimeHandshakeSecretsFromSliceForVersion(
    version: u32,
    cipher_suite: CipherSuite,
    shared_secret: []const u8,
    transcript_hash: quic.tls.transcript.Digest,
    psk: ?quic.tls.secret.Secret,
) (quic.protection.VersionError ||
    quic.tls.key_schedule.Error ||
    error{HashMismatch})!RuntimeHandshakeSecrets {
    const hash = cipher_suite.hash();
    if (transcript_hash.hash != hash) return error.HashMismatch;
    const secrets = try quic.tls.key_schedule.deriveHandshakeFor(
        hash,
        shared_secret,
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

fn writeSupportedGroupsExtension(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    key_shares: []const KeyShare,
) Error!void {
    if (key_shares.len == 0 or
        key_shares.len > std.math.maxInt(u16) / 2)
    {
        return error.InvalidClientHello;
    }
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try appendInt(
        &payload,
        allocator,
        u16,
        @intCast(key_shares.len * 2),
    );
    for (key_shares, 0..) |share, index| {
        for (key_shares[0..index]) |previous| {
            if (share.group() == previous.group()) {
                return error.InvalidClientHello;
            }
        }
        try appendInt(
            &payload,
            allocator,
            u16,
            @intFromEnum(share.group()),
        );
    }
    try writeExtension(
        list,
        allocator,
        ext_supported_groups,
        payload.items,
    );
}

fn writeSignatureAlgorithmsExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    // These are exactly the schemes Vail can verify for peer
    // CertificateVerify. Built-in signing remains Ed25519/ECDSA.
    var payload: [20]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 18, .big);
    std.mem.writeInt(u16, payload[2..4], 0x0403, .big);
    std.mem.writeInt(u16, payload[4..6], 0x0503, .big);
    std.mem.writeInt(u16, payload[6..8], 0x0804, .big);
    std.mem.writeInt(u16, payload[8..10], 0x0805, .big);
    std.mem.writeInt(u16, payload[10..12], 0x0806, .big);
    std.mem.writeInt(u16, payload[12..14], 0x0807, .big);
    std.mem.writeInt(u16, payload[14..16], 0x0809, .big);
    std.mem.writeInt(u16, payload[16..18], 0x080a, .big);
    std.mem.writeInt(u16, payload[18..20], 0x080b, .big);
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

fn writeKeyShareExtension(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    key_shares: []const KeyShare,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    var shares: std.ArrayList(u8) = .empty;
    defer shares.deinit(allocator);
    for (key_shares) |*share| {
        if (!share.validForClientHello()) {
            return error.InvalidClientHello;
        }
        try appendInt(
            &shares,
            allocator,
            u16,
            @intFromEnum(share.group()),
        );
        try appendU16Len(
            &shares,
            allocator,
            share.bytes().len,
            error.InvalidClientHello,
        );
        try shares.appendSlice(allocator, share.bytes());
    }
    try appendU16Len(
        &payload,
        allocator,
        shares.items.len,
        error.InvalidClientHello,
    );
    try payload.appendSlice(allocator, shares.items);
    try writeExtension(list, allocator, ext_key_share, payload.items);
}

fn writeServerKeyShareExtension(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    share: KeyShare,
) Error!void {
    if (!share.validForServerHello()) return error.InvalidServerHello;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try appendInt(
        &payload,
        allocator,
        u16,
        @intFromEnum(share.group()),
    );
    try appendU16Len(
        &payload,
        allocator,
        share.bytes().len,
        error.InvalidServerHello,
    );
    try payload.appendSlice(allocator, share.bytes());
    try writeExtension(list, allocator, ext_key_share, payload.items);
}

fn writeExtension(list: *std.ArrayList(u8), allocator: std.mem.Allocator, typ: u16, payload: []const u8) Error!void {
    if (payload.len > std.math.maxInt(u16)) return error.InvalidClientHello;
    try list.ensureUnusedCapacity(allocator, 4 + payload.len);
    appendU16AssumeCapacity(list, typ);
    appendU16AssumeCapacity(list, @intCast(payload.len));
    list.appendSliceAssumeCapacity(payload);
}

fn appendU16AssumeCapacity(list: *std.ArrayList(u8), value: u16) void {
    const start = list.items.len;
    list.items.len = start + 2;
    std.mem.writeInt(u16, list.items[start..][0..2], value, .big);
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

const ParsedSupportedGroups = struct {
    x25519: bool = false,
    secp256r1: bool = false,
    secp384r1: bool = false,
    x25519_mlkem768: bool = false,
    secp256r1_mlkem768: bool = false,
    secp384r1_mlkem1024: bool = false,
};

fn parseSupportedGroups(
    payload: []const u8,
) Error!ParsedSupportedGroups {
    if (payload.len < 4) return error.InvalidClientHello;
    const list_len = std.mem.readInt(u16, payload[0..2], .big);
    if (list_len == 0 or list_len % 2 != 0 or
        list_len + 2 != payload.len)
    {
        return error.InvalidClientHello;
    }
    var result = ParsedSupportedGroups{};
    var pos: usize = 2;
    while (pos < payload.len) : (pos += 2) {
        const group_wire = std.mem.readInt(
            u16,
            payload[pos..][0..2],
            .big,
        );
        var previous: usize = 2;
        while (previous < pos) : (previous += 2) {
            if (std.mem.readInt(
                u16,
                payload[previous..][0..2],
                .big,
            ) == group_wire) return error.InvalidClientHello;
        }
        const group = std.enums.fromInt(
            NamedGroup,
            group_wire,
        ) orelse continue;
        switch (group) {
            .x25519 => result.x25519 = true,
            .secp256r1 => result.secp256r1 = true,
            .secp384r1 => result.secp384r1 = true,
            .x25519_mlkem768 => result.x25519_mlkem768 = true,
            .secp256r1_mlkem768 => result.secp256r1_mlkem768 = true,
            .secp384r1_mlkem1024 => result.secp384r1_mlkem1024 = true,
        }
    }
    return result;
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

const ParsedClientKeyShares = struct {
    x25519: ?[]const u8 = null,
    secp256r1: ?[]const u8 = null,
    secp384r1: ?[]const u8 = null,
    x25519_mlkem768: ?[]const u8 = null,
    secp256r1_mlkem768: ?[]const u8 = null,
    secp384r1_mlkem1024: ?[]const u8 = null,
};

const ParsedKeyShare = struct {
    group: NamedGroup,
    key: []const u8,
};

fn parseClientKeyShares(
    payload: []const u8,
) Error!ParsedClientKeyShares {
    var cursor = wire.Cursor.init(payload);
    const shares_len = try cursor.readInt(u16, .big);
    const shares = try cursor.readSlice(shares_len);
    if (!cursor.eof()) return error.InvalidClientHello;
    var shares_cursor = wire.Cursor.init(shares);
    var result = ParsedClientKeyShares{};
    while (!shares_cursor.eof()) {
        const group_wire = try shares_cursor.readInt(u16, .big);
        const key_len = try shares_cursor.readInt(u16, .big);
        const key = try shares_cursor.readSlice(key_len);
        const group = std.enums.fromInt(
            NamedGroup,
            group_wire,
        ) orelse continue;
        switch (group) {
            .x25519 => {
                if (result.x25519 != null or
                    key.len != quic.tls.key_exchange.public_len)
                {
                    return error.InvalidClientHello;
                }
                result.x25519 = key;
            },
            .secp256r1 => {
                if (result.secp256r1 != null or
                    key.len != quic.tls.key_exchange.p256.public_len or
                    key[0] != 0x04)
                {
                    return error.InvalidClientHello;
                }
                result.secp256r1 = key;
            },
            .secp384r1 => {
                if (result.secp384r1 != null or
                    key.len != quic.tls.key_exchange.p384.public_len or
                    key[0] != 0x04)
                {
                    return error.InvalidClientHello;
                }
                result.secp384r1 = key;
            },
            .x25519_mlkem768 => {
                if (result.x25519_mlkem768 != null or
                    key.len != quic.tls.key_exchange
                        .x25519_mlkem768.client_share_len)
                {
                    return error.InvalidClientHello;
                }
                result.x25519_mlkem768 = key;
            },
            .secp256r1_mlkem768 => {
                if (result.secp256r1_mlkem768 != null or
                    key.len != quic.tls.key_exchange
                        .secp256r1_mlkem768.client_share_len or
                    key[0] != 0x04)
                {
                    return error.InvalidClientHello;
                }
                result.secp256r1_mlkem768 = key;
            },
            .secp384r1_mlkem1024 => {
                if (result.secp384r1_mlkem1024 != null or
                    key.len != quic.tls.key_exchange
                        .secp384r1_mlkem1024.client_share_len or
                    key[0] != 0x04)
                {
                    return error.InvalidClientHello;
                }
                result.secp384r1_mlkem1024 = key;
            },
        }
    }
    if (result.x25519 == null and
        result.secp256r1 == null and
        result.secp384r1 == null and
        result.x25519_mlkem768 == null and
        result.secp256r1_mlkem768 == null and
        result.secp384r1_mlkem1024 == null)
    {
        return error.MissingKeyShare;
    }
    return result;
}

fn parseServerKeyShare(payload: []const u8) Error!ParsedKeyShare {
    var cursor = wire.Cursor.init(payload);
    const group_wire = try cursor.readInt(u16, .big);
    const key_len = try cursor.readInt(u16, .big);
    const key = try cursor.readSlice(key_len);
    if (!cursor.eof()) return error.InvalidServerHello;
    const group = std.enums.fromInt(
        NamedGroup,
        group_wire,
    ) orelse return error.MissingKeyShare;
    const valid = switch (group) {
        .x25519 => key.len == quic.tls.key_exchange.public_len,
        .secp256r1 => key.len ==
            quic.tls.key_exchange.p256.public_len and key[0] == 0x04,
        .secp384r1 => key.len ==
            quic.tls.key_exchange.p384.public_len and key[0] == 0x04,
        .x25519_mlkem768 => key.len == quic.tls.key_exchange
            .x25519_mlkem768.server_share_len,
        .secp256r1_mlkem768 => key.len == quic.tls.key_exchange
            .secp256r1_mlkem768.server_share_len and key[0] == 0x04,
        .secp384r1_mlkem1024 => key.len == quic.tls.key_exchange
            .secp384r1_mlkem1024.server_share_len and key[0] == 0x04,
    };
    if (!valid) return error.MissingKeyShare;
    return .{ .group = group, .key = key };
}

fn appendInt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var tmp: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &tmp, value, .big);
    try list.ensureUnusedCapacity(allocator, tmp.len);
    list.appendSliceAssumeCapacity(&tmp);
}

fn appendU24(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u24) !void {
    try list.ensureUnusedCapacity(allocator, 3);
    list.appendAssumeCapacity(@truncate(value >> 16));
    list.appendAssumeCapacity(@truncate(value >> 8));
    list.appendAssumeCapacity(@truncate(value));
}

fn writeHandshakeMessage(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    handshake_type: u8,
    body: []const u8,
    err: Error,
) Error!void {
    if (body.len > std.math.maxInt(u24)) return err;
    try list.ensureUnusedCapacity(allocator, 4 + body.len);
    list.appendAssumeCapacity(handshake_type);
    list.appendAssumeCapacity(@truncate(body.len >> 16));
    list.appendAssumeCapacity(@truncate(body.len >> 8));
    list.appendAssumeCapacity(@truncate(body.len));
    list.appendSliceAssumeCapacity(body);
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
    _ = @import("tls/key_exchange_tests.zig");
}

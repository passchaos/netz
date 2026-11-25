//! Blocking TLS 1.3 server handshake over a connected TCP stream.
//!
//! Keeping transcript construction and handshake-key processing separate from
//! the established record stream keeps client-certificate authentication and
//! application protocol state independent.

const std = @import("std");
const secure_random = @import("../../internal/secure_random.zig");
const vail = @import("vail");
const handshake_deadline = @import("handshake_deadline.zig");
const stream_io = @import("../../internal/stream_io.zig");
const record_io = @import("record_io.zig");

const net = std.Io.net;
const tls_record = vail.tls.record;

const x25519_group: u16 = 0x001d;
const max_client_finished_len: usize = 512;

pub const Error = std.mem.Allocator.Error ||
    std.Io.RandomSecureError ||
    record_io.Error ||
    vail.tls.auth.Error ||
    vail.tls.client_hello.Error ||
    vail.tls.key_exchange.Error ||
    vail.tls.key_schedule.Error ||
    vail.tls.record.Error ||
    vail.tls.secret.Error ||
    vail.tls.server_handshake.Error ||
    error{
        BadClientFinished,
        ExpectedClientFinished,
        ExpectedHandshakeRecord,
        HandshakeMessageTooLarge,
        InvalidCompatibilityCcs,
        InvalidClientFlight,
        InvalidServerFlight,
        MissingKeyShare,
        UnsupportedSignatureScheme,
    };

/// One server TLS policy generation borrowed for exactly one handshake.
/// Providers use the release callback to keep retired server certificates,
/// client trust, and revocation storage alive until every selecting handshake
/// has completed.
pub const ServerIdentityLease = struct {
    identity: vail.tls.auth.ServerIdentity,
    /// Optional client-authentication policy from the same configuration
    /// generation. Null preserves the static policy in `Options`.
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    context: ?*anyopaque = null,
    release_fn: ?*const fn (?*anyopaque) void = null,

    pub fn deinit(self: *ServerIdentityLease) void {
        if (self.release_fn) |release| release(self.context);
        self.* = undefined;
    }
};

/// Late-bound server TLS policy source. `acquire` must return a lease whose
/// identity and optional client-auth policy remain valid through release.
pub const ServerIdentityProvider = struct {
    context: *anyopaque,
    acquire_fn: *const fn (*anyopaque) ServerIdentityLease,

    pub fn acquire(self: ServerIdentityProvider) ServerIdentityLease {
        return self.acquire_fn(self.context);
    }
};

pub const Options = struct {
    /// Static identity, borrowed only while `perform` executes. A configured
    /// `identity_provider` overrides it for each handshake.
    identity: vail.tls.auth.ServerIdentity,
    /// Optional identity source consulted once at the start of each handshake.
    /// This supports atomic certificate rotation without rebinding listeners.
    identity_provider: ?ServerIdentityProvider = null,
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget for the complete TLS handshake. The deadline is
    /// established before reading ClientHello and is not renewed when a peer
    /// trickles records. Null preserves the existing blocking behavior.
    handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    /// Server-preference ALPN list. When `require_alpn` is true, the handshake
    /// fails unless the client offers one of these protocols.
    alpn_protocols: []const []const u8 = &.{},
    /// Permit clients without ALPN while still selecting an offered protocol.
    /// This supports protocols such as MQTT whose TLS mapping makes ALPN optional.
    require_alpn: bool = true,
    /// RFC 8879 algorithms the TLS 1.3 server may use to compress its
    /// Certificate message on demand when the client offers them.
    certificate_compression_algorithms: []const vail.tls.certificate_compression.Algorithm =
        &@import("mod.zig").default_certificate_compression_algorithms,

    pub fn acquireIdentity(self: Options) Error!ServerIdentityLease {
        var lease = if (self.identity_provider) |provider|
            provider.acquire()
        else
            ServerIdentityLease{ .identity = self.identity };
        errdefer lease.deinit();
        try lease.identity.validate();
        return lease;
    }

    pub fn validateIdentity(self: Options) Error!void {
        var lease = try self.acquireIdentity();
        defer lease.deinit();
    }
};

pub const PeerCertificateChain = struct {
    allocator: std.mem.Allocator,
    certificates: []const []const u8,

    pub fn deinit(self: *PeerCertificateChain) void {
        for (self.certificates) |certificate| {
            self.allocator.free(certificate);
        }
        self.allocator.free(self.certificates);
        self.* = undefined;
    }
};

pub const TrafficKeys = struct {
    read: tls_record.Keys,
    write: tls_record.Keys,
    read_traffic_secret: vail.tls.secret.Secret,
    write_traffic_secret: vail.tls.secret.Secret,
    cipher_suite: vail.tls.cipher_suite.Suite,
    peer_certificate_chain: ?PeerCertificateChain = null,
    selected_alpn: ?[]const u8 = null,
    exporter_master_secret: vail.tls.secret.Secret,

    pub fn deinit(self: *TrafficKeys) void {
        self.read.deinit();
        self.write.deinit();
        self.read_traffic_secret.deinit();
        self.write_traffic_secret.deinit();
        if (self.peer_certificate_chain) |*chain| chain.deinit();
        self.exporter_master_secret.deinit();
        self.* = undefined;
    }
};

pub fn perform(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: Options,
) Error!TrafficKeys {
    return performBefore(
        allocator,
        io,
        stream,
        options,
        try handshake_deadline.fromTimeout(io, options.handshake_timeout),
    );
}

/// Server-side counterpart to the client handshake deadline API. The caller's
/// outer budget is retained while `options.handshake_timeout` may shorten it.
pub fn performWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: Options,
    deadline: std.Io.Clock.Timestamp,
) Error!TrafficKeys {
    return performBefore(
        allocator,
        io,
        stream,
        options,
        try handshake_deadline.capTimeout(
            io,
            deadline,
            options.handshake_timeout,
        ),
    );
}

fn performBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    options: Options,
    deadline: ?std.Io.Clock.Timestamp,
) Error!TrafficKeys {
    var identity_lease = try options.acquireIdentity();
    defer identity_lease.deinit();
    const identity = identity_lease.identity;
    const client_auth = identity_lease.client_auth orelse options.client_auth;

    var client_hello_storage: std.ArrayList(u8) = .empty;
    defer client_hello_storage.deinit(allocator);
    try readCleartextHandshake(
        allocator,
        io,
        stream,
        &client_hello_storage,
        options.max_client_hello_size,
        deadline,
    );
    const client_hello = client_hello_storage.items;
    const parsed = try vail.tls.client_hello.parse(client_hello);
    if (!clientSupportsSignatureScheme(
        parsed.signature_algorithms,
        identity.signer.scheme(),
    )) return error.UnsupportedSignatureScheme;

    const share = (try parsed.keyShareForGroup(x25519_group)) orelse
        return error.MissingKeyShare;
    var server_secret: [
        vail.tls.key_exchange.secret_len
    ]u8 = undefined;
    defer std.crypto.secureZero(u8, &server_secret);
    try secure_random.fill(io, &server_secret);
    const server_public = try vail.tls.key_exchange.publicKey(
        server_secret,
    );
    var shared_secret = try vail.tls.key_exchange.sharedSecret(
        server_secret,
        share.key_exchange,
    );
    defer std.crypto.secureZero(u8, &shared_secret);
    var server_random: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &server_random);
    try secure_random.fill(io, &server_random);

    var flight: std.ArrayList(u8) = .empty;
    defer flight.deinit(allocator);
    var signer = try freshSigner(io, identity.signer);
    defer wipeSigner(&signer);
    var handshake =
        try vail.tls.server_handshake.writeServerHandshakeFlight(
            &flight,
            allocator,
            .{
                .client_hello_bytes = client_hello,
                .parsed_client_hello = parsed,
                .policy = .{
                    .cipher_suites = options.cipher_suites,
                    // This stream transport currently implements X25519.
                    // Advertising only implemented groups avoids negotiating
                    // a share for which no secret can be derived.
                    .groups = &.{x25519_group},
                    .alpn_protocols = options.alpn_protocols,
                    .auto_certificate_compression = options.certificate_compression_algorithms,
                },
                .server_random = server_random,
                .server_key_share = &server_public,
                .shared_secret = &shared_secret,
                .certificate_chain = identity.certificate_chain,
                .signer = signer,
                .client_auth = if (client_auth) |policy|
                    .{
                        .certificate_authorities = policy.certificate_authorities,
                    }
                else
                    null,
            },
        );
    defer handshake.handshake_secret.deinit();
    defer handshake.client_handshake_traffic_secret.deinit();
    defer handshake.server_handshake_traffic_secret.deinit();
    if ((options.require_alpn or parsed.alpn_protocols.len != 0) and options.alpn_protocols.len != 0 and
        handshake.selection.alpn_protocol == null)
    {
        return error.InvalidAlpn;
    }

    try writeServerFlight(io, stream, flight.items);

    var handshake_read_keys = try tls_record.Keys.derive(
        handshake.selection.suite,
        handshake.client_handshake_traffic_secret,
    );
    defer handshake_read_keys.deinit();
    var client_flight: std.ArrayList(u8) = .empty;
    defer client_flight.deinit(allocator);
    try readEncryptedHandshakeFlight(
        allocator,
        io,
        stream,
        &handshake_read_keys,
        &client_flight,
        if (client_auth == null)
            max_client_finished_len
        else
            options.max_client_handshake_size,
        deadline,
    );
    var peer_certificate_chain: ?PeerCertificateChain = null;
    errdefer if (peer_certificate_chain) |*chain| chain.deinit();
    if (client_auth) |policy| {
        const split = try splitAuthenticatedClientFlight(
            client_flight.items,
        );
        var verification = try vail.tls.client_auth.verifyClientFlight(
            allocator,
            policy,
            &.{},
            handshake.transcript_state_after_server_finished,
            handshake.client_handshake_traffic_secret,
            split.certificate,
            split.certificate_verify,
            split.finished,
        );
        defer verification.deinit(allocator);
        if (verification.authenticated()) {
            peer_certificate_chain = try copyPeerCertificateChain(
                allocator,
                verification.certificate.entries,
            );
        }
    } else {
        try verifyClientFinished(client_flight.items, &handshake);
    }

    var application = try vail.tls.key_schedule.deriveApplicationFor(
        handshake.handshake_secret,
        handshake.transcript_after_server_finished,
    );
    defer application.master_secret.deinit();
    defer application.client_traffic_secret.deinit();
    defer application.server_traffic_secret.deinit();

    var read_keys = try tls_record.Keys.derive(
        handshake.selection.suite,
        application.client_traffic_secret,
    );
    errdefer read_keys.deinit();
    var exporter_master_secret =
        try vail.tls.key_schedule.deriveExporterMasterSecretFor(
            application.master_secret,
            handshake.transcript_after_server_finished,
        );
    errdefer exporter_master_secret.deinit();
    return .{
        .read = read_keys,
        .write = try tls_record.Keys.derive(
            handshake.selection.suite,
            application.server_traffic_secret,
        ),
        .read_traffic_secret = application.client_traffic_secret,
        .write_traffic_secret = application.server_traffic_secret,
        .cipher_suite = handshake.selection.suite,
        .peer_certificate_chain = peer_certificate_chain,
        .selected_alpn = handshake.selection.alpn_protocol,
        .exporter_master_secret = exporter_master_secret,
    };
}

fn readCleartextHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    message: *std.ArrayList(u8),
    max_message_size: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record_bytes = if (deadline) |absolute|
            try record_io.readRecordWithDeadline(
                io,
                stream,
                &encoded,
                absolute,
            )
        else
            try record_io.readRecord(io, stream, &encoded);
        if (record_bytes[0] != tls_record.content_type_handshake) {
            return error.ExpectedHandshakeRecord;
        }
        try appendBounded(
            allocator,
            message,
            record_bytes[tls_record.header_len..],
            max_message_size,
        );
        if (try completeHandshakeLength(message.items)) |total_len| {
            if (message.items.len != total_len) {
                return error.ExpectedHandshakeRecord;
            }
            return;
        }
    }
}

fn readEncryptedHandshakeFlight(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    keys: *const tls_record.Keys,
    message: *std.ArrayList(u8),
    max_message_size: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var encoded: [record_io.max_record_len]u8 = undefined;
    var sequence: u64 = 0;
    while (true) {
        const record_bytes = if (deadline) |absolute|
            try record_io.readRecordWithDeadline(
                io,
                stream,
                &encoded,
                absolute,
            )
        else
            try record_io.readRecord(io, stream, &encoded);
        // TLS 1.3 compatibility mode permits dummy cleartext CCS records
        // between the encrypted server and client flights.
        if (record_bytes[0] == 0x14) {
            if (!std.mem.eql(
                u8,
                record_bytes,
                &.{ 0x14, 0x03, 0x03, 0, 1, 1 },
            )) return error.InvalidCompatibilityCcs;
            continue;
        }

        var opened_storage: [record_io.max_plaintext_len + 1]u8 =
            undefined;
        const opened = try keys.open(
            sequence,
            record_bytes,
            &opened_storage,
        );
        sequence = try record_io.nextSequence(sequence);
        if (opened.content_type != tls_record.content_type_handshake) {
            return error.ExpectedClientFinished;
        }
        try appendBounded(
            allocator,
            message,
            opened_storage[0..opened.len],
            max_message_size,
        );
        if (try flightEndsWithFinished(message.items)) return;
    }
}

const AuthenticatedClientFlight = struct {
    certificate: []const u8,
    certificate_verify: ?[]const u8,
    finished: []const u8,
};

fn splitAuthenticatedClientFlight(
    bytes: []const u8,
) Error!AuthenticatedClientFlight {
    const certificate_len = try handshakeMessageLength(bytes);
    if (bytes[0] != vail.tls.auth.handshake_type_certificate) {
        return error.InvalidClientFlight;
    }
    var offset = certificate_len;
    if (offset >= bytes.len) return error.InvalidClientFlight;

    var certificate_verify: ?[]const u8 = null;
    if (bytes[offset] == vail.tls.auth.handshake_type_certificate_verify) {
        const verify_len = try handshakeMessageLength(bytes[offset..]);
        certificate_verify = bytes[offset..][0..verify_len];
        offset += verify_len;
        if (offset >= bytes.len) return error.InvalidClientFlight;
    }
    const finished_len = try handshakeMessageLength(bytes[offset..]);
    if (bytes[offset] !=
        vail.tls.server_handshake.handshake_type_finished or
        offset + finished_len != bytes.len)
    {
        return error.InvalidClientFlight;
    }
    return .{
        .certificate = bytes[0..certificate_len],
        .certificate_verify = certificate_verify,
        .finished = bytes[offset..],
    };
}

fn flightEndsWithFinished(bytes: []const u8) Error!bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (bytes.len - offset < 4) return false;
        const message_len = try handshakeMessageLength(bytes[offset..]);
        if (message_len > bytes.len - offset) return false;
        const typ = bytes[offset];
        offset += message_len;
        if (typ == vail.tls.server_handshake.handshake_type_finished) {
            if (offset != bytes.len) return error.InvalidClientFlight;
            return true;
        }
    }
    return false;
}

fn handshakeMessageLength(bytes: []const u8) Error!usize {
    if (bytes.len < 4) return error.InvalidClientFlight;
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    return std.math.add(usize, 4, body_len) catch
        error.InvalidClientFlight;
}

fn copyPeerCertificateChain(
    allocator: std.mem.Allocator,
    certificates: []const []const u8,
) Error!PeerCertificateChain {
    var copies: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (copies.items) |certificate| allocator.free(certificate);
        copies.deinit(allocator);
    }
    for (certificates) |certificate| {
        const copy = try allocator.dupe(u8, certificate);
        errdefer allocator.free(copy);
        try copies.append(
            allocator,
            copy,
        );
    }
    return .{
        .allocator = allocator,
        .certificates = try copies.toOwnedSlice(allocator),
    };
}

fn verifyClientFinished(
    bytes: []const u8,
    handshake: *const vail.tls.server_handshake.Result,
) Error!void {
    if (bytes.len < 4 or
        bytes[0] != vail.tls.server_handshake.handshake_type_finished)
    {
        return error.ExpectedClientFinished;
    }
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    if (body_len != bytes.len - 4) {
        return error.ExpectedClientFinished;
    }
    var expected = try vail.tls.key_schedule.computeFinishedFor(
        handshake.client_handshake_traffic_secret,
        handshake.transcript_after_server_finished,
    );
    defer expected.deinit();
    var actual = try vail.tls.secret.Secret.init(
        expected.hash,
        bytes[4..],
    );
    defer actual.deinit();
    if (!expected.eql(&actual)) return error.BadClientFinished;
}

fn writeServerFlight(
    io: std.Io,
    stream: net.Stream,
    flight: []const u8,
) Error!void {
    if (flight.len < 4) return error.InvalidServerFlight;
    const server_hello_len =
        4 +
        ((@as(usize, flight[1]) << 16) |
            (@as(usize, flight[2]) << 8) |
            flight[3]);
    if (server_hello_len > flight.len or
        server_hello_len > record_io.max_plaintext_len)
    {
        return error.InvalidServerFlight;
    }

    var header: [tls_record.header_len]u8 =
        .{ tls_record.content_type_handshake, 0x03, 0x03, 0, 0 };
    std.mem.writeInt(
        u16,
        header[3..5],
        @intCast(server_hello_len),
        .big,
    );
    try stream_io.writeAllParts(
        io,
        stream,
        &header,
        flight[0..server_hello_len],
    );
    // Compatibility CCS remains necessary for Zig 0.16's TLS client and is
    // accepted (then ignored) by other TLS 1.3 implementations.
    try record_io.writeAll(
        io,
        stream,
        &.{ 0x14, 0x03, 0x03, 0, 1, 1 },
    );

    var offset = server_hello_len;
    while (offset < flight.len) {
        if (flight.len - offset < tls_record.header_len) {
            return error.InvalidServerFlight;
        }
        const encrypted_len = std.mem.readInt(
            u16,
            flight[offset + 3 ..][0..2],
            .big,
        );
        const record_len = tls_record.header_len + encrypted_len;
        if (record_len > flight.len - offset) {
            return error.InvalidServerFlight;
        }
        try record_io.writeAll(
            io,
            stream,
            flight[offset .. offset + record_len],
        );
        offset += record_len;
    }
}

fn completeHandshakeLength(bytes: []const u8) Error!?usize {
    if (bytes.len < 4) return null;
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    const total_len = std.math.add(usize, 4, body_len) catch
        return error.HandshakeMessageTooLarge;
    return if (bytes.len >= total_len) total_len else null;
}

fn appendBounded(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),
    bytes: []const u8,
    limit: usize,
) Error!void {
    const next_len = std.math.add(
        usize,
        list.items.len,
        bytes.len,
    ) catch return error.HandshakeMessageTooLarge;
    if (next_len > limit) return error.HandshakeMessageTooLarge;
    try list.appendSlice(allocator, bytes);
}

fn clientSupportsSignatureScheme(
    encoded: []const u8,
    target: u16,
) bool {
    if (encoded.len < 2) return false;
    const list_len = std.mem.readInt(u16, encoded[0..2], .big);
    if (list_len != encoded.len - 2 or list_len % 2 != 0) return false;
    var offset: usize = 2;
    while (offset < encoded.len) : (offset += 2) {
        if (std.mem.readInt(
            u16,
            encoded[offset..][0..2],
            .big,
        ) == target) return true;
    }
    return false;
}

fn freshSigner(
    io: std.Io,
    configured: vail.tls.auth.Signer,
) Error!vail.tls.auth.Signer {
    var signer = configured;
    // vail identities may carry deterministic test noise/nonces. A long-lived
    // listener must never reuse those values across handshakes, so production
    // accepts copy the key material but always replace per-signature entropy.
    switch (signer) {
        .ed25519 => |*value| {
            var noise: [
                std.crypto.sign.Ed25519.noise_length
            ]u8 = undefined;
            try secure_random.fill(io, &noise);
            value.noise = noise;
        },
        .ecdsa_p256_sha256 => |*value| {
            var noise: [
                std.crypto.sign.ecdsa.EcdsaP256Sha256.noise_length
            ]u8 = undefined;
            try secure_random.fill(io, &noise);
            value.noise = noise;
        },
        .ecdsa_p384_sha384 => |*value| {
            var noise: [
                std.crypto.sign.ecdsa.EcdsaP384Sha384.noise_length
            ]u8 = undefined;
            try secure_random.fill(io, &noise);
            value.noise = noise;
        },
        .ecdsa_p521_sha512 => |*value| value.io = io,
        .ecdsa_p521_sha512_prepared => {},
        .sm2sig_sm3 => |*value| {
            try secure_random.fill(io, &value.nonce);
        },
        inline .ml_dsa_44, .ml_dsa_65, .ml_dsa_87 => |*value| {
            var noise = value.noise orelse undefined;
            try secure_random.fill(io, &noise);
            value.noise = noise;
        },
        .rsa_pss => |*value| value.io = io,
        .rsa_pkcs1, .custom => {},
    }
    return signer;
}

fn wipeSigner(signer: *vail.tls.auth.Signer) void {
    // `freshSigner` copies private key material as well as its per-signature
    // randomness. Wipe the whole temporary union once CertificateVerify has
    // been generated; the caller-owned configured identity remains intact.
    std.crypto.secureZero(u8, std.mem.asBytes(signer));
    signer.* = undefined;
}

test "signature scheme offer parsing is length bounded" {
    try std.testing.expect(clientSupportsSignatureScheme(
        &.{ 0, 4, 0x08, 0x07, 0x04, 0x03 },
        vail.tls.auth.signature_scheme_ecdsa_secp256r1_sha256,
    ));
    try std.testing.expect(!clientSupportsSignatureScheme(
        &.{ 0, 4, 0x08, 0x07 },
        vail.tls.auth.signature_scheme_ecdsa_secp256r1_sha256,
    ));
}

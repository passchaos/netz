//! Blocking vail-backed TLS 1.3 client connection.
//!
//! This transport exists alongside Zig's standard TLS client because Zig 0.16
//! cannot send a client identity. Application protocols can opt into it while
//! retaining the mature standard-library path for ordinary verified clients.

const std = @import("std");
const vail = @import("vail");
const handshake_deadline = @import("handshake_deadline.zig");
const record_io = @import("record_io.zig");
const record_stream = @import("record_stream.zig");
const stream_io = @import("../../internal/stream_io.zig");

const net = std.Io.net;
const tls_record = vail.tls.record;
const CertificateBundle = std.crypto.Certificate.Bundle;

const x25519_group: u16 = 0x001d;

pub const Error = std.mem.Allocator.Error ||
    std.Io.RandomSecureError ||
    std.Io.Cancelable ||
    CertificateBundle.RescanError ||
    record_io.Error ||
    record_stream.Error ||
    vail.tls.auth.Error ||
    vail.tls.client_auth.Error ||
    vail.tls.client_handshake.Error ||
    vail.tls.client_hello.Error ||
    vail.tls.key_exchange.Error ||
    vail.tls.key_schedule.Error ||
    vail.tls.record.Error ||
    vail.tls.server_hello.Error ||
    error{
        InvalidCompatibilityCcs,
        InvalidServerFlight,
        MissingKeyShare,
        UnexpectedTlsContent,
        UnsupportedCipherSuite,
        ConflictingOcspVerifier,
        OcspPolicyRequiresRequest,
    };

pub const Options = struct {
    server_name: []const u8,
    server_verifier: vail.tls.auth.ClientVerifier,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    /// Ordered ALPN offers carried in ClientHello. When non-empty, the server
    /// must select exactly one of them or the handshake is rejected.
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    /// Request an RFC 6066 stapled OCSP response. This defaults on so an RFC
    /// 7633 Must-Staple leaf can satisfy the verifier automatically.
    request_ocsp: bool = true,
    max_server_handshake_size: usize = 256 * 1024,
    /// Optional absolute receive budget for the complete TLS handshake. It is
    /// not renewed between ServerHello and the encrypted server flight.
    handshake_timeout: ?std.Io.Duration = null,
};

pub const CaBundle = struct {
    bundle: *CertificateBundle,
    lock: *std.Io.RwLock,
};

/// High-level trust and identity policy for the vail TLS client.
///
/// The low-level `Options` API remains useful for custom verifiers. This
/// wrapper gives application transports the same system-root/caller-bundle
/// defaults as netz's standard-library TLS client while adding the client
/// identity that Zig 0.16's standard client cannot send.
pub const VerifiedOptions = struct {
    server_name: []const u8,
    verify_host: bool = true,
    ca_bundle: ?CaBundle = null,
    server_verifier: ?vail.tls.auth.ClientVerifier = null,
    /// Stapled OCSP policy applied by the built-in system/caller-bundle
    /// verifier. A custom `server_verifier` must own its OCSP policy and
    /// therefore cannot be combined with a non-default value here.
    stapled_ocsp: vail.x509.trust.StapledOcspPolicy = .ignore,
    request_ocsp: bool = true,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_server_handshake_size: usize = 256 * 1024,
    handshake_timeout: ?std.Io.Duration = null,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    records: record_stream.Stream,
    selected_alpn: ?[]u8 = null,
    peer_certificate_chain: [][]const u8 = &.{},
    cipher_suite: vail.tls.cipher_suite.Suite,
    exporter_master_secret: vail.tls.secret.Secret,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
    ) Error!*Connection {
        return initBefore(
            allocator,
            io,
            stream,
            options,
            try handshake_deadline.fromTimeout(
                io,
                options.handshake_timeout,
            ),
        );
    }

    /// Perform the complete TLS handshake under the earlier of the caller's
    /// absolute deadline and `options.handshake_timeout`.
    pub fn initWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*Connection {
        return initBefore(
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

    fn initBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!*Connection {
        if (options.client_identity) |identity| try identity.validate();

        var client_random: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &client_random);
        try std.Io.randomSecure(io, &client_random);
        var session_id: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &session_id);
        try std.Io.randomSecure(io, &session_id);
        var x25519_secret: [
            vail.tls.key_exchange.secret_len
        ]u8 = undefined;
        defer std.crypto.secureZero(u8, &x25519_secret);
        try std.Io.randomSecure(io, &x25519_secret);
        // Normalize deterministic/random material exactly once before deriving
        // both public and shared keys.
        x25519_secret[0] &= 248;
        x25519_secret[31] &= 127;
        x25519_secret[31] |= 64;
        const x25519_public = try vail.tls.key_exchange.publicKey(
            x25519_secret,
        );

        var client_hello: std.ArrayList(u8) = .empty;
        defer client_hello.deinit(allocator);
        try vail.tls.client_hello.write(
            &client_hello,
            allocator,
            .{
                .random = client_random,
                .session_id = &session_id,
                .server_name = options.server_name,
                .x25519_public_key = x25519_public,
                .cipher_suites = options.cipher_suites,
                .alpn_protocols = options.alpn_protocols,
                .request_ocsp = options.request_ocsp,
            },
        );
        try writeCleartextHandshake(
            io,
            stream,
            client_hello.items,
        );

        var server_hello: std.ArrayList(u8) = .empty;
        defer server_hello.deinit(allocator);
        try readCleartextHandshake(
            allocator,
            io,
            stream,
            &server_hello,
            options.max_server_handshake_size,
            deadline,
        );
        const parsed_server_hello =
            try vail.tls.server_hello.parseServerHello(
                server_hello.items,
            );
        if (!containsCipherSuite(
            options.cipher_suites,
            parsed_server_hello.cipher_suite,
        )) return error.UnsupportedCipherSuite;
        if (parsed_server_hello.key_share_group != x25519_group) {
            return error.MissingKeyShare;
        }
        if (!std.mem.eql(
            u8,
            parsed_server_hello.session_id_echo,
            &session_id,
        )) return error.InvalidServerFlight;
        var shared_secret = try vail.tls.key_exchange.sharedSecret(
            x25519_secret,
            parsed_server_hello.key_share,
        );
        defer std.crypto.secureZero(u8, &shared_secret);

        const hello_hash = vail.tls.transcript.hashFor(
            parsed_server_hello.cipher_suite.hash(),
            &.{ client_hello.items, server_hello.items },
        );
        var handshake = try vail.tls.key_schedule.deriveHandshakeFor(
            parsed_server_hello.cipher_suite.hash(),
            &shared_secret,
            hello_hash,
            null,
        );
        defer handshake.early_secret.deinit();
        defer handshake.handshake_secret.deinit();
        defer handshake.client_traffic_secret.deinit();
        defer handshake.server_traffic_secret.deinit();

        var handshake_read_keys = try tls_record.Keys.derive(
            parsed_server_hello.cipher_suite,
            handshake.server_traffic_secret,
        );
        defer handshake_read_keys.deinit();
        var server_flight: std.ArrayList(u8) = .empty;
        defer server_flight.deinit(allocator);
        try readEncryptedServerFlight(
            allocator,
            io,
            stream,
            &handshake_read_keys,
            &server_flight,
            options.max_server_handshake_size,
            deadline,
        );

        var client_flight: std.ArrayList(u8) = .empty;
        defer client_flight.deinit(allocator);
        var verified =
            try vail.tls.client_handshake
                .verifyServerAndWriteClientFlight(
                &client_flight,
                allocator,
                .{
                    .client_hello_bytes = client_hello.items,
                    .server_hello_bytes = server_hello.items,
                    .encrypted_server_flight = server_flight.items,
                    .handshake_secret = handshake.handshake_secret,
                    .client_handshake_traffic_secret = handshake.client_traffic_secret,
                    .server_handshake_traffic_secret = handshake.server_traffic_secret,
                    .server_verifier = options.server_verifier,
                    .server_name = options.server_name,
                    .client_identity = options.client_identity,
                },
            );
        defer verified.deinit();
        if (options.alpn_protocols.len != 0 and
            !containsProtocol(options.alpn_protocols, verified.selected_alpn))
        {
            return error.InvalidServerFlight;
        }
        try writeEncryptedClientFlight(
            io,
            stream,
            parsed_server_hello.cipher_suite,
            handshake.client_traffic_secret,
            client_flight.items,
        );

        var read_keys = try tls_record.Keys.derive(
            parsed_server_hello.cipher_suite,
            verified.application.server_traffic_secret,
        );
        errdefer read_keys.deinit();
        var write_keys = try tls_record.Keys.derive(
            parsed_server_hello.cipher_suite,
            verified.application.client_traffic_secret,
        );
        errdefer write_keys.deinit();
        const selected_alpn = if (verified.selected_alpn) |protocol|
            try allocator.dupe(u8, protocol)
        else
            null;
        errdefer if (selected_alpn) |protocol| allocator.free(protocol);
        const peer_certificate_chain = verified.peer_certificate_chain;
        verified.peer_certificate_chain = &.{};
        errdefer {
            for (peer_certificate_chain) |certificate| {
                allocator.free(certificate);
            }
            allocator.free(peer_certificate_chain);
        }
        var exporter_master_secret =
            try vail.tls.key_schedule.deriveExporterMasterSecretFor(
                verified.application.master_secret,
                verified.transcript_after_server_finished,
            );
        errdefer exporter_master_secret.deinit();

        var records = record_stream.Stream.init(
            read_keys,
            write_keys,
            verified.application.server_traffic_secret,
            verified.application.client_traffic_secret,
        );
        records.allowNewSessionTickets();
        const connection = try allocator.create(Connection);
        // Transfer all established-session secrets only after the final
        // allocation succeeds; earlier failures stay owned by local errdefers.
        connection.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .records = records,
            .selected_alpn = selected_alpn,
            .peer_certificate_chain = peer_certificate_chain,
            .cipher_suite = verified.cipher_suite,
            .exporter_master_secret = exporter_master_secret,
        };
        exporter_master_secret = undefined;
        return connection;
    }

    /// Establish a client-authenticated TLS connection with normal host trust.
    ///
    /// Caller-managed CA bundles are read-locked only for the synchronous
    /// handshake. The resulting connection retains traffic keys, not verifier
    /// context pointers or trust-store locks.
    pub fn initVerified(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: VerifiedOptions,
    ) Error!*Connection {
        return initVerifiedBefore(
            allocator,
            io,
            stream,
            options,
            null,
        );
    }

    /// High-level verified-client counterpart to `initWithDeadline`.
    pub fn initVerifiedWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: VerifiedOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*Connection {
        return initVerifiedBefore(
            allocator,
            io,
            stream,
            options,
            try handshake_deadline.usable(io, deadline),
        );
    }

    fn initVerifiedBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: VerifiedOptions,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!*Connection {
        try validateVerifiedOptions(options);
        var system_store: ?vail.x509.trust.SystemStore = null;
        defer if (system_store) |*store| store.deinit();
        var caller_bundle_locked = false;
        defer if (caller_bundle_locked) {
            options.ca_bundle.?.lock.unlockShared(io);
        };

        var bundle_verifier: vail.x509.trust.BundleVerifier = undefined;
        const verifier = options.server_verifier orelse blk: {
            // Disabling hostname verification without supplying an explicit
            // pin/custom verifier would silently turn mTLS into unauthenticated
            // encryption. Reject that ambiguous configuration.
            if (!options.verify_host) return error.CertificateUntrusted;
            const now = std.Io.Timestamp.now(io, .real);
            if (options.ca_bundle) |ca_bundle| {
                try ca_bundle.lock.lockShared(io);
                caller_bundle_locked = true;
                bundle_verifier = .{
                    .bundle = ca_bundle.bundle,
                    .now_seconds = now.toSeconds(),
                };
            } else {
                system_store = try .init(allocator, io, now);
                bundle_verifier =
                    system_store.?.verifier(now.toSeconds());
            }
            bundle_verifier.stapled_ocsp = options.stapled_ocsp;
            break :blk bundle_verifier.clientVerifier();
        };

        const low_level_options: Options = .{
            .server_name = options.server_name,
            .server_verifier = verifier,
            .client_identity = options.client_identity,
            .alpn_protocols = options.alpn_protocols,
            .cipher_suites = options.cipher_suites,
            .request_ocsp = options.request_ocsp,
            .max_server_handshake_size = options.max_server_handshake_size,
            .handshake_timeout = options.handshake_timeout,
        };
        return if (outer_deadline) |deadline|
            initWithDeadline(
                allocator,
                io,
                stream,
                low_level_options,
                deadline,
            )
        else
            init(allocator, io, stream, low_level_options);
    }

    pub fn deinit(self: *Connection) void {
        if (self.records.shouldSendCloseNotify()) {
            self.records.sendCloseNotify(self.io, self.stream) catch {};
        }
        self.records.deinit();
        self.stream.close(self.io);
        const allocator = self.allocator;
        if (self.selected_alpn) |protocol| allocator.free(protocol);
        for (self.peer_certificate_chain) |certificate| {
            allocator.free(certificate);
        }
        allocator.free(self.peer_certificate_chain);
        self.exporter_master_secret.deinit();
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Return the ALPN protocol selected during the TLS handshake. The slice
    /// is owned by this connection and remains valid until `deinit`.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return self.selected_alpn;
    }

    /// Return the authenticated server certificate chain. The DER entries are
    /// owned by this connection and remain valid until `deinit`.
    pub fn peerCertificates(self: *const Connection) []const []const u8 {
        return self.peer_certificate_chain;
    }

    /// Return the authenticated TLS 1.3 cipher suite negotiated with the
    /// server. This value remains available for the connection lifetime.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) vail.tls.cipher_suite.Suite {
        return self.cipher_suite;
    }

    /// Return the transcript/HKDF hash implied by the negotiated suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) vail.tls.secret.Hash {
        return self.cipher_suite.hash();
    }

    /// Export TLS 1.3 channel-bound keying material (RFC 8446 section 7.5).
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try vail.tls.key_schedule.exportKeyingMaterialFor(
            self.exporter_master_secret,
            label,
            context,
            out,
        );
    }

    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        try self.records.updateTrafficKeys(
            self.io,
            self.stream,
            request_peer_update,
        );
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) record_stream.KeyUpdateCounts {
        return self.records.keyUpdateCounts();
    }

    /// Send an orderly TLS write-half close while retaining the receive side.
    pub fn sendCloseNotify(self: *Connection) Error!void {
        try self.records.sendCloseNotify(self.io, self.stream);
    }

    pub fn receivedCloseNotify(self: *const Connection) bool {
        return self.records.receivedCloseNotify();
    }

    pub fn isReusableBoundary(self: *const Connection) bool {
        return self.records.isReusableBoundary();
    }

    pub fn read(self: *Connection, out: []u8) Error!usize {
        return self.records.read(self.io, self.stream, out);
    }

    pub fn readWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return self.records.readWithDeadline(
            self.io,
            self.stream,
            out,
            deadline,
        );
    }

    pub fn writeAll(
        self: *Connection,
        bytes: []const u8,
    ) Error!void {
        return self.records.writeAll(self.io, self.stream, bytes);
    }

    pub fn writeAllWithDeadline(
        self: *Connection,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.records.writeAllWithDeadline(
            self.io,
            self.stream,
            bytes,
            committed,
            deadline,
        );
    }

    pub fn finishPendingWrite(
        self: *Connection,
        committed: *usize,
    ) Error!void {
        return self.records.finishPendingWrite(
            self.io,
            self.stream,
            committed,
        );
    }

    pub fn writeAllParts(
        self: *Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.records.writeAllParts(
            self.io,
            self.stream,
            first,
            second,
        );
    }

    pub fn writeAllSlices(
        self: *Connection,
        parts: []const []const u8,
    ) Error!void {
        return self.records.writeAllSlices(
            self.io,
            self.stream,
            parts,
        );
    }
};

fn validateVerifiedOptions(options: VerifiedOptions) Error!void {
    if (options.stapled_ocsp != .ignore and !options.request_ocsp) {
        return error.OcspPolicyRequiresRequest;
    }
    if (options.server_verifier != null and
        options.stapled_ocsp != .ignore)
    {
        return error.ConflictingOcspVerifier;
    }
}

test "verified client rejects a built-in OCSP policy with a custom verifier" {
    const Callback = struct {
        fn verify(
            _: ?*anyopaque,
            _: vail.tls.auth.TrustContext,
        ) anyerror!void {}
    };
    try std.testing.expectError(
        error.OcspPolicyRequiresRequest,
        validateVerifiedOptions(.{
            .server_name = "localhost",
            .stapled_ocsp = .require,
            .request_ocsp = false,
        }),
    );
    try std.testing.expectError(
        error.ConflictingOcspVerifier,
        validateVerifiedOptions(.{
            .server_name = "localhost",
            .server_verifier = .{ .verify_trust = Callback.verify },
            .stapled_ocsp = .require,
        }),
    );
}

fn writeCleartextHandshake(
    io: std.Io,
    stream: net.Stream,
    message: []const u8,
) Error!void {
    if (message.len > std.math.maxInt(u16)) {
        return error.InvalidServerFlight;
    }
    var header: [tls_record.header_len]u8 =
        .{ tls_record.content_type_handshake, 0x03, 0x01, 0, 0 };
    std.mem.writeInt(
        u16,
        header[3..5],
        @intCast(message.len),
        .big,
    );
    // Keep the TLS record header and ClientHello contiguous. TURN servers such
    // as coturn share plain-TCP and TLS listeners and sniff the first receive;
    // a single contiguous write avoids classifying a header-only first chunk.
    var encoded: [tls_record.header_len + std.math.maxInt(u16)]u8 = undefined;
    @memcpy(encoded[0..tls_record.header_len], &header);
    @memcpy(encoded[tls_record.header_len..][0..message.len], message);
    try record_io.writeAll(io, stream, encoded[0 .. tls_record.header_len + message.len]);
}

fn readCleartextHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    message: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = if (deadline) |absolute|
            try record_io.readRecordWithDeadline(
                io,
                stream,
                &encoded,
                absolute,
            )
        else
            try record_io.readRecord(io, stream, &encoded);
        if (record[0] != tls_record.content_type_handshake) {
            return error.InvalidServerFlight;
        }
        try appendBounded(
            allocator,
            message,
            record[tls_record.header_len..],
            limit,
        );
        if (try completeHandshakeLength(message.items)) |total| {
            if (total != message.items.len) {
                return error.InvalidServerFlight;
            }
            return;
        }
    }
}

fn readEncryptedServerFlight(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    keys: *const tls_record.Keys,
    flight: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var encoded: [record_io.max_record_len]u8 = undefined;
    var sequence: u64 = 0;
    while (true) {
        const record = if (deadline) |absolute|
            try record_io.readRecordWithDeadline(
                io,
                stream,
                &encoded,
                absolute,
            )
        else
            try record_io.readRecord(io, stream, &encoded);
        if (record[0] == 0x14) {
            if (!std.mem.eql(
                u8,
                record,
                &.{ 0x14, 0x03, 0x03, 0, 1, 1 },
            )) return error.InvalidCompatibilityCcs;
            continue;
        }
        var plaintext: [
            record_io.max_plaintext_len + 1
        ]u8 = undefined;
        const opened = try keys.open(sequence, record, &plaintext);
        sequence = try record_io.nextSequence(sequence);
        if (opened.content_type != tls_record.content_type_handshake) {
            return error.UnexpectedTlsContent;
        }
        try appendBounded(
            allocator,
            flight,
            plaintext[0..opened.len],
            limit,
        );
        if (serverFlightComplete(flight.items)) return;
    }
}

fn writeEncryptedClientFlight(
    io: std.Io,
    stream: net.Stream,
    suite: vail.tls.cipher_suite.Suite,
    traffic_secret: vail.tls.secret.Secret,
    flight: []const u8,
) Error!void {
    var keys = try tls_record.Keys.derive(suite, traffic_secret);
    defer keys.deinit();
    var offset: usize = 0;
    var sequence: u64 = 0;
    while (offset < flight.len) {
        const message_len = (try completeHandshakeLength(
            flight[offset..],
        )) orelse return error.InvalidServerFlight;
        var encoded: [record_io.max_record_len]u8 = undefined;
        const len = try keys.seal(
            sequence,
            tls_record.content_type_handshake,
            flight[offset .. offset + message_len],
            &encoded,
        );
        sequence = try record_io.nextSequence(sequence);
        try record_io.writeAll(io, stream, encoded[0..len]);
        offset += message_len;
    }
}

fn serverFlightComplete(bytes: []const u8) bool {
    if (bytes.len < 4) return false;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const total = completeHandshakeLength(bytes[offset..]) catch
            return false;
        const len = total orelse return false;
        if (len > bytes.len - offset) return false;
        const typ = bytes[offset];
        offset += len;
        if (typ == vail.tls.server_handshake.handshake_type_finished) {
            return offset == bytes.len;
        }
        // Finished is the only legal terminator. If a complete message follows
        // it later, this function will never return true and the bounded reader
        // rejects the oversized/invalid flight rather than accepting a prefix.
    }
    return false;
}

fn completeHandshakeLength(bytes: []const u8) Error!?usize {
    if (bytes.len < 4) return null;
    const body_len =
        (@as(usize, bytes[1]) << 16) |
        (@as(usize, bytes[2]) << 8) |
        bytes[3];
    const total = std.math.add(usize, 4, body_len) catch
        return error.InvalidServerFlight;
    return if (bytes.len >= total) total else null;
}

fn appendBounded(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),
    bytes: []const u8,
    limit: usize,
) Error!void {
    const next = std.math.add(
        usize,
        list.items.len,
        bytes.len,
    ) catch return error.InvalidServerFlight;
    if (next > limit) return error.InvalidServerFlight;
    try list.appendSlice(allocator, bytes);
}

fn containsCipherSuite(
    suites: []const vail.tls.cipher_suite.Suite,
    selected: vail.tls.cipher_suite.Suite,
) bool {
    for (suites) |suite| {
        if (suite == selected) return true;
    }
    return false;
}

fn containsProtocol(
    protocols: []const []const u8,
    selected: ?[]const u8,
) bool {
    const value = selected orelse return false;
    for (protocols) |protocol| {
        if (std.mem.eql(u8, protocol, value)) return true;
    }
    return false;
}

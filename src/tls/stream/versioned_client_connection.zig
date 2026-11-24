//! Blocking vail-backed TLS 1.2/TLS 1.3 client connection.

const std = @import("std");
const vail = @import("vail");
const handshake_deadline = @import("handshake_deadline.zig");
const key_material = @import("key_material.zig");
const record_io = @import("record_io.zig");
const record_stream = @import("record_stream.zig");
const tls12_record_stream = @import("tls12_record_stream.zig");
const version = @import("version.zig");
const root_trust = @import("../../trust.zig");

const net = std.Io.net;
const CertificateBundle = std.crypto.Certificate.Bundle;
const max_handshake_size: usize = 256 * 1024;
const max_post_handshake_size: usize = 64 * 1024;
const max_tls12_cipher_suites: usize = 64;
const AutoClient = vail.tls.versioned_client_connection.ClientConnection(
    max_handshake_size,
    max_post_handshake_size,
);
const Tls13Client = vail.tls.client_connection.ClientConnection(
    max_handshake_size,
    max_post_handshake_size,
);
const Tls12Client = vail.tls.tls12_client_connection.ClientConnection(
    max_handshake_size,
    max_post_handshake_size,
);

pub const Error = std.mem.Allocator.Error ||
    std.Io.RandomSecureError ||
    CertificateBundle.RescanError ||
    record_io.Error ||
    vail.tls.versioned_client_connection.Error ||
    vail.tls.ticket.Error ||
    vail.tls.tls12_client_connection.Error ||
    record_stream.Error ||
    tls12_record_stream.Error ||
    vail.tls.auth.Error ||
    error{
        HandshakeMessageTooLarge,
        InvalidProtocolPolicy,
        PeerAbortedHandshake,
        CertificateUntrusted,
        ConflictingOcspVerifier,
        OcspPolicyRequiresRequest,
        PlatformVerifierUnavailable,
        TlsKeyUpdateUnavailable,
        ReadFailed,
        StreamTooLong,
    };

pub const CaBundle = struct {
    bundle: *CertificateBundle,
    lock: *std.Io.RwLock,
};

pub const Options = struct {
    server_name: []const u8,
    server_verifier: vail.tls.auth.ClientVerifier,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const vail.tls.tls12.Suite =
        &version.default_tls12_cipher_suites,
    protocol_policy: version.Policy = .tls12_and_tls13,
    /// Request an RFC 5077 ticket on a full TLS 1.2 handshake. A supplied
    /// resumption ticket is always offered and requests renewal.
    request_tls12_session_ticket: bool = true,
    tls12_ticket_resumption: ?*const vail.tls.tls12_ticket.Cached = null,
    /// Request and retain an RFC 8446 NewSessionTicket on TLS 1.3.
    request_tls13_session_ticket: bool = true,
    tls13_ticket_resumption: ?*const vail.tls.ticket.Cached = null,
    request_ocsp: bool = true,
    /// RFC 8879 algorithms advertised in the TLS 1.3 compress_certificate
    /// extension. All three vail-supported algorithms are offered by
    /// default; an empty slice disables the extension entirely.
    certificate_compression_algorithms: []const vail.tls.certificate_compression.Algorithm =
        &default_certificate_compression_algorithms,
    /// Reject a compressed Certificate whose declared uncompressed size
    /// exceeds this bound before allocating or inflating any bytes.
    max_decompressed_certificate_len: usize = default_max_decompressed_certificate_len,
    max_server_handshake_size: usize = max_handshake_size,
    handshake_timeout: ?std.Io.Duration = null,
};

/// Brotli and zstd compress real certificate chains substantially better than
/// zlib while remaining in vail's pure-Zig support set; keep zlib last for
/// maximum server interoperability.
pub const default_certificate_compression_algorithms = [_]vail.tls.certificate_compression.Algorithm{
    .brotli,
    .zstd,
    .zlib,
};
pub const default_max_decompressed_certificate_len: usize = 64 * 1024;

pub const VerifiedOptions = struct {
    server_name: []const u8,
    /// When false, the built-in verifier still enforces the complete CA path,
    /// validity, signature, serverAuth EKU, revocation, and OCSP policy while
    /// omitting only DNS/IP identity matching.
    verify_host: bool = true,
    ca_bundle: ?CaBundle = null,
    /// Optional process environment used to honor `SSL_CERT_FILE` and
    /// `SSL_CERT_DIR` when no caller CA bundle is supplied. Null keeps the
    /// platform store.
    system_environ: ?std.process.Environ = null,
    /// Optional caller-owned system store reused across handshakes. It takes
    /// precedence over `system_environ`; the caller must keep it alive for the
    /// synchronous handshake.
    system_store: ?*const vail.x509.trust.SystemStore = null,
    /// Selects the default root set when no explicit verifier, CA bundle, or
    /// store is supplied. `.platform` uses the OS verifier; `.bundled` uses
    /// the compiled-in Mozilla roots.
    root_source: root_trust.RootSource = .system,
    server_verifier: ?vail.tls.auth.ClientVerifier = null,
    stapled_ocsp: vail.x509.trust.StapledOcspPolicy = .ignore,
    request_ocsp: bool = true,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const vail.tls.tls12.Suite =
        &version.default_tls12_cipher_suites,
    protocol_policy: version.Policy = .tls12_and_tls13,
    request_tls12_session_ticket: bool = true,
    tls12_ticket_resumption: ?*const vail.tls.tls12_ticket.Cached = null,
    request_tls13_session_ticket: bool = true,
    tls13_ticket_resumption: ?*const vail.tls.ticket.Cached = null,
    certificate_compression_algorithms: []const vail.tls.certificate_compression.Algorithm =
        &default_certificate_compression_algorithms,
    max_decompressed_certificate_len: usize = default_max_decompressed_certificate_len,
    max_server_handshake_size: usize = max_handshake_size,
    handshake_timeout: ?std.Io.Duration = null,
};

pub const Connection = struct {
    const Records = union(enum) {
        tls13: record_stream.Stream,
        tls12: tls12_record_stream.Stream,
    };

    const Tls12Exporter = struct {
        master_secret: [vail.tls.tls12.master_secret_len]u8,
        client_random: [32]u8,
        server_random: [32]u8,
        suite: vail.tls.tls12.Suite,
    };

    const Exporter = union(enum) {
        tls13: vail.tls.secret.Secret,
        tls12: Tls12Exporter,
    };

    const Tls13TicketContext = struct {
        master_secret: vail.tls.secret.Secret,
        transcript_after_client_finished: vail.tls.transcript.Digest,
        server_name: []u8,

        fn deinit(self: *Tls13TicketContext, allocator: std.mem.Allocator) void {
            self.master_secret.deinit();
            allocator.free(self.server_name);
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    records: Records,
    selected_alpn: ?[]u8,
    peer_certificate_chain: [][]const u8,
    protocol: version.Protocol,
    cipher_suite: version.NegotiatedCipherSuite,
    transcript_hash: vail.tls.secret.Hash,
    exporter: Exporter,
    tls13_ticket_context: ?Tls13TicketContext = null,
    tls13_session_ticket: ?vail.tls.ticket.Cached = null,
    tls12_session_ticket: ?vail.tls.tls12_ticket.Cached = null,
    resumed: bool,
    /// Algorithm of the compressed Certificate received from the server
    /// (RFC 8879), or null when the Certificate message was uncompressed.
    certificate_compression: ?vail.tls.certificate_compression.Algorithm = null,

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
            try handshake_deadline.fromTimeout(io, options.handshake_timeout),
        );
    }

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
        if ((options.protocol_policy.offersTls12() and
            options.tls12_cipher_suites.len == 0) or
            (options.protocol_policy.offersTls13() and
                options.cipher_suites.len == 0))
        {
            return error.InvalidProtocolPolicy;
        }
        if (!options.protocol_policy.offersTls12() and
            options.tls12_ticket_resumption != null)
        {
            return error.InvalidProtocolPolicy;
        }
        if (!options.protocol_policy.offersTls13() and
            options.tls13_ticket_resumption != null)
        {
            return error.InvalidProtocolPolicy;
        }
        vail.tls.certificate_compression.validateAlgorithms(
            options.certificate_compression_algorithms,
        ) catch return error.InvalidProtocolPolicy;
        if (options.max_decompressed_certificate_len == 0) {
            return error.InvalidProtocolPolicy;
        }
        if (options.max_server_handshake_size == 0 or
            options.max_server_handshake_size > max_handshake_size)
        {
            return error.HandshakeMessageTooLarge;
        }
        if (options.client_identity) |identity| try identity.validate();

        var client_random: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &client_random);
        try std.Io.randomSecure(io, &client_random);
        var session_id: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &session_id);
        try std.Io.randomSecure(io, &session_id);
        var tls13_key: vail.tls.key_exchange.ClientKeyMaterial =
            if (options.protocol_policy.offersTls12())
                .{ .secp256r1 = try key_material.randomP256(io) }
            else
                .{ .x25519 = try key_material.randomX25519(io) };
        var tls13_retry_key: vail.tls.key_exchange.ClientKeyMaterial =
            if (options.protocol_policy.offersTls12())
                .{ .x25519 = try key_material.randomX25519(io) }
            else
                .{ .secp256r1 = try key_material.randomP256(io) };
        var tls13_keys_owned = true;
        defer if (tls13_keys_owned) {
            tls13_key.wipe();
            tls13_retry_key.wipe();
        };
        var tls13_public_storage: [vail.tls.key_exchange.p256.public_len]u8 = undefined;
        const tls13_public = switch (tls13_key) {
            .x25519 => |secret| blk: {
                const public = try vail.tls.key_exchange.publicKey(secret);
                @memcpy(tls13_public_storage[0..public.len], &public);
                break :blk tls13_public_storage[0..public.len];
            },
            .secp256r1 => |secret| blk: {
                const public = try vail.tls.key_exchange.p256.publicKey(secret);
                @memcpy(tls13_public_storage[0..public.len], &public);
                break :blk tls13_public_storage[0..public.len];
            },
            else => unreachable,
        };
        var tls12_key_x25519 = try key_material.randomX25519(io);
        defer std.crypto.secureZero(u8, &tls12_key_x25519);
        var tls12_key = try key_material.randomP256(io);
        defer std.crypto.secureZero(u8, &tls12_key);
        var tls12_key_p384 = if (options.protocol_policy == .tls12_only)
            try key_material.randomP384(io)
        else
            null;
        defer if (tls12_key_p384) |*key| std.crypto.secureZero(u8, key);
        var tls12_key_p521 = if (options.protocol_policy == .tls12_only)
            try key_material.randomP521(io)
        else
            null;
        defer if (tls12_key_p521) |*key| std.crypto.secureZero(u8, key);
        const tls12_groups: []const u16 = if (options.protocol_policy.offersTls13())
            &version.dual_version_tls12_groups
        else
            &version.default_tls12_groups;

        var tls12_wire: [max_tls12_cipher_suites + 1]u16 = undefined;
        if (options.tls12_cipher_suites.len > max_tls12_cipher_suites) {
            return error.InvalidProtocolPolicy;
        }
        for (options.tls12_cipher_suites, 0..) |suite, index| {
            tls12_wire[index] = @intFromEnum(suite);
        }
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV is mandatory for the strict TLS
        // 1.2 profile and harmless to TLS 1.3 peers.
        tls12_wire[options.tls12_cipher_suites.len] = 0x00ff;

        const now_milliseconds: u64 = @intCast(@max(
            0,
            std.Io.Timestamp.now(io, .real).toMilliseconds(),
        ));
        const now_seconds = now_milliseconds / std.time.ms_per_s;
        const tls13_resumption = if (options.tls13_ticket_resumption) |cached| blk: {
            if (!std.mem.eql(u8, cached.server_name, options.server_name) or
                !cachedAlpnOffered(cached.alpn, options.alpn_protocols))
            {
                return error.SessionContextMismatch;
            }
            break :blk try vail.tls.client_connection.ClientPsk.fromCached(
                cached,
                now_milliseconds,
            );
        } else null;
        const tls13_config = vail.tls.client_connection.Config{
            .allocator = allocator,
            .random = client_random,
            .session_id = &session_id,
            .server_name = options.server_name,
            .key_material = &tls13_key,
            .retry_key_material = &tls13_retry_key,
            .cipher_suites = options.cipher_suites,
            .additional_cipher_suites = if (options.protocol_policy.offersTls12())
                tls12_wire[0 .. options.tls12_cipher_suites.len + 1]
            else
                &.{},
            .supported_versions = if (options.protocol_policy.offersTls12())
                &.{ 0x0304, 0x0303 }
            else
                &.{0x0304},
            .offer_extended_master_secret = options.protocol_policy.offersTls12(),
            .alpn_protocols = options.alpn_protocols,
            .request_ocsp = options.request_ocsp,
            .certificate_compression_algorithms = options.certificate_compression_algorithms,
            .max_decompressed_certificate_len = options.max_decompressed_certificate_len,
            .server_verifier = options.server_verifier,
            .client_identity = options.client_identity,
            .request_resumption = options.request_tls13_session_ticket or
                options.tls13_ticket_resumption != null,
            .resumption = tls13_resumption,
        };
        const tls12_config = vail.tls.tls12_client_connection.Config{
            .allocator = allocator,
            .random = client_random,
            .server_name = options.server_name,
            .client_private_key_x25519 = &tls12_key_x25519,
            .client_private_key = &tls12_key,
            .client_private_key_p384 = if (tls12_key_p384) |*key| key else null,
            .client_private_key_p521 = if (tls12_key_p521) |*key| key else null,
            .policy = .{
                .cipher_suites = options.tls12_cipher_suites,
                .groups = tls12_groups,
                .alpn_protocols = options.alpn_protocols,
            },
            .tls13_cipher_suites = if (options.protocol_policy.offersTls13())
                options.cipher_suites
            else
                &.{},
            .client_hello_key_share = if (options.protocol_policy.offersTls13())
                .{
                    .group = tls13_key.namedGroup(),
                    .key_exchange = tls13_public,
                }
            else
                null,
            .client_hello_supported_groups = tls12_groups,
            .supported_versions = if (options.protocol_policy.offersTls13())
                &.{ 0x0304, 0x0303 }
            else
                &.{0x0303},
            .server_verifier = options.server_verifier,
            .client_identity = options.client_identity,
            .request_ocsp = options.request_ocsp,
            .request_session_ticket = options.request_tls12_session_ticket or
                options.tls12_ticket_resumption != null,
            .ticket_resumption = options.tls12_ticket_resumption,
            .now_seconds = now_seconds,
        };

        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(allocator);
        var established: AutoClient.Established = undefined;
        if (options.protocol_policy == .tls13_only) {
            const engine = try allocator.create(Tls13Client);
            defer allocator.destroy(engine);
            defer std.crypto.secureZero(u8, std.mem.asBytes(engine));
            tls13_keys_owned = false;
            try engine.initInto(tls13_config, &output);
            defer engine.deinit();
            try record_io.writeAll(io, stream, output.items);
            output.clearRetainingCapacity();
            established = .{ .tls13 = try driveTls13(
                engine,
                io,
                stream,
                &output,
                options.max_server_handshake_size,
                deadline,
            ) };
        } else if (options.protocol_policy == .tls12_only) {
            const engine = try allocator.create(Tls12Client);
            defer allocator.destroy(engine);
            defer std.crypto.secureZero(u8, std.mem.asBytes(engine));
            try engine.initInto(tls12_config, &output);
            defer engine.deinit();
            try record_io.writeAll(io, stream, output.items);
            output.clearRetainingCapacity();
            established = .{ .tls12 = try driveTls12(
                engine,
                allocator,
                io,
                stream,
                &output,
                options.max_server_handshake_size,
                deadline,
            ) };
        } else {
            const engine = try allocator.create(AutoClient);
            defer allocator.destroy(engine);
            defer std.crypto.secureZero(u8, std.mem.asBytes(engine));
            tls13_keys_owned = false;
            try engine.initInto(.{
                .tls13 = tls13_config,
                .tls12 = tls12_config,
            }, &output);
            defer engine.deinit();
            try record_io.writeAll(io, stream, output.items);
            output.clearRetainingCapacity();
            established = try driveAuto(
                engine,
                io,
                stream,
                &output,
                options.max_server_handshake_size,
                deadline,
            );
        }
        errdefer established.deinit();
        return fromEstablished(
            allocator,
            io,
            stream,
            options.server_name,
            now_seconds,
            options.request_tls13_session_ticket or
                options.tls13_ticket_resumption != null,
            &established,
        );
    }

    pub fn initVerified(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: VerifiedOptions,
    ) Error!*Connection {
        return initVerifiedBefore(allocator, io, stream, options, null);
    }

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
        var platform_verifier: ?vail.x509.platform.Verifier = null;
        defer if (platform_verifier) |*verifier| verifier.deinit();
        var caller_bundle_locked = false;
        defer if (caller_bundle_locked) options.ca_bundle.?.lock.unlockShared(io);
        var bundle_verifier: vail.x509.trust.BundleVerifier = undefined;
        const verifier = options.server_verifier orelse blk: {
            const now = std.Io.Timestamp.now(io, .real);
            if (options.ca_bundle) |ca_bundle| {
                try ca_bundle.lock.lockShared(io);
                caller_bundle_locked = true;
                bundle_verifier = .{
                    .bundle = ca_bundle.bundle,
                    .now_seconds = now.toSeconds(),
                };
            } else if (options.system_store) |store| {
                bundle_verifier = store.verifier(now.toSeconds());
            } else if (options.root_source == .bundled) {
                system_store = root_trust.initBundledStore(
                    allocator,
                    now,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.CertificateUntrusted,
                };
                bundle_verifier = system_store.?.verifier(now.toSeconds());
            } else if (options.root_source == .platform) {
                if (options.stapled_ocsp != .ignore) {
                    return error.ConflictingOcspVerifier;
                }
                platform_verifier = vail.x509.platform.Verifier.init(
                    allocator,
                    .{ .verify_host = options.verify_host },
                ) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    if (err == error.PlatformVerifierUnavailable) {
                        return error.PlatformVerifierUnavailable;
                    }
                    return error.CertificateUntrusted;
                };
                break :blk vail.tls.auth.ClientVerifier.fromTrustVerifier(
                    platform_verifier.?.clientVerifier(),
                );
            } else {
                system_store = if (options.system_environ) |environ|
                    try .initWithEnviron(allocator, io, now, environ)
                else
                    try .init(allocator, io, now);
                bundle_verifier = system_store.?.verifier(now.toSeconds());
            }
            bundle_verifier.stapled_ocsp = options.stapled_ocsp;
            break :blk vail.tls.auth.ClientVerifier.fromTrustVerifier(
                if (options.verify_host)
                    bundle_verifier.clientVerifier()
                else
                    bundle_verifier.serverChainVerifier(),
            );
        };
        const mapped = Options{
            .server_name = options.server_name,
            .server_verifier = verifier,
            .client_identity = options.client_identity,
            .alpn_protocols = options.alpn_protocols,
            .cipher_suites = options.cipher_suites,
            .tls12_cipher_suites = options.tls12_cipher_suites,
            .protocol_policy = options.protocol_policy,
            .request_tls12_session_ticket = options.request_tls12_session_ticket,
            .tls12_ticket_resumption = options.tls12_ticket_resumption,
            .request_tls13_session_ticket = options.request_tls13_session_ticket,
            .tls13_ticket_resumption = options.tls13_ticket_resumption,
            .request_ocsp = options.request_ocsp,
            .certificate_compression_algorithms = options.certificate_compression_algorithms,
            .max_decompressed_certificate_len = options.max_decompressed_certificate_len,
            .max_server_handshake_size = options.max_server_handshake_size,
            .handshake_timeout = options.handshake_timeout,
        };
        return if (outer_deadline) |deadline|
            initWithDeadline(allocator, io, stream, mapped, deadline)
        else
            init(allocator, io, stream, mapped);
    }

    /// Release a terminal transport without writing further TLS records.
    pub fn deinitWithoutCloseNotify(self: *Connection) void {
        switch (self.records) {
            inline else => |*records| records.failed = true,
        }
        self.deinit();
    }

    pub fn deinit(self: *Connection) void {
        if (self.shouldSendCloseNotify()) {
            self.sendCloseNotify() catch {};
        }
        switch (self.records) {
            inline else => |*records| records.deinit(),
        }
        self.stream.close(self.io);
        const allocator = self.allocator;
        if (self.selected_alpn) |protocol| allocator.free(protocol);
        for (self.peer_certificate_chain) |certificate| {
            allocator.free(certificate);
        }
        allocator.free(self.peer_certificate_chain);
        if (self.tls12_session_ticket) |*ticket| ticket.deinit();
        if (self.tls13_session_ticket) |*ticket| ticket.deinit();
        if (self.tls13_ticket_context) |*context| {
            context.deinit(allocator);
        }
        switch (self.exporter) {
            .tls13 => |*secret| secret.deinit(),
            .tls12 => |*state| {
                std.crypto.secureZero(u8, &state.master_secret);
                std.crypto.secureZero(u8, &state.client_random);
                std.crypto.secureZero(u8, &state.server_random);
            },
        }
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn negotiatedProtocol(self: *const Connection) version.Protocol {
        return self.protocol;
    }

    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        return self.selected_alpn;
    }

    pub fn peerCertificates(self: *const Connection) []const []const u8 {
        return self.peer_certificate_chain;
    }

    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) version.NegotiatedCipherSuite {
        return self.cipher_suite;
    }

    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) vail.tls.secret.Hash {
        return self.transcript_hash;
    }

    pub fn wasResumed(self: *const Connection) bool {
        return self.resumed;
    }

    /// Transfer the newest authenticated RFC 5077 ticket to the caller.
    /// Returns null for TLS 1.3 or when the TLS 1.2 server issued no ticket.
    pub fn takeTls12SessionTicket(
        self: *Connection,
    ) ?vail.tls.tls12_ticket.Cached {
        const ticket = self.tls12_session_ticket;
        self.tls12_session_ticket = null;
        return ticket;
    }

    /// Transfer the newest authenticated RFC 8446 ticket observed while
    /// reading application traffic. The caller owns the returned cache entry.
    pub fn takeTls13SessionTicket(
        self: *Connection,
    ) Error!?vail.tls.ticket.Cached {
        try self.captureTls13SessionTicket();
        const ticket = self.tls13_session_ticket;
        self.tls13_session_ticket = null;
        return ticket;
    }

    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        return switch (self.exporter) {
            .tls13 => |secret| vail.tls.key_schedule.exportKeyingMaterialFor(
                secret,
                label,
                context,
                out,
            ),
            .tls12 => |state| vail.tls.tls12.exportKeyingMaterial(
                state.suite,
                &state.master_secret,
                state.client_random,
                state.server_random,
                label,
                context,
                out,
            ),
        };
    }

    pub fn updateTrafficKeys(self: *Connection, request_peer_update: bool) Error!void {
        return switch (self.records) {
            .tls13 => |*records| records.updateTrafficKeys(
                self.io,
                self.stream,
                request_peer_update,
            ),
            .tls12 => error.TlsKeyUpdateUnavailable,
        };
    }

    pub fn keyUpdateCounts(self: *const Connection) @import("record_stream.zig").KeyUpdateCounts {
        return switch (self.records) {
            .tls13 => |*records| records.keyUpdateCounts(),
            .tls12 => .{
                .sent = 0,
                .received = 0,
                .awaiting_peer_response = false,
            },
        };
    }

    pub fn sendCloseNotify(self: *Connection) Error!void {
        return switch (self.records) {
            inline else => |*records| records.sendCloseNotify(
                self.io,
                self.stream,
            ),
        };
    }

    pub fn sendCloseNotifyWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!void {
        return switch (self.records) {
            inline else => |*records| records.sendCloseNotifyWithDeadline(self.io, self.stream, deadline),
        };
    }

    pub fn receivedCloseNotify(self: *const Connection) bool {
        return switch (self.records) {
            inline else => |*records| records.receivedCloseNotify(),
        };
    }

    pub fn isReusableBoundary(self: *const Connection) bool {
        return switch (self.records) {
            inline else => |*records| records.isReusableBoundary(),
        };
    }

    pub fn read(self: *Connection, out: []u8) Error!usize {
        const result = switch (self.records) {
            inline else => |*records| records.read(self.io, self.stream, out),
        };
        return self.finishRead(result);
    }

    pub fn readWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        const result = switch (self.records) {
            inline else => |*records| records.readWithDeadline(
                self.io,
                self.stream,
                out,
                deadline,
            ),
        };
        return self.finishRead(result);
    }

    fn finishRead(self: *Connection, result: Error!usize) Error!usize {
        const count = result catch |err| {
            try self.captureTls13SessionTicket();
            return err;
        };
        try self.captureTls13SessionTicket();
        return count;
    }

    fn captureTls13SessionTicket(self: *Connection) Error!void {
        const context = if (self.tls13_ticket_context) |*value|
            value
        else
            return;
        var message = switch (self.records) {
            .tls13 => |*records| records.takeNewSessionTicketMessage() orelse
                return,
            .tls12 => return,
        };
        defer message.deinit(self.allocator);
        var ticket = vail.tls.ticket.cache(
            self.allocator,
            message.items,
            switch (self.records) {
                .tls13 => |*records| records.read_keys.suite,
                .tls12 => unreachable,
            },
            context.master_secret,
            context.transcript_after_client_finished,
            context.server_name,
            self.selected_alpn orelse "",
            @intCast(@max(
                0,
                std.Io.Timestamp.now(self.io, .real).toMilliseconds(),
            )),
        ) catch |err| switch (err) {
            error.OutOfMemory,
            error.TicketDiscarded,
            => return,
            else => {
                self.records.tls13.failed = true;
                return err;
            },
        };
        errdefer ticket.deinit();
        if (self.tls13_session_ticket) |*cached| cached.deinit();
        self.tls13_session_ticket = ticket;
    }

    pub fn writeAll(self: *Connection, bytes: []const u8) Error!void {
        return switch (self.records) {
            inline else => |*records| records.writeAll(
                self.io,
                self.stream,
                bytes,
            ),
        };
    }

    pub fn writeAllWithDeadline(
        self: *Connection,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return switch (self.records) {
            inline else => |*records| records.writeAllWithDeadline(
                self.io,
                self.stream,
                bytes,
                committed,
                deadline,
            ),
        };
    }

    pub fn finishPendingWrite(self: *Connection, committed: *usize) Error!void {
        return switch (self.records) {
            inline else => |*records| records.finishPendingWrite(
                self.io,
                self.stream,
                committed,
            ),
        };
    }

    pub fn writeAllParts(
        self: *Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return switch (self.records) {
            inline else => |*records| records.writeAllParts(
                self.io,
                self.stream,
                first,
                second,
            ),
        };
    }

    pub fn writeAllSlices(
        self: *Connection,
        parts: []const []const u8,
    ) Error!void {
        return switch (self.records) {
            inline else => |*records| records.writeAllSlices(
                self.io,
                self.stream,
                parts,
            ),
        };
    }

    fn shouldSendCloseNotify(self: *const Connection) bool {
        return switch (self.records) {
            inline else => |*records| records.shouldSendCloseNotify(),
        };
    }
};

fn fromEstablished(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    server_identity: []const u8,
    now_seconds: u64,
    retain_tls13_session_tickets: bool,
    established: *AutoClient.Established,
) Error!*Connection {
    const connection = try allocator.create(Connection);
    errdefer allocator.destroy(connection);
    connection.* = switch (established.*) {
        .tls13 => |*value| blk: {
            const resumed = value.resumed;
            const certificate_compression = value.certificate_compression;
            const cipher_suite = value.application.suite;
            const exporter = value.exporter_master_secret;
            // Finish fallible ticket-context allocation before detaching any
            // handshake-owned buffers or secrets. The caller can then deinit
            // the intact Established result on every conversion failure.
            var ticket_context: ?Connection.Tls13TicketContext =
                if (retain_tls13_session_tickets) .{
                    .master_secret = value.master_secret,
                    .transcript_after_client_finished = value.transcript_after_client_finished,
                    .server_name = try allocator.dupe(u8, server_identity),
                } else null;
            errdefer if (ticket_context) |*context| {
                context.deinit(allocator);
            };
            const selected_alpn = value.selected_alpn;
            value.selected_alpn = null;
            const peer_certificate_chain = value.peer_certificate_chain;
            value.peer_certificate_chain = &.{};
            var records = record_stream.Stream.init(
                value.application.traffic.read.keys,
                value.application.traffic.write.keys,
                value.application.traffic.read.traffic_secret,
                value.application.traffic.write.traffic_secret,
            );
            records.read_sequence =
                value.application.traffic.read.next_sequence_number;
            records.write_sequence =
                value.application.traffic.write.next_sequence_number;
            value.application.secrets_extracted = true;
            std.crypto.secureZero(
                u8,
                std.mem.asBytes(&value.application.traffic),
            );
            value.application.deinit();
            if (!retain_tls13_session_tickets) value.master_secret.deinit();
            value.exporter_master_secret.deinit();
            if (value.local_application_settings) |settings| {
                allocator.free(settings);
            }
            if (value.peer_application_settings) |settings| {
                allocator.free(settings);
            }
            value.* = undefined;
            if (retain_tls13_session_tickets) {
                records.retainNewSessionTickets(allocator);
            } else {
                records.allowNewSessionTickets();
            }
            break :blk .{
                .allocator = allocator,
                .io = io,
                .stream = stream,
                .records = .{ .tls13 = records },
                .selected_alpn = selected_alpn,
                .peer_certificate_chain = peer_certificate_chain,
                .protocol = .tls13,
                .cipher_suite = .fromTls13(cipher_suite),
                .transcript_hash = cipher_suite.hash(),
                .exporter = .{ .tls13 = exporter },
                .tls13_ticket_context = ticket_context,
                .tls13_session_ticket = null,
                .tls12_session_ticket = null,
                .resumed = resumed,
                .certificate_compression = certificate_compression,
            };
        },
        .tls12 => |*value| blk: {
            const resumed = value.resumed;
            var session_ticket = if (value.session_ticket != null)
                try value.createTicketSession(server_identity, now_seconds)
            else
                null;
            errdefer if (session_ticket) |*ticket| ticket.deinit();
            const selected_alpn = value.selected_alpn;
            value.selected_alpn = null;
            const peer_certificate_chain = value.peer_certificate_chain;
            value.peer_certificate_chain = &.{};
            const suite = value.suite;
            const exporter = Connection.Tls12Exporter{
                .master_secret = value.master_secret,
                .client_random = value.client_random,
                .server_random = value.server_random,
                .suite = suite,
            };
            const records = tls12_record_stream.Stream.init(
                value.read,
                value.write,
            );
            value.secrets_extracted = true;
            std.crypto.secureZero(u8, std.mem.asBytes(&value.read));
            std.crypto.secureZero(u8, std.mem.asBytes(&value.write));
            value.deinit();
            break :blk .{
                .allocator = allocator,
                .io = io,
                .stream = stream,
                .records = .{ .tls12 = records },
                .selected_alpn = selected_alpn,
                .peer_certificate_chain = peer_certificate_chain,
                .protocol = .tls12,
                .cipher_suite = .fromTls12(suite),
                .transcript_hash = version.transcriptHash(suite),
                .exporter = .{ .tls12 = exporter },
                .tls13_ticket_context = null,
                .tls13_session_ticket = null,
                .tls12_session_ticket = session_ticket,
                .resumed = resumed,
                .certificate_compression = null,
            };
        },
    };
    established.* = undefined;
    return connection;
}

test "versioned TLS establishment OOM preserves caller-owned metadata and keys" {
    try @import("testing/established_ownership.zig").failure(fromEstablished, AutoClient.Established);
}

test "versioned TLS establishment transfers metadata keys sequences and ticket policy" {
    try @import("testing/established_ownership.zig").success(fromEstablished, AutoClient.Established);
}

fn cachedAlpnOffered(
    cached: []const u8,
    offered: []const []const u8,
) bool {
    if (cached.len == 0) return offered.len == 0;
    for (offered) |protocol| {
        if (std.mem.eql(u8, cached, protocol)) return true;
    }
    return false;
}

fn driveAuto(
    engine: *AutoClient,
    io: std.Io,
    stream: net.Stream,
    output: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!AutoClient.Established {
    var established: AutoClient.Established = undefined;
    var total: usize = 0;
    var reader: record_io.Reader = .{};
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = try readHandshakeRecord(
            &reader,
            io,
            stream,
            &encoded,
            deadline,
        );
        total = std.math.add(usize, total, record.len) catch
            return error.HandshakeMessageTooLarge;
        if (total > limit) return error.HandshakeMessageTooLarge;
        var input = record;
        while (true) {
            const result = try engine.receiveInto(input, output, &established);
            if (result.consumed > input.len) return error.ConnectionFailed;
            input = input[result.consumed..];
            if (output.items.len != 0) {
                try record_io.writeAll(io, stream, output.items);
                output.clearRetainingCapacity();
            }
            if (result.event) |event| switch (event) {
                .tls13 => |nested| switch (nested) {
                    .peer_alert => return error.PeerAbortedHandshake,
                    .ech_rejected => return error.PeerAbortedHandshake,
                    .established => return established,
                    else => {},
                },
                .tls12 => |nested| switch (nested) {
                    .peer_alert => return error.PeerAbortedHandshake,
                    .established => return established,
                    else => {},
                },
            };
            if (input.len == 0 and result.event == null) break;
            if (input.len == 0 and result.consumed == 0) break;
        }
    }
}

fn driveTls13(
    engine: *Tls13Client,
    io: std.Io,
    stream: net.Stream,
    output: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Tls13Client.Established {
    var established: Tls13Client.Established = undefined;
    var total: usize = 0;
    var reader: record_io.Reader = .{};
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = try readHandshakeRecord(
            &reader,
            io,
            stream,
            &encoded,
            deadline,
        );
        total = std.math.add(usize, total, record.len) catch
            return error.HandshakeMessageTooLarge;
        if (total > limit) return error.HandshakeMessageTooLarge;
        var input = record;
        while (true) {
            const result = try engine.receiveInto(input, output, &established);
            if (result.consumed > input.len) return error.ConnectionFailed;
            input = input[result.consumed..];
            if (output.items.len != 0) {
                try record_io.writeAll(io, stream, output.items);
                output.clearRetainingCapacity();
            }
            if (result.event) |event| switch (event) {
                .peer_alert, .ech_rejected => return error.PeerAbortedHandshake,
                .established => return established,
                else => {},
            };
            if (input.len == 0 and result.event == null) break;
            if (input.len == 0 and result.consumed == 0) break;
        }
    }
}

fn driveTls12(
    engine: *Tls12Client,
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    output: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!vail.tls.tls12_client_connection.Established {
    _ = allocator;
    var established: vail.tls.tls12_client_connection.Established = undefined;
    var total: usize = 0;
    var reader: record_io.Reader = .{};
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = try readHandshakeRecord(
            &reader,
            io,
            stream,
            &encoded,
            deadline,
        );
        total = std.math.add(usize, total, record.len) catch
            return error.HandshakeMessageTooLarge;
        if (total > limit) return error.HandshakeMessageTooLarge;
        var input = record;
        while (true) {
            const result = try engine.receiveInto(input, output, &established);
            if (result.consumed > input.len) return error.ConnectionFailed;
            input = input[result.consumed..];
            if (output.items.len != 0) {
                try record_io.writeAll(io, stream, output.items);
                output.clearRetainingCapacity();
            }
            if (result.event) |event| switch (event) {
                .peer_alert => return error.PeerAbortedHandshake,
                .established => return established,
                else => {},
            };
            if (input.len == 0 and result.event == null) break;
            if (input.len == 0 and result.consumed == 0) break;
        }
    }
}

fn readHandshakeRecord(
    reader: *record_io.Reader,
    io: std.Io,
    stream: net.Stream,
    encoded: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) record_io.Error![]u8 {
    return if (deadline) |absolute|
        reader.readWithDeadline(io, stream, encoded, absolute)
    else
        reader.read(io, stream, encoded);
}

fn validateVerifiedOptions(options: VerifiedOptions) Error!void {
    if (options.stapled_ocsp != .ignore and !options.request_ocsp) {
        return error.OcspPolicyRequiresRequest;
    }
    if (options.server_verifier != null and options.stapled_ocsp != .ignore) {
        return error.ConflictingOcspVerifier;
    }
    vail.tls.certificate_compression.validateAlgorithms(
        options.certificate_compression_algorithms,
    ) catch return error.InvalidProtocolPolicy;
    if (options.max_decompressed_certificate_len == 0) {
        return error.InvalidProtocolPolicy;
    }
}

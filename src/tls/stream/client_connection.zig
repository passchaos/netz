//! Blocking vail-backed TLS 1.3 client connection.
//!
//! This transport exists alongside Zig's standard TLS client because Zig 0.16
//! cannot send a client identity. Application protocols can opt into it while
//! retaining the mature standard-library path for ordinary verified clients.

const std = @import("std");
const vail = @import("vail");
const record_io = @import("record_io.zig");
const record_stream = @import("record_stream.zig");

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
    };

pub const Options = struct {
    server_name: []const u8,
    server_verifier: vail.tls.auth.ClientVerifier,
    client_identity: vail.tls.client_auth.ClientIdentity,
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_server_handshake_size: usize = 256 * 1024,
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
    client_identity: vail.tls.client_auth.ClientIdentity,
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_server_handshake_size: usize = 256 * 1024,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    records: record_stream.Stream,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: Options,
    ) Error!*Connection {
        try options.client_identity.validate();

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

        const connection = try allocator.create(Connection);
        connection.* = .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .records = .init(read_keys, write_keys),
        };
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
            break :blk bundle_verifier.clientVerifier();
        };

        return init(allocator, io, stream, .{
            .server_name = options.server_name,
            .server_verifier = verifier,
            .client_identity = options.client_identity,
            .cipher_suites = options.cipher_suites,
            .max_server_handshake_size = options.max_server_handshake_size,
        });
    }

    pub fn deinit(self: *Connection) void {
        if (!self.records.closed) {
            self.records.sendCloseNotify(self.io, self.stream) catch {};
        }
        self.records.deinit();
        self.stream.close(self.io);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn read(self: *Connection, out: []u8) Error!usize {
        return self.records.read(self.io, self.stream, out);
    }

    pub fn writeAll(
        self: *Connection,
        bytes: []const u8,
    ) Error!void {
        return self.records.writeAll(self.io, self.stream, bytes);
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
};

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
    try record_io.writeAll(io, stream, &header);
    try record_io.writeAll(io, stream, message);
}

fn readCleartextHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    message: *std.ArrayList(u8),
    limit: usize,
) Error!void {
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = try record_io.readRecord(io, stream, &encoded);
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
) Error!void {
    var encoded: [record_io.max_record_len]u8 = undefined;
    var sequence: u64 = 0;
    while (true) {
        const record = try record_io.readRecord(io, stream, &encoded);
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

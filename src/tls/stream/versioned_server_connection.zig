//! Blocking vail-backed TLS 1.2/TLS 1.3 server connection.

const std = @import("std");
const vail = @import("vail");
const handshake_deadline = @import("handshake_deadline.zig");
const record_io = @import("record_io.zig");
const record_stream = @import("record_stream.zig");
const server_handshake = @import("server_handshake.zig");
const tls12_record_stream = @import("tls12_record_stream.zig");
const version = @import("version.zig");

const net = std.Io.net;
const max_handshake_size: usize = 256 * 1024;
const max_post_handshake_size: usize = 64 * 1024;
const AutoServer = vail.tls.versioned_server_connection.ServerConnection(
    max_handshake_size,
    max_post_handshake_size,
);

pub const Error = std.mem.Allocator.Error ||
    std.Io.RandomSecureError ||
    record_io.Error ||
    server_handshake.Error ||
    vail.tls.versioned_server_connection.Error ||
    record_stream.Error ||
    tls12_record_stream.Error ||
    error{
        HandshakeMessageTooLarge,
        InvalidAlpn,
        InvalidProtocolPolicy,
        PeerAbortedHandshake,
        TlsKeyUpdateUnavailable,
    };

pub const Options = struct {
    identity: vail.tls.auth.ServerIdentity,
    identity_provider: ?server_handshake.ServerIdentityProvider = null,
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const vail.tls.tls12.Suite =
        &version.default_tls12_cipher_suites,
    protocol_policy: version.Policy = .tls12_and_tls13,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = max_handshake_size,
    handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    alpn_protocols: []const []const u8 = &.{},
    require_alpn: bool = true,

    pub fn acquireIdentity(self: Options) Error!server_handshake.ServerIdentityLease {
        var lease = if (self.identity_provider) |provider|
            provider.acquire()
        else
            server_handshake.ServerIdentityLease{ .identity = self.identity };
        errdefer lease.deinit();
        try lease.identity.validate();
        return lease;
    }

    pub fn validateIdentity(self: Options) Error!void {
        var lease = try self.acquireIdentity();
        defer lease.deinit();
    }
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

    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    records: Records,
    selected_alpn: ?[]u8 = null,
    peer_certificate_chain: ?[][]const u8,
    protocol: version.Protocol,
    cipher_suite: version.NegotiatedCipherSuite,
    transcript_hash: vail.tls.secret.Hash,
    exporter: Exporter,

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
        if ((!options.protocol_policy.offersTls12() and
            !options.protocol_policy.offersTls13()) or
            (options.protocol_policy.offersTls12() and
                options.tls12_cipher_suites.len == 0) or
            (options.protocol_policy.offersTls13() and
                options.cipher_suites.len == 0))
        {
            return error.InvalidProtocolPolicy;
        }
        if (options.max_client_hello_size == 0 or
            options.max_client_hello_size > max_handshake_size or
            options.max_client_handshake_size == 0 or
            options.max_client_handshake_size > max_handshake_size)
        {
            return error.HandshakeMessageTooLarge;
        }
        var identity_lease = try options.acquireIdentity();
        defer identity_lease.deinit();
        const identity = identity_lease.identity;
        const client_auth = identity_lease.client_auth orelse options.client_auth;

        var client_hello: std.ArrayList(u8) = .empty;
        defer client_hello.deinit(allocator);
        try readClientHello(
            allocator,
            io,
            stream,
            &client_hello,
            options.max_client_hello_size,
            deadline,
        );
        const parsed = try vail.tls.client_hello.parse(client_hello.items);
        const selected_alpn = try vail.tls.tls12_handshake.selectAlpn(
            parsed.alpn_protocols,
            options.alpn_protocols,
        );
        if ((options.require_alpn or parsed.alpn_protocols.len != 0) and
            options.alpn_protocols.len != 0 and selected_alpn == null)
        {
            return error.InvalidAlpn;
        }

        const client_offered_x25519 =
            (try parsed.keyShareForGroup(
                vail.tls.key_exchange.named_group_x25519,
            )) != null;
        const client_offered_p256 =
            (try parsed.keyShareForGroup(
                vail.tls.key_exchange.named_group_secp256r1,
            )) != null;
        var tls13_key: vail.tls.key_exchange.ServerKeyMaterial =
            if (client_offered_x25519 or !client_offered_p256)
                .{ .x25519 = try randomX25519(io) }
            else
                .{ .secp256r1 = try randomP256(io) };
        const tls13_groups = [_]u16{tls13_key.namedGroup()};
        var tls13_key_owned = true;
        defer if (tls13_key_owned) tls13_key.wipe();
        var tls12_key = try randomP256(io);
        defer std.crypto.secureZero(u8, &tls12_key);
        var tls13_random: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &tls13_random);
        try std.Io.randomSecure(io, &tls13_random);
        var tls12_random: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &tls12_random);
        try std.Io.randomSecure(io, &tls12_random);
        var signer = try freshSigner(io, identity.signer);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&signer));

        const engine = try allocator.create(AutoServer);
        defer allocator.destroy(engine);
        defer std.crypto.secureZero(u8, std.mem.asBytes(engine));
        engine.initInto(.{
            .tls13 = .{
                .allocator = allocator,
                .policy = .{
                    .cipher_suites = options.cipher_suites,
                    .groups = &tls13_groups,
                    .alpn_protocols = options.alpn_protocols,
                },
                .server_random = tls13_random,
                .key_material = &tls13_key,
                .certificate_chain = identity.certificate_chain,
                .signer = signer,
                .server_certificate_type = identity.certificate_type,
                .client_auth = if (client_auth) |policy| .{
                    .certificate_authorities = policy.certificate_authorities,
                } else null,
                .client_auth_policy = client_auth,
            },
            .tls12 = .{
                .allocator = allocator,
                .policy = .{
                    .cipher_suites = options.tls12_cipher_suites,
                    .groups = &version.default_tls12_groups,
                    .alpn_protocols = options.alpn_protocols,
                    .client_certificate_authorities = if (client_auth) |policy|
                        policy.certificate_authorities
                    else
                        null,
                },
                .server_random = tls12_random,
                .server_private_key = &tls12_key,
                .certificate_chain = identity.certificate_chain,
                .signer = signer,
                .client_auth_policy = client_auth,
            },
            .enable_tls13 = options.protocol_policy.offersTls13(),
            .enable_tls12 = options.protocol_policy.offersTls12(),
        });
        tls13_key_owned = false;
        defer engine.deinit();

        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(allocator);
        var established: AutoServer.Established = undefined;
        try feedClientHello(
            engine,
            client_hello.items,
            &output,
            &established,
        );
        if (output.items.len != 0) {
            try record_io.writeAll(io, stream, output.items);
            output.clearRetainingCapacity();
        }
        established = try finishHandshake(
            engine,
            io,
            stream,
            &output,
            options.max_client_handshake_size,
            deadline,
        );
        errdefer established.deinit();
        return fromEstablished(
            allocator,
            io,
            stream,
            selected_alpn,
            &established,
        );
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
        if (self.peer_certificate_chain) |chain| {
            for (chain) |certificate| allocator.free(@constCast(certificate));
            allocator.free(chain);
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

    pub fn peerCertificates(self: *const Connection) ?[]const []const u8 {
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

    pub fn receivedCloseNotify(self: *const Connection) bool {
        return switch (self.records) {
            inline else => |*records| records.receivedCloseNotify(),
        };
    }

    pub fn read(self: *Connection, out: []u8) Error!usize {
        return switch (self.records) {
            inline else => |*records| records.read(self.io, self.stream, out),
        };
    }

    pub fn readWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return switch (self.records) {
            inline else => |*records| records.readWithDeadline(
                self.io,
                self.stream,
                out,
                deadline,
            ),
        };
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
    selected_alpn: ?[]const u8,
    established: *AutoServer.Established,
) Error!*Connection {
    const owned_alpn = if (selected_alpn) |protocol|
        try allocator.dupe(u8, protocol)
    else
        null;
    errdefer if (owned_alpn) |protocol| allocator.free(protocol);
    const connection = try allocator.create(Connection);
    connection.* = switch (established.*) {
        .tls13 => |*value| blk: {
            const peer_certificate_chain = value.peer_certificate_chain;
            value.peer_certificate_chain = null;
            const cipher_suite = value.application.suite;
            const exporter = value.exporter_master_secret;
            const records = record_stream.Stream.init(
                value.application.traffic.read.keys,
                value.application.traffic.write.keys,
                value.application.traffic.read.traffic_secret,
                value.application.traffic.write.traffic_secret,
            );
            value.application.secrets_extracted = true;
            std.crypto.secureZero(
                u8,
                std.mem.asBytes(&value.application.traffic),
            );
            value.application.deinit();
            value.master_secret.deinit();
            value.exporter_master_secret.deinit();
            if (value.local_application_settings) |settings| {
                allocator.free(settings);
            }
            if (value.peer_application_settings) |settings| {
                allocator.free(settings);
            }
            value.* = undefined;
            break :blk .{
                .allocator = allocator,
                .io = io,
                .stream = stream,
                .records = .{ .tls13 = records },
                .selected_alpn = owned_alpn,
                .peer_certificate_chain = if (peer_certificate_chain) |chain|
                    @ptrCast(chain)
                else
                    null,
                .protocol = .tls13,
                .cipher_suite = .fromTls13(cipher_suite),
                .transcript_hash = cipher_suite.hash(),
                .exporter = .{ .tls13 = exporter },
            };
        },
        .tls12 => |*value| blk: {
            const peer_certificate_chain = value.peer_certificate_chain;
            value.peer_certificate_chain = null;
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
                .selected_alpn = owned_alpn,
                .peer_certificate_chain = peer_certificate_chain,
                .protocol = .tls12,
                .cipher_suite = .fromTls12(suite),
                .transcript_hash = version.transcriptHash(suite),
                .exporter = .{ .tls12 = exporter },
            };
        },
    };
    established.* = undefined;
    return connection;
}

fn readClientHello(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    message: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var reader: record_io.Reader = .{};
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = if (deadline) |absolute|
            try reader.readWithDeadline(io, stream, &encoded, absolute)
        else
            try reader.read(io, stream, &encoded);
        if (record[0] != vail.tls.record.content_type_handshake) {
            return error.UnexpectedRecord;
        }
        const fragment = record[vail.tls.record.header_len..];
        const next = std.math.add(usize, message.items.len, fragment.len) catch
            return error.HandshakeMessageTooLarge;
        if (next > limit) return error.HandshakeMessageTooLarge;
        try message.appendSlice(allocator, fragment);
        if (message.items.len < 4) continue;
        const body_len = (@as(usize, message.items[1]) << 16) |
            (@as(usize, message.items[2]) << 8) | message.items[3];
        const total_len = std.math.add(usize, 4, body_len) catch
            return error.HandshakeMessageTooLarge;
        if (total_len > limit) return error.HandshakeMessageTooLarge;
        if (message.items.len < total_len) continue;
        if (message.items.len != total_len) return error.UnexpectedHandshakeMessage;
        return;
    }
}

fn feedClientHello(
    engine: *AutoServer,
    message: []const u8,
    output: *std.ArrayList(u8),
    established: *AutoServer.Established,
) Error!void {
    var offset: usize = 0;
    var encoded: [vail.tls.record.header_len + vail.tls.record.max_plaintext_len]u8 = undefined;
    while (offset < message.len) {
        const count = @min(vail.tls.record.max_plaintext_len, message.len - offset);
        encoded[0..5].* = .{
            vail.tls.record.content_type_handshake,
            3,
            1,
            @truncate(count >> 8),
            @truncate(count),
        };
        @memcpy(encoded[5..][0..count], message[offset..][0..count]);
        const result = try engine.receiveInto(
            encoded[0 .. 5 + count],
            output,
            established,
        );
        if (result.consumed != 5 + count) return error.ConnectionFailed;
        if (result.event) |event| switch (event) {
            .tls13 => |nested| switch (nested) {
                .peer_alert => return error.PeerAbortedHandshake,
                .established => return error.ConnectionFailed,
                else => {},
            },
            .tls12 => |nested| switch (nested) {
                .peer_alert => return error.PeerAbortedHandshake,
                .established => return error.ConnectionFailed,
                else => {},
            },
        };
        offset += count;
    }
}

fn finishHandshake(
    engine: *AutoServer,
    io: std.Io,
    stream: net.Stream,
    output: *std.ArrayList(u8),
    limit: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!AutoServer.Established {
    var established: AutoServer.Established = undefined;
    var total: usize = 0;
    var reader: record_io.Reader = .{};
    var encoded: [record_io.max_record_len]u8 = undefined;
    while (true) {
        const record = if (deadline) |absolute|
            try reader.readWithDeadline(io, stream, &encoded, absolute)
        else
            try reader.read(io, stream, &encoded);
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

fn randomP256(io: std.Io) (std.Io.RandomSecureError || error{InvalidSecretKey})![vail.tls.key_exchange.p256.secret_len]u8 {
    var secret: [vail.tls.key_exchange.p256.secret_len]u8 = undefined;
    var attempts: usize = 0;
    while (attempts < 16) : (attempts += 1) {
        try std.Io.randomSecure(io, &secret);
        _ = vail.tls.key_exchange.p256.publicKey(secret) catch |err| switch (err) {
            error.InvalidSecretKey => continue,
            else => return error.InvalidSecretKey,
        };
        return secret;
    }
    std.crypto.secureZero(u8, &secret);
    return error.InvalidSecretKey;
}

fn randomX25519(io: std.Io) std.Io.RandomSecureError![vail.tls.key_exchange.secret_len]u8 {
    var secret: [vail.tls.key_exchange.secret_len]u8 = undefined;
    try std.Io.randomSecure(io, &secret);
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    return secret;
}

fn freshSigner(
    io: std.Io,
    configured: vail.tls.auth.Signer,
) Error!vail.tls.auth.Signer {
    var signer = configured;
    switch (signer) {
        .ed25519 => |*value| {
            var noise: [std.crypto.sign.Ed25519.noise_length]u8 = undefined;
            try std.Io.randomSecure(io, &noise);
            value.noise = noise;
        },
        .ecdsa_p256_sha256 => |*value| {
            var noise: [std.crypto.sign.ecdsa.EcdsaP256Sha256.noise_length]u8 = undefined;
            try std.Io.randomSecure(io, &noise);
            value.noise = noise;
        },
        .ecdsa_p384_sha384 => |*value| {
            var noise: [std.crypto.sign.ecdsa.EcdsaP384Sha384.noise_length]u8 = undefined;
            try std.Io.randomSecure(io, &noise);
            value.noise = noise;
        },
        .ecdsa_p521_sha512 => |*value| value.io = io,
        .ecdsa_p521_sha512_prepared => {},
        .sm2sig_sm3 => |*value| try std.Io.randomSecure(io, &value.nonce),
        inline .ml_dsa_44, .ml_dsa_65, .ml_dsa_87 => |*value| {
            var noise = value.noise orelse undefined;
            try std.Io.randomSecure(io, &noise);
            value.noise = noise;
        },
        .rsa_pss => |*value| value.io = io,
        .rsa_pkcs1, .custom => {},
    }
    return signer;
}

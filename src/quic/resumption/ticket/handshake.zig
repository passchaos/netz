//! Integrated post-handshake ticket issuance, caching, and server selection.

const std = @import("std");
const quic = @import("../../mod.zig");
const codec = @import("vail").tls.ticket;
const keyring = @import("vail").tls.ticket_keyring;
const store = @import("store.zig");

pub const Error = codec.Error || store.Error || quic.resumption.cache.Error ||
    keyring.Error || quic.one_rtt.Error || std.Io.RandomSecureError || error{
    InvalidNewSessionTicket,
    MissingTicketBackend,
};

pub const ClientConfig = struct {
    cache: *quic.resumption.Cache,
    server_id: []const u8,
    now_ms: u64,
};

pub const ServerConfig = struct {
    store: ?*store.Store = null,
    stateless: ?StatelessIssue = null,
    now_ms: u64,
    lifetime_seconds: u32 = 24 * 60 * 60,
    allow_early_data: bool = true,
    nonce: ?[16]u8 = null,
    identity: ?[32]u8 = null,
    age_add: ?u32 = null,
};

pub const StatelessIssue = struct {
    keyring: *const keyring.Keyring,
    server_id: []const u8,
    alpn: []const u8,
    nonce: ?[keyring.nonce_len]u8 = null,
};

pub const ClientAutoResume = struct {
    cache: *quic.resumption.Cache,
    server_id: []const u8,
    now_ms: u64,
};

pub const ServerAutoResume = struct {
    allocator: std.mem.Allocator,
    store: ?*store.Store = null,
    stateless: ?StatelessResume = null,
    now_ms: u64,
    age_tolerance_ms: u32 = 10_000,
};

pub const StatelessResume = struct {
    keyring: *const keyring.Keyring,
    server_id: []const u8,
    alpn: []const u8,
};

pub const Issued = struct {
    nonce: [16]u8,
    identity: [keyring.sealed_len]u8,
    identity_len: usize,
    age_add: u32,
    psk: [32]u8,
    cipher_suite: quic.tls.cipher_suite.Suite,
};

pub fn issue(
    connection: *quic.one_rtt.Connection,
    io: std.Io,
    config: ServerConfig,
    resumption_master_secret: [32]u8,
    crypto_offset: *u64,
) Error!Issued {
    const cipher_suite = connection.config.send_keys.suite;
    var nonce = config.nonce orelse blk: {
        var value: [16]u8 = undefined;
        try std.Io.randomSecure(io, &value);
        break :blk value;
    };
    var age_add = config.age_add orelse blk: {
        var bytes: [4]u8 = undefined;
        try std.Io.randomSecure(io, &bytes);
        break :blk std.mem.readInt(u32, &bytes, .big);
    };
    // Zero is legal, but regenerating it avoids deterministic-looking wire
    // ages and catches broken entropy providers in tests/integrations.
    if (age_add == 0 and config.age_add == null) age_add = 1;

    const psk = codec.derivePsk(resumption_master_secret, &nonce);
    var identity_storage: [keyring.sealed_len]u8 = undefined;
    const identity: []const u8 = if (config.stateless) |stateless| blk: {
        const seal_nonce = stateless.nonce orelse random: {
            var value: [keyring.nonce_len]u8 = undefined;
            try std.Io.randomSecure(io, &value);
            break :random value;
        };
        const sealed = try stateless.keyring.seal(
            seal_nonce,
            stateless.server_id,
            stateless.alpn,
            .{
                .secret = psk,
                .age_add = age_add,
                .issued_at_ms = config.now_ms,
                .lifetime_seconds = config.lifetime_seconds,
                .cipher_suite = cipher_suite,
            },
        );
        @memcpy(&identity_storage, &sealed);
        break :blk &identity_storage;
    } else blk: {
        const stateful = config.identity orelse random: {
            var value: [32]u8 = undefined;
            try std.Io.randomSecure(io, &value);
            break :random value;
        };
        @memcpy(identity_storage[0..stateful.len], &stateful);
        break :blk identity_storage[0..stateful.len];
    };

    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(connection.endpoint.allocator);
    try codec.write(&message, connection.endpoint.allocator, .{
        .lifetime_seconds = config.lifetime_seconds,
        .age_add = age_add,
        .nonce = &nonce,
        .ticket = identity,
        .allow_early_data = config.allow_early_data,
    });
    if (config.store) |server_store| {
        try server_store.issue(.{
            .identity = identity,
            .secret = psk,
            .age_add = age_add,
            .cipher_suite = cipher_suite,
            .issued_at_ms = config.now_ms,
            .lifetime_seconds = config.lifetime_seconds,
        });
    } else if (config.stateless == null) {
        return error.MissingTicketBackend;
    }
    try connection.sendPostHandshakeCrypto(crypto_offset, message.items);
    return .{
        .nonce = nonce,
        .identity = identity_storage,
        .identity_len = identity.len,
        .age_add = age_add,
        .psk = psk,
        .cipher_suite = cipher_suite,
    };
}

pub fn receiveAndCache(
    connection: *quic.one_rtt.Connection,
    config: ClientConfig,
    resumption_master_secret: [32]u8,
    alpn: []const u8,
    peer_transport_parameters: quic.resumption.Snapshot,
    expected_crypto_offset: *u64,
) Error!void {
    var packet = try connection.receivePacket();
    defer packet.deinit(connection.endpoint.allocator);

    var found: ?quic.CryptoFrame = null;
    for (packet.frames) |frame| {
        if (frame != .crypto) continue;
        if (found != null) return error.InvalidNewSessionTicket;
        found = frame.crypto;
    }
    const crypto = found orelse return error.InvalidNewSessionTicket;
    if (crypto.offset != expected_crypto_offset.*) {
        return error.InvalidNewSessionTicket;
    }
    const parsed = try codec.parse(crypto.data);
    const psk = codec.derivePsk(resumption_master_secret, parsed.nonce);
    try config.cache.store(.{
        .server_id = config.server_id,
        .alpn = alpn,
        .ticket = parsed.ticket,
        .psk = psk,
        .issued_at_ms = config.now_ms,
        .lifetime_seconds = parsed.lifetime_seconds,
        .age_add = parsed.age_add,
        .cipher_suite = connection.config.receive_keys.suite,
        .max_early_data_size = parsed.max_early_data_size,
        .transport_parameters = peer_transport_parameters,
    });
    expected_crypto_offset.* = std.math.add(
        u64,
        expected_crypto_offset.*,
        crypto.data.len,
    ) catch return error.InvalidNewSessionTicket;
}

pub fn acquireFirst(
    config: ClientAutoResume,
    alpns: []const []const u8,
) Error!?quic.resumption.Session {
    for (alpns) |alpn| {
        if (try config.cache.acquire(
            config.server_id,
            alpn,
            config.now_ms,
        )) |session| {
            return session;
        }
    }
    return null;
}

pub fn lookupServer(
    config: ServerAutoResume,
    identity: []const u8,
) Error!?store.Lease {
    if (config.stateless) |stateless| {
        const opened = stateless.keyring.open(
            identity,
            stateless.server_id,
            stateless.alpn,
            config.now_ms,
        ) catch |err| switch (err) {
            error.InvalidTicket,
            error.ExpiredTicket,
            error.UnknownKey,
            error.AuthenticationFailed,
            => return null,
            else => return err,
        };
        const identity_copy = try config.allocator.dupe(u8, identity);
        return .{
            .allocator = config.allocator,
            .identity = identity_copy,
            .secret = opened.secret,
            .age_add = opened.age_add,
            .cipher_suite = opened.cipher_suite,
            .issued_at_ms = opened.issued_at_ms,
            .lifetime_seconds = opened.lifetime_seconds,
        };
    }
    if (config.store) |server_store| {
        return try server_store.lookup(identity, config.now_ms);
    }
    return error.MissingTicketBackend;
}

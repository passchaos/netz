//! Integrated post-handshake ticket issuance, caching, and server selection.

const std = @import("std");
const quic = @import("../../mod.zig");
const codec = @import("codec.zig");
const store = @import("store.zig");

pub const Error = codec.Error || store.Error || quic.resumption.cache.Error ||
    quic.one_rtt.Error || std.Io.RandomSecureError || error{
    InvalidNewSessionTicket,
};

pub const ClientConfig = struct {
    cache: *quic.resumption.Cache,
    server_id: []const u8,
    now_ms: u64,
};

pub const ServerConfig = struct {
    store: *store.Store,
    now_ms: u64,
    lifetime_seconds: u32 = 24 * 60 * 60,
    allow_early_data: bool = true,
    nonce: ?[16]u8 = null,
    identity: ?[32]u8 = null,
    age_add: ?u32 = null,
};

pub const ClientAutoResume = struct {
    cache: *quic.resumption.Cache,
    server_id: []const u8,
    now_ms: u64,
};

pub const ServerAutoResume = struct {
    store: *store.Store,
    now_ms: u64,
    age_tolerance_ms: u32 = 10_000,
};

pub const Issued = struct {
    nonce: [16]u8,
    identity: [32]u8,
    age_add: u32,
    psk: [32]u8,
};

pub fn issue(
    connection: *quic.one_rtt.Connection,
    io: std.Io,
    config: ServerConfig,
    resumption_master_secret: [32]u8,
    crypto_offset: *u64,
) Error!Issued {
    var nonce = config.nonce orelse blk: {
        var value: [16]u8 = undefined;
        try std.Io.randomSecure(io, &value);
        break :blk value;
    };
    var identity = config.identity orelse blk: {
        var value: [32]u8 = undefined;
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

    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(connection.endpoint.allocator);
    try codec.write(&message, connection.endpoint.allocator, .{
        .lifetime_seconds = config.lifetime_seconds,
        .age_add = age_add,
        .nonce = &nonce,
        .ticket = &identity,
        .allow_early_data = config.allow_early_data,
    });
    try config.store.issue(.{
        .identity = &identity,
        .secret = psk,
        .age_add = age_add,
        .issued_at_ms = config.now_ms,
        .lifetime_seconds = config.lifetime_seconds,
    });
    // Store before the socket write so a successfully delivered identity is
    // always selectable. A send failure may leave one unreachable entry, which
    // is bounded and expires naturally.
    try connection.sendPostHandshakeCrypto(crypto_offset, message.items);
    return .{
        .nonce = nonce,
        .identity = identity,
        .age_add = age_add,
        .psk = psk,
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

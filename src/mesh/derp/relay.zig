//! DERP relay server core.
//!
//! The relay is transport agnostic: a WebSocket/HTTP adapter feeds decoded
//! frames in and writes returned frames out. Authorization is default-deny;
//! a peer must be explicitly allowed before `attach` succeeds.

const std = @import("std");
const types = @import("../types.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;

pub const RelayError = error{
    NotAuthorized,
    NotAttached,
    DestinationOffline,
    PeerLimitReached,
    InvalidFrame,
    PacketTooLarge,
    OutOfMemory,
};

pub const Peer = struct {
    key: types.NodeKey,
    capabilities: types.Capabilities = .{},
    preferred: bool = false,
    name_len: u8 = 0,
    name: [types.max_hostname_len]u8 = [_]u8{0} ** types.max_hostname_len,
};

pub const Action = union(enum) {
    none,
    forward: struct {
        to: types.NodeKey,
        frame: Frame,
    },
    reply: Frame,
    peer_present: struct {
        peer: types.NodeKey,
        broadcast: bool,
    },
    peer_gone: struct {
        peer: types.NodeKey,
        reason: u8,
    },
};

pub const Relay = struct {
    allocator: std.mem.Allocator,
    peers: std.AutoHashMap(types.NodeKey, Peer),
    allowed: std.AutoHashMap(types.NodeKey, void),
    server_key: types.NodeKey,
    max_peers: usize,
    require_authorization: bool = true,

    pub fn init(
        allocator: std.mem.Allocator,
        server_key: types.NodeKey,
        max_peers: usize,
    ) Relay {
        return .{
            .allocator = allocator,
            .peers = std.AutoHashMap(types.NodeKey, Peer).init(allocator),
            .allowed = std.AutoHashMap(types.NodeKey, void).init(allocator),
            .server_key = server_key,
            .max_peers = max_peers,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.peers.deinit();
        self.allowed.deinit();
        self.* = undefined;
    }

    pub fn authorize(self: *Relay, key: types.NodeKey) !void {
        try self.allowed.put(key, {});
    }

    pub fn revoke(self: *Relay, key: types.NodeKey) bool {
        const removed = self.allowed.remove(key);
        if (removed) _ = self.detach(key);
        return removed;
    }

    pub fn isAuthorized(self: *const Relay, key: types.NodeKey) bool {
        return !self.require_authorization or self.allowed.contains(key);
    }

    pub fn attach(self: *Relay, key: types.NodeKey) RelayError!Action {
        if (!self.isAuthorized(key)) return error.NotAuthorized;
        if (self.peers.contains(key)) return .{ .none = {} };
        if (self.peers.count() >= self.max_peers) return error.PeerLimitReached;
        try self.peers.put(key, .{ .key = key });
        return .{ .peer_present = .{ .peer = key, .broadcast = true } };
    }

    pub fn detach(self: *Relay, key: types.NodeKey) ?Action {
        const removed = self.peers.remove(key);
        if (!removed) return null;
        return .{ .peer_gone = .{ .peer = key, .reason = 0 } };
    }

    pub fn isAttached(self: *const Relay, key: types.NodeKey) bool {
        return self.peers.contains(key);
    }

    pub fn peerCount(self: *const Relay) usize {
        return self.peers.count();
    }

    pub fn handleFrame(
        self: *Relay,
        from: types.NodeKey,
        frame: Frame,
    ) RelayError!Action {
        const peer = self.peers.getPtr(from) orelse return error.NotAttached;

        return switch (frame) {
            .send_packet => |packet| blk: {
                if (packet.packet.len > frame_mod.max_packet_bytes) {
                    return error.PacketTooLarge;
                }
                if (!self.peers.contains(packet.destination)) {
                    return error.DestinationOffline;
                }
                break :blk .{ .forward = .{
                    .to = packet.destination,
                    .frame = .{ .recv_packet = .{
                        .source = from,
                        .packet = packet.packet,
                    } },
                } };
            },
            .ping => |ping| .{ .reply = .{ .pong = .{ .nonce = ping.nonce } } },
            .pong => .{ .none = {} },
            .keep_alive => .{ .none = {} },
            .note_preferred => |note| blk: {
                peer.preferred = note.preferred;
                break :blk .{ .none = {} };
            },
            .client_info => |info| blk: {
                peer.capabilities = info.capabilities;
                const name_len = @min(info.name.len, types.max_hostname_len);
                peer.name_len = @intCast(name_len);
                @memcpy(peer.name[0..name_len], info.name[0..name_len]);
                break :blk .{ .none = {} };
            },
            .client_deps => .{ .none = {} },
            .server_key,
            .recv_packet,
            .peer_gone,
            .peer_present,
            .health,
            .restarting,
            => error.InvalidFrame,
        };
    }
};

test "relay denies unauthorized peers by default" {
    var relay = Relay.init(std.testing.allocator, [_]u8{0x01} ** 32, 4);
    defer relay.deinit();

    const peer_key = [_]u8{0x02} ** 32;
    try std.testing.expectError(error.NotAuthorized, relay.attach(peer_key));

    try relay.authorize(peer_key);
    const action = try relay.attach(peer_key);
    try std.testing.expectEqual(@as(?types.NodeKey, peer_key), switch (action) {
        .peer_present => |present| present.peer,
        else => null,
    });
    try std.testing.expect(relay.isAttached(peer_key));
}

test "relay forwards packets to an attached destination" {
    var relay = Relay.init(std.testing.allocator, [_]u8{0x01} ** 32, 4);
    defer relay.deinit();

    const a = [_]u8{0x0a} ** 32;
    const b = [_]u8{0x0b} ** 32;
    try relay.authorize(a);
    try relay.authorize(b);
    _ = try relay.attach(a);
    _ = try relay.attach(b);

    const packet = [_]u8{ 1, 2, 3, 4 };
    const action = try relay.handleFrame(a, .{ .send_packet = .{
        .destination = b,
        .packet = &packet,
    } });
    switch (action) {
        .forward => |forward| {
            try std.testing.expectEqualSlices(u8, &b, &forward.to);
            try std.testing.expectEqualSlices(u8, &packet, forward.frame.recv_packet.packet);
            try std.testing.expectEqualSlices(u8, &a, &forward.frame.recv_packet.source);
        },
        else => return error.UnexpectedAction,
    }
}

test "relay reports offline destinations and detach" {
    var relay = Relay.init(std.testing.allocator, [_]u8{0x01} ** 32, 4);
    defer relay.deinit();

    const a = [_]u8{0x0a} ** 32;
    const b = [_]u8{0x0b} ** 32;
    try relay.authorize(a);
    try relay.authorize(b);
    _ = try relay.attach(a);

    const packet = [_]u8{ 1, 2, 3 };
    try std.testing.expectError(
        error.DestinationOffline,
        relay.handleFrame(a, .{ .send_packet = .{ .destination = b, .packet = &packet } }),
    );

    _ = try relay.attach(b);
    const gone = relay.detach(b).?;
    try std.testing.expectEqual(@as(?types.NodeKey, b), switch (gone) {
        .peer_gone => |value| value.peer,
        else => null,
    });
    try std.testing.expect(!relay.isAttached(b));
}

test "relay answers pings and records preference" {
    var relay = Relay.init(std.testing.allocator, [_]u8{0x01} ** 32, 4);
    defer relay.deinit();

    const peer_key = [_]u8{0x0a} ** 32;
    try relay.authorize(peer_key);
    _ = try relay.attach(peer_key);

    const nonce = [_]u8{0x55} ** 16;
    const action = try relay.handleFrame(peer_key, .{ .ping = .{ .nonce = nonce } });
    switch (action) {
        .reply => |reply| try std.testing.expectEqualSlices(u8, &nonce, &reply.pong.nonce),
        else => return error.UnexpectedAction,
    }

    _ = try relay.handleFrame(peer_key, .{ .note_preferred = .{ .preferred = true } });
    try std.testing.expect(relay.peers.get(peer_key).?.preferred);
}

test "relay rejects client-only frames and unauthenticated senders" {
    var relay = Relay.init(std.testing.allocator, [_]u8{0x01} ** 32, 4);
    defer relay.deinit();

    const unknown = [_]u8{0x0a} ** 32;
    try std.testing.expectError(
        error.NotAttached,
        relay.handleFrame(unknown, .{ .keep_alive = {} }),
    );

    try relay.authorize(unknown);
    _ = try relay.attach(unknown);
    try std.testing.expectError(
        error.InvalidFrame,
        relay.handleFrame(unknown, .{ .peer_present = .{ .peer = unknown } }),
    );
}

test "relay enforces peer limit" {
    var relay = Relay.init(std.testing.allocator, [_]u8{0x01} ** 32, 1);
    defer relay.deinit();

    const a = [_]u8{0x0a} ** 32;
    const b = [_]u8{0x0b} ** 32;
    try relay.authorize(a);
    try relay.authorize(b);
    _ = try relay.attach(a);
    try std.testing.expectError(error.PeerLimitReached, relay.attach(b));
}

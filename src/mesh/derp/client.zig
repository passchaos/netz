//! DERP relay client state machine.
//!
//! The client owns connection state and validates the relay's advertised key
//! before accepting packets. Transport code (WebSocket/TLS via `netz`) is kept
//! outside this file so the state machine remains deterministic and testable.

const std = @import("std");
const types = @import("../types.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;

pub const State = enum {
    disconnected,
    connecting,
    connected,
    restarting,
    closed,
};

pub const ClientError = error{
    NotConnected,
    ServerKeyMissing,
    ServerKeyMismatch,
    UnexpectedFrame,
    InvalidFrame,
    PacketTooLarge,
};

pub const Action = union(enum) {
    none,
    pong: Frame,
    deliver: frame_mod.RecvPacket,
    peer_gone: frame_mod.PeerGone,
    peer_present: frame_mod.PeerPresent,
    restart: u16,
};

pub const Client = struct {
    client_key: types.NodeKey,
    expected_server_key: ?types.NodeKey = null,
    server_key: ?types.NodeKey = null,
    state: State = .disconnected,
    restart_after_ms: u16 = 0,
    preferred: bool = false,

    pub fn init(client_key: types.NodeKey) Client {
        return .{ .client_key = client_key };
    }

    pub fn beginConnect(self: *Client) ClientError!void {
        if (self.state != .disconnected and self.state != .closed) {
            return error.UnexpectedFrame;
        }
        self.state = .connecting;
    }

    pub fn onDisconnect(self: *Client) void {
        self.state = .disconnected;
        self.server_key = null;
        self.restart_after_ms = 0;
    }

    pub fn onServerKey(self: *Client, key: types.NodeKey) ClientError!void {
        if (self.state != .connecting and self.state != .connected and self.state != .restarting) {
            return error.UnexpectedFrame;
        }
        if (self.expected_server_key) |expected| {
            if (!std.mem.eql(u8, &expected, &key)) return error.ServerKeyMismatch;
        }
        self.server_key = key;
        self.state = .connected;
        self.restart_after_ms = 0;
    }

    pub fn handleFrame(self: *Client, frame: Frame) ClientError!Action {
        if (self.state != .connected) return error.NotConnected;

        return switch (frame) {
            .server_key => |server| blk: {
                try self.onServerKey(server.key);
                break :blk .{ .none = {} };
            },
            .ping => |ping| .{ .pong = .{ .pong = .{ .nonce = ping.nonce } } },
            .recv_packet => |packet| blk: {
                if (packet.packet.len > frame_mod.max_packet_bytes) {
                    return error.PacketTooLarge;
                }
                break :blk .{ .deliver = packet };
            },
            .peer_gone => |gone| .{ .peer_gone = gone },
            .peer_present => |present| .{ .peer_present = present },
            .keep_alive => .{ .none = {} },
            .restarting => |restart| blk: {
                self.state = .restarting;
                self.restart_after_ms = restart.reconnect_after_ms;
                break :blk .{ .restart = restart.reconnect_after_ms };
            },
            .health => .{ .none = {} },
            .pong => .{ .none = {} },
            .note_preferred,
            .client_info,
            .client_deps,
            .send_packet,
            => error.UnexpectedFrame,
        };
    }

    pub fn encodeSendPacket(
        self: *Client,
        destination: types.NodeKey,
        packet: []const u8,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (self.state != .connected) return error.NotConnected;
        if (packet.len > frame_mod.max_packet_bytes) return error.PacketTooLarge;
        return (Frame{ .send_packet = .{
            .destination = destination,
            .packet = packet,
        } }).encode(allocator, frame_mod.default_max_payload_bytes);
    }

    pub fn reconnect(self: *Client) ClientError!void {
        if (self.state != .restarting and self.state != .disconnected) {
            return error.UnexpectedFrame;
        }
        self.state = .connecting;
        self.server_key = null;
    }
};

test "client validates server key and rejects a mismatch" {
    var client = Client.init([_]u8{0x01} ** 32);
    client.expected_server_key = [_]u8{0x02} ** 32;
    try client.beginConnect();
    try client.onServerKey([_]u8{0x02} ** 32);
    try std.testing.expectEqual(State.connected, client.state);

    var other = Client.init([_]u8{0x01} ** 32);
    other.expected_server_key = [_]u8{0x02} ** 32;
    try other.beginConnect();
    try std.testing.expectError(
        error.ServerKeyMismatch,
        other.onServerKey([_]u8{0x03} ** 32),
    );
}

test "client answers relay ping and delivers packets" {
    var client = Client.init([_]u8{0x01} ** 32);
    try client.beginConnect();
    try client.onServerKey([_]u8{0x02} ** 32);

    const ping: Frame = .{ .ping = .{ .nonce = [_]u8{0xaa} ** 16 } };
    const ping_action = try client.handleFrame(ping);
    try std.testing.expectEqualSlices(u8, &ping.ping.nonce, &ping_action.pong.pong.nonce);

    const packet = [_]u8{ 1, 2, 3 };
    const action = try client.handleFrame(.{ .recv_packet = .{
        .source = [_]u8{0x04} ** 32,
        .packet = &packet,
    } });
    try std.testing.expectEqualSlices(u8, &packet, action.deliver.packet);
}

test "client cannot send before connecting" {
    var client = Client.init([_]u8{0x01} ** 32);
    try std.testing.expectError(
        error.NotConnected,
        client.handleFrame(.{ .keep_alive = {} }),
    );
    try std.testing.expectError(
        error.NotConnected,
        client.encodeSendPacket(
            [_]u8{0x02} ** 32,
            &.{1},
            std.testing.allocator,
        ),
    );
}

test "restarting transition and reconnect" {
    var client = Client.init([_]u8{0x01} ** 32);
    try client.beginConnect();
    try client.onServerKey([_]u8{0x02} ** 32);

    const action = try client.handleFrame(.{ .restarting = .{ .reconnect_after_ms = 500 } });
    try std.testing.expectEqual(@as(u16, 500), action.restart);
    try std.testing.expectEqual(State.restarting, client.state);

    try client.reconnect();
    try std.testing.expectEqual(State.connecting, client.state);
    try std.testing.expect(client.server_key == null);
}

test "disconnect clears server identity and requires a fresh connect" {
    var client = Client.init([_]u8{0x01} ** 32);
    try client.beginConnect();
    try client.onServerKey([_]u8{0x02} ** 32);
    client.onDisconnect();
    try std.testing.expectEqual(State.disconnected, client.state);
    try std.testing.expect(client.server_key == null);
    try std.testing.expectError(
        error.NotConnected,
        client.handleFrame(.{ .keep_alive = {} }),
    );
    try client.beginConnect();
    try client.onServerKey([_]u8{0x02} ** 32);
    try std.testing.expectEqual(State.connected, client.state);
}

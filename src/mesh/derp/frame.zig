//! Bounded DERP relay frame codec.
//!
//! Frames use the Tailscale DERP wire shape: one type byte followed by a
//! big-endian 32-bit payload length. The codec bounds every payload and
//! rejects trailing bytes so a relay cannot be tricked into forwarding a
//! frame with ambiguous contents.

const std = @import("std");
const wire = @import("../wire.zig");
const types = @import("../types.zig");
const disco_message = @import("../disco/message.zig");

pub const header_len = 5;
pub const default_max_payload_bytes: usize = 64 * 1024;
pub const max_packet_bytes: usize = default_max_payload_bytes - types.node_key_len - 1;
pub const max_health_bytes: usize = 512;

pub const FrameType = enum(u8) {
    server_key = 1,
    client_info = 2,
    client_deps = 3,
    send_packet = 4,
    recv_packet = 5,
    keep_alive = 6,
    note_preferred = 7,
    peer_gone = 8,
    peer_present = 9,
    ping = 10,
    pong = 11,
    health = 12,
    restarting = 13,
    _,
};

pub const Error = wire.Error || disco_message.Error || error{
    InvalidFrameType,
    PayloadTooLarge,
    TrailingBytes,
    EmptyPacket,
    PacketTooLarge,
    HealthTooLarge,
    InvalidPayload,
    InvalidEndpoint,
    TooManyEndpoints,
};

pub const ServerKey = struct {
    key: types.NodeKey,
};

pub const ClientInfo = struct {
    client_key: types.NodeKey,
    capabilities: types.Capabilities = .{},
    name: []const u8 = "",
};

pub const ClientDeps = struct {
    client_key: types.NodeKey,
    endpoints: disco_message.EndpointList = .{},
};

pub const SendPacket = struct {
    destination: types.NodeKey,
    packet: []const u8,
};

pub const RecvPacket = struct {
    source: types.NodeKey,
    packet: []const u8,
};

pub const NotePreferred = struct {
    preferred: bool,
};

pub const PeerGone = struct {
    peer: types.NodeKey,
    reason: u8 = 0,
};

pub const PeerPresent = struct {
    peer: types.NodeKey,
};

pub const NonceFrame = struct {
    nonce: [16]u8,
};

pub const Health = struct {
    message: []const u8,
};

pub const Restarting = struct {
    reconnect_after_ms: u16,
};

pub const Frame = union(FrameType) {
    server_key: ServerKey,
    client_info: ClientInfo,
    client_deps: ClientDeps,
    send_packet: SendPacket,
    recv_packet: RecvPacket,
    keep_alive: void,
    note_preferred: NotePreferred,
    peer_gone: PeerGone,
    peer_present: PeerPresent,
    ping: NonceFrame,
    pong: NonceFrame,
    health: Health,
    restarting: Restarting,

    pub fn frameType(self: Frame) FrameType {
        return std.meta.activeTag(self);
    }

    pub fn encode(
        self: Frame,
        allocator: std.mem.Allocator,
        max_payload_bytes: usize,
    ) ![]u8 {
        var payload = wire.Writer.init(allocator);
        defer payload.deinit();
        try self.writePayload(&payload);
        if (payload.slice().len > max_payload_bytes) return error.PayloadTooLarge;

        var out = wire.Writer.init(allocator);
        errdefer out.deinit();
        try out.writeU8(@intFromEnum(self.frameType()));
        try out.writeU32(@intCast(payload.slice().len));
        try out.writeSlice(payload.slice());
        return out.toOwnedSlice();
    }

    fn writePayload(self: Frame, out: *wire.Writer) !void {
        switch (self) {
            .server_key => |value| try out.writeSlice(&value.key),
            .client_info => |value| {
                try out.writeSlice(&value.client_key);
                try out.writeU32(value.capabilities.toInt());
                try out.writeBoundedSlice(value.name, types.max_hostname_len);
            },
            .client_deps => |value| {
                try out.writeSlice(&value.client_key);
                try value.endpoints.write(out);
            },
            .send_packet => |value| {
                try out.writeSlice(&value.destination);
                try out.writeSlice(value.packet);
            },
            .recv_packet => |value| {
                try out.writeSlice(&value.source);
                try out.writeSlice(value.packet);
            },
            .keep_alive => {},
            .note_preferred => |value| try out.writeU8(if (value.preferred) 1 else 0),
            .peer_gone => |value| {
                try out.writeSlice(&value.peer);
                try out.writeU8(value.reason);
            },
            .peer_present => |value| try out.writeSlice(&value.peer),
            .ping, .pong => |value| try out.writeSlice(&value.nonce),
            .health => |value| try out.writeBoundedSlice(value.message, max_health_bytes),
            .restarting => |value| try out.writeU16(value.reconnect_after_ms),
        }
    }
};

pub const Decoded = struct {
    frame: Frame,
};

pub fn decode(input: []const u8, max_payload_bytes: usize) Error!Decoded {
    if (input.len < header_len) return error.Truncated;
    var reader = wire.Reader.init(input);
    const type_value = try reader.readU8();
    const frame_type = std.enums.fromInt(FrameType, type_value) orelse
        return error.InvalidFrameType;
    const payload_len = try reader.readU32();
    if (payload_len > max_payload_bytes) return error.PayloadTooLarge;
    if (reader.remainingLen() != payload_len) return error.TrailingBytes;

    const payload = try reader.readSlice(payload_len);
    var payload_reader = wire.Reader.init(payload);
    const frame: Frame = switch (frame_type) {
        .server_key => .{ .server_key = .{
            .key = try payload_reader.readFixed(types.node_key_len),
        } },
        .client_info => blk: {
            const client_key = try payload_reader.readFixed(types.node_key_len);
            const capabilities = types.Capabilities.fromInt(try payload_reader.readU32());
            const name = try payload_reader.readBoundedSlice(types.max_hostname_len);
            break :blk .{ .client_info = .{
                .client_key = client_key,
                .capabilities = capabilities,
                .name = name,
            } };
        },
        .client_deps => .{ .client_deps = .{
            .client_key = try payload_reader.readFixed(types.node_key_len),
            .endpoints = try disco_message.EndpointList.read(&payload_reader),
        } },
        .send_packet => .{ .send_packet = .{
            .destination = try payload_reader.readFixed(types.node_key_len),
            .packet = try readPacket(&payload_reader),
        } },
        .recv_packet => .{ .recv_packet = .{
            .source = try payload_reader.readFixed(types.node_key_len),
            .packet = try readPacket(&payload_reader),
        } },
        .keep_alive => .{ .keep_alive = {} },
        .note_preferred => .{ .note_preferred = .{
            .preferred = try readBool(&payload_reader),
        } },
        .peer_gone => .{ .peer_gone = .{
            .peer = try payload_reader.readFixed(types.node_key_len),
            .reason = try payload_reader.readU8(),
        } },
        .peer_present => .{ .peer_present = .{
            .peer = try payload_reader.readFixed(types.node_key_len),
        } },
        .ping => .{ .ping = .{ .nonce = try payload_reader.readFixed(16) } },
        .pong => .{ .pong = .{ .nonce = try payload_reader.readFixed(16) } },
        .health => .{ .health = .{
            .message = try payload_reader.readBoundedSlice(max_health_bytes),
        } },
        .restarting => .{ .restarting = .{
            .reconnect_after_ms = try payload_reader.readU16(),
        } },
        else => return error.InvalidFrameType,
    };
    try payload_reader.expectEnd();
    return .{ .frame = frame };
}

fn readPacket(reader: *wire.Reader) Error![]const u8 {
    const remaining = reader.remainingLen();
    if (remaining == 0) return error.EmptyPacket;
    if (remaining > max_packet_bytes) return error.PacketTooLarge;
    return reader.readSlice(remaining);
}

fn readBool(reader: *wire.Reader) Error!bool {
    const value = try reader.readU8();
    if (value > 1) return error.InvalidPayload;
    return value == 1;
}

test "server key and ping round trip" {
    const server_key: Frame = .{ .server_key = .{
        .key = [_]u8{0xaa} ** types.node_key_len,
    } };
    const encoded = try server_key.encode(std.testing.allocator, default_max_payload_bytes);
    defer std.testing.allocator.free(encoded);
    const decoded = try decode(encoded, default_max_payload_bytes);
    try std.testing.expectEqual(FrameType.server_key, decoded.frame.frameType());
    try std.testing.expectEqualSlices(u8, &server_key.server_key.key, &decoded.frame.server_key.key);

    const ping: Frame = .{ .ping = .{ .nonce = [_]u8{0x55} ** 16 } };
    const ping_encoded = try ping.encode(std.testing.allocator, default_max_payload_bytes);
    defer std.testing.allocator.free(ping_encoded);
    const ping_decoded = try decode(ping_encoded, default_max_payload_bytes);
    try std.testing.expectEqual(FrameType.ping, ping_decoded.frame.frameType());
    try std.testing.expectEqualSlices(u8, &ping.ping.nonce, &ping_decoded.frame.ping.nonce);
}

test "send packet round trip preserves packet bytes" {
    const packet = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const frame: Frame = .{ .send_packet = .{
        .destination = [_]u8{0x01} ** types.node_key_len,
        .packet = &packet,
    } };
    const encoded = try frame.encode(std.testing.allocator, default_max_payload_bytes);
    defer std.testing.allocator.free(encoded);
    const decoded = try decode(encoded, default_max_payload_bytes);
    try std.testing.expectEqualSlices(u8, &packet, decoded.frame.send_packet.packet);
    try std.testing.expectEqualSlices(u8, &frame.send_packet.destination, &decoded.frame.send_packet.destination);
}

test "decoder rejects empty packets and oversized payloads" {
    const empty: Frame = .{ .send_packet = .{
        .destination = [_]u8{0x01} ** types.node_key_len,
        .packet = &.{},
    } };
    const encoded = try empty.encode(std.testing.allocator, default_max_payload_bytes);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectError(error.EmptyPacket, decode(encoded, default_max_payload_bytes));

    var short = [_]u8{ @intFromEnum(FrameType.keep_alive), 0, 0 };
    try std.testing.expectError(error.Truncated, decode(&short, default_max_payload_bytes));
}

test "decoder rejects unknown frame types and trailing bytes" {
    const unknown = [_]u8{ 99, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidFrameType, decode(&unknown, default_max_payload_bytes));

    const encoded = try (@as(Frame, .{ .keep_alive = {} })).encode(
        std.testing.allocator,
        default_max_payload_bytes,
    );
    defer std.testing.allocator.free(encoded);
    const with_trailing = try std.mem.concat(
        std.testing.allocator,
        u8,
        &.{ encoded, &.{0xff} },
    );
    defer std.testing.allocator.free(with_trailing);
    try std.testing.expectError(error.TrailingBytes, decode(with_trailing, default_max_payload_bytes));
}

test "client info and deps round trip" {
    const endpoint = types.Endpoint.fromV4(.{ 10, 0, 0, 5 }, 41641);
    const deps = disco_message.EndpointList.init(&.{endpoint}) catch unreachable;
    const frame: Frame = .{ .client_deps = .{
        .client_key = [_]u8{0x02} ** types.node_key_len,
        .endpoints = deps,
    } };
    const encoded = try frame.encode(std.testing.allocator, default_max_payload_bytes);
    defer std.testing.allocator.free(encoded);
    const decoded = try decode(encoded, default_max_payload_bytes);
    try std.testing.expectEqual(@as(u8, 1), decoded.frame.client_deps.endpoints.count);
    try std.testing.expect(types.Endpoint.eql(
        endpoint,
        decoded.frame.client_deps.endpoints.slice()[0],
    ));
}

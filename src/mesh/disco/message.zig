//! Bounded mesh discovery (disco) message codec.
//!
//! Disco messages are small, self-delimiting frames exchanged between nodes.
//! The codec never allocates while decoding and rejects unknown versions,
//! unknown message types, trailing payload bytes, and oversized endpoint lists.

const std = @import("std");
const wire = @import("../wire.zig");
const types = @import("../types.zig");

pub const magic: u32 = 0x4d445343; // "MDSC"
pub const version: u8 = 1;
pub const header_len = 20;
pub const max_payload_bytes = 4096;
pub const max_frame_bytes = header_len + max_payload_bytes;

pub const MessageType = enum(u8) {
    ping = 1,
    pong = 2,
    call_me_maybe = 3,
    endpoint_update = 4,
    nat_info = 5,
    capabilities = 6,
    path_hint = 7,
    _,
};

pub const Error = wire.Error || error{
    InvalidMagic,
    UnsupportedVersion,
    UnknownMessageType,
    PayloadTooLarge,
    TooManyEndpoints,
    InvalidEndpoint,
    TrailingBytes,
};

pub const EndpointList = struct {
    endpoints: [types.max_endpoints]types.Endpoint = [_]types.Endpoint{.{}} ** types.max_endpoints,
    count: u8 = 0,

    pub fn init(endpoints: []const types.Endpoint) Error!EndpointList {
        var list = EndpointList{};
        for (endpoints) |endpoint| try list.append(endpoint);
        return list;
    }

    pub fn slice(self: *const EndpointList) []const types.Endpoint {
        return self.endpoints[0..self.count];
    }

    pub fn append(self: *EndpointList, endpoint: types.Endpoint) Error!void {
        if (!endpoint.isValid()) return error.InvalidEndpoint;
        if (self.count >= types.max_endpoints) return error.TooManyEndpoints;
        self.endpoints[self.count] = endpoint;
        self.count += 1;
    }

    /// Merge endpoints in place, preserving order and rejecting duplicates.
    pub fn merge(self: *EndpointList, other: *const EndpointList) Error!void {
        for (other.slice()) |endpoint| {
            if (self.contains(endpoint)) continue;
            try self.append(endpoint);
        }
    }

    pub fn contains(self: *const EndpointList, endpoint: types.Endpoint) bool {
        for (self.slice()) |existing| {
            if (types.Endpoint.eql(existing, endpoint)) return true;
        }
        return false;
    }

    pub fn write(self: *const EndpointList, out: *wire.Writer) !void {
        if (self.count > types.max_endpoints) return error.TooManyEndpoints;
        try out.writeU8(self.count);
        for (self.slice()) |endpoint| try endpoint.write(out);
    }

    pub fn read(input: *wire.Reader) Error!EndpointList {
        const count = try input.readU8();
        if (count > types.max_endpoints) return error.TooManyEndpoints;
        var list = EndpointList{};
        var index: usize = 0;
        while (index < count) : (index += 1) {
            try list.append(try types.Endpoint.read(input));
        }
        return list;
    }
};

pub const PingPong = struct {
    node_key: types.NodeKey,
    endpoints: EndpointList = .{},
    capabilities: types.Capabilities = .{},
    nonce: [16]u8 = [_]u8{0} ** 16,

    fn write(self: *const PingPong, out: *wire.Writer) !void {
        try out.writeSlice(&self.node_key);
        try self.endpoints.write(out);
        try out.writeU32(self.capabilities.toInt());
        try out.writeSlice(&self.nonce);
    }

    fn read(input: *wire.Reader) Error!PingPong {
        return .{
            .node_key = try input.readFixed(types.node_key_len),
            .endpoints = try EndpointList.read(input),
            .capabilities = types.Capabilities.fromInt(try input.readU32()),
            .nonce = try input.readFixed(16),
        };
    }
};

pub const NatInfo = struct {
    nat_type: types.NatType,
    observed: types.Endpoint,
    port_preserved: bool,

    fn write(self: NatInfo, out: *wire.Writer) !void {
        try out.writeU8(@intFromEnum(self.nat_type));
        try self.observed.write(out);
        try out.writeU8(if (self.port_preserved) 1 else 0);
    }

    fn read(input: *wire.Reader) Error!NatInfo {
        const nat_type: types.NatType = @enumFromInt(try input.readU8());
        const observed = try types.Endpoint.read(input);
        const flag = try input.readU8();
        if (flag > 1) return error.InvalidEndpoint;
        return .{
            .nat_type = nat_type,
            .observed = observed,
            .port_preserved = flag == 1,
        };
    }
};

pub const PathHint = struct {
    kind: types.PathKind,
    derp_region: u16 = 0,

    fn write(self: PathHint, out: *wire.Writer) !void {
        try out.writeU8(@intFromEnum(self.kind));
        try out.writeU16(self.derp_region);
    }

    fn read(input: *wire.Reader) Error!PathHint {
        return .{
            .kind = @enumFromInt(try input.readU8()),
            .derp_region = try input.readU16(),
        };
    }
};

pub const Message = union(MessageType) {
    ping: PingPong,
    pong: PingPong,
    call_me_maybe: EndpointList,
    endpoint_update: EndpointList,
    nat_info: NatInfo,
    capabilities: types.Capabilities,
    path_hint: PathHint,

    pub fn messageType(self: Message) MessageType {
        return std.meta.activeTag(self);
    }

    pub fn encode(self: Message, allocator: std.mem.Allocator) ![]u8 {
        var payload = wire.Writer.init(allocator);
        defer payload.deinit();
        try self.writePayload(&payload);
        if (payload.slice().len > max_payload_bytes) return error.PayloadTooLarge;

        var out = wire.Writer.init(allocator);
        errdefer out.deinit();
        try out.writeU32(magic);
        try out.writeU8(version);
        try out.writeU8(@intFromEnum(self.messageType()));
        try out.writeU16(0);
        try out.writeU64(0);
        try out.writeU32(@intCast(payload.slice().len));
        try out.writeSlice(payload.slice());
        return out.toOwnedSlice();
    }

    /// Encode with a caller-supplied transaction ID.
    pub fn encodeWithTxId(
        self: Message,
        allocator: std.mem.Allocator,
        tx_id: u64,
    ) ![]u8 {
        var payload = wire.Writer.init(allocator);
        defer payload.deinit();
        try self.writePayload(&payload);
        if (payload.slice().len > max_payload_bytes) return error.PayloadTooLarge;

        var out = wire.Writer.init(allocator);
        errdefer out.deinit();
        try out.writeU32(magic);
        try out.writeU8(version);
        try out.writeU8(@intFromEnum(self.messageType()));
        try out.writeU16(0);
        try out.writeU64(tx_id);
        try out.writeU32(@intCast(payload.slice().len));
        try out.writeSlice(payload.slice());
        return out.toOwnedSlice();
    }

    fn writePayload(self: Message, out: *wire.Writer) !void {
        switch (self) {
            .ping => |value| try value.write(out),
            .pong => |value| try value.write(out),
            .call_me_maybe => |value| try value.write(out),
            .endpoint_update => |value| try value.write(out),
            .nat_info => |value| try value.write(out),
            .capabilities => |value| try out.writeU32(value.toInt()),
            .path_hint => |value| try value.write(out),
        }
    }
};

pub const Decoded = struct {
    tx_id: u64,
    flags: u16,
    message: Message,
};

pub fn decode(input: []const u8) Error!Decoded {
    if (input.len > max_frame_bytes) return error.PayloadTooLarge;
    var reader = wire.Reader.init(input);

    const received_magic = try reader.readU32();
    if (received_magic != magic) return error.InvalidMagic;
    const received_version = try reader.readU8();
    if (received_version != version) return error.UnsupportedVersion;
    const type_value = try reader.readU8();
    const message_type = std.enums.fromInt(MessageType, type_value) orelse
        return error.UnknownMessageType;
    const flags = try reader.readU16();
    const tx_id = try reader.readU64();
    const payload_len = try reader.readU32();
    if (payload_len > max_payload_bytes) return error.PayloadTooLarge;
    if (reader.remainingLen() != payload_len) return error.TrailingBytes;

    const payload = try reader.readSlice(payload_len);
    var payload_reader = wire.Reader.init(payload);
    const message: Message = switch (message_type) {
        .ping => .{ .ping = try PingPong.read(&payload_reader) },
        .pong => .{ .pong = try PingPong.read(&payload_reader) },
        .call_me_maybe => .{ .call_me_maybe = try EndpointList.read(&payload_reader) },
        .endpoint_update => .{ .endpoint_update = try EndpointList.read(&payload_reader) },
        .nat_info => .{ .nat_info = try NatInfo.read(&payload_reader) },
        .capabilities => .{
            .capabilities = types.Capabilities.fromInt(try payload_reader.readU32()),
        },
        .path_hint => .{ .path_hint = try PathHint.read(&payload_reader) },
        else => return error.UnknownMessageType,
    };
    try payload_reader.expectEnd();

    return .{ .tx_id = tx_id, .flags = flags, .message = message };
}

test "ping round trip" {
    const endpoints = [_]types.Endpoint{
        types.Endpoint.fromV4(.{ 192, 168, 1, 10 }, 41641),
        types.Endpoint.fromV6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12, 41641),
    };
    const message: Message = .{ .ping = .{
        .node_key = [_]u8{0x11} ** types.node_key_len,
        .endpoints = try EndpointList.init(&endpoints),
        .capabilities = .{ .direct = true, .derp = true },
        .nonce = [_]u8{0x22} ** 16,
    } };

    const encoded = try message.encodeWithTxId(std.testing.allocator, 7);
    defer std.testing.allocator.free(encoded);

    const decoded = try decode(encoded);
    try std.testing.expectEqual(@as(u64, 7), decoded.tx_id);
    try std.testing.expectEqual(MessageType.ping, decoded.message.messageType());
    const ping = decoded.message.ping;
    try std.testing.expectEqualSlices(u8, &message.ping.node_key, &ping.node_key);
    try std.testing.expectEqual(@as(usize, 2), ping.endpoints.count);
    try std.testing.expect(types.Endpoint.eql(endpoints[0], ping.endpoints.slice()[0]));
    try std.testing.expectEqual(message.ping.capabilities, ping.capabilities);
}

test "nat and path hint round trip" {
    const nat: Message = .{ .nat_info = .{
        .nat_type = .symmetric,
        .observed = types.Endpoint.fromV4(.{ 203, 0, 113, 5 }, 51820),
        .port_preserved = false,
    } };
    const encoded = try nat.encode(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    const decoded = try decode(encoded);
    try std.testing.expectEqual(types.NatType.symmetric, decoded.message.nat_info.nat_type);
    try std.testing.expect(!decoded.message.nat_info.port_preserved);

    const hint: Message = .{ .path_hint = .{ .kind = .derp, .derp_region = 3 } };
    const hint_encoded = try hint.encode(std.testing.allocator);
    defer std.testing.allocator.free(hint_encoded);
    const hint_decoded = try decode(hint_encoded);
    try std.testing.expectEqual(types.PathKind.derp, hint_decoded.message.path_hint.kind);
    try std.testing.expectEqual(@as(u16, 3), hint_decoded.message.path_hint.derp_region);
}

test "decode rejects malformed headers and trailing bytes" {
    var writer = wire.Writer.init(std.testing.allocator);
    defer writer.deinit();
    try writer.writeU32(0x01020304);
    try std.testing.expectError(error.InvalidMagic, decode(writer.slice()));

    const message: Message = .{ .capabilities = .{ .direct = true } };
    const encoded = try message.encode(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    var bad_version = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(bad_version);
    bad_version[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, decode(bad_version));

    var bad_type = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(bad_type);
    bad_type[5] = 99;
    try std.testing.expectError(error.UnknownMessageType, decode(bad_type));

    const trailing = try std.mem.concat(
        std.testing.allocator,
        u8,
        &.{ encoded, &.{0xff} },
    );
    defer std.testing.allocator.free(trailing);
    try std.testing.expectError(error.TrailingBytes, decode(trailing));
}

test "endpoint list is bounded" {
    const too_many = [_]types.Endpoint{
        types.Endpoint.fromV4(.{ 10, 0, 0, 1 }, 1),
    } ** (types.max_endpoints + 1);
    try std.testing.expectError(error.TooManyEndpoints, EndpointList.init(&too_many));

    var list = EndpointList{};
    try list.append(types.Endpoint.fromV4(.{ 10, 0, 0, 1 }, 1));
    try list.append(types.Endpoint.fromV4(.{ 10, 0, 0, 1 }, 1));
    try std.testing.expectEqual(@as(u8, 2), list.count);
    try std.testing.expect(list.contains(types.Endpoint.fromV4(.{ 10, 0, 0, 1 }, 1)));
}

test "merge deduplicates endpoints" {
    var first = try EndpointList.init(&.{
        types.Endpoint.fromV4(.{ 10, 0, 0, 1 }, 1),
    });
    const second = try EndpointList.init(&.{
        types.Endpoint.fromV4(.{ 10, 0, 0, 1 }, 1),
        types.Endpoint.fromV4(.{ 10, 0, 0, 2 }, 2),
    });
    try first.merge(&second);
    try std.testing.expectEqual(@as(u8, 2), first.count);
}

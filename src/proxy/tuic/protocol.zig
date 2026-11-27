//! TUIC v5 command and address codec.

const std = @import("std");

const net = std.Io.net;

pub const version: u8 = 5;
/// Version/command, association/packet IDs, fragment fields, payload length,
/// plus the longest encoded domain address (type, length, 255 bytes, port).
pub const maximum_encoded_address_bytes = 1 + 1 + 255 + 2;
pub const maximum_packet_header_bytes = 10 + maximum_encoded_address_bytes;

pub const CommandType = enum(u8) {
    authenticate = 0,
    connect = 1,
    packet = 2,
    dissociate = 3,
    heartbeat = 4,
};

pub const Address = union(enum) {
    none,
    ip: net.IpAddress,
    domain: struct {
        host: []const u8,
        port: u16,
    },

    pub fn getPort(self: Address) u16 {
        return switch (self) {
            .none => 0,
            .ip => |ip| ip.getPort(),
            .domain => |domain| domain.port,
        };
    }
};

pub const DecodedAddress = struct {
    address: Address,
    end: usize,
};

pub const Error = error{
    InvalidCommand,
    InvalidAddress,
    InvalidHostName,
    UnsupportedAddressType,
    BufferTooSmall,
};

pub fn encodeAddress(output: []u8, address: Address) Error!usize {
    switch (address) {
        .none => {
            if (output.len < 1) return error.BufferTooSmall;
            output[0] = 0xff;
            return 1;
        },
        .ip => |ip| switch (ip) {
            .ip4 => |value| {
                if (output.len < 1 + 4 + 2) return error.BufferTooSmall;
                output[0] = 0x01;
                @memcpy(output[1..5], &value.bytes);
                std.mem.writeInt(u16, output[5..7], value.port, .big);
                return 7;
            },
            .ip6 => |value| {
                if (output.len < 1 + 16 + 2) return error.BufferTooSmall;
                output[0] = 0x02;
                @memcpy(output[1..17], &value.bytes);
                std.mem.writeInt(u16, output[17..19], value.port, .big);
                return 19;
            },
        },
        .domain => |domain| {
            _ = net.HostName.init(domain.host) catch return error.InvalidHostName;
            const total = 2 + domain.host.len + 2;
            if (output.len < total) return error.BufferTooSmall;
            output[0] = 0x00;
            output[1] = @intCast(domain.host.len);
            @memcpy(output[2..][0..domain.host.len], domain.host);
            std.mem.writeInt(
                u16,
                output[2 + domain.host.len ..][0..2],
                domain.port,
                .big,
            );
            return total;
        },
    }
}

pub fn decodeAddress(bytes: []const u8, offset: usize) Error!DecodedAddress {
    if (offset >= bytes.len) return error.InvalidAddress;
    return switch (bytes[offset]) {
        0xff => .{ .address = .none, .end = offset + 1 },
        0x01 => blk: {
            if (bytes.len - offset < 1 + 4 + 2) return error.InvalidAddress;
            break :blk .{
                .address = .{ .ip = .{ .ip4 = .{
                    .bytes = bytes[offset + 1 ..][0..4].*,
                    .port = std.mem.readInt(
                        u16,
                        bytes[offset + 5 ..][0..2],
                        .big,
                    ),
                } } },
                .end = offset + 7,
            };
        },
        0x02 => blk: {
            if (bytes.len - offset < 1 + 16 + 2) return error.InvalidAddress;
            break :blk .{
                .address = .{ .ip = .{ .ip6 = .{
                    .bytes = bytes[offset + 1 ..][0..16].*,
                    .port = std.mem.readInt(
                        u16,
                        bytes[offset + 17 ..][0..2],
                        .big,
                    ),
                    .flow = 0,
                    .interface = .none,
                } } },
                .end = offset + 19,
            };
        },
        0x00 => blk: {
            if (bytes.len - offset < 2) return error.InvalidAddress;
            const host_len = bytes[offset + 1];
            if (host_len == 0) return error.InvalidHostName;
            const end = offset + 2 + @as(usize, host_len) + 2;
            if (bytes.len < end) return error.InvalidAddress;
            const host = bytes[offset + 2 ..][0..host_len];
            _ = net.HostName.init(host) catch return error.InvalidHostName;
            break :blk .{
                .address = .{ .domain = .{
                    .host = host,
                    .port = std.mem.readInt(u16, bytes[end - 2 ..][0..2], .big),
                } },
                .end = end,
            };
        },
        else => error.UnsupportedAddressType,
    };
}

pub fn buildAuthenticate(uuid: [16]u8, token: [32]u8) [50]u8 {
    var command: [50]u8 = undefined;
    command[0] = version;
    command[1] = @intFromEnum(CommandType.authenticate);
    @memcpy(command[2..18], &uuid);
    @memcpy(command[18..50], &token);
    return command;
}

pub const Authenticate = struct {
    uuid: [16]u8,
    token: [32]u8,
};

pub fn parseAuthenticate(bytes: []const u8) Error!Authenticate {
    if (bytes.len < 50) return error.InvalidCommand;
    if (bytes[0] != version or
        bytes[1] != @intFromEnum(CommandType.authenticate))
    {
        return error.InvalidCommand;
    }
    return .{
        .uuid = bytes[2..18].*,
        .token = bytes[18..50].*,
    };
}

pub fn buildConnect(allocator: std.mem.Allocator, address: Address) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, version);
    try output.append(allocator, @intFromEnum(CommandType.connect));
    var storage: [maximum_encoded_address_bytes]u8 = undefined;
    const len = try encodeAddress(&storage, address);
    try output.appendSlice(allocator, storage[0..len]);
    return output.toOwnedSlice(allocator);
}

pub const Connect = struct {
    address: Address,
    end: usize,
};

pub fn parseConnect(bytes: []const u8) Error!Connect {
    if (bytes.len < 2) return error.InvalidCommand;
    if (bytes[0] != version or bytes[1] != @intFromEnum(CommandType.connect)) {
        return error.InvalidCommand;
    }
    const decoded = try decodeAddress(bytes, 2);
    return .{ .address = decoded.address, .end = decoded.end };
}

pub const Packet = struct {
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    address: Address,
    payload: []const u8,
};

pub const ParsedPacket = struct {
    packet: Packet,
    end: usize,
};

pub fn buildPacket(
    allocator: std.mem.Allocator,
    packet: Packet,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.append(allocator, version);
    try output.append(allocator, @intFromEnum(CommandType.packet));
    try output.append(allocator, @intCast(packet.assoc_id >> 8));
    try output.append(allocator, @intCast(packet.assoc_id & 0xff));
    try output.append(allocator, @intCast(packet.pkt_id >> 8));
    try output.append(allocator, @intCast(packet.pkt_id & 0xff));
    try output.append(allocator, packet.frag_total);
    try output.append(allocator, packet.frag_id);
    try output.append(allocator, @intCast(packet.payload.len >> 8));
    try output.append(allocator, @intCast(packet.payload.len & 0xff));
    var address_storage: [maximum_encoded_address_bytes]u8 = undefined;
    const address_len = try encodeAddress(&address_storage, packet.address);
    try output.appendSlice(allocator, address_storage[0..address_len]);
    try output.appendSlice(allocator, packet.payload);
    return output.toOwnedSlice(allocator);
}

pub fn parsePacket(bytes: []const u8) Error!ParsedPacket {
    if (bytes.len < 10) return error.InvalidCommand;
    if (bytes[0] != version or bytes[1] != @intFromEnum(CommandType.packet)) {
        return error.InvalidCommand;
    }
    const assoc_id = std.mem.readInt(u16, bytes[2..4], .big);
    const pkt_id = std.mem.readInt(u16, bytes[4..6], .big);
    const frag_total = bytes[6];
    const frag_id = bytes[7];
    if (frag_total == 0 or frag_id >= frag_total) return error.InvalidCommand;
    const size = std.mem.readInt(u16, bytes[8..10], .big);
    const decoded = try decodeAddress(bytes, 10);
    const end = decoded.end + @as(usize, size);
    if (bytes.len < end) return error.InvalidCommand;
    return .{
        .packet = .{
            .assoc_id = assoc_id,
            .pkt_id = pkt_id,
            .frag_total = frag_total,
            .frag_id = frag_id,
            .address = decoded.address,
            .payload = bytes[decoded.end..end],
        },
        .end = end,
    };
}

pub fn buildDissociate(assoc_id: u16) [4]u8 {
    return .{
        version,
        @intFromEnum(CommandType.dissociate),
        @intCast(assoc_id >> 8),
        @intCast(assoc_id & 0xff),
    };
}

pub fn parseDissociate(bytes: []const u8) Error!u16 {
    if (bytes.len < 4) return error.InvalidCommand;
    if (bytes[0] != version or
        bytes[1] != @intFromEnum(CommandType.dissociate))
    {
        return error.InvalidCommand;
    }
    return std.mem.readInt(u16, bytes[2..4], .big);
}

pub const heartbeat_command: [2]u8 = .{
    version,
    @intFromEnum(CommandType.heartbeat),
};

pub fn isUnidirectional(stream_id: u64) bool {
    return (stream_id & 0x2) != 0;
}

pub fn isClientInitiated(stream_id: u64) bool {
    return (stream_id & 0x1) == 0;
}

test "TUIC addresses round trip every family" {
    const addresses = [_]Address{
        .{ .ip = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 443 } } },
        .{ .ip = .{ .ip6 = .{
            .bytes = .{
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0,    0,    0,    0,    0, 0, 0, 1,
            },
            .port = 8443,
            .flow = 0,
            .interface = .none,
        } } },
        .{ .domain = .{ .host = "origin.example", .port = 8080 } },
        .none,
    };
    for (addresses) |address| {
        var storage: [64]u8 = undefined;
        const len = try encodeAddress(&storage, address);
        const decoded = try decodeAddress(storage[0..len], 0);
        try std.testing.expectEqual(len, decoded.end);
        switch (address) {
            .none => try std.testing.expectEqual(Address.none, decoded.address),
            .ip => |ip| try std.testing.expect(decoded.address.ip.eql(&ip)),
            .domain => |domain| try std.testing.expectEqualStrings(
                domain.host,
                decoded.address.domain.host,
            ),
        }
    }
}

test "TUIC commands parse version type and payload" {
    const uuid = [_]u8{0x42} ** 16;
    const token = [_]u8{0x24} ** 32;
    const auth = buildAuthenticate(uuid, token);
    const parsed = try parseAuthenticate(&auth);
    try std.testing.expectEqualSlices(u8, &uuid, &parsed.uuid);
    try std.testing.expectEqualSlices(u8, &token, &parsed.token);

    var bad = auth;
    bad[0] = 4;
    try std.testing.expectError(error.InvalidCommand, parseAuthenticate(&bad));

    const allocator = std.testing.allocator;
    const target = Address{ .ip = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = 80,
    } } };
    const connect = try buildConnect(allocator, target);
    defer allocator.free(connect);
    const parsed_connect = try parseConnect(connect);
    try std.testing.expect(parsed_connect.address.ip.eql(&target.ip));
}

test "TUIC stream direction helpers" {
    try std.testing.expect(isUnidirectional(2));
    try std.testing.expect(isUnidirectional(6));
    try std.testing.expect(!isUnidirectional(0));
    try std.testing.expect(!isUnidirectional(4));
    try std.testing.expect(isClientInitiated(0));
    try std.testing.expect(isClientInitiated(2));
    try std.testing.expect(!isClientInitiated(1));
}

test "TUIC Packet commands round trip and parse fragments" {
    const allocator = std.testing.allocator;
    const target = Address{ .ip = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = 53,
    } } };
    const command = try buildPacket(allocator, .{
        .assoc_id = 7,
        .pkt_id = 9,
        .frag_total = 1,
        .frag_id = 0,
        .address = target,
        .payload = "dns query",
    });
    defer allocator.free(command);
    const parsed = try parsePacket(command);
    try std.testing.expectEqual(@as(u16, 7), parsed.packet.assoc_id);
    try std.testing.expectEqual(@as(u16, 9), parsed.packet.pkt_id);
    try std.testing.expectEqual(@as(u8, 1), parsed.packet.frag_total);
    try std.testing.expectEqual(@as(u8, 0), parsed.packet.frag_id);
    try std.testing.expect(parsed.packet.address.ip.eql(&target.ip));
    try std.testing.expectEqualStrings("dns query", parsed.packet.payload);
    try std.testing.expectEqual(command.len, parsed.end);
}

test "TUIC Dissociate and heartbeat commands are bounded" {
    const command = buildDissociate(42);
    try std.testing.expectEqual(@as(u16, 42), try parseDissociate(&command));
    var bad = command;
    bad[0] = 4;
    try std.testing.expectError(error.InvalidCommand, parseDissociate(&bad));
    try std.testing.expectEqual(@as(u8, 4), heartbeat_command[1]);
}

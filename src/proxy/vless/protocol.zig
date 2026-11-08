//! VLESS request wire codec: UUID, command, and address framing.

const std = @import("std");

const net = std.Io.net;
const codec = @import("../socks/codec.zig");

pub const Uuid = [16]u8;

pub const Error = error{
    InvalidUuid,
    InvalidAddress,
    InvalidHostName,
    UnsupportedCommand,
    UnsupportedAddressType,
    BufferTooSmall,
};

pub const Command = enum(u8) {
    tcp = 1,
    udp = 2,

    pub fn fromByte(value: u8) Error!Command {
        return switch (value) {
            1 => .tcp,
            2 => .udp,
            else => error.UnsupportedCommand,
        };
    }
};

pub const AddressType = enum(u8) {
    ipv4 = 1,
    domain = 2,
    ipv6 = 3,
};

pub fn parseUuid(text: []const u8) Error!Uuid {
    var digits: [32]u8 = undefined;
    var count: usize = 0;
    for (text) |byte| {
        if (byte == '-') continue;
        if (count == digits.len) return error.InvalidUuid;
        if (!std.ascii.isHex(byte)) return error.InvalidUuid;
        digits[count] = byte;
        count += 1;
    }
    if (count != digits.len) return error.InvalidUuid;
    var uuid: Uuid = undefined;
    _ = std.fmt.hexToBytes(&uuid, &digits) catch return error.InvalidUuid;
    return uuid;
}

pub fn uuidEql(a: Uuid, b: Uuid) bool {
    var difference: u8 = 0;
    for (a, b) |lhs, rhs| difference |= lhs ^ rhs;
    return difference == 0;
}

pub const DecodedAddress = struct {
    address: codec.Address,
    end: usize,
};

/// Decode a VLESS address. VLESS carries the port separately, so `port` is
/// supplied by the caller and the returned `end` points just past the address.
pub fn decodeAddress(
    bytes: []const u8,
    offset: usize,
    port: u16,
) Error!DecodedAddress {
    if (offset >= bytes.len) return error.InvalidAddress;
    return switch (bytes[offset]) {
        1 => blk: {
            if (bytes.len - offset < 1 + 4) return error.InvalidAddress;
            break :blk .{
                .address = .{ .ip = .{ .ip4 = .{
                    .bytes = bytes[offset + 1 ..][0..4].*,
                    .port = port,
                } } },
                .end = offset + 5,
            };
        },
        2 => blk: {
            if (bytes.len - offset < 2) return error.InvalidAddress;
            const host_len = bytes[offset + 1];
            if (host_len == 0) return error.InvalidHostName;
            const end = offset + 2 + @as(usize, host_len);
            if (bytes.len < end) return error.InvalidAddress;
            const host = bytes[offset + 2 ..][0..host_len];
            _ = net.HostName.init(host) catch return error.InvalidHostName;
            break :blk .{
                .address = .{ .domain = .{
                    .host = host,
                    .port = port,
                } },
                .end = end,
            };
        },
        3 => blk: {
            if (bytes.len - offset < 1 + 16) return error.InvalidAddress;
            break :blk .{
                .address = .{ .ip = .{ .ip6 = .{
                    .bytes = bytes[offset + 1 ..][0..16].*,
                    .port = port,
                    .flow = 0,
                    .interface = .none,
                } } },
                .end = offset + 17,
            };
        },
        else => error.UnsupportedAddressType,
    };
}

pub fn encodeAddress(output: []u8, address: codec.Address) Error!usize {
    switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => |value| {
                if (output.len < 5) return error.BufferTooSmall;
                output[0] = 1;
                @memcpy(output[1..5], &value.bytes);
                return 5;
            },
            .ip6 => |value| {
                if (output.len < 17) return error.BufferTooSmall;
                output[0] = 3;
                @memcpy(output[1..17], &value.bytes);
                return 17;
            },
        },
        .domain => |domain| {
            _ = net.HostName.init(domain.host) catch return error.InvalidHostName;
            const total = 2 + domain.host.len;
            if (output.len < total) return error.BufferTooSmall;
            output[0] = 2;
            output[1] = @intCast(domain.host.len);
            @memcpy(output[2..][0..domain.host.len], domain.host);
            return total;
        },
    }
}

test "VLESS UUID parsing accepts canonical and compact forms" {
    const expected: Uuid = .{
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
        0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
    };
    try std.testing.expect(uuidEql(
        expected,
        try parseUuid("b831381d-6324-4d53-ad4f-8cda48b30811"),
    ));
    try std.testing.expect(uuidEql(
        expected,
        try parseUuid("b831381d63244d53ad4f8cda48b30811"),
    ));
    try std.testing.expectError(
        error.InvalidUuid,
        parseUuid("b831381d-6324-4d53-ad4f-8cda48b3081"),
    );
    try std.testing.expectError(
        error.InvalidUuid,
        parseUuid("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
    );
}

test "VLESS addresses round trip IPv4 domain and IPv6" {
    const addresses = [_]codec.Address{
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
    };
    for (addresses) |address| {
        var storage: [64]u8 = undefined;
        const len = try encodeAddress(&storage, address);
        const decoded = try decodeAddress(
            storage[0..len],
            0,
            address.getPort(),
        );
        try std.testing.expect(decoded.address.eql(address));
        try std.testing.expectEqual(len, decoded.end);
    }
}

test "VLESS rejects malformed address frames" {
    try std.testing.expectError(
        error.InvalidAddress,
        decodeAddress(&.{1}, 0, 80),
    );
    try std.testing.expectError(
        error.UnsupportedAddressType,
        decodeAddress(&.{ 9, 0, 0 }, 0, 80),
    );
    try std.testing.expectError(
        error.InvalidHostName,
        decodeAddress(&.{ 2, 0 }, 0, 80),
    );
    try std.testing.expectError(
        error.InvalidAddress,
        decodeAddress(&.{ 2, 4, 'a' }, 0, 80),
    );
}

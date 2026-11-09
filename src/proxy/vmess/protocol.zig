//! VMess request header codec shared by the AEAD path.
//!
//! The AEAD layer owns authentication and header encryption; this module
//! parses the plaintext request header, its address, padding, and FNV-1a
//! checksum.

const std = @import("std");

const net = std.Io.net;
const codec = @import("../socks/codec.zig");
const crypto = @import("crypto.zig");

pub const version: u8 = 1;
pub const security_none: u8 = 5;
pub const security_aes128_gcm: u8 = 3;
pub const security_chacha20_poly1305: u8 = 4;

pub const Error = error{
    UnsupportedSecurity,
    InvalidHeader,
    TruncatedHeader,
    InvalidAddress,
    InvalidHostName,
    InvalidChecksum,
    BufferTooSmall,
    UnsupportedCommand,
};

pub const Command = enum(u8) {
    tcp = 1,
    udp = 2,
};

pub const ServerSession = struct {
    body_key: [16]u8,
    body_iv: [16]u8,
    response_header: u8,
    security: u8 = security_none,
    option: u8 = 0,
};

pub const Request = struct {
    command: Command,
    address: codec.Address,
};

/// Build the plaintext VMess request header before AEAD sealing.
pub fn buildPlainHeader(
    allocator: std.mem.Allocator,
    request: Request,
    padding_len: u8,
    response_header: u8,
    body_key: [16]u8,
    body_iv: [16]u8,
    security: u8,
    option: u8,
) ![]u8 {
    if (padding_len > 15) return error.InvalidHeader;

    var plain: std.ArrayList(u8) = .empty;
    errdefer plain.deinit(allocator);
    try plain.append(allocator, version);
    try plain.appendSlice(allocator, &body_iv);
    try plain.appendSlice(allocator, &body_key);
    try plain.append(allocator, response_header);
    try plain.append(allocator, option);
    try plain.append(allocator, (padding_len << 4) | security);
    try plain.append(allocator, 0);
    try plain.append(allocator, @intFromEnum(request.command));
    try plain.append(allocator, @intCast(request.address.getPort() >> 8));
    try plain.append(allocator, @intCast(request.address.getPort() & 0xff));
    try encodeAddress(allocator, &plain, request.address);
    for (0..padding_len) |_| {
        try plain.append(allocator, 0x5a);
    }
    const checksum = crypto.fnv1a32(plain.items);
    try plain.append(allocator, @intCast(checksum >> 24));
    try plain.append(allocator, @intCast((checksum >> 16) & 0xff));
    try plain.append(allocator, @intCast((checksum >> 8) & 0xff));
    try plain.append(allocator, @intCast(checksum & 0xff));
    return plain.toOwnedSlice(allocator);
}

pub const DecodedRequest = struct {
    request: Request,
    session: ServerSession,
};

/// Parse a complete plaintext VMess request header, including padding and the
/// FNV-1a checksum.
pub fn parsePlainHeader(
    bytes: []const u8,
    host_storage: []u8,
) !DecodedRequest {
    if (bytes.len < 38) return error.TruncatedHeader;
    if (bytes[0] != version) return error.InvalidHeader;
    const session: ServerSession = .{
        .body_iv = bytes[1..17].*,
        .body_key = bytes[17..33].*,
        .response_header = bytes[33],
        .security = bytes[35] & 0x0f,
        .option = bytes[34],
    };
    const security = bytes[35] & 0x0f;
    if (security != security_none and
        security != security_aes128_gcm and
        security != security_chacha20_poly1305)
    {
        return error.UnsupportedSecurity;
    }
    const padding_len: usize = bytes[35] >> 4;
    if (padding_len > 15) return error.InvalidHeader;
    if (bytes[36] != 0) return error.InvalidHeader;
    const command: Command = switch (bytes[37]) {
        1 => .tcp,
        2 => .udp,
        else => return error.UnsupportedCommand,
    };

    var offset: usize = 38;
    if (bytes.len < offset + 2 + 1) return error.TruncatedHeader;
    const port = std.mem.readInt(u16, bytes[offset..][0..2], .big);
    offset += 2;
    const address_type = bytes[offset];
    offset += 1;

    var address: codec.Address = undefined;
    switch (address_type) {
        1 => {
            if (bytes.len < offset + 4) return error.TruncatedHeader;
            address = .{ .ip = .{ .ip4 = .{
                .bytes = bytes[offset..][0..4].*,
                .port = port,
            } } };
            offset += 4;
        },
        3 => {
            if (bytes.len < offset + 16) return error.TruncatedHeader;
            address = .{ .ip = .{ .ip6 = .{
                .bytes = bytes[offset..][0..16].*,
                .port = port,
                .flow = 0,
                .interface = .none,
            } } };
            offset += 16;
        },
        2 => {
            if (bytes.len < offset + 1) return error.TruncatedHeader;
            const host_len = bytes[offset];
            offset += 1;
            if (host_len == 0) return error.InvalidAddress;
            if (bytes.len < offset + host_len) return error.TruncatedHeader;
            const host = bytes[offset..][0..host_len];
            _ = net.HostName.init(host) catch return error.InvalidHostName;
            if (host_len > host_storage.len) return error.BufferTooSmall;
            @memcpy(host_storage[0..host_len], host);
            address = .{ .domain = .{
                .host = host_storage[0..host_len],
                .port = port,
            } };
            offset += host_len;
        },
        else => return error.InvalidAddress,
    }

    if (bytes.len < offset + padding_len + 4) return error.TruncatedHeader;
    offset += padding_len;
    const expected = std.mem.readInt(u32, bytes[offset..][0..4], .big);
    if (crypto.fnv1a32(bytes[0..offset]) != expected) {
        return error.InvalidChecksum;
    }

    return .{
        .request = .{ .command = command, .address = address },
        .session = session,
    };
}

fn encodeAddress(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    address: codec.Address,
) !void {
    switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => |value| {
                try output.append(allocator, 1);
                try output.appendSlice(allocator, &value.bytes);
            },
            .ip6 => |value| {
                try output.append(allocator, 3);
                try output.appendSlice(allocator, &value.bytes);
            },
        },
        .domain => |domain| {
            _ = net.HostName.init(domain.host) catch
                return error.InvalidHostName;
            try output.append(allocator, 2);
            try output.append(allocator, @intCast(domain.host.len));
            try output.appendSlice(allocator, domain.host);
        },
    }
}

test "VMess plain header rejects an unsupported security mode" {
    var header: [38]u8 = [_]u8{0} ** 38;
    header[0] = version;
    header[35] = 0x0f;
    header[37] = 1;
    var host_storage: [255]u8 = undefined;
    try std.testing.expectError(
        error.UnsupportedSecurity,
        parsePlainHeader(&header, &host_storage),
    );
}

//! RFC 3986 host/port parsing for HTTP request authority fields.
const std = @import("std");
const ipv6 = @import("ipv6.zig");

pub const Error = error{InvalidAuthority};
pub const Kind = enum { name, ipv6, future };
pub const Parsed = struct {
    host: []const u8,
    port: ?u16,
    kind: Kind,
    address: [16]u8 = @splat(0),
};

pub fn parse(raw: []const u8) Error!Parsed {
    if (raw.len == 0) return error.InvalidAuthority;
    if (raw[0] == '[') {
        const end = std.mem.indexOfScalar(u8, raw, ']') orelse return error.InvalidAuthority;
        const host = raw[1..end];
        if (host.len == 0) return error.InvalidAuthority;
        const suffix = raw[end + 1 ..];
        if (suffix.len != 0 and suffix[0] != ':') return error.InvalidAuthority;
        const port = if (suffix.len == 0) null else try parsePort(suffix[1..]);
        if (host[0] == 'v' or host[0] == 'V') {
            try validateFuture(host);
            return .{ .host = host, .port = port, .kind = .future };
        }
        return .{ .host = host, .port = port, .kind = .ipv6, .address = try ipv6.parse(host) };
    }
    const colon = std.mem.indexOfScalar(u8, raw, ':');
    const host = if (colon) |index| raw[0..index] else raw;
    try validateName(host);
    const port = if (colon) |index| try parsePort(raw[index + 1 ..]) else null;
    return .{ .host = host, .port = port, .kind = .name };
}

/// An empty HTTP URI port normalizes to the scheme default. CONNECT needs
/// an explicit numeric port and therefore checks the parsed result separately.
fn parsePort(raw: []const u8) Error!?u16 {
    if (raw.len == 0) return null;
    var value: u16 = 0;
    for (raw) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidAuthority;
        value = std.math.mul(u16, value, 10) catch return error.InvalidAuthority;
        value = std.math.add(u16, value, byte - '0') catch return error.InvalidAuthority;
    }
    return value;
}

fn validateName(host: []const u8) Error!void {
    if (host.len == 0) return error.InvalidAuthority;
    var index: usize = 0;
    while (index < host.len) : (index += 1) {
        const byte = host[index];
        if (unreserved(byte) or subDelimiter(byte)) continue;
        if (byte != '%' or host.len - index < 3 or
            !std.ascii.isHex(host[index + 1]) or !std.ascii.isHex(host[index + 2])) return error.InvalidAuthority;
        index += 2;
    }
}

pub fn validateFuture(host: []const u8) Error!void {
    const dot = std.mem.indexOfScalar(u8, host, '.') orelse return error.InvalidAuthority;
    if (dot <= 1 or dot + 1 == host.len) return error.InvalidAuthority;
    for (host[1..dot]) |byte| if (!std.ascii.isHex(byte)) return error.InvalidAuthority;
    for (host[dot + 1 ..]) |byte| if (!unreserved(byte) and !subDelimiter(byte) and byte != ':') return error.InvalidAuthority;
}

pub fn unreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn subDelimiter(byte: u8) bool {
    return switch (byte) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

pub fn validateConnect(raw: []const u8) Error!void {
    const value = try parse(raw);
    if (value.port == null) return error.InvalidAuthority;
}

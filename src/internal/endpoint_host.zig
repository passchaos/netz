//! Borrowed DNS/IP endpoint identity with HTTP authority formatting.
const std = @import("std");
const host_parser = @import("../http/authority/host.zig");
const net = std.Io.net;

pub const Parsed = struct {
    host: []const u8,
    literal: ?net.IpAddress = null,

    pub fn authorityAlloc(self: Parsed, allocator: std.mem.Allocator, port: u16) std.mem.Allocator.Error![]u8 {
        if (self.literal) |literal| {
            var address = literal;
            address.setPort(port);
            return std.fmt.allocPrint(allocator, "{f}", .{address});
        }
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.host, port });
    }
};

/// A separate port excludes embedded ports. Brackets are optional for IPv6
/// input and never become part of the TLS identity or resolver hostname.
pub fn parse(host: []const u8, port: u16) net.HostName.ValidateError!Parsed {
    if (std.mem.indexOfAny(u8, host, "[]:") != null) {
        const parsed = host_parser.parse(host) catch return error.InvalidHostName;
        if (parsed.kind != .ipv6 or parsed.port != null) return error.InvalidHostName;
        return .{ .host = parsed.host, .literal = .{ .ip6 = .{ .bytes = parsed.address, .port = port } } };
    }
    if (net.IpAddress.parseIp4(host, port)) |address| {
        return .{ .host = host, .literal = address };
    } else |_| {}
    _ = try net.HostName.init(host);
    return .{ .host = host };
}

test "endpoint host distinguishes DNS and IP identities and formats IPv6 authority" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { host: []const u8, identity: []const u8, authority: []const u8, literal: bool }{
        .{ .host = "example.com", .identity = "example.com", .authority = "example.com:443", .literal = false },
        .{ .host = "127.0.0.1", .identity = "127.0.0.1", .authority = "127.0.0.1:443", .literal = true },
        .{ .host = "::1", .identity = "::1", .authority = "[::1]:443", .literal = true },
        .{ .host = "[::1]", .identity = "::1", .authority = "[::1]:443", .literal = true },
        .{ .host = "0:0:0:0:0:0:0:1", .identity = "0:0:0:0:0:0:0:1", .authority = "[::1]:443", .literal = true },
        .{ .host = "[::ffff:192.0.2.1]", .identity = "::ffff:192.0.2.1", .authority = "[::ffff:192.0.2.1]:443", .literal = true },
    };
    for (cases) |case| {
        const parsed = try parse(case.host, 443);
        try std.testing.expectEqualStrings(case.identity, parsed.host);
        try std.testing.expectEqual(case.literal, parsed.literal != null);
        const text = try parsed.authorityAlloc(allocator, 443);
        defer allocator.free(text);
        try std.testing.expectEqualStrings(case.authority, text);
        if (parsed.literal) |address| try std.testing.expectEqual(@as(u16, 443), address.getPort());
    }
}

test "endpoint host rejects malformed literals and embedded ports before allocation" {
    for ([_][]const u8{ "", "[]", "[::1", "::1]", "[::1]:443", "127.0.0.1:443", "example.com:443", ":::1", "1::2::3", "[v1.future]", "[::1%eth0]", "https://example.com", "user@example.com" }) |host| {
        try std.testing.expectError(error.InvalidHostName, parse(host, 443));
    }
}

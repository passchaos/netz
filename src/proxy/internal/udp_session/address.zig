//! Numeric UDP reply host, with the protocol's separate port left out.
const std = @import("std");
const net = std.Io.net;

pub fn formatHost(buffer: []u8, address: net.IpAddress) ![]const u8 {
    return switch (address) {
        .ip4 => |ip| std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{ ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3] }),
        .ip6 => |ip| std.fmt.bufPrint(buffer, "{f}", .{net.Ip6Address.Unresolved{ .bytes = ip.bytes, .interface_name = null }}),
    };
}

test "proxy UDP reply address encodes numeric host without port" {
    var buffer: [64]u8 = undefined;
    const ip4 = net.IpAddress{ .ip4 = .loopback(18453) };
    try std.testing.expectEqualStrings("127.0.0.1", try formatHost(&buffer, ip4));
    const ip6 = try net.IpAddress.parse("2001:db8::dead:beef", 18453);
    try std.testing.expectEqualStrings("2001:db8::dead:beef", try formatHost(&buffer, ip6));
    try std.testing.expectError(error.NoSpaceLeft, formatHost(buffer[0..1], ip4));
}

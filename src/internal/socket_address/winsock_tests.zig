const std = @import("std");
const winsock = @import("winsock.zig");

const ipv4 = [_]u8{ 2, 0, 0x1f, 0x90, 192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0 };
const ipv6 = [_]u8{
    23,   0,    0x13, 0x88, 4, 3, 2, 1,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 1,
    9,    0,    0,    0,
};

test "Winsock peer address vectors match the socket ABI" {
    const address = std.os.windows.ws2_32.sockaddr;
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(address.in));
    try std.testing.expectEqual(@as(usize, 28), @sizeOf(address.in6));
    try std.testing.expectEqual(@as(usize, 2), @offsetOf(address.in, "port"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(address.in, "addr"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(address.in6, "flowinfo"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(address.in6, "addr"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(address.in6, "scope_id"));
}

test "Winsock peer address decodes fixed IPv4 and IPv6 vectors" {
    const a = winsock.decode(&ipv4).?.ip4;
    try std.testing.expectEqual(@as(u16, 8080), a.port);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, &a.bytes);
    const b = winsock.decode(&ipv6).?.ip6;
    try std.testing.expectEqual(@as(u16, 5000), b.port);
    try std.testing.expectEqual(@as(u32, 0x01020304), b.flow);
    try std.testing.expectEqualSlices(u8, ipv6[8..24], &b.bytes);
    try std.testing.expectEqual(@as(u32, 9), b.interface.index);
}

test "Winsock connect address encoding matches fixed IPv4 and IPv6 vectors" {
    const a = winsock.Encoded.init(winsock.decode(&ipv4).?);
    const b = winsock.Encoded.init(winsock.decode(&ipv6).?);
    try std.testing.expectEqualSlices(u8, &ipv4, a.bytes[0..a.len]);
    try std.testing.expectEqualSlices(u8, &ipv6, b.bytes[0..b.len]);
}

test "Winsock peer address rejects truncated and non-IP outputs" {
    for (0..ipv4.len) |length| try std.testing.expect(winsock.decode(ipv4[0..length]) == null);
    for (0..ipv6.len) |length| try std.testing.expect(winsock.decode(ipv6[0..length]) == null);
    try std.testing.expect(winsock.decode(&.{ 1, 0 }) == null);
    try std.testing.expect(winsock.decode(&.{ 255, 255 }) == null);
}

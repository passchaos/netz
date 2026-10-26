const std = @import("std");
const authority = @import("mod.zig");

test "HTTP authority accepts URI hosts and bounded numeric ports" {
    for ([_][]const u8{ "example.test", "example.test:", "example.test:00080", "[2001:db8::1]:443", "[::ffff:192.0.2.1]", "[v1.a:b]:0", "%65xample.test", "a!$&'()*+,;=b.test" }) |raw| _ = try authority.parse(raw);
    for ([_][]const u8{ "", ":80", "user@example.test", "bad host", "bad\\host", "a/b", "a?b", "a#b", "bad\xff", "bad%", "bad%0", "bad%zz", "[invalid]", "[::1", "[::1]suffix", "[::1]]", "::1", "[fe80::1%25eth0]", "[v.a]", "[v1.]", "[v1.a/b]", "host:65536", "host:999999999999", "host:+80", "host:-1", "host:80:90" }) |raw| try std.testing.expectError(error.InvalidAuthority, authority.parse(raw));
    try std.testing.expectEqual(@as(u16, 65535), (try authority.parse("host:65535")).port.?);
    try authority.validateConnect("example.test:443");
    try authority.validateConnect("[::1]:443");
    try std.testing.expectError(error.InvalidAuthority, authority.validateConnect("example.test:"));
    try std.testing.expectError(error.InvalidAuthority, authority.validateConnect("example.test"));
}

test "HTTP authority normalizes default ports percent escapes and IPv6 literals" {
    const Case = struct { scheme: []const u8 = "https", left: []const u8, right: []const u8 };
    for ([_]Case{
        .{ .left = "Example.TEST", .right = "example.test:443" },
        .{ .left = "example.test:", .right = "example.test:00443" },
        .{ .scheme = "HTTP", .left = "EXAMPLE.TEST", .right = "example.test:080" },
        .{ .left = "%65xample.test", .right = "example.test" },
        .{ .left = "a%7Eb.test", .right = "a~b.test" },
        .{ .left = "a%2Fb.test", .right = "a%2fb.test" },
        .{ .left = "[2001:DB8:0:0:0:0:0:1]", .right = "[2001:db8::1]:443" },
        .{ .left = "[::ffff:192.0.2.1]", .right = "[::ffff:c000:201]" },
        .{ .left = "[v1.A:B]", .right = "[V1.a:b]:443" },
        .{ .scheme = "custom", .left = "example.test", .right = "EXAMPLE.test:" },
    }) |case| {
        if (!authority.equivalent(case.scheme, case.left, case.right)) std.debug.print("authority mismatch: {s} {s} {s}\n", .{ case.scheme, case.left, case.right });
        try std.testing.expect(authority.equivalent(case.scheme, case.left, case.right));
        try std.testing.expect(authority.equivalent(case.scheme, case.right, case.left));
    }
    for ([_]Case{
        .{ .left = "example.test", .right = "example.test:80" },
        .{ .scheme = "", .left = "example.test:443", .right = "example.test" },
        .{ .scheme = "custom", .left = "example.test:80", .right = "example.test" },
        .{ .left = "example.test", .right = "other.test" },
        .{ .left = "a%2Bb.test", .right = "a+b.test" },
        .{ .left = "[::1]", .right = "[::2]" },
        .{ .left = "[::1]", .right = "::1" },
        .{ .left = "[invalid]", .right = "[invalid]" },
    }) |case| try std.testing.expect(!authority.equivalent(case.scheme, case.left, case.right));
}

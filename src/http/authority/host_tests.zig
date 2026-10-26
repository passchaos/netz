const std = @import("std");
const host = @import("host.zig");

test "HTTP origin host canonicalization agrees with equality and hashing" {
    const cases = [_][3][]const u8{
        .{ "%45xample.TEST", "example.test", "example.test" },
        .{ "a%7Eb.test", "A~B.TEST", "a~b.test" },
        .{ "[2001:DB8:0:0:0:0:0:1]", "2001:db8::1", "2001:db8::1" },
        .{ "::ffff:c000:201", "[::ffff:192.0.2.1]", "::ffff:192.0.2.1" },
        .{ "[V1.A]", "[v1.a]", "[v1.a]" },
    };
    for (cases) |row| {
        try std.testing.expect(host.equivalent(row[0], row[1]));
        try std.testing.expectEqual(try host.hash(row[0]), try host.hash(row[1]));
        for (row[0..2]) |text| {
            const canonical = try host.canonicalAlloc(std.testing.allocator, text);
            defer std.testing.allocator.free(canonical);
            try std.testing.expectEqualStrings(row[2], canonical);
            try std.testing.expectEqual(try host.hash(text), try host.hash(canonical));
            var buffer: [256]u8 = undefined;
            try std.testing.expectEqualStrings(canonical, try host.canonicalInto(&buffer, text));
        }
    }
    try std.testing.expect(!host.equivalent("[v1.a]", "v1.a"));
    try std.testing.expect(!host.equivalent("::1", "::2"));
    try std.testing.expect(!host.equivalent("a%2Fb.test", "a/b.test"));
    try std.testing.expect(!host.equivalent("[invalid]", "[invalid]"));
}

test "HTTP origin host canonicalization validates before allocation and owns results" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    for ([_][]const u8{ "", "[invalid]", "host:443", "bad%GG", "::1%eth0" }) |text| try std.testing.expectError(error.InvalidAuthority, host.canonicalAlloc(failing.allocator(), text));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const name = try host.canonicalAlloc(allocator, "%45xample.test");
    defer allocator.free(name);
    const address = try host.canonicalAlloc(allocator, "2001:DB8:0:0:0:0:0:1");
    defer allocator.free(address);
    const future = try host.canonicalAlloc(allocator, "[V1.A]");
    defer allocator.free(future);
    try std.testing.expectEqualStrings("example.test", name);
    try std.testing.expectEqualStrings("2001:db8::1", address);
    try std.testing.expectEqualStrings("[v1.a]", future);
}

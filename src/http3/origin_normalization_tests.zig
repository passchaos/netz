const std = @import("std");
const http3 = @import("mod.zig");
const pools = @import("origin_pool.zig");

const Pair = struct { authority: []const u8, alias: []const u8, canonical: []const u8 };
const pairs = [_]Pair{
    .{ .authority = "%45xample.TEST", .alias = "example.test:443", .canonical = "example.test" },
    .{ .authority = "[2001:DB8:0:0:0:0:0:1]", .alias = "[2001:db8::1]:443", .canonical = "2001:db8::1" },
    .{ .authority = "[::ffff:c000:201]", .alias = "[::ffff:192.0.2.1]:443", .canonical = "::ffff:192.0.2.1" },
};

test "HTTP/3 origin identity keys and pool indexes share canonical hosts" {
    const Drop = struct {
        fn drop(_: std.mem.Allocator, _: usize) void {}
    };
    const Pool = pools.Pool(usize);
    for (pairs) |pair| {
        var pool = Pool.init(std.testing.allocator, .{ .max_idle_per_origin = 1 }, Drop.drop);
        defer pool.deinit();
        const original = try http3.requestOrigin("https", pair.authority);
        const alias = try http3.requestOrigin("HTTPS", pair.alias);
        try std.testing.expect(http3.sameOrigin(original, alias));
        try std.testing.expectEqual(http3.ReuseDecision.same_origin, http3.connectionReuseDecision(original, alias));
        var key = try http3.originKeyFromOrigin(std.testing.allocator, original);
        defer key.deinit();
        try std.testing.expectEqualStrings(pair.canonical, key.host);
        try pool.release(1, original, 1);
        try std.testing.expectEqual(@as(usize, 1), pool.idleCountForOrigin(alias));
        try pool.release(2, alias, 2);
        try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
        try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
        try std.testing.expectEqual(@as(?usize, 1), pool.acquire(alias, 3));
        try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
        const Policy = struct {
            fn allows(_: *const anyopaque, stored: http3.Origin, requested: http3.Origin, _: *const usize) bool {
                return http3.sameOrigin(stored, requested);
            }
        };
        var context: u8 = 0;
        try pool.release(3, original, 4);
        var acquired = pool.acquireMatching(alias, 5, .{ .context = &context, .allows = Policy.allows }) orelse return error.TestUnexpectedResult;
        defer acquired.key.deinit();
        try std.testing.expect(acquired.exact_origin);
        try std.testing.expectEqual(@as(usize, 3), acquired.handle);
        try std.testing.expect(!http3.sameOrigin(original, .{ .scheme = "http", .host = alias.host, .port = alias.port }));
        try std.testing.expect(!http3.sameOrigin(original, .{ .scheme = "https", .host = alias.host, .port = 8443 }));
    }
}

test "HTTP/3 ORIGIN normalization deduplicates and removes every equivalent alias" {
    const allocator = std.testing.allocator;
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    control.settings.received = true;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.OriginPayload.write(&bytes, allocator, &.{
        "https://[2001:DB8:0:0:0:0:0:1]", "https://[2001:db8::1]:443",
        "https://%65xample.test",         "https://example.test:443",
        "https://[v1.a]",                 "https://v1.a",
    });
    try control.applyFrame(allocator, try http3.Frame.parse(bytes.items));
    try std.testing.expectEqual(@as(usize, 4), control.peerOrigins().len);
    const original = try http3.requestOrigin("https", "[2001:db8::1]");
    const alias = try http3.requestOrigin("https", "[2001:db8:0:0:0:0:0:1]:443");
    try std.testing.expect(control.peerOriginKnown(alias));
    try control.removePeerOrigin(allocator, alias);
    try std.testing.expect(control.peerOriginExcluded(original));
    try std.testing.expectEqual(false, control.peerOriginSetAllows(try http3.requestOrigin("https", "initial.test"), original).?);
    try std.testing.expectEqual(@as(usize, 3), control.peerOrigins().len);
    bytes.clearRetainingCapacity();
    try http3.OriginPayload.write(&bytes, allocator, &.{"https://[2001:db8::1]"});
    try control.applyFrame(allocator, try http3.Frame.parse(bytes.items));
    try std.testing.expect(!control.peerOriginExcluded(alias));
    try std.testing.expect(control.peerOriginKnown(alias));
    try std.testing.expect(!http3.sameOrigin(try http3.requestOrigin("https", "[v1.a]"), try http3.requestOrigin("https", "v1.a")));
}

test "HTTP/3 canonical origin key allocation failures retain ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    for (pairs) |pair| {
        var key = try http3.requestOriginKey(allocator, "HTTPS", pair.authority);
        defer key.deinit();
        try std.testing.expectEqualStrings(pair.canonical, key.host);
    }
}

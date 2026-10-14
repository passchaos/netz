const std = @import("std");
const cache_mod = @import("alt_svc_cache.zig");
const http3 = @import("../http3/mod.zig");

test "Alt-Svc cache applies max-age clear and replacement transactionally" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = try cache_mod.Cache.init(std.testing.allocator, threaded.io(), .{});
    defer cache.deinit();
    const origin: http3.Origin = .{
        .scheme = "HTTPS",
        .host = "Example.COM",
        .port = 443,
    };
    const advertised = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "Alt-Svc", .value = "h3=\"alt.EXAMPLE:8443\"; ma=2" },
    };
    try std.testing.expectEqual(
        cache_mod.UpdateResult.stored,
        try cache.updateFromHeadersAt(origin, &advertised, 1000),
    );
    var alternative = (try cache.lookupAt(origin, 2999)).?;
    defer alternative.deinit();
    try std.testing.expectEqualStrings("h3", alternative.alpn);
    try std.testing.expectEqualStrings("alt.example", alternative.connect_host);
    try std.testing.expectEqual(@as(u16, 8443), alternative.port);
    try std.testing.expect((try cache.lookupAt(origin, 3000)) == null);

    const inherited = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "alt-svc", .value = "h3=\":443\"" },
    };
    try std.testing.expectEqual(
        cache_mod.UpdateResult.stored,
        try cache.updateFromHeadersAt(origin, &inherited, 4000),
    );
    const malformed = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "alt-svc", .value = "h3=\":bad\"" },
    };
    try std.testing.expectError(
        error.InvalidHeader,
        cache.updateFromHeadersAt(origin, &malformed, 5000),
    );
    var retained = (try cache.lookupAt(origin, 5000)).?;
    retained.deinit();

    const zero_age = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "alt-svc", .value = "h3=\":443\"; ma=0" },
    };
    try std.testing.expectEqual(
        cache_mod.UpdateResult.removed,
        try cache.updateFromHeadersAt(origin, &zero_age, 5500),
    );
    _ = try cache.updateFromHeadersAt(origin, &inherited, 5600);

    const clear = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "alt-svc", .value = "clear" },
    };
    try std.testing.expectEqual(
        cache_mod.UpdateResult.removed,
        try cache.updateFromHeadersAt(origin, &clear, 6000),
    );
    try std.testing.expect((try cache.lookupAt(origin, 6000)) == null);
}

test "Alt-Svc cache preserves exponential backoff across refresh" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = try cache_mod.Cache.init(std.testing.allocator, threaded.io(), .{
        .failure_backoff_initial = .fromMilliseconds(10),
        .failure_backoff_max = .fromMilliseconds(40),
    });
    defer cache.deinit();
    const origin: http3.Origin = .{
        .scheme = "https",
        .host = "backoff.example",
        .port = 443,
    };
    const headers = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "alt-svc", .value = "h3=\":443\"; ma=60" },
    };
    _ = try cache.updateFromHeadersAt(origin, &headers, 100);
    try std.testing.expect(cache.recordFailureAt(origin, 100));
    try std.testing.expect((try cache.lookupAt(origin, 109)) == null);
    _ = try cache.updateFromHeadersAt(origin, &headers, 105);
    try std.testing.expect((try cache.lookupAt(origin, 109)) == null);
    var first_retry = (try cache.lookupAt(origin, 110)).?;
    first_retry.deinit();

    try std.testing.expect(cache.recordFailureAt(origin, 110));
    try std.testing.expect((try cache.lookupAt(origin, 129)) == null);
    var second_retry = (try cache.lookupAt(origin, 130)).?;
    try std.testing.expectEqual(@as(u8, 2), second_retry.failure_count);
    second_retry.deinit();
    try std.testing.expect(cache.recordSuccessAt(origin, 130));
    var reset = (try cache.lookupAt(origin, 130)).?;
    try std.testing.expectEqual(@as(u8, 0), reset.failure_count);
    reset.deinit();
}

test "Alt-Svc cache evicts true LRU and isolates origins" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var cache = try cache_mod.Cache.init(std.testing.allocator, threaded.io(), .{
        .max_entries = 2,
    });
    defer cache.deinit();
    const headers = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "alt-svc", .value = "h3=\":443\"; ma=60" },
    };
    const first: http3.Origin = .{ .scheme = "https", .host = "a.example", .port = 443 };
    const second: http3.Origin = .{ .scheme = "https", .host = "b.example", .port = 443 };
    const third: http3.Origin = .{ .scheme = "https", .host = "c.example", .port = 443 };
    _ = try cache.updateFromHeadersAt(first, &headers, 0);
    _ = try cache.updateFromHeadersAt(second, &headers, 0);
    var touch = (try cache.lookupAt(first, 1)).?;
    touch.deinit();
    _ = try cache.updateFromHeadersAt(third, &headers, 2);
    try std.testing.expect((try cache.lookupAt(second, 2)) == null);
    var first_value = (try cache.lookupAt(first, 2)).?;
    first_value.deinit();
    var third_value = (try cache.lookupAt(third, 2)).?;
    third_value.deinit();
    try std.testing.expectEqual(@as(usize, 2), cache.countAt(2));
    try std.testing.expectEqual(@as(u64, 1), cache.statsAt(2).evicted);
}

test "Alt-Svc cache allocation failures leave no partial entry" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var cache = try cache_mod.Cache.init(allocator, threaded.io(), .{});
            defer cache.deinit();
            const origin: http3.Origin = .{
                .scheme = "https",
                .host = "allocation.example",
                .port = 443,
            };
            const headers = [_]struct { name: []const u8, value: []const u8 }{
                .{ .name = "alt-svc", .value = "h3=\"alt.example:8443\"; ma=60" },
            };
            try std.testing.expectEqual(
                cache_mod.UpdateResult.stored,
                try cache.updateFromHeadersAt(origin, &headers, 0),
            );
            var alternative = (try cache.lookupAt(origin, 1)).?;
            alternative.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Exercise.run,
        .{},
    );
}

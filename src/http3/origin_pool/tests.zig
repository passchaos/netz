const std = @import("std");
const origin_pool_root = @import("../origin_pool.zig");

const http3 = @import("../mod.zig");

const Pool = origin_pool_root.Pool;
const countDrop = origin_pool_root.countDrop;
const dropInt = origin_pool_root.dropInt;

test "HTTP/3 origin pool releases and acquires by normalized origin" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{}, dropInt);
    defer pool.deinit();

    const origin = try http3.requestOrigin("https", "Example.COM");
    try pool.release(42, origin, 1000);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.origin_index.count());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCountForOrigin(
        try http3.requestOrigin("HTTPS", "example.com:443"),
    ));

    try std.testing.expectEqual(@as(?usize, 42), pool.acquire(
        try http3.requestOrigin("https", "example.com:443"),
        1500,
    ));
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.origin_index.count());
    const stats = pool.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.total_reused);
    try std.testing.expectEqual(@as(f64, 1.0), stats.hitRate());
    try std.testing.expectEqual(@as(f64, 1.0), pool.hitRate());
}

test "HTTP/3 origin pool matching prefers exact then oldest authorized origin" {
    const allocator = std.testing.allocator;
    const Drop = struct {
        fn drop(_: std.mem.Allocator, _: usize) void {}
    };
    const HandlePool = Pool(usize);
    var pool = HandlePool.init(allocator, .{
        .max_idle_per_origin = 2,
        .max_idle_total = 4,
    }, Drop.drop);
    defer pool.deinit();

    const origin_a = try http3.requestOrigin("https", "a.example");
    const origin_b = try http3.requestOrigin("https", "b.example");
    const origin_c = try http3.requestOrigin("https", "c.example");
    try pool.release(11, origin_b, 1);
    try pool.release(22, origin_a, 2);

    const Policy = struct {
        fn allowAll(
            _: *const anyopaque,
            _: http3.Origin,
            _: http3.Origin,
            _: *const usize,
        ) bool {
            return true;
        }

        fn allowB(
            context: *const anyopaque,
            connection_origin: http3.Origin,
            _: http3.Origin,
            _: *const usize,
        ) bool {
            const allowed: *const http3.Origin = @ptrCast(@alignCast(context));
            return http3.sameOrigin(connection_origin, allowed.*);
        }
    };
    const context: u8 = 0;
    var exact = pool.acquireMatching(origin_a, 3, .{
        .context = &context,
        .allows = Policy.allowAll,
    }).?;
    defer exact.key.deinit();
    try std.testing.expect(exact.exact_origin);
    try std.testing.expectEqual(@as(usize, 22), exact.handle);

    var cross = pool.acquireMatching(origin_c, 4, .{
        .context = &origin_b,
        .allows = Policy.allowB,
    }).?;
    defer cross.key.deinit();
    try std.testing.expect(!cross.exact_origin);
    try std.testing.expectEqual(@as(usize, 11), cross.handle);
    try std.testing.expect(http3.sameOrigin(
        origin_b,
        cross.key.origin(),
    ));
}

test "HTTP/3 origin pool preserves global LRU across swap removal" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{
        .max_idle_per_origin = 3,
        .max_idle_total = 3,
        .idle_timeout_ms = 100,
    }, dropInt);
    defer pool.deinit();

    const a = try http3.requestOrigin("https", "a.example");
    const b = try http3.requestOrigin("https", "b.example");
    try pool.release(1, a, 0);
    try pool.release(2, a, 1);
    try pool.release(3, b, 2);
    try std.testing.expectEqual(@as(usize, 2), pool.origin_index.count());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCountForOrigin(a));
    try std.testing.expectEqual(@as(usize, 1), pool.idleCountForOrigin(b));

    try std.testing.expectEqual(@as(?usize, 1), pool.acquire(a, 3));
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCountForOrigin(a));
    try std.testing.expectEqual(@as(usize, 1), pool.idleCountForOrigin(b));

    const c = try http3.requestOrigin("https", "c.example");
    try pool.release(4, c, 4);
    try pool.release(5, c, 5);
    // Acquiring handle 1 swap-moves newer handle 3 into array index zero. The
    // subsequent capacity eviction must still retire handle 2, whose release
    // timestamp is oldest, rather than confusing array position with age.
    try std.testing.expectEqual(@as(usize, 3), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 2), pool.origin_index.count());
    try std.testing.expect(pool.acquire(a, 6) == null);
    try std.testing.expectEqual(@as(?usize, 3), pool.acquire(b, 6));
    try std.testing.expectEqual(@as(?usize, 4), pool.acquire(c, 6));
    try std.testing.expectEqual(@as(?usize, 5), pool.acquire(c, 6));
    try std.testing.expectEqual(@as(usize, 0), pool.origin_index.count());
}

test "HTTP/3 origin pool breaks equal-time LRU ties by release order" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{
        .max_idle_per_origin = 2,
        .max_idle_total = 2,
    }, dropInt);
    defer pool.deinit();

    const a = try http3.requestOrigin("https", "a.example");
    const b = try http3.requestOrigin("https", "b.example");
    const c = try http3.requestOrigin("https", "c.example");
    try pool.release(1, a, 10);
    try pool.release(2, b, 10);
    try pool.release(3, c, 10);

    try std.testing.expect(pool.acquire(a, 10) == null);
    try std.testing.expectEqual(@as(?usize, 2), pool.acquire(b, 10));
    try std.testing.expectEqual(@as(?usize, 3), pool.acquire(c, 10));
}

test "HTTP/3 origin pool accepts owned origin keys" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{}, dropInt);
    defer pool.deinit();

    const key = try http3.requestOriginKey(allocator, "HTTPS", "Owned.EXAMPLE:443");
    try pool.releaseKey(7, key, 10);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(?usize, 7), pool.acquire(
        try http3.requestOrigin("https", "owned.example"),
        11,
    ));

    const disabled_key = try http3.requestOriginKey(allocator, "https", "drop.example");
    var disabled = IntPool.init(allocator, .{ .max_idle_total = 0 }, dropInt);
    defer disabled.deinit();
    try disabled.releaseKey(9, disabled_key, 0);
    try std.testing.expectEqual(@as(usize, 0), disabled.idleCount());
    try std.testing.expectEqual(@as(u64, 1), disabled.stats().total_dropped);
}

test "HTTP/3 origin pool releaseKey is transactional on allocation failure" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const CounterPool = Pool(*usize);
    var pool = CounterPool.init(failing.allocator(), .{}, countDrop);
    defer pool.deinit();

    var drops: usize = 0;
    const key = try http3.requestOriginKey(allocator, "https", "oom.example");
    try std.testing.expectError(
        error.OutOfMemory,
        pool.releaseKey(&drops, key, 0),
    );
    try std.testing.expectEqual(@as(usize, 0), drops);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 0), pool.stats().total_dropped);
}

test "HTTP/3 origin pool disabled release does not allocate" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const CounterPool = Pool(*usize);
    var pool = CounterPool.init(failing.allocator(), .{ .max_idle_total = 0 }, countDrop);
    defer pool.deinit();

    var drops: usize = 0;
    try pool.release(&drops, try http3.requestOrigin("https", "disabled.example"), 0);
    try std.testing.expectEqual(@as(usize, 1), drops);
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
}

test "HTTP/3 origin pool enforces expiry and capacity" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{
        .max_idle_per_origin = 1,
        .max_idle_total = 2,
        .idle_timeout_ms = 10,
    }, dropInt);
    defer pool.deinit();

    const a = try http3.requestOrigin("https", "a.example");
    const b = try http3.requestOrigin("https", "b.example");
    const c = try http3.requestOrigin("https", "c.example");
    try pool.release(1, a, 0);
    try pool.release(2, a, 1); // per-origin overflow: dropped.
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
    try pool.release(3, b, 2);
    try pool.release(4, c, 3); // total overflow evicts oldest.
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
    try std.testing.expect(pool.acquire(a, 4) == null);
    try std.testing.expectEqual(@as(u64, 1), pool.getStats().total_misses);

    // Expired b is removed while searching, then c is returned before its own
    // idle timeout elapses.
    try std.testing.expectEqual(@as(?usize, 4), pool.acquire(c, 13));
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 3), pool.stats().total_dropped);
}

test "HTTP/3 origin pool prunes expired idle handles explicitly" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{ .idle_timeout_ms = 10 }, dropInt);
    defer pool.deinit();

    try pool.release(1, try http3.requestOrigin("https", "a.example"), 0);
    try pool.release(2, try http3.requestOrigin("https", "b.example"), 5);
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());

    try std.testing.expectEqual(@as(usize, 1), pool.pruneExpired(11));
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
    try std.testing.expectEqual(@as(?usize, 2), pool.acquire(
        try http3.requestOrigin("https", "b.example"),
        12,
    ));
}

test "HTTP/3 origin pool release ignores expired capacity occupants" {
    const allocator = std.testing.allocator;
    const IntPool = Pool(usize);
    var pool = IntPool.init(allocator, .{
        .max_idle_per_origin = 1,
        .max_idle_total = 1,
        .idle_timeout_ms = 10,
    }, dropInt);
    defer pool.deinit();

    const origin = try http3.requestOrigin("https", "slot.example");
    try pool.release(1, origin, 0);
    try pool.release(2, origin, 11);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_dropped);
    try std.testing.expectEqual(@as(?usize, 2), pool.acquire(origin, 12));
}

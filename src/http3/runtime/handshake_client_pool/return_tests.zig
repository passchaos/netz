const std = @import("std");
const support = @import("../../../internal/retired_capacity/h3_test_support.zig");
const budget_mod = @import("../../../internal/connection_budget.zig");

test "HTTP/3 pool deadline close retains published client while an admitted publisher is pending" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();
    var trace = support.Trace{ .base = io, .budget = budget, .reusable = true };
    var pool = try support.Pool.init(std.testing.allocator, io, .{ .local_address = .{ .ip4 = .loopback(0) }, .shared_connection_budget = budget, .connector = trace.connector() });
    defer pool.deinit();
    var lease = try pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1));
    lease.release();
    pool.returns.publishers.store(1, .release);
    var admitted = true;
    defer if (admitted) {
        _ = pool.returns.publishers.fetchSub(1, .release);
    };
    try std.testing.expectError(error.Timeout, pool.closeWithTimeout(.fromMilliseconds(10)));
    try std.testing.expect(pool.closed);
    try std.testing.expect(pool.returns.head.load(.acquire) != null);
    try std.testing.expectEqual(@as(usize, 0), trace.drops);
    _ = pool.returns.publishers.fetchSub(1, .release);
    admitted = false;
    try pool.closeWithTimeout(.fromSeconds(1));
    try pool.closeWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
}

test "HTTP/3 pool deadline close preserves a checked out lease until its owner returns" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var trace = support.Trace{ .base = io, .reusable = true };
    var pool = try support.Pool.init(std.testing.allocator, io, .{ .local_address = .{ .ip4 = .loopback(0) }, .connector = trace.connector() });
    defer pool.deinit();
    var lease = try pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1));
    pool.mutex.lockUncancelable(io);
    var locked = true;
    defer if (locked) pool.mutex.unlock(io);
    try std.testing.expectError(error.Timeout, pool.closeWithTimeout(.fromMilliseconds(10)));
    try std.testing.expect(!pool.closed and !pool.mutex.tryLock());
    pool.mutex.unlock(io);
    locked = false;
    try pool.closeWithTimeout(.fromSeconds(1));
    try std.testing.expect(lease.active);
    try std.testing.expectEqual(@as(usize, 0), trace.drops);
    try std.testing.expectEqual(@as(usize, 1), pool.leasedCount());
    lease.release();
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
}

test "HTTP/3 pool collector delay preserves the original returned connection idle age" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var trace = support.Trace{ .base = io, .reusable = true };
    var pool = try support.Pool.init(std.testing.allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .connector = trace.connector(),
    });
    defer pool.deinit();
    var lease = try pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1));
    const Clock = struct {
        var time_ms: u64 = 1000;
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return .fromNanoseconds(@as(i96, time_ms) * std.time.ns_per_ms);
        }
    };
    var table = io.vtable.*;
    table.now = Clock.now;
    pool.io = .{ .userdata = io.userdata, .vtable = &table };
    defer pool.io = io;
    Clock.time_ms = 1000;
    lease.release();
    Clock.time_ms = 1001 + pool.options.idle.idle_timeout_ms;
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/3 pool connection return preserves client ownership under occupied pool mutex" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();
    var trace = support.Trace{ .base = io, .budget = budget, .reusable = true };
    var pool = try support.Pool.init(std.testing.allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .shared_connection_budget = budget,
        .connector = trace.connector(),
    });
    defer pool.deinit();
    var lease = try pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1));
    defer lease.discard();
    const node = lease.return_node;
    pool.mutex.lockUncancelable(io);
    var held = true;
    defer if (held) pool.mutex.unlock(io);
    lease.release();
    lease.release();
    lease.discard();
    try std.testing.expect(!lease.active);
    try std.testing.expect(!pool.mutex.tryLock());
    try std.testing.expect(pool.returns.head.load(.acquire) == node);
    try std.testing.expectEqual(@as(usize, 0), trace.drops);
    try std.testing.expectEqual(@as(usize, 1), pool.connections);
    pool.mutex.unlock(io);
    held = false;
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    var next = try pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1));
    try std.testing.expect(next.was_reused and next.return_node == node);
    next.release();
    pool.close();
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
}

test "HTTP/3 pool late return after close retires resource and lease counts once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var trace = support.Trace{ .base = io, .reusable = true };
    var pool = try support.Pool.init(std.testing.allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .connector = trace.connector(),
    });
    defer pool.deinit();
    var lease = try pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1));
    pool.close();
    pool.mutex.lockUncancelable(io);
    var held = true;
    defer if (held) pool.mutex.unlock(io);
    lease.release();
    lease.release();
    lease.discard();
    try std.testing.expect(!pool.mutex.tryLock());
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    pool.mutex.unlock(io);
    held = false;
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
}

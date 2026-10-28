const std = @import("std");
const support = @import("../../../internal/retired_capacity/h3_test_support.zig");
const budget_mod = @import("../../../internal/connection_budget.zig");

test "HTTP/3 pool closing during connect destroys the client before retiring once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();
    var trace = support.Trace{ .base = io, .budget = budget, .close_during_connect = true };
    var pool = try support.Pool.init(std.testing.allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .shared_connection_budget = budget,
        .connector = trace.connector(),
    });
    defer pool.deinit();
    trace.pool = &pool;
    try std.testing.expectError(error.PoolClosed, pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1)));
    try std.testing.expect(trace.called);
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    try std.testing.expect(trace.dropped_before_budget_release);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
}

test "HTTP/3 pool failed connection retirement returns under cleanup contention" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |shared| {
        for ([_]support.Runtime.Error{ error.Timeout, error.Canceled, error.NetworkUnreachable }) |failure| {
            const budget = try budget_mod.Budget.create(std.testing.allocator, base, 1);
            defer budget.deinit();
            var trace = support.Trace{ .base = base, .budget = budget, .failure = failure };
            var pool = try support.Pool.init(std.testing.allocator, base, .{
                .local_address = .{ .ip4 = .loopback(0) },
                .shared_connection_budget = budget,
                .connector = trace.connector(),
            });
            defer pool.deinit();
            trace.pool = &pool;
            trace.held_mutex = if (shared) &budget.mutex else &pool.mutex;
            var table: std.Io.VTable = undefined;
            pool.io = trace.io(&table);
            budget.io = pool.io;
            defer {
                trace.restore();
                pool.io = base;
                budget.io = base;
            }
            try std.testing.expectError(failure, pool.acquireUriWithTimeout("https://127.0.0.1/", .fromSeconds(1)));
            try std.testing.expect(trace.called);
            try std.testing.expectEqual(@as(usize, 0), trace.unbounded_waits);
            try std.testing.expectEqual(@as(usize, 0), trace.drops);
            try std.testing.expect(!trace.held_mutex.?.tryLock());
            try std.testing.expectEqual(@as(usize, 1), if (shared) budget.connections else pool.connections);
            trace.restore();
            pool.io = base;
            budget.io = base;
            try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
            try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
            try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
        }
    }
}

test "HTTP/3 pool bounds final connection admission and retires a completed client once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, base, 1);
    defer budget.deinit();
    var trace = support.Trace{ .base = base, .budget = budget };
    var pool = try support.Pool.init(std.testing.allocator, base, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .shared_connection_budget = budget,
        .connector = trace.connector(),
    });
    defer pool.deinit();
    trace.pool = &pool;
    trace.held_mutex = &pool.mutex;
    var table: std.Io.VTable = undefined;
    pool.io = trace.io(&table);
    budget.io = pool.io;
    defer {
        trace.restore();
        pool.io = base;
        budget.io = base;
    }
    const result = pool.acquireUriWithTimeout("https://127.0.0.1/", .fromMilliseconds(100));
    // Rescue leaves the old code's lock released; clean up its unexpected
    // lease before reporting the deadline failure.
    if (result) |value| {
        var lease = value;
        trace.restore();
        lease.discard();
        return error.UnexpectedLeaseAfterContendedAdmission;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    try std.testing.expectEqual(@as(usize, 0), trace.unbounded_waits);
    try std.testing.expectEqual(@as(usize, 1), trace.drops);
    try std.testing.expect(trace.dropped_before_budget_release);
    try std.testing.expect(!pool.mutex.tryLock());
    trace.restore();
    pool.io = base;
    budget.io = base;
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
}

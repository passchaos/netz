//! Unified close retains incomplete TCP, H3 and cache cleanup for a retry.
const std = @import("std");
const Guard = @import("../../internal/mutex_guard.zig").Guard;
const deadline_policy = @import("../../internal/deadline.zig");
const owning_close = @import("../../internal/pool_returns/close.zig");
pub const Error = owning_close.Error;

pub fn close(pool: anytype) void {
    closeBefore(pool, null) catch unreachable;
}

pub fn closeWithTimeout(pool: anytype, timeout: std.Io.Duration) Error!void {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return closeWithDeadline(pool, .fromNow(pool.io, .{ .clock = .awake, .raw = timeout }));
}

pub fn closeWithDeadline(pool: anytype, deadline: std.Io.Clock.Timestamp) Error!void {
    _ = try deadline_policy.usableAwake(pool.io, deadline);
    return closeBefore(pool, deadline);
}

fn closeBefore(pool: anytype, deadline: ?std.Io.Clock.Timestamp) Error!void {
    var guard = try Guard.initBefore(&pool.mutex, pool.io, deadline);
    defer guard.unlock();
    pool.retired_connections.apply(&pool.connections, &pool.capacity_waiters, pool.io);
    pool.closed = true;
    pool.capacity_waiters.notifyAll(pool.io);
    {
        var current = try pool.returns.closeBefore(pool.io, deadline);
        errdefer pool.returns.restore(current);
        while (current) |node| {
            if (deadline) |until| _ = try deadline_policy.usableAwake(pool.io, until);
            current = node.next;
            var connection = node.value.connection_value;
            var key = node.value.origin_key;
            const result = owning_close.transport(&connection, deadline);
            key.deinit();
            node.destroy();
            pool.connections -= 1;
            pool.shared_budget.release(1);
            try result;
        }
        while (pool.idle.idleCount() != 0) {
            if (deadline) |until| _ = try deadline_policy.usableAwake(pool.io, until);
            var idle = pool.idle.takeOldest().?;
            const result = owning_close.transport(&idle.connection_value, deadline);
            idle.return_node.destroy();
            pool.connections -= 1;
            pool.shared_budget.release(1);
            try result;
        }
    }
    guard.unlock();
    try pool.shared_budget.closeBefore(deadline);
    try pool.tickets.clearBefore(deadline);
    if (pool.http3) |state| try state.closeBefore(deadline);
}

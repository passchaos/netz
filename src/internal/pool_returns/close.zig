//! Bounded owning-pool closure, preserving the remaining list on interruption.
const std = @import("std");
const Guard = @import("../mutex_guard.zig").Guard;
const deadline_policy = @import("../deadline.zig");
pub const Error = std.Io.Cancelable || error{Timeout};

pub fn transport(connection: anytype, deadline: ?std.Io.Clock.Timestamp) Error!void {
    if (deadline) |until| {
        connection.closeWithDeadline(until) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
            else => {},
        };
    } else connection.close();
}

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

fn destroy(pool: anytype, value: anytype, deadline: ?std.Io.Clock.Timestamp) Error!void {
    var slot = value;
    defer {
        pool.allocator.free(slot.tls_host);
        if (slot.return_node) |node| node.destroy();
        pool.connections -= 1;
    }
    if (@hasField(@TypeOf(slot), "client")) try transport(&slot.client, deadline) else try transport(&slot.connection, deadline);
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
            try destroy(pool, node.value.slot, deadline);
        }
        while (pool.idle.items.len != 0) {
            if (deadline) |until| _ = try deadline_policy.usableAwake(pool.io, until);
            const slot = pool.idle.pop().?;
            try destroy(pool, slot, deadline);
        }
    }
    guard.unlock();
    try pool.tls12_tickets.clearBefore(deadline);
    try pool.tls13_tickets.clearBefore(deadline);
}

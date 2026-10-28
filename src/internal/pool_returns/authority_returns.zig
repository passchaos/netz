//! Exclusive H1/H2 pool returns share one publication and cache policy.
const std = @import("std");
const tickets = @import("tickets.zig");
const timed_mutex = @import("../timed_mutex.zig");
const deadline_policy = @import("../deadline.zig");

fn transport(slot: anytype) *@FieldType(@TypeOf(slot.*), if (@hasField(@TypeOf(slot.*), "client")) "client" else "connection") {
    return if (@hasField(@TypeOf(slot.*), "client")) &slot.client else &slot.connection;
}

pub fn release(pool: anytype, slot_value: anytype, reusable: bool) void {
    var slot = slot_value;
    if (slot.return_node) |node| {
        node.value = .{ .slot = slot, .reusable = reusable, .returned_at_ns = std.Io.Clock.awake.now(pool.io).nanoseconds };
        if (pool.returns.publish(node, pool.io)) {
            pool.capacity_waiters.notifyRetry(pool.io);
            return;
        }
    }
    transport(&slot).closeWithoutCloseNotify();
    pool.allocator.free(slot.tls_host);
    if (slot.return_node) |node| node.destroy();
    pool.retired_connections.release(&pool.connections, &pool.capacity_waiters, &pool.mutex, pool.io, 1);
}

pub fn collect(pool: anytype) void {
    collectBefore(pool, null) catch unreachable;
}

pub fn collectBefore(pool: anytype, deadline: ?std.Io.Clock.Timestamp) timed_mutex.Error!void {
    var current = pool.returns.take();
    errdefer pool.returns.restore(current);
    while (current) |node| {
        if (deadline) |until| _ = try deadline_policy.usableAwake(pool.io, until);
        const slot = &node.value.slot;
        const h1 = @hasField(@TypeOf(slot.*), "client");
        if (slot.transport == .tls and (!h1 or pool.options.vail_tls != null)) {
            try tickets.remember(&pool.tls13_tickets, transport(slot), slot.tls_host, slot.port, false, pool.io, deadline);
        }
        const next = node.next;
        const payload = node.value;
        if (!payload.reusable or pool.closed) {
            destroy(pool, &node.value.slot, deadline);
        } else cacheIdle(pool, payload.slot, payload.returned_at_ns, deadline);
        current = next;
    }
}

fn destroy(pool: anytype, slot: anytype, deadline: ?std.Io.Clock.Timestamp) void {
    if (deadline != null) transport(slot).closeWithoutCloseNotify() else transport(slot).close();
    pool.allocator.free(slot.tls_host);
    if (slot.return_node) |node| node.destroy();
    pool.connections -= 1;
    pool.capacity_waiters.notifyHead(pool.io);
}

fn cacheIdle(pool: anytype, slot_value: anytype, returned_at_ns: i96, deadline: ?std.Io.Clock.Timestamp) void {
    var slot = slot_value;
    if (pool.options.max_idle_connections == 0 or pool.options.max_idle_per_authority == 0) {
        destroy(pool, &slot, deadline);
        return;
    }
    var same_authority: usize = 0;
    for (pool.idle.items) |idle| {
        same_authority += @intFromBool(idle.transport == slot.transport and idle.port == slot.port and std.ascii.eqlIgnoreCase(idle.tls_host, slot.tls_host));
    }
    if (same_authority >= pool.options.max_idle_per_authority) {
        destroy(pool, &slot, deadline);
        return;
    }
    pool.sequence +%= 1;
    slot.last_used = pool.sequence;
    slot.idle_since_ns = returned_at_ns;
    if (pool.idle.items.len >= pool.options.max_idle_connections) {
        var oldest_index: usize = 0;
        for (pool.idle.items[1..], 1..) |idle, index| {
            if (idle.last_used < pool.idle.items[oldest_index].last_used) oldest_index = index;
        }
        var oldest = pool.idle.swapRemove(oldest_index);
        destroy(pool, &oldest, deadline);
    }
    pool.idle.append(pool.allocator, slot) catch {
        destroy(pool, &slot, deadline);
        return;
    };
    pool.capacity_waiters.notifyHead(pool.io);
}

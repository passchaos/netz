//! Pre-connect ticket locking must spend the caller's original request budget.
const std = @import("std");
const http = @import("../../http/client_pool.zig");

const Operation = enum { acquire_deadline, acquire_timeout, request_deadline, request_timeout };
const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex,
    canceled: bool,
    unbounded_waits: usize = 0,
    connections: usize = 0,
    var active: ?*Probe = null;

    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer != target) return self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        self.unbounded_waits += 1;
        self.mutex.state.store(.unlocked, .release);
    }
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer == target and self.canceled) return error.Canceled;
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
    fn connect(_: ?*anyopaque, _: *const std.Io.net.IpAddress, _: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
        active.?.connections += 1;
        return error.NetworkUnreachable;
    }
};

pub fn exercise(comptime Pool: type) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ .tls12_only, .tls13_only }) |policy| {
        inline for (.{ false, true }) |canceled| {
            for (std.enums.values(Operation)) |operation| {
                var pool = if (Pool == http.Pool)
                    try Pool.init(std.testing.allocator, base, .{ .client = .{ .tls = .{ .protocol_policy = policy } } })
                else if (@hasField(@FieldType(Pool, "options"), "vail_tls"))
                    try Pool.init(std.testing.allocator, base, .{ .vail_tls = .{ .protocol_policy = policy } })
                else
                    try Pool.init(std.testing.allocator, base, .{ .tls = .{ .protocol_policy = policy } });
                defer pool.deinit();
                const cache12 = if (Pool == http.Pool) &pool.tickets.tls12 else &pool.tls12_tickets;
                const cache13 = if (Pool == http.Pool) &pool.tickets.tls13 else &pool.tls13_tickets;
                const mutex = if (policy == .tls12_only) &cache12.mutex else &cache13.mutex;
                var probe = Probe{ .base = base, .mutex = mutex, .canceled = canceled };
                var table = base.vtable.*;
                table.futexWaitUncancelable = Probe.waitUncancelable;
                table.futexWait = Probe.wait;
                table.netConnectIp = Probe.connect;
                Probe.active = &probe;
                const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
                pool.io = io;
                cache12.io = io;
                cache13.io = io;
                mutex.lockUncancelable(base);
                defer {
                    _ = mutex.tryLock();
                    mutex.unlock(base);
                    pool.io = base;
                    cache12.io = base;
                    cache13.io = base;
                    Probe.active = null;
                }
                const until = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) });
                const expected = if (canceled) error.Canceled else error.Timeout;
                switch (operation) {
                    .acquire_deadline => try std.testing.expectError(expected, pool.acquireUriWithDeadline("https://127.0.0.1:1/", until)),
                    .acquire_timeout => try std.testing.expectError(expected, pool.acquireUriWithTimeout("https://127.0.0.1:1/", .fromMilliseconds(10))),
                    .request_deadline => try std.testing.expectError(expected, pool.requestUriWithDeadline("https://127.0.0.1:1/", .{}, until)),
                    .request_timeout => try std.testing.expectError(expected, pool.requestUriWithTimeout("https://127.0.0.1:1/", .{}, .fromMilliseconds(10))),
                }
                try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
                try std.testing.expectEqual(@as(usize, 0), probe.connections);
                try std.testing.expect(!mutex.tryLock());
                try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
                try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
                if (Pool == http.Pool) try std.testing.expectEqual(@as(usize, 0), pool.shared_budget.connectionCount());
            }
        }
    }
}

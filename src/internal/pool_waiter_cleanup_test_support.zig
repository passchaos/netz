//! Keep the ownership lock occupied from FIFO sleep through caller cleanup.
const std = @import("std");
const connection_budget = @import("connection_budget.zig");

const Operation = enum { acquire_deadline, acquire_timeout, request_deadline, request_timeout };
const Cleanup = enum { counter, close };

const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex,
    canceled: bool,
    now_ns: i96 = 1000,
    entered: bool = false,
    unbounded_waits: usize = 0,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn wait(context: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        // FIFO registration released its pool/budget lock before sleeping.
        // A publisher now keeps that lock through timeout and cancellation.
        if (!self.entered) {
            self.mutex.lockUncancelable(self.base);
            self.entered = true;
        }
        if (self.canceled) return error.Canceled;
        self.now_ns = 1003;
    }

    fn waitUncancelable(context: ?*anyopaque, _: *const u32, _: u32) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.unbounded_waits += 1;
        // Rescue old stack-waiter cleanup without deadlocking the test.
        self.mutex.state.store(.unlocked, .release);
    }

    fn wake(_: ?*anyopaque, _: *const u32, _: u32) void {}
};

pub fn exercise(pool: anytype, base: std.Io) !void {
    return exerciseUri(pool, base, "http://127.0.0.1:1/");
}

pub fn exerciseUri(pool: anytype, base: std.Io, uri: []const u8) !void {
    const shared: ?*connection_budget.Budget = if (@hasField(@TypeOf(pool.*), "shared_budget")) pool.shared_budget else null;
    inline for ([_]bool{ false, true }) |use_shared| {
        if (comptime use_shared and !@hasField(@TypeOf(pool.*), "shared_budget")) continue;
        for ([_]bool{ false, true }) |canceled| {
            for (std.enums.values(Operation)) |operation| {
                for (std.enums.values(Cleanup)) |cleanup| {
                    const prior_limit = pool.options.max_connections;
                    pool.options.max_connections = 1;
                    // Model a leased connection; no live transport is needed
                    // because admission must stop before any connection I/O.
                    pool.connections = if (use_shared) 0 else 1;
                    defer {
                        pool.connections = 0;
                        pool.options.max_connections = prior_limit;
                        pool.closed = false;
                        if (shared) |budget| budget.closed = false;
                    }
                    if (use_shared) {
                        shared.?.limit = 1;
                        shared.?.connections = 1;
                    }
                    defer if (use_shared) {
                        shared.?.limit = 0;
                        shared.?.connections = 0;
                        shared.?.closed = false;
                    };
                    var probe = Probe{
                        .base = base,
                        .mutex = if (use_shared) &shared.?.mutex else &pool.mutex,
                        .canceled = canceled,
                    };
                    var table = base.vtable.*;
                    table.now = Probe.now;
                    table.futexWait = Probe.wait;
                    table.futexWaitUncancelable = Probe.waitUncancelable;
                    table.futexWake = Probe.wake;
                    pool.io = .{ .userdata = &probe, .vtable = &table };
                    if (shared) |budget| budget.io = pool.io;
                    defer {
                        pool.io = base;
                        if (shared) |budget| budget.io = base;
                    }
                    var released = false;
                    defer if (probe.entered and !released) {
                        _ = probe.mutex.tryLock();
                        probe.mutex.unlock(base);
                    };
                    const expected = if (canceled) error.Canceled else error.Timeout;
                    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1003) };
                    switch (operation) {
                        .acquire_deadline => try std.testing.expectError(expected, pool.acquireUriWithDeadline(uri, deadline)),
                        .acquire_timeout => try std.testing.expectError(expected, pool.acquireUriWithTimeout(uri, .fromNanoseconds(3))),
                        .request_deadline => try std.testing.expectError(expected, pool.requestUriWithDeadline(uri, .{}, deadline)),
                        .request_timeout => try std.testing.expectError(expected, pool.requestUriWithTimeout(uri, .{}, .fromNanoseconds(3))),
                    }
                    try std.testing.expect(probe.entered);
                    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
                    try std.testing.expect(!probe.mutex.tryLock());
                    // The original reservation remains owned by its lease.
                    try std.testing.expectEqual(@as(usize, if (use_shared) 0 else 1), pool.connections);
                    if (use_shared) try std.testing.expectEqual(@as(usize, 1), shared.?.connections);
                    probe.mutex.unlock(base);
                    released = true;
                    pool.io = base;
                    if (shared) |budget| budget.io = base;
                    switch (cleanup) {
                        .counter => {
                            if (use_shared) {
                                try std.testing.expectEqual(@as(usize, 0), shared.?.waitingCount());
                            } else {
                                try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
                            }
                        },
                        .close => {
                            if (use_shared) shared.?.close() else pool.close();
                            if (use_shared) {
                                try std.testing.expectEqual(@as(usize, 0), shared.?.waitingCount());
                            } else {
                                try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
                            }
                        },
                    }
                }
            }
        }
    }
}

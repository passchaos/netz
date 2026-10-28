//! Bounded pool close is resumable after ownership admission or cleanup waits.
const std = @import("std");
const http = @import("../../http/client_pool.zig");
const Stage = enum { admission, publisher, tls12, tls13, budget };
const Probe = struct {
    base: std.Io,
    target: *const u32,
    canceled: bool,
    waits: usize = 0,
    var active: ?*Probe = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (pointer == self.target) {
            self.waits += 1;
            if (self.canceled) return error.Canceled;
        }
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

pub fn exercise(comptime Pool: type) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    inline for (std.enums.values(Stage)) |stage| {
        if (comptime stage == .budget and Pool != http.Pool) continue;
        inline for (.{ false, true }) |canceled| {
            inline for (.{ false, true }) |relative| {
                var pool = try Pool.init(std.testing.allocator, base, .{});
                defer pool.deinit();
                const cache12 = if (Pool == http.Pool) &pool.tickets.tls12 else &pool.tls12_tickets;
                const cache13 = if (Pool == http.Pool) &pool.tickets.tls13 else &pool.tls13_tickets;
                const mutex: ?*std.Io.Mutex = switch (stage) {
                    .admission => &pool.mutex,
                    .publisher => null,
                    .tls12 => &cache12.mutex,
                    .tls13 => &cache13.mutex,
                    .budget => &pool.shared_budget.mutex,
                };
                if (mutex) |value| value.lockUncancelable(base) else pool.returns.publishers.store(1, .release);
                var held = true;
                defer if (held) {
                    if (mutex) |value| value.unlock(base) else _ = pool.returns.publishers.fetchSub(1, .release);
                };
                var probe = Probe{ .base = base, .target = if (mutex) |value| @ptrCast(&value.state.raw) else &pool.returns.publishers.raw, .canceled = canceled };
                var table = base.vtable.*;
                table.futexWait = Probe.wait;
                const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
                Probe.active = &probe;
                pool.io = io;
                cache12.io = io;
                cache13.io = io;
                if (Pool == http.Pool) pool.shared_budget.io = io;
                defer {
                    pool.io = base;
                    cache12.io = base;
                    cache13.io = base;
                    if (Pool == http.Pool) pool.shared_budget.io = base;
                    Probe.active = null;
                }
                const expected = if (canceled) error.Canceled else error.Timeout;
                if (relative) try std.testing.expectError(expected, pool.closeWithTimeout(.fromMilliseconds(10))) else try std.testing.expectError(expected, pool.closeWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(10) })));
                try std.testing.expect(probe.waits != 0);
                try std.testing.expectEqual(stage != .admission, pool.closed);
                if (mutex) |value| try std.testing.expect(!value.tryLock());
                if (stage != .admission) {
                    try std.testing.expect(pool.mutex.tryLock());
                    pool.mutex.unlock(base);
                    try std.testing.expectError(error.PoolClosed, pool.acquireUri("http://127.0.0.1:1/"));
                }
                if (mutex) |value| value.unlock(base) else _ = pool.returns.publishers.fetchSub(1, .release);
                held = false;
                try pool.closeWithTimeout(.fromSeconds(1));
                try pool.closeWithTimeout(.fromSeconds(1));
                try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
                try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
                if (Pool == http.Pool) try std.testing.expectEqual(@as(usize, 0), pool.shared_budget.connectionCount());
            }
        }
    }
}

pub fn validate(comptime Pool: type) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try Pool.init(std.testing.allocator, io, .{});
    defer pool.deinit();
    try std.testing.expectError(error.Timeout, pool.closeWithTimeout(.zero));
    try std.testing.expectError(error.Timeout, pool.closeWithDeadline(.{ .clock = .real, .raw = .zero }));
    try std.testing.expect(!pool.closed);
}

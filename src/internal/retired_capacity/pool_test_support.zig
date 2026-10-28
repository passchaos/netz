//! A connect result must not be delayed by retiring its reserved pool slot.
const std = @import("std");
const budget_mod = @import("../connection_budget.zig");

const Operation = enum { acquire_deadline, acquire_timeout, request_deadline, request_timeout };
const Outcome = enum { timeout, canceled, network_unreachable };
const Cleanup = enum { counter, close };

const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex,
    outcome: Outcome,
    called: bool = false,
    held: bool = false,
    unbounded_waits: usize = 0,

    var active: ?*Probe = null;

    fn connect(_: ?*anyopaque, _: *const std.Io.net.IpAddress, _: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
        const self = active.?;
        self.called = true;
        self.mutex.lockUncancelable(self.base);
        self.held = true;
        return failure(self.outcome);
    }

    fn waitUncancelable(context: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer != target) return self.base.vtable.futexWaitUncancelable(context, pointer, expected);
        self.unbounded_waits += 1;
        // Rescue the baseline after it tries to retire under the occupied
        // pool/budget mutex. A regression must fail without hanging forever.
        self.mutex.state.store(.unlocked, .release);
    }
};

fn failure(outcome: Outcome) std.Io.net.IpAddress.ConnectError {
    return switch (outcome) {
        .timeout => error.Timeout,
        .canceled => error.Canceled,
        .network_unreachable => error.NetworkUnreachable,
    };
}

pub fn exercise(pool: anytype, base: std.Io) !void {
    const budget: ?*budget_mod.Budget = if (@hasField(@TypeOf(pool.*), "shared_budget")) pool.shared_budget else null;
    inline for ([_]bool{ false, true }) |shared| {
        if (comptime shared and !@hasField(@TypeOf(pool.*), "shared_budget")) continue;
        for (std.enums.values(Outcome)) |outcome| {
            for (std.enums.values(Operation)) |operation| {
                for (std.enums.values(Cleanup)) |cleanup| {
                    var probe = Probe{
                        .base = base,
                        .mutex = if (shared) &budget.?.mutex else &pool.mutex,
                        .outcome = outcome,
                    };
                    var table = base.vtable.*;
                    table.netConnectIp = Probe.connect;
                    table.futexWaitUncancelable = Probe.waitUncancelable;
                    Probe.active = &probe;
                    pool.io = .{ .userdata = base.userdata, .vtable = &table };
                    if (budget) |value| value.io = pool.io;
                    defer {
                        pool.io = base;
                        Probe.active = null;
                        pool.closed = false;
                        if (budget) |value| {
                            value.io = base;
                            value.closed = false;
                        }
                    }
                    defer if (probe.held) {
                        _ = probe.mutex.tryLock();
                        probe.mutex.unlock(base);
                    };
                    const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
                    switch (operation) {
                        .acquire_deadline => try std.testing.expectError(failure(outcome), pool.acquireUriWithDeadline("http://127.0.0.1:1/", deadline)),
                        .acquire_timeout => try std.testing.expectError(failure(outcome), pool.acquireUriWithTimeout("http://127.0.0.1:1/", .fromSeconds(1))),
                        .request_deadline => try std.testing.expectError(failure(outcome), pool.requestUriWithDeadline("http://127.0.0.1:1/", .{}, deadline)),
                        .request_timeout => try std.testing.expectError(failure(outcome), pool.requestUriWithTimeout("http://127.0.0.1:1/", .{}, .fromSeconds(1))),
                    }
                    try std.testing.expect(probe.called);
                    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
                    try std.testing.expect(!probe.mutex.tryLock());
                    // An owner still holding the lock sees its original
                    // accounting value until it consumes retirement receipts.
                    try std.testing.expectEqual(@as(usize, 1), if (shared) budget.?.connections else pool.connections);
                    probe.mutex.unlock(base);
                    probe.held = false;
                    pool.io = base;
                    if (budget) |value| value.io = base;
                    if (cleanup == .close) pool.close();
                    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
                    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
                    if (budget) |value| try std.testing.expectEqual(@as(usize, 0), value.connectionCount());
                }
            }
        }
    }
}

const std = @import("std");
const budget_mod = @import("../connection_budget.zig");

const ReleaseOnAllocate = struct {
    backing: std.mem.Allocator,
    budget: *budget_mod.Budget,
    fired: bool = false,

    fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(pointer));
        if (!self.fired) {
            self.fired = true;
            // Admission already observed full capacity and owns the mutex.
            // Release is published before enqueue captures its retry epoch.
            self.budget.release(1);
        }
        return self.backing.rawAlloc(len, alignment, ret);
    }
    fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *@This() = @ptrCast(@alignCast(pointer));
        self.backing.rawFree(bytes, alignment, ret);
    }
    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free };
};

test "deferred capacity retirement cannot lose a release before FIFO registration" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
    defer {
        budget.allocator = std.testing.allocator;
        budget.deinit();
    }
    try budget.tryReserve(null);
    var allocator = ReleaseOnAllocate{ .backing = std.testing.allocator, .budget = budget };
    budget.allocator = .{ .ptr = &allocator, .vtable = &ReleaseOnAllocate.vtable };
    var waiter: budget_mod.Waiter = .{};
    defer budget.cancel(&waiter);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expectError(error.ConnectionLimitReached, budget.tryReserveBefore(&waiter, deadline));
    try std.testing.expect(allocator.fired);
    // Check before calling a getter that could collect a missed retirement.
    try std.testing.expect(waiter.isNotified());
    try std.testing.expectEqual(@as(usize, 0), budget.connections);
    try budget.tryReserveBefore(&waiter, deadline);
    budget.release(1);
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
}

const ReleaseOnWake = struct {
    base: std.Io,
    budget: *budget_mod.Budget,
    fired: bool = false,
    var active: ?*ReleaseOnWake = null;

    fn wake(userdata: ?*anyopaque, pointer: *const u32, max_waiters: u32) void {
        const self = active.?;
        if (!self.fired) {
            self.fired = true;
            // Pruning the old head notified its successor under the budget
            // lock, immediately before the successor rearmed its cursor.
            self.budget.release(1);
        }
        self.base.vtable.futexWake(userdata, pointer, max_waiters);
    }
};

test "deferred capacity retirement cannot lose a release before FIFO rearm" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();
    try budget.tryReserve(null);
    var first: budget_mod.Waiter = .{};
    var second: budget_mod.Waiter = .{};
    defer budget.cancel(&first);
    defer budget.cancel(&second);
    try std.testing.expectError(error.ConnectionLimitReached, budget.tryReserve(&first));
    try std.testing.expectError(error.ConnectionLimitReached, budget.tryReserve(&second));
    budget.mutex.lockUncancelable(io);
    budget.cancel(&first);
    budget.mutex.unlock(io);
    var gate = ReleaseOnWake{ .base = io, .budget = budget };
    var table = io.vtable.*;
    table.futexWake = ReleaseOnWake.wake;
    ReleaseOnWake.active = &gate;
    budget.io = .{ .userdata = io.userdata, .vtable = &table };
    defer {
        budget.io = io;
        ReleaseOnWake.active = null;
    }
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expectError(error.ConnectionLimitReached, budget.tryReserveBefore(&second, deadline));
    try std.testing.expect(gate.fired);
    try std.testing.expect(second.isNotified());
    try std.testing.expectEqual(@as(usize, 0), budget.connections);
    try budget.tryReserveBefore(&second, deadline);
    budget.release(1);
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
}

test "deferred capacity reuse feedback returns while the accounting owner is occupied" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();
    try budget.tryReserve(null);
    var waiter: budget_mod.Waiter = .{};
    defer budget.cancel(&waiter);
    try std.testing.expectError(error.ConnectionLimitReached, budget.tryReserve(&waiter));
    budget.mutex.lockUncancelable(io);
    var locked = true;
    defer if (locked) budget.mutex.unlock(io);
    const epoch = budget.waiters.epoch.load(.acquire);
    budget.release(0);
    try std.testing.expectEqual(epoch, budget.waiters.epoch.load(.acquire));
    budget.notify();
    try std.testing.expect(!waiter.isNotified());
    try std.testing.expect(!budget.mutex.tryLock());
    try std.testing.expectEqual(@as(usize, 1), budget.connections);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try waiter.waitUntil(io, deadline);
    budget.mutex.unlock(io);
    locked = false;
    try std.testing.expect(budget.mayReclaimFor(&waiter));
    budget.release(1);
    try budget.tryReserveBefore(&waiter, deadline);
    budget.release(1);
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
}

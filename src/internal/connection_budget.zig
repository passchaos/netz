//! Move-stable shared admission budget for independently owned connection pools.
//!
//! A caller reserves exactly once before creating a new connection and releases
//! exactly once when that connection is destroyed. Reuse and same-pool idle
//! displacement transfer the existing reservation without touching this count.

const std = @import("std");
const fifo_admission = @import("fifo_admission.zig");

pub const Error = error{
    ConnectionLimitReached,
    PoolClosed,
};

pub const Waiter = fifo_admission.Queue.Waiter;

pub const Budget = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    limit: usize,
    mutex: std.Io.Mutex = .init,
    connections: usize = 0,
    waiters: fifo_admission.Queue = .{},
    closed: bool = false,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        limit: usize,
    ) std.mem.Allocator.Error!*Budget {
        const self = try allocator.create(Budget);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .limit = limit,
        };
        return self;
    }

    pub fn deinit(self: *Budget) void {
        const allocator = self.allocator;
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.waiters.count() == 0);
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Reserve one connection without blocking. A bounded caller supplies its
    /// stack waiter and sleeps only after this method releases the mutex.
    pub fn tryReserve(
        self: *Budget,
        waiter: ?*Waiter,
    ) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) {
            if (waiter) |queued| self.waiters.cancel(queued, self.io);
            return error.PoolClosed;
        }
        if (!self.waiters.mayAttempt(waiter) or
            (self.limit != 0 and self.connections >= self.limit))
        {
            if (waiter) |queued| {
                if (!queued.linked) {
                    self.waiters.enqueue(queued);
                } else if (queued.isNotified()) {
                    queued.rearm();
                }
            }
            return error.ConnectionLimitReached;
        }
        if (waiter) |queued| {
            if (queued.linked) {
                std.debug.assert(self.waiters.remove(queued));
            }
        }
        self.connections += 1;
        if (self.hasCapacityLocked()) self.waiters.notifyHead(self.io);
    }

    pub fn cancel(self: *Budget, waiter: *Waiter) void {
        self.mutex.lockUncancelable(self.io);
        self.waiters.cancel(waiter, self.io);
        self.mutex.unlock(self.io);
    }

    /// Release destroyed connections and wake the oldest cross-pool waiter.
    pub fn release(self: *Budget, count: usize) void {
        if (count == 0) return;
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.connections >= count);
        self.connections -= count;
        self.waiters.notifyHead(self.io);
        self.mutex.unlock(self.io);
    }

    /// Wake the oldest waiter when an existing reservation became reusable or
    /// transferable without reducing the total connection count.
    pub fn notify(self: *Budget) void {
        self.mutex.lockUncancelable(self.io);
        self.waiters.notifyHead(self.io);
        self.mutex.unlock(self.io);
    }

    pub fn close(self: *Budget) void {
        self.mutex.lockUncancelable(self.io);
        self.closed = true;
        self.waiters.notifyAll(self.io);
        self.mutex.unlock(self.io);
    }

    pub fn connectionCount(self: *Budget) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.connections;
    }

    pub fn waitingCount(self: *Budget) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.waiters.count();
    }

    fn hasCapacityLocked(self: *const Budget) bool {
        return self.closed or self.limit == 0 or self.connections < self.limit;
    }
};

test "shared connection budget reserves releases and closes atomically" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var budget = try Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();

    try budget.tryReserve(null);
    try std.testing.expectEqual(@as(usize, 1), budget.connectionCount());
    try std.testing.expectError(
        error.ConnectionLimitReached,
        budget.tryReserve(null),
    );
    budget.release(1);
    try budget.tryReserve(null);
    var waiter: Waiter = .{};
    try std.testing.expectError(
        error.ConnectionLimitReached,
        budget.tryReserve(&waiter),
    );
    budget.close();
    try std.testing.expect(waiter.isNotified());
    try std.testing.expectError(error.PoolClosed, budget.tryReserve(&waiter));
    try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
    budget.release(1);
    try std.testing.expectError(error.PoolClosed, budget.tryReserve(null));
}

test "shared connection budget preserves FIFO across independent pools" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var budget = try Budget.create(std.testing.allocator, io, 1);
    defer budget.deinit();
    try budget.tryReserve(null);
    var first: Waiter = .{};
    var second: Waiter = .{};
    try std.testing.expectError(
        error.ConnectionLimitReached,
        budget.tryReserve(&first),
    );
    try std.testing.expectError(
        error.ConnectionLimitReached,
        budget.tryReserve(&second),
    );
    try std.testing.expectEqual(@as(usize, 2), budget.waitingCount());

    budget.release(1);
    try std.testing.expect(first.isNotified());
    try std.testing.expect(!second.isNotified());
    try std.testing.expectError(
        error.ConnectionLimitReached,
        budget.tryReserve(&second),
    );
    try budget.tryReserve(&first);
    budget.release(1);
    try std.testing.expect(second.isNotified());
    try budget.tryReserve(&second);
    budget.release(1);
    try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
}

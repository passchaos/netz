//! Move-stable shared admission budget for independently owned connection pools.
//!
//! A caller reserves exactly once before creating a new connection and releases
//! exactly once when that connection is destroyed. Reuse and same-pool idle
//! displacement transfer the existing reservation without touching this count.

const std = @import("std");
const owned_admission = @import("owned_fifo_admission.zig");
const MutexGuard = @import("mutex_guard.zig").Guard;
const retired_capacity = @import("retired_capacity.zig");

pub const Error = std.mem.Allocator.Error || error{
    ConnectionLimitReached,
    PoolClosed,
};

pub const ReservationError = Error || std.Io.Timeout.Error || std.Io.Cancelable;
pub const Waiter = owned_admission.Queue.Waiter;

pub const Reclaimer = struct {
    context: *anyopaque,
    reclaim: *const fn (context: *anyopaque) bool,
};

pub const Budget = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    limit: usize,
    mutex: std.Io.Mutex = .init,
    connections: usize = 0,
    retired_connections: retired_capacity.Retirements = .{},
    waiters: owned_admission.Queue = .{},
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
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.waiters.count(self.io) == 0);
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Try one connection reservation. A caller keeps a stack cursor; an
    /// owned waiting node is allocated only when capacity/FIFO blocks it.
    pub fn tryReserve(
        self: *Budget,
        waiter: ?*Waiter,
    ) Error!void {
        return self.tryReserveBefore(waiter, null) catch |err| switch (err) {
            error.Timeout, error.Canceled => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn tryReserveBefore(
        self: *Budget,
        waiter: ?*Waiter,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReservationError!void {
        var admission_lock = try MutexGuard.initBefore(&self.mutex, self.io, deadline);
        defer admission_lock.unlock();
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        if (self.closed) {
            if (waiter) |queued| self.waiters.cancel(queued, self.io);
            return error.PoolClosed;
        }
        if (!self.waiters.mayAttempt(waiter, self.io) or
            (self.limit != 0 and self.connections >= self.limit))
        {
            if (waiter) |queued| {
                if (!queued.linked) {
                    try self.waiters.enqueue(queued, self.allocator, self.io);
                } else if (queued.isNotified()) {
                    queued.rearm();
                }
            }
            self.retired_connections.apply(&self.connections, &self.waiters, self.io);
            return error.ConnectionLimitReached;
        }
        if (waiter) |queued| {
            if (queued.linked) {
                std.debug.assert(self.waiters.remove(queued));
            }
            queued.deinit();
        }
        self.connections += 1;
        if (self.hasCapacityLocked()) self.waiters.notifyHead(self.io);
    }

    /// Retry one reservation after allowing another pool to retire an idle
    /// connection. The callback runs without the budget mutex, and the final
    /// reservation still obeys FIFO if another waiter arrives meanwhile.
    pub fn tryReserveReclaiming(
        self: *Budget,
        waiter: ?*Waiter,
        reclaimer: Reclaimer,
    ) Error!void {
        return self.tryReserveReclaimingBefore(waiter, reclaimer, null) catch |err| switch (err) {
            error.Timeout, error.Canceled => unreachable,
            else => return @errorCast(err),
        };
    }

    pub fn tryReserveReclaimingBefore(
        self: *Budget,
        waiter: ?*Waiter,
        reclaimer: Reclaimer,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReservationError!void {
        var admission_lock = try MutexGuard.initBefore(&self.mutex, self.io, deadline);
        defer admission_lock.unlock();
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        if (self.closed) {
            if (waiter) |queued| self.waiters.cancel(queued, self.io);
            admission_lock.unlock();
            return error.PoolClosed;
        }
        if (!self.waiters.mayAttempt(waiter, self.io)) {
            if (waiter) |queued| {
                if (!queued.linked) {
                    try self.waiters.enqueue(queued, self.allocator, self.io);
                } else if (queued.isNotified()) {
                    queued.rearm();
                }
            }
            self.retired_connections.apply(&self.connections, &self.waiters, self.io);
            admission_lock.unlock();
            return error.ConnectionLimitReached;
        }
        if (self.limit == 0 or self.connections < self.limit) {
            if (waiter) |queued| {
                if (queued.linked) {
                    std.debug.assert(self.waiters.remove(queued));
                }
                queued.deinit();
            }
            self.connections += 1;
            if (self.hasCapacityLocked()) self.waiters.notifyHead(self.io);
            admission_lock.unlock();
            return;
        }
        admission_lock.unlock();

        _ = reclaimer.reclaim(reclaimer.context);
        return self.tryReserveBefore(waiter, deadline);
    }

    pub fn cancel(self: *Budget, waiter: *Waiter) void {
        if (!self.waiters.abandon(waiter, self.io)) return;
        if (self.mutex.tryLock()) {
            self.waiters.pruneAbandoned(self.io);
            self.mutex.unlock(self.io);
        }
    }

    /// Release destroyed connections and wake the oldest cross-pool waiter.
    pub fn release(self: *Budget, count: usize) void {
        self.retired_connections.release(&self.connections, &self.waiters, &self.mutex, self.io, count);
    }

    /// Reuse/reclamation feedback does not wait for an accounting owner.
    pub fn notify(self: *Budget) void {
        self.retired_connections.notify(&self.connections, &self.waiters, &self.mutex, self.io);
    }

    pub fn close(self: *Budget) void {
        self.closeBefore(null) catch unreachable;
    }

    pub fn closeBefore(self: *Budget, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || error{Timeout})!void {
        var guard = try MutexGuard.initBefore(&self.mutex, self.io, deadline);
        defer guard.unlock();
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        self.closed = true;
        self.waiters.notifyAll(self.io);
    }

    pub fn connectionCount(self: *Budget) usize {
        self.mutex.lockUncancelable(self.io);
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        defer self.mutex.unlock(self.io);
        return self.connections;
    }

    pub fn waitingCount(self: *Budget) usize {
        self.mutex.lockUncancelable(self.io);
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        defer self.mutex.unlock(self.io);
        return self.waiters.count(self.io);
    }

    /// Return whether this caller currently owns the FIFO right to replace an
    /// idle connection while the total budget is full. No reservation changes.
    pub fn mayReclaimFor(self: *Budget, waiter: ?*const Waiter) bool {
        self.mutex.lockUncancelable(self.io);
        self.retired_connections.apply(&self.connections, &self.waiters, self.io);
        defer self.mutex.unlock(self.io);
        return !self.closed and self.limit != 0 and
            self.connections >= self.limit and
            self.waiters.mayAttempt(waiter, self.io);
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
    try std.testing.expect(budget.mayReclaimFor(&first));
    try std.testing.expect(!budget.mayReclaimFor(&second));
    try std.testing.expect(!budget.mayReclaimFor(null));

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

test "shared connection budget reclaims without holding its mutex" {
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

    const Context = struct {
        budget: *Budget,
        calls: usize = 0,

        fn reclaim(context: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.budget.release(1);
            return true;
        }
    };
    var context = Context{ .budget = budget };
    try budget.tryReserveReclaiming(&first, .{
        .context = &context,
        .reclaim = Context.reclaim,
    });
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try std.testing.expectEqual(@as(usize, 1), budget.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), budget.waitingCount());
    try std.testing.expect(!second.isNotified());
    budget.release(1);
    try std.testing.expect(second.isNotified());
    budget.cancel(&second);
}

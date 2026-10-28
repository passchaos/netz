//! Deterministic lock contention for the owning HTTP pool regression tests.
const std = @import("std");
const fifo_admission = @import("fifo_admission.zig");
const connection_budget = @import("connection_budget.zig");

const Operation = enum { acquire_deadline, acquire_timeout, request_deadline, request_timeout };

const Probe = struct {
    mutex: *std.Io.Mutex,
    shared_mutex: ?*std.Io.Mutex = null,
    canceled: bool,
    now_ns: i96 = 1000,
    bounded_waits: usize = 0,
    unbounded_waits: usize = 0,
    deadline_preserved: bool = true,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn wait(context: ?*anyopaque, _: *const u32, _: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.bounded_waits += 1;
        self.deadline_preserved = self.deadline_preserved and switch (timeout) {
            .deadline => |deadline| deadline.clock == .awake and deadline.raw.nanoseconds == 1003,
            else => false,
        };
        if (self.canceled) return error.Canceled;
        // The first two wakes are spurious; only the original bound expires.
        self.now_ns += 1;
    }

    fn waitUncancelable(context: ?*anyopaque, pointer: *const u32, _: u32) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.unbounded_waits += 1;
        // Rescue the old implementation so its regression fails without hanging.
        self.now_ns = 1003;
        const local_word: *const u32 = @ptrCast(&self.mutex.state.raw);
        const mutex = if (pointer == local_word) self.mutex else self.shared_mutex.?;
        mutex.state.store(.unlocked, .release);
    }

    fn wake(_: ?*anyopaque, _: *const u32, _: u32) void {}
};

pub fn exercise(pool: anytype, base: std.Io) !void {
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1003) };
    // A closed pool gives the old code a safe result after the rescue unlock,
    // and proves deadline/cancellation wins before shared state is admitted.
    pool.closed = true;
    defer pool.closed = false;
    var older: fifo_admission.Queue.Waiter = .{};
    pool.capacity_waiters.enqueue(&older);
    defer _ = pool.capacity_waiters.remove(&older);
    const shared: ?*connection_budget.Budget = if (@hasField(@TypeOf(pool.*), "shared_budget")) pool.shared_budget else null;
    for ([_]bool{ false, true }) |canceled| {
        for (std.enums.values(Operation)) |operation| {
            var probe = Probe{
                .mutex = &pool.mutex,
                .shared_mutex = if (shared) |budget| &budget.mutex else null,
                .canceled = canceled,
            };
            var table = base.vtable.*;
            table.now = Probe.now;
            table.futexWait = Probe.wait;
            table.futexWaitUncancelable = Probe.waitUncancelable;
            table.futexWake = Probe.wake;
            pool.io = .{ .userdata = &probe, .vtable = &table };
            defer pool.io = base;
            if (shared) |budget| {
                budget.io = pool.io;
                budget.mutex.lockUncancelable(base);
            }
            defer if (shared) |budget| {
                _ = budget.mutex.tryLock();
                budget.mutex.unlock(base);
                budget.io = base;
            };
            pool.mutex.lockUncancelable(base);
            defer {
                // The baseline rescue leaves the lock released. Reacquire it
                // if needed so a failed assertion still tears down safely.
                _ = pool.mutex.tryLock();
                pool.mutex.unlock(base);
            }
            const expected = if (canceled) error.Canceled else error.Timeout;
            switch (operation) {
                .acquire_deadline => try std.testing.expectError(expected, pool.acquireUriWithDeadline("http://127.0.0.1:1/", deadline)),
                .acquire_timeout => try std.testing.expectError(expected, pool.acquireUriWithTimeout("http://127.0.0.1:1/", .fromNanoseconds(3))),
                .request_deadline => try std.testing.expectError(expected, pool.requestUriWithDeadline("http://127.0.0.1:1/", .{}, deadline)),
                .request_timeout => try std.testing.expectError(expected, pool.requestUriWithTimeout("http://127.0.0.1:1/", .{}, .fromNanoseconds(3))),
            }
            try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
            try std.testing.expectEqual(@as(usize, if (canceled) 1 else 3), probe.bounded_waits);
            try std.testing.expect(probe.deadline_preserved);
            try std.testing.expect(!pool.mutex.tryLock());
            try std.testing.expectEqual(@as(usize, 0), pool.connections);
            try std.testing.expectEqual(@as(usize, 1), pool.capacity_waiters.count());
            try std.testing.expect(pool.capacity_waiters.mayAttempt(&older));
            try std.testing.expect(!older.isNotified());
            if (shared) |budget| {
                try std.testing.expect(!budget.mutex.tryLock());
                try std.testing.expectEqual(@as(usize, 0), budget.connections);
                try std.testing.expectEqual(@as(usize, 0), budget.waiters.count());
            }
        }
    }
}

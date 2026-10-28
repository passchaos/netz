//! std.Io mutex admission under one absolute operation deadline.
const std = @import("std");
const deadline_policy = @import("deadline.zig");

pub const Error = std.Io.Cancelable || error{Timeout};

pub fn lock(mutex: *std.Io.Mutex, io: std.Io, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const until = deadline orelse {
        mutex.lockUncancelable(io);
        return;
    };
    _ = try deadline_policy.usableAwake(io, until);
    var acquired = false;
    errdefer {
        if (acquired) {
            mutex.unlock(io);
        } else {
            // A canceled/timed-out waiter may consume an unlock notification.
            // Hand it to another waiter; a wake while still locked is harmless.
            io.futexWake(std.Io.Mutex.State, &mutex.state.raw, 1);
        }
    }
    if (mutex.tryLock()) {
        acquired = true;
        _ = try deadline_policy.usableAwake(io, until);
        return;
    }
    while (true) {
        _ = try deadline_policy.usableAwake(io, until);
        // Match std.Io.Mutex's contended-state protocol so ordinary unlock
        // and unbounded lock users continue sharing the same primitive.
        if (mutex.state.swap(.contended, .acquire) == .unlocked) {
            acquired = true;
            _ = try deadline_policy.usableAwake(io, until);
            return;
        }
        // Futex timeout and spurious wakes both return normally. Recheck the
        // original deadline before attempting another acquisition.
        try io.futexWaitTimeout(std.Io.Mutex.State, &mutex.state.raw, .contended, .{ .deadline = until });
    }
}

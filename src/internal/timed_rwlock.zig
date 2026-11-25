//! Shared read-lock admission under one absolute operation deadline.
const std = @import("std");
const deadline_policy = @import("deadline.zig");
const timed_mutex = @import("timed_mutex.zig");

pub const Error = std.Io.Cancelable || error{Timeout};

pub fn lockShared(lock: *std.Io.RwLock, io: std.Io, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const until = deadline orelse return lock.lockShared(io);
    try checkpoint(io, until);
    while (true) {
        if (lock.tryLockShared(io)) {
            errdefer lock.unlockShared(io);
            try checkpoint(io, until);
            return;
        }
        // RwLock serializes contended read admission through this mutex.
        // Wait on the same primitive, then let its public shared-lock method
        // install reader ownership. Never modify RwLock's reader/writer bits.
        try timed_mutex.lock(&lock.mutex, io, until);
        lock.mutex.unlock(io);
        try checkpoint(io, until);
    }
}

fn checkpoint(io: std.Io, deadline: std.Io.Clock.Timestamp) Error!void {
    try io.checkCancel();
    _ = try deadline_policy.usableAwake(io, deadline);
}

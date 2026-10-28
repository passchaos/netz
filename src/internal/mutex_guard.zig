//! Scoped ownership for admission paths with allocation and early returns.
const std = @import("std");
const timed_mutex = @import("timed_mutex.zig");

pub const Guard = struct {
    mutex: *std.Io.Mutex,
    io: std.Io,
    active: bool = true,

    pub fn init(mutex: *std.Io.Mutex, io: std.Io) Guard {
        mutex.lockUncancelable(io);
        return .{ .mutex = mutex, .io = io };
    }

    pub fn initBefore(mutex: *std.Io.Mutex, io: std.Io, deadline: ?std.Io.Clock.Timestamp) timed_mutex.Error!Guard {
        try timed_mutex.lock(mutex, io, deadline);
        return .{ .mutex = mutex, .io = io };
    }

    pub fn unlock(self: *Guard) void {
        if (!self.active) return;
        self.active = false;
        self.mutex.unlock(self.io);
    }
};

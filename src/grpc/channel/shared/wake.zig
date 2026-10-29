//! A retired endpoint's wake storage may still belong to a departing Job.
const std = @import("std");
pub const Wake = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    event: std.Io.Event = .unset,
    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Wake {
        const wake = try allocator.create(Wake);
        wake.* = .{ .allocator = allocator };
        return wake;
    }
    pub fn retain(self: *Wake) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Wake) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) self.allocator.destroy(self);
    }
    pub fn set(self: *Wake, io: std.Io) void {
        self.event.set(io);
    }
    pub fn reset(self: *Wake) void {
        self.event.reset();
    }
    pub fn wait(self: *Wake, io: std.Io) std.Io.Cancelable!void {
        return self.event.wait(io);
    }
    pub fn waitTimeout(self: *Wake, io: std.Io, timeout: std.Io.Timeout) std.Io.Event.WaitTimeoutError!void {
        return self.event.waitTimeout(io, timeout);
    }
};

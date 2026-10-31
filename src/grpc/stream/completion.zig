//! Optional one-shot call completion hook for channel-owned policies.
const std = @import("std");

pub const Observer = struct {
    allocator: std.mem.Allocator,
    context: *anyopaque,
    finish_fn: *const fn (context: *anyopaque, success: bool) void,

    pub fn create(
        allocator: std.mem.Allocator,
        context: *anyopaque,
        finish_fn: *const fn (context: *anyopaque, success: bool) void,
    ) std.mem.Allocator.Error!*Observer {
        const observer = try allocator.create(Observer);
        observer.* = .{
            .allocator = allocator,
            .context = context,
            .finish_fn = finish_fn,
        };
        return observer;
    }

    pub fn finish(self: *Observer, success: bool) void {
        const allocator = self.allocator;
        self.finish_fn(self.context, success);
        self.* = undefined;
        allocator.destroy(self);
    }
};

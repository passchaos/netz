//! Optional one-shot call completion hook for channel-owned policies.
const std = @import("std");
const observability = @import("../observability.zig");

pub const Observer = struct {
    allocator: std.mem.Allocator,
    context: ?*anyopaque = null,
    finish_fn: ?*const fn (context: *anyopaque, success: bool) void = null,
    /// Optional external call observer (for example Channelz). It receives the
    /// same terminal success classification as the policy hook.
    call_observer: ?observability.ServerObserver = null,

    pub fn create(
        allocator: std.mem.Allocator,
        context: ?*anyopaque,
        finish_fn: ?*const fn (context: *anyopaque, success: bool) void,
        call_observer: ?observability.ServerObserver,
    ) std.mem.Allocator.Error!*Observer {
        const observer = try allocator.create(Observer);
        observer.* = .{
            .allocator = allocator,
            .context = context,
            .finish_fn = finish_fn,
            .call_observer = call_observer,
        };
        return observer;
    }

    pub fn finish(self: *Observer, success: bool) void {
        if (self.finish_fn) |finish_fn| finish_fn(self.context.?, success);
        if (self.call_observer) |observer| {
            if (success) observer.callSucceeded() else observer.callFailed();
        }
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }
};

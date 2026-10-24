const std = @import("std");
const runtime_error = @import("../error.zig");

/// Default polling retains failed messages until their scoped cancellation is
/// submitted. Storage is reserved before parsing and bounded by live requests.
pub fn For(comptime Failure: type) type {
    return struct {
        const Pending = @This();
        items: std.ArrayList(Failure) = .empty,

        pub fn count(self: *const Pending) usize {
            return self.items.items.len;
        }

        pub fn clear(self: *Pending) void {
            self.items.clearRetainingCapacity();
        }

        pub fn deinit(self: *Pending, allocator: std.mem.Allocator) void {
            self.items.deinit(allocator);
            self.* = .{};
        }

        pub fn reserve(self: *Pending, allocator: std.mem.Allocator) std.mem.Allocator.Error!void {
            try self.items.ensureUnusedCapacity(allocator, 1);
        }

        pub fn append(self: *Pending, failure: Failure) void {
            for (self.items.items) |existing| std.debug.assert(existing.stream_id != failure.stream_id);
            self.items.appendAssumeCapacity(failure);
        }

        pub fn take(self: *Pending, target: ?u62) ?Failure {
            for (self.items.items, 0..) |failure, index| {
                if (target) |id| if (failure.stream_id != id) continue;
                return self.items.orderedRemove(index);
            }
            return null;
        }

        /// One submission per matching owner. Congestion or pacing on a failed
        /// stream does not prevent another buffered request from being parsed.
        pub fn poll(self: *Pending, context: anytype, target: ?u62, comptime submit: anytype) runtime_error.Error!?Failure {
            for (self.items.items, 0..) |failure, index| {
                if (target) |id| if (failure.stream_id != id) continue;
                submit(context, failure) catch |err| switch (err) {
                    error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => continue,
                    else => return err,
                };
                return self.items.orderedRemove(index);
            }
            return null;
        }
    };
}

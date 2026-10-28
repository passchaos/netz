//! A stack cursor owns a node only after capacity waiting actually begins.
const std = @import("std");
const Node = @import("node.zig").Node;
const deadline_policy = @import("../deadline.zig");

pub const Waiter = struct {
    node: ?*Node = null,
    linked: bool = false,
    epoch: ?*std.atomic.Value(u32) = null,
    observed_epoch: u32 = 0,

    pub fn isNotified(self: *const Waiter) bool {
        const node = self.node orelse return false;
        return node.state.load(.acquire) == .notified;
    }

    pub fn rearm(self: *Waiter) void {
        std.debug.assert(self.linked);
        self.node.?.state.store(.queued, .release);
        self.observed_epoch = self.epoch.?.load(.acquire);
    }

    /// Return for a FIFO notification or a hint to recheck queue ownership.
    /// The owning pool always rechecks admission under its mutex, so retries
    /// caused by a peer's abandonment cannot let this cursor barge ahead.
    pub fn waitUntil(self: *Waiter, io: std.Io, deadline: std.Io.Clock.Timestamp) (std.Io.Timeout.Error || std.Io.Cancelable)!void {
        std.debug.assert(self.linked);
        const node = self.node.?;
        const epoch = self.epoch.?;
        while (!self.isNotified()) {
            _ = try deadline_policy.usableAwake(io, deadline);
            const current = epoch.load(.acquire);
            if (current != self.observed_epoch) {
                self.observed_epoch = current;
                return;
            }
            std.debug.assert(node.state.load(.acquire) == .queued);
            try io.futexWaitTimeout(u32, &epoch.raw, current, .{ .deadline = deadline });
        }
    }

    /// Queue removal already retired its reference. Repeated cursor cleanup
    /// is harmless, and a subsequent capacity wait may allocate a fresh node.
    pub fn deinit(self: *Waiter) void {
        std.debug.assert(!self.linked);
        if (self.node) |node| node.release();
        self.* = .{};
    }
};

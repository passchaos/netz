//! A queue reference keeps notifications independent of the caller's frame.
const std = @import("std");

pub const Node = struct {
    pub const State = enum(u32) { queued, notified, abandoned };

    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize) = .init(1),
    state: std.atomic.Value(State) = .init(.queued),
    previous: ?*Node = null,
    next: ?*Node = null,

    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Node {
        const node = try allocator.create(Node);
        node.* = .{ .allocator = allocator };
        return node;
    }

    pub fn retain(self: *Node) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
    }

    pub fn release(self: *Node) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous == 1) self.allocator.destroy(self);
    }

    pub fn notify(self: *Node) bool {
        return self.state.cmpxchgStrong(.queued, .notified, .release, .monotonic) == null;
    }
};

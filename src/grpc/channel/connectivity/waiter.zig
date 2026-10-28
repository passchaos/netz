//! Caller and tracker share ownership until notification or abandonment wins.
const std = @import("std");
const connectivity = @import("../connectivity.zig");

pub const Waiter = struct {
    pub const State = enum(u8) { waiting, notified, abandoned };

    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize) = .init(1),
    state: std.atomic.Value(State) = .init(.waiting),
    node: std.DoublyLinkedList.Node = .{},
    event: std.Io.Event = .unset,
    snapshot: connectivity.Snapshot = undefined,

    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Waiter {
        const waiter = try allocator.create(Waiter);
        waiter.* = .{ .allocator = allocator };
        return waiter;
    }

    pub fn retain(self: *Waiter) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
    }

    pub fn release(self: *Waiter) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous == 1) self.allocator.destroy(self);
    }

    /// Snapshot publication precedes the notification state. The tracker
    /// keeps its reference through event.set even if the caller returns first.
    pub fn notify(self: *Waiter, io: std.Io, snapshot: connectivity.Snapshot) void {
        self.snapshot = snapshot;
        if (self.state.cmpxchgStrong(.waiting, .notified, .release, .monotonic) == null) self.event.set(io);
    }

    /// Once abandoned, a delayed notifier cannot change the returned result
    /// or access caller stack storage. A prior notification keeps its snapshot.
    pub fn abandon(self: *Waiter) bool {
        return self.state.cmpxchgStrong(.waiting, .abandoned, .acq_rel, .acquire) == null;
    }
};

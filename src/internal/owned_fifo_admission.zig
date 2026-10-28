//! FIFO capacity admission with lazy, shared ownership of waiting nodes.
//!
//! List mutations use the owning pool's mutex. A departing caller can mark
//! its node abandoned and retire its cursor without that mutex. The next
//! queue access retires list references. An epoch also wakes waiting callers
//! to recheck admission, including when abandonment races an owner's final
//! notification; available capacity cannot remain behind an abandoned head.
const std = @import("std");
const Node = @import("owned_fifo_admission/node.zig").Node;
const Cursor = @import("owned_fifo_admission/waiter.zig").Waiter;

test {
    _ = @import("owned_fifo_admission/tests.zig");
}

pub const Queue = struct {
    pub const Waiter = Cursor;

    head: ?*Node = null,
    tail: ?*Node = null,
    len: usize = 0,
    abandoned_nodes: std.atomic.Value(bool) = .init(false),
    epoch: std.atomic.Value(u32) = .init(0),

    pub fn count(self: *Queue, io: std.Io) usize {
        self.pruneAbandoned(io);
        return self.len;
    }

    pub fn mayAttempt(self: *Queue, waiter: ?*const Waiter, io: std.Io) bool {
        self.pruneAbandoned(io);
        const first = self.head orelse return waiter == null or !waiter.?.linked;
        return if (waiter) |candidate| candidate.node == first else false;
    }

    pub fn enqueue(self: *Queue, waiter: *Waiter, allocator: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!void {
        std.debug.assert(!waiter.linked);
        self.pruneAbandoned(io);
        const node = waiter.node orelse try Node.create(allocator);
        node.retain(); // The list retains a reference until remove or prune.
        node.previous = self.tail;
        node.next = null;
        node.state.store(.queued, .release);
        if (self.tail) |tail| tail.next = node else self.head = node;
        self.tail = node;
        self.len += 1;
        waiter.node = node;
        waiter.linked = true;
        waiter.epoch = &self.epoch;
        waiter.observed_epoch = self.epoch.load(.acquire);
    }

    pub fn remove(self: *Queue, waiter: *Waiter) bool {
        if (!waiter.linked) return false;
        const was_head = self.unlink(waiter.node.?);
        waiter.linked = false;
        waiter.node.?.release();
        return was_head;
    }

    /// Locked removal, for a terminal branch that already owns the mutex.
    pub fn cancel(self: *Queue, waiter: *Waiter, io: std.Io) void {
        const was_head = self.remove(waiter);
        waiter.deinit();
        if (was_head) self.notifyHead(io);
    }

    /// Caller-only departure; no list fields or peer cursors are accessed.
    /// Return whether list work remains for the owning pool to reclaim.
    pub fn abandon(self: *Queue, waiter: *Waiter, io: std.Io) bool {
        const linked = waiter.linked;
        if (linked) {
            waiter.node.?.state.store(.abandoned, .release);
            self.abandoned_nodes.store(true, .release);
            waiter.linked = false;
            // A retry hint is independent of the ownership mutex. An already
            // sleeping successor can recheck even if the owner misses this
            // departure while completing a previous capacity notification.
            self.notifyRetry(io);
        }
        waiter.deinit();
        return linked;
    }

    pub fn pruneAbandoned(self: *Queue, io: std.Io) void {
        if (!self.abandoned_nodes.swap(false, .acq_rel)) return;
        var head_removed = false;
        var current = self.head;
        while (current) |node| {
            current = node.next;
            if (node.state.load(.acquire) == .abandoned) {
                head_removed = self.unlink(node) or head_removed;
                node.release();
            }
        }
        if (head_removed) self.notifyHeadRaw(io);
    }

    pub fn notifyHead(self: *Queue, io: std.Io) void {
        self.pruneAbandoned(io);
        self.notifyHeadRaw(io);
    }

    pub fn notifyAll(self: *Queue, io: std.Io) void {
        self.pruneAbandoned(io);
        var changed = false;
        var current = self.head;
        while (current) |node| : (current = node.next) {
            changed = node.notify() or changed;
        }
        if (changed) self.notifyRetry(io);
    }

    fn unlink(self: *Queue, node: *Node) bool {
        const was_head = self.head == node;
        if (node.previous) |previous| previous.next = node.next else self.head = node.next;
        if (node.next) |next| next.previous = node.previous else self.tail = node.previous;
        node.previous = null;
        node.next = null;
        self.len -= 1;
        return was_head;
    }

    fn notifyHeadRaw(self: *Queue, io: std.Io) void {
        if (self.head) |head| {
            if (head.notify()) self.notifyRetry(io);
        }
    }

    /// A resource change may be published while another caller owns the list.
    /// This hint touches only the epoch and never waits for the owning mutex.
    pub fn notifyRetry(self: *Queue, io: std.Io) void {
        _ = self.epoch.fetchAdd(1, .release);
        io.futexWake(u32, &self.epoch.raw, std.math.maxInt(u32));
    }
};

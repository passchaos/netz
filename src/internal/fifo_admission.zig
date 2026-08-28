//! Allocation-free FIFO admission for bounded resource pools.
//!
//! The queue is intrusive: each blocking caller keeps a `Waiter` in its own
//! stack frame. All queue mutations must be protected by the owning pool's
//! mutex. Waiting happens after that mutex is released, using the waiter's
//! atomic state as a futex so notification cannot be lost between unlock and
//! sleep.

const std = @import("std");

pub const Queue = struct {
    head: ?*Waiter = null,
    tail: ?*Waiter = null,
    len: usize = 0,

    pub const Waiter = struct {
        previous: ?*Waiter = null,
        next: ?*Waiter = null,
        state: std.atomic.Value(State) = .init(.queued),
        linked: bool = false,

        const State = enum(u32) {
            queued,
            notified,
        };

        /// Wait for this caller's FIFO turn under one absolute deadline.
        /// Spurious futex wakeups do not let a later caller bypass the queue.
        pub fn waitUntil(
            self: *Waiter,
            io: std.Io,
            deadline: std.Io.Clock.Timestamp,
        ) (std.Io.Timeout.Error || std.Io.Cancelable)!void {
            while (self.state.load(.acquire) == .queued) {
                if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
                    return error.Timeout;
                }
                io.futexWaitTimeout(
                    State,
                    &self.state.raw,
                    .queued,
                    .{ .deadline = deadline },
                ) catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
            }
        }

        pub fn isNotified(self: *const Waiter) bool {
            return self.state.load(.acquire) == .notified;
        }

        /// Rearm after a notified head observed that capacity was consumed by
        /// another in-flight operation before it could claim the resource.
        pub fn rearm(self: *Waiter) void {
            std.debug.assert(self.linked);
            self.state.store(.queued, .release);
        }

        fn notify(self: *Waiter, io: std.Io) void {
            if (self.state.swap(.notified, .release) == .queued) {
                io.futexWake(State, &self.state.raw, 1);
            }
        }
    };

    pub fn count(self: *const Queue) usize {
        return self.len;
    }

    /// Return whether a caller may inspect/claim capacity. New callers may
    /// proceed only when no waiter exists; queued callers proceed only at the
    /// head. This is the anti-barging rule that makes wake order meaningful.
    pub fn mayAttempt(self: *const Queue, waiter: ?*const Waiter) bool {
        const first = self.head orelse return waiter == null or !waiter.?.linked;
        return if (waiter) |candidate| first == candidate else false;
    }

    pub fn enqueue(self: *Queue, waiter: *Waiter) void {
        std.debug.assert(!waiter.linked);
        waiter.previous = self.tail;
        waiter.next = null;
        waiter.state.store(.queued, .release);
        waiter.linked = true;
        if (self.tail) |tail| {
            tail.next = waiter;
        } else {
            self.head = waiter;
        }
        self.tail = waiter;
        self.len += 1;
    }

    /// Remove a caller and report whether it was the head. Timeout and
    /// cancellation paths use this to hand available capacity to the next
    /// waiter instead of stranding the queue behind an abandoned ticket.
    pub fn remove(self: *Queue, waiter: *Waiter) bool {
        if (!waiter.linked) return false;
        const was_head = self.head == waiter;
        if (waiter.previous) |previous| {
            previous.next = waiter.next;
        } else {
            self.head = waiter.next;
        }
        if (waiter.next) |next| {
            next.previous = waiter.previous;
        } else {
            self.tail = waiter.previous;
        }
        waiter.previous = null;
        waiter.next = null;
        waiter.linked = false;
        self.len -= 1;
        return was_head;
    }

    /// Remove a waiter and immediately wake its FIFO successor. Pool close
    /// uses `notifyAll` instead; normal cancellation and timeout use this
    /// helper so an already-available resource does not become stranded.
    pub fn cancel(self: *Queue, waiter: *Waiter, io: std.Io) void {
        if (self.remove(waiter)) self.notifyHead(io);
    }

    pub fn notifyHead(self: *Queue, io: std.Io) void {
        if (self.head) |head| head.notify(io);
    }

    pub fn notifyAll(self: *Queue, io: std.Io) void {
        var current = self.head;
        while (current) |waiter| : (current = waiter.next) {
            waiter.notify(io);
        }
    }
};

test "FIFO admission rejects barging and skips a canceled head" {
    var queue: Queue = .{};
    var first: Queue.Waiter = .{};
    var second: Queue.Waiter = .{};
    var third: Queue.Waiter = .{};

    try std.testing.expect(queue.mayAttempt(null));
    queue.enqueue(&first);
    queue.enqueue(&second);
    queue.enqueue(&third);
    try std.testing.expect(!queue.mayAttempt(null));
    try std.testing.expect(queue.mayAttempt(&first));
    try std.testing.expect(!queue.mayAttempt(&second));
    try std.testing.expectEqual(@as(usize, 3), queue.count());

    try std.testing.expect(queue.remove(&first));
    try std.testing.expect(queue.mayAttempt(&second));
    try std.testing.expect(!queue.remove(&third));
    try std.testing.expect(queue.mayAttempt(&second));
    try std.testing.expectEqual(@as(usize, 1), queue.count());
    try std.testing.expect(queue.remove(&second));
    try std.testing.expect(queue.mayAttempt(null));
}

test "FIFO admission notifies only its head" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var first: Queue.Waiter = .{};
    var second: Queue.Waiter = .{};
    queue.enqueue(&first);
    queue.enqueue(&second);

    queue.notifyHead(io);
    try std.testing.expect(first.isNotified());
    try std.testing.expect(!second.isNotified());
    _ = queue.remove(&first);
    queue.notifyHead(io);
    try std.testing.expect(second.isNotified());
    _ = queue.remove(&second);
}

test "FIFO admission cancel wakes the next waiter" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var first: Queue.Waiter = .{};
    var second: Queue.Waiter = .{};
    queue.enqueue(&first);
    queue.enqueue(&second);

    queue.cancel(&first, io);
    try std.testing.expect(second.isNotified());
    try std.testing.expect(queue.mayAttempt(&second));
    _ = queue.remove(&second);
}

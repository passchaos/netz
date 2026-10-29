//! Reference-counted gRPC Channel connectivity state and one-shot watches.

const std = @import("std");
const timed_mutex = @import("../../internal/timed_mutex.zig");
const deadline_policy = @import("../../internal/deadline.zig");

test {
    _ = @import("connectivity/deadline_tests.zig");
    _ = @import("connectivity/lifetime_tests.zig");
}

pub const State = enum {
    idle,
    connecting,
    ready,
    transient_failure,
    shutdown,
};

pub const Snapshot = struct {
    state: State,
    generation: u64,
};

pub const WaitError = std.Io.Event.WaitTimeoutError || std.mem.Allocator.Error;
pub const ReadyError = WaitError || error{ChannelShutdown};

const Waiter = @import("connectivity/waiter.zig").Waiter;

pub const Tracker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    references: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    state: State = .idle,
    generation: u64 = 0,
    waiters: std.DoublyLinkedList = .{},
    abandoned_waiters: std.atomic.Value(bool) = .init(false),

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
    ) std.mem.Allocator.Error!*Tracker {
        const tracker = try allocator.create(Tracker);
        tracker.* = .{ .allocator = allocator, .io = io };
        return tracker;
    }

    pub fn retain(self: *Tracker) void {
        const previous = self.references.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
    }

    pub fn release(self: *Tracker) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        // No caller references remain. Outstanding nodes can only be waits
        // that already returned under lock contention; retire their list refs.
        self.pruneAbandonedLocked();
        std.debug.assert(self.waiters.first == null);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn snapshot(self: *Tracker) Snapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneAbandonedLocked();
        return self.snapshotLocked();
    }

    pub fn snapshotWithDeadline(self: *Tracker, deadline: std.Io.Clock.Timestamp) WaitError!Snapshot {
        try timed_mutex.lock(&self.mutex, self.io, deadline);
        defer self.mutex.unlock(self.io);
        self.pruneAbandonedLocked();
        return self.snapshotLocked();
    }

    pub fn snapshotWithTimeout(self: *Tracker, timeout: std.Io.Duration) WaitError!Snapshot {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.snapshotWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }

    pub fn setState(self: *Tracker, state: State) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.setStateLocked(state);
    }

    pub fn exitIdle(self: *Tracker) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.state == .idle) self.setStateLocked(.connecting);
    }

    pub fn exitIdleWithDeadline(self: *Tracker, deadline: std.Io.Clock.Timestamp) WaitError!void {
        try timed_mutex.lock(&self.mutex, self.io, deadline);
        defer self.mutex.unlock(self.io);
        if (self.state == .idle) self.setStateLocked(.connecting);
    }

    fn setStateLocked(self: *Tracker, state: State) void {
        self.pruneAbandonedLocked();
        if (self.state == .shutdown or self.state == state) {
            return;
        }
        self.state = state;
        self.generation +%= 1;
        const current_snapshot = self.snapshotLocked();
        while (self.waiters.popFirst()) |node| {
            const waiter: *Waiter = @fieldParentPtr("node", node);
            waiter.notify(self.io, current_snapshot);
            waiter.release();
        }
    }

    pub fn waitAfter(
        self: *Tracker,
        generation: u64,
        deadline: std.Io.Clock.Timestamp,
    ) WaitError!Snapshot {
        // An immediately available changed snapshot or SHUTDOWN still wins
        // with a zero timeout. Contended admission uses the supplied bound.
        if (!self.mutex.tryLock()) try timed_mutex.lock(&self.mutex, self.io, deadline);
        self.pruneAbandonedLocked();
        const current = self.snapshotLocked();
        if (current.generation != generation or current.state == .shutdown) {
            self.mutex.unlock(self.io);
            return current;
        }
        _ = deadline_policy.usableAwake(self.io, deadline) catch |err| {
            self.mutex.unlock(self.io);
            return err;
        };
        const waiter = Waiter.create(self.allocator) catch |err| {
            self.mutex.unlock(self.io);
            return err;
        };
        defer waiter.release();
        // One caller reference and one list reference; the list may outlive
        // timeout/cancellation when its lock belongs to a state publisher.
        waiter.retain();
        self.waiters.append(&waiter.node);
        self.mutex.unlock(self.io);

        while (true) {
            waiter.event.waitTimeout(
                self.io,
                .{ .deadline = deadline },
            ) catch |err| {
                if (waiter.state.load(.acquire) == .notified) return waiter.snapshot;
                // Event reports both expiration and a spurious futex wake as
                // Timeout. Only the caller's original bound ends this watch.
                if (err == error.Timeout) {
                    if (deadline_policy.usableAwake(self.io, deadline)) |_| continue else |_| {}
                }
                if (waiter.abandon()) {
                    self.abandoned_waiters.store(true, .release);
                    if (self.mutex.tryLock()) {
                        self.pruneAbandonedLocked();
                        self.mutex.unlock(self.io);
                    }
                    return err;
                }
                return waiter.snapshot;
            };
            return waiter.snapshot;
        }
    }

    fn snapshotLocked(self: *const Tracker) Snapshot {
        return .{ .state = self.state, .generation = self.generation };
    }

    fn pruneAbandonedLocked(self: *Tracker) void {
        if (!self.abandoned_waiters.swap(false, .acq_rel)) return;
        var node = self.waiters.first;
        while (node) |current| {
            node = current.next;
            const waiter: *Waiter = @fieldParentPtr("node", current);
            if (waiter.state.load(.acquire) == .abandoned) {
                self.waiters.remove(current);
                waiter.release();
            }
        }
    }
};

/// A moveable, single-owner cursor. Separate handles may wait concurrently;
/// one handle must not be used by multiple tasks at the same time.
pub const Watch = struct {
    tracker: *Tracker,
    observed: Snapshot,

    pub fn init(tracker: *Tracker) Watch {
        tracker.retain();
        return .{ .tracker = tracker, .observed = tracker.snapshot() };
    }

    pub fn initWithDeadline(tracker: *Tracker, deadline: std.Io.Clock.Timestamp) WaitError!Watch {
        const observed = try tracker.snapshotWithDeadline(deadline);
        tracker.retain();
        return .{ .tracker = tracker, .observed = observed };
    }

    pub fn initWithTimeout(tracker: *Tracker, timeout: std.Io.Duration) WaitError!Watch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return initWithDeadline(tracker, .fromNow(tracker.io, .{ .clock = .awake, .raw = timeout }));
    }

    pub fn deinit(self: *Watch) void {
        self.tracker.release();
        self.* = undefined;
    }

    pub fn snapshot(self: *const Watch) Snapshot {
        return self.observed;
    }

    pub fn nextWithDeadline(
        self: *Watch,
        deadline: std.Io.Clock.Timestamp,
    ) WaitError!Snapshot {
        const changed = try self.tracker.waitAfter(
            self.observed.generation,
            deadline,
        );
        self.observed = changed;
        return changed;
    }

    pub fn nextWithTimeout(
        self: *Watch,
        timeout: std.Io.Duration,
    ) WaitError!Snapshot {
        return self.nextWithDeadline(.fromNow(self.tracker.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn waitForReadyWithDeadline(
        self: *Watch,
        deadline: std.Io.Clock.Timestamp,
    ) ReadyError!void {
        while (true) {
            switch (self.observed.state) {
                .ready => return,
                .shutdown => return error.ChannelShutdown,
                else => _ = try self.nextWithDeadline(deadline),
            }
        }
    }

    pub fn waitForReadyWithTimeout(
        self: *Watch,
        timeout: std.Io.Duration,
    ) ReadyError!void {
        return self.waitForReadyWithDeadline(.fromNow(self.tracker.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }
};

test "gRPC connectivity shutdown remains terminal for retained watches" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const tracker = try Tracker.create(allocator, threaded.io());
    var watch = Watch.init(tracker);
    defer watch.deinit();

    tracker.setState(.connecting);
    tracker.setState(.shutdown);
    const terminal = tracker.snapshot();
    for ([_]State{ .idle, .connecting, .ready, .transient_failure, .shutdown }) |state| {
        tracker.setState(state);
        try std.testing.expectEqualDeep(terminal, tracker.snapshot());
    }
    tracker.release();

    try std.testing.expectEqualDeep(
        terminal,
        try watch.nextWithTimeout(.zero),
    );
    try std.testing.expectEqualDeep(
        terminal,
        try watch.nextWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.ChannelShutdown,
        watch.waitForReadyWithTimeout(.zero),
    );
}

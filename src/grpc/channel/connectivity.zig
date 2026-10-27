//! Reference-counted gRPC Channel connectivity state and one-shot watches.

const std = @import("std");

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

pub const WaitError = std.Io.Event.WaitTimeoutError;
pub const ReadyError = WaitError || error{ChannelShutdown};

const Waiter = struct {
    node: std.DoublyLinkedList.Node = .{},
    event: std.Io.Event = .unset,
    registered: bool = false,
    snapshot: Snapshot = undefined,
};

pub const Tracker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    references: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    state: State = .idle,
    generation: u64 = 0,
    waiters: std.DoublyLinkedList = .{},

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
        std.debug.assert(self.waiters.first == null);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn snapshot(self: *Tracker) Snapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.snapshotLocked();
    }

    pub fn setState(self: *Tracker, state: State) void {
        self.mutex.lockUncancelable(self.io);
        if (self.state == .shutdown or self.state == state) {
            self.mutex.unlock(self.io);
            return;
        }
        self.state = state;
        self.generation +%= 1;
        const current_snapshot = self.snapshotLocked();
        while (self.waiters.popFirst()) |node| {
            const waiter: *Waiter = @fieldParentPtr("node", node);
            waiter.registered = false;
            waiter.snapshot = current_snapshot;
            waiter.event.set(self.io);
        }
        self.mutex.unlock(self.io);
    }

    pub fn waitAfter(
        self: *Tracker,
        generation: u64,
        deadline: std.Io.Clock.Timestamp,
    ) WaitError!Snapshot {
        var waiter: Waiter = .{};
        self.mutex.lockUncancelable(self.io);
        const current = self.snapshotLocked();
        if (current.generation != generation or current.state == .shutdown) {
            self.mutex.unlock(self.io);
            return current;
        }
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.io).raw.nanoseconds <= 0)
        {
            self.mutex.unlock(self.io);
            return error.Timeout;
        }
        waiter.registered = true;
        self.waiters.append(&waiter.node);
        self.mutex.unlock(self.io);

        waiter.event.waitTimeout(
            self.io,
            .{ .deadline = deadline },
        ) catch |err| {
            self.mutex.lockUncancelable(self.io);
            if (waiter.registered) {
                self.waiters.remove(&waiter.node);
                waiter.registered = false;
                self.mutex.unlock(self.io);
                return err;
            }
            const changed = waiter.snapshot;
            self.mutex.unlock(self.io);
            return changed;
        };
        return waiter.snapshot;
    }

    fn snapshotLocked(self: *const Tracker) Snapshot {
        return .{ .state = self.state, .generation = self.generation };
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

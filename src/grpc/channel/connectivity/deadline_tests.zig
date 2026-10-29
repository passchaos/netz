const std = @import("std");
const connectivity = @import("../connectivity.zig");
const allocator = std.testing.allocator;

const Gate = struct {
    delegate: std.Io,
    tracker: *connectivity.Tracker,
    entered: std.Io.Event = .unset,
    armed: bool = true,
    var active: ?*Gate = null;

    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.armed) {
            self.armed = false;
            // Registration released the tracker mutex before event waiting.
            // Keep it occupied through timeout and the unregister path.
            self.tracker.mutex.lockUncancelable(self.delegate);
            self.entered.set(self.delegate);
        }
        return self.delegate.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

const Cleanup = enum { snapshot, same_state, next_wait, shutdown, release };

fn exercise(unregister: bool, canceled: bool, cleanup: Cleanup) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const tracker = try connectivity.Tracker.create(allocator, base);
    defer tracker.release();
    var watch = connectivity.Watch.init(tracker);
    defer watch.deinit();
    var gate = Gate{ .delegate = base, .tracker = tracker };
    var table = base.vtable.*;
    if (unregister) {
        Gate.active = &gate;
        table.futexWait = Gate.wait;
        tracker.io = .{ .userdata = base.userdata, .vtable = &table };
    }
    defer Gate.active = null;
    var locked = !unregister;
    if (locked) tracker.mutex.lockUncancelable(base);
    defer if (locked) tracker.mutex.unlock(base);
    const Task = struct {
        watch: *connectivity.Watch,
        io: std.Io,
        started: std.Io.Event = .unset,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        canceled: bool,
        fn run(self: *@This()) void {
            self.started.set(self.io);
            _ = self.watch.nextWithTimeout(if (self.canceled) .fromSeconds(1) else .fromMilliseconds(10)) catch |err| {
                self.err = err;
            };
            self.done.set(self.io);
        }
    };
    var task = Task{ .watch = &watch, .io = base, .canceled = canceled };
    var future = try base.concurrent(Task.run, .{&task});
    defer _ = future.cancel(base);
    try task.started.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    if (unregister) {
        try gate.entered.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
        locked = true;
    }
    if (canceled) _ = future.cancel(base);
    const observed = if (task.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } })) |_| true else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    if (observed and unregister) try std.testing.expect(tracker.waiters.first != null);
    tracker.mutex.unlock(base);
    locked = false;
    future.await(base);
    try std.testing.expect(observed);
    try std.testing.expectEqual(@as(?anyerror, if (canceled) error.Canceled else error.Timeout), task.err);
    try std.testing.expectEqualDeep(connectivity.Snapshot{ .state = .idle, .generation = 0 }, watch.snapshot());
    switch (cleanup) {
        .snapshot => _ = tracker.snapshot(),
        .same_state => tracker.setState(.idle),
        .next_wait => try std.testing.expectError(error.Timeout, watch.nextWithTimeout(.fromMilliseconds(1))),
        .shutdown => tracker.setState(.shutdown),
        .release => return, // Final tracker release retires the abandoned list.
    }
    try std.testing.expect(tracker.waiters.first == null);
    if (cleanup == .shutdown) {
        try std.testing.expectEqual(connectivity.State.shutdown, (try watch.nextWithTimeout(.zero)).state);
    } else {
        tracker.setState(.ready);
        try std.testing.expectEqual(connectivity.State.ready, (try watch.nextWithTimeout(.zero)).state);
    }
}

test "gRPC connectivity watch deadline includes registration mutex contention" {
    try exercise(false, false, .snapshot);
}

test "gRPC connectivity watch deadline includes unregister mutex contention" {
    for (std.enums.values(Cleanup)) |cleanup| try exercise(true, false, cleanup);
}

test "gRPC connectivity watch cancellation preserves cursor through mutex contention" {
    try exercise(false, true, .snapshot);
    for (std.enums.values(Cleanup)) |cleanup| try exercise(true, true, cleanup);
}

test "gRPC connectivity snapshot watch initialization and exit-idle obey lock deadlines" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const tracker = try connectivity.Tracker.create(allocator, base);
    defer tracker.release();
    const references = tracker.references.load(.acquire);
    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            if (pointer == mutex) {
                self.unbounded_waits += 1;
                self.mutex.state.store(.unlocked, .release);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var probe = Probe{ .base = base, .mutex = &tracker.mutex };
    var table = base.vtable.*;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    tracker.io = .{ .userdata = base.userdata, .vtable = &table };
    tracker.mutex.lockUncancelable(base);

    try std.testing.expectError(error.Timeout, tracker.snapshotWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, connectivity.Watch.initWithTimeout(tracker, .fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, tracker.exitIdleWithDeadline(.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(1) })));
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expectEqual(references, tracker.references.load(.acquire));
    try std.testing.expect(!tracker.mutex.tryLock());

    tracker.io = base;
    Probe.active = null;
    tracker.mutex.unlock(base);
}

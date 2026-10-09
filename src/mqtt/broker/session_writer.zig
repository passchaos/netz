const std = @import("std");

const State = enum(u2) {
    idle,
    queued,
    running,
    rerun,
};

/// Allocation-free bounded work queue used by the broker's shared durable
/// Session writers. At most one queued or running entry exists for each slot;
/// work arriving while that slot is running is coalesced into one rerun.
pub const WorkQueue = struct {
    states: []State,
    ring: []usize,
    head: usize = 0,
    len: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        slot_count: usize,
    ) std.mem.Allocator.Error!WorkQueue {
        std.debug.assert(slot_count != 0);
        const states = try allocator.alloc(State, slot_count);
        errdefer allocator.free(states);
        const ring = try allocator.alloc(usize, slot_count);
        @memset(states, .idle);
        return .{
            .states = states,
            .ring = ring,
        };
    }

    pub fn deinit(self: *WorkQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.ring);
        allocator.free(self.states);
        self.* = undefined;
    }

    /// Returns true only when a new queue entry was added. A queued duplicate
    /// needs no work; a running duplicate marks one bounded rerun instead.
    pub fn schedule(self: *WorkQueue, slot_index: usize) bool {
        std.debug.assert(slot_index < self.states.len);
        switch (self.states[slot_index]) {
            .idle => {
                self.push(slot_index);
                self.states[slot_index] = .queued;
                return true;
            },
            .queued, .rerun => return false,
            .running => {
                self.states[slot_index] = .rerun;
                return false;
            },
        }
    }

    pub fn take(self: *WorkQueue) ?usize {
        if (self.len == 0) return null;
        const slot_index = self.ring[self.head];
        self.head = (self.head + 1) % self.ring.len;
        self.len -= 1;
        std.debug.assert(self.states[slot_index] == .queued);
        self.states[slot_index] = .running;
        return slot_index;
    }

    /// Completes a running slot and returns whether one coalesced rerun was
    /// queued. The caller uses this to wake an idle worker.
    pub fn complete(self: *WorkQueue, slot_index: usize) bool {
        std.debug.assert(slot_index < self.states.len);
        switch (self.states[slot_index]) {
            .running => {
                self.states[slot_index] = .idle;
                return false;
            },
            .rerun => {
                self.push(slot_index);
                self.states[slot_index] = .queued;
                return true;
            },
            .idle, .queued => unreachable,
        }
    }

    pub fn isEmpty(self: *const WorkQueue) bool {
        return self.len == 0;
    }

    pub fn reset(self: *WorkQueue) void {
        @memset(self.states, .idle);
        self.head = 0;
        self.len = 0;
    }

    fn push(self: *WorkQueue, slot_index: usize) void {
        std.debug.assert(self.len < self.ring.len);
        const tail = (self.head + self.len) % self.ring.len;
        self.ring[tail] = slot_index;
        self.len += 1;
    }
};

pub const Pool = struct {
    pub const RunFn = *const fn (context: *anyopaque, slot_index: usize) void;

    serving: std.atomic.Value(bool) = .init(false),
    active: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    mutex: std.Io.Mutex = .init,
    ready: std.Io.Condition = .init,
    work: WorkQueue,
    errors: []?anyerror,
    group: ?*std.Io.Group = null,
    context: ?*anyopaque = null,
    run_fn: ?RunFn = null,
    worker_count: usize = 0,
    unavailable: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        slot_count: usize,
    ) std.mem.Allocator.Error!Pool {
        var work = try WorkQueue.init(allocator, slot_count);
        errdefer work.deinit(allocator);
        const errors = try allocator.alloc(?anyerror, slot_count);
        @memset(errors, null);
        return .{
            .work = work,
            .errors = errors,
        };
    }

    pub fn deinit(self: *Pool, allocator: std.mem.Allocator) void {
        std.debug.assert(!self.serving.load(.acquire));
        std.debug.assert(!self.active.load(.acquire));
        allocator.free(self.errors);
        self.work.deinit(allocator);
        self.* = undefined;
    }

    pub fn isAvailable(self: *const Pool) bool {
        return self.serving.load(.acquire);
    }

    /// Open one serving scope without allocating a coroutine stack. The first
    /// eligible multi-destination delivery starts the fixed worker set.
    pub fn begin(
        self: *Pool,
        io: std.Io,
        group: *std.Io.Group,
        worker_count: usize,
        context: *anyopaque,
        run_fn: RunFn,
    ) void {
        std.debug.assert(!self.isAvailable());
        std.debug.assert(!self.active.load(.acquire));
        std.debug.assert(worker_count != 0);
        std.debug.assert(worker_count <= self.work.states.len);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.work.reset();
        @memset(self.errors, null);
        self.group = group;
        self.context = context;
        self.run_fn = run_fn;
        self.worker_count = worker_count;
        self.unavailable = false;
        self.stopping.store(false, .release);
        self.serving.store(true, .release);
    }

    /// Lazily start every worker as one transaction. A scheduling-resource
    /// failure disables the pool for this serving scope; the broker can then
    /// preserve delivery by using its synchronous path.
    pub fn ensureStarted(self: *Pool, io: std.Io) bool {
        if (self.active.load(.acquire)) return true;
        if (!self.isAvailable()) return false;

        self.mutex.lockUncancelable(io);
        if (self.active.load(.acquire)) {
            self.mutex.unlock(io);
            return true;
        }
        if (!self.isAvailable() or self.unavailable) {
            self.mutex.unlock(io);
            return false;
        }
        const group = self.group.?;
        for (0..self.worker_count) |_| {
            group.concurrent(
                io,
                Worker.run,
                .{ self, io, self.context.?, self.run_fn.? },
            ) catch {
                self.unavailable = true;
                self.stopping.store(true, .release);
                self.ready.broadcast(io);
                self.mutex.unlock(io);
                group.cancel(io);
                return false;
            };
        }
        self.active.store(true, .release);
        self.mutex.unlock(io);
        return true;
    }

    pub fn stop(self: *Pool, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        const workers_started = self.active.load(.acquire);
        const group = self.group.?;
        self.serving.store(false, .release);
        self.active.store(false, .release);
        self.stopping.store(true, .release);
        self.ready.broadcast(io);
        self.mutex.unlock(io);
        if (workers_started) group.await(io) catch {};

        self.mutex.lockUncancelable(io);
        self.work.reset();
        self.group = null;
        self.context = null;
        self.run_fn = null;
        self.worker_count = 0;
        self.unavailable = false;
        self.mutex.unlock(io);
    }

    /// Returns false only when the serving scope is stopping, letting the
    /// caller fall back to an ordered synchronous flush without losing work.
    pub fn schedule(self: *Pool, io: std.Io, slot_index: usize) bool {
        if (!self.active.load(.acquire)) return false;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (!self.active.load(.acquire)) return false;
        if (self.work.schedule(slot_index)) self.ready.signal(io);
        return true;
    }

    pub fn recordError(
        self: *Pool,
        io: std.Io,
        slot_index: usize,
        err: anyerror,
    ) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.errors[slot_index] == null) self.errors[slot_index] = err;
    }

    pub fn takeError(
        self: *Pool,
        io: std.Io,
        slot_index: usize,
    ) ?anyerror {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const writer_error = self.errors[slot_index];
        self.errors[slot_index] = null;
        return writer_error;
    }

    fn take(self: *Pool, io: std.Io) ?usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (self.work.isEmpty() and !self.stopping.load(.acquire)) {
            self.ready.waitUncancelable(io, &self.mutex);
        }
        if (self.stopping.load(.acquire)) return null;
        return self.work.take().?;
    }

    fn complete(self: *Pool, io: std.Io, slot_index: usize) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.work.complete(slot_index)) self.ready.signal(io);
    }

    const Worker = struct {
        fn run(
            pool: *Pool,
            io: std.Io,
            context: *anyopaque,
            run_fn: RunFn,
        ) void {
            while (pool.take(io)) |slot_index| {
                run_fn(context, slot_index);
                pool.complete(io, slot_index);
            }
        }
    };
};

test "durable Session writer queue coalesces queued and running work" {
    var queue = try WorkQueue.init(std.testing.allocator, 2);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.schedule(1));
    try std.testing.expect(!queue.schedule(1));
    try std.testing.expectEqual(@as(?usize, 1), queue.take());
    try std.testing.expect(queue.isEmpty());

    try std.testing.expect(!queue.schedule(1));
    try std.testing.expect(!queue.schedule(1));
    try std.testing.expect(queue.complete(1));
    try std.testing.expectEqual(@as(?usize, 1), queue.take());
    try std.testing.expect(!queue.complete(1));
    try std.testing.expect(queue.isEmpty());
}

test "durable Session writer queue wraps at its fixed slot bound" {
    var queue = try WorkQueue.init(std.testing.allocator, 3);
    defer queue.deinit(std.testing.allocator);

    try std.testing.expect(queue.schedule(0));
    try std.testing.expect(queue.schedule(1));
    try std.testing.expect(queue.schedule(2));
    try std.testing.expectEqual(@as(?usize, 0), queue.take());
    try std.testing.expect(!queue.complete(0));
    try std.testing.expect(queue.schedule(0));

    try std.testing.expectEqual(@as(?usize, 1), queue.take());
    try std.testing.expect(!queue.complete(1));
    try std.testing.expectEqual(@as(?usize, 2), queue.take());
    try std.testing.expect(!queue.complete(2));
    try std.testing.expectEqual(@as(?usize, 0), queue.take());
    try std.testing.expect(!queue.complete(0));
    try std.testing.expectEqual(@as(?usize, null), queue.take());
}

test "durable Session writer pool starts lazily and stops idle waiters" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try Pool.init(std.testing.allocator, 4);
    defer pool.deinit(std.testing.allocator);
    var calls: usize = 0;
    const run = struct {
        fn run(context: *anyopaque, _: usize) void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    }.run;

    var unused_group: std.Io.Group = .init;
    pool.begin(io, &unused_group, 2, &calls, run);
    try std.testing.expect(pool.isAvailable());
    try std.testing.expect(!pool.active.load(.acquire));
    pool.stop(io);
    try std.testing.expect(!pool.isAvailable());

    var active_group: std.Io.Group = .init;
    pool.begin(io, &active_group, 2, &calls, run);
    try std.testing.expect(pool.ensureStarted(io));
    try std.testing.expect(pool.active.load(.acquire));
    pool.stop(io);
    try std.testing.expect(!pool.isAvailable());
    try std.testing.expect(!pool.active.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), calls);
}

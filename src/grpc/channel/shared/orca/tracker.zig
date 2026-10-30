//! Reference-counted latest-value ORCA report fan-out per endpoint.
const std = @import("std");
const timed_mutex = @import("../../../../internal/timed_mutex.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");
const orca = @import("../../../orca.zig");

pub const Status = enum {
    idle,
    ready,
    unavailable,
    unimplemented,
    shutdown,
};

pub const Header = struct {
    status: Status,
    generation: u64,
};

pub const Update = struct {
    header: Header,
    report: ?orca.OwnedLoadReport,

    pub fn deinit(self: *Update) void {
        if (self.report) |*report| report.deinit();
        self.* = undefined;
    }
};

pub const Error = std.Io.Event.WaitTimeoutError || std.mem.Allocator.Error;

const Waiter = struct {
    const State = enum(u8) { waiting, notified, abandoned };

    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    state: std.atomic.Value(State) = .init(.waiting),
    node: std.DoublyLinkedList.Node = .{},
    event: std.Io.Event = .unset,
    header: Header = undefined,

    fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Waiter {
        const waiter = try allocator.create(Waiter);
        waiter.* = .{ .allocator = allocator };
        return waiter;
    }

    fn retain(self: *Waiter) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn release(self: *Waiter) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            self.allocator.destroy(self);
        }
    }

    fn notify(self: *Waiter, io: std.Io, header: Header) void {
        self.header = header;
        if (self.state.cmpxchgStrong(
            .waiting,
            .notified,
            .release,
            .monotonic,
        ) == null) self.event.set(io);
    }

    fn abandon(self: *Waiter) bool {
        return self.state.cmpxchgStrong(
            .waiting,
            .abandoned,
            .acq_rel,
            .acquire,
        ) == null;
    }
};

pub const Tracker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    refs: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    status: Status = .idle,
    generation: u64 = 0,
    latest: ?orca.OwnedLoadReport = null,
    waiters: std.DoublyLinkedList = .{},
    abandoned: std.atomic.Value(bool) = .init(false),

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
    ) std.mem.Allocator.Error!*Tracker {
        const tracker = try allocator.create(Tracker);
        tracker.* = .{ .allocator = allocator, .io = io };
        return tracker;
    }

    pub fn retain(self: *Tracker) void {
        const previous = self.refs.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
    }

    pub fn release(self: *Tracker) void {
        const previous = self.refs.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        self.pruneLocked();
        std.debug.assert(self.waiters.first == null);
        if (self.latest) |*report| report.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Transfer one decoded report into the latest-value slot.
    pub fn publish(self: *Tracker, report: *orca.OwnedLoadReport) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.status == .shutdown) {
            report.deinit();
            report.* = undefined;
            return;
        }
        if (self.latest) |*previous| previous.deinit();
        self.latest = report.*;
        report.* = undefined;
        self.advanceLocked(.ready, false);
    }

    pub fn setStatus(self: *Tracker, status: Status) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.status == .shutdown or self.status == status) return;
        self.advanceLocked(status, status != .ready);
    }

    pub fn shutdown(self: *Tracker) void {
        self.setStatus(.shutdown);
    }

    pub fn current(self: *Tracker) Error!Update {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneLocked();
        return self.cloneLocked();
    }

    pub fn currentWithDeadline(
        self: *Tracker,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Update {
        try timed_mutex.lock(&self.mutex, self.io, deadline);
        defer self.mutex.unlock(self.io);
        self.pruneLocked();
        return self.cloneLocked();
    }

    fn waitAfter(
        self: *Tracker,
        generation: u64,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Header {
        if (!self.mutex.tryLock()) {
            try timed_mutex.lock(&self.mutex, self.io, deadline);
        }
        self.pruneLocked();
        const header = self.headerLocked();
        if (header.generation != generation or header.status == .shutdown) {
            self.mutex.unlock(self.io);
            return header;
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
        waiter.retain();
        self.waiters.append(&waiter.node);
        self.mutex.unlock(self.io);
        while (true) {
            waiter.event.waitTimeout(self.io, .{ .deadline = deadline }) catch |err| {
                if (waiter.state.load(.acquire) == .notified) {
                    return waiter.header;
                }
                if (err == error.Timeout) {
                    if (deadline_policy.usableAwake(self.io, deadline)) |_| {
                        continue;
                    } else |_| {}
                }
                if (waiter.abandon()) {
                    self.abandoned.store(true, .release);
                    if (self.mutex.tryLock()) {
                        self.pruneLocked();
                        self.mutex.unlock(self.io);
                    }
                    return err;
                }
                return waiter.header;
            };
            return waiter.header;
        }
    }

    fn advanceLocked(
        self: *Tracker,
        status: Status,
        clear_report: bool,
    ) void {
        self.pruneLocked();
        if (clear_report) {
            if (self.latest) |*report| report.deinit();
            self.latest = null;
        }
        self.status = status;
        self.generation +%= 1;
        const header = self.headerLocked();
        while (self.waiters.popFirst()) |node| {
            const waiter: *Waiter = @fieldParentPtr("node", node);
            waiter.notify(self.io, header);
            waiter.release();
        }
    }

    fn cloneLocked(self: *Tracker) Error!Update {
        return .{
            .header = self.headerLocked(),
            .report = if (self.latest) |report|
                try report.clone(self.allocator)
            else
                null,
        };
    }

    fn headerLocked(self: *const Tracker) Header {
        return .{ .status = self.status, .generation = self.generation };
    }

    fn pruneLocked(self: *Tracker) void {
        if (!self.abandoned.swap(false, .acq_rel)) return;
        var node = self.waiters.first;
        while (node) |current_node| {
            node = current_node.next;
            const waiter: *Waiter = @fieldParentPtr("node", current_node);
            if (waiter.state.load(.acquire) == .abandoned) {
                self.waiters.remove(current_node);
                waiter.release();
            }
        }
    }
};

pub const Watch = struct {
    tracker: *Tracker,
    observed_generation: u64 = 0,

    pub fn init(tracker: *Tracker) Watch {
        tracker.retain();
        return .{ .tracker = tracker };
    }

    pub fn deinit(self: *Watch) void {
        self.tracker.release();
        self.* = undefined;
    }

    pub fn current(self: *Watch) Error!Update {
        const update = try self.tracker.current();
        self.observed_generation = update.header.generation;
        return update;
    }

    pub fn nextWithDeadline(
        self: *Watch,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Update {
        _ = try self.tracker.waitAfter(self.observed_generation, deadline);
        const update = try self.tracker.currentWithDeadline(deadline);
        self.observed_generation = update.header.generation;
        return update;
    }

    pub fn nextWithTimeout(
        self: *Watch,
        timeout: std.Io.Duration,
    ) Error!Update {
        return self.nextWithDeadline(.fromNow(self.tracker.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }
};

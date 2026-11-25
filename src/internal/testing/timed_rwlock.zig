//! Read-lock ownership and waiter handoff after interrupted admission.
const std = @import("std");
const locking = @import("../timed_rwlock.zig");
const policy = @import("../deadline.zig");

pub fn fastPath() !void {
    const Probe = struct {
        mode: enum { late, canceled, expired },
        checks: usize = 0,
        clocks: usize = 0,
        fn context(userdata: ?*anyopaque) *@This() {
            return @ptrCast(@alignCast(userdata.?));
        }
        fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
            const self = context(userdata);
            self.checks += 1;
            if (self.mode == .canceled and self.checks == 2) return error.Canceled;
        }
        fn now(userdata: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self = context(userdata);
            self.clocks += 1;
            return .{ .nanoseconds = if (self.mode == .expired or (self.mode == .late and self.clocks > 1)) 300 else 100 };
        }
    };
    inline for (.{ .late, .canceled, .expired }) |mode| {
        var probe: Probe = .{ .mode = mode };
        var table = std.Io.failing.vtable.*;
        table.checkCancel = Probe.check;
        table.now = Probe.now;
        const io: std.Io = .{ .userdata = &probe, .vtable = &table };
        var lock: std.Io.RwLock = .init;
        const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .{ .nanoseconds = 200 } };
        try std.testing.expectError(if (mode == .canceled) error.Canceled else error.Timeout, locking.lockShared(&lock, io, deadline));
        // A rejected fast-path reader must not leave the writer locked out.
        try std.testing.expect(lock.tryLock(io));
        lock.unlock(io);
    }
}

fn waitBefore(event: *std.Io.Event, io: std.Io) !void {
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| switch (err) {
            error.Canceled => return err,
            error.Timeout => {
                _ = try policy.usableAwake(io, deadline);
                continue;
            },
        };
        return;
    }
}

pub fn canceledWaiter() !void {
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var lock: std.Io.RwLock = .init;
    lock.lockUncancelable(io);
    var writer_held = true;
    defer if (writer_held) lock.unlock(io);

    const Observe = struct {
        delegate: std.Io,
        target: *const u32,
        first: std.Io.Event = .unset,
        second: std.Io.Event = .unset,
        admissions: std.atomic.Value(usize) = .init(0),
        var active: ?*@This() = null;
        fn waitFirst(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (ptr == self.target) self.first.set(self.delegate);
            return self.delegate.vtable.futexWait(userdata, ptr, expected, timeout);
        }
        fn waitSecond(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (ptr == self.target) self.second.set(self.delegate);
            return self.delegate.vtable.futexWait(userdata, ptr, expected, timeout);
        }
        fn rejectConcurrent(_: ?*anyopaque, _: *std.Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            _ = active.?.admissions.fetchAdd(1, .monotonic);
            return error.ConcurrencyUnavailable;
        }
    };
    var observe: Observe = .{ .delegate = io, .target = @ptrCast(&lock.mutex.state.raw) };
    Observe.active = &observe;
    defer Observe.active = null;
    var first_table = io.vtable.*;
    first_table.futexWait = Observe.waitFirst;
    first_table.groupConcurrent = Observe.rejectConcurrent;
    var second_table = first_table;
    second_table.futexWait = Observe.waitSecond;
    const Worker = struct {
        io: std.Io,
        lock: *std.Io.RwLock,
        err: ?anyerror = null,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            defer self.done.set(self.io);
            locking.lockShared(self.lock, self.io, .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(5) })) catch |err| {
                self.err = err;
                return;
            };
            self.lock.unlockShared(self.io);
        }
    };
    var first: Worker = .{ .io = .{ .userdata = io.userdata, .vtable = &first_table }, .lock = &lock };
    var first_future = try std.Io.concurrent(io, Worker.run, .{&first});
    defer first_future.cancel(io);
    try waitBefore(&observe.first, io);
    var second: Worker = .{ .io = .{ .userdata = io.userdata, .vtable = &second_table }, .lock = &lock };
    var second_future = try std.Io.concurrent(io, Worker.run, .{&second});
    defer second_future.cancel(io);
    try waitBefore(&observe.second, io);
    first_future.cancel(io);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), first.err);
    lock.unlock(io);
    writer_held = false;
    try waitBefore(&second.done, io);
    second_future.await(io);
    try std.testing.expect(second.err == null);
    try std.testing.expectEqual(@as(usize, 0), observe.admissions.load(.acquire));
    try std.testing.expect(lock.tryLock(io));
    lock.unlock(io);
}

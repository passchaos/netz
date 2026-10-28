const std = @import("std");
const timed = @import("timed_mutex.zig");

const Probe = struct {
    mutex: *std.Io.Mutex,
    now_ns: i96 = 1000,
    waits: usize = 0,
    wakes: usize = 0,
    cancel_on_wait: bool = false,
    release_on_wait: bool = false,
    now_calls: usize = 0,
    expire_on_now_call: ?usize = null,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.now_calls += 1;
        if (self.expire_on_now_call == self.now_calls) self.now_ns = 1003;
        return .fromNanoseconds(self.now_ns);
    }

    fn wait(context: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.waits += 1;
        if (self.cancel_on_wait) {
            // The original owner released the mutex at the same time that
            // this notified waiter was canceled. Another waiter needs a wake.
            self.mutex.state.store(.unlocked, .release);
            return error.Canceled;
        }
        if (self.release_on_wait) self.mutex.state.store(.unlocked, .release);
        self.now_ns += 1;
    }

    fn wake(context: ?*anyopaque, _: *const u32, _: u32) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.wakes += 1;
    }
};

test "timed mutex ignores spurious wakes until its original deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var mutex: std.Io.Mutex = .init;
    mutex.lockUncancelable(base);
    var probe = Probe{ .mutex = &mutex };
    var table = base.vtable.*;
    table.now = Probe.now;
    table.futexWait = Probe.wait;
    table.futexWake = Probe.wake;
    const io: std.Io = .{ .userdata = &probe, .vtable = &table };
    try std.testing.expectError(error.Timeout, timed.lock(&mutex, io, .{ .clock = .awake, .raw = .fromNanoseconds(1003) }));
    try std.testing.expectEqual(@as(usize, 3), probe.waits);
    try std.testing.expect(!mutex.tryLock());
    mutex.unlock(base);
    try timed.lock(&mutex, base, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    mutex.unlock(base);
}

test "timed mutex cancellation passes a consumed unlock wake to another waiter" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var mutex: std.Io.Mutex = .init;
    mutex.lockUncancelable(base);
    var probe = Probe{ .mutex = &mutex, .cancel_on_wait = true };
    var table = base.vtable.*;
    table.now = Probe.now;
    table.futexWait = Probe.wait;
    table.futexWake = Probe.wake;
    const io: std.Io = .{ .userdata = &probe, .vtable = &table };
    try std.testing.expectError(error.Canceled, timed.lock(&mutex, io, .{ .clock = .awake, .raw = .fromNanoseconds(1003) }));
    try std.testing.expectEqual(@as(usize, 1), probe.wakes);
    try std.testing.expect(mutex.tryLock());
    mutex.unlock(base);
}

test "timed mutex rejects expired and foreign clock bounds before acquisition" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var mutex: std.Io.Mutex = .init;
    try std.testing.expectError(error.Timeout, timed.lock(&mutex, io, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expectError(error.Timeout, timed.lock(&mutex, io, .{ .clock = .real, .raw = .zero }));
    try std.testing.expect(mutex.tryLock());
    mutex.unlock(io);
}

test "timed mutex admits a notified waiter within the original deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var mutex: std.Io.Mutex = .init;
    mutex.lockUncancelable(base);
    var probe = Probe{ .mutex = &mutex, .release_on_wait = true };
    var table = base.vtable.*;
    table.now = Probe.now;
    table.futexWait = Probe.wait;
    table.futexWake = Probe.wake;
    const io: std.Io = .{ .userdata = &probe, .vtable = &table };
    try timed.lock(&mutex, io, .{ .clock = .awake, .raw = .fromNanoseconds(1003) });
    try std.testing.expectEqual(@as(usize, 1), probe.waits);
    try std.testing.expect(!mutex.tryLock());
    mutex.unlock(io);
    try std.testing.expectEqual(@as(usize, 1), probe.wakes);
}

test "timed mutex releases admission when the deadline expires during acquisition" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |contended| {
        var mutex: std.Io.Mutex = .init;
        if (contended) mutex.lockUncancelable(base);
        var probe = Probe{ .mutex = &mutex, .release_on_wait = contended, .expire_on_now_call = if (contended) 4 else 2 };
        var table = base.vtable.*;
        table.now = Probe.now;
        table.futexWait = Probe.wait;
        table.futexWake = Probe.wake;
        const io: std.Io = .{ .userdata = &probe, .vtable = &table };
        try std.testing.expectError(error.Timeout, timed.lock(&mutex, io, .{ .clock = .awake, .raw = .fromNanoseconds(1003) }));
        try std.testing.expectEqual(@as(usize, if (contended) 1 else 0), probe.wakes);
        try std.testing.expect(mutex.tryLock());
        mutex.unlock(base);
    }
}

const std = @import("std");
const connectivity = @import("../connectivity.zig");
const Waiter = @import("waiter.zig").Waiter;
const allocator = std.testing.allocator;

test "gRPC connectivity watch notification wins before cancellation without caller-stack ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const waiter = try Waiter.create(allocator);
    defer waiter.release();
    waiter.retain(); // Track the reference used by the publishing list.
    const expected: connectivity.Snapshot = .{ .state = .ready, .generation = 7 };
    waiter.notify(io, expected);
    waiter.release();
    try std.testing.expect(!waiter.abandon());
    try std.testing.expectEqualDeep(expected, waiter.snapshot);
    try std.testing.expect(waiter.event.isSet());
}

test "gRPC connectivity watch abandoned node outlives the caller until tracker notification" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const waiter = try Waiter.create(allocator);
    waiter.retain();
    try std.testing.expect(waiter.abandon());
    waiter.release(); // Caller has already returned Timeout or Canceled.
    defer waiter.release();
    waiter.notify(io, .{ .state = .shutdown, .generation = 8 });
    try std.testing.expectEqual(Waiter.State.abandoned, waiter.state.load(.acquire));
    try std.testing.expect(!waiter.event.isSet());
}

test "gRPC connectivity watch keeps the notification owner through event wake" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const waiter = try Waiter.create(failing.allocator());
    waiter.retain();
    waiter.event = .waiting;
    const Probe = struct {
        var current: *Waiter = undefined;
        var called: bool = false;
        fn wake(_: ?*anyopaque, _: *const u32, _: u32) void {
            called = true;
            // A notified caller may finish before event.set returns.
            current.release();
        }
    };
    Probe.current = waiter;
    Probe.called = false;
    var table = base.vtable.*;
    table.futexWake = Probe.wake;
    waiter.notify(.{ .userdata = base.userdata, .vtable = &table }, .{ .state = .ready, .generation = 4 });
    try std.testing.expect(Probe.called);
    try std.testing.expectEqual(@as(usize, 0), failing.deallocations);
    waiter.release();
    try std.testing.expectEqual(@as(usize, 1), failing.deallocations);
}

test "gRPC connectivity watch allocation failure preserves tracker cursor and retry" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const tracker = try connectivity.Tracker.create(failing.allocator(), threaded.io());
    defer tracker.release();
    var watch = connectivity.Watch.init(tracker);
    defer watch.deinit();
    const original = watch.snapshot();
    try std.testing.expectError(error.OutOfMemory, watch.nextWithTimeout(.fromSeconds(1)));
    try std.testing.expect(tracker.waiters.first == null);
    try std.testing.expectEqualDeep(original, watch.snapshot());
    tracker.setState(.connecting);
    try std.testing.expectEqual(connectivity.State.connecting, (try watch.nextWithTimeout(.zero)).state);
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectError(error.Timeout, watch.nextWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectEqual(@as(usize, 1), failing.deallocations);
    tracker.setState(.ready);
    try std.testing.expectEqual(connectivity.State.ready, (try watch.nextWithTimeout(.zero)).state);
}

test "gRPC connectivity watch ignores spurious wakes until its original deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    const Probe = struct {
        now_ns: i96 = 1000,
        waits: usize = 0,
        expected: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1003) },
        changed_deadline: bool = false,
        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }
        fn wait(context: ?*anyopaque, _: *const u32, _: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.waits += 1;
            if (timeout != .deadline or !std.meta.eql(timeout.deadline, self.expected)) self.changed_deadline = true;
            self.now_ns += 1;
        }
        fn wake(_: ?*anyopaque, _: *const u32, _: u32) void {}
    };
    var probe: Probe = .{};
    var table = base.vtable.*;
    table.now = Probe.now;
    table.futexWait = Probe.wait;
    table.futexWake = Probe.wake;
    const tracker = try connectivity.Tracker.create(allocator, .{ .userdata = &probe, .vtable = &table });
    defer tracker.release();
    var watch = connectivity.Watch.init(tracker);
    defer watch.deinit();
    try std.testing.expectError(error.Timeout, watch.nextWithDeadline(probe.expected));
    try std.testing.expectEqual(@as(usize, 3), probe.waits);
    try std.testing.expect(!probe.changed_deadline);
    try std.testing.expect(tracker.waiters.first == null);
}

test "gRPC connectivity watch returns first notification when cancellation races later states" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    const tracker = try connectivity.Tracker.create(allocator, base);
    defer tracker.release();
    var watch = connectivity.Watch.init(tracker);
    defer watch.deinit();
    const Probe = struct {
        var current: *connectivity.Tracker = undefined;
        fn wait(_: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
            current.setState(.ready);
            current.setState(.idle);
            return error.Canceled;
        }
    };
    Probe.current = tracker;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    tracker.io = .{ .userdata = base.userdata, .vtable = &table };
    const first = try watch.nextWithTimeout(.fromSeconds(1));
    try std.testing.expectEqualDeep(connectivity.Snapshot{ .state = .ready, .generation = 1 }, first);
    const latest = try watch.nextWithTimeout(.zero);
    try std.testing.expectEqualDeep(connectivity.Snapshot{ .state = .idle, .generation = 2 }, latest);
    try std.testing.expect(tracker.waiters.first == null);
}

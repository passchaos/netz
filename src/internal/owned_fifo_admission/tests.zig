const std = @import("std");
const Queue = @import("../owned_fifo_admission.zig").Queue;

test "owned FIFO admission preserves order and retires abandoned head and middle nodes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var first: Queue.Waiter = .{};
    var second: Queue.Waiter = .{};
    var third: Queue.Waiter = .{};
    defer {
        _ = queue.abandon(&first, io);
        _ = queue.abandon(&second, io);
        _ = queue.abandon(&third, io);
        queue.pruneAbandoned(io);
    }
    try queue.enqueue(&first, std.testing.allocator, io);
    try queue.enqueue(&second, std.testing.allocator, io);
    try queue.enqueue(&third, std.testing.allocator, io);
    try std.testing.expect(!queue.mayAttempt(null, io));
    try std.testing.expect(!queue.mayAttempt(&second, io));
    try std.testing.expect(queue.mayAttempt(&first, io));
    try std.testing.expect(queue.abandon(&second, io));
    try std.testing.expectEqual(@as(usize, 3), queue.len);
    try std.testing.expectEqual(@as(usize, 2), queue.count(io));
    try std.testing.expect(!first.isNotified());
    try std.testing.expect(!third.isNotified());
    try std.testing.expect(queue.abandon(&first, io));
    try std.testing.expect(queue.mayAttempt(&third, io));
    try std.testing.expect(third.isNotified());
    try std.testing.expectEqual(@as(usize, 1), queue.count(io));
    queue.cancel(&third, io);
    try std.testing.expect(queue.mayAttempt(null, io));
    try std.testing.expectEqual(@as(usize, 0), queue.count(io));
}

test "owned FIFO admission allocates only on registration and leaves failed registration empty" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var queue: Queue = .{};
    var waiter: Queue.Waiter = .{};
    try std.testing.expect(queue.mayAttempt(null, io));
    try std.testing.expect(!queue.abandon(&waiter, io));
    try std.testing.expectEqual(@as(usize, 0), queue.count(io));
    try std.testing.expectError(error.OutOfMemory, queue.enqueue(&waiter, failing.allocator(), io));
    try std.testing.expect(waiter.node == null);
    try std.testing.expect(!waiter.linked);
    try std.testing.expect(queue.head == null and queue.tail == null);
    try std.testing.expectEqual(@as(usize, 0), queue.count(io));
}

test "owned FIFO admission reuses a detached cursor until caller cleanup" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var waiter: Queue.Waiter = .{};
    defer {
        _ = queue.abandon(&waiter, io);
        queue.pruneAbandoned(io);
    }
    try queue.enqueue(&waiter, std.testing.allocator, io);
    const node = waiter.node.?;
    try std.testing.expect(queue.remove(&waiter));
    try std.testing.expectEqual(@as(usize, 1), node.references.load(.acquire));
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try queue.enqueue(&waiter, failing.allocator(), io);
    try std.testing.expect(waiter.node == node);
    queue.notifyHead(io);
    try std.testing.expect(waiter.isNotified());
    waiter.rearm();
    try std.testing.expect(!waiter.isNotified());
    queue.notifyHead(io);
    try std.testing.expect(waiter.isNotified());
    queue.cancel(&waiter, io);
    try std.testing.expect(waiter.node == null);
}

const WakeGate = struct {
    queue: *Queue,
    waiter: *Queue.Waiter,
    io: std.Io = undefined,
    armed: bool = true,
    retained: bool = false,

    fn wake(context: ?*anyopaque, _: *const u32, _: u32) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        if (!self.armed) return;
        self.armed = false;
        const node = self.waiter.node.?;
        _ = self.queue.abandon(self.waiter, self.io);
        // An owner still publishing its wake retains the list reference.
        self.retained = node.references.load(.acquire) == 1;
    }
};

test "owned FIFO admission keeps notifier storage alive through caller departure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var queue: Queue = .{};
    var first: Queue.Waiter = .{};
    var second: Queue.Waiter = .{};
    defer {
        _ = queue.abandon(&first, base);
        _ = queue.abandon(&second, base);
        queue.pruneAbandoned(base);
    }
    try queue.enqueue(&first, std.testing.allocator, base);
    try queue.enqueue(&second, std.testing.allocator, base);
    var gate = WakeGate{ .queue = &queue, .waiter = &first };
    var table = base.vtable.*;
    table.futexWake = WakeGate.wake;
    gate.io = .{ .userdata = &gate, .vtable = &table };
    queue.notifyHead(gate.io);
    try std.testing.expect(gate.retained);
    try std.testing.expect(first.node == null);
    // A delayed publication must not revive the departed head and pin FIFO.
    try std.testing.expect(!queue.head.?.notify());
    try std.testing.expect(queue.mayAttempt(&second, base));
    try std.testing.expect(second.isNotified());
}

const WaitGate = struct {
    queue: *Queue,
    departing: ?*Queue.Waiter = null,
    io: std.Io = undefined,
    now_ns: i96 = 1000,
    waits: usize = 0,
    original_deadline: bool = true,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn wait(context: ?*anyopaque, _: *const u32, _: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.waits += 1;
        self.original_deadline = self.original_deadline and switch (timeout) {
            .deadline => |deadline| deadline.clock == .awake and deadline.raw.nanoseconds == 1003,
            else => false,
        };
        if (self.departing) |waiter| {
            self.departing = null;
            _ = self.queue.abandon(waiter, self.io);
        } else self.now_ns += 1;
    }

    fn wake(_: ?*anyopaque, _: *const u32, _: u32) void {}
};

test "owned FIFO admission retries when abandonment races the last capacity wake" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var queue: Queue = .{};
    var first: Queue.Waiter = .{};
    var second: Queue.Waiter = .{};
    defer {
        _ = queue.abandon(&first, base);
        _ = queue.abandon(&second, base);
        queue.pruneAbandoned(base);
    }
    try queue.enqueue(&first, std.testing.allocator, base);
    queue.notifyHead(base); // The owner has already completed its notification.
    try queue.enqueue(&second, std.testing.allocator, base);
    var gate = WaitGate{ .queue = &queue, .departing = &first };
    var table = base.vtable.*;
    table.now = WaitGate.now;
    table.futexWait = WaitGate.wait;
    table.futexWake = WaitGate.wake;
    gate.io = .{ .userdata = &gate, .vtable = &table };
    try second.waitUntil(gate.io, .{ .clock = .awake, .raw = .fromNanoseconds(1003) });
    try std.testing.expectEqual(@as(usize, 1), gate.waits);
    try std.testing.expect(!second.isNotified());
    // This is only a retry hint. The ownership check retires the old head and
    // admits this cursor in FIFO order under the pool's mutex.
    try std.testing.expect(queue.mayAttempt(&second, base));
    try std.testing.expect(second.isNotified());
    try std.testing.expect(gate.original_deadline);
}

test "owned FIFO admission ignores spurious wakes under its original deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var queue: Queue = .{};
    var waiter: Queue.Waiter = .{};
    defer {
        _ = queue.abandon(&waiter, base);
        queue.pruneAbandoned(base);
    }
    try queue.enqueue(&waiter, std.testing.allocator, base);
    var gate = WaitGate{ .queue = &queue };
    var table = base.vtable.*;
    table.now = WaitGate.now;
    table.futexWait = WaitGate.wait;
    table.futexWake = WaitGate.wake;
    gate.io = .{ .userdata = &gate, .vtable = &table };
    try std.testing.expectError(error.Timeout, waiter.waitUntil(gate.io, .{ .clock = .awake, .raw = .fromNanoseconds(1003) }));
    try std.testing.expectEqual(@as(usize, 3), gate.waits);
    try std.testing.expect(gate.original_deadline);
}

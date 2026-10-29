const std = @import("std");
const grpc = @import("../../mod.zig");
const Shared = @import("../shared.zig");
const Job = @import("job.zig").Job;

const Operation = enum { unary, retry, stream, enqueue };
const TimeoutSource = enum { explicit, inherited, capped, unbounded };
const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex,
    canceled: bool,
    unbounded_waits: usize = 0,
    var active: ?*Probe = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer == target and self.canceled) return error.Canceled;
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        const target: *const u32 = @ptrCast(&self.mutex.state.raw);
        if (pointer == target) {
            self.unbounded_waits += 1;
            self.mutex.state.store(.unlocked, .release);
        } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }
};

fn exercise(operation: Operation, source: TimeoutSource, canceled: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try Shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{
        .service_config_json = if (source == .explicit or source == .unbounded) null else "{\"methodConfig\":[{\"name\":[{\"service\":\"svc\",\"method\":\"Op\"}],\"timeout\":\"0.01s\"}]}",
    });
    var sender = channel.sender();
    defer sender.deinit();
    // Keep the retained endpoint/config state, with no background worker able
    // to release the deliberately occupied admission mutex during this test.
    channel.deinit();
    const state = sender.state;
    const references = state.refs.load(.acquire);
    var probe = Probe{ .base = base, .mutex = &state.mutex, .canceled = canceled };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    defer {
        state.io = base;
        Probe.active = null;
    }
    state.mutex.lockUncancelable(base);
    defer {
        _ = state.mutex.tryLock();
        state.mutex.unlock(base);
    }
    const timeout: ?grpc.Timeout = switch (source) {
        .explicit => .{ .value = 10, .unit = .millisecond },
        .inherited => null,
        .capped => .{ .value = 1, .unit = .second },
        .unbounded => null,
    };
    const expected = if (canceled) error.Canceled else error.Timeout;
    const started = std.Io.Clock.awake.now(base);
    switch (operation) {
        .unary => try std.testing.expectError(expected, sender.unary(.{ .path = "/svc/Op", .message = "body", .timeout = timeout })),
        .retry => try std.testing.expectError(expected, sender.unaryWithRetry(.{ .path = "/svc/Op", .message = "body", .timeout = timeout }, .{
            .max_attempts = 2,
            .initial_backoff = .fromMilliseconds(1),
            .max_backoff = .fromMilliseconds(1),
            .backoff_multiplier = 2,
            .retryable_status_codes = &.{.unavailable},
        })),
        .stream => try std.testing.expectError(expected, sender.startDuplex(.{ .path = "/svc/Op", .timeout = timeout })),
        .enqueue => {
            var job = Job{ .options = .{ .path = "/svc/Op", .message = "body" }, .deadline = if (source == .unbounded) null else .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) }), .wait_for_ready = false, .previous_attempts = null };
            try std.testing.expectError(expected, state.enqueue(&job));
        },
    }
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(base)).nanoseconds < std.Io.Duration.fromMilliseconds(200).nanoseconds);
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expect(!state.mutex.tryLock());
    try std.testing.expectEqual(references, state.refs.load(.acquire));
    try std.testing.expect(state.head == null and state.tail == null);
    try std.testing.expectEqual(@as(usize, 0), state.queued);
}

test "gRPC shared admission bounds explicit inherited and capped RPC deadlines" {
    for ([_]Operation{ .unary, .retry, .stream }) |operation| {
        for (std.enums.values(TimeoutSource)) |source| {
            for ([_]bool{ false, true }) |canceled| {
                if (source == .unbounded and !canceled) continue;
                try exercise(operation, source, canceled);
            }
        }
    }
}

test "gRPC shared enqueue preserves caller ownership during timed lock admission" {
    for ([_]bool{ false, true }) |canceled| try exercise(.enqueue, .explicit, canceled);
    try exercise(.enqueue, .unbounded, true);
}

test "gRPC shared stream admission retires unsubmitted allocation without cleanup locking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ false, true }) |canceled| {
        var channel = try Shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
        var sender = channel.sender();
        defer sender.deinit();
        channel.deinit();
        const state = sender.state;
        // Isolate caller admission from endpoint workers, which are already
        // joined. This opens only the synthetic queue path for this test.
        state.closed = false;
        defer state.closed = true;
        const State = @TypeOf(state.*);
        const Allocator = struct {
            backing: std.mem.Allocator,
            mutex: *std.Io.Mutex,
            base: std.Io,
            entered: bool = false,
            allocated: usize = 0,
            freed: usize = 0,
            fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
                const self: *@This() = @ptrCast(@alignCast(pointer));
                const memory = self.backing.rawAlloc(len, alignment, ret) orelse return null;
                self.allocated += 1;
                if (len == @sizeOf(State.StreamCall)) {
                    self.entered = true;
                    self.mutex.lockUncancelable(self.base);
                }
                return memory;
            }
            fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
                const self: *@This() = @ptrCast(@alignCast(pointer));
                self.freed += 1;
                self.backing.rawFree(bytes, alignment, ret);
            }
            const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free };
        };
        var allocator = Allocator{ .backing = std.testing.allocator, .mutex = &state.mutex, .base = base };
        var probe = Probe{ .base = base, .mutex = &state.mutex, .canceled = canceled };
        var table = base.vtable.*;
        table.futexWait = Probe.wait;
        table.futexWaitUncancelable = Probe.waitUncancelable;
        Probe.active = &probe;
        state.io = .{ .userdata = base.userdata, .vtable = &table };
        state.allocator = .{ .ptr = &allocator, .vtable = &Allocator.vtable };
        defer {
            if (allocator.entered) {
                _ = state.mutex.tryLock();
                state.mutex.unlock(base);
            }
            state.io = base;
            state.allocator = std.testing.allocator;
            Probe.active = null;
        }
        const references = state.refs.load(.acquire);
        try std.testing.expectError(if (canceled) error.Canceled else error.Timeout, sender.startDuplex(.{ .path = "/svc/Op", .timeout = .{ .value = 100, .unit = .millisecond } }));
        try std.testing.expect(allocator.entered);
        try std.testing.expect(!state.mutex.tryLock());
        try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
        try std.testing.expectEqual(references, state.refs.load(.acquire));
        try std.testing.expectEqual(allocator.allocated, allocator.freed);
        try std.testing.expect(state.head == null and state.queued == 0);
    }
}

const std = @import("std");
const Shared = @import("../shared.zig");
const Job = @import("job.zig").Job;

fn exercise(assigned: bool, canceled: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try Shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    const State = @TypeOf(state.*);
    state.closed = false;
    const job = try Job.create(state, .{ .path = "/svc/Op", .message = "original", .wait_for_ready = true }, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(100) }), null, null);
    defer job.release();
    job.retain();
    var endpoint = true;
    defer if (endpoint) job.release();
    if (!assigned) {
        state.head = job;
        state.tail = job;
        state.queued = 1;
    }
    const Probe = struct {
        base: std.Io,
        state: *State,
        job: *Job,
        canceled: bool,
        entered: bool = false,
        lock_waits: usize = 0,
        retirement_waits: usize = 0,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (!self.entered) {
                self.state.mutex.lockUncancelable(self.base);
                self.entered = true;
            }
            if (self.canceled) return error.Canceled;
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.state.mutex.state.raw);
            const event: *const u32 = @ptrCast(&self.job.done);
            if (pointer == mutex) {
                self.lock_waits += 1;
                self.state.mutex.state.store(.unlocked, .release);
            } else if (pointer == event) {
                self.retirement_waits += 1;
                self.job.done.set(self.base);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var probe = Probe{ .base = base, .state = state, .job = job, .canceled = canceled };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    defer {
        if (probe.entered) {
            _ = state.mutex.tryLock();
            state.mutex.unlock(base);
        }
        state.head = null;
        state.tail = null;
        state.queued = 0;
        state.closed = true;
        state.io = base;
        Probe.active = null;
    }
    try std.testing.expectError(if (canceled) error.Canceled else error.Timeout, state.awaitJob(job));
    try std.testing.expect(probe.entered);
    try std.testing.expectEqual(@as(usize, 0), probe.lock_waits);
    try std.testing.expectEqual(@as(usize, 0), probe.retirement_waits);
    try std.testing.expect(!state.mutex.tryLock());
    try std.testing.expect(job.canceled());
    state.io = base;
    if (!assigned) endpoint = false;
    state.unlock();
    probe.entered = false;
    if (assigned) {
        endpoint = false;
        state.finish(job, null, error.Canceled);
    }
    try std.testing.expect(state.head == null and state.queued == 0);
}

test "gRPC queued RPC interruption returns before cancellation cleanup mutex" {
    for ([_]bool{ false, true }) |canceled| try exercise(false, canceled);
}

test "gRPC assigned RPC interruption returns before endpoint retirement" {
    for ([_]bool{ false, true }) |canceled| try exercise(true, canceled);
}

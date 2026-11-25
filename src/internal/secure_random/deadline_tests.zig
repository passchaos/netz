const std = @import("std");
const entropy = @import("../secure_random.zig");

test "startup entropy deadline rejects expired budgets and missing timer admission" {
    const Probe = @import("../testing/startup_entropy.zig").Probe;
    inline for (.{ false, true }) |expired| {
        var probe: Probe = .{};
        var buffer: [16]u8 = @splat(0x55);
        const deadline = if (expired) std.Io.Clock.Timestamp{ .clock = .awake, .raw = .zero } else probe.deadline();
        try std.testing.expectError(if (expired) error.Timeout else error.ConcurrencyUnavailable, entropy.fillBefore(probe.io(), &buffer, deadline));
        try probe.expectUntouched(if (expired) 0 else 1);
        try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0x55))), &buffer);
    }
}

const Mode = enum { success, failure, expired_success, expired_failure, canceled_success, canceled_failure };

const Delegate = struct {
    backend: std.Io.Threaded,
    mode: Mode,
    deadline_ns: i64 = 0,
    now_override: std.atomic.Value(i64) = .init(0),
    cancel_pending: std.atomic.Value(bool) = .init(false),
    calls: usize = 0,
    admissions: usize = 0,
    reject_admission: usize = 0,
    protected_fill: bool = false,
    gated: bool = false,
    ready: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    tick: std.Io.Event = .unset,
    cancel_started: std.Io.Event = .unset,

    fn context(userdata: ?*anyopaque) *Delegate {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = context(userdata);
        const override = self.now_override.load(.acquire);
        if (clock == .awake and override != 0) return .{ .nanoseconds = override };
        return clock.now(self.backend.io());
    }
    fn random(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
        const self = context(userdata);
        self.calls += 1;
        const old = self.backend.io().swapCancelProtection(.blocked);
        self.protected_fill = old == .blocked;
        _ = self.backend.io().swapCancelProtection(old);
        if (self.gated) {
            self.ready.set(self.backend.io());
            self.release.waitUncancelable(self.backend.io());
        }
        @memset(buffer, 0xa5);
        switch (self.mode) {
            .expired_success, .expired_failure => self.now_override.store(self.deadline_ns + 1, .release),
            .canceled_success, .canceled_failure => self.cancel_pending.store(true, .release),
            else => {},
        }
        switch (self.mode) {
            .failure, .expired_failure, .canceled_failure => return error.EntropyUnavailable,
            else => {},
        }
    }
    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = context(userdata);
        const io = self.backend.io();
        try io.checkCancel();
        const old = io.swapCancelProtection(.blocked);
        _ = io.swapCancelProtection(old);
        if (old == .unblocked and self.cancel_pending.swap(false, .acq_rel)) return error.Canceled;
    }
    fn concurrent(userdata: ?*anyopaque, group: *std.Io.Group, args: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        const self = context(userdata);
        self.admissions += 1;
        if (self.admissions == self.reject_admission) return error.ConcurrencyUnavailable;
        const io = self.backend.io();
        return io.vtable.groupConcurrent(io.userdata, group, args, alignment, start);
    }
    fn sleep(userdata: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
        const self = context(userdata);
        try self.tick.wait(self.backend.io());
        self.now_override.store(self.deadline_ns + 1, .release);
    }
    fn cancel(userdata: ?*anyopaque, group: *std.Io.Group, token: *anyopaque) void {
        const self = context(userdata);
        const io = self.backend.io();
        self.cancel_started.set(io);
        io.vtable.groupCancel(io.userdata, group, token);
    }
};

fn exercise(mode: Mode, reject_admission: usize) !void {
    var delegate: Delegate = .{
        .backend = .init(std.testing.allocator, .{}),
        .mode = mode,
        .reject_admission = reject_admission,
    };
    defer delegate.backend.deinit();
    const native_io = delegate.backend.io();
    var table = native_io.vtable.*;
    table.randomSecure = Delegate.random;
    table.now = Delegate.now;
    table.checkCancel = Delegate.check;
    table.groupConcurrent = Delegate.concurrent;
    const io: std.Io = .{ .userdata = native_io.userdata, .vtable = &table };
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    delegate.deadline_ns = @intCast(deadline.raw.nanoseconds);
    var buffer: [16]u8 = @splat(0x55);
    const result = entropy.fillBefore(io, &buffer, deadline);
    if (reject_admission != 0) {
        try std.testing.expectError(error.ConcurrencyUnavailable, result);
        try std.testing.expectEqual(@as(usize, 0), delegate.calls);
        try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0x55))), &buffer);
        return;
    }
    switch (mode) {
        .success => try result,
        .failure => try std.testing.expectError(error.EntropyUnavailable, result),
        .expired_success, .expired_failure => try std.testing.expectError(error.Timeout, result),
        .canceled_success, .canceled_failure => try std.testing.expectError(error.Canceled, result),
    }
    try std.testing.expectEqual(@as(usize, 1), delegate.calls);
    try std.testing.expectEqual(@as(usize, 2), delegate.admissions);
    try std.testing.expect(delegate.protected_fill);
    try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &buffer);
}

test "startup entropy deadline completion preserves timely errors and rejects late or canceled results" {
    inline for (std.meta.tags(Mode)) |mode| try exercise(mode, 0);
}

test "startup entropy deadline joins its timer when worker admission fails" {
    try exercise(.success, 2);
}

fn waitGate(event: *const std.Io.Event, io: std.Io) !void {
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    while (!event.isSet()) {
        _ = try @import("../deadline.zig").usableAwake(io, deadline);
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

test "startup entropy timer joins a protected writer before returning its borrowed buffer" {
    var delegate: Delegate = .{ .backend = .init(std.testing.allocator, .{}), .mode = .success, .gated = true };
    defer delegate.backend.deinit();
    const native_io = delegate.backend.io();
    var table = native_io.vtable.*;
    table.now = Delegate.now;
    table.randomSecure = Delegate.random;
    table.sleep = Delegate.sleep;
    table.groupCancel = Delegate.cancel;
    const io: std.Io = .{ .userdata = native_io.userdata, .vtable = &table };
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
    delegate.deadline_ns = @intCast(deadline.raw.nanoseconds);
    const Caller = struct {
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
        returned: std.Io.Event = .unset,
        buffer: [16]u8 = @splat(0x55),
        result: ?entropy.BeforeError!void = null,
        fn run(self: *@This()) void {
            self.result = entropy.fillBefore(self.io, &self.buffer, self.deadline);
            self.returned.set(self.io);
        }
    };
    var caller: Caller = .{ .io = io, .deadline = deadline };
    var future = try std.Io.concurrent(native_io, Caller.run, .{&caller});
    var joined = false;
    defer if (!joined) {
        delegate.tick.set(native_io);
        delegate.release.set(native_io);
        future.cancel(native_io);
    };
    try waitGate(&delegate.ready, native_io);
    delegate.tick.set(native_io);
    try waitGate(&delegate.cancel_started, native_io);
    try std.testing.expect(!caller.returned.isSet());
    delegate.release.set(native_io);
    future.await(native_io);
    joined = true;
    try std.testing.expectError(error.Timeout, caller.result.?);
    try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &caller.buffer);
    try std.testing.expectEqual(@as(usize, 1), delegate.calls);
    try std.testing.expect(delegate.protected_fill);
}

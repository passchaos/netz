const std = @import("std");
const shared = @import("../../shared.zig");
const resolver = @import("../../resolver.zig");

const Operation = enum { request, refresh, reset_backoff };

fn exerciseAdmission(operation: Operation) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    state.closed = false;
    defer state.closed = true;
    state.resolution_changed.reset();
    const references = state.refs.load(.acquire);

    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        cancel: bool,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            if (self.cancel and pointer == mutex) return error.Canceled;
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            if (pointer == mutex) {
                self.unbounded_waits += 1;
                self.mutex.state.store(.unlocked, .release);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    const canceled = operation != .refresh;
    var probe = Probe{ .base = base, .mutex = &state.mutex, .cancel = canceled };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    state.mutex.lockUncancelable(base);

    switch (operation) {
        .request => try std.testing.expectError(error.Canceled, state.requestNameResolution()),
        .refresh => try std.testing.expectError(error.Timeout, state.refreshNameResolution(.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(1) }))),
        .reset_backoff => try std.testing.expectError(error.Canceled, (shared.SharedChannel{ .state = state }).resetConnectionBackoff()),
    }
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expect(!state.mutex.tryLock());
    try std.testing.expect(!state.demand);
    try std.testing.expect(!state.resolution_changed.isSet());

    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

test "gRPC shared name resolution admission obeys deadline and cancellation" {
    try exerciseAdmission(.request);
    try exerciseAdmission(.refresh);
    try exerciseAdmission(.reset_backoff);
}

test "gRPC shared name resolution refresh bounds post-wake State reacquisition" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    const State = @TypeOf(state.*);
    state.closed = false;
    defer state.closed = true;
    state.resolution_changed.reset();
    const references = state.refs.load(.acquire);

    const Probe = struct {
        state: *State,
        base: std.Io,
        woke: bool = false,
        unbounded_waits: usize = 0,
        var active: ?*@This() = null;
        fn wait(_: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (!self.woke) {
                self.state.mutex.lockUncancelable(self.base);
                self.state.resolution_changed.set(self.base);
                self.woke = true;
                return;
            }
            return;
        }
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.state.mutex.state.raw);
            if (pointer == mutex) {
                self.unbounded_waits += 1;
                self.state.mutex.state.store(.unlocked, .release);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var fake_resolver: resolver.State = undefined;
    state.sources[0].resolver = &fake_resolver;
    defer state.sources[0].resolver = null;
    var probe = Probe{ .state = state, .base = base };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };

    try std.testing.expectError(error.Timeout, state.refreshNameResolution(.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) })));
    try std.testing.expect(probe.woke);
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded_waits);
    try std.testing.expect(!state.mutex.tryLock());

    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

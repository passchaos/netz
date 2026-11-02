const std = @import("std");
const Sync = @import("sync.zig");
const allocator = std.testing.allocator;

const Probe = struct {
    base: std.Io,
    sync: *Sync,
    state: *std.atomic.Value(u8),
    waits: usize = 0,
    notify_on_wait: bool = false,
    var active: ?*Probe = null;

    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        self.waits += 1;
        if (!self.notify_on_wait) return error.Canceled;
        self.state.store(1, .release);
        self.sync.notify(self.base);
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

test "ordinary Channel health gate observes a publication between scan and wait" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var sync: Sync = .{};
    var state: std.atomic.Value(u8) = .init(0);
    var probe = Probe{ .base = base, .sync = &sync, .state = &state };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };

    const generation = sync.snapshot();
    try std.testing.expectEqual(@as(u8, 0), state.load(.acquire));
    state.store(1, .release);
    sync.notify(base);
    // A stale scan cannot park, with or without an RPC deadline. An attempted
    // wait deterministically returns Canceled instead of hanging the test.
    try sync.wait(io, generation, null);
    try sync.wait(io, generation, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 0), probe.waits);
    try std.testing.expectEqual(@as(u8, 1), state.load(.acquire));
}

test "ordinary Channel health gate observes a publication while parking" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var sync: Sync = .{};
    var state: std.atomic.Value(u8) = .init(0);
    var probe = Probe{ .base = base, .sync = &sync, .state = &state, .notify_on_wait = true };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };

    try sync.wait(io, sync.snapshot(), .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 1), probe.waits);
    try std.testing.expectEqual(@as(u8, 1), state.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), sync.snapshot());
}

test "ordinary Channel health gate wait preserves cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var sync: Sync = .{};
    var state: std.atomic.Value(u8) = .init(0);
    var probe = Probe{ .base = base, .sync = &sync, .state = &state };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    try std.testing.expectError(error.Canceled, sync.wait(io, sync.snapshot(), null));
    try std.testing.expectEqual(@as(usize, 1), probe.waits);
    try std.testing.expectEqual(@as(u64, 0), sync.snapshot());
}

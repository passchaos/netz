const std = @import("std");
const admission = @import("admission.zig");
const gate = @import("../health_gate.zig");
const Sync = @import("sync.zig");
const allocator = std.testing.allocator;

const Slot = struct { health_state: std.atomic.Value(u8) = .init(gate.unknown) };
const Probe = struct {
    base: std.Io,
    sync: *Sync,
    slot: *Slot,
    clocks: usize = 0,
    waits: usize = 0,
    step_ns: i96 = 0,
    seen_timeout: ?std.Io.Timeout = null,
    recover: bool = true,
    canceled: std.Io.Event = .unset,
    var active: ?*Probe = null;

    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = active.?;
        self.clocks += 1;
        return self.base.vtable.now(userdata, clock).addDuration(.fromNanoseconds(self.step_ns * @as(i96, @intCast(self.clocks))));
    }

    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        self.waits += 1;
        self.seen_timeout = timeout;
        if (!self.recover) return error.Canceled;
        self.slot.health_state.store(gate.serving, .release);
        self.sync.notify(self.base);
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

test "ordinary Channel health gate initial unbounded admission has no implicit clock deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |wait_for_ready| {
        var sync: Sync = .{};
        var slots = [_]Slot{.{}};
        // CONNECTING does not itself fail either RPC mode. Advancing ten
        // seconds per clock read catches a hidden five-second wait budget.
        var probe = Probe{ .base = base, .sync = &sync, .slot = &slots[0], .step_ns = 10 * std.time.ns_per_s };
        Probe.active = &probe;
        defer Probe.active = null;
        var table = base.vtable.*;
        table.now = Probe.now;
        table.futexWait = Probe.wait;
        const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
        try admission.wait(io, &sync, &slots, .{ .wait_for_ready = wait_for_ready, .deadline = null, .canceled = &probe.canceled });
        try std.testing.expectEqual(@as(usize, 1), probe.waits);
        try std.testing.expect(probe.seen_timeout.? == .none);
        try std.testing.expectEqual(gate.serving, slots[0].health_state.load(.acquire));
    }
}

test "ordinary Channel health gate waiting keeps the exact caller deadline and cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var sync: Sync = .{};
    var slots = [_]Slot{.{ .health_state = .init(gate.not_serving) }};
    var probe = Probe{ .base = base, .sync = &sync, .slot = &slots[0], .recover = false };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.now = Probe.now;
    table.futexWait = Probe.wait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const deadline: std.Io.Clock.Timestamp = .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(30) });
    try std.testing.expectError(error.Canceled, admission.wait(io, &sync, &slots, .{ .wait_for_ready = true, .deadline = deadline, .canceled = &probe.canceled }));
    try std.testing.expectEqualDeep(std.Io.Timeout{ .deadline = deadline }, probe.seen_timeout.?);
    try std.testing.expectEqual(gate.not_serving, slots[0].health_state.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), probe.waits);
}

test "ordinary Channel health gate rejects a known failure without waiting" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var sync: Sync = .{};
    var slots = [_]Slot{.{ .health_state = .init(gate.not_serving) }};
    var probe = Probe{ .base = base, .sync = &sync, .slot = &slots[0], .recover = false };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    try std.testing.expectError(error.ConnectionUnavailable, admission.wait(io, &sync, &slots, .{ .wait_for_ready = false, .deadline = null, .canceled = &probe.canceled }));
    try std.testing.expectEqual(@as(usize, 0), probe.waits);
}

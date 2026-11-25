const std = @import("std");
const bounded = @import("progress_deadline.zig");
const allocator = std.testing.allocator;

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    clock: std.atomic.Value(i64) = .init(0),
    entered: std.Io.Event = .unset,
    never_release: std.Io.Event = .unset,
    returned: std.atomic.Value(bool) = .init(false),
    canceled: std.atomic.Value(bool) = .init(false),

    fn io(self: *Probe) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.now = now;
        self.table.sleep = sleep;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }
    fn from(userdata: ?*anyopaque) *Probe {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = from(userdata);
        if (clock == .awake) return .fromNanoseconds(self.clock.load(.acquire));
        const base = self.backend.io();
        return base.vtable.now(base.userdata, clock);
    }
    fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(userdata);
        const until = switch (timeout) {
            .deadline => |value| value,
            else => return error.Canceled,
        };
        // Clock expiry follows actual work entry, with no scheduler delay
        // assumption. Cancellation still releases a watcher if work admission
        // fails before it can enter.
        try self.entered.wait(self.backend.io());
        self.clock.store(@intCast(until.raw.nanoseconds), .release);
    }
    fn work(self: *Probe, run_io: std.Io) usize {
        self.entered.set(run_io);
        self.never_release.wait(run_io) catch |err| {
            self.canceled.store(err == error.Canceled, .release);
        };
        self.returned.store(true, .release);
        return 7;
    }
};

test "QUIC send deadline joins canceled work and retains its late result" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }) };
    defer probe.backend.deinit();
    const io = probe.io();
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    const result = bounded.before(io, until, Probe.work, .{ &probe, io });
    try std.testing.expectEqual(error.Timeout, result.wait_error.?);
    try std.testing.expectEqual(@as(usize, 7), result.result.?);
    try std.testing.expect(probe.returned.load(.acquire));
    try std.testing.expect(probe.canceled.load(.acquire));
}

test "QUIC send deadline rejects expired and foreign-clock work before entry" {
    for ([_]std.Io.Clock{ .awake, .real }) |clock| {
        var probe: Probe = .{ .backend = .init(allocator, .{}) };
        defer probe.backend.deinit();
        const io = probe.io();
        const until: std.Io.Clock.Timestamp = .{ .clock = clock, .raw = .zero };
        const result = bounded.before(io, until, Probe.work, .{ &probe, io });
        try std.testing.expectEqual(error.Timeout, result.wait_error.?);
        try std.testing.expect(result.result == null and !probe.entered.isSet());
    }
}

test "QUIC send deadline preserves unavailable watcher capability before work" {
    var probe: Probe = .{ .backend = .init(allocator, .{}) };
    defer probe.backend.deinit();
    const io = probe.io();
    probe.table.groupConcurrent = std.Io.failingGroupConcurrent;
    const until: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1000000) };
    const result = bounded.before(io, until, Probe.work, .{ &probe, io });
    try std.testing.expectEqual(error.ConcurrencyUnavailable, result.wait_error.?);
    try std.testing.expect(result.result == null and !probe.entered.isSet());
}

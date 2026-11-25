//! Shared rejection probes before address planning or connection work.
const std = @import("std");
const competition = @import("../connection_race.zig");
const families = @import("../happy_eyeballs.zig");
pub const Error = error{ Timeout, HandshakeTimeout, Canceled, Unexpected };

const Probe = struct {
    calls: usize = 0,
    fn connect(self: *@This(), _: std.Io, _: std.Io.net.IpAddress, _: usize) Error!u8 {
        self.calls += 1;
        return error.Unexpected;
    }
    fn close(_: *@This(), _: *u8) void {
        unreachable;
    }
    fn next(_: Error) bool {
        return true;
    }
};

pub fn rejected(comptime planned: bool, timeout_error: Error) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const storage: [9]std.Io.net.IpAddress = @splat(.{ .ip4 = .loopback(1) });
    const addresses: []const std.Io.net.IpAddress = &storage;
    inline for (.{ .expired, .foreign_clock, .canceled }) |kind| {
        if (comptime planned and kind == .canceled) continue;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        var probe: Probe = .{};
        var canceled: std.Io.Event = .is_set;
        const deadline: ?std.Io.Clock.Timestamp = if (kind == .canceled) null else .{
            .clock = if (kind == .foreign_clock) .real else .awake,
            .raw = .zero,
        };
        const expected: Error = if (kind == .canceled) error.Canceled else timeout_error;
        const result = if (planned)
            families.race(Error, u8, failing.allocator(), io, addresses, .{}, deadline, timeout_error, &probe, Probe.connect, Probe.close, Probe.next)
        else
            competition.race(Error, u8, failing.allocator(), io, addresses, .{ .attempt_delay = .fromMilliseconds(1), .max_in_flight = 2, .cancel_event = if (kind == .canceled) &canceled else null }, deadline, if (deadline != null) timeout_error else null, &probe, Probe.connect, Probe.close, Probe.next);
        try std.testing.expectError(expected, result);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), probe.calls);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

pub fn canceledAtWorkerAdmission() !void {
    const Scheduler = struct {
        threaded: std.Io.Threaded,
        canceled: std.Io.Event = .unset,
        admitted: usize = 0,
        fn groupConcurrent(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, context_alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata));
            const self: *@This() = @fieldParentPtr("threaded", backend);
            const io = self.threaded.io();
            self.admitted += 1;
            // The cancellation watcher is admitted first. Set the event at
            // entry to the first connection worker, after initial admission.
            if (self.admitted == 2) self.canceled.set(io);
            return io.vtable.groupConcurrent(io.userdata, group, context, context_alignment, start);
        }
    };
    var scheduler: Scheduler = .{ .threaded = .init(std.testing.allocator, .{}) };
    defer scheduler.threaded.deinit();
    const base = scheduler.threaded.io();
    var vtable = base.vtable.*;
    vtable.groupConcurrent = Scheduler.groupConcurrent;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var probe: Probe = .{};
    const target = [_]std.Io.net.IpAddress{.{ .ip4 = .loopback(1) }};
    try std.testing.expectError(error.Canceled, competition.race(Error, u8, std.testing.allocator, io, &target, .{ .attempt_delay = .fromMilliseconds(1), .max_in_flight = 2, .cancel_event = &scheduler.canceled }, null, null, &probe, Probe.connect, Probe.close, Probe.next));
    try std.testing.expectEqual(@as(usize, 2), scheduler.admitted);
    try std.testing.expectEqual(@as(usize, 0), probe.calls);
}

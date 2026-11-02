const std = @import("std");
const endpoint = @import("../endpoint_server.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const stream_io = @import("../../../internal/stream_io.zig");
const allocator = std.testing.allocator;

const Mode = enum {
    expired,
    wrong_clock,
    cancel_entry,
    cancel_before_start,
    cancel_after_start,
    fail_state,
    fail_pending,
    fail_sessions,
    owner_failure,
    late_allocation,
    late_owner,
};
const Probe = struct {
    base: std.Io,
    caller: std.Thread.Id,
    mode: Mode,
    allocations: usize = 0,
    checks: usize = 0,
    starts: usize = 0,
    shift: std.atomic.Value(bool) = .init(false),
    var active: ?*Probe = null;

    fn allocator(self: *Probe) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Probe = @ptrCast(@alignCast(context));
        const index = self.allocations;
        self.allocations += 1;
        const failed = switch (self.mode) {
            .fail_state => index == 0,
            .fail_pending => index == 1,
            .fail_sessions => index == 2,
            else => false,
        };
        if (failed) return null;
        const bytes = std.testing.allocator.rawAlloc(len, alignment, ra);
        if (bytes != null and self.mode == .late_allocation and index == 2) self.shift.store(true, .release);
        return bytes;
    }
    fn resize(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        return std.testing.allocator.rawResize(bytes, alignment, len, ra);
    }
    fn remap(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
    }
    fn free(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        std.testing.allocator.rawFree(bytes, alignment, ra);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = active.?;
        const original = self.base.vtable.now(userdata, clock);
        return if (self.shift.load(.acquire)) original.addDuration(.fromSeconds(10)) else original;
    }
    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = active.?;
        if (std.Thread.getCurrentId() == self.caller) {
            self.checks += 1;
            const canceled = switch (self.mode) {
                .cancel_entry => self.checks == 1,
                .cancel_before_start => self.checks == 2,
                .cancel_after_start => self.checks == 3,
                else => false,
            };
            if (canceled) return error.Canceled;
        }
        return self.base.vtable.checkCancel(userdata);
    }
    fn concurrent(userdata: ?*anyopaque, group: *std.Io.Group, bytes: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        const self = active.?;
        if (std.Thread.getCurrentId() == self.caller) {
            if (self.mode == .owner_failure) return error.ConcurrencyUnavailable;
            self.starts += 1;
        }
        try self.base.vtable.groupConcurrent(userdata, group, bytes, alignment, start);
        if (std.Thread.getCurrentId() == self.caller and self.mode == .late_owner) self.shift.store(true, .release);
    }
};

test "WebTransport HTTP2 EndpointServer initialization owns rollback across deadline cancellation and allocation failures" {
    for (std.enums.values(Mode)) |mode| try exercise(mode);
}

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var fixture = try Fixture.init(base);
    defer {
        fixture.peer.close(base);
        fixture.listener.deinit(base);
    }
    var probe = Probe{ .base = base, .caller = std.Thread.getCurrentId(), .mode = mode };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.now = Probe.now;
    table.checkCancel = Probe.check;
    table.groupConcurrent = Probe.concurrent;
    fixture.connection.io = .{ .userdata = base.userdata, .vtable = &table };
    fixture.connection.role = .server;
    const deadline: std.Io.Clock.Timestamp = switch (mode) {
        .expired => .fromNow(base, .{ .clock = .awake, .raw = .fromNanoseconds(-1) }),
        .wrong_clock => .{ .clock = .real, .raw = .{ .nanoseconds = 0 } },
        else => .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(5) }),
    };
    const expected: anyerror = switch (mode) {
        .expired, .wrong_clock, .late_allocation, .late_owner => error.Timeout,
        .cancel_entry, .cancel_before_start, .cancel_after_start => error.Canceled,
        .fail_state, .fail_pending, .fail_sessions => error.OutOfMemory,
        .owner_failure => error.ConcurrencyUnavailable,
    };
    const result = endpoint.EndpointServer.initWithDeadline(probe.allocator(), fixture.connection, .{ .max_sessions = 2, .max_pending_sessions = 2 }, deadline);
    if (result) |value| {
        var unexpected = value;
        unexpected.deinitAbortive();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(expected, err);
    const started = mode == .late_owner or mode == .cancel_after_start;
    try std.testing.expectEqual(@as(usize, if (started) 1 else 0), probe.starts);
    if (mode == .expired or mode == .wrong_clock or mode == .cancel_entry) try std.testing.expectEqual(@as(usize, 0), probe.allocations);
    // No handshake or Session output is produced by failed adoption. Physical
    // TCP closure also proves a started candidate's owner was fully joined.
    var byte: [1]u8 = undefined;
    const count = try stream_io.readSomeWithDeadline(base, fixture.peer, &byte, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "WebTransport HTTP2 EndpointServer initialization allocation sweep reclaims every provisional table" {
    const Harness = struct {
        fn run(gpa: std.mem.Allocator) !void {
            var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
            defer threaded.deinit();
            const io = threaded.io();
            var fixture = try Fixture.init(io);
            defer {
                fixture.peer.close(io);
                fixture.listener.deinit(io);
            }
            fixture.connection.role = .server;
            var server = try endpoint.EndpointServer.initWithDeadline(gpa, fixture.connection, .{ .max_sessions = 2, .max_pending_sessions = 2 }, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
            server.deinitAbortive();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{});
}

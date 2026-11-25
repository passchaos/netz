//! Expire or cancel during a real trust source's allocation failure.
const std = @import("std");

pub const Mode = enum { ordinary, expired, canceled };
pub const Probe = struct {
    mode: Mode,
    now_ns: i96 = 1000,
    cancel_pending: bool = false,
    allocations: usize = 0,
    admissions: usize = 0,

    fn context(userdata: ?*anyopaque) *Probe {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn finish(self: *Probe) void {
        switch (self.mode) {
            .ordinary => {},
            .expired => self.now_ns = 3000,
            .canceled => self.cancel_pending = true,
        }
    }
    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = context(userdata);
        if (self.cancel_pending) {
            self.cancel_pending = false;
            return error.Canceled;
        }
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        return .{ .nanoseconds = if (clock == .real) @as(i96, 1_790_000_000) * std.time.ns_per_s else context(userdata).now_ns };
    }
    fn concurrent(userdata: ?*anyopaque, _: *std.Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        const self = context(userdata);
        self.admissions += 1;
        self.finish();
        return error.ConcurrencyUnavailable;
    }
    const io_table: std.Io.VTable = blk: {
        var table = std.Io.failing.vtable.*;
        table.now = now;
        table.checkCancel = check;
        table.groupConcurrent = concurrent;
        break :blk table;
    };
    pub fn io(self: *Probe) std.Io {
        return .{ .userdata = self, .vtable = &io_table };
    }
    pub fn deadline(_: *Probe) std.Io.Clock.Timestamp {
        return .{ .clock = .awake, .raw = .{ .nanoseconds = 2000 } };
    }
    fn alloc(userdata: *anyopaque, _: usize, _: std.mem.Alignment, _: usize) ?[*]u8 {
        const self: *Probe = @ptrCast(@alignCast(userdata));
        self.allocations += 1;
        self.finish();
        return null;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
        unreachable; // This allocator never hands out an allocation.
    }
    pub fn allocator(self: *Probe) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
};

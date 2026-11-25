//! A bounded trust load must admit its watcher before reading any roots.
const std = @import("std");

pub const Probe = struct {
    admissions: usize = 0,
    opens: usize = 0,

    fn context(userdata: ?*anyopaque) *@This() {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        return .{ .nanoseconds = @as(i96, 1_790_000_000) * std.time.ns_per_s };
    }
    fn check(_: ?*anyopaque) std.Io.Cancelable!void {}
    fn concurrent(userdata: ?*anyopaque, _: *std.Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        context(userdata).admissions += 1;
        return error.ConcurrencyUnavailable;
    }
    fn open(userdata: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
        context(userdata).opens += 1;
        return error.AccessDenied;
    }
    const table: std.Io.VTable = blk: {
        var value = std.Io.failing.vtable.*;
        value.now = now;
        value.checkCancel = check;
        value.groupConcurrent = concurrent;
        value.dirOpenFile = open;
        break :blk value;
    };
    pub fn io(self: *@This()) std.Io {
        return .{ .userdata = self, .vtable = &table };
    }
    pub fn deadline(self: *@This()) std.Io.Clock.Timestamp {
        return .fromNow(self.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    }
    pub fn expectRejected(self: *@This()) !void {
        try std.testing.expectEqual(@as(usize, 1), self.admissions);
        try std.testing.expectEqual(@as(usize, 0), self.opens);
    }
};

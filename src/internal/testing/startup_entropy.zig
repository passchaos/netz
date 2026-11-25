//! URI startup must establish and admit its budget before requesting entropy.
const std = @import("std");

pub const Probe = struct {
    entropy_calls: usize = 0,
    admissions: usize = 0,
    opens: usize = 0,
    protection: std.Io.CancelProtection = .unblocked,

    fn context(userdata: ?*anyopaque) *Probe {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        return .{ .nanoseconds = 1000 };
    }
    fn check(_: ?*anyopaque) std.Io.Cancelable!void {}
    fn swap(userdata: ?*anyopaque, protection: std.Io.CancelProtection) std.Io.CancelProtection {
        const self = context(userdata);
        const old = self.protection;
        self.protection = protection;
        return old;
    }
    fn random(userdata: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
        context(userdata).entropy_calls += 1;
        return error.EntropyUnavailable;
    }
    fn concurrent(userdata: ?*anyopaque, _: *std.Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        context(userdata).admissions += 1;
        return error.ConcurrencyUnavailable;
    }
    fn open(userdata: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
        context(userdata).opens += 1;
        return error.AccessDenied;
    }
    const table: std.Io.VTable = blk: {
        var out = std.Io.failing.vtable.*;
        out.now = now;
        out.checkCancel = check;
        out.swapCancelProtection = swap;
        out.randomSecure = random;
        out.groupConcurrent = concurrent;
        out.dirOpenFile = open;
        break :blk out;
    };
    pub fn io(self: *Probe) std.Io {
        return .{ .userdata = self, .vtable = &table };
    }
    pub fn deadline(_: *Probe) std.Io.Clock.Timestamp {
        return .{ .clock = .awake, .raw = .{ .nanoseconds = 2000 } };
    }
    pub fn expectUntouched(self: *Probe, expected_admissions: usize) !void {
        try std.testing.expectEqual(expected_admissions, self.admissions);
        try std.testing.expectEqual(@as(usize, 0), self.entropy_calls);
        try std.testing.expectEqual(@as(usize, 0), self.opens);
        try std.testing.expectEqual(std.Io.CancelProtection.unblocked, self.protection);
    }
};

//! Deterministic early wake and cancellation for absolute deadline waiting.
const std = @import("std");
const policy = @import("../deadline.zig");

const Legacy = struct {
    fn wait(io: std.Io, deadline: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
        try deadline.wait(io);
    }
};

pub fn exercise(comptime canceled: bool) !void {
    const Probe = struct {
        now_ns: i96 = 1000,
        calls: usize = 0,
        wrong_deadline: bool = false,
        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }
        fn sleep(context: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (timeout != .deadline or timeout.deadline.clock != .awake or timeout.deadline.raw.nanoseconds != 2000) self.wrong_deadline = true;
            if (self.calls == 1) {
                self.now_ns = 1001;
                return;
            }
            if (canceled) return error.Canceled;
            self.now_ns = 2000;
        }
    };
    var probe: Probe = .{};
    var table = std.Io.failing.vtable.*;
    table.now = Probe.now;
    table.sleep = Probe.sleep;
    const io: std.Io = .{ .userdata = &probe, .vtable = &table };
    const waiting = if (@hasDecl(policy, "waitUntil")) policy.waitUntil else Legacy.wait;
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .{ .nanoseconds = 2000 } };
    if (canceled) {
        try std.testing.expectError(error.Canceled, waiting(io, deadline));
    } else {
        try waiting(io, deadline);
        try std.testing.expect(deadline.durationFromNow(io).raw.nanoseconds <= 0);
    }
    try std.testing.expectEqual(@as(usize, 2), probe.calls);
    try std.testing.expect(!probe.wrong_deadline);
}

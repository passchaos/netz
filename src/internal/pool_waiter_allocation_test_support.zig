//! Every allocation failure must release pool admission and preserve capacity.
const std = @import("std");

const Probe = struct {
    now_ns: i96 = 1000,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn wait(context: ?*anyopaque, _: *const u32, _: u32, _: std.Io.Timeout) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.now_ns += 1;
    }

    fn wake(_: ?*anyopaque, _: *const u32, _: u32) void {}
};

pub fn exercise(comptime Pool: type, base: std.Io) !void {
    const Task = struct {
        fn run(allocator: std.mem.Allocator, io: std.Io) !void {
            var pool = try Pool.init(allocator, io, .{});
            defer pool.deinit();
            pool.options.max_connections = 1;
            pool.connections = 1; // The original lease remains owned.
            defer pool.connections = 0;
            var probe: Probe = .{};
            var table = io.vtable.*;
            table.now = Probe.now;
            table.futexWait = Probe.wait;
            table.futexWake = Probe.wake;
            pool.io = .{ .userdata = &probe, .vtable = &table };
            defer pool.io = io;
            const result = pool.requestUriWithDeadline(
                "http://127.0.0.1:1/",
                .{},
                .{ .clock = .awake, .raw = .fromNanoseconds(1003) },
            );
            const acquired = pool.mutex.tryLock();
            if (acquired) pool.mutex.unlock(io) else {
                // Keep a lock-leak failure from hanging pool destruction.
                pool.mutex.state.store(.unlocked, .release);
            }
            try std.testing.expect(acquired);
            try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
            try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
            if (result) |_| return error.UnexpectedAdmission else |err| switch (err) {
                error.Timeout => return,
                error.OutOfMemory => return err,
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Task.run, .{base});
}

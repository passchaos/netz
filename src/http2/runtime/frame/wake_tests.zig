const std = @import("std");
const wake = @import("wake.zig");
const allocator = std.testing.allocator;
const ReadError = error{ Canceled, Timeout, UnexpectedFrame, EndOfStream };

const Read = struct {
    io: std.Io,
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    finished: std.Io.Event = .unset,
    failure: ?ReadError = null,
    fn run(self: *@This(), _: ?std.Io.Clock.Timestamp) ReadError!u32 {
        self.entered.set(self.io);
        defer self.finished.set(self.io);
        // Emulate a successful transport read that commits input during join.
        self.release.wait(self.io) catch {};
        if (self.failure) |err| return err;
        return 42;
    }
};

test "HTTP/2 buffered frame wake retains a completed read when wake admission fails" {
    const Probe = struct {
        backend: std.Io.Threaded,
        table: std.Io.VTable = undefined,
        read: *Read = undefined,
        submissions: usize = 0,
        fn io(self: *@This()) std.Io {
            const base = self.backend.io();
            self.table = base.vtable.*;
            self.table.groupConcurrent = concurrent;
            return .{ .userdata = base.userdata, .vtable = &self.table };
        }
        fn concurrent(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            const self: *@This() = @fieldParentPtr("backend", backend);
            self.submissions += 1;
            const base = self.backend.io();
            if (self.submissions == 2) {
                self.read.release.set(base);
                self.read.finished.wait(base) catch {};
                return error.ConcurrencyUnavailable;
            }
            return base.vtable.groupConcurrent(base.userdata, group, context, alignment, start);
        }
    };
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .nothing }) };
    defer probe.backend.deinit();
    const io = probe.io();
    var read: Read = .{ .io = io };
    probe.read = &read;
    var cancel: std.Io.Event = .unset;
    const result = try wake.read(io, &read, null, &cancel, u32, ReadError, Read.run);
    try std.testing.expectEqual(@as(u32, 42), result.frame);
    try std.testing.expectEqual(@as(usize, 2), probe.submissions);
}

test "HTTP/2 buffered frame wake returns late input and rearms parent cancellation" {
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    var read: Read = .{ .io = io };
    var cancel: std.Io.Event = .unset;
    const Worker = struct {
        read: *Read,
        cancel: *std.Io.Event,
        value: ?u32 = null,
        err: ?anyerror = null,
        cancel_rearmed: bool = false,
        fn run(self: *@This()) void {
            const result = wake.read(self.read.io, self.read, null, self.cancel, u32, ReadError, Read.run) catch |err| {
                self.err = err;
                return;
            };
            self.value = result.frame;
            self.read.io.checkCancel() catch |err| {
                self.cancel_rearmed = err == error.Canceled;
            };
        }
    };
    var worker: Worker = .{ .read = &read, .cancel = &cancel };
    var future = try std.Io.concurrent(io, Worker.run, .{&worker});
    defer future.cancel(io);
    try read.entered.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
    future.cancel(io);
    try std.testing.expect(worker.err == null);
    try std.testing.expectEqual(@as(?u32, 42), worker.value);
    try std.testing.expect(worker.cancel_rearmed);
}

test "HTTP/2 buffered frame wake rejects missing concurrency before reading" {
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    var read: Read = .{ .io = io };
    var cancel: std.Io.Event = .unset;
    try std.testing.expectError(error.ConcurrencyUnavailable, wake.read(io, &read, null, &cancel, u32, ReadError, Read.run));
    try std.testing.expect(!read.entered.isSet());
}

test "HTTP/2 buffered frame wake preserves reader timeout protocol failure and EOF during join" {
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    for ([_]ReadError{ error.Timeout, error.UnexpectedFrame, error.EndOfStream }) |failure| {
        var read: Read = .{ .io = io, .failure = failure };
        var cancel: std.Io.Event = .unset;
        cancel.set(io);
        try std.testing.expectError(failure, wake.read(io, &read, null, &cancel, u32, ReadError, Read.run));
        try std.testing.expect(read.finished.isSet());
    }
}

test "HTTP/2 buffered frame wake returns wake only after the canceled reader joins" {
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    var read: Read = .{ .io = io, .failure = error.Canceled };
    var cancel: std.Io.Event = .unset;
    cancel.set(io);
    const result = try wake.read(io, &read, null, &cancel, u32, ReadError, Read.run);
    try std.testing.expect(result == .wake);
    try std.testing.expect(read.finished.isSet());
}

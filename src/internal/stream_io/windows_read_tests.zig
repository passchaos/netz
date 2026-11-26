//! Native Threaded TCP cancellation preserves completed and queued input.
const std = @import("std");
const builtin = @import("builtin");
const ordinary = @import("read.zig").readSome;
const timed = @import("timed_read.zig").readSomeWithDeadline;
const net = std.Io.net;

const Pair = struct {
    sender: net.Stream,
    receiver: net.Stream,
    sender_open: bool = true,

    fn init(io: std.Io) !Pair {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer sender.close(io);
        return .{ .sender = sender, .receiver = try listener.accept(io) };
    }

    fn deinit(self: Pair, io: std.Io) void {
        self.receiver.close(io);
        if (self.sender_open) self.sender.close(io);
    }

    fn send(self: Pair, io: std.Io, bytes: []const u8) !void {
        var writer = self.sender.writer(io, &.{});
        try writer.interface.writeAll(bytes);
    }
};

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
}

fn read(io: std.Io, stream: net.Stream, bytes: []u8, bounded: bool) !usize {
    return if (bounded) timed(io, stream, bytes, deadline(io)) else ordinary(io, stream, bytes);
}

/// Retain the original backend userdata. Only this wait is observed; native
/// submission/completion and cancellation still use the actual Threaded owner.
const Wait = struct {
    var active: ?*Wait = null;
    delegate: std.Io,
    mode: enum { completed, entered },
    first: bool = true,
    native_entered: bool = false,
    ready: std.Io.Event = .unset,
    never: std.Io.Event = .unset,

    fn awaitConcurrent(_: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
        const self = active.?;
        if (self.first) {
            self.first = false;
            switch (self.mode) {
                .completed => {
                    try batch.awaitConcurrent(self.delegate, timeout);
                    std.debug.assert(batch.completed.head != .none);
                    self.ready.set(self.delegate);
                    try self.never.wait(self.delegate);
                    return;
                },
                .entered => {
                    batch.awaitConcurrent(self.delegate, .{ .duration = .{ .clock = .awake, .raw = .zero } }) catch |err| {
                        if (err != error.Timeout) return err;
                    };
                    self.native_entered = batch.pending.head != .none;
                    self.ready.set(self.delegate);
                },
            }
        }
        return batch.awaitConcurrent(self.delegate, timeout);
    }

    fn io(self: *Wait, table: *std.Io.VTable) std.Io {
        active = self;
        table.* = self.delegate.vtable.*;
        table.batchAwaitConcurrent = awaitConcurrent;
        return .{ .userdata = self.delegate.userdata, .vtable = table };
    }
};

const Caller = struct {
    io: std.Io,
    stream: net.Stream,
    bounded: bool,
    buffer: [5]u8 = @splat(0xcc),
    received: usize = 0,
    read_error: ?anyerror = null,
    never: std.Io.Event = .unset,
    observe_rearm: bool = false,

    fn run(self: *Caller) !void {
        defer Wait.active.?.ready.set(Wait.active.?.delegate);
        self.received = read(self.io, self.stream, &self.buffer, self.bounded) catch |err| {
            self.read_error = err;
            return err;
        };
        if (self.observe_rearm) try self.never.wait(self.io);
    }
};

test "stream timed Windows completed reads preserve bytes EOF and caller cancellation" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |bounded| for ([_]bool{ false, true }) |eof| {
        var pair = try Pair.init(base);
        defer pair.deinit(base);
        if (eof) {
            pair.sender.close(base);
            pair.sender_open = false;
        } else try pair.send(base, "first");
        var wait = Wait{ .delegate = base, .mode = .completed };
        defer Wait.active = null;
        var table: std.Io.VTable = undefined;
        var caller = Caller{ .io = wait.io(&table), .stream = pair.receiver, .bounded = bounded, .observe_rearm = true };
        var task = try base.concurrent(Caller.run, .{&caller});
        defer task.cancel(base) catch {};
        try wait.ready.wait(base);
        try std.testing.expectError(error.Canceled, task.cancel(base));
        try std.testing.expect(caller.read_error == null);
        try std.testing.expectEqual(@as(usize, if (eof) 0 else 5), caller.received);
        if (!eof) {
            try std.testing.expectEqualStrings("first", &caller.buffer);
            try pair.send(base, "reuse");
            var suffix: [5]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 5), try timed(base, pair.receiver, &suffix, deadline(base)));
            try std.testing.expectEqualStrings("reuse", &suffix);
        }
    };
}

test "stream timed Windows idle reads cancel after native entry and reuse sockets" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |bounded| {
        const pair = try Pair.init(base);
        defer pair.deinit(base);
        var wait = Wait{ .delegate = base, .mode = .entered };
        defer Wait.active = null;
        var table: std.Io.VTable = undefined;
        var caller = Caller{ .io = wait.io(&table), .stream = pair.receiver, .bounded = bounded };
        var task = try base.concurrent(Caller.run, .{&caller});
        defer task.cancel(base) catch {};
        try wait.ready.wait(base);
        try std.testing.expect(wait.native_entered);
        try std.testing.expectError(error.Canceled, task.cancel(base));
        try std.testing.expectEqualSlices(u8, &@as([5]u8, @splat(0xcc)), &caller.buffer);
        try pair.send(base, "reuse");
        var bytes: [5]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 5), try timed(base, pair.receiver, &bytes, deadline(base)));
        try std.testing.expectEqualStrings("reuse", &bytes);
    }
}

test "stream timed Windows read cancellation preserves queued input before admission" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const Early = struct {
        ready: std.Io.Event = .unset,
        never: std.Io.Event = .unset,
        buffer: [5]u8 = @splat(0xcc),

        fn run(self: *@This(), task_io: std.Io, stream: net.Stream, bounded: bool) !void {
            self.ready.set(task_io);
            self.never.wait(task_io) catch {
                std.Io.recancel(task_io);
            };
            try std.testing.expectError(error.Canceled, read(task_io, stream, &self.buffer, bounded));
        }
    };
    for ([_]bool{ false, true }) |bounded| {
        const pair = try Pair.init(io);
        defer pair.deinit(io);
        try pair.send(io, "first");
        var early = Early{};
        var task = try io.concurrent(Early.run, .{ &early, io, pair.receiver, bounded });
        defer task.cancel(io) catch {};
        try early.ready.wait(io);
        try task.cancel(io);
        try std.testing.expectEqualSlices(u8, &@as([5]u8, @splat(0xcc)), &early.buffer);
        var bytes: [5]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 5), try timed(io, pair.receiver, &bytes, deadline(io)));
        try std.testing.expectEqualStrings("first", &bytes);
    }
}

test "stream timed Windows read races conserve the exact TCP prefix" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |bounded| {
        const pair = try Pair.init(base);
        defer pair.deinit(base);
        for (0..32) |_| {
            var wait = Wait{ .delegate = base, .mode = .entered };
            defer Wait.active = null;
            var table: std.Io.VTable = undefined;
            var caller = Caller{ .io = wait.io(&table), .stream = pair.receiver, .bounded = bounded };
            var task = try base.concurrent(Caller.run, .{&caller});
            defer task.cancel(base) catch {};
            try wait.ready.wait(base);
            try std.testing.expect(wait.native_entered);
            try pair.send(base, "first");
            task.cancel(base) catch |err| try std.testing.expectEqual(error.Canceled, err);
            if (caller.read_error) |err| try std.testing.expectEqual(error.Canceled, err);
            const count = caller.received;
            try std.testing.expect(count <= 5);
            try std.testing.expectEqualStrings("first"[0..count], caller.buffer[0..count]);
            try pair.send(base, "reuse");
            var remainder: [10]u8 = undefined;
            var filled: usize = 0;
            const until = deadline(base);
            const expected = "firstreuse"[count..];
            while (filled < expected.len) {
                const received = try timed(base, pair.receiver, remainder[filled..expected.len], until);
                try std.testing.expect(received != 0);
                filled += received;
            }
            try std.testing.expectEqualStrings(expected, remainder[0..filled]);
        }
    }
}

test "stream timed Windows vector reads retain every completed destination" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const base = threaded.io();
    const pair = try Pair.init(base);
    defer pair.deinit(base);
    try pair.send(base, "first");
    var wait = Wait{ .delegate = base, .mode = .completed };
    defer Wait.active = null;
    var table: std.Io.VTable = undefined;
    const VectorCaller = struct {
        io: std.Io,
        stream: net.Stream,
        first: [2]u8 = undefined,
        second: [3]u8 = undefined,
        received: usize = 0,
        never: std.Io.Event = .unset,

        fn run(self: *@This()) !void {
            defer Wait.active.?.ready.set(Wait.active.?.delegate);
            var vectors = [_][]u8{ &self.first, &self.second };
            self.received = try @import("read.zig").readVec(self.io, self.stream, &vectors);
            try self.never.wait(self.io);
        }
    };
    var caller = VectorCaller{ .io = wait.io(&table), .stream = pair.receiver };
    var task = try base.concurrent(VectorCaller.run, .{&caller});
    defer task.cancel(base) catch {};
    try wait.ready.wait(base);
    try std.testing.expectError(error.Canceled, task.cancel(base));
    try std.testing.expectEqual(@as(usize, 5), caller.received);
    try std.testing.expectEqualStrings("fi", &caller.first);
    try std.testing.expectEqualStrings("rst", &caller.second);
}

//! Hold the first write and observe the second writer entering its futex wait.
//! This forces the queued-writer boundary without relying on sleep durations.
const std = @import("std");
const stream_connection = @import("../stream_connection.zig");
const allocator = std.testing.allocator;
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");

const Peer = struct {
    io: std.Io,
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    output: std.ArrayList(u8) = .empty,
    writes: usize = 0,
    closes: usize = 0,
    fail: bool,

    fn read(_: ?*anyopaque, _: []u8) anyerror!usize {
        return 0;
    }

    fn write(context: ?*anyopaque, bytes: []const u8) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.writes += 1;
        if (self.writes == 1) {
            self.entered.set(self.io);
            try self.release.wait(self.io);
            if (self.fail) {
                try self.output.appendSlice(allocator, bytes[0..1]);
                return error.WriteFailed;
            }
        }
        try self.output.appendSlice(allocator, bytes);
    }

    fn close(context: ?*anyopaque) void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.closes += 1;
    }
};

const WaitProbe = struct {
    delegate: std.Io,
    mutex: *std.Io.Mutex,
    waiting: std.Io.Event = .unset,

    fn wait(context: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self: *WaitProbe = @ptrCast(@alignCast(context.?));
        if (pointer == @as(*const u32, @ptrCast(&self.mutex.state.raw))) {
            self.waiting.set(self.delegate);
        }
        self.delegate.vtable.futexWaitUncancelable(self.delegate.userdata, pointer, expected);
    }

    fn wake(context: ?*anyopaque, pointer: *const u32, count: u32) void {
        const self: *WaitProbe = @ptrCast(@alignCast(context.?));
        self.delegate.vtable.futexWake(self.delegate.userdata, pointer, count);
    }
};

const Writer = struct {
    const Kind = enum { text, slices, close };
    connection: *stream_connection.Connection,
    kind: Kind,
    err: ?anyerror = null,

    fn run(self: *Writer) void {
        const result = switch (self.kind) {
            .text => self.connection.sendText("queued"),
            .slices => self.connection.sendTextSlices(&.{ "queued", "-slices" }),
            .close => self.connection.sendClose(.normal_closure, ""),
        };
        result catch |err| {
            self.err = err;
        };
    }
};

fn exercise(base: std.Io, fail: bool, kind: Writer.Kind) !void {
    var peer = Peer{ .io = base, .fail = fail };
    defer peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(allocator, base, .{
        .context = &peer,
        .read_fn = Peer.read,
        .write_fn = Peer.write,
        .close_fn = Peer.close,
    }, .{});
    defer connection.deinit();
    var probe = WaitProbe{ .delegate = base, .mutex = &connection.write_mutex };
    connection.io = forwarded_io.observer(&probe, .{
        .futexWaitUncancelable = WaitProbe.wait,
        .futexWake = WaitProbe.wake,
    });
    defer connection.io = base;

    var first = Writer{ .connection = &connection, .kind = .close };
    const closer = try std.Thread.spawn(.{}, Writer.run, .{&first});
    var closer_joined = false;
    defer if (!closer_joined) {
        peer.release.set(base);
        closer.join();
    };
    try peer.entered.wait(base);
    var second = Writer{ .connection = &connection, .kind = kind };
    const queued = try std.Thread.spawn(.{}, Writer.run, .{&second});
    var queued_joined = false;
    defer if (!queued_joined) {
        peer.release.set(base);
        queued.join();
    };
    try probe.waiting.wait(base);
    peer.release.set(base);
    closer.join();
    closer_joined = true;
    queued.join();
    queued_joined = true;

    try std.testing.expectEqual(@as(usize, 1), peer.writes);
    if (fail) {
        try std.testing.expectEqual(error.WriteFailed, first.err.?);
        try std.testing.expectEqual(error.ConnectionClosed, second.err.?);
        try std.testing.expect(connection.isClosed());
        try std.testing.expect(!connection.closeSent());
        try std.testing.expectEqualSlices(u8, &.{0x88}, peer.output.items);
        try std.testing.expectEqual(@as(usize, 1), peer.closes);
    } else {
        try std.testing.expect(first.err == null);
        if (kind == .close) {
            try std.testing.expect(second.err == null);
        } else try std.testing.expectEqual(error.ConnectionClosed, second.err.?);
        try std.testing.expect(connection.closeSent());
        try std.testing.expectEqualSlices(u8, &.{ 0x88, 2, 3, 0xe8 }, peer.output.items);
    }
}

test "WebSocket stream adapter queued writers observe Close and transport failure" {
    try native_protocol_io.runStream(queuedWriters);
}

fn queuedWriters(io: std.Io) !void {
    for ([_]bool{ false, true }) |fail| {
        for (std.meta.tags(Writer.Kind)) |kind| try exercise(io, fail, kind);
    }
}

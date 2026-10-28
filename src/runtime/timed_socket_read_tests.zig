const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const Backend = @import("../runtime.zig").Backend;
const native = @import("timed_socket.zig");
const stream_io = @import("../internal/stream_io.zig");
const allocator = std.testing.allocator;

const Pair = struct {
    client: std.Io.net.Stream,
    peer: std.Io.net.Stream,
    peer_open: bool = true,

    fn init(io: std.Io) !Pair {
        var listener = try std.Io.net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, io, .{});
        defer listener.deinit(io);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer client.close(io);
        const peer = try listener.accept(io);
        return .{ .client = client, .peer = peer };
    }

    fn deinit(self: Pair, io: std.Io) void {
        self.client.close(io);
        if (self.peer_open) self.peer.close(io);
    }

    fn send(self: Pair, io: std.Io, text: []const u8) !void {
        var committed: usize = 0;
        try stream_io.writeAllTrackedWithDeadline(io, self.peer, text, &committed, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    }
};

test "stream native timed reader rejects wrapped foreign blocking and ordinary-thread contexts" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var buffer: [1]u8 = undefined;
    const invalid: std.Io.net.Stream = .{ .socket = .{ .handle = 0, .address = .{ .ip4 = .loopback(0) } } };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var vtable = io.vtable.*;
    try std.testing.expect(native.tryRead(.{ .userdata = io.userdata, .vtable = &vtable }, invalid, &buffer, deadline) == null);
    try std.testing.expect(native.tryRead(zio.Runtime.fromIo(io).?.blockingIo(), invalid, &buffer, deadline) == null);
    const other = try zio.Runtime.init(allocator, .{ .enable_main_executor = false, .executors = .exact(1) });
    defer other.deinit();
    try std.testing.expect(native.tryRead(other.io(), invalid, &buffer, deadline) == null);
    const Probe = struct {
        fn run(task_io: std.Io, stream: std.Io.net.Stream, result: *bool) void {
            var bytes: [1]u8 = undefined;
            result.* = native.tryRead(task_io, stream, &bytes, .{ .clock = .awake, .raw = .zero }) == null;
        }
    };
    var rejected = false;
    const thread = try std.Thread.spawn(.{}, Probe.run, .{ io, invalid, &rejected });
    thread.join();
    try std.testing.expect(rejected);
}

test "stream native timed reader preserves ready bytes expired budgets and EOF" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    try std.testing.expect(native.available(io));
    var pair = try Pair.init(io);
    defer pair.deinit(io);
    try pair.send(io, "ready");
    var bytes: [16]u8 = @splat(0xcc);
    try std.testing.expectError(error.Timeout, stream_io.readSomeWithDeadline(io, pair.client, &bytes, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xcc)), &bytes);
    const count = try stream_io.readSomeWithDeadline(io, pair.client, &bytes, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings("ready", bytes[0..count]);
    pair.peer.close(io);
    pair.peer_open = false;
    try std.testing.expectEqual(@as(usize, 0), try stream_io.readSomeWithDeadline(io, pair.client, &bytes, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
}

test "stream native timed reader timeout joins borrowed storage without consuming later bytes" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    var abandoned: [32]u8 = @splat(0xcc);
    try std.testing.expectError(error.Timeout, stream_io.readSomeWithDeadline(io, pair.client, &abandoned, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(20) })));
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0xcc)), &abandoned);
    @memset(&abandoned, 0xee);
    try pair.send(io, "after-timeout");
    var next: [32]u8 = undefined;
    const count = try stream_io.readSomeWithDeadline(io, pair.client, &next, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings("after-timeout", next[0..count]);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0xee)), &abandoned);
}

test "stream native timed reader cancellation joins storage and leaves the next read intact" {
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const pair = try Pair.init(io);
    defer pair.deinit(io);
    const Probe = struct {
        started: std.Io.Event = .unset,
        bytes: [32]u8 = @splat(0xcc),
        fn run(self: *@This(), task_io: std.Io, stream: std.Io.net.Stream) !usize {
            const deadline = std.Io.Clock.Timestamp.fromNow(task_io, .{ .clock = .awake, .raw = .fromSeconds(5) });
            var first: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 1), try stream_io.readSomeWithDeadline(task_io, stream, &first, deadline));
            try std.testing.expectEqual(@as(u8, '*'), first[0]);
            self.started.set(task_io);
            return stream_io.readSomeWithDeadline(task_io, stream, &self.bytes, deadline);
        }
    };
    var probe: Probe = .{};
    var reading = try io.concurrent(Probe.run, .{ &probe, io, pair.client });
    defer _ = reading.cancel(io) catch {};
    try pair.send(io, "*");
    try probe.started.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectError(error.Canceled, reading.cancel(io));
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0xcc)), &probe.bytes);
    @memset(&probe.bytes, 0xee);
    try pair.send(io, "after-cancel");
    var next: [32]u8 = undefined;
    const count = try stream_io.readSomeWithDeadline(io, pair.client, &next, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings("after-cancel", next[0..count]);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0xee)), &probe.bytes);
}

test "stream native timed reader reports abortive TCP reset as a socket error" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var backend = try Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var pair = try Pair.init(io);
    defer pair.deinit(io);
    const abortive = std.posix.linger{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(pair.peer.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&abortive));
    pair.peer.close(io);
    pair.peer_open = false;
    var descriptors = [_]std.posix.pollfd{.{ .fd = pair.client.socket.handle, .events = std.posix.POLL.ERR | std.posix.POLL.HUP, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&descriptors, 1000));
    var bytes: [8]u8 = @splat(0xcc);
    try std.testing.expectError(error.ConnectionResetByPeer, stream_io.readSomeWithDeadline(io, pair.client, &bytes, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0xcc)), &bytes);
}

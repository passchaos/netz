const std = @import("std");
const runtime = @import("../../runtime.zig");
const websocket = @import("../../mod.zig");
const allocator = std.testing.allocator;

const Clock = struct {
    delegate: std.Io,
    connection: *runtime.Connection,
    failed: std.Io.Event = .unset,
    var active: std.atomic.Value(?*Clock) = .init(null);
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = active.load(.acquire).?;
        if (self.connection.receive_failed.load(.acquire)) self.failed.set(self.delegate);
        return self.delegate.vtable.now(userdata, clock);
    }
};

test "WebSocket fatal receive cleanup sends mapped Close when contention clears within budget" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{ .reuse_address = true });
        defer listener.deinit(base);
        const peer_stream = try listener.socket.address.connect(base, .{ .mode = .stream });
        const stream = try listener.accept(base);
        var peer = runtime.testing.initDirectConnection(allocator, base, peer_stream, if (role == .client) .server else .client, .{});
        defer peer.close();
        var connection = runtime.testing.initDirectConnection(allocator, base, stream, role, .{});
        defer connection.close();
        var clock = Clock{ .delegate = base, .connection = &connection };
        Clock.active.store(&clock, .release);
        defer Clock.active.store(null, .release);
        var table = base.vtable.*;
        table.now = Clock.now;
        connection.io = .{ .userdata = base.userdata, .vtable = &table };
        try connection.inbuf.appendSlice(allocator, &.{ 0x83, 0 });
        connection.send_mutex.lockUncancelable(base);
        var locked = true;
        defer if (locked) connection.send_mutex.unlock(base);
        const Task = struct {
            connection: *runtime.Connection,
            err: ?anyerror = null,
            fn run(self: *@This()) void {
                var frame = self.connection.receiveFrameWithTimeout(.fromSeconds(1)) catch |err| {
                    self.err = err;
                    return;
                };
                frame.deinit(allocator);
            }
        };
        var task = Task{ .connection = &connection };
        var future = try base.concurrent(Task.run, .{&task});
        defer _ = future.cancel(base);
        const observed = if (clock.failed.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } })) |_| true else |err| switch (err) {
            error.Timeout => false,
            else => return err,
        };
        connection.send_mutex.unlock(base);
        locked = false;
        future.await(base);
        try std.testing.expect(observed);
        try std.testing.expectEqual(@as(?anyerror, error.InvalidOpcode), task.err);
        var reply = try peer.receiveFrameWithTimeout(.fromSeconds(1));
        defer reply.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.close, reply.header.opcode);
        try std.testing.expectEqual(@as(u16, 1002), std.mem.readInt(u16, reply.payload[0..2], .big));
        try std.testing.expect(connection.close_sent.load(.acquire));
        try std.testing.expect(!connection.write_aborted.load(.acquire));
        try std.testing.expect(!connection.receive_abort_pending.load(.acquire));
    }
}

test "WebSocket fatal receive cleanup aborts TCP when an error Close cannot obtain a mask" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer peer.close(io);
    const stream = try listener.accept(io);
    const Entropy = struct {
        fn fail(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return error.EntropyUnavailable;
        }
    };
    var table = io.vtable.*;
    table.randomSecure = Entropy.fail;
    var connection = runtime.testing.initDirectConnection(allocator, .{ .userdata = io.userdata, .vtable = &table }, stream, .client, .{});
    defer connection.close();
    try connection.inbuf.appendSlice(allocator, &.{ 0x83, 0 });
    try std.testing.expectError(error.InvalidOpcode, connection.receiveFrameWithTimeout(.fromSeconds(1)));
    try std.testing.expect(connection.receive_failed.load(.acquire));
    try std.testing.expect(connection.write_aborted.load(.acquire));
    try std.testing.expect(connection.pending_write.isNone());
    try std.testing.expect(!connection.close_sent.load(.acquire));
    var storage: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try @import("../../../internal/stream_io.zig").readSomeWithDeadline(io, peer, &storage, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
}

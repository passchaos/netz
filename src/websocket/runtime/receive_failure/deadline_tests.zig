const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

test "WebSocket fatal receive cleanup keeps its deadline while a sender owns the mutex" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ false, true }) |abrupt| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
        defer peer.close(io);
        const stream = try listener.accept(io);
        var connection = runtime.testing.initDirectConnection(allocator, io, stream, .client, .{});
        defer connection.close();
        if (abrupt) {
            try peer.shutdown(io, .send);
        } else try connection.inbuf.appendSlice(allocator, &.{ 0x83, 0 });
        connection.send_mutex.lockUncancelable(io);
        var locked = true;
        defer if (locked) connection.send_mutex.unlock(io);
        const Task = struct {
            connection: *runtime.Connection,
            io: std.Io,
            done: std.Io.Event = .unset,
            err: ?anyerror = null,
            fn run(self: *@This()) void {
                var frame = self.connection.receiveFrameWithTimeout(.fromMilliseconds(10)) catch |err| {
                    self.err = err;
                    self.done.set(self.io);
                    return;
                };
                frame.deinit(allocator);
                self.done.set(self.io);
            }
        };
        var task = Task{ .connection = &connection, .io = io };
        var future = try io.concurrent(Task.run, .{&task});
        defer _ = future.cancel(io);
        const observed = if (task.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } })) |_| true else |err| switch (err) {
            error.Timeout => false,
            else => return err,
        };
        connection.send_mutex.unlock(io);
        locked = false;
        future.await(io);
        try std.testing.expect(observed);
        try std.testing.expectEqual(@as(?anyerror, if (abrupt) error.ConnectionClosed else error.InvalidOpcode), task.err);
        try std.testing.expect(connection.receive_failed.load(.acquire));
    }
}

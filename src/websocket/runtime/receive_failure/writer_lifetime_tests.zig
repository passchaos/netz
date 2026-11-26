const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");

const Gate = struct {
    delegate: std.Io,
    read_armed: std.atomic.Value(bool) = .init(true),
    read_entered: std.Io.Event = .unset,
    read_release: std.Io.Event = .unset,
    write_entered: std.Io.Event = .unset,
    write_release: std.Io.Event = .unset,
    stable: bool = true,

    fn read(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, buffers: [][]u8) std.Io.net.Stream.Reader.Error!usize {
        const self: *Gate = @ptrCast(@alignCast(userdata.?));
        if (self.read_armed.swap(false, .acq_rel)) {
            self.read_entered.set(self.delegate);
            self.read_release.waitUncancelable(self.delegate);
        }
        return self.delegate.vtable.netRead(self.delegate.userdata, socket, buffers);
    }

    fn write(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self: *Gate = @ptrCast(@alignCast(userdata.?));
        const fingerprint = std.hash.Wyhash.hash(0, header);
        self.write_entered.set(self.delegate);
        self.write_release.waitUncancelable(self.delegate);
        self.stable = fingerprint == std.hash.Wyhash.hash(0, header);
        return self.delegate.vtable.netWrite(self.delegate.userdata, socket, header, parts, splat);
    }
};

test "WebSocket fatal receive cleanup retains active writer buffers until joined completion" {
    try native_protocol_io.runStream(activeWriterLifetime);
}

fn activeWriterLifetime(base: std.Io) !void {
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{ .reuse_address = true });
    defer listener.deinit(base);
    const peer = try listener.socket.address.connect(base, .{ .mode = .stream });
    defer peer.close(base);
    const stream = try listener.accept(base);
    var gate = Gate{ .delegate = base };
    const io = forwarded_io.observer(&gate, .{
        .netRead = Gate.read,
        .netWrite = Gate.write,
    });
    var connection = runtime.testing.initDirectConnection(allocator, io, stream, .client, .{});
    defer connection.close();
    defer connection.io = base;
    connection.permessage_deflate = true;
    connection.compression_send_context_takeover = true;
    connection.compression_threshold = 1;
    var writer = peer.writer(base, &.{});
    try writer.interface.writeAll(&.{ 0x83, 0 });
    const Receiver = struct {
        connection: *runtime.Connection,
        io: std.Io,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var frame = self.connection.receiveFrameWithTimeout(.fromMilliseconds(100)) catch |err| {
                self.err = err;
                self.done.set(self.io);
                return;
            };
            frame.deinit(allocator);
            self.done.set(self.io);
        }
    };
    var receiver = Receiver{ .connection = &connection, .io = base };
    var read_future = try base.concurrent(Receiver.run, .{&receiver});
    defer _ = read_future.cancel(base);
    defer gate.read_release.set(base);
    try gate.read_entered.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const Sender = struct {
        connection: *runtime.Connection,
        err: ?anyerror = null,
        progress: runtime.MessageWriteProgress = .{},
        fn run(self: *@This()) void {
            self.connection.sendBinaryWithTimeout("owned compression payload/" ** 128, &self.progress, .fromSeconds(5)) catch |err| {
                self.err = err;
            };
        }
    };
    var sender = Sender{ .connection = &connection };
    var write_future = try base.concurrent(Sender.run, .{&sender});
    defer _ = write_future.cancel(base);
    defer gate.write_release.set(base);
    try gate.write_entered.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    gate.read_release.set(base);
    const observed = if (receiver.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } })) |_| true else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    // The write callback cannot mutate these fields until its gate opens.
    const retained = observed and connection.pending_write.isMessage() and connection.compression_send.payload.capacity != 0 and connection.receive_abort_pending.load(.acquire);
    gate.write_release.set(base);
    write_future.await(base);
    read_future.await(base);
    try std.testing.expect(observed);
    try std.testing.expect(retained);
    try std.testing.expectEqual(@as(?anyerror, error.InvalidOpcode), receiver.err);
    try std.testing.expect(sender.err != null);
    try std.testing.expect(gate.stable);
    try std.testing.expect(connection.pending_write.isNone());
    try std.testing.expectEqual(@as(usize, 0), connection.compression_send.payload.capacity);
    try std.testing.expect(!connection.receive_abort_pending.load(.acquire));
}

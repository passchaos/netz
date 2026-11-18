const std = @import("std");
const test_socket = @import("test_socket.zig");
const builtin = @import("builtin");
const stream_io = @import("stream_io.zig");

const Observer = struct {
    var active: *Observer = undefined;
    delegate: std.Io,
    calls: usize = 0,
    bytes: [32]u8 = undefined,
    written: usize = 0,
    race_timeout: bool = false,
    race_cancel: bool = false,
    begun: std.Io.Event = .unset,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        self.calls += 1;
        if (self.calls > 1) return error.NetworkDown;
        const count = @min(@as(usize, 3), header.len);
        @memcpy(self.bytes[0..count], header[0..count]);
        self.written = count;
        if (self.race_cancel) {
            self.begun.set(self.delegate);
            std.Io.sleep(self.delegate, .fromSeconds(10), .awake) catch {};
        }
        if (self.race_timeout) std.Io.sleep(self.delegate, .fromMilliseconds(20), .awake) catch {};
        return count;
    }
};

fn dummyStream() std.Io.net.Stream {
    return test_socket.stream();
}

test "stream timed socket writer preserves prefix before a network error" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const delegate = threaded.io();
    var observer = Observer{ .delegate = delegate };
    Observer.active = &observer;
    var vtable = delegate.vtable.*;
    vtable.netWrite = Observer.write;
    const io = std.Io{ .userdata = delegate.userdata, .vtable = &vtable };
    var committed: usize = 99;
    try std.testing.expectError(error.NetworkDown, stream_io.writeAllTrackedWithDeadline(io, dummyStream(), "abcdef", &committed, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expectEqual(@as(usize, 3), committed);
    try std.testing.expectEqualStrings("abc", observer.bytes[0..observer.written]);
}

test "stream timed socket writer rejects expired deadline before netWrite" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const delegate = threaded.io();
    var observer = Observer{ .delegate = delegate };
    Observer.active = &observer;
    var vtable = delegate.vtable.*;
    vtable.netWrite = Observer.write;
    const io = std.Io{ .userdata = delegate.userdata, .vtable = &vtable };
    try std.testing.expectError(error.Timeout, stream_io.writeSomeWithDeadline(io, dummyStream(), "abc", .{ .clock = .awake, .raw = .zero }));
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
}

test "stream timed socket writer retains a commit racing timeout cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const delegate = threaded.io();
    var observer = Observer{ .delegate = delegate, .race_timeout = true };
    Observer.active = &observer;
    var vtable = delegate.vtable.*;
    vtable.netWrite = Observer.write;
    const io = std.Io{ .userdata = delegate.userdata, .vtable = &vtable };
    const written = try stream_io.writeSomeWithDeadline(io, dummyStream(), "abc", .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) }));
    try std.testing.expectEqual(@as(usize, 3), written);
    try std.testing.expectEqualStrings("abc", observer.bytes[0..observer.written]);
}

test "stream timed socket writer preserves cancellation after committed progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const delegate = threaded.io();
    var observer = Observer{ .delegate = delegate, .race_cancel = true };
    Observer.active = &observer;
    var vtable = delegate.vtable.*;
    vtable.netWrite = Observer.write;
    const io: std.Io = .{ .userdata = delegate.userdata, .vtable = &vtable };
    const Caller = struct {
        io: std.Io,
        written: usize = 0,
        never: std.Io.Event = .unset,
        fn run(self: *@This()) !void {
            self.written = try stream_io.writeSomeWithDeadline(self.io, dummyStream(), "abcdef", .fromNow(self.io, .{ .raw = .fromSeconds(10), .clock = .awake }));
            try self.never.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        }
    };
    var caller = Caller{ .io = io };
    var task = io.async(Caller.run, .{&caller});
    defer _ = task.cancel(io) catch {};
    try observer.begun.wait(delegate);
    try std.testing.expectError(error.Canceled, task.cancel(io));
    try std.testing.expectEqual(@as(usize, 3), caller.written);
    try std.testing.expectEqualStrings("abc", observer.bytes[0..3]);
}

test "stream timed socket writer reports an abortive TCP peer reset" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const peer = try listener.accept(io);
    const abortive = std.posix.linger{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(peer.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&abortive));
    peer.close(io);
    var fds = [_]std.posix.pollfd{.{ .fd = client.socket.handle, .events = std.posix.POLL.ERR | std.posix.POLL.HUP, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&fds, 1000));
    var committed: usize = 99;
    const result = stream_io.writeAllTrackedWithDeadline(io, client, "must-fail", &committed, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    if (result) |_| return error.TestUnexpectedResult else |err| {
        try std.testing.expect(err == error.ConnectionResetByPeer or err == error.SocketUnconnected);
    }
    try std.testing.expectEqual(@as(usize, 0), committed);
}

test "wide stream write waits for writability after EAGAIN" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer sender.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);

    const buffer_size: c_int = 4096;
    try std.posix.setsockopt(
        sender.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&buffer_size),
    );
    try std.posix.setsockopt(
        peer.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVBUF,
        std.mem.asBytes(&buffer_size),
    );

    // Fill both kernel queues so the next raw sendmsg observes EAGAIN.
    const filler = "z" ** 4096;
    for (0..3) |round| {
        while (true) {
            const rc = std.posix.system.sendto(
                sender.socket.handle,
                filler.ptr,
                filler.len,
                std.posix.MSG.DONTWAIT | std.posix.MSG.NOSIGNAL,
                null,
                0,
            );
            switch (std.posix.errno(rc)) {
                .SUCCESS, .INTR => continue,
                .AGAIN => break,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
        if (round != 2) {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
    }

    const payload = "x" ** (64 * 1024);
    const parts = [_][]const u8{payload};
    const Reader = struct {
        stream: std.Io.net.Stream,
        io: std.Io,
        payload_bytes: usize = 0,

        fn run(self: *@This()) void {
            var buffer: [4096]u8 = undefined;
            var reader = self.stream.reader(self.io, &buffer);
            var one: [1]u8 = undefined;
            while (true) {
                const count = reader.interface.readSliceShort(&one) catch return;
                if (count == 0) return;
                if (one[0] == 'x') self.payload_bytes += 1;
                if (self.payload_bytes == payload.len) return;
            }
        }
    };
    var reader = Reader{ .stream = peer, .io = io };
    const thread = try std.Thread.spawn(.{}, Reader.run, .{&reader});
    var joined = false;
    defer if (!joined) {
        peer.shutdown(io, .both) catch {};
        thread.join();
    };

    try stream_io.writeAllSlicesWide(io, sender, &parts);
    thread.join();
    joined = true;
    try std.testing.expectEqual(payload.len, reader.payload_bytes);
}

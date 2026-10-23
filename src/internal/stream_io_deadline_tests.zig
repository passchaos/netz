const std = @import("std");
const builtin = @import("builtin");
const stream_io = @import("stream_io.zig");

const Observer = struct {
    var active: *Observer = undefined;
    delegate: std.Io,
    calls: usize = 0,
    bytes: [32]u8 = undefined,
    written: usize = 0,
    race_timeout: bool = false,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        self.calls += 1;
        if (self.calls > 1) return error.NetworkDown;
        const count = @min(@as(usize, 3), header.len);
        @memcpy(self.bytes[0..count], header[0..count]);
        self.written = count;
        if (self.race_timeout) std.Io.sleep(self.delegate, .fromMilliseconds(20), .awake) catch {};
        return count;
    }
};

fn dummyStream() std.Io.net.Stream {
    return .{ .socket = .{ .handle = 0, .address = .{ .ip4 = .loopback(0) } } };
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

test "stream timed socket writer reports an abortive TCP peer reset" {
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

//! A timed socket read retains consumed bytes and joins cancellation.
const std = @import("std");
const read = @import("timed_read.zig").readSomeWithDeadline;
const test_socket = @import("../test_socket.zig");

const Observer = struct {
    var active: *Observer = undefined;
    delegate: std.Io,
    mode: enum { bytes, eof, io_error, blocked, late_bytes, late_io_error },
    calls: usize = 0,
    finished: bool = false,
    sleeps: std.atomic.Value(usize) = .init(0),
    started: std.Io.Event = .unset,
    timer_started: std.Io.Event = .unset,
    release: std.Io.Event = .unset,

    fn netRead(_: ?*anyopaque, _: std.Io.net.Socket.Handle, buffers: [][]u8) std.Io.net.Stream.Reader.Error!usize {
        const self = active;
        self.calls += 1;
        defer self.finished = true;
        self.started.set(self.delegate);
        switch (self.mode) {
            .bytes => {},
            .eof => return 0,
            .io_error => return error.NetworkDown,
            .blocked => try self.release.wait(self.delegate),
            .late_bytes => self.release.wait(self.delegate) catch {},
            .late_io_error => {
                self.release.wait(self.delegate) catch {};
                return error.NetworkDown;
            },
        }
        @memcpy(buffers[0][0..3], "abc");
        return 3;
    }

    fn io(self: *Observer, vtable: *std.Io.VTable) std.Io {
        active = self;
        vtable.* = self.delegate.vtable.*;
        vtable.netRead = netRead;
        return .{ .userdata = self.delegate.userdata, .vtable = vtable };
    }

    fn earlySleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active;
        if (self.sleeps.fetchAdd(1, .monotonic) == 0) return;
        self.timer_started.set(self.delegate);
        try self.delegate.vtable.sleep(userdata, timeout);
    }
};

fn deadline(io: std.Io, milliseconds: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromMilliseconds(milliseconds), .clock = .awake });
}

test "stream timed reader preserves wrapped netRead bytes EOF and source errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]@FieldType(Observer, "mode"){ .bytes, .eof, .io_error }) |mode| {
        var observer = Observer{ .delegate = io, .mode = mode };
        var vtable: std.Io.VTable = undefined;
        const wrapped = observer.io(&vtable);
        var buffer: [8]u8 = @splat(0xcc);
        const result = read(wrapped, test_socket.stream(), &buffer, deadline(io, 1000));
        switch (mode) {
            .bytes => {
                const count = try result;
                try std.testing.expectEqual(@as(usize, 3), count);
                try std.testing.expectEqualStrings("abc", buffer[0..count]);
                try std.testing.expectEqual(@as(u8, 0xcc), buffer[count]);
            },
            .eof => try std.testing.expectEqual(@as(usize, 0), try result),
            .io_error => try std.testing.expectError(error.NetworkDown, result),
            else => unreachable,
        }
        try std.testing.expectEqual(@as(usize, 1), observer.calls);
        try std.testing.expect(observer.finished);
    }
}

test "stream timed reader rejects expired deadlines without starting a read" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .mode = .bytes };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(error.Timeout, read(io, test_socket.stream(), &buffer, .{ .raw = .zero, .clock = .awake }));
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
    try std.testing.expectEqual(@as(usize, 0), try read(io, test_socket.stream(), &.{}, .{ .raw = .zero, .clock = .awake }));
}

test "stream timed reader admission failure leaves the receive buffer untouched" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .mode = .bytes };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    const Unavailable = struct {
        fn start(_: ?*anyopaque, _: *std.Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            return error.ConcurrencyUnavailable;
        }
    };
    vtable.groupConcurrent = Unavailable.start;
    var buffer: [8]u8 = @splat(0xcc);
    try std.testing.expectError(error.ConcurrencyUnavailable, read(io, test_socket.stream(), &buffer, deadline(io, 1000)));
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
    try std.testing.expectEqual(@as(u8, 0xcc), buffer[0]);
}

test "stream timed reader timeout joins the pending socket operation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .mode = .blocked };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var buffer: [8]u8 = @splat(0xcc);
    try std.testing.expectError(error.Timeout, read(io, test_socket.stream(), &buffer, deadline(io, 50)));
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expect(observer.finished);
    try std.testing.expectEqual(@as(u8, 0xcc), buffer[0]);
}

test "stream timed reader early timer wake preserves the original absolute deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .mode = .blocked };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    vtable.sleep = Observer.earlySleep;
    const Peer = struct {
        fn release(source: *Observer) !void {
            try source.started.wait(source.delegate);
            try source.timer_started.wait(source.delegate);
            source.release.set(source.delegate);
        }
    };
    var peer = try observer.delegate.concurrent(Peer.release, .{&observer});
    defer _ = peer.cancel(observer.delegate) catch {};
    var buffer: [8]u8 = undefined;
    const count = try read(io, test_socket.stream(), &buffer, deadline(io, 1000));
    try peer.await(observer.delegate);
    try std.testing.expectEqualStrings("abc", buffer[0..count]);
    try std.testing.expect(observer.sleeps.load(.monotonic) >= 2);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
}

test "stream timed reader retains bytes racing cancellation and rearms the caller" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .mode = .late_bytes };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    const Caller = struct {
        io: std.Io,
        buffer: [8]u8 = @splat(0xcc),
        received: usize = 0,
        never: std.Io.Event = .unset,

        fn run(self: *@This()) !void {
            self.received = try read(self.io, test_socket.stream(), &self.buffer, deadline(self.io, 5000));
            try self.never.wait(self.io);
        }
    };
    var caller = Caller{ .io = io };
    var task = try io.concurrent(Caller.run, .{&caller});
    defer _ = task.cancel(io) catch {};
    try observer.started.wait(io);
    try std.testing.expectError(error.Canceled, task.cancel(io));
    try std.testing.expect(observer.finished);
    try std.testing.expectEqual(@as(usize, 3), caller.received);
    try std.testing.expectEqualStrings("abc", caller.buffer[0..caller.received]);
}

test "stream timed reader retains a transport failure completed during cancellation join" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var observer = Observer{ .delegate = threaded.io(), .mode = .late_io_error };
    var vtable: std.Io.VTable = undefined;
    const io = observer.io(&vtable);
    var buffer: [8]u8 = @splat(0xcc);
    var task = try io.concurrent(read, .{ io, test_socket.stream(), &buffer, deadline(io, 5000) });
    defer _ = task.cancel(io) catch {};
    try observer.started.wait(io);
    try std.testing.expectError(error.NetworkDown, task.cancel(io));
    try std.testing.expect(observer.finished);
    try std.testing.expectEqual(@as(u8, 0xcc), buffer[0]);
}

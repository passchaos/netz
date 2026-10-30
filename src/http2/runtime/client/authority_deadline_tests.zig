const std = @import("std");
const runtime = @import("../../runtime.zig");

test "HTTP/2 IP and host authority allocation cannot renew a connect deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const parent_io = threaded.io();
    const Fake = struct {
        var timestamp: std.Io.Timestamp = .zero;
        var network_calls: std.atomic.Value(usize) = .init(0);
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return timestamp;
        }
        fn connect(_: ?*anyopaque, _: *const std.Io.net.IpAddress, _: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
            _ = network_calls.fetchAdd(1, .monotonic);
            return error.ConnectionRefused;
        }
    };
    const DelayedAllocator = struct {
        backing: std.mem.Allocator,
        allocated: usize = 0,
        freed: usize = 0,
        fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            const bytes = self.backing.rawAlloc(len, alignment, ret) orelse return null;
            self.allocated += len;
            Fake.timestamp.nanoseconds += std.time.ns_per_s;
            return bytes;
        }
        fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.freed += bytes.len;
            self.backing.rawFree(bytes, alignment, ret);
        }
        const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free };
    };
    var vtable = parent_io.vtable.*;
    vtable.now = Fake.now;
    vtable.netConnectIp = Fake.connect;
    const io: std.Io = .{ .userdata = parent_io.userdata, .vtable = &vtable };
    for (0..9) |mode| {
        Fake.timestamp = std.Io.Clock.awake.now(parent_io);
        Fake.network_calls.store(0, .monotonic);
        var delayed: DelayedAllocator = .{ .backing = allocator };
        const delayed_allocator: std.mem.Allocator = .{ .ptr = &delayed, .vtable = &DelayedAllocator.vtable };
        const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(9) };
        const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .{ .nanoseconds = Fake.timestamp.nanoseconds + std.time.ns_per_ms } };
        switch (mode) {
            0 => try std.testing.expectError(error.Timeout, runtime.Client.connect(delayed_allocator, io, address, .{ .connect_timeout = .fromMilliseconds(1) })),
            1 => try std.testing.expectError(error.Timeout, runtime.Client.connectWithDeadline(delayed_allocator, io, address, .{ .connect_timeout = null }, deadline)),
            2 => try std.testing.expectError(error.Timeout, runtime.Client.connectWithTimeout(delayed_allocator, io, address, .{ .connect_timeout = null }, .fromMilliseconds(1))),
            3 => try std.testing.expectError(error.Timeout, runtime.Client.connectHost(delayed_allocator, io, "127.0.0.1", 9, .{ .connect_timeout = .fromMilliseconds(1) })),
            4 => try std.testing.expectError(error.Timeout, runtime.Client.connectHostWithDeadline(delayed_allocator, io, "127.0.0.1", 9, .{ .connect_timeout = null }, deadline)),
            5 => try std.testing.expectError(error.Timeout, runtime.Client.connectHostWithTimeout(delayed_allocator, io, "127.0.0.1", 9, .{ .connect_timeout = null }, .fromMilliseconds(1))),
            6 => try std.testing.expectError(error.Timeout, runtime.Client.connectTlsHost(delayed_allocator, io, "127.0.0.1", 9, .{ .connect_timeout = .fromMilliseconds(1) }, .{})),
            7 => try std.testing.expectError(error.Timeout, runtime.Client.connectTlsHostWithDeadline(delayed_allocator, io, "127.0.0.1", 9, .{ .connect_timeout = null }, .{}, deadline)),
            8 => try std.testing.expectError(error.Timeout, runtime.Client.connectTlsHostWithTimeout(delayed_allocator, io, "127.0.0.1", 9, .{ .connect_timeout = null }, .{}, .fromMilliseconds(1))),
            else => unreachable,
        }
        try std.testing.expect(delayed.allocated != 0);
        try std.testing.expectEqual(delayed.allocated, delayed.freed);
        try std.testing.expectEqual(@as(usize, 0), Fake.network_calls.load(.monotonic));
    }
}

test "HTTP/2 TLS host closes ownership when the deadline expires after TCP connect" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const parent = threaded.io();
    var server = try runtime.Server.listen(allocator, parent, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *runtime.Server) !void {
            var connection = listener.acceptWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                error.ConnectionClosed, error.UnexpectedEof, error.SocketUnconnected, error.ConnectionResetByPeer => return,
                else => return err,
            };
            defer connection.close();
            return error.UnexpectedClientAdmission;
        }
    };
    var task = parent.async(Peer.run, .{&server});
    defer _ = task.cancel(parent) catch {};
    const Fake = struct {
        var base: std.Io = undefined;
        var expired: std.atomic.Value(bool) = .init(false);
        var after: std.Io.Timestamp = .zero;
        var timer: std.Io.Event = .unset;
        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            if (clock == .awake and expired.load(.acquire)) return after;
            return base.vtable.now(userdata, clock);
        }
        fn connect(userdata: ?*anyopaque, address: *const std.Io.net.IpAddress, options: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
            const socket = try base.vtable.netConnectIp(userdata, address, options);
            expired.store(true, .release);
            return socket;
        }
        fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            // Keep the connect race's timer pending until cancellation. The
            // completed socket must reach the TLS ownership boundary.
            try timer.wait(base);
        }
    };
    Fake.base = parent;
    Fake.expired.store(false, .monotonic);
    const deadline = std.Io.Clock.Timestamp.fromNow(parent, .{ .raw = .fromSeconds(2), .clock = .awake });
    Fake.after = deadline.raw.addDuration(.fromSeconds(1));
    var vtable = parent.vtable.*;
    vtable.now = Fake.now;
    vtable.netConnectIp = Fake.connect;
    vtable.sleep = Fake.sleep;
    const io: std.Io = .{ .userdata = parent.userdata, .vtable = &vtable };
    try std.testing.expectError(error.Timeout, runtime.Client.connectTlsHostWithDeadline(allocator, io, "127.0.0.1", server.address().getPort(), .{ .connect_timeout = null }, .{}, deadline));
    try std.testing.expect(Fake.expired.load(.acquire));
    try task.await(parent);
}

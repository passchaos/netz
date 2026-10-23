const std = @import("std");
const runtime = @import("../../runtime.zig");

pub const BlockedWrite = struct {
    delegate: std.Io,
    delay: std.Io.Duration = .fromMilliseconds(300),
    armed: std.atomic.Value(bool) = .init(false),
    entered: std.atomic.Value(bool) = .init(false),
    canceled: std.atomic.Value(bool) = .init(false),

    pub var active: ?*BlockedWrite = null;

    pub fn netWrite(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        if (self.armed.load(.acquire)) {
            self.entered.store(true, .release);
            std.Io.sleep(self.delegate, self.delay, .awake) catch |err| {
                if (err == error.Canceled) self.canceled.store(true, .release);
                return err;
            };
        }
        return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
    }
};

test "MQTT client PING deadline cancels a blocked request write" {
    for ([_]bool{ false, true }) |absolute| try blockedPing(absolute);
}

fn blockedPing(absolute: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = BlockedWrite{ .delegate = io };
    BlockedWrite.active = &observer;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            accepted.connection.readPingReq() catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                else => return err,
            };
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, observed_io, server.address(), .{ .client_id = "ping-write-deadline" });
    var open = true;
    defer if (open) client.close();
    observer.armed.store(true, .release);
    const result = if (absolute)
        client.pingWithDeadline(.fromNow(observed_io, .{ .raw = .fromMilliseconds(50), .clock = .awake }))
    else
        client.pingWithTimeout(.fromMilliseconds(50));
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expect(observer.entered.load(.acquire));
    try std.testing.expect(observer.canceled.load(.acquire));
    try std.testing.expect(!client.isUsable());
    client.close();
    open = false;
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

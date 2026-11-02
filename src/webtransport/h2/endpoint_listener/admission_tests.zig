const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const listener_mod = @import("../endpoint_listener.zig");
const allocator = std.testing.allocator;

test "WebTransport HTTP2 EndpointListener exits its accept worker after canceled owner admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const Probe = struct {
        base: std.Io,
        caller: std.Thread.Id,
        watching: std.atomic.Value(bool) = .init(true),
        armed: std.atomic.Value(bool) = .init(false),
        hits: std.atomic.Value(usize) = .init(0),
        canceled: std.Io.Event = .unset,
        var active: ?*@This() = null;
        fn allocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
        }
        fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            const bytes = std.testing.allocator.rawAlloc(len, alignment, ra);
            if (bytes != null and std.Thread.getCurrentId() != self.caller and self.watching.swap(false, .acq_rel)) {
                // Raw HTTP/2 acceptance uses the listener's own allocator.
                // The first background allocation here is its managed owner.
                self.armed.store(true, .release);
            }
            return bytes;
        }
        fn resize(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
            return std.testing.allocator.rawResize(bytes, alignment, len, ra);
        }
        fn remap(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
            return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
        }
        fn free(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
            std.testing.allocator.rawFree(bytes, alignment, ra);
        }
        fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
            const self = active.?;
            if (std.Thread.getCurrentId() != self.caller and self.armed.swap(false, .acq_rel)) {
                _ = self.hits.fetchAdd(1, .acq_rel);
                self.canceled.set(self.base);
                return error.Canceled;
            }
            return self.base.vtable.checkCancel(userdata);
        }
    };
    var probe = Probe{ .base = base, .caller = std.Thread.getCurrentId() };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.checkCancel = Probe.check;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const raw = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    var listener = try listener_mod.EndpointListener.initServer(probe.allocator(), raw, .{ .max_connections = 1, .accept_workers = 1 });
    defer listener.deinit();
    var connection = http2.runtime.Client.connectWithTimeout(allocator, base, listener.address(), .{}, .fromSeconds(1)) catch |err| switch (err) {
        error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected, error.UnexpectedEof => null,
        else => return err,
    };
    defer if (connection) |*value| value.close();
    try probe.canceled.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const Join = struct {
        group: *std.Io.Group,
        io: std.Io,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.group.await(self.io) catch |err| {
                self.err = err;
            };
            self.done.set(self.io);
        }
    };
    var join = Join{ .group = &listener.state.group, .io = base };
    var task = try base.concurrent(Join.run, .{&join});
    defer task.cancel(base);
    // Ignoring Canceled would leave the accept loop blocked on a new peer.
    try join.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    task.await(base);
    try std.testing.expect(join.err == null);
    try std.testing.expectEqual(@as(usize, 1), probe.hits.load(.acquire));
    listener.state.mutex.lockUncancelable(base);
    defer listener.state.mutex.unlock(base);
    try std.testing.expect(!listener.state.connections[0].reserved);
    try std.testing.expect(listener.state.connections[0].connection == null);
}

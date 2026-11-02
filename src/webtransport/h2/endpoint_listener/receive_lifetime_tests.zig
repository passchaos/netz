const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const listener_mod = @import("../endpoint_listener.zig");
const allocator = std.testing.allocator;

test "WebTransport HTTP2 EndpointListener receive keeps its deadline after a wake and contended reacquisition" {
    try exercise(false);
}

test "WebTransport HTTP2 EndpointListener close retains state until a waiting receiver exits" {
    try exercise(true);
}

fn exercise(closing: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const Probe = struct {
        base: std.Io,
        target: std.atomic.Value(?*const u32) = .init(null),
        parked: std.Io.Event = .unset,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (self.target.load(.acquire) == pointer) self.parked.set(self.base);
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
    };
    var probe = Probe{ .base = base };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const raw = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    var listener = try listener_mod.EndpointListener.initServer(allocator, raw, .{ .max_connections = 1, .accept_workers = 1 });
    var owned = true;
    defer if (owned) listener.deinit();
    probe.target.store(@ptrCast(&listener.state.request_ready), .release);
    const Caller = struct {
        listener: listener_mod.EndpointListener,
        io: std.Io,
        closing: bool,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var request = self.listener.receiveRequestWithTimeout(if (self.closing) .fromSeconds(5) else .fromMilliseconds(500)) catch |err| {
                self.err = err;
                self.done.set(self.io);
                return;
            };
            request.deinit();
            self.err = error.TestUnexpectedResult;
            self.done.set(self.io);
        }
    };
    var caller = Caller{ .listener = listener, .io = base, .closing = closing };
    var task = try base.concurrent(Caller.run, .{&caller});
    defer task.cancel(base);
    try probe.parked.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectEqual(@as(usize, 2), listener.state.refs.load(.acquire));
    if (closing) {
        listener.deinit();
        owned = false;
        try caller.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
        task.await(base);
        try std.testing.expectEqual(@as(?anyerror, error.ListenerClosed), caller.err);
    } else {
        listener.state.mutex.lockUncancelable(base);
        defer listener.state.mutex.unlock(base);
        // The receiver wakes, but must bound its second State acquisition by
        // the same deadline rather than parking on an uncancellable mutex.
        listener.state.request_ready.set(base);
        try caller.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
        task.await(base);
        try std.testing.expectEqual(@as(?anyerror, error.Timeout), caller.err);
        try std.testing.expectEqual(@as(usize, 1), listener.state.refs.load(.acquire));
        try std.testing.expect(!listener.state.mutex.tryLock());
    }
}

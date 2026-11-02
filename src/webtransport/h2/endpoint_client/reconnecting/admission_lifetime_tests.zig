const std = @import("std");
const reconnecting = @import("../reconnecting.zig");
const http2 = @import("../../../../http2/mod.zig");
const allocator = std.testing.allocator;

test "WebTransport HTTP2 reconnecting close waits for activity notification before destroying state" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const Connector = struct {
        fn connect(_: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            unreachable;
        }
    };
    var client = try reconnecting.ReconnectingEndpointClient.init(allocator, base, .{ .custom = .{ .context = null, .connect_fn = Connector.connect } }, .{});
    var live = true;
    defer if (live) client.deinit();
    const state = client.state;
    try state.enter(.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    var registered = true;
    defer if (registered) state.leave();

    const Probe = struct {
        base: std.Io,
        idle: *std.Io.Event,
        parked: std.Io.Event = .unset,
        notifying: std.Io.Event = .unset,
        permitted: std.Io.Event = .unset,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (pointer == @as(*const u32, @ptrCast(self.idle))) self.parked.set(self.base);
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
        fn wake(userdata: ?*anyopaque, pointer: *const u32, max_waiters: u32) void {
            const self = active.?;
            if (pointer == @as(*const u32, @ptrCast(self.idle))) {
                self.notifying.set(self.base);
                self.permitted.waitUncancelable(self.base);
            }
            self.base.vtable.futexWake(userdata, pointer, max_waiters);
        }
    };
    var probe = Probe{ .base = base, .idle = &state.idle };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWake = Probe.wake;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    const Closing = struct {
        client: *reconnecting.ReconnectingEndpointClient,
        io: std.Io,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            self.client.deinit();
            self.done.set(self.io);
        }
    };
    var closing = Closing{ .client = &client, .io = base };
    var close_task = try base.concurrent(Closing.run, .{&closing});
    live = false;
    defer {
        probe.permitted.set(base);
        if (registered) {
            state.leave();
            registered = false;
        }
        close_task.await(base);
    }
    try probe.parked.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const Leave = struct {
        fn run(value: @TypeOf(state)) void {
            value.leave();
        }
    };
    var leaving = try base.concurrent(Leave.run, .{state});
    registered = false;
    defer {
        probe.permitted.set(base);
        leaving.await(base);
    }
    try probe.notifying.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectEqual(@as(usize, 1), state.active.load(.acquire));
    try std.testing.expect(!closing.done.isSet());
    probe.permitted.set(base);
    leaving.await(base);
    try closing.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    close_task.await(base);
}

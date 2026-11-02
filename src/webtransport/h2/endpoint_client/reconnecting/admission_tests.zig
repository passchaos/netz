const std = @import("std");
const http2 = @import("../../../../http2/mod.zig");
const reconnecting = @import("../reconnecting.zig");
const allocator = std.testing.allocator;

const Operation = enum {
    connect,
    connect_attempt,
    datagram,
    receive,
    close,
    remove,
    open_stream,
    send_stream,
    consume,
    retire_stream,
    reset_stream,
    stop_sending,
    grant_data,
    grant_streams,
    grant_stream_data,
    drain,
    exporter,
};
const handle: reconnecting.Handle = .{ .connection_generation = 1, .session = .{ .index = 0, .generation = 1 } };

fn run(client: reconnecting.ReconnectingEndpointClient, operation: Operation, deadline: std.Io.Clock.Timestamp) !void {
    switch (operation) {
        .connect => _ = try client.connectWithDeadline(.{ .path = "/wt", .authority = "localhost" }, deadline),
        .connect_attempt => {
            var attempt = try client.connectAttemptWithDeadline(.{ .path = "/wt", .authority = "localhost" }, deadline);
            defer attempt.deinit();
        },
        .datagram => try client.sendDatagramWithDeadline(handle, "blocked", deadline),
        .receive => {
            var event = try client.receiveWithDeadline(handle, deadline);
            defer event.deinit();
        },
        .close => try client.closeWithDeadline(handle, 0, "closed", deadline),
        .remove => _ = try client.removeWithDeadline(handle, deadline),
        .open_stream => _ = try client.openStreamWithDeadline(handle, .bidirectional, deadline),
        .send_stream => try client.sendStreamWithDeadline(handle, 0, "blocked", true, deadline),
        .consume => try client.consumeWithDeadline(handle, 0, 1, deadline),
        .retire_stream => try client.retireStreamWithDeadline(handle, 0, deadline),
        .reset_stream => try client.resetStreamWithDeadline(handle, 0, 0, deadline),
        .stop_sending => try client.stopSendingWithDeadline(handle, 0, 0, deadline),
        .grant_data => try client.grantDataWithDeadline(handle, 4096, deadline),
        .grant_streams => try client.grantStreamsWithDeadline(handle, .bidirectional, 4, deadline),
        .grant_stream_data => try client.grantStreamDataWithDeadline(handle, 0, 4096, deadline),
        .drain => try client.drainWithDeadline(handle, deadline),
        .exporter => {
            var material = try client.exportKeyingMaterialWithDeadline(handle, "probe", "", 32, deadline);
            defer material.deinit();
        },
    }
}

const Connector = struct {
    calls: usize = 0,
    fn connect(context: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        return error.ConnectionRefused;
    }
};

const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex,
    canceled: bool,
    unbounded: usize = 0,
    waits: usize = 0,
    var active: ?*Probe = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (pointer == @as(*const u32, @ptrCast(&self.mutex.state.raw))) {
            self.waits += 1;
            if (self.canceled) return error.Canceled;
        }
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (pointer == @as(*const u32, @ptrCast(&self.mutex.state.raw))) {
            // Release on a regression instead of hanging the test process.
            self.unbounded += 1;
            self.mutex.state.store(.unlocked, .release);
            return;
        }
        self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }
};

test "WebTransport HTTP2 reconnecting state admission bounds every public deadline and cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |canceled| {
        var connector: Connector = .{};
        var client = try reconnecting.ReconnectingEndpointClient.init(allocator, base, .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, .{});
        defer client.deinit();
        var probe = Probe{ .base = base, .mutex = &client.state.mutex, .canceled = canceled };
        Probe.active = &probe;
        defer Probe.active = null;
        var table = base.vtable.*;
        table.futexWait = Probe.wait;
        table.futexWaitUncancelable = Probe.waitUncancelable;
        client.state.io = .{ .userdata = base.userdata, .vtable = &table };
        client.state.mutex.lockUncancelable(base);
        defer client.state.mutex.unlock(base);
        for (std.enums.values(Operation)) |operation| {
            const deadline: std.Io.Clock.Timestamp = .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(2) });
            try std.testing.expectError(if (canceled) error.Canceled else error.Timeout, run(client, operation, deadline));
            try std.testing.expectEqual(@as(usize, 0), client.state.active.load(.acquire));
            try std.testing.expect(client.state.current == null);
            try std.testing.expect(!client.state.connecting);
            try std.testing.expectEqual(@as(u64, 1), client.state.next_generation);
        }
        try std.testing.expectEqual(@as(usize, 0), connector.calls);
        try std.testing.expectEqual(@as(usize, 0), probe.unbounded);
        try std.testing.expect(probe.waits != 0);
        try std.testing.expect(!client.state.mutex.tryLock());
        const waits = probe.waits;
        for (std.enums.values(Operation)) |operation| {
            try std.testing.expectError(error.Timeout, run(client, operation, .fromNow(base, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
            try std.testing.expectError(error.Timeout, run(client, operation, .{ .clock = .real, .raw = .{ .nanoseconds = 0 } }));
            try std.testing.expectEqual(@as(usize, 0), client.state.active.load(.acquire));
        }
        try std.testing.expectEqual(waits, probe.waits);
        try std.testing.expectEqual(@as(usize, 0), connector.calls);
    }
}

test "WebTransport HTTP2 reconnecting state lookups keep deadlines and release activity without relocking" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var connector: Connector = .{};
    var client = try reconnecting.ReconnectingEndpointClient.init(allocator, base, .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, .{});
    defer client.deinit();
    try client.state.enter(.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    var probe = Probe{ .base = base, .mutex = &client.state.mutex, .canceled = false };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    client.state.io = .{ .userdata = base.userdata, .vtable = &table };
    client.state.mutex.lockUncancelable(base);
    defer client.state.mutex.unlock(base);
    try std.testing.expectError(error.Timeout, client.state.acquireCurrent(.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(2) })));
    try std.testing.expectError(error.Timeout, client.state.acquireHandle(1, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(2) })));
    client.state.leave();
    try std.testing.expectEqual(@as(usize, 0), client.state.active.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), probe.unbounded);
    try std.testing.expectEqual(@as(usize, 0), connector.calls);
    try std.testing.expect(!client.state.mutex.tryLock());
}

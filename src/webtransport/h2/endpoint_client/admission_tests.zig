const std = @import("std");
const endpoint = @import("../endpoint_client.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const queue = @import("queue.zig");
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
const handle: endpoint.Handle = .{ .index = 0, .generation = 1 };

fn run(client: endpoint.EndpointClient, operation: Operation, deadline: std.Io.Clock.Timestamp) !void {
    switch (operation) {
        .connect => _ = try client.connectWithDeadline(.{ .path = "/wt", .authority = "localhost", .protocols = .{ .values = &.{"probe"} } }, deadline),
        .connect_attempt => {
            var attempt = try client.connectAttemptWithDeadline(.{ .path = "/wt", .authority = "localhost", .headers = &.{.{ .name = "x-probe", .value = "owned" }} }, deadline);
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
            var material = try client.exportKeyingMaterialWithDeadline(handle, "probe", "context", 32, deadline);
            defer material.deinit();
        },
    }
}

const Probe = struct {
    base: std.Io,
    mutex: *std.Io.Mutex,
    owner: std.Thread.Id,
    canceled: bool = false,
    fast_cancel: bool = false,
    unbounded: usize = 0,
    waits: usize = 0,
    held: bool = true,
    var active: ?*Probe = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (std.Thread.getCurrentId() == self.owner and pointer == @as(*const u32, @ptrCast(&self.mutex.state.raw))) {
            self.waits += 1;
            if (self.canceled) return error.Canceled;
        }
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = active.?;
        if (std.Thread.getCurrentId() == self.owner and self.fast_cancel and self.mutex.state.load(.acquire) != .unlocked) return error.Canceled;
        return self.base.vtable.checkCancel(userdata);
    }
    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (std.Thread.getCurrentId() == self.owner and pointer == @as(*const u32, @ptrCast(&self.mutex.state.raw))) {
            // A regression should fail instead of hanging the test process.
            self.unbounded += 1;
            self.mutex.state.store(.unlocked, .release);
            self.held = false;
            return;
        }
        self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }
};

test "WebTransport HTTP2 EndpointClient queue admission keeps all operation deadlines and ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    for ([_]bool{ false, true }) |canceled| {
        var fixture = try Fixture.init(base);
        defer {
            fixture.peer.close(base);
            fixture.listener.deinit(base);
        }
        var client = try endpoint.EndpointClient.init(allocator, fixture.connection, .{});
        var probe = Probe{ .base = base, .mutex = &client.state.mutex, .owner = std.Thread.getCurrentId(), .canceled = canceled };
        Probe.active = &probe;
        defer {
            client.deinit();
            Probe.active = null;
        }
        var table = base.vtable.*;
        table.futexWait = Probe.wait;
        table.futexWaitUncancelable = Probe.waitUncancelable;
        client.state.mutex.lockUncancelable(base);
        client.state.io = .{ .userdata = base.userdata, .vtable = &table };
        defer {
            client.state.io = base;
            if (probe.held) client.state.mutex.unlock(base);
        }
        const refs = client.state.refs.load(.acquire);
        for (std.enums.values(Operation)) |operation| {
            try std.testing.expectError(if (canceled) error.Canceled else error.Timeout, run(client, operation, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(2) })));
            try std.testing.expectEqual(refs, client.state.refs.load(.acquire));
            try std.testing.expectEqual(@as(usize, 0), client.state.queued);
            try std.testing.expect(client.state.head == null and client.state.tail == null);
            try std.testing.expectEqual(@as(usize, 0), client.state.active_sessions);
            try std.testing.expectEqual(@as(u31, 1), client.state.connection.next_client_stream_id);
        }
        const waits = probe.waits;
        for (std.enums.values(Operation)) |operation| {
            try std.testing.expectError(error.Timeout, run(client, operation, .fromNow(base, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
            try std.testing.expectError(error.Timeout, run(client, operation, .{ .clock = .real, .raw = .{ .nanoseconds = 0 } }));
        }
        try std.testing.expectEqual(waits, probe.waits);
        try std.testing.expectEqual(@as(usize, 0), probe.unbounded);
        try std.testing.expect(!client.state.mutex.tryLock());
    }
}

test "WebTransport HTTP2 EndpointClient queue cancellation and capacity rejection preserve job ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var fixture = try Fixture.init(base);
    defer {
        fixture.peer.close(base);
        fixture.listener.deinit(base);
    }
    var client = try endpoint.EndpointClient.init(allocator, fixture.connection, .{});
    defer client.deinit();
    var probe = Probe{ .base = base, .mutex = &client.state.mutex, .owner = std.Thread.getCurrentId(), .fast_cancel = true };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.checkCancel = Probe.check;
    // The worker keeps its own base I/O. Only the admission seam is replaced.
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const State = @TypeOf(client.state.*);
    const job = try State.Job.create(client.state, .{ .send_datagram = .{ .handle = handle, .data = "owned" } }, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer job.release();
    const refs = client.state.refs.load(.acquire);
    const Harness = struct {
        mutex: std.Io.Mutex = .init,
        io: std.Io,
        closed: bool = false,
        abortive_shutdown: std.atomic.Value(bool) = .init(false),
        failure: ?anyerror = null,
        options: endpoint.Options = .{},
        head: ?*State.Job = null,
        tail: ?*State.Job = null,
        queued: usize = 0,
        wake: std.Io.Event = .unset,
    };
    var state = Harness{ .io = io };
    probe.mutex = &state.mutex;
    // Exercise the pre-commit cancellation seam with a separate queue mutex
    // while the Job still owns its real endpoint parent reference.
    try std.testing.expectError(error.Canceled, queue.enqueue(&state, job));
    try std.testing.expectEqual(@as(usize, 1), job.refs.load(.acquire));
    try std.testing.expectEqual(refs, client.state.refs.load(.acquire));
    try std.testing.expect(state.head == null and state.tail == null and state.queued == 0);
    probe.fast_cancel = false;
    state.options.max_queued_commands = 1;
    state.queued = 1;
    state.head = job;
    state.tail = job;
    try std.testing.expectError(error.EndpointQueueFull, queue.enqueue(&state, job));
    try std.testing.expect(state.head == job and state.tail == job and state.queued == 1);
    try std.testing.expectEqual(@as(usize, 1), job.refs.load(.acquire));
    try std.testing.expect(job.next == null);
}

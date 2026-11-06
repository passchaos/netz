//! Physical hedge ownership, cancellation before admission, and RPC deadlines.
const std = @import("std");
const grpc = @import("../../../mod.zig");
const http2 = @import("../../../../http2/mod.zig");
const shared = @import("../../shared.zig");
const State = @import("../state.zig").State;
const Job = @import("../job.zig").Job;
const Control = @import("control.zig").Control;
const fault = @import("../../../fault.zig");
const allocator = std.testing.allocator;

fn waitEvent(event: *std.Io.Event, io: std.Io, deadline: std.Io.Clock.Timestamp) std.Io.Event.WaitTimeoutError!void {
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| {
            if (err == error.Timeout and deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        return;
    }
}

fn stoppedSender(io: std.Io) !shared.Sender {
    var channel = try shared.SharedChannel.init(allocator, io, .{
        .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } },
    }, .{});
    const sender = channel.sender();
    channel.deinit();
    // All endpoint owners have joined. Only synthetic queue/attempt admission
    // runs against the retained state; no backend can race these tests.
    sender.state.closed = false;
    return sender;
}

test "gRPC hedging lifecycle physical Job retains Control after caller retirement" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try stoppedSender(io);
    defer {
        sender.state.close();
        sender.deinit();
    }
    const state = sender.state;
    const references = state.refs.load(.acquire);
    const control = try Control.create(allocator, io, .{ .max_attempts = 2 });
    var root_owned = true;
    defer if (root_owned) control.release();
    const job = try Job.create(state, .{ .path = "/demo.Hedge/Unary", .message = "retained" }, null, null, 1);
    var caller_owned = true;
    defer if (caller_owned) job.release();
    job.setHedgingControl(control);
    job.retain(); // The physical endpoint remains responsible for retirement.
    var endpoint_owned = true;
    defer if (endpoint_owned) job.release();
    control.release();
    root_owned = false;
    try std.testing.expect(job.abandon());
    job.release();
    caller_owned = false;

    try std.testing.expectEqual(@as(usize, 1), control.refs.load(.acquire));
    try std.testing.expectEqualStrings("retained", job.options.message);
    state.commitHedge(control, 0);
    try std.testing.expect(control.committed.isSet());
    try std.testing.expect(job.canceled());
    // Completing the abandoned physical job destroys its inputs and its last
    // Control reference, even though the original caller cannot take a result.
    state.finish(job, null, error.Canceled);
    endpoint_owned = false;
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

test "gRPC hedging lifecycle commitment cancels queued losers before backend admission" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try stoppedSender(io);
    defer {
        sender.state.close();
        sender.deinit();
    }
    const state = sender.state;
    const control = try Control.create(allocator, io, .{ .max_attempts = 3 });
    defer control.release();
    var jobs: [4]*Job = undefined;
    var created: usize = 0;
    defer for (jobs[0..created]) |job| job.release();
    // The loser at each end exercises removal of both the queue head and tail.
    const indices = [_]?u8{ null, null, 1, 2 };
    for (&jobs, indices, 0..) |*slot, index, ordinal| {
        slot.* = try Job.create(state, .{ .path = "/demo.Hedge/Unary", .message = "request", .wait_for_ready = true }, null, null, index);
        created += 1;
        if (ordinal != 1) slot.*.setHedgingControl(control);
        try state.enqueue(slot.*);
    }
    try std.testing.expectEqual(@as(usize, 4), state.queued);
    state.commitHedge(control, 1);
    try std.testing.expectEqual(@as(usize, 2), state.queued);
    try std.testing.expect(state.head == jobs[1] and state.tail == jobs[2]);
    try std.testing.expect(jobs[1].next == jobs[2] and jobs[2].next == null);
    for ([_]usize{ 0, 3 }) |index| {
        try std.testing.expectError(error.Canceled, state.awaitJob(jobs[index]));
        try std.testing.expect(jobs[index].done.isSet());
        try std.testing.expect(jobs[index].selected_worker == null);
        try std.testing.expect(jobs[index].owner_wake.load(.acquire) == null);
    }
    try std.testing.expect(!jobs[1].done.isSet() and !jobs[2].done.isSet());
    const late = try Job.create(state, .{ .path = "/demo.Hedge/Unary", .message = "late", .wait_for_ready = true }, null, null, 2);
    defer late.release();
    late.setHedgingControl(control);
    try std.testing.expectError(error.Canceled, state.enqueue(late));
    try std.testing.expectEqual(@as(usize, 2), state.queued);
    state.close();
    try std.testing.expectError(error.SharedChannelClosed, state.awaitJob(jobs[1]));
    try std.testing.expectError(error.SharedChannelClosed, state.awaitJob(jobs[2]));
}

test "gRPC hedging lifecycle commitment interrupts pending fault delay and releases its slot" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var sender = try stoppedSender(base);
    defer {
        sender.state.close();
        sender.deinit();
    }
    const state = sender.state;
    var policy = fault.Policy{
        .delay = .{ .fixed = .fromSeconds(30), .percentage = .{ .numerator = 100, .denominator = 100 } },
        .max_active_faults = 1,
    };
    const control = try Control.create(allocator, base, .{ .max_attempts = 2 });
    defer control.release();
    const Probe = struct {
        base: std.Io,
        commitment: *std.Io.Event,
        entered: std.Io.Event = .unset,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            const target: *const u32 = @ptrCast(self.commitment);
            if (pointer == target) self.entered.set(self.base);
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
    };
    var probe = Probe{ .base = base, .commitment = &control.committed };
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    defer {
        state.io = base;
        Probe.active = null;
    }
    const Attempt = struct {
        fn run(owner: *State, shared_control: *Control, fault_policy: *fault.Policy, done: *std.Io.Event) !void {
            defer done.set(owner.io);
            try std.testing.expectError(error.Canceled, owner.attemptHedged(.{
                .path = "/demo.Hedge/Unary",
                .message = "delayed",
                .fault_policy = fault_policy,
            }, .fromNow(owner.io, .{ .clock = .awake, .raw = .fromSeconds(60) }), null, 1, shared_control));
        }
    };
    var completed: std.Io.Event = .unset;
    var attempt = try base.concurrent(Attempt.run, .{ state, control, &policy, &completed });
    defer _ = attempt.cancel(base) catch {};
    try waitEvent(&probe.entered, base, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expectEqual(@as(u32, 1), policy.active.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.queued);
    state.commitHedge(control, 0);
    try waitEvent(&completed, base, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try attempt.await(base);
    try std.testing.expectEqual(@as(u32, 0), policy.active.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.queued);
    try std.testing.expect(!state.demand);
    var random = std.Random.DefaultPrng.init(7);
    var next = try policy.evaluateWith(allocator, .{ .path = "/demo.Hedge/Unary", .authority = "" }, null, random.random());
    defer next.release(&policy);
    try std.testing.expect(next.delay != null and next.counted);
}

const HeldBodyPeer = struct {
    server: *http2.runtime.Server,
    requests: usize = 0,

    fn run(self: *HeldBodyPeer) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(5));
        defer connection.close();
        var request = try connection.readRequestWithTimeout(.fromSeconds(5));
        defer request.deinit(allocator);
        self.requests += 1;
        var parsed = try grpc.parseUnaryRequest(allocator, &request, 4096);
        defer parsed.deinit();
        try std.testing.expectEqualStrings("request", parsed.message.payload);
        try std.testing.expect(grpc.call.headerValue(request.headers, "grpc-timeout") != null);
        try std.testing.expect(grpc.call.headerValue(request.headers, "grpc-previous-rpc-attempts") == null);
        // Ordinary response HEADERS commit the attempt, but no DATA, terminal
        // status, or END_STREAM can finish it while its body remains held.
        var writer = try connection.startResponseWithTimeout(request.stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "content-type", .value = "application/grpc" }},
        }, .fromSeconds(5));
        defer writer.deinit();
        var reset = try connection.readResetStreamWithTimeout(.fromSeconds(5));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
        try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
        writer.finished = true; // The client already reset this response.
    }
};

fn deadlineAttempt(state: *State, control: *Control, deadline: std.Io.Clock.Timestamp, done: *std.Io.Event) !void {
    defer done.set(state.io);
    const timeout_header = try grpc.Timeout.fromDuration(deadline.durationFromNow(state.io).raw);
    var response = try state.attemptHedged(.{
        .path = "/demo.Hedge/Unary",
        .authority = "localhost",
        .message = "request",
        .wait_for_ready = true,
        .transparent_retry = false,
    }, deadline, timeout_header, 0, control);
    defer response.deinit();
    return error.ExpectedDeadlineTimeout;
}

test "gRPC hedging lifecycle ordinary response HEADERS preserve the original RPC deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var peer = HeldBodyPeer{ .server = &server };
    var peer_task = try io.concurrent(HeldBodyPeer.run, .{&peer});
    errdefer _ = peer_task.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{
        .cleartext_ip = .{ .address = server.address() },
    }, .{ .operation_timeout = .fromSeconds(10), .keepalive = null });
    defer client.deinit();
    // Start the RPC deadline after connection readiness, so connection setup
    // cannot satisfy this held-body deadline regression.
    var watch = client.watchConnectivity();
    defer watch.deinit();
    const ready_until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    try client.connectWithDeadline(ready_until);
    try watch.waitForReadyWithDeadline(ready_until);
    const control = try Control.create(allocator, io, .{
        .max_attempts = 2,
        .hedging_delay = .fromSeconds(10),
        .non_fatal_status_codes = &.{.unavailable},
    });
    defer control.release();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    const guard = deadline.addDuration(.{ .clock = .awake, .raw = .fromSeconds(4) });
    var completed: std.Io.Event = .unset;
    var attempt = try io.concurrent(deadlineAttempt, .{ client.state, control, deadline, &completed });
    errdefer _ = attempt.cancel(io) catch {};
    // The worker must have processed HEADERS and committed the still pending
    // attempt before its deadline; a server-side write alone cannot prove it.
    try waitEvent(&control.committed, io, deadline);
    try std.testing.expectEqual(@as(?u8, 0), control.winner());
    try std.testing.expect(deadline.durationFromNow(io).raw.nanoseconds > 0);
    try std.testing.expect(!completed.isSet());
    try waitEvent(&completed, io, guard);
    try std.testing.expectError(error.Timeout, attempt.await(io));
    try std.testing.expect(deadline.durationFromNow(io).raw.nanoseconds <= 0);
    // Observe the RPC's natural wire cancellation before teardown or any
    // failure-only Future.cancel call could generate a reset.
    try peer_task.await(io);
    try std.testing.expectEqual(@as(usize, 1), peer.requests);
}

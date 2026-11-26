//! Actual Future cancellation, native timers and protected response packets.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const Pair = @import("test_support/completion_pair.zig").Pair;
const observed_io = @import("../../../internal/testing/borrowed_command_io.zig");
const native_io = @import("../../../internal/testing/native_protocol_io.zig");
const Engine = runtime.HandshakeConcurrentEngine;
const Probe = observed_io.Probe(Engine);
const Outcome = observed_io.Outcome;
const allocator = std.testing.allocator;

pub fn exercise(io: std.Io, outcome: Outcome) !void {
    var pair: Pair = undefined;
    try pair.init(io);
    defer pair.deinit();
    var engine = Engine.init(&pair.server, allocator, io, .{});
    defer engine.deinit();
    // A failing legacy implementation can release its caller's stack early.
    // Discard that pointer without dereferencing it during fixture cleanup.
    defer engine.commands.clearRetainingCapacity();
    engine.summary.last_stream_id = pair.stream_id;
    const timed = outcome == .timed_out_before_execution or outcome == .expired_before_execution;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = if (timed) .fromMilliseconds(250) else .fromSeconds(5) });
    var probe: Probe = .{ .delegate = io, .engine = &engine, .outcome = outcome, .deadline = deadline };
    const observed = probe.io();
    engine.io = observed;
    engine.options.shutdown = &probe.shutdown;
    pair.endpoint.io = observed;
    defer pair.endpoint.io = io;
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{
        .engine = &engine,
        .stream = undefined,
        .from = pair.client.address(),
        .stream_id = pair.stream_id,
        // The fixture owns this head until both Futures have joined.
        .head = pair.head,
        .request_finished = pair.head.request_finished,
        .body_finished = pair.head.request_finished,
    };
    slot.stream = .{ .engine = &engine, .slot = &slot };
    var owner = try io.concurrent(Probe.own, .{&probe});
    defer _ = owner.cancel(io) catch {};
    const Caller = struct {
        fn run(stream: *Engine.Stream, until: std.Io.Clock.Timestamp, execution_io: std.Io, check_cancel: bool) !void {
            try stream.startResponseWithBodyWithDeadline(.{ .status = 200 }, 9, "committed", true, until);
            if (check_cancel) try std.testing.expectError(error.Canceled, execution_io.checkCancel());
        }
    };
    const completed = outcome == .completed_during_cancel;
    var caller = try io.concurrent(Caller.run, .{ &slot.stream, deadline, io, completed });
    defer _ = caller.cancel(io) catch {};
    try probe.waiting.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    const result = if (timed) caller.await(io) else caller.cancel(io);
    try owner.await(io);
    try std.testing.expect(engine.commands.isEmpty());
    try std.testing.expectEqual(completed, slot.response_started and slot.response_finished);
    if (!timed) try std.testing.expect(probe.canceled_waits.load(.acquire) != 0);
    if (outcome == .canceled_before_execution or outcome == .timed_out_before_execution) {
        try std.testing.expectEqual(@as(usize, 1), probe.joins.load(.acquire));
    }
    if (completed) {
        // Verify actual protected response output before reporting a failed
        // cancellation assertion in the caller's result.
        var response = try pair.client.receiveResponseWithTimeout(pair.stream_id, .fromSeconds(1));
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        try std.testing.expectEqualStrings("committed", response.response.body);
        try result;
    } else {
        try std.testing.expectError(if (timed) error.Timeout else error.Canceled, result);
        try std.testing.expectError(error.Timeout, pair.client.receiveResponseWithTimeout(pair.stream_id, .fromMilliseconds(5)));
    }
}

pub fn timeoutSkipped(io: std.Io) !void {
    try exercise(io, .timed_out_before_execution);
}
pub fn canceledSkipped(io: std.Io) !void {
    try exercise(io, .canceled_before_execution);
}
pub fn canceledCompleted(io: std.Io) !void {
    try exercise(io, .completed_during_cancel);
}

test "HTTP/3 concurrent command owner rejects native expired queued response" {
    try native_io.run(struct {
        fn run(io: std.Io) !void {
            try exercise(io, .expired_before_execution);
        }
    }.run);
}

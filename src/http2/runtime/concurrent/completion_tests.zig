//! Actual Future cancellation and timers at a borrowed command's wait boundary.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const Fixture = @import("../duplex/testing.zig").Fixture;
const FrameReader = @import("../frame/io.zig").Reader;
const observed_io = @import("../../../internal/testing/borrowed_command_io.zig");
const native_io = @import("../../../internal/testing/native_protocol_io.zig");
const Engine = runtime.Http2ConcurrentEngine;
const allocator = std.testing.allocator;
const Outcome = observed_io.Outcome;
const Probe = observed_io.Probe(Engine);

fn exercise(io: std.Io, outcome: Outcome) !void {
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    fixture.connection.role = .server;
    try runtime.testing.addActivePeerStream(&fixture.connection, 1);
    var engine = Engine.init(&fixture.connection, allocator, io, .{});
    defer engine.deinit();
    // A legacy failure may leave a pointer to the returned caller's stack.
    // Never dereference that pointer during fixture cleanup.
    defer engine.commands.clearRetainingCapacity();
    engine.summary.last_stream_id = 1;
    const until = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = if (outcome == .expired_before_execution) .fromMilliseconds(250) else .fromSeconds(5),
    });
    var probe: Probe = .{ .delegate = io, .engine = &engine, .outcome = outcome, .deadline = until };
    const observed = probe.io();
    engine.io = observed;
    engine.options.shutdown = &probe.shutdown;
    fixture.connection.io = observed;
    defer fixture.connection.io = io;
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{
        .engine = &engine,
        .stream = .{
            .connection = &fixture.connection,
            .stream_id = 1,
            .headers = &.{},
            .method = "GET",
            .path = "/completion",
            .scheme = "http",
            .authority = "localhost",
            .protocol = null,
            .priority = .{},
            .expected_request_length = null,
            .request_finished = true,
        },
        .public_stream = undefined,
    };
    slot.public_stream = .{ .engine = &engine, .slot = &slot };
    defer slot.stream.deinit();
    var owner = try io.concurrent(Probe.own, .{&probe});
    defer _ = owner.cancel(io) catch {};
    const Caller = struct {
        fn run(stream: *Engine.Stream, deadline: std.Io.Clock.Timestamp, execution_io: std.Io, check_cancel: bool) !void {
            try stream.startResponseWithBodyWithDeadline(.{ .status = 200 }, "committed", true, deadline);
            if (check_cancel) try std.testing.expectError(error.Canceled, execution_io.checkCancel());
        }
    };
    var caller = try io.concurrent(Caller.run, .{ &slot.public_stream, until, io, outcome == .completed_during_cancel });
    defer _ = caller.cancel(io) catch {};
    try probe.waiting.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    if (outcome == .expired_before_execution) {
        try std.testing.expectError(error.Timeout, caller.await(io));
    } else {
        const result = caller.cancel(io);
        if (outcome == .completed_during_cancel) try result else try std.testing.expectError(error.Canceled, result);
        try std.testing.expect(probe.canceled_waits.load(.acquire) != 0);
        if (outcome == .canceled_before_execution) try std.testing.expectEqual(@as(usize, 1), probe.joins.load(.acquire));
    }
    try owner.await(io);
    try std.testing.expect(engine.commands.isEmpty());
    try std.testing.expectEqual(outcome == .completed_during_cancel, slot.response_finished);
    // Retire the unfinished protocol stream while terminal output is still
    // available. Closing the TCP send half first would make deinit attempt
    // its RST_STREAM on a deliberately disconnected socket.
    const cleanup_reset = outcome != .completed_during_cancel;
    if (cleanup_reset) try slot.stream.resetWithTimeout(.cancel, .fromSeconds(1));
    try fixture.connection.stream.shutdown(io, .send);
    var reader: FrameReader = .{};
    defer reader.deinit(allocator);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    var heads: usize = 0;
    var fins: usize = 0;
    var resets: usize = 0;
    while (true) {
        const frame = reader.read(allocator, io, fixture.peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        switch (frame.frame.header.frame_type) {
            .headers => heads += 1,
            .data => {
                try payload.appendSlice(allocator, frame.frame.payload);
                if (frame.frame.header.flags & 1 != 0) fins += 1;
            },
            .goaway => {},
            .rst_stream => resets += 1,
            else => return error.UnexpectedFrame,
        }
    }
    try std.testing.expectEqualStrings(if (outcome == .completed_during_cancel) "committed" else "", payload.items);
    try std.testing.expectEqual(@as(usize, @intFromBool(outcome == .completed_during_cancel)), heads);
    try std.testing.expectEqual(heads, fins);
    try std.testing.expectEqual(@as(usize, @intFromBool(cleanup_reset)), resets);
}

test "HTTP/2 concurrent command cancellation joins borrowed stack before return" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try exercise(io, .canceled_before_execution);
        }
    }.run);
}
test "HTTP/2 concurrent command cancellation reports actual committed response" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try exercise(io, .completed_during_cancel);
        }
    }.run);
}
test "HTTP/2 concurrent command owner rejects expired queued response before sending" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try exercise(io, .expired_before_execution);
        }
    }.run);
}

fn directOutput(io: std.Io) !void {
    const Operation = enum { buffered_response, duplex_reset, connection_reset };
    for ([_]Operation{ .buffered_response, .duplex_reset, .connection_reset }) |operation| {
        var fixture = try Fixture.init(io);
        defer fixture.deinit();
        fixture.connection.role = .server;
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        var stream: runtime.ServerDuplexStream = .{
            .connection = &fixture.connection,
            .stream_id = 1,
            .headers = &.{},
            .method = "GET",
            .path = "/direct",
            .scheme = "http",
            .authority = "localhost",
            .protocol = null,
            .priority = .{},
            .expected_request_length = null,
            .request_finished = true,
        };
        defer if (operation != .connection_reset) stream.deinit();
        const Invoke = struct {
            fn run(s: *runtime.ServerDuplexStream, kind: Operation, duration: std.Io.Duration) !void {
                return switch (kind) {
                    .buffered_response => s.startResponseWithBodyWithTimeout(.{ .status = 200 }, "body", duration),
                    .duplex_reset => s.resetWithTimeout(.cancel, duration),
                    .connection_reset => s.connection.terminateOwnedStreamWithTimeout(1, .cancel, duration),
                };
            }
        };
        try std.testing.expectError(error.Timeout, Invoke.run(&stream, operation, .zero));
        try std.testing.expect(!stream.response_started and !stream.released);
        try std.testing.expect(fixture.connection.active_peer_index.contains(1));
        try Invoke.run(&stream, operation, .fromSeconds(1));
        try std.testing.expect(!fixture.connection.active_peer_index.contains(1));
        if (operation != .connection_reset) try std.testing.expect(stream.response_finished and stream.released);
        try fixture.connection.stream.shutdown(io, .send);
        var reader: FrameReader = .{};
        defer reader.deinit(allocator);
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        var heads: usize = 0;
        var resets: usize = 0;
        var fins: usize = 0;
        while (true) {
            const frame = reader.read(allocator, io, fixture.peer, 16_384) catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
            switch (frame.frame.header.frame_type) {
                .headers => heads += 1,
                .data => {
                    try payload.appendSlice(allocator, frame.frame.payload);
                    fins += @intFromBool(frame.frame.header.flags & 1 != 0);
                },
                .rst_stream => resets += 1,
                else => return error.UnexpectedFrame,
            }
        }
        const complete = operation == .buffered_response;
        try std.testing.expectEqualStrings(if (complete) "body" else "", payload.items);
        try std.testing.expectEqual(@as(usize, @intFromBool(complete)), heads);
        try std.testing.expectEqual(heads, fins);
        try std.testing.expectEqual(@as(usize, @intFromBool(!complete)), resets);
    }
}

test "HTTP/2 concurrent output counterparts retain timeout admission and terminal ownership" {
    try native_io.runStream(directOutput);
}

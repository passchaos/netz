//! Actual Future cancellation and timers at a borrowed command's wait boundary.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const Fixture = @import("../duplex/testing.zig").Fixture;
const FrameReader = @import("../frame/io.zig").Reader;
const forwarded = @import("../../../internal/testing/forwarded_io.zig");
const native_io = @import("../../../internal/testing/native_protocol_io.zig");
const Engine = runtime.Http2ConcurrentEngine;
const allocator = std.testing.allocator;
const Outcome = enum { canceled_before_execution, completed_during_cancel, expired_before_execution };

const Probe = struct {
    delegate: std.Io,
    table: std.Io.VTable = undefined,
    engine: *Engine,
    outcome: Outcome,
    deadline: std.Io.Clock.Timestamp,
    waiting: std.Io.Event = .unset,
    owner_begin: std.Io.Event = .unset,
    owner_done: std.Io.Event = .unset,
    shutdown: std.Io.Event = .unset,
    joins: std.atomic.Value(usize) = .init(0),
    canceled_waits: std.atomic.Value(usize) = .init(0),
    command_done: std.atomic.Value(?*const u32) = .init(null),

    fn from(context: ?*anyopaque) *Probe {
        return @ptrCast(@alignCast(context.?));
    }
    fn base(self: *Probe) std.Io {
        return self.delegate;
    }
    fn timeout(_: *Probe, value: std.Io.Timeout) std.Io.Timeout {
        return value;
    }
    fn io(self: *Probe) std.Io {
        self.table = forwarded.table(from, base, timeout);
        self.table.futexWait = wait;
        self.table.futexWaitUncancelable = join;
        return .{ .userdata = self, .vtable = &self.table };
    }
    fn isCommand(self: *Probe, pointer: *const u32) bool {
        if (self.command_done.load(.acquire)) |done| return pointer == done;
        // Owner dispatch is gated until this first command wait is entered.
        // Capture its identity once; later callbacks never scan a live queue
        // or acquire an owner mutex recursively from a futex callback.
        for (self.engine.commands.slice()) |command| {
            if (pointer == @as(*const u32, @ptrCast(&command.done))) {
                self.command_done.store(pointer, .release);
                return true;
            }
        }
        return false;
    }
    fn wait(context: ?*anyopaque, pointer: *const u32, expected: u32, until: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(context);
        const io_base = self.delegate;
        if (!self.isCommand(pointer)) return io_base.vtable.futexWait(io_base.userdata, pointer, expected, until);
        self.waiting.set(io_base);
        io_base.vtable.futexWait(io_base.userdata, pointer, expected, until) catch |err| {
            if (err == error.Canceled) {
                _ = self.canceled_waits.fetchAdd(1, .monotonic);
                if (self.outcome == .completed_during_cancel) {
                    // A separate, uncanceled owner commits real TCP output
                    // before this actual canceled wait returns to the caller.
                    self.owner_begin.set(io_base);
                    self.owner_done.waitUncancelable(io_base);
                }
            }
            return err;
        };
        if (self.outcome == .expired_before_execution and
            self.deadline.durationFromNow(io_base).raw.nanoseconds <= 0)
        {
            // The native timer has expired, but the caller has not marked
            // abandonment. Owner-side admission must reject this queued work.
            self.owner_begin.set(io_base);
            self.owner_done.waitUncancelable(io_base);
        }
    }
    fn join(context: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = from(context);
        const io_base = self.delegate;
        if (self.isCommand(pointer)) {
            _ = self.joins.fetchAdd(1, .monotonic);
            self.owner_begin.set(io_base);
        }
        io_base.vtable.futexWaitUncancelable(io_base.userdata, pointer, expected);
    }
    fn own(self: *Probe) !void {
        try self.owner_begin.wait(self.delegate);
        defer self.owner_done.set(self.delegate);
        self.shutdown.set(self.delegate);
        const Handler = struct {
            fn run(_: *void, _: *Engine.Stream) !void {
                return error.UnexpectedHandler;
            }
        };
        var context: void = {};
        _ = try self.engine.serve(void, &context, Handler.run);
    }
};

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
    try fixture.connection.stream.shutdown(io, .send);
    var reader: FrameReader = .{};
    defer reader.deinit(allocator);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    var heads: usize = 0;
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
                if (frame.frame.header.flags & 1 != 0) fins += 1;
            },
            .goaway => {},
            else => return error.UnexpectedFrame,
        }
    }
    try std.testing.expectEqualStrings(if (outcome == .completed_during_cancel) "committed" else "", payload.items);
    try std.testing.expectEqual(@as(usize, @intFromBool(outcome == .completed_during_cancel)), heads);
    try std.testing.expectEqual(heads, fins);
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

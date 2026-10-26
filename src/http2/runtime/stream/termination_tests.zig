const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const frame_wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

const Action = enum { cancel, drop, finish };
const Mode = enum { blocked, partial, disabled, unusable, callback };
const Writer = struct {
    var active: std.atomic.Value(?*Writer) = .init(null);
    io: std.Io,
    mode: Mode,
    calls: std.atomic.Value(usize) = .init(0),
    cancelled: std.atomic.Value(bool) = .init(false),
    wait: std.Io.Event = .unset,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        const count = self.calls.fetchAdd(1, .monotonic);
        switch (self.mode) {
            .blocked => {
                self.wait.wait(self.io) catch |err| {
                    self.cancelled.store(true, .release);
                    return err;
                };
                return header.len;
            },
            .partial => return if (count == 0) @min(header.len, 4) else error.NetworkDown,
            .disabled, .unusable, .callback => return error.NetworkDown,
        }
    }
};

test "HTTP/2 client stream terminal cleanup bounds cancellation and destruction" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |duplex| {
        inline for (.{ Action.cancel, Action.drop }) |action| try exercise(duplex, action, .blocked);
    }
}

test "HTTP/2 client stream terminal cleanup retires partial reset without retry" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |duplex| try exercise(duplex, .cancel, .partial);
    try exercise(true, .finish, .partial);
}

test "HTTP/2 client stream terminal cleanup honors disabled output and unsafe prefix" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |duplex| {
        inline for (.{ Mode.disabled, Mode.unusable, Mode.callback }) |mode| try exercise(duplex, .cancel, mode);
    }
    try exercise(true, .finish, .disabled);
    try exercise(true, .finish, .unusable);
    try exercise(true, .finish, .callback);
}

test "HTTP/2 client stream terminal cleanup preserves buffered sibling responses" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    fixture.connection.limits.terminal_cleanup_timeout = .fromSeconds(1);
    var first = try fixture.connection.startRequest(.{ .method = "POST", .path = "/early" });
    defer first.deinit();
    var sibling = try fixture.connection.startRequest(.{ .method = "GET", .path = "/sibling" });
    defer sibling.deinit();
    try sibling.finish();
    try frame_wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 5, sibling.stream_id, &.{0x88});
    try frame_wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 5, first.stream_id, &.{0x88});
    var stream = try first.beginDuplex();
    var stream_live = true;
    defer if (stream_live) stream.deinit();
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    var finished = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
    try stream.closeRequestAfterResponse();
    try std.testing.expect(stream.released);
    // A live sibling prevents returning the connection to an idle pool, but
    // the channel must remain healthy enough to deliver that sibling.
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(!fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeLocalStreamCount());
    stream.deinit();
    stream_live = false;
    var response = try sibling.readResponseWithTimeout(.fromSeconds(1));
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expect(fixture.connection.isReusable());
}

test "HTTP/2 client stream terminal cleanup retires interrupted HPACK context" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    var request = try fixture.connection.startRequest(.{ .method = "POST", .path = "/headers" });
    defer request.deinit();
    var stream = try request.beginDuplex();
    defer stream.deinit();
    // Opening HEADERS was consumed, but no END_HEADERS/CONTINUATION arrives.
    try frame_wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 0, stream.stream_id, &.{0x88});
    try std.testing.expectError(error.Timeout, stream.readResponseEventWithTimeout(.fromMilliseconds(5)));
    try std.testing.expectError(error.ConnectionClosed, stream.reset(.cancel));
    try std.testing.expect(stream.released);
    try std.testing.expect(!fixture.connection.isReusable());
    try std.testing.expect(fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expect(!fixture.connection.duplex_reader_active);
}

test "HTTP/2 client stream terminal cleanup cancels a short declared request entity" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    fixture.connection.limits.terminal_cleanup_timeout = .fromSeconds(1);
    var request = try fixture.connection.startRequest(.{
        .method = "POST",
        .path = "/early",
        .headers = &.{.{ .name = "content-length", .value = "5" }},
    });
    defer request.deinit();
    try request.write("a");
    var stream = try request.beginDuplex();
    defer stream.deinit();
    stream.response_finished = true;
    try stream.closeRequestAfterResponse();
    try std.testing.expect(fixture.connection.isReusable());
    try std.testing.expect(stream.released);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    var peer: runtime.Connection = .{ .allocator = allocator, .io = io, .stream = fixture.peer, .role = .server };
    defer peer.frame_reader.deinit(allocator);
    while (true) {
        var frame = try runtime.testing.readOwnedFrame(&peer);
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type == .rst_stream) {
            const reset = try http2.ResetStreamPayload.parse(frame.frame);
            try std.testing.expectEqual(stream.stream_id, reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
            break;
        }
        try std.testing.expect(frame.frame.header.frame_type != .data or frame.frame.header.flags & 1 == 0);
    }
}

test "HTTP/2 client stream terminal cleanup releases ownership on reset history OOM" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |duplex| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        var fixture = try BlockedOutput.init(threaded.io(), .client);
        defer fixture.deinit();
        var request = try fixture.connection.startRequest(.{ .method = "POST", .path = "/oom" });
        defer request.deinit();
        try request.write("a");
        _ = try runtime.testing.recvStreamWindow(&fixture.connection, request.stream_id);
        var stream = if (duplex) try request.beginDuplex() else request;
        if (!duplex) request.completed = true;
        defer stream.deinit();
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        fixture.connection.allocator = failing.allocator();
        const result = if (duplex) stream.reset(.cancel) else stream.cancel(.cancel);
        fixture.connection.allocator = allocator;
        try std.testing.expectError(error.OutOfMemory, result);
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
        try std.testing.expectEqual(@as(usize, 0), fixture.connection.recv_stream_windows.items.len);
        try std.testing.expectEqual(@as(usize, 0), fixture.connection.send_stream_windows.items.len);
        try std.testing.expect(!fixture.connection.isReusable());
        try std.testing.expect(!fixture.connection.duplex_reader_active);
    }
}

test "HTTP/2 client stream terminal cleanup retires undecoded complete HPACK after OOM" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    var request = try fixture.connection.startRequest(.{ .method = "POST", .path = "/oom-headers" });
    defer request.deinit();
    var stream = try request.beginDuplex();
    defer stream.deinit();
    try frame_wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 0, stream.stream_id, &.{});
    try std.testing.expectError(error.Timeout, stream.readResponseEventWithTimeout(.fromMilliseconds(5)));
    // A complete indexed literal requires HPACK table allocation. Reading the
    // continuation and retaining its bytes succeed before that allocation fails.
    const block = [_]u8{ 0x88, 0x40, 5, 'x', '-', 'o', 'n', 'e', 1, 'a' };
    try frame_wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .continuation, 4, stream.stream_id, &block);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 2 });
    fixture.connection.allocator = failing.allocator();
    const result = stream.readResponseEventWithTimeout(.fromSeconds(1));
    fixture.connection.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(stream.pending_header.value.end_headers);
    // END_HEADERS is insufficient: an aborted decode may only have applied a
    // prefix of the peer's table updates, so siblings cannot reuse the decoder.
    try std.testing.expectError(error.ConnectionClosed, stream.reset(.cancel));
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(fixture.connection.terminal_write_failed);
}

fn exercise(comptime duplex: bool, comptime action: Action, mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    var request = try fixture.connection.startRequest(.{ .method = "POST", .path = "/cleanup" });
    defer request.deinit();
    // Populate both directions' indexed windows before cancellation.
    try request.write("a");
    _ = try runtime.testing.recvStreamWindow(&fixture.connection, request.stream_id);
    var stream = if (duplex) try request.beginDuplex() else request;
    if (!duplex) request.completed = true;
    var stream_live = true;
    defer if (stream_live) stream.deinit();
    fixture.connection.limits.terminal_cleanup_timeout = if (mode == .disabled) .zero else .fromMilliseconds(20);
    if (mode == .unusable) fixture.connection.aggregate_timeout_unusable = true;
    if (mode == .callback) fixture.connection.callback_reader_active = true;
    var writer: Writer = .{ .io = io, .mode = mode };
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    Writer.active.store(&writer, .release);
    defer Writer.active.store(null, .release);
    // Rescue an accidentally unbounded hook while retaining the underlying
    // write's Canceled error when the production deadline wins the race.
    const rescue: ?std.Thread = if (mode == .blocked) try std.Thread.spawn(.{}, struct {
        fn run(self: *Writer) void {
            std.Io.sleep(self.io, .fromMilliseconds(500), .awake) catch {};
            self.wait.set(self.io);
        }
    }.run, .{&writer}) else null;
    defer if (rescue) |thread| thread.join();
    const started = std.Io.Clock.awake.now(io);
    if (action == .drop) {
        stream.deinit();
        stream_live = false;
    } else {
        const result = if (action == .finish) blk: {
            stream.response_finished = true;
            break :blk stream.closeRequestAfterResponse();
        } else if (duplex) stream.reset(.cancel) else stream.cancel(.cancel);
        try std.testing.expectError(switch (mode) {
            .blocked, .disabled => error.Timeout,
            .partial => error.NetworkDown,
            .unusable => error.ConnectionClosed,
            .callback => error.UnexpectedFrame,
        }, result);
    }
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.recv_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.send_stream_windows.items.len);
    try std.testing.expect(!fixture.connection.duplex_reader_active);
    const expected_calls: usize = switch (mode) {
        .blocked => 1,
        .partial => 2,
        .disabled, .unusable, .callback => 0,
    };
    try std.testing.expectEqual(expected_calls, writer.calls.load(.acquire));
    if (mode == .blocked) try std.testing.expect(writer.cancelled.load(.acquire));
    if (action != .drop) {
        stream.deinit();
        stream_live = false;
        try std.testing.expectEqual(expected_calls, writer.calls.load(.acquire));
    }
}

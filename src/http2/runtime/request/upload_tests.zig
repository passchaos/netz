//! Suspended complete uploads retain wire credit and bounded terminal cleanup.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;
const options: runtime.RequestOptions = .{ .method = "POST", .path = "/early", .authority = "localhost", .body = "upload" };

fn queueResponse(connection: *runtime.Connection) !void {
    connection.peer_initial_stream_window = 1;
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0x05, 1, &.{0x88});
}

test "HTTP/2 suspended complete upload preserves exact prefix credit and suffix" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    try queueResponse(&fixture.connection);
    const pending = try runtime.testing.sendCompleteRequest(&fixture.connection, options);
    const upload = pending.upload orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("pload", upload.body);
    try std.testing.expectEqual(@as(i64, window.default_value - 1), fixture.connection.send_connection_window.value);
    try std.testing.expectEqual(@as(i64, 0), (try runtime.testing.sendStreamWindow(&fixture.connection, pending.stream_id)).value);
    var head = try frame_io.readOwned(allocator, fixture.connection.io, fixture.peer, 16_384);
    defer head.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.headers, head.frame.header.frame_type);
    var data = try frame_io.readOwned(allocator, fixture.connection.io, fixture.peer, 16_384);
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("u", data.frame.payload);
    try std.testing.expectEqual(@as(u8, 0), data.frame.header.flags);
}

const Observer = struct {
    fixture: *BlockedOutput,
    block: bool = false,
    reject_body: bool = false,
    fn begin(self: *@This(), _: runtime.StreamingResponseHead) !void {
        if (self.block and !self.reject_body) try self.fixture.saturate();
    }
    fn consume(self: *@This(), bytes: []const u8) !void {
        if (self.reject_body) {
            try self.fixture.saturate();
            return error.CallbackRejected;
        }
        try std.testing.expectEqual(@as(usize, 0), bytes.len);
    }
};

test "HTTP/2 early complete response honors zero terminal cleanup budget" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |callbacks| {
        var fixture = try BlockedOutput.init(threaded.io(), .client);
        defer fixture.deinit();
        const connection = &fixture.connection;
        connection.limits.terminal_cleanup_timeout = .zero;
        try queueResponse(connection);
        if (callbacks) {
            var observer: Observer = .{ .fixture = &fixture };
            var response = try connection.requestStreamingWithHeadAndTimeout(options, .fromSeconds(1), &observer, Observer.begin, Observer.consume);
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
        } else {
            var response = try connection.requestWithTimeout(options, .fromSeconds(1));
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
        }
        try std.testing.expect(connection.aggregate_timeout_unusable);
        try std.testing.expect(connection.terminal_write_failed);
        try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
        try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
        try connection.stream.shutdown(connection.io, .send);
        for (0..2) |_| {
            var sent = try frame_io.readOwned(allocator, connection.io, fixture.peer, 16_384);
            sent.deinit(allocator);
        }
        try std.testing.expectError(error.ConnectionClosed, frame_io.readOwned(allocator, connection.io, fixture.peer, 16_384));
    }
}

test "HTTP/2 early complete response callback rejection bounds refund and cancellation together" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    fixture.connection.peer_initial_stream_window = 1;
    try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 0x04, 1, &.{0x88});
    try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .data, 0x01, 1, "denied");
    try fixture.startRescue();
    var observer: Observer = .{ .fixture = &fixture, .block = true, .reject_body = true };
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    try std.testing.expectError(error.CallbackRejected, fixture.connection.requestStreamingWithHeadAndTimeout(options, .fromSeconds(2), &observer, Observer.begin, Observer.consume));
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
}

test "HTTP/2 reset admission synchronization uses the next request deadline" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    fixture.connection.peer_reset_admission_pending = true;
    try fixture.startRescue();
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    try std.testing.expectError(error.Timeout, fixture.connection.requestWithTimeout(options, .fromMilliseconds(30)));
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u31, 1), fixture.connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    var probe = try frame_io.readOwned(allocator, fixture.connection.io, fixture.peer, 16_384);
    defer probe.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, probe.frame.header.frame_type);
}

test "HTTP/2 early complete response survives bounded blocked cancellation output" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    try queueResponse(&fixture.connection);
    try fixture.startRescue();
    var observer: Observer = .{ .fixture = &fixture, .block = true };
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    var response = try fixture.connection.requestStreamingWithHeadAndTimeout(options, .fromSeconds(2), &observer, Observer.begin, Observer.consume);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
}

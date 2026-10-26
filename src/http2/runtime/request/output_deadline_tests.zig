//! Incremental upload deadlines include its opening head and early-response FIN.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

test "HTTP/2 streaming request deadline bounds blocked opening HEADERS" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .client);
    defer fixture.deinit();
    try fixture.startRescue();
    const started = std.Io.Clock.awake.now(fixture.connection.io);
    const result = fixture.connection.startRequestWithTimeout(.{ .method = "POST", .path = "/blocked", .authority = "localhost", .headers = &.{.{ .name = "x-large", .value = "x" ** (256 * 1024) }} }, .fromMilliseconds(30));
    if (result) |value| {
        var writer = value;
        writer.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.Timeout, err);
    try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
}

test "HTTP/2 streaming request deadline bounds early-response END_STREAM" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for (0..3) |operation| {
        var fixture = try BlockedOutput.init(threaded.io(), .client);
        defer fixture.deinit();
        const id = try runtime.testing.reserveNextClientStreamId(&fixture.connection);
        var writer = runtime.RequestWriter{ .connection = &fixture.connection, .stream_id = id, .expected_length = null, .head_request = false };
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try wire.appendFrame(&encoded, allocator, .headers, 5, id, &.{0x88});
        const bytes = try encoded.toOwnedSlice(allocator);
        try runtime.testing.queuePendingApplicationFrame(&fixture.connection, .{ .bytes = bytes, .frame = try http2.Frame.parse(bytes) });
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(fixture.connection.io);
        const result = switch (operation) {
            0 => writer.writeWithTimeout("upload", .fromMilliseconds(30)),
            1 => writer.finishDataWithTimeout("upload", .fromMilliseconds(30)),
            else => writer.finishWithTimeout(.fromMilliseconds(30)),
        };
        try std.testing.expectError(error.ResponseAvailable, result);
        try std.testing.expect(started.untilNow(fixture.connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
        try std.testing.expect(writer.body_finished);
        try std.testing.expectEqual(@as(usize, 0), writer.committedBytes());
        try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    }
}

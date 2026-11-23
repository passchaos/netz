const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const wt = @import("mod.zig");
const allocator = std.testing.allocator;

test "WebTransport HTTP2 encoded writes retain transaction and exact suffix across deadlines" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("../../http2/runtime/testing/blocked_output.zig").BlockedOutput.init(io, .client);
    defer fixture.deinit();
    const limits: wt.Limits = .{ .data = 1024, .bidi = 1, .bidi_remote_data = 1024 };
    var session = try wt.Session.init(allocator, .{ .connection = &fixture.connection, .stream_id = 1 }, .{}, limits, .{});
    defer session.deinit();
    const id = try session.openStream(.bidirectional);
    try std.testing.expectError(error.Timeout, session.grantStreamsWithTimeout(.bidirectional, 1, .zero));
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    try std.testing.expectError(error.Timeout, session.sendStreamWithDeadline(id, "kept", true, expired));
    try std.testing.expect(session.pending != null);
    try std.testing.expectEqual(@as(usize, 0), session.pending.?.offset);
    try std.testing.expectEqual(@as(u64, 0), session.state.sent_data);
    try std.testing.expect(!session.state.streams.get(id).?.send_fin);
    try std.testing.expectError(error.PendingWrite, session.sendDatagramWithDeadline("later", .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake })));
    const expected = session.pending.?.bytes;
    try std.testing.expectEqualStrings("kept", (try wt.Capsule.parse(expected)).capsule.stream.data);
    // The retained encoding and virtual-stream accounting survive repeated
    // interruptions, including after the caller's original payload expires.
    try std.testing.expectError(error.Timeout, session.resumeWriteWithTimeout(.zero));
    try std.testing.expectEqualSlices(u8, expected, session.pending.?.bytes);
    try std.testing.expectEqual(@as(u64, 0), session.state.sent_data);
}

test "WebTransport HTTP2 slice sends encode one stream capsule" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("../../http2/runtime/testing/blocked_output.zig").BlockedOutput.init(io, .client);
    defer fixture.deinit();
    const limits: wt.Limits = .{ .data = 1024, .bidi = 1, .bidi_remote_data = 1024 };
    var session = try wt.Session.init(allocator, .{ .connection = &fixture.connection, .stream_id = 1 }, .{}, limits, .{});
    defer session.deinit();
    const id = try session.openStream(.bidirectional);
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    try std.testing.expectError(
        error.Timeout,
        session.sendStreamSlicesWithDeadline(
            id,
            &.{ "ab", "", "cde" },
            true,
            expired,
        ),
    );
    try std.testing.expect(session.pending != null);
    const parsed = try wt.Capsule.parse(session.pending.?.bytes);
    try std.testing.expectEqual(id, parsed.capsule.stream.id);
    try std.testing.expectEqualStrings("abcde", parsed.capsule.stream.data);
    try std.testing.expect(parsed.capsule.stream.fin);
    try std.testing.expectEqual(@as(u64, 0), session.state.sent_data);
    try std.testing.expect(!session.state.streams.get(id).?.send_fin);
    try std.testing.expectError(
        error.PendingWrite,
        session.sendDatagramWithDeadline(
            "later",
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "WebTransport HTTP2 empty slice send encodes a fin-only stream capsule" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("../../http2/runtime/testing/blocked_output.zig").BlockedOutput.init(io, .client);
    defer fixture.deinit();
    const limits: wt.Limits = .{ .data = 1024, .bidi = 1, .bidi_remote_data = 1024 };
    var session = try wt.Session.init(allocator, .{ .connection = &fixture.connection, .stream_id = 1 }, .{}, limits, .{});
    defer session.deinit();
    const id = try session.openStream(.bidirectional);
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    try std.testing.expectError(
        error.Timeout,
        session.sendStreamSlicesWithDeadline(id, &.{}, true, expired),
    );
    const parsed = try wt.Capsule.parse(session.pending.?.bytes);
    try std.testing.expectEqual(id, parsed.capsule.stream.id);
    try std.testing.expectEqual(@as(usize, 0), parsed.capsule.stream.data.len);
    try std.testing.expect(parsed.capsule.stream.fin);
}

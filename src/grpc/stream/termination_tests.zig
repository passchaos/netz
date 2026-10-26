//! Terminal cleanup must not turn an RPC deadline into an unbounded write.
const std = @import("std");
const builtin = @import("builtin");
const grpc = @import("mod.zig");
const http2 = @import("../../http2/mod.zig");
const frame_wire = @import("../../http2/runtime/frame/wire.zig");
const BlockedOutput = @import("../../http2/runtime/testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

test "gRPC streaming terminal cleanup bounds blocked RPC cancellation" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |duplex| {
        try blockedCancellation(duplex);
    }
}

fn blockedCancellation(comptime duplex: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    // Waiting for credit times out without submitting a partial DATA frame.
    fixture.connection.peer_initial_stream_window = 0;
    var stream = if (duplex)
        try grpc.startDuplex(&fixture.connection, allocator, .{ .path = "/fixture.Termination/Stream" })
    else
        try grpc.startClient(&fixture.connection, allocator, .{ .path = "/fixture.Termination/Stream" });
    defer stream.deinit();
    try fixture.saturate();
    try fixture.startRescue();
    stream.deadline = .fromNow(io, .{ .raw = .fromMilliseconds(30), .clock = .awake });
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, stream.writeMessage("blocked"));
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try retired(&fixture.connection);
    if (duplex) {
        try std.testing.expect(stream.transport.released);
        try std.testing.expectError(error.ConnectionClosed, stream.writeMessage("later"));
    } else {
        try std.testing.expect(stream.transport.completed);
        try std.testing.expectError(error.ConnectionClosed, stream.transport.write("later"));
    }
}

test "gRPC duplex terminal cleanup preserves status with blocked request FIN" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    var stream = try grpc.startDuplex(&fixture.connection, allocator, .{ .path = "/fixture.Termination/Stream" });
    defer stream.deinit();
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "grpc-status", .value = "7" },
        .{ .name = "grpc-message", .value = "denied" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &fields);
    try frame_wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 5, stream.streamId(), encoded.items);
    try fixture.saturate();
    try fixture.startRescue();
    const Consumer = struct {
        fn consume(_: void, _: grpc.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    const started = std.Io.Clock.awake.now(io);
    var event = try stream.readResponseEvent({}, Consumer.consume);
    defer event.deinit(allocator);
    try std.testing.expect(event == .terminal);
    try std.testing.expectEqual(@as(@TypeOf(event.terminal.status), .permission_denied), event.terminal.status);
    try std.testing.expectEqualStrings("denied", event.terminal.status_message);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try retired(&fixture.connection);
    try std.testing.expect(stream.transport.released);
}

fn retired(connection: *http2.runtime.Connection) !void {
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
    try std.testing.expect(!connection.duplex_reader_active);
}

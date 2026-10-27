const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Fixture = @import("testing.zig").Fixture;
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
}

test "HTTP/2 duplex pump delivers a ready sibling while another stream is silent" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try fixture.frame(.headers, 4, b.streamId(), "\x88");
    try fixture.frame(.data, 1, b.streamId(), "ready");
    // Input is available to the pump but poll must not read even buffered
    // socket-parser input on behalf of either stream.
    try std.testing.expect((try a.pollResponseEvent()) == null);
    try std.testing.expect((try b.pollResponseEvent()) == null);
    try std.testing.expectEqual(b.streamId(), (try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io))).stream);
    try std.testing.expect((try a.pollResponseEvent()) == null);
    var head = (try b.pollResponseEventWithDeadline(deadline(fixture.io))).?;
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
    try std.testing.expectEqual(b.streamId(), (try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io))).stream);
    var data = (try b.pollResponseEventWithDeadline(deadline(fixture.io))).?;
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("ready", data.data.data);
    var finished = (try b.pollResponseEvent()).?;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeClientDuplexCount());
    try std.testing.expect((try a.pollResponseEvent()) == null);
}

test "HTTP/2 duplex pump retains partial headers and ordered HPACK for polled streams" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-shared", .value = "pump-indexed" },
    };
    const block = try encoder.encodeBlockRetained(allocator, &fields);
    try fixture.frame(.headers, 1, a.streamId(), block[0..1]);
    try std.testing.expectEqual(runtime.ClientDuplexPumpEvent.progress, try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io)));
    try std.testing.expect((try a.pollResponseEvent()) == null);
    try fixture.frame(.continuation, 4, a.streamId(), block[1..]);
    try fixture.headers(&encoder, b.streamId(), true, &fields);
    try std.testing.expectEqual(a.streamId(), (try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io))).stream);
    try std.testing.expectEqual(b.streamId(), (try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io))).stream);
    var bh = (try b.pollResponseEvent()).?;
    defer bh.deinit(allocator);
    try std.testing.expectEqualStrings("pump-indexed", runtime.testing.findHeader(bh.head.headers, "x-shared").?);
    var ah = (try a.pollResponseEvent()).?;
    defer ah.deinit(allocator);
    try std.testing.expectEqualStrings("pump-indexed", runtime.testing.findHeader(ah.head.headers, "x-shared").?);
}

test "HTTP/2 duplex pump command wake preserves a partial transport frame" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    // Start with only the first byte of an HTTP/2 HEADERS frame header.
    try fixture.connection.frame_reader.buffer.append(allocator, 0);
    var wake: std.Io.Event = .unset;
    const Await = struct {
        fn run(connection: *runtime.Connection, event: *std.Io.Event) !runtime.ClientDuplexPumpEvent {
            return connection.pumpClientDuplexWithDeadlineOrWake(deadline(connection.io), event);
        }
    };
    var pending = fixture.io.async(Await.run, .{ &fixture.connection, &wake });
    wake.set(fixture.io);
    try std.testing.expectEqual(runtime.ClientDuplexPumpEvent.wake, try pending.await(fixture.io));
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.frame_reader.buffer.items.len - fixture.connection.frame_reader.start);
    wake.reset();
    // Complete the original frame: length=1, HEADERS, END_HEADERS|END_STREAM,
    // stream=1, static :status=200.
    try fixture.connection.frame_reader.buffer.appendSlice(allocator, &.{ 0, 1, 1, 5, 0, 0, 0, 1, 0x88 });
    try std.testing.expectEqual(a.streamId(), (try fixture.connection.pumpClientDuplexWithDeadlineOrWake(deadline(fixture.io), &wake)).stream);
    var head = (try a.pollResponseEvent()).?;
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
}

test "HTTP/2 duplex pump publishes GOAWAY for every affected polled stream" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try fixture.frame(.goaway, 0, 0, &.{ 0, 0, 0, 1, 0, 0, 0, 0 });
    try std.testing.expectEqual(runtime.ClientDuplexPumpEvent.progress, try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io)));
    try std.testing.expectError(error.ConnectionGoAway, b.pollResponseEvent());
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeLocalStreamCount());
    try std.testing.expect((try a.pollResponseEvent()) == null);
}

test "HTTP/2 duplex pump task cancellation joins its frame read and retains input" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    try fixture.connection.frame_reader.buffer.append(allocator, 0);
    var wake: std.Io.Event = .unset;
    const Await = struct {
        fn run(connection: *runtime.Connection, event: *std.Io.Event) !runtime.ClientDuplexPumpEvent {
            return connection.pumpClientDuplexWithDeadlineOrWake(deadline(connection.io), event);
        }
    };
    var pending = fixture.io.async(Await.run, .{ &fixture.connection, &wake });
    try std.testing.expectError(error.Canceled, pending.cancel(fixture.io));
    try fixture.connection.frame_reader.buffer.appendSlice(allocator, &.{ 0, 1, 1, 5, 0, 0, 0, 1, 0x88 });
    try std.testing.expectEqual(a.streamId(), (try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io))).stream);
    var head = (try a.pollResponseEvent()).?;
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
}

test "HTTP/2 duplex pump simultaneous command wake and frame never lose or duplicate a frame" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for (0..20) |_| {
        var fixture = try Fixture.init(threaded.io());
        defer fixture.deinit();
        var a = try fixture.open();
        defer a.deinit();
        try fixture.frame(.headers, 5, a.streamId(), "\x88");
        var wake: std.Io.Event = .unset;
        wake.set(fixture.io);
        const event = try fixture.connection.pumpClientDuplexWithDeadlineOrWake(deadline(fixture.io), &wake);
        switch (event) {
            .wake => {
                wake.reset();
                try std.testing.expectEqual(a.streamId(), (try fixture.connection.pumpClientDuplexWithDeadline(deadline(fixture.io))).stream);
            },
            .stream => |id| try std.testing.expectEqual(a.streamId(), id),
            .progress => return error.UnexpectedProgress,
        }
        var head = (try a.pollResponseEvent()).?;
        defer head.deinit(allocator);
        var finished = (try a.pollResponseEvent()).?;
        defer finished.deinit(allocator);
        try std.testing.expect(finished == .finished);
        try std.testing.expectError(error.ConnectionClosed, a.pollResponseEvent());
        try std.testing.expect(fixture.connection.isReusable());
    }
}

test "HTTP/2 duplex pump admission failure preserves partial input and reader ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .limited(1) });
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    try fixture.connection.frame_reader.buffer.append(allocator, 0);
    var wake: std.Io.Event = .unset;
    try std.testing.expectError(error.ConcurrencyUnavailable, fixture.connection.pumpClientDuplexWithDeadlineOrWake(deadline(fixture.io), &wake));
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeClientDuplexCount());
    threaded.concurrent_limit = .unlimited;
    try fixture.connection.frame_reader.buffer.appendSlice(allocator, &.{ 0, 1, 1, 5, 0, 0, 0, 1, 0x88 });
    try std.testing.expectEqual(a.streamId(), (try fixture.connection.pumpClientDuplexWithDeadlineOrWake(deadline(fixture.io), &wake)).stream);
    var head = (try a.pollResponseEvent()).?;
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
}

test "HTTP/2 duplex event poll bounds malformed DATA credit refund and preserves the protocol error" {
    if (@import("builtin").os.tag != .linux) return;
    const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
    const wire = @import("../frame/wire.zig");
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    var writer = try fixture.connection.startRequest(.{ .authority = "localhost", .body_length = 0 });
    defer writer.deinit();
    try writer.finish();
    var stream = try writer.beginDuplex();
    defer stream.deinit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    const block = try encoder.encodeBlockRetained(allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "0" },
    });
    try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .headers, 4, stream.streamId(), block);
    try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .data, 1, stream.streamId(), "x");
    _ = try fixture.connection.pumpClientDuplexWithDeadline(deadline(io));
    var head = (try stream.pollResponseEvent()).?;
    defer head.deinit(allocator);
    _ = try fixture.connection.pumpClientDuplexWithDeadline(deadline(io));
    try fixture.saturate();
    try fixture.startRescue();
    const start = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.InvalidContentLength, stream.pollResponseEventWithDeadline(.fromNow(io, .{ .raw = .fromMilliseconds(10), .clock = .awake })));
    try std.testing.expect(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 250 * std.time.ns_per_ms);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(fixture.connection.terminal_write_failed);
}

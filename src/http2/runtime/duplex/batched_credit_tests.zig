const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Fixture = @import("testing.zig").Fixture;
const FrameReader = @import("../frame/io.zig").Reader;
const allocator = std.testing.allocator;

fn next(stream: *runtime.ClientDuplexStream, deadline: std.Io.Clock.Timestamp) runtime.Error!runtime.DuplexResponseEvent {
    while (true) {
        if (try stream.pollResponseEventWithCreditPolicyAndDeadline(.low_watermark, deadline)) |event| return event;
        _ = try stream.connection.pumpClientDuplexWithDeadline(deadline);
    }
}

test "HTTP/2 batched deferred credit emits one connection and stream update per half window" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    var stream = try fixture.open();
    defer stream.deinit();
    try stream.deferResponseStreamCredit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, stream.streamId(), false, &.{.{ .name = ":status", .value = "200" }});
    try fixture.frame(.data, 0, stream.streamId(), "x" ** 16384);
    try fixture.frame(.data, 0, stream.streamId(), "y" ** 16384);
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var first = try next(&stream, deadline);
    defer first.deinit(allocator);
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(i64, 49151), fixture.connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(usize, 0), try stream.releaseResponseStreamCreditBatchedWithDeadline(16384, deadline));
    try std.testing.expectEqual(@as(u32, 16384), stream.deferred_response_credit);
    var second = try next(&stream, deadline);
    defer second.deinit(allocator);
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(i64, 65535), fixture.connection.recv_connection_window.value);
    try std.testing.expectError(error.FlowControlViolation, stream.releaseResponseStreamCreditBatchedWithDeadline(32769, deadline));
    try std.testing.expectEqual(@as(usize, 32768), try stream.releaseResponseStreamCreditBatchedWithDeadline(32768, deadline));
    try std.testing.expectEqual(@as(u32, 0), stream.deferred_response_credit);
    const index = fixture.connection.recv_stream_window_index.get(stream.streamId()).?;
    try std.testing.expectEqual(@as(i64, 65535), fixture.connection.recv_stream_windows.items[index].window.value);
    try fixture.connection.stream.shutdown(io, .send);
    var reader: FrameReader = .{};
    defer reader.deinit(allocator);
    var connection_updates: usize = 0;
    var stream_updates: usize = 0;
    while (true) {
        const frame = reader.read(allocator, io, fixture.peer, 16384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (frame.frame.header.frame_type != .window_update) continue;
        const update = try http2.WindowUpdatePayload.parse(frame.frame);
        try std.testing.expectEqual(@as(u31, 32768), update.increment);
        if (update.stream_id == 0) connection_updates += 1 else {
            try std.testing.expectEqual(stream.streamId(), update.stream_id);
            stream_updates += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), connection_updates);
    try std.testing.expectEqual(@as(usize, 1), stream_updates);
}

test "HTTP/2 batched deferred credit returns padding and flushes a full tiny window" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    fixture.connection.limits.initial_window_size = 8;
    fixture.connection.recv_stream_window_target = 8;
    var stream = try fixture.open();
    defer stream.deinit();
    try stream.deferResponseStreamCredit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, stream.streamId(), false, &.{.{ .name = ":status", .value = "200" }});
    try fixture.frame(.data, 8, stream.streamId(), "\x02abcd\x00\x00");
    try fixture.frame(.data, 0, stream.streamId(), "wxyz");
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var first = try next(&stream, deadline);
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", first.data.data);
    try std.testing.expectEqual(@as(i64, 65531), fixture.connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(usize, 0), try stream.releaseResponseStreamCreditBatchedWithDeadline(3, deadline));
    var second = try next(&stream, deadline);
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("wxyz", second.data.data);
    try std.testing.expectEqual(@as(usize, 3), try stream.releaseResponseStreamCreditBatchedWithDeadline(3, deadline));
    try std.testing.expectEqual(@as(u32, 5), stream.deferred_response_credit);
    try fixture.headers(&encoder, stream.streamId(), true, &.{.{ .name = "x-end", .value = "done" }});
    var trailers = try next(&stream, deadline);
    defer trailers.deinit(allocator);
    try std.testing.expect(trailers == .trailers);
    try std.testing.expectEqual(@as(usize, 5), try stream.releaseResponseStreamCreditBatchedWithDeadline(5, deadline));
    try std.testing.expectEqual(@as(u32, 0), stream.deferred_response_credit);
}

test "HTTP/2 batched deferred credit fails closed after uncertain output" {
    const Fault = struct {
        var current: ?*@This() = null;
        calls: std.atomic.Value(usize) = .init(0),
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            const self = current.?;
            if (self.calls.fetchAdd(1, .monotonic) == 0) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    var stream = try fixture.open();
    defer stream.deinit();
    try stream.deferResponseStreamCredit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, stream.streamId(), false, &.{.{ .name = ":status", .value = "200" }});
    try fixture.frame(.data, 0, stream.streamId(), "abc");
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    fixture.connection.recv_connection_window.value = 32770;
    var fault: Fault = .{};
    Fault.current = &fault;
    defer Fault.current = null;
    var vtable = io.vtable.*;
    vtable.netWrite = Fault.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    try std.testing.expectError(error.NetworkDown, next(&stream, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable and fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 2), fault.calls.load(.acquire));
    stream.reset(.cancel) catch {};
    try std.testing.expectEqual(@as(usize, 2), fault.calls.load(.acquire));
}

test "HTTP/2 batched deferred credit restores a full refill after terminal close" {
    const Closed = struct {
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            return error.SocketUnconnected;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    var stream = try fixture.open();
    defer stream.deinit();
    try stream.deferResponseStreamCredit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, stream.streamId(), false, &.{.{ .name = ":status", .value = "200" }});
    try fixture.frame(.data, 8, stream.streamId(), "\x01ab\x00");
    try fixture.headers(&encoder, stream.streamId(), true, &.{.{ .name = "x-end", .value = "retained" }});
    var head = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer head.deinit(allocator);
    fixture.connection.recv_connection_window.value = 32770;
    var vtable = io.vtable.*;
    vtable.netWrite = Closed.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var data = try next(&stream, deadline);
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("ab", data.data.data);
    try std.testing.expectEqual(@as(i64, 65535), fixture.connection.recv_connection_window.value);
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable and !fixture.connection.terminal_write_failed);
    var trailers = try next(&stream, deadline);
    defer trailers.deinit(allocator);
    try std.testing.expectEqualStrings("retained", runtime.testing.findHeader(trailers.trailers, "x-end").?);
    try std.testing.expectEqual(@as(usize, 2), try stream.releaseResponseStreamCreditBatchedWithDeadline(2, deadline));
}

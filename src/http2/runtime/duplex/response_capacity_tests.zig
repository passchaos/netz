const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Fixture = @import("testing.zig").Fixture;
const FrameReader = @import("../frame/io.zig").Reader;
const allocator = std.testing.allocator;

test "HTTP/2 deferred duplex stream credit preserves connection credit and padding" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    fixture.connection.limits.initial_window_size = 8;
    fixture.connection.recv_stream_window_target = 8;
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try a.deferResponseStreamCredit();
    try b.deferResponseStreamCredit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, a.streamId(), false, &.{.{ .name = ":status", .value = "200" }});
    try fixture.headers(&encoder, b.streamId(), false, &.{.{ .name = ":status", .value = "200" }});
    try fixture.frame(.data, 8, a.streamId(), "\x02abcd\x00\x00");
    try fixture.frame(.data, 0, b.streamId(), "xy");
    var ah = try a.readResponseEventWithTimeout(.fromSeconds(1));
    defer ah.deinit(allocator);
    var bh = try b.readResponseEventWithTimeout(.fromSeconds(1));
    defer bh.deinit(allocator);
    var ad = try a.readResponseEventWithTimeout(.fromSeconds(1));
    defer ad.deinit(allocator);
    var bd = try b.readResponseEventWithTimeout(.fromSeconds(1));
    defer bd.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", ad.data.data);
    try std.testing.expectEqualStrings("xy", bd.data.data);
    try std.testing.expectEqual(@as(usize, 4), a.deferred_response_credit);
    try std.testing.expectEqual(@as(usize, 2), b.deferred_response_credit);
    try std.testing.expectEqual(@as(i64, 65_535), fixture.connection.recv_connection_window.value);
    const a_index = fixture.connection.recv_stream_window_index.get(a.streamId()).?;
    const b_index = fixture.connection.recv_stream_window_index.get(b.streamId()).?;
    try std.testing.expectEqual(@as(i64, 4), fixture.connection.recv_stream_windows.items[a_index].window.value);
    try std.testing.expectEqual(@as(i64, 6), fixture.connection.recv_stream_windows.items[b_index].window.value);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try std.testing.expectError(error.FlowControlViolation, a.releaseResponseStreamCreditWithDeadline(5, deadline));
    try a.releaseResponseStreamCreditWithDeadline(3, deadline);
    try a.releaseResponseStreamCreditWithDeadline(1, deadline);
    try std.testing.expectEqual(@as(usize, 0), a.deferred_response_credit);
    try std.testing.expectEqual(@as(i64, 8), fixture.connection.recv_stream_windows.items[a_index].window.value);
    try fixture.headers(&encoder, a.streamId(), true, &.{.{ .name = "x-done", .value = "yes" }});
    try fixture.frame(.data, 1, b.streamId(), "z");
    var at = try a.readResponseEventWithTimeout(.fromSeconds(1));
    defer at.deinit(allocator);
    var last = try b.readResponseEventWithTimeout(.fromSeconds(1));
    defer last.deinit(allocator);
    try b.releaseResponseStreamCreditWithDeadline(2, deadline);
    try std.testing.expectEqual(@as(usize, 0), b.deferred_response_credit);
    var af = try a.readResponseEventWithTimeout(.fromSeconds(1));
    defer af.deinit(allocator);
    var bf = try b.readResponseEventWithTimeout(.fromSeconds(1));
    defer bf.deinit(allocator);
    try std.testing.expect(af == .finished and bf == .finished);
    try fixture.connection.stream.shutdown(io, .send);
    var reader: FrameReader = .{};
    defer reader.deinit(allocator);
    var connection_credit: usize = 0;
    var a_credit: usize = 0;
    var b_credit: usize = 0;
    while (true) {
        const frame = reader.read(allocator, io, fixture.peer, 16384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (frame.frame.header.frame_type == .window_update) {
            const update = try http2.WindowUpdatePayload.parse(frame.frame);
            if (update.stream_id == 0) connection_credit += update.increment else if (update.stream_id == a.streamId()) a_credit += update.increment else if (update.stream_id == b.streamId()) b_credit += update.increment else return error.WrongStream;
        }
    }
    try std.testing.expectEqual(@as(usize, 10), connection_credit);
    try std.testing.expectEqual(@as(usize, 7), a_credit);
    try std.testing.expectEqual(@as(usize, 0), b_credit);
}

test "HTTP/2 deferred duplex credit preserves buffered trailers after terminal close" {
    const Closed = struct {
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            return error.SocketUnconnected;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
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
    var vtable = io.vtable.*;
    vtable.netWrite = Closed.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    var data = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("ab", data.data.data);
    try stream.releaseResponseStreamCreditWithDeadline(2, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(i64, 65_535), fixture.connection.recv_connection_window.value);
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    var terminal = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer terminal.deinit(allocator);
    try std.testing.expectEqualStrings("retained", runtime.testing.findHeader(terminal.trailers, "x-end").?);
    var finished = try stream.readResponseEventWithTimeout(.fromSeconds(1));
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
}

test "HTTP/2 deferred duplex credit stops control output after an uncertain prefix" {
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
    var fault: Fault = .{};
    Fault.current = &fault;
    defer Fault.current = null;
    var vtable = io.vtable.*;
    vtable.netWrite = Fault.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    try std.testing.expectError(error.NetworkDown, stream.readResponseEventWithTimeout(.fromSeconds(1)));
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 2), fault.calls.load(.acquire));
    stream.reset(.cancel) catch {};
    try std.testing.expectEqual(@as(usize, 2), fault.calls.load(.acquire));
}

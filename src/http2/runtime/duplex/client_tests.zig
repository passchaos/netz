const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

const Fixture = struct {
    io: std.Io,
    listener: std.Io.net.Server,
    peer: std.Io.net.Stream,
    connection: runtime.Connection,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{ .io = io, .listener = listener, .peer = peer, .connection = .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
        } };
    }

    fn deinit(self: *Fixture) void {
        self.connection.close();
        self.peer.close(self.io);
        self.listener.deinit(self.io);
    }

    fn frame(self: *Fixture, kind: http2.FrameType, flags: u8, id: u31, bytes: []const u8) !void {
        try wire.appendFrame(&self.connection.frame_reader.buffer, allocator, kind, flags, id, bytes);
    }

    fn headers(self: *Fixture, encoder: *http2.Hpack.Encoder, id: u31, end_stream: bool, fields: []const http2.Hpack.HeaderField) !void {
        const block = try encoder.encodeBlockRetained(allocator, fields);
        try self.frame(.headers, 4 | @as(u8, if (end_stream) 1 else 0), id, block);
    }

    fn open(self: *Fixture) !runtime.ClientDuplexStream {
        var writer = try self.connection.startRequest(.{ .authority = "localhost", .body_length = 0 });
        errdefer writer.deinit();
        try writer.finish();
        return writer.beginDuplex();
    }
};

fn expectField(fields: []const http2.Hpack.HeaderField, name: []const u8, value: []const u8) !void {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return std.testing.expectEqualStrings(value, field.value);
    }
    return error.MissingExpectedField;
}

fn read(stream: *runtime.ClientDuplexStream) !runtime.DuplexResponseEvent {
    return stream.readResponseEventWithTimeout(.fromSeconds(1));
}

test "HTTP/2 multiplexed duplex routes HPACK and DATA and isolates cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    var a_live = true;
    defer if (a_live) a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try std.testing.expectEqual(@as(usize, 2), fixture.connection.activeClientDuplexCount());
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    const head = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-shared", .value = "same" },
    };
    // B changes the dynamic table before A references that table. A's owner
    // reads first; it must retain B's decoded fields and deliver only A's data.
    try fixture.headers(&encoder, b.streamId(), false, &head);
    try fixture.headers(&encoder, a.streamId(), false, &head);
    try fixture.frame(.data, 0, b.streamId(), "b");
    try fixture.frame(.data, 0, a.streamId(), "a");
    const trailers = [_]http2.Hpack.HeaderField{.{ .name = "x-late", .value = "retained" }};
    try fixture.headers(&encoder, a.streamId(), true, &trailers);
    try fixture.headers(&encoder, b.streamId(), true, &trailers);
    try fixture.headers(&encoder, 5, true, &.{
        .{ .name = ":status", .value = "200" },
        trailers[0],
    });

    var ah = try read(&a);
    defer ah.deinit(allocator);
    try expectField(ah.head.headers, "x-shared", "same");
    var bh = try read(&b);
    defer bh.deinit(allocator);
    try expectField(bh.head.headers, "x-shared", "same");
    var ad = try read(&a);
    defer ad.deinit(allocator);
    try std.testing.expectEqualStrings("a", ad.data.data);
    try a.reset(.cancel);
    a.deinit();
    a_live = false;
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeClientDuplexCount());
    try std.testing.expect(fixture.connection.duplex_reader_active);
    var bd = try read(&b);
    defer bd.deinit(allocator);
    try std.testing.expectEqualStrings("b", bd.data.data);
    var bt = try read(&b);
    defer bt.deinit(allocator);
    try expectField(bt.trailers, "x-late", "retained");
    var done = try read(&b);
    defer done.deinit(allocator);
    try std.testing.expect(done == .finished);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeClientDuplexCount());
    try std.testing.expect(!fixture.connection.duplex_reader_active);

    var ordinary = try fixture.connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
    defer ordinary.deinit(allocator);
    try expectField(ordinary.headers, "x-late", "retained");
    try std.testing.expect(fixture.connection.isReusable());
}

test "HTTP/2 multiplexed duplex preserves a partial shared header across timeout and another stream" {
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
        .{ .name = "x-shared", .value = "fragmented" },
    };
    const block = try encoder.encodeBlockRetained(allocator, &fields);
    try fixture.frame(.headers, 1, a.streamId(), block[0..1]);
    try std.testing.expectError(error.Timeout, a.readResponseEventWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.Timeout, b.readResponseEventWithTimeout(.fromMilliseconds(1)));
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try fixture.frame(.continuation, 4, a.streamId(), block[1..]);
    try fixture.headers(&encoder, b.streamId(), true, &fields);
    var bh = try read(&b);
    defer bh.deinit(allocator);
    try expectField(bh.head.headers, "x-shared", "fragmented");
    var ah = try read(&a);
    defer ah.deinit(allocator);
    try expectField(ah.head.headers, "x-shared", "fragmented");
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeClientDuplexCount());
}

test "HTTP/2 multiplexed duplex cancel preserves another stream partial header" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try fixture.frame(.headers, 1, a.streamId(), "\x88");
    try std.testing.expectError(error.Timeout, a.readResponseEventWithTimeout(.fromMilliseconds(1)));
    try b.reset(.cancel);
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeClientDuplexCount());
    try fixture.frame(.continuation, 4, a.streamId(), "");
    var head = try read(&a);
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.head.status);
}

test "HTTP/2 multiplexed duplex cancel of incomplete HPACK prevents sibling reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try fixture.frame(.headers, 1, a.streamId(), "\x88");
    try std.testing.expectError(error.Timeout, a.readResponseEventWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectError(error.ConnectionClosed, a.reset(.cancel));
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, read(&b));
}

test "HTTP/2 multiplexed duplex continuations do not exhaust deferred frame capacity" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.connection.limits.max_pending_ping_frames = 1;
    fixture.connection.limits.max_continuation_frames = 32;
    var a = try fixture.open();
    defer a.deinit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    const block = try encoder.encodeBlockRetained(allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-continuations", .value = "a long enough literal value for many individual continuation frames" },
    });
    try fixture.frame(.headers, 1, a.streamId(), block[0..1]);
    for (1..16) |i| try fixture.frame(.continuation, 0, a.streamId(), block[i..][0..1]);
    try fixture.frame(.continuation, 4, a.streamId(), block[16..]);
    var head = try read(&a);
    defer head.deinit(allocator);
    try expectField(head.head.headers, "x-continuations", "a long enough literal value for many individual continuation frames");
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeClientDuplexCount());
}

test "HTTP/2 multiplexed duplex flow-control waits retain sibling headers once" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var writer = try fixture.connection.startRequest(.{ .authority = "localhost" });
    errdefer writer.deinit();
    var a = try writer.beginDuplex();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    (try runtime.testing.sendStreamWindow(&fixture.connection, a.streamId())).value = 0;
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-dictionary", .value = "kept" },
    };
    try fixture.headers(&encoder, b.streamId(), true, &fields);
    try fixture.frame(.window_update, 0, a.streamId(), &.{ 0, 0, 0, 1 });
    try fixture.headers(&encoder, a.streamId(), true, &fields);
    const written = try a.write("u");
    try std.testing.expectEqual(@as(usize, 1), written.written);
    try std.testing.expect(!written.response_available);
    var bh = try read(&b);
    defer bh.deinit(allocator);
    try expectField(bh.head.headers, "x-dictionary", "kept");
    _ = try a.finishRequest();
    var ah = try read(&a);
    defer ah.deinit(allocator);
    try expectField(ah.head.headers, "x-dictionary", "kept");
}

test "HTTP/2 multiplexed duplex decoded header limits remain stream scoped" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.connection.limits.max_header_fields = 2;
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, a.streamId(), true, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-extra", .value = "too many fields" },
        .{ .name = "x-shared", .value = "indexed" },
    });
    try fixture.headers(&encoder, b.streamId(), true, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-shared", .value = "indexed" },
    });
    var bh = try read(&b);
    defer bh.deinit(allocator);
    try expectField(bh.head.headers, "x-shared", "indexed");
    try std.testing.expectError(error.MessageTooLarge, read(&a));
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try a.reset(.cancel);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeClientDuplexCount());
}

test "HTTP/2 multiplexed duplex ownership registration requires no allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var writer = try fixture.connection.startRequest(.{ .authority = "localhost", .body_length = 0 });
    defer writer.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    fixture.connection.allocator = failing.allocator();
    const result = writer.beginDuplex();
    fixture.connection.allocator = allocator;
    var stream = try result;
    defer stream.deinit();
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(writer.completed);
    try std.testing.expect(fixture.connection.duplex_reader_active);
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeClientDuplexCount());
    try std.testing.expectEqual(@as(usize, 1), fixture.connection.activeLocalStreamCount());
}

test "HTTP/2 multiplexed duplex deferred frame overflow prevents sibling reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.connection.limits.max_pending_ping_frames = 1;
    var a = try fixture.open();
    defer a.deinit();
    var b = try fixture.open();
    defer b.deinit();
    try fixture.frame(.headers, 5, b.streamId(), "\x88");
    try fixture.frame(.headers, 5, a.streamId(), "\x88");
    try std.testing.expectError(error.MessageTooLarge, read(&a));
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, read(&b));
}

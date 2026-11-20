//! Request queue admission, body ownership and response callback contracts.
const std = @import("std");
const http3 = @import("../../../mod.zig");
const command = @import("../stream_command.zig");
const Stream = command.Stream;
const CallbackSink = command.CallbackSink;
const max_pending_write_bytes = command.max_pending_write_bytes;

test "stream response callbacks preserve interims and complete once across poll and read" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const TestPool = struct {};
    var pool: TestPool = .{};
    const Recorder = struct {
        events: [8]u8 = undefined,
        count: usize = 0,
        fn append(self: *@This(), event: u8) void {
            if (self.count < self.events.len) self.events[self.count] = event;
            self.count += 1;
        }
        fn informational(context: *anyopaque, head: http3.DecodedResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.append(if (head.status == 100) 'a' else 'b');
        }
        fn begin(context: *anyopaque, head: http3.DecodedResponseHead) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try std.testing.expectEqual(@as(u16, 200), head.status);
            self.append('H');
        }
        fn data(context: *anyopaque, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try std.testing.expectEqualStrings("body", bytes);
            self.append('D');
        }
        fn end(context: *anyopaque, _: []const http3.Qpack.HeaderField) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.append('E');
        }
        fn makeHead(status: u16) http3.DecodedResponseHead {
            return .{ .status = status, .headers = &.{}, .content_length = null, .body_allowed = status >= 200, .consumed = 0, .qpack_section_acknowledgments = 0 };
        }
    };
    for ([_]bool{ true, false }) |observe_interims| {
        var stream = Stream(TestPool).init(&pool, allocator, io);
        defer stream.deinit();
        try stream.deliverInformational(Recorder.makeHead(100));
        try stream.deliverInformational(Recorder.makeHead(103));
        stream.deliverHead(Recorder.makeHead(200));
        try stream.deliverData("body");
        stream.finish();
        var recorder = Recorder{};
        const sink: CallbackSink = .{ .context = &recorder, .begin = Recorder.begin, .data = Recorder.data, .end = Recorder.end, .informational = if (observe_interims) Recorder.informational else null };
        try std.testing.expect(try stream.pollResponse(sink));
        try std.testing.expect(try stream.pollResponse(sink));
        _ = try stream.readResponse(sink, null);
        try std.testing.expectEqualStrings(if (observe_interims) "abHDE" else "HDE", recorder.events[0..recorder.count]);
    }
}

test "stream blocking body write waits for queue capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const TestPool = struct {};
    var pool: TestPool = .{};
    var stream = Stream(TestPool).init(&pool, allocator, io);
    defer stream.deinit();

    var chunk: [max_pending_write_bytes]u8 = @splat(0);
    try stream.writeBody(&chunk, false);
    try std.testing.expectError(
        error.Backpressure,
        stream.writeBody("x", false),
    );

    const expired = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromNanoseconds(-1),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.Timeout,
        stream.writeBodyBlocking("x", false, expired),
    );

    const drained = stream.takeWrite().?;
    allocator.free(drained.data);
    try stream.writeBodyBlocking("x", true, .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    }));
    const final = stream.takeWrite().?;
    defer allocator.free(final.data);
    try std.testing.expectEqualStrings("x", final.data);
    try std.testing.expect(final.fin);
}

test "H3 streaming queue blocking write splits oversized contributions and closes once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const TestPool = struct {};
    var pool: TestPool = .{};
    var stream = Stream(TestPool).init(&pool, allocator, io);
    defer stream.deinit();
    const source = try allocator.alloc(u8, max_pending_write_bytes * 2 + 3);
    defer allocator.free(source);
    for (source, 0..) |*byte, index| byte.* = @truncate(index);
    const Drain = struct {
        fn run(value: *Stream(TestPool), expected: []const u8) !void {
            var offset: usize = 0;
            while (true) {
                value.activity.reset();
                if (value.takeWrite()) |write| {
                    defer allocator.free(write.data);
                    try std.testing.expect(write.data.len <= max_pending_write_bytes);
                    try std.testing.expectEqualSlices(u8, expected[offset..][0..write.data.len], write.data);
                    offset += write.data.len;
                    if (write.fin) {
                        try std.testing.expectEqual(expected.len, offset);
                        return;
                    }
                } else try value.activity.wait(value.io);
            }
        }
    };
    var draining = try io.concurrent(Drain.run, .{ &stream, source });
    defer _ = draining.cancel(io) catch {};
    try stream.writeBodyBlocking(source, true, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try draining.await(io);
    try std.testing.expectError(error.RequestBodyFinished, stream.writeBody("later", false));
}

test "H3 streaming queue timeout preserves accepted prefix for suffix retry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const TestPool = struct {};
    var pool: TestPool = .{};
    var stream = Stream(TestPool).init(&pool, allocator, io);
    defer stream.deinit();
    const source = try allocator.alloc(u8, max_pending_write_bytes + 3);
    defer allocator.free(source);
    @memset(source, 0x51);
    var accepted: usize = 999;
    try std.testing.expectError(error.Timeout, stream.writeBodyBlockingTracked(source, true, &accepted, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(20) })));
    try std.testing.expectEqual(max_pending_write_bytes, accepted);
    try std.testing.expectEqual(accepted, stream.acceptedBodyBytes());
    try std.testing.expect(!stream.isRequestClosed());
    const first = stream.takeWrite().?;
    defer allocator.free(first.data);
    try std.testing.expect(!first.fin);
    try std.testing.expectEqualSlices(u8, source[0..accepted], first.data);
    const offset = accepted;
    try stream.writeBodyBlockingTracked(source[offset..], true, &accepted, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 3), accepted);
    const last = stream.takeWrite().?;
    defer allocator.free(last.data);
    try std.testing.expect(last.fin);
    try std.testing.expectEqualSlices(u8, source[offset..], last.data);
    try std.testing.expectEqual(source.len, stream.acceptedBodyBytes());
}

test "H3 streaming queue expired writes and repeated message ends accept nothing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const TestPool = struct {};
    var pool: TestPool = .{};
    var stream = Stream(TestPool).init(&pool, std.testing.allocator, io);
    defer stream.deinit();
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    var accepted: usize = 999;
    try std.testing.expectError(error.Timeout, stream.writeBodyBlockingTracked("body", false, &accepted, expired));
    try std.testing.expectEqual(@as(usize, 0), accepted);
    try std.testing.expectEqual(@as(usize, 0), stream.acceptedBodyBytes());
    for (0..100) |_| try stream.writeBody(&.{}, false);
    try std.testing.expect(stream.takeWrite() == null);
    try std.testing.expectError(error.Timeout, stream.writeTrailersWithDeadline(&.{}, expired));
    try std.testing.expect(!stream.isRequestClosed());
    try stream.writeTrailers(&.{.{ .name = "x-end", .value = "done", .never_indexed = true }});
    const end = stream.takeTrailers().?;
    defer {
        var value = end;
        value.deinit(std.testing.allocator);
    }
    try std.testing.expect(end.fields[0].never_indexed);
    try std.testing.expectError(error.RequestBodyFinished, stream.writeBody("later", false));
    try std.testing.expectError(error.RequestBodyFinished, stream.writeBody(&.{}, true));
    try std.testing.expectError(error.RequestBodyFinished, stream.writeTrailers(&.{}));
}

test "H3 streaming queue validates complete body length before accepting a prefix" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const TestPool = struct {};
    var pool: TestPool = .{};
    var stream = Stream(TestPool).init(&pool, std.testing.allocator, io);
    defer stream.deinit();
    stream.expected_body_length = 4;
    var accepted: usize = 999;
    try std.testing.expectError(error.InvalidContentLength, stream.writeBodyBlockingTracked("too-long", false, &accepted, null));
    try std.testing.expectEqual(@as(usize, 0), accepted);
    try std.testing.expect(stream.takeWrite() == null);
    try stream.writeBody("ab", false);
    try std.testing.expectError(error.InvalidContentLength, stream.writeBody(&.{}, true));
    try std.testing.expectError(error.InvalidContentLength, stream.writeTrailers(&.{}));
    try std.testing.expect(!stream.isRequestClosed());
    try stream.writeBody("cd", true);
    try std.testing.expectEqual(@as(usize, 4), stream.acceptedBodyBytes());
}

test "H3 streaming queue cancellation joins the writer and retains copied prefix ownership" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const TestPool = struct {};
    var pool: TestPool = .{};
    var stream = Stream(TestPool).init(&pool, allocator, io);
    defer stream.deinit();
    const source = try allocator.alloc(u8, max_pending_write_bytes + 3);
    defer allocator.free(source);
    @memset(source, 0x43);
    const Caller = struct {
        stream: *Stream(TestPool),
        source: []const u8,
        accepted: usize = 0,
        fn run(self: *@This()) !void {
            try self.stream.writeBodyBlockingTracked(self.source, true, &self.accepted, null);
        }
    };
    var caller = Caller{ .stream = &stream, .source = source };
    var writing = try io.concurrent(Caller.run, .{&caller});
    defer _ = writing.cancel(io) catch {};
    try stream.activity.wait(io);
    try std.testing.expectError(error.Canceled, writing.cancel(io));
    try std.testing.expectEqual(max_pending_write_bytes, caller.accepted);
    try std.testing.expect(!stream.isRequestClosed());
    const retained = stream.takeWrite().?;
    defer allocator.free(retained.data);
    try std.testing.expectEqualSlices(u8, source[0..caller.accepted], retained.data);
    try stream.writeBody(source[caller.accepted..], true);
}

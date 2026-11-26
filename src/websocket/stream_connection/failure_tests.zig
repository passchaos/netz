const std = @import("std");
const stream_connection = @import("../stream_connection.zig");
const allocator = std.testing.allocator;

const Peer = struct {
    input: []const u8 = &.{},
    offset: usize = 0,
    output: std.ArrayList(u8) = .empty,
    writes: usize = 0,
    reads: usize = 0,
    closes: usize = 0,
    fail_write: usize = 2,
    failure: anyerror = error.WriteFailed,

    fn read(context: ?*anyopaque, buffer: []u8) anyerror!usize {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.reads += 1;
        const count = @min(buffer.len, self.input.len - self.offset);
        @memcpy(buffer[0..count], self.input[self.offset..][0..count]);
        self.offset += count;
        return count;
    }

    fn write(context: ?*anyopaque, bytes: []const u8) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.writes += 1;
        if (self.writes == self.fail_write) {
            try self.output.appendSlice(allocator, bytes[0..@min(1, bytes.len)]);
            return self.failure;
        }
        try self.output.appendSlice(allocator, bytes);
    }

    fn close(context: ?*anyopaque) void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.closes += 1;
    }

    fn writeDeadline(context: ?*anyopaque, bytes: []const u8, _: std.Io.Clock.Timestamp) anyerror!void {
        return write(context, bytes);
    }

    fn writeParts(context: ?*anyopaque, header: []const u8, payload: []const u8) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.writes += 1;
        try self.output.appendSlice(allocator, header);
        try self.output.appendSlice(allocator, payload[0..@min(1, payload.len)]);
        return self.failure;
    }

    fn writePartsDeadline(context: ?*anyopaque, header: []const u8, payload: []const u8, _: std.Io.Clock.Timestamp) anyerror!void {
        return writeParts(context, header, payload);
    }

    fn writeSlices(context: ?*anyopaque, header: []const u8, payloads: []const []const u8) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.writes += 1;
        try self.output.appendSlice(allocator, header);
        for (payloads) |payload| {
            if (payload.len == 0) continue;
            try self.output.appendSlice(allocator, payload[0..1]);
            break;
        }
        return self.failure;
    }

    fn writeSlicesDeadline(context: ?*anyopaque, header: []const u8, payloads: []const []const u8, _: std.Io.Clock.Timestamp) anyerror!void {
        return writeSlices(context, header, payloads);
    }

    fn transport(self: *Peer) stream_connection.Transport {
        return .{
            .context = self,
            .read_fn = read,
            .write_fn = write,
            .close_fn = close,
        };
    }
};

test "WebSocket stream adapter retires a partially written slice frame" {
    var peer = Peer{};
    defer peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(
        allocator,
        std.testing.io,
        peer.transport(),
        .{},
    );
    defer connection.deinit();
    try std.testing.expectError(error.WriteFailed, connection.sendTextSlices(&.{ "ab", "cd" }));
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 4, 'a' }, peer.output.items);
    const committed = peer.output.items.len;
    try std.testing.expectError(error.ConnectionClosed, connection.sendText("later"));
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    try std.testing.expectEqual(committed, peer.output.items.len);
    try std.testing.expectEqual(@as(usize, 0), peer.reads);
    try std.testing.expectEqual(@as(usize, 1), peer.closes);
}

test "WebSocket stream adapter retires every invoked write callback error" {
    const Shape = enum { staged_server, staged_client, parts, slices };
    inline for (.{ error.WriteFailed, error.Timeout, error.Canceled }) |failure| {
        inline for (std.meta.tags(Shape)) |shape| {
            inline for (.{ false, true }) |bounded| {
                var peer = Peer{ .fail_write = 1, .failure = failure };
                defer peer.output.deinit(allocator);
                var transport = peer.transport();
                transport.write_deadline_fn = Peer.writeDeadline;
                if (shape == .parts) {
                    transport.write_parts_fn = if (bounded) null else Peer.writeParts;
                    transport.write_parts_deadline_fn = Peer.writePartsDeadline;
                }
                if (shape == .slices) {
                    transport.write_slices_fn = if (bounded) null else Peer.writeSlices;
                    transport.write_slices_deadline_fn = Peer.writeSlicesDeadline;
                }
                var connection = stream_connection.Connection.init(allocator, std.testing.io, transport, .{
                    .role = if (shape == .staged_client) .client else .server,
                });
                var live = true;
                defer if (live) connection.deinit();
                const result = if (shape == .slices)
                    if (bounded) connection.sendBinarySlicesWithTimeout(&.{ "ab", "cd" }, .fromSeconds(1)) else connection.sendBinarySlices(&.{ "ab", "cd" })
                else if (bounded)
                    connection.sendBinaryWithTimeout("abcd", .fromSeconds(1))
                else
                    connection.sendBinary("abcd");
                try std.testing.expectError(failure, result);
                try std.testing.expectEqual(@as(usize, if (shape == .parts or shape == .slices) 3 else 1), peer.output.items.len);
                try std.testing.expect(connection.isClosed());
                try std.testing.expect(!connection.closeSent());
                const committed = peer.output.items.len;
                try std.testing.expectError(error.ConnectionClosed, connection.sendBinary("later"));
                try std.testing.expectError(error.ConnectionClosed, connection.sendClose(.normal_closure, ""));
                connection.close();
                connection.abort();
                connection.deinit();
                live = false;
                try std.testing.expectEqual(committed, peer.output.items.len);
                try std.testing.expectEqual(@as(usize, 1), peer.closes);
            }
        }
    }
}

test "WebSocket stream adapter preserves preflight failures for retry" {
    var peer = Peer{ .fail_write = std.math.maxInt(usize) };
    defer peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(allocator, std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    try std.testing.expectError(error.InvalidUtf8, connection.sendText(&.{0xff}));
    try std.testing.expectError(error.DeadlineUnsupported, connection.sendBinaryWithTimeout("abcd", .fromSeconds(1)));
    try std.testing.expectError(error.Timeout, connection.sendBinaryWithTimeout("abcd", .fromNanoseconds(0)));
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    try std.testing.expectEqual(@as(usize, 0), peer.closes);
    try std.testing.expect(!connection.isClosed());
    try connection.sendBinary("retry");
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 5, 'r', 'e', 't', 'r', 'y' }, peer.output.items);
}

test "WebSocket stream adapter preserves encoding allocation failure for retry" {
    var peer = Peer{ .fail_write = std.math.maxInt(usize) };
    defer peer.output.deinit(allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var connection = stream_connection.Connection.init(failing.allocator(), std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    try std.testing.expectError(error.DeadlineUnsupported, connection.sendBinaryWithTimeout("abcd", .fromSeconds(1)));
    try std.testing.expectError(error.OutOfMemory, connection.sendBinary("abcd"));
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    try std.testing.expect(!connection.isClosed());
    failing.fail_index = std.math.maxInt(usize);
    try connection.sendBinary("retry");
}

test "WebSocket stream adapter retires a frame when its budget expires after the header" {
    try @import("../../internal/testing/native_protocol_io.zig").runStream(headerDeadline);
}

fn headerDeadline(io: std.Io) !void {
    const NativeIo = @import("../../internal/testing/deadline_send_io.zig").Native;
    const ClockPeer = struct {
        peer: Peer = .{ .fail_write = std.math.maxInt(usize) },
        clock: *NativeIo,

        fn write(context: ?*anyopaque, bytes: []const u8, until: std.Io.Clock.Timestamp) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            try Peer.write(&self.peer, bytes);
            self.clock.setNow(@intCast(until.raw.nanoseconds));
        }

        fn read(context: ?*anyopaque, bytes: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return Peer.read(&self.peer, bytes);
        }

        fn writeOrdinary(context: ?*anyopaque, bytes: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return Peer.write(&self.peer, bytes);
        }

        fn close(context: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            Peer.close(&self.peer);
        }
    };
    var clock: NativeIo = .{
        .backend = .init(allocator, .{ .async_limit = .nothing }),
        .delegate_io = io,
    };
    defer clock.backend.deinit();
    var peer = ClockPeer{ .clock = &clock };
    defer peer.peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(allocator, clock.io(), .{
        .context = &peer,
        .read_fn = ClockPeer.read,
        .write_fn = ClockPeer.writeOrdinary,
        .write_deadline_fn = ClockPeer.write,
        .close_fn = ClockPeer.close,
    }, .{});
    defer connection.deinit();
    try std.testing.expectError(error.Timeout, connection.sendTextSlicesWithDeadline(&.{ "ab", "cd" }, .{
        .clock = .awake,
        .raw = .fromNanoseconds(1000),
    }));
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 4 }, peer.peer.output.items);
    try std.testing.expectEqual(@as(usize, 1), peer.peer.writes);
    try std.testing.expectEqual(@as(usize, 1), peer.peer.closes);
    try std.testing.expect(connection.isClosed());
}

test "WebSocket stream adapter retains peer Close metadata after a failed automatic reply" {
    var peer = Peer{
        .input = &.{ 0x88, 0x82, 1, 2, 3, 4, 0x03 ^ 1, 0xe8 ^ 2 },
        .fail_write = 1,
    };
    defer peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(allocator, std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    try std.testing.expect(connection.isClosed());
    try std.testing.expect(connection.closeReceived());
    try std.testing.expect(!connection.closeSent());
    try std.testing.expectEqual(@import("../mod.zig").CloseCode.normal_closure, connection.peerClose().?.code);
    const reads = peer.reads;
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    try std.testing.expectEqual(reads, peer.reads);
    try std.testing.expectEqual(@as(usize, 1), peer.closes);
}

test "WebSocket stream adapter retires a failed automatic Pong write" {
    var peer = Peer{ .input = &.{ 0x89, 0x81, 1, 2, 3, 4, 'q' ^ 1 }, .fail_write = 1 };
    defer peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(allocator, std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    try std.testing.expectError(error.WriteFailed, connection.receiveMessage());
    try std.testing.expect(connection.isClosed());
    try std.testing.expectEqualSlices(u8, &.{0x8a}, peer.output.items);
    try std.testing.expectEqual(@as(usize, 1), peer.closes);
}

test "WebSocket stream adapter hides buffered frames after a write failure" {
    var peer = Peer{
        .input = &.{
            0x82, 0x81, 1, 2, 3, 4, 'a' ^ 1,
            0x82, 0x81, 1, 2, 3, 4, 'b' ^ 1,
        },
        .fail_write = 1,
    };
    defer peer.output.deinit(allocator);
    var connection = stream_connection.Connection.init(allocator, std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    var message = try connection.receiveMessage();
    defer message.deinit(allocator);
    const buffered = connection.buffer.items.len;
    const cursor = connection.start;
    try std.testing.expect(buffered > cursor);
    try std.testing.expectError(error.WriteFailed, connection.sendBinary("outbound"));
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    try std.testing.expectEqual(buffered, connection.buffer.items.len);
    try std.testing.expectEqual(cursor, connection.start);
    try std.testing.expectEqualStrings("a", message.payload);
    try std.testing.expectEqual(@as(usize, 1), peer.reads);
}

const std = @import("std");
const websocket = @import("../mod.zig");
const stream = @import("../stream_connection.zig");
const allocator = std.testing.allocator;

const Peer = struct {
    input: []const u8 = &.{},
    offset: usize = 0,
    chunk: usize = std.math.maxInt(usize),
    reads: usize = 0,
    writes: usize = 0,
    pause_at: ?usize = null,
    paused: bool = false,
    output: std.ArrayList(u8) = .empty,

    fn read(context: ?*anyopaque, bytes: []u8) anyerror!usize {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.reads += 1;
        if (self.pause_at) |offset| {
            if (!self.paused and self.offset >= offset) {
                self.paused = true;
                return error.Timeout;
            }
        }
        const count = @min(self.chunk, @min(bytes.len, self.input.len - self.offset));
        @memcpy(bytes[0..count], self.input[self.offset..][0..count]);
        self.offset += count;
        return count;
    }

    fn write(context: ?*anyopaque, bytes: []const u8) anyerror!void {
        const self: *Peer = @ptrCast(@alignCast(context.?));
        self.writes += 1;
        try self.output.appendSlice(allocator, bytes);
    }

    fn readDeadline(context: ?*anyopaque, bytes: []u8, _: std.Io.Clock.Timestamp) anyerror!usize {
        return read(context, bytes);
    }

    fn writeDeadline(context: ?*anyopaque, bytes: []const u8, _: std.Io.Clock.Timestamp) anyerror!void {
        return write(context, bytes);
    }

    fn parts(context: ?*anyopaque, header: []const u8, payload: []const u8) anyerror!void {
        try write(context, header);
        try write(context, payload);
    }

    fn partsDeadline(context: ?*anyopaque, header: []const u8, payload: []const u8, _: std.Io.Clock.Timestamp) anyerror!void {
        return parts(context, header, payload);
    }

    fn slices(context: ?*anyopaque, header: []const u8, payloads: []const []const u8) anyerror!void {
        try write(context, header);
        for (payloads) |payload| try write(context, payload);
    }

    fn slicesDeadline(context: ?*anyopaque, header: []const u8, payloads: []const []const u8, _: std.Io.Clock.Timestamp) anyerror!void {
        return slices(context, header, payloads);
    }

    fn transport(self: *Peer) stream.Transport {
        return .{ .context = self, .read_fn = read, .write_fn = write };
    }

    fn boundedTransport(self: *Peer) stream.Transport {
        return .{
            .context = self,
            .read_fn = read,
            .read_deadline_fn = readDeadline,
            .write_fn = write,
            .write_deadline_fn = writeDeadline,
        };
    }
};

test "WebSocket stream adapter rejects outbound message limits before writing" {
    var peer = Peer{};
    defer peer.output.deinit(allocator);
    var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{ .max_message_bytes = 2 });
    defer connection.deinit();
    try std.testing.expectError(error.PayloadTooLarge, connection.sendBinary("abc"));
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    try std.testing.expect(!connection.isClosed());
}

test "WebSocket stream adapter receives a short frame with a split masked header" {
    var peer = Peer{ .input = &.{ 0x82, 0x81, 1, 2, 3, 4, 'a' ^ 1 }, .chunk = 1 };
    defer peer.output.deinit(allocator);
    var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    var message = try connection.receiveMessage();
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("a", message.payload);
    try std.testing.expectEqual(@as(usize, 7), peer.offset);
}

test "WebSocket stream adapter rejects aggregate message length at the continuation header" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try websocket.writeFrame(&input, allocator, .binary, "ab", .{ .fin = false, .mask_key = .{ 1, 2, 3, 4 } });
    const first_length = input.items.len;
    var header: [websocket.max_frame_header_len]u8 = undefined;
    try input.appendSlice(allocator, try websocket.writeFrameHeaderForLengthInto(&header, .continuation, 2, .{ .mask_key = .{ 1, 2, 3, 4 } }));
    var peer = Peer{ .input = input.items, .chunk = 1 };
    defer peer.output.deinit(allocator);
    var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{ .max_message_bytes = 3 });
    defer connection.deinit();
    try std.testing.expectError(error.PayloadTooLarge, connection.receiveMessage());
    try std.testing.expectEqual(first_length + 6, peer.offset);
    try std.testing.expect(connection.isClosed());
}

test "WebSocket stream adapter enforces send limits across callback shapes and roles" {
    const Shape = enum { staged, parts, slices, scatter };
    inline for (.{ stream.Role.server, stream.Role.client }) |role| {
        inline for (std.meta.tags(Shape)) |shape| {
            inline for (.{ false, true }) |bounded| {
                var peer = Peer{};
                defer peer.output.deinit(allocator);
                var transport = peer.boundedTransport();
                if (shape == .parts) {
                    transport.write_parts_fn = Peer.parts;
                    transport.write_parts_deadline_fn = Peer.partsDeadline;
                }
                if (shape == .slices) {
                    transport.write_slices_fn = Peer.slices;
                    transport.write_slices_deadline_fn = Peer.slicesDeadline;
                }
                const wire_limit: usize = if (role == .client) 8 else 4;
                var connection = stream.Connection.init(allocator, std.testing.io, transport, .{
                    .role = role,
                    .max_message_bytes = 2,
                    .max_frame_bytes = wire_limit,
                });
                defer connection.deinit();
                const rejected = if (shape == .slices or shape == .scatter)
                    if (bounded) connection.sendBinarySlicesWithTimeout(&.{ "a", "bc" }, .fromSeconds(1)) else connection.sendBinarySlices(&.{ "a", "bc" })
                else if (bounded)
                    connection.sendBinaryWithTimeout("abc", .fromSeconds(1))
                else
                    connection.sendBinary("abc");
                try std.testing.expectError(error.PayloadTooLarge, rejected);
                try std.testing.expectEqual(@as(usize, 0), peer.writes);
                try std.testing.expectEqual(@as(usize, 0), connection.write_buffer.capacity);
                try std.testing.expect(!connection.isClosed());
                if (shape == .slices or shape == .scatter) {
                    if (bounded) try connection.sendBinarySlicesWithTimeout(&.{ "a", "b" }, .fromSeconds(1)) else try connection.sendBinarySlices(&.{ "a", "b" });
                } else if (bounded) try connection.sendBinaryWithTimeout("ab", .fromSeconds(1)) else try connection.sendBinary("ab");
                try std.testing.expectEqual(wire_limit, peer.output.items.len);
                var frame = try websocket.parseFrame(allocator, peer.output.items);
                defer frame.deinit(allocator);
                try std.testing.expectEqualStrings("ab", frame.payload);
                try std.testing.expectEqual(role == .client, frame.header.masked);
            }
        }
    }
}

test "WebSocket stream adapter counts outbound masking and extended header bytes" {
    inline for (.{ stream.Role.server, stream.Role.client }) |role| {
        for ([_]usize{ 0, 125, 126, 65535, 65536 }) |length| {
            const payload = try allocator.alloc(u8, length);
            defer allocator.free(payload);
            @memset(payload, 'x');
            var storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderForLengthInto(&storage, .binary, length, .{
                .mask_key = if (role == .client) .{ 1, 2, 3, 4 } else null,
            });
            var peer = Peer{};
            defer peer.output.deinit(allocator);
            var transport = peer.transport();
            transport.write_parts_fn = Peer.parts;
            var connection = stream.Connection.init(allocator, std.testing.io, transport, .{
                .role = role,
                .max_message_bytes = length,
                .max_frame_bytes = header.len + length - 1,
            });
            defer connection.deinit();
            try std.testing.expectError(error.PayloadTooLarge, connection.sendBinary(payload));
            try std.testing.expectEqual(@as(usize, 0), peer.writes);
            connection.options.max_frame_bytes += 1;
            try connection.sendBinary(payload);
            try std.testing.expectEqual(header.len + length, peer.output.items.len);
        }
    }
}

test "WebSocket stream adapter excludes control traffic from the message limit" {
    var peer = Peer{};
    defer peer.output.deinit(allocator);
    var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{
        .max_message_bytes = 0,
        .max_frame_bytes = 125 + 2,
    });
    defer connection.deinit();
    try std.testing.expectError(error.PayloadTooLarge, connection.sendBinary("x"));
    try connection.sendPing("control");
    try connection.sendClose(.normal_closure, "");
    try std.testing.expect(connection.closeSent());
}

test "WebSocket stream adapter rejects oversized headers before payload allocation or reads" {
    var storage: [websocket.max_frame_header_len]u8 = undefined;
    const header = try websocket.writeFrameHeaderForLengthInto(&storage, .binary, 1024 * 1024, .{ .mask_key = .{ 1, 2, 3, 4 } });
    var peer = Peer{ .input = header, .chunk = 1 };
    defer peer.output.deinit(allocator);
    var transport = peer.transport();
    transport.write_parts_fn = Peer.parts;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    var connection = stream.Connection.init(failing.allocator(), std.testing.io, transport, .{ .max_message_bytes = 2 });
    defer connection.deinit();
    try std.testing.expectError(error.PayloadTooLarge, connection.receiveMessage());
    try std.testing.expectEqual(header.len, peer.offset);
    try std.testing.expectEqual(@as(usize, 1), failing.alloc_index);
    try std.testing.expect(connection.buffer.capacity <= 139);
    var close_frame = try websocket.parseFrame(allocator, peer.output.items);
    defer close_frame.deinit(allocator);
    try std.testing.expectEqual(websocket.CloseCode.message_too_big, (try websocket.parseClosePayload(close_frame.payload)).?.code);
    try std.testing.expect(connection.isClosed());
    const reads = peer.reads;
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    try std.testing.expectEqual(reads, peer.reads);
}

test "WebSocket stream adapter retries fragmented assembly allocation failures without losing input" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try websocket.writeFrame(&input, allocator, .text, "ab", .{ .fin = false, .mask_key = .{ 1, 2, 3, 4 } });
    try websocket.writeFrame(&input, allocator, .continuation, "cd", .{ .mask_key = .{ 1, 2, 3, 4 } });
    var failures: usize = 0;
    for (0..8) |index| {
        var peer = Peer{ .input = input.items };
        defer peer.output.deinit(allocator);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
        var connection = stream.Connection.init(failing.allocator(), std.testing.io, peer.transport(), .{ .max_message_bytes = 4 });
        defer connection.deinit();
        var message = connection.receiveMessage() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(!connection.isClosed());
            failures += 1;
            failing.fail_index = std.math.maxInt(usize);
            var recovered = try connection.receiveMessage();
            defer recovered.deinit(failing.allocator());
            try std.testing.expectEqualStrings("abcd", recovered.payload);
            continue;
        };
        defer message.deinit(failing.allocator());
        try std.testing.expectEqualStrings("abcd", message.payload);
        break;
    }
    try std.testing.expect(failures >= 3);
}

test "WebSocket stream adapter reads all header widths without waiting for the next frame" {
    inline for (.{ stream.Role.server, stream.Role.client }) |role| {
        for ([_]usize{ 0, 125, 126, 65536 }) |length| {
            const payload = try allocator.alloc(u8, length);
            defer allocator.free(payload);
            @memset(payload, 'x');
            var input: std.ArrayList(u8) = .empty;
            defer input.deinit(allocator);
            try websocket.writeFrame(&input, allocator, .binary, payload, .{
                .mask_key = if (role == .server) .{ 1, 2, 3, 4 } else null,
            });
            var peer = Peer{ .input = input.items, .chunk = 1 };
            defer peer.output.deinit(allocator);
            var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{
                .role = role,
                .max_message_bytes = length,
                .max_frame_bytes = input.items.len,
            });
            defer connection.deinit();
            var message = try connection.receiveMessage();
            defer message.deinit(allocator);
            try std.testing.expectEqualSlices(u8, payload, message.payload);
            try std.testing.expectEqual(input.items.len, peer.offset);
        }
    }
}

test "WebSocket stream adapter rejects malformed headers before reading payload" {
    const Case = struct { header: []const u8, role: stream.Role = .server, err: anyerror };
    for ([_]Case{
        .{ .header = &.{ 0x83, 0 }, .err = error.InvalidOpcode },
        .{ .header = &.{ 0xc2, 0x81, 1, 2, 3, 4 }, .err = error.UnexpectedRsv },
        .{ .header = &.{ 0x82, 1 }, .err = error.UnmaskedClientFrame },
        .{ .header = &.{ 0x82, 0x81, 1, 2, 3, 4 }, .role = .client, .err = error.MaskedServerFrame },
        .{ .header = &.{ 0x82, 0xfe, 0, 1, 1, 2, 3, 4 }, .err = error.NonMinimalLength },
        .{ .header = &.{ 0x80, 0x81, 1, 2, 3, 4 }, .err = error.InvalidFrame },
    }) |case| {
        var peer = Peer{ .input = case.header, .chunk = 1 };
        defer peer.output.deinit(allocator);
        var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{ .role = case.role });
        defer connection.deinit();
        try std.testing.expectError(case.err, connection.receiveMessage());
        try std.testing.expectEqual(case.header.len, peer.offset);
        try std.testing.expect(connection.isClosed());
        try std.testing.expect(!connection.closeReceived());
        var close = try websocket.parseFrame(allocator, peer.output.items);
        defer close.deinit(allocator);
        try std.testing.expectEqual(websocket.CloseCode.protocol_error, (try websocket.parseClosePayload(close.payload)).?.code);
    }
}

test "WebSocket stream adapter preserves partial headers and assembly through receive timeouts" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try websocket.writeFrame(&input, allocator, .binary, "ab", .{ .fin = false, .mask_key = .{ 1, 2, 3, 4 } });
    const first = input.items.len;
    try websocket.writeFrame(&input, allocator, .continuation, "cd", .{ .mask_key = .{ 1, 2, 3, 4 } });
    for ([_]usize{ 3, first + 6 }) |offset| {
        var peer = Peer{ .input = input.items, .chunk = 1, .pause_at = offset };
        defer peer.output.deinit(allocator);
        var connection = stream.Connection.init(allocator, std.testing.io, peer.boundedTransport(), .{ .max_message_bytes = 4 });
        defer connection.deinit();
        try std.testing.expectError(error.Timeout, connection.receiveMessageWithTimeout(.fromSeconds(1)));
        try std.testing.expect(!connection.isClosed());
        try std.testing.expectEqual(offset, peer.offset);
        var message = try connection.receiveMessageWithTimeout(.fromSeconds(1));
        defer message.deinit(allocator);
        try std.testing.expectEqualStrings("abcd", message.payload);
        try std.testing.expectEqual(input.items.len, peer.offset);
    }
}

test "WebSocket stream adapter retries an automatic Pong rejected before writing" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try websocket.writeFrame(&input, allocator, .ping, "q", .{ .mask_key = .{ 1, 2, 3, 4 } });
    try websocket.writeFrame(&input, allocator, .binary, "data", .{ .mask_key = .{ 1, 2, 3, 4 } });
    var peer = Peer{ .input = input.items };
    defer peer.output.deinit(allocator);
    var transport = peer.boundedTransport();
    transport.write_deadline_fn = null;
    var connection = stream.Connection.init(allocator, std.testing.io, transport, .{});
    defer connection.deinit();
    try std.testing.expectError(error.DeadlineUnsupported, connection.receiveMessageWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqual(@as(usize, 0), connection.start);
    try std.testing.expectEqual(@as(usize, 0), peer.writes);
    try std.testing.expect(!connection.isClosed());
    var message = try connection.receiveMessage();
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("data", message.payload);
    try std.testing.expectEqualSlices(u8, &.{ 0x8a, 1, 'q' }, peer.output.items);
}

test "WebSocket stream adapter rejects receive capability before allocating" {
    var peer = Peer{};
    defer peer.output.deinit(allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var connection = stream.Connection.init(failing.allocator(), std.testing.io, peer.transport(), .{});
    defer connection.deinit();
    try std.testing.expectError(error.DeadlineUnsupported, connection.receiveMessageWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectEqual(@as(usize, 0), peer.reads);
}

test "WebSocket stream adapter receives maximum control traffic with zero message budget" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    const payload = "q" ** 125;
    try websocket.writeFrame(&input, allocator, .ping, payload, .{ .mask_key = .{ 1, 2, 3, 4 } });
    try websocket.writeFrame(&input, allocator, .close, &.{ 3, 0xe8 }, .{ .mask_key = .{ 1, 2, 3, 4 } });
    var peer = Peer{ .input = input.items };
    defer peer.output.deinit(allocator);
    var connection = stream.Connection.init(allocator, std.testing.io, peer.transport(), .{
        .max_message_bytes = 0,
        .max_frame_bytes = 131,
    });
    defer connection.deinit();
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
    try std.testing.expect(connection.closeReceived());
    try std.testing.expectEqual(websocket.CloseCode.normal_closure, connection.peerClose().?.code);
    try std.testing.expect(connection.buffer.capacity <= 139);
    var pong = try websocket.parseFrame(allocator, peer.output.items);
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings(payload, pong.payload);
}

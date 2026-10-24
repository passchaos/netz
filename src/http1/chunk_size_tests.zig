const std = @import("std");
const http1 = @import("mod.zig");
const runtime = @import("runtime.zig");
const framing = @import("runtime/message/framing.zig");
const Reader = @import("runtime/body_reader.zig").Reader(anyerror);
const allocator = std.testing.allocator;

const Padding = enum { spaces, zeroes };

fn appendPaddedChunk(bytes: *std.ArrayList(u8), padding: Padding) !void {
    if (padding == .spaces) {
        try bytes.append(allocator, '1');
        try bytes.appendNTimes(allocator, ' ', http1.max_chunk_size_line_bytes - 2);
    } else {
        try bytes.appendNTimes(allocator, '0', http1.max_chunk_size_line_bytes - 2);
        try bytes.append(allocator, '1');
    }
    try bytes.appendSlice(allocator, "\r\nx\r\n");
}

fn expectPureFailure(bytes: []const u8) !void {
    if (http1.decodeChunked(allocator, bytes, .{})) |value| {
        var decoded = value;
        decoded.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.ChunkExtensionTooLarge, err);
}

test "HTTP/1 pure chunked decoding bounds cumulative size metadata" {
    for (std.enums.values(Padding)) |padding| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        for (0..2) |_| try appendPaddedChunk(&bytes, padding);
        try bytes.appendSlice(allocator, "0\r\n\r\n");
        // Every individual size line is legal. Repetition exceeds the shared
        // per-message allowance despite carrying only two application bytes.
        try std.testing.expectError(error.BodyTooLarge, framing.chunkedBodyLayout(bytes.items, 1024, 2));
        try expectPureFailure(bytes.items);
    }
}

const Source = struct {
    bytes: []const u8,
    step: usize,
    offset: usize = 0,
    fn read(context: ?*anyopaque, out: []u8) anyerror!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        const len = @min(self.step, @min(out.len, self.bytes.len - self.offset));
        @memcpy(out[0..len], self.bytes[self.offset..][0..len]);
        self.offset += len;
        return len;
    }
};
const Sink = struct {
    bytes: usize = 0,
    fn request(_: *@This(), _: Reader.RequestHead) anyerror!void {}
    fn response(_: *@This(), _: Reader.ResponseHead) anyerror!void {}
    fn consume(self: *@This(), bytes: []const u8) anyerror!void {
        self.bytes += bytes.len;
    }
};

test "HTTP/1 streaming chunked readers bound cumulative size metadata" {
    for ([_]bool{ false, true }) |request| {
        for (std.enums.values(Padding)) |padding| {
            for ([_]usize{ 1, 4096 }) |step| {
                var wire: std.ArrayList(u8) = .empty;
                defer wire.deinit(allocator);
                try wire.appendSlice(allocator, if (request) "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" else "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                for (0..2) |_| try appendPaddedChunk(&wire, padding);
                try wire.appendSlice(allocator, "0\r\n\r\n");
                var source = Source{ .bytes = wire.items, .step = step };
                var input: std.ArrayList(u8) = .empty;
                defer input.deinit(allocator);
                var reader = Reader{ .allocator = allocator, .context = &source, .read_some = Source.read, .inbuf = &input, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 2 }, .options = .{} };
                var sink: Sink = .{};
                if (request) {
                    if (reader.readRequest(&sink, Sink.request, Sink.consume)) |value| {
                        var received = value;
                        received.deinit(allocator);
                        return error.TestUnexpectedResult;
                    } else |err| try std.testing.expectEqual(error.BodyTooLarge, err);
                } else {
                    if (reader.readResponse(.GET, &sink, Sink.response, Sink.consume)) |value| {
                        var received = value;
                        received.deinit(allocator);
                        return error.TestUnexpectedResult;
                    } else |err| try std.testing.expectEqual(error.BodyTooLarge, err);
                }
                // The second chunk's payload must not be delivered after its
                // metadata exhausted the allowance.
                try std.testing.expectEqual(@as(usize, 1), sink.bytes);
            }
        }
    }
}

test "HTTP/1 chunked metadata budget includes the final zero chunk" {
    for (std.enums.values(Padding)) |padding| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try appendPaddedChunk(&bytes, padding);
        const prefix_len = bytes.items.len;
        try bytes.appendSlice(allocator, "000\r\n\r\n");
        var exact = try http1.decodeChunked(allocator, bytes.items, .{});
        defer exact.deinit(allocator);
        try std.testing.expectEqualStrings("x", exact.body);
        try std.testing.expectEqual(bytes.items.len, (try framing.chunkedBodyLayout(bytes.items, 1024, 1)).wire_len);
        bytes.items.len = prefix_len;
        try bytes.appendSlice(allocator, "0000\r\n\r\n");
        try expectPureFailure(bytes.items);
    }
}

test "HTTP/1 chunked size line permits split CRLF at its exclusive bound" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try appendPaddedChunk(&bytes, .spaces);
    try bytes.appendSlice(allocator, "000\r\n\r\n");
    const cr = http1.max_chunk_size_line_bytes - 1;
    try std.testing.expectError(error.BufferTooShort, http1.decodeChunked(allocator, bytes.items[0 .. cr + 1], .{}));
    try std.testing.expectError(error.BufferTooShort, framing.chunkedBodyLayout(bytes.items[0 .. cr + 1], 1024, 1));
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try wire.appendSlice(allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    try wire.appendSlice(allocator, bytes.items);
    for ([_]usize{ 1, 4096 }) |step| {
        var source = Source{ .bytes = wire.items, .step = step };
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(allocator);
        var reader = Reader{ .allocator = allocator, .context = &source, .read_some = Source.read, .inbuf = &input, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 1 }, .options = .{} };
        var sink: Sink = .{};
        var received = try reader.readResponse(.GET, &sink, Sink.response, Sink.consume);
        defer received.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), sink.bytes);
    }
    var excessive: std.ArrayList(u8) = .empty;
    defer excessive.deinit(allocator);
    try excessive.append(allocator, '1');
    try excessive.appendNTimes(allocator, ' ', http1.max_chunk_size_line_bytes - 1);
    try std.testing.expectError(error.ChunkExtensionTooLarge, http1.decodeChunked(allocator, excessive.items, .{}));
    try excessive.append(allocator, '\r');
    try std.testing.expectError(error.ChunkExtensionTooLarge, http1.decodeChunked(allocator, excessive.items, .{}));
}

test "HTTP/1 chunked metadata permits many minimal chunks and independent trailers" {
    const chunk_count = http1.max_chunk_size_line_bytes + 1;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    for (0..chunk_count) |_| try bytes.appendSlice(allocator, "1\r\nx\r\n");
    try bytes.appendSlice(allocator, "0\r\nDigest: kept\r\n\r\n");
    var decoded = try http1.decodeChunked(allocator, bytes.items, .{});
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(chunk_count, decoded.body.len);
    try std.testing.expectEqualStrings("kept", decoded.trailers[0].value);
    const layout = try framing.chunkedBodyLayout(bytes.items, 64, chunk_count);
    try std.testing.expectEqual(bytes.items.len, layout.wire_len);
    try std.testing.expectEqual(chunk_count, layout.decoded_len);
}

test "HTTP/1 real TCP streaming metadata rejection retires the connection" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ false, true }) |request| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const receiver = try listener.socket.address.connect(io, .{ .mode = .stream });
        const sender = try listener.accept(io);
        defer sender.close(io);
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(allocator);
        try wire.appendSlice(allocator, if (request) "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" else "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        for (0..2) |_| try appendPaddedChunk(&wire, .spaces);
        try wire.appendSlice(allocator, "0\r\n\r\n");
        var writer = sender.writer(io, &.{});
        try writer.interface.writeAll(wire.items);
        var sink: Sink = .{};
        if (request) {
            var connection = runtime.Connection{ .allocator = allocator, .io = io, .stream = receiver, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 2 } };
            defer connection.close();
            try std.testing.expectError(error.BodyTooLarge, connection.readRequestStreaming(&sink, Sink.consume));
            try std.testing.expect(connection.writer_state.phase == .unusable);
            try std.testing.expectError(error.ConnectionUnusable, connection.readRequest(.{}));
        } else {
            var client = try runtime.Client.adoptStream(allocator, io, receiver, "localhost", .{ .max_head_bytes = 1024, .max_body_bytes = 2 });
            defer client.close();
            try std.testing.expectError(error.BodyTooLarge, client.requestStreamingWithTimeout(.{ .target = "/" }, .fromSeconds(1), &sink, Sink.consume));
            try std.testing.expect(!client.isReusable());
            try std.testing.expectError(error.ConnectionUnusable, client.request(.{ .target = "/late" }));
        }
        try std.testing.expectEqual(@as(usize, 1), sink.bytes);
    }
}

test "HTTP/1 chunked canonical size digits do not consume padding allowance" {
    const chunk_count = http1.max_chunk_size_line_bytes / 2 + 1;
    const chunk_bytes = 256;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    for (0..chunk_count) |_| {
        try bytes.appendSlice(allocator, "100\r\n");
        try bytes.appendNTimes(allocator, 'x', chunk_bytes);
        try bytes.appendSlice(allocator, "\r\n");
    }
    try bytes.appendSlice(allocator, "0\r\n\r\n");
    const length = chunk_count * chunk_bytes;
    const layout = try framing.chunkedBodyLayout(bytes.items, 64, length);
    try std.testing.expectEqual(length, layout.decoded_len);
    var decoded = try http1.decodeChunked(allocator, bytes.items, .{});
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(length, decoded.body.len);
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try wire.appendSlice(allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    try wire.appendSlice(allocator, bytes.items);
    var source = Source{ .bytes = wire.items, .step = 64 * 1024 };
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    var reader = Reader{ .allocator = allocator, .context = &source, .read_some = Source.read, .inbuf = &input, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = length }, .options = .{} };
    var sink: Sink = .{};
    var received = try reader.readResponse(.GET, &sink, Sink.response, Sink.consume);
    defer received.deinit(allocator);
    try std.testing.expectEqual(length, sink.bytes);
}

test "HTTP/1 streaming chunk metadata allowance resets between pipeline messages" {
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    for (0..2) |_| {
        try wire.appendSlice(allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        try appendPaddedChunk(&wire, .spaces);
        try wire.appendSlice(allocator, "000\r\n\r\n");
    }
    var source = Source{ .bytes = wire.items, .step = 4096 };
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    var reader = Reader{ .allocator = allocator, .context = &source, .read_some = Source.read, .inbuf = &input, .limits = .{ .max_head_bytes = 1024, .max_body_bytes = 1 }, .options = .{} };
    var sink: Sink = .{};
    for (0..2) |_| {
        var received = try reader.readResponse(.GET, &sink, Sink.response, Sink.consume);
        defer received.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), received.body_bytes);
    }
    try std.testing.expectEqual(@as(usize, 2), sink.bytes);
}

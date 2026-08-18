const std = @import("std");
const codec = @import("codec.zig");
const compression = @import("../compression.zig");
const runtime = @import("runtime.zig");
const wire = @import("../wire.zig");
const http2 = @import("../../http2/mod.zig");

test "gRPC stream decoder handles every split and several messages per feed" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.writeMessage(&encoded, allocator, "first", false);
    try wire.writeMessage(&encoded, allocator, "", false);
    try wire.writeMessage(&encoded, allocator, "third", false);

    const Collector = struct {
        count: usize = 0,
        bytes: std.ArrayList(u8) = .empty,

        fn consume(
            self: *@This(),
            message: codec.DecodedMessage,
        ) !void {
            try self.bytes.append(
                std.testing.allocator,
                @intCast(message.payload.len),
            );
            try self.bytes.appendSlice(
                std.testing.allocator,
                message.payload,
            );
            self.count += 1;
            try std.testing.expect(!message.was_compressed);
        }
    };

    for (0..encoded.items.len + 1) |split| {
        var decoder = try codec.Decoder.init(
            allocator,
            64,
            null,
            .{},
        );
        defer decoder.deinit();
        var collector: Collector = .{};
        defer collector.bytes.deinit(allocator);
        try decoder.feed(
            encoded.items[0..split],
            &collector,
            Collector.consume,
        );
        try decoder.feed(
            encoded.items[split..],
            &collector,
            Collector.consume,
        );
        try decoder.finish();
        try std.testing.expectEqual(@as(usize, 3), collector.count);
        try std.testing.expectEqualSlices(
            u8,
            &.{ 5, 'f', 'i', 'r', 's', 't', 0, 5, 't', 'h', 'i', 'r', 'd' },
            collector.bytes.items,
        );
    }
}

test "gRPC stream decoder applies compression per message" {
    const allocator = std.testing.allocator;
    const compressible = "stream-compressed-" ** 64;
    var compressed = try compression.compressAlloc(
        allocator,
        .gzip,
        compressible,
        1,
    );
    defer compressed.deinit(allocator);
    try std.testing.expect(compressed.compressed);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.writeMessage(
        &encoded,
        allocator,
        compressed.bytes,
        true,
    );
    try wire.writeMessage(&encoded, allocator, "identity", false);

    const Collector = struct {
        calls: usize = 0,
        compressed_seen: bool = false,

        fn consume(
            self: *@This(),
            message: codec.DecodedMessage,
        ) !void {
            if (self.calls == 0) {
                try std.testing.expectEqualStrings(
                    compressible,
                    message.payload,
                );
                self.compressed_seen = message.was_compressed;
            } else {
                try std.testing.expectEqualStrings(
                    "identity",
                    message.payload,
                );
                try std.testing.expect(!message.was_compressed);
            }
            self.calls += 1;
        }
    };

    var decoder = try codec.Decoder.init(
        allocator,
        compressible.len,
        "gzip",
        .{ .gzip = true },
    );
    defer decoder.deinit();
    var collector: Collector = .{};
    // Force both prefix and compressed payload to cross callback boundaries.
    for (encoded.items, 0..) |_, index| {
        try decoder.feed(
            encoded.items[index .. index + 1],
            &collector,
            Collector.consume,
        );
    }
    try decoder.finish();
    try std.testing.expectEqual(@as(usize, 2), collector.calls);
    try std.testing.expect(collector.compressed_seen);
}

test "gRPC stream decoder rejects malformed and truncated messages" {
    const allocator = std.testing.allocator;
    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {}
    };

    var invalid_flag = try codec.Decoder.init(allocator, 16, null, .{});
    defer invalid_flag.deinit();
    try std.testing.expectError(
        error.InvalidCompressedFlag,
        invalid_flag.feed(
            &.{ 2, 0, 0, 0, 0 },
            {},
            Consumer.consume,
        ),
    );
    try std.testing.expectError(error.BufferTooShort, invalid_flag.finish());

    var compressed_without_header =
        try codec.Decoder.init(allocator, 16, null, .{});
    defer compressed_without_header.deinit();
    try std.testing.expectError(
        error.CompressionNotNegotiated,
        compressed_without_header.feed(
            &.{ 1, 0, 0, 0, 0 },
            {},
            Consumer.consume,
        ),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        compressed_without_header.finish(),
    );

    var oversized = try codec.Decoder.init(allocator, 4, null, .{});
    defer oversized.deinit();
    try std.testing.expectError(
        error.GrpcMessageTooLarge,
        oversized.feed(
            &.{ 0, 0, 0, 0, 5 },
            {},
            Consumer.consume,
        ),
    );

    var truncated = try codec.Decoder.init(allocator, 16, null, .{});
    defer truncated.deinit();
    try truncated.feed(
        &.{ 0, 0, 0, 0, 3, 'a' },
        {},
        Consumer.consume,
    );
    try std.testing.expectError(error.BufferTooShort, truncated.finish());
}

test "gRPC stream encoder uses independent compression contexts" {
    const allocator = std.testing.allocator;
    const payload = "independent-compression-context-" ** 64;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const encoder = codec.Encoder{
        .allocator = allocator,
        .algorithm = .gzip,
        .compression_level = 1,
        .max_message_size = payload.len,
    };
    try encoder.appendMessage(&encoded, payload);
    try encoder.appendMessage(&encoded, payload);

    var iterator = wire.MessageIterator.init(encoded.items, payload.len);
    const first = (try iterator.next()).?;
    const second = (try iterator.next()).?;
    try std.testing.expect(first.compressed);
    try std.testing.expect(second.compressed);
    // Equal standalone gzip members prove no compressor history leaked from
    // the first gRPC message into the second.
    try std.testing.expectEqualSlices(u8, first.payload, second.payload);
    try std.testing.expect(try iterator.next() == null);
}

test "gRPC request and response message streams cross HTTP2 DATA frames" {
    const allocator = std.testing.allocator;
    const large_request = "request-compressible-" ** 128;
    const large_response = "response-compressible-" ** 128;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // Keep enough room for connection SETTINGS. Large messages still span
    // many DATA frames; the first request below explicitly splits its gRPC
    // prefix across two writer calls to cover the stricter boundary case.
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 24,
        .max_body_bytes = 64 * 1024,
        .initial_window_size = 1024,
    };
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,
        received: usize = 0,
        compressed: usize = 0,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn consume(
            self: *@This(),
            message: codec.DecodedMessage,
        ) !void {
            switch (self.received) {
                0 => try std.testing.expectEqualStrings(
                    "first",
                    message.payload,
                ),
                1 => try std.testing.expectEqualStrings(
                    large_request,
                    message.payload,
                ),
                2 => try std.testing.expectEqualStrings(
                    "",
                    message.payload,
                ),
                else => return error.UnexpectedMessage,
            }
            self.received += 1;
            self.compressed += @intFromBool(message.was_compressed);
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try runtime.readRequest(
                &connection,
                self.server.allocator,
                16 * 1024,
                self,
                consume,
            );
            defer request.deinit();
            try std.testing.expectEqualStrings(
                "demo.Stream",
                request.service,
            );
            try std.testing.expectEqualStrings(
                "Bidi",
                request.method,
            );
            try std.testing.expectEqual(@as(usize, 3), request.message_count);
            try std.testing.expectEqual(@as(usize, 1), self.compressed);

            var response = try runtime.startResponse(
                &connection,
                self.server.allocator,
                request.transport.stream_id,
                .{
                    .compression = .deflate,
                    .compression_level = 1,
                    .request_accepted_encodings = request.accepted_encodings,
                },
            );
            defer response.deinit();
            try response.writeMessage("one");
            try response.writeMessage(large_response);
            try response.writeMessage("");
            try response.finish(
                .ok,
                null,
                &.{.{ .name = "x-stream", .value = "complete" }},
                &.{},
            );
        }
    };

    const ClientCollector = struct {
        count: usize = 0,
        compressed: usize = 0,

        fn consume(
            self: *@This(),
            message: codec.DecodedMessage,
        ) !void {
            switch (self.count) {
                0 => try std.testing.expectEqualStrings(
                    "one",
                    message.payload,
                ),
                1 => try std.testing.expectEqualStrings(
                    large_response,
                    message.payload,
                ),
                2 => try std.testing.expectEqualStrings(
                    "",
                    message.payload,
                ),
                else => return error.UnexpectedMessage,
            }
            self.count += 1;
            self.compressed += @intFromBool(message.was_compressed);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var call = try runtime.startClient(&connection, allocator, .{
        .path = "/demo.Stream/Bidi",
        .authority = "localhost",
        .compression = .gzip,
        .compression_level = 1,
    });
    defer call.deinit();
    var first_message: [10]u8 = undefined;
    const first = try wire.writeMessageInto(
        &first_message,
        "first",
        false,
    );
    try call.transport.write(first[0..2]);
    try call.transport.write(first[2..]);
    try call.writeMessage(large_request);
    try call.writeMessage("");
    var collector: ClientCollector = .{};
    var response = try call.finishAndRead(
        &collector,
        ClientCollector.consume,
    );
    defer response.deinit();

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(wire.Status.ok, response.status);
    try std.testing.expectEqualStrings("", response.status_message);
    try std.testing.expectEqualStrings("deflate", response.encoding.?);
    try std.testing.expectEqual(@as(usize, 3), collector.count);
    try std.testing.expectEqual(@as(usize, 1), collector.compressed);
    try std.testing.expectEqualStrings(
        "complete",
        headerValue(response.transport.trailers, "x-stream").?,
    );
}

test "gRPC streaming upload returns early cancelled status while flow blocked" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const stream_id = try readRequestHeadersStreamId(&connection);
            // A trailers-only response is legal gRPC and may arrive before
            // the client finishes uploading request messages.
            try http2.runtime.testing.writeHeaders(
                &connection,
                stream_id,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{
                        .name = "content-type",
                        .value = "application/grpc+proto",
                    },
                    .{ .name = "grpc-status", .value = "1" },
                    .{
                        .name = "grpc-message",
                        .value = "stop%20uploading",
                    },
                    .{ .name = "x-early", .value = "cancelled" },
                },
                true,
            );
        }
    };

    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var client = try runtime.startClient(&connection, allocator, .{
        .path = "/demo.Stream/EarlyCancel",
        .authority = "localhost",
    });
    defer client.deinit();

    // Allow the first framed message, then force the second call to pump peer
    // input while waiting for WINDOW_UPDATE. It must surface typed gRPC status
    // rather than require callers to interpret ResponseAvailable themselves.
    const first_wire_len = try wire.encodedMessageLen("first".len);
    http2.runtime.testing.setSendConnectionWindow(
        &connection,
        @intCast(first_wire_len),
    );
    (try http2.runtime.testing.sendStreamWindow(
        &connection,
        client.transport.stream_id,
    )).value = @intCast(first_wire_len);
    try std.testing.expect((try client.writeMessageOrReadResponse(
        "first",
        {},
        Consumer.consume,
    )) == null);
    var early = (try client.writeMessageOrReadResponse(
        "second",
        {},
        Consumer.consume,
    )).?;
    defer early.deinit();

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(wire.Status.cancelled, early.status);
    try std.testing.expectEqualStrings(
        "stop uploading",
        early.status_message,
    );
    try std.testing.expectEqualStrings(
        "cancelled",
        headerValue(early.transport.headers, "x-early").?,
    );
    try std.testing.expect(client.transport.body_finished);
    try std.testing.expect(client.transport.completed);
    try std.testing.expectEqual(first_wire_len, client.transport.written);
}

test "gRPC streaming request rejects a truncated message and resets HTTP2" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
        .max_body_bytes = 1024,
    };
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn consume(_: void, _: codec.DecodedMessage) !void {}

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try std.testing.expectError(
                error.BufferTooShort,
                runtime.readRequest(
                    &connection,
                    self.server.allocator,
                    1024,
                    {},
                    consume,
                ),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var writer = try connection.startRequest(.{
        .path = "/demo.Stream/Truncated",
        .authority = "localhost",
        .headers = &.{
            .{
                .name = "content-type",
                .value = "application/grpc+proto",
            },
            .{ .name = "te", .value = "trailers" },
        },
    });
    defer writer.deinit();
    try writer.finishData(&.{ 0, 0, 0, 0, 3, 'x' });
    var reset = try connection.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(
        http2.ErrorCode.internal_error,
        reset.reset.error_code,
    );
    thread.join();
    if (shared.err) |err| return err;
}

fn readRequestHeadersStreamId(
    connection: *http2.runtime.Connection,
) !u31 {
    while (true) {
        var frame = try http2.runtime.testing.readOwnedFrame(connection);
        defer frame.deinit(connection.allocator);
        if (try http2.runtime.testing.handleConnectionFrame(
            connection,
            frame.frame,
        )) continue;
        try std.testing.expectEqual(
            http2.FrameType.headers,
            frame.frame.header.frame_type,
        );
        return frame.frame.header.stream_id;
    }
}

fn headerValue(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

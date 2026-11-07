const std = @import("std");
const codec = @import("codec.zig");
const compression = @import("../compression.zig");
const runtime = @import("runtime.zig");
const wire = @import("../wire.zig");
const http2 = @import("../../http2/mod.zig");
const duplex = @import("duplex.zig");

test "gRPC duplex bounded accept rejects non-positive timeout" {
    var connection = http2.runtime.Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    try std.testing.expectError(
        error.Timeout,
        duplex.acceptDuplexWithTimeout(
            &connection,
            std.testing.allocator,
            1024,
            .{ .nanoseconds = 0 },
        ),
    );
}

test "gRPC duplex deadline reads validate clock before transport IO" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const wrong_clock = std.Io.Clock.Timestamp{
        .raw = .zero,
        .clock = .real,
    };

    var client_connection = http2.runtime.Connection{
        .io = io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    client_connection.duplex_reader_active = true;
    var client = duplex.ClientDuplex{
        .allocator = allocator,
        .transport = .{
            .connection = &client_connection,
            .stream_id = 1,
            .expected_request_length = null,
        },
        .encoder = .{ .allocator = allocator },
        .accepted_encodings = .{},
        .max_message_size = 1024,
    };
    defer client.deinit();
    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {}
    };
    try std.testing.expectError(
        error.Timeout,
        client.readResponseEventWithDeadline(
            wrong_clock,
            {},
            Consumer.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        client.readResponseEventWithDeadline(
            .{ .raw = .zero, .clock = .awake },
            {},
            Consumer.consume,
        ),
    );

    var server_connection = http2.runtime.Connection{
        .io = io,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    server_connection.duplex_reader_active = true;
    const empty_headers = try allocator.alloc(http2.Hpack.HeaderField, 0);
    var server = duplex.ServerDuplex{
        .allocator = allocator,
        .transport = .{
            .connection = &server_connection,
            .stream_id = 1,
            .headers = empty_headers,
            .method = "POST",
            .path = "/demo.Test/Method",
            .scheme = "http",
            .authority = null,
            .protocol = null,
            .priority = .{},
            .expected_request_length = null,
        },
        .decoder = try codec.Decoder.init(allocator, 1024, null, .{}),
        .path = "/demo.Test/Method",
        .service = "demo.Test",
        .method = "Method",
        .timeout = null,
        .encoding = null,
        .accepted_encodings = .{},
    };
    defer server.deinit();
    try std.testing.expectError(
        error.Timeout,
        server.readRequestEventWithDeadline(
            wrong_clock,
            {},
            Consumer.consume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        server.readRequestEventWithDeadline(
            .{ .raw = .zero, .clock = .awake },
            {},
            Consumer.consume,
        ),
    );
}

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

test "gRPC stream owned decoder transfers assembled allocation without recopy" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.writeMessage(&encoded, allocator, "owned-across-data", false);

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    var decoder = try codec.Decoder.init(
        failing.allocator(),
        64,
        null,
        .{},
    );
    defer decoder.deinit();
    const Collector = struct {
        message: ?codec.OwnedDecodedMessage = null,
        fn consumeBorrowed(_: *@This(), _: codec.DecodedMessage) !void {
            return error.ExpectedOwnedMessage;
        }
        fn consumeOwned(self: *@This(), message: codec.OwnedDecodedMessage) !void {
            self.message = message;
        }
    };
    var collector: Collector = .{};
    const first = try decoder.feedLimitedAssembledOwned(
        encoded.items[0..6],
        1,
        &collector,
        Collector.consumeBorrowed,
        Collector.consumeOwned,
    );
    try std.testing.expectEqual(@as(usize, 0), first.messages);
    const assembled = decoder.payload.?.ptr;
    const second = try decoder.feedLimitedAssembledOwned(
        encoded.items[6..],
        1,
        &collector,
        Collector.consumeBorrowed,
        Collector.consumeOwned,
    );
    try std.testing.expectEqual(@as(usize, 1), second.messages);
    try std.testing.expect(!failing.has_induced_failure);
    var message = collector.message.?;
    collector.message = null;
    defer message.deinit();
    try std.testing.expectEqual(assembled, message.payload.ptr);
    try std.testing.expectEqualStrings("owned-across-data", message.payload);
    try std.testing.expect(!message.was_compressed);
    try decoder.finish();

    var direct = try codec.Decoder.init(allocator, 64, null, .{});
    defer direct.deinit();
    const DirectCollector = struct {
        seen: bool = false,
        fn consumeBorrowed(self: *@This(), value: codec.DecodedMessage) !void {
            self.seen = true;
            try std.testing.expectEqualStrings("owned-across-data", value.payload);
        }
        fn consumeOwned(_: *@This(), value: codec.OwnedDecodedMessage) !void {
            var owned = value;
            owned.deinit();
            return error.ExpectedBorrowedMessage;
        }
    };
    var direct_collector: DirectCollector = .{};
    _ = try direct.feedLimitedAssembledOwned(
        encoded.items,
        1,
        &direct_collector,
        DirectCollector.consumeBorrowed,
        DirectCollector.consumeOwned,
    );
    try std.testing.expect(direct_collector.seen);
    try direct.finish();
}

test "gRPC stream owned decoder frees transferred payload on callback failure" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.writeMessage(&encoded, allocator, "callback-failure", false);
    var decoder = try codec.Decoder.init(allocator, 64, null, .{});
    defer decoder.deinit();
    const Consumer = struct {
        fn consume(_: void, _: codec.OwnedDecodedMessage) error{Rejected}!void {
            return error.Rejected;
        }
    };
    _ = try decoder.feedLimitedOwned(
        encoded.items[0..6],
        1,
        {},
        Consumer.consume,
    );
    try std.testing.expectError(
        error.Rejected,
        decoder.feedLimitedOwned(
            encoded.items[6..],
            1,
            {},
            Consumer.consume,
        ),
    );
    try std.testing.expect(decoder.payload == null);
}

test "gRPC stream owned decoder transfers decompressed output" {
    const allocator = std.testing.allocator;
    const expected = "owned-compressed-message-" ** 64;
    var compressed = try compression.compressAlloc(
        allocator,
        .gzip,
        expected,
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
    var decoder = try codec.Decoder.init(
        allocator,
        expected.len,
        "gzip",
        .{ .gzip = true },
    );
    defer decoder.deinit();
    const Collector = struct {
        message: ?codec.OwnedDecodedMessage = null,
        fn consume(self: *@This(), message: codec.OwnedDecodedMessage) !void {
            self.message = message;
        }
    };
    var collector: Collector = .{};
    for (encoded.items, 0..) |_, index| {
        _ = try decoder.feedLimitedOwned(
            encoded.items[index .. index + 1],
            1,
            &collector,
            Collector.consume,
        );
    }
    var message = collector.message.?;
    collector.message = null;
    defer message.deinit();
    try std.testing.expectEqualStrings(expected, message.payload);
    try std.testing.expect(message.was_compressed);
    try decoder.finish();
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

test "gRPC stream encoder supports per-message compression opt-out" {
    const allocator = std.testing.allocator;
    const payload = "per-message-compression-opt-out-" ** 64;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const encoder = codec.Encoder{
        .allocator = allocator,
        .algorithm = .gzip,
        .compression_level = 1,
        .max_message_size = payload.len,
    };
    try encoder.appendMessage(&encoded, payload);
    try encoder.appendMessageWithOptions(
        &encoded,
        payload,
        .{ .disable_compression = true },
    );
    try encoder.appendMessage(&encoded, payload);

    var iterator = wire.MessageIterator.init(encoded.items, payload.len);
    const first = (try iterator.next()).?;
    const identity = (try iterator.next()).?;
    const third = (try iterator.next()).?;
    try std.testing.expect(first.compressed);
    try std.testing.expect(!identity.compressed);
    try std.testing.expectEqualStrings(payload, identity.payload);
    try std.testing.expect(third.compressed);
    try std.testing.expectEqualSlices(u8, first.payload, third.payload);
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
        .max_frame_size = 16 * 1024,
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
        headerValue(response.transport.?.trailers, "x-stream").?,
    );
}

test "gRPC duplex interleaves a response before request FIN" {
    const allocator = std.testing.allocator;
    const first_request = "first-request-compressed-" ** 16;
    const second_request = "second-request-identity-" ** 16;
    const fragmented_response = "fragmented-response-" ** 8;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 32,
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
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            const expected = if (self.requests == 0)
                first_request
            else
                second_request;
            try std.testing.expectEqualStrings(expected, message.payload);
            try std.testing.expectEqual(
                self.requests == 0,
                message.was_compressed,
            );
            self.requests += 1;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            );
            defer stream.deinit();
            try std.testing.expectEqualStrings("demo.Echo", stream.service);
            try std.testing.expectEqualStrings("Bidi", stream.method);

            while (self.requests == 0) {
                var first = try stream.readRequestEvent(self, consume);
                defer first.deinit();
                switch (first) {
                    .messages => |progress| {
                        try std.testing.expect(progress.count <= 1);
                        try std.testing.expect(!progress.end_stream);
                    },
                    .finished, .reset => return error.UnexpectedEndOfStream,
                }
            }
            try stream.startResponse(.{
                .compression = .gzip,
                .request_accepted_encodings = stream.accepted_encodings,
                .initial_metadata = &.{.{
                    .name = "x-duplex",
                    .value = "interleaved",
                }},
            });
            var first_response = try stream.allocMessage(
                fragmented_response.len,
            );
            defer first_response.deinit();
            @memcpy(first_response.payload(), fragmented_response);
            try std.testing.expectEqual(
                duplex.WriteResult.complete,
                try stream.writeOwnedMessage(&first_response),
            );
            try std.testing.expect(!first_response.hasValue());

            var request_ended = false;
            while (self.requests == 1) {
                var second = try stream.readRequestEvent(self, consume);
                defer second.deinit();
                switch (second) {
                    .messages => |progress| {
                        try std.testing.expect(progress.count <= 1);
                        request_ended = progress.end_stream;
                    },
                    .finished, .reset => return error.UnexpectedEndOfStream,
                }
            }
            try std.testing.expect(request_ended);

            var finished = try stream.readRequestEvent(self, consume);
            defer finished.deinit();
            try std.testing.expectEqual(
                @as(usize, 2),
                finished.finished.message_count,
            );
            var second_response = try stream.allocMessage("ack-two".len);
            defer second_response.deinit();
            @memcpy(second_response.payload(), "ack-two");
            try std.testing.expectEqual(
                duplex.WriteResult.complete,
                try stream.writeOwnedMessageWithOptions(
                    &second_response,
                    .{ .disable_compression = true },
                ),
            );
            try std.testing.expect(!second_response.hasValue());
            try stream.finishOk();
        }
    };

    const Collector = struct {
        count: usize = 0,

        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            const expected = if (self.count == 0)
                fragmented_response
            else
                "ack-two";
            try std.testing.expectEqualStrings(expected, message.payload);
            try std.testing.expectEqual(
                self.count == 0,
                message.was_compressed,
            );
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Echo/Bidi",
            .authority = "localhost",
            .compression = .gzip,
            .accepted_encodings = .{ .gzip = true },
        },
    );
    defer stream.deinit();
    var first_owned = try stream.allocMessage(first_request.len);
    defer first_owned.deinit();
    @memcpy(first_owned.payload(), first_request);
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.writeOwnedMessage(&first_owned),
    );
    try std.testing.expect(!first_owned.hasValue());

    var collector: Collector = .{};
    var head = try stream.readResponseEvent(&collector, Collector.consume);
    defer head.deinit(allocator);
    try std.testing.expectEqualStrings(
        "interleaved",
        headerValue(head.initial_metadata.headers, "x-duplex").?,
    );
    var saw_fragment_only_progress = false;
    while (collector.count == 0) {
        var first_reply = try stream.readResponseEvent(
            &collector,
            Collector.consume,
        );
        defer first_reply.deinit(allocator);
        const progress = first_reply.messages;
        // Message progress is scoped to one HTTP/2 DATA event. A frame can
        // advance an incomplete gRPC message without invoking the callback.
        saw_fragment_only_progress = saw_fragment_only_progress or
            progress.count == 0;
        try std.testing.expect(progress.count <= 1);
    }
    try std.testing.expect(saw_fragment_only_progress);
    try std.testing.expect(!stream.requestFinished());

    var final_owned = try stream.allocMessage(second_request.len);
    defer final_owned.deinit();
    @memcpy(final_owned.payload(), second_request);
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.writeFinalOwnedMessageWithOptions(
            &final_owned,
            .{ .disable_compression = true },
        ),
    );
    try std.testing.expect(!final_owned.hasValue());
    var second_reply = try stream.readResponseEvent(
        &collector,
        Collector.consume,
    );
    defer second_reply.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), second_reply.messages.count);
    var terminal = try stream.readResponseEvent(
        &collector,
        Collector.consume,
    );
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(wire.Status.ok, terminal.terminal.status);
    try std.testing.expectEqual(@as(usize, 2), collector.count);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.requests);
}

test "gRPC duplex preserves trailers-only status before request FIN" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var stream = duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            ) catch |err| {
                self.err = err;
                return;
            };
            defer stream.deinit();
            stream.deadline = std.Io.Clock.Timestamp.fromNow(
                self.server.io,
                .{
                    .raw = .fromNanoseconds(1),
                    .clock = .awake,
                },
            );
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(1),
                .awake,
            ) catch |err| {
                self.err = err;
                return;
            };
            if (!stream.deadlineExpired()) {
                self.err = error.ExpectedExpiredDeadline;
                return;
            }
            stream.finish(
                .permission_denied,
                "not allowed",
                &.{.{ .name = "x-early", .value = "yes" }},
                &.{},
            ) catch |err| {
                self.err = err;
                return;
            };
            const drained = stream.drainRequestAfterResponseWithDeadline(
                std.Io.Clock.Timestamp.fromNow(self.server.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            ) catch |err| {
                self.err = err;
                return;
            };
            switch (drained) {
                .finished => {},
                .reset => {
                    self.err = error.UnexpectedReset;
                },
            }
        }
    };
    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Echo/Denied",
            .authority = "localhost",
        },
    );
    defer stream.deinit();
    var terminal = try stream.readResponseEvent({}, Consumer.consume);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(
        wire.Status.permission_denied,
        terminal.terminal.status,
    );
    try std.testing.expectEqualStrings(
        "not allowed",
        terminal.terminal.status_message,
    );
    try std.testing.expectEqualStrings(
        "yes",
        headerValue(terminal.terminal.head.?.headers, "x-early").?,
    );
    try std.testing.expect(stream.requestFinished());
    try std.testing.expectError(
        error.ConnectionClosed,
        stream.writeMessage("too late"),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC server duplex observes cancellation after request FIN" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
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
        response_started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            );
            var stream_live = true;
            defer if (stream_live) stream.deinit();
            var finished = try stream.readRequestEvent({}, consume);
            defer finished.deinit();
            try std.testing.expectEqual(
                @as(usize, 0),
                finished.finished.message_count,
            );
            try stream.startResponse(.{});
            self.response_started.set(self.server.io);
            const reset = try stream.waitForPeerResetWithTimeout(
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.error_code,
            );
            stream.deinit();
            stream_live = false;

            var next = try connection.readRequest();
            defer next.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("next", next.body);
            try connection.writeResponse(next.stream_id, .{
                .status = 204,
                .request_method = next.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Watch/Stream",
            .authority = "localhost",
        },
    );
    var stream_live = true;
    defer if (stream_live) stream.deinit();
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.finishRequest(),
    );
    try shared.response_started.waitTimeout(
        io,
        .{ .duration = .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        } },
    );
    try stream.cancel();
    stream.deinit();
    stream_live = false;

    var next = try connection.request(.{
        .method = "POST",
        .path = "/next",
        .authority = "localhost",
        .body = "next",
    });
    defer next.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), next.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC duplex RPC deadline cancels a silent response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
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

        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            );
            defer stream.deinit();
            var finished = try stream.readRequestEvent({}, consume);
            defer finished.deinit();
            try std.testing.expect(finished == .finished);
            const reset = try stream.waitForPeerResetWithTimeout(
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.error_code,
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
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Deadline/Stream",
            .authority = "localhost",
            .timeout = try wire.Timeout.init(100, .millisecond),
        },
    );
    defer stream.deinit();
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.finishRequest(),
    );
    try std.testing.expectError(
        error.Timeout,
        stream.readResponseEvent({}, Consumer.consume),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        stream.readResponseEvent({}, Consumer.consume),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC duplex RPC deadline bounds flow control wait" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
        .max_body_bytes = 4096,
        .initial_window_size = 5,
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

        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(200),
                .awake,
            );
            var stream = try duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            );
            defer stream.deinit();
            while (true) {
                var event = try stream.readRequestEventWithTimeout(
                    .fromSeconds(2),
                    {},
                    consume,
                );
                defer event.deinit();
                switch (event) {
                    .reset => |reset| {
                        try std.testing.expectEqual(
                            http2.ErrorCode.cancel,
                            reset.error_code,
                        );
                        break;
                    },
                    .messages => {},
                    .finished => return error.UnexpectedFrame,
                }
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Deadline/Stream",
            .authority = "localhost",
            .timeout = try wire.Timeout.init(50, .millisecond),
        },
    );
    defer stream.deinit();
    try std.testing.expectError(
        error.Timeout,
        stream.writeMessage("blocked"),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC duplex shorter read timeout preserves the RPC" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
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

        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            );
            defer stream.deinit();
            var finished = try stream.readRequestEvent({}, consume);
            defer finished.deinit();
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(30),
                .awake,
            );
            try stream.finish(.unavailable, "later", &.{}, &.{});
        }
    };
    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Deadline/Stream",
            .authority = "localhost",
            .timeout = try wire.Timeout.init(1, .second),
        },
    );
    defer stream.deinit();
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.finishRequest(),
    );
    try std.testing.expectError(
        error.Timeout,
        stream.readResponseEventWithTimeout(
            .fromMilliseconds(1),
            {},
            Consumer.consume,
        ),
    );
    var terminal = try stream.readResponseEvent({}, Consumer.consume);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(
        wire.Status.unavailable,
        terminal.terminal.status,
    );
    try std.testing.expectEqualStrings(
        "later",
        terminal.terminal.status_message,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC duplex callback failure resets once and connection is reusable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 64,
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
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try duplex.acceptDuplex(
                &connection,
                self.server.allocator,
                1024,
            );
            var first_live = true;
            defer if (first_live) first.deinit();
            while (true) {
                var request_event = try first.readRequestEvent(
                    {},
                    struct {
                        fn consume(_: void, _: codec.DecodedMessage) !void {}
                    }.consume,
                );
                defer request_event.deinit();
                if (request_event == .finished) break;
            }
            try first.startResponse(.{});
            try std.testing.expectEqual(
                duplex.WriteResult.complete,
                try first.writeMessage("reject-me"),
            );
            try first.finishOk();
            first.deinit();
            first_live = false;

            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("next", request.body);
            try connection.writeResponse(request.stream_id, .{
                .status = 204,
                .request_method = request.method,
            });
        }
    };

    const Reject = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.RejectedMessage;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Echo/Reject",
            .authority = "localhost",
        },
    );
    var stream_live = true;
    defer if (stream_live) stream.deinit();
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.finishRequest(),
    );
    var head = try stream.readResponseEvent({}, Reject.consume);
    defer head.deinit(allocator);
    try std.testing.expect(head == .initial_metadata);
    try std.testing.expectError(
        error.RejectedMessage,
        stream.readResponseEvent({}, Reject.consume),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        stream.readResponseEvent({}, Reject.consume),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        stream.writeMessage("again"),
    );
    stream.deinit();
    stream_live = false;

    var next = try connection.request(.{
        .method = "POST",
        .path = "/next",
        .authority = "localhost",
        .body = "next",
    });
    defer next.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), next.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
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
            // Complete the request half before closing the TCP socket. A
            // close with unread upload DATA can reset the transport and race
            // the client's empty FIN, obscuring the response being tested.
            var uploaded: usize = 0;
            while (true) {
                var frame = try http2.runtime.testing.readOwnedFrame(&connection);
                defer frame.deinit(connection.allocator);
                if (try http2.runtime.testing.handleConnectionFrame(&connection, frame.frame)) continue;
                try std.testing.expectEqual(http2.FrameType.data, frame.frame.header.frame_type);
                try std.testing.expectEqual(stream_id, frame.frame.header.stream_id);
                uploaded += frame.frame.payload.len;
                if (frame.frame.header.flags & 0x1 != 0) break;
            }
            try std.testing.expectEqual(try wire.encodedMessageLen("first".len), uploaded);
        }
    };

    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
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
    var early = (try client.writeMessageWithOptionsOrReadResponse(
        "second",
        .{ .disable_compression = true },
        {},
        Consumer.consume,
    )).?;
    defer early.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(wire.Status.cancelled, early.status);
    try std.testing.expectEqualStrings(
        "stop uploading",
        early.status_message,
    );
    try std.testing.expectEqualStrings(
        "cancelled",
        headerValue(early.transport.?.headers, "x-early").?,
    );
    try std.testing.expect(client.transport.body_finished);
    try std.testing.expect(client.transport.completed);
    try std.testing.expectEqual(first_wire_len, client.transport.written);
}

test "gRPC streaming response returns typed status for HTTP2 reset" {
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
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.sendResetStream(
                request.stream_id,
                .enhance_your_calm,
            ) catch |err| {
                self.err = err;
            };
        }
    };

    const Consumer = struct {
        fn consume(_: void, _: codec.DecodedMessage) !void {
            return error.UnexpectedMessage;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var client = try runtime.startClient(&connection, allocator, .{
        .path = "/demo.Reset/Stream",
        .authority = "localhost",
    });
    defer client.deinit();
    var response = try client.finishAndRead({}, Consumer.consume);
    defer response.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        wire.Status.resource_exhausted,
        response.status,
    );
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        response.reset.?.error_code,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.status_message,
        "enhance_your_calm",
    ) != null);
    try std.testing.expect(response.transport == null);
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

test "gRPC client duplex copies only the unsent suffix after an early response" {
    const allocator = std.testing.allocator;
    const large_request = "client-duplex-early-" ** 8192;
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = large_request.len + 16,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

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
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                std.testing.allocator,
                1024,
            );
            defer stream.deinit();
            try stream.startResponse(.{});
            _ = try stream.writeMessage("early");
            try stream.finish(.unavailable, "stop", &.{}, &.{});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Echo/Bidi",
            .authority = "localhost",
        },
    );
    defer stream.deinit();
    try std.testing.expectEqual(
        duplex.WriteResult.peer_event,
        try stream.writeMessage(large_request),
    );

    const Collector = struct {
        messages: usize = 0,
        terminal: ?wire.Status = null,

        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            try std.testing.expectEqualStrings("early", message.payload);
            self.messages += 1;
        }
    };
    var collector: Collector = .{};
    while (collector.terminal == null) {
        var event = try stream.readResponseEvent(&collector, Collector.consume);
        defer event.deinit(allocator);
        switch (event) {
            .terminal => |value| collector.terminal = value.status,
            .messages, .initial_metadata, .informational => {},
        }
    }
    try std.testing.expectEqual(wire.Status.unavailable, collector.terminal.?);
    try std.testing.expectEqual(@as(usize, 1), collector.messages);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC server duplex writes a large response without staging" {
    const allocator = std.testing.allocator;
    const large_response = "server-duplex-large-" ** 4096;
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = large_response.len + 16,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Tracker = struct {
        child: std.mem.Allocator,
        threshold: usize,
        large_allocations: usize = 0,

        fn asAllocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            if (len >= self.threshold) self.large_allocations += 1;
            return self.child.rawAlloc(len, alignment, ret);
        }

        fn resize(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            return self.child.rawResize(bytes, alignment, len, ret);
        }

        fn remap(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            return self.child.rawRemap(bytes, alignment, len, ret);
        }

        fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.child.rawFree(bytes, alignment, ret);
        }

        const vtable: std.mem.Allocator.VTable = .{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        };
    };

    var tracker = Tracker{
        .child = allocator,
        .threshold = large_response.len,
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
        payload: []const u8,
        tracker: *Tracker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(_: *@This(), message: codec.DecodedMessage) !void {
            try std.testing.expectEqualStrings("request", message.payload);
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                self.tracker.asAllocator(),
                1024,
            );
            defer stream.deinit();

            var finished = false;
            while (!finished) {
                var event = try stream.readRequestEvent(self, consume);
                defer event.deinit();
                switch (event) {
                    .messages => {},
                    .finished => finished = true,
                    .reset => return error.UnexpectedReset,
                }
            }

            try stream.startResponse(.{});
            self.tracker.large_allocations = 0;
            try std.testing.expectEqual(
                duplex.WriteResult.complete,
                try stream.writeMessage(self.payload),
            );
            try std.testing.expectEqual(@as(usize, 0), self.tracker.large_allocations);
            try stream.finishOk();
        }
    };

    var shared = Shared{
        .server = &server,
        .payload = large_response,
        .tracker = &tracker,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        allocator,
        .{
            .path = "/demo.Echo/Bidi",
            .authority = "localhost",
        },
    );
    defer stream.deinit();
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.writeFinalMessage("request"),
    );

    const Collector = struct {
        count: usize = 0,

        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            try std.testing.expectEqualStrings(large_response, message.payload);
            self.count += 1;
        }
    };
    var collector: Collector = .{};
    var head = try stream.readResponseEvent(&collector, Collector.consume);
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.initial_metadata.status);
    while (collector.count == 0) {
        var reply = try stream.readResponseEvent(&collector, Collector.consume);
        defer reply.deinit(allocator);
        switch (reply) {
            .messages, .initial_metadata => {},
            else => return error.UnexpectedResponseEvent,
        }
    }
    var terminal = try stream.readResponseEvent(&collector, Collector.consume);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(wire.Status.ok, terminal.terminal.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "gRPC client duplex writes a large request without staging" {
    const allocator = std.testing.allocator;
    const large_request = "client-duplex-large-" ** 8192;
    const limits: http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = large_request.len + 16,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Tracker = struct {
        child: std.mem.Allocator,
        threshold: usize,
        large_allocations: usize = 0,

        fn asAllocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            if (len >= self.threshold) self.large_allocations += 1;
            return self.child.rawAlloc(len, alignment, ret);
        }

        fn resize(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            return self.child.rawResize(bytes, alignment, len, ret);
        }

        fn remap(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            return self.child.rawRemap(bytes, alignment, len, ret);
        }

        fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.child.rawFree(bytes, alignment, ret);
        }

        const vtable: std.mem.Allocator.VTable = .{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        };
    };

    var tracker = Tracker{
        .child = allocator,
        .threshold = large_request.len,
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
        payload: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            try std.testing.expectEqualStrings(self.payload, message.payload);
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var stream = try duplex.acceptDuplex(
                &connection,
                std.testing.allocator,
                large_request.len + 16,
            );
            defer stream.deinit();

            var finished = false;
            while (!finished) {
                var event = try stream.readRequestEvent(self, consume);
                defer event.deinit();
                switch (event) {
                    .messages => {},
                    .finished => finished = true,
                    .reset => return error.UnexpectedReset,
                }
            }

            try stream.startResponse(.{});
            _ = try stream.writeMessage("ok");
            try stream.finishOk();
        }
    };

    var shared = Shared{
        .server = &server,
        .payload = large_request,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connection = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer connection.close();
    var stream = try duplex.startDuplex(
        &connection,
        tracker.asAllocator(),
        .{
            .path = "/demo.Echo/Bidi",
            .authority = "localhost",
        },
    );
    defer stream.deinit();
    tracker.large_allocations = 0;
    try std.testing.expectEqual(
        duplex.WriteResult.complete,
        try stream.writeFinalMessage(large_request),
    );
    try std.testing.expectEqual(@as(usize, 0), tracker.large_allocations);
    const Collector = struct {
        count: usize = 0,

        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            try std.testing.expectEqualStrings("ok", message.payload);
            self.count += 1;
        }
    };
    var collector: Collector = .{};
    var head = try stream.readResponseEvent(&collector, Collector.consume);
    defer head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head.initial_metadata.status);
    while (collector.count == 0) {
        var reply = try stream.readResponseEvent(&collector, Collector.consume);
        defer reply.deinit(allocator);
        switch (reply) {
            .messages, .initial_metadata => {},
            else => return error.UnexpectedResponseEvent,
        }
    }
    var terminal = try stream.readResponseEvent(&collector, Collector.consume);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(wire.Status.ok, terminal.terminal.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");

test "gRPC-Web h2c unary uses body trailer frames for binary and text" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();

            // Binary gRPC-Web RPC.
            {
                var request = connection.readUnaryWeb() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                if (!std.mem.eql(u8, request.request.message.payload, "ping")) {
                    self.err = error.InvalidGrpcRequest;
                    return;
                }
                connection.writeUnaryWeb(
                    request.request.stream_id,
                    .{ .message = "pong" },
                    request.content_type,
                ) catch |err| {
                    self.err = err;
                    return;
                };
            }

            // Base64 text gRPC-Web RPC.
            {
                var request = connection.readUnaryWeb() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                if (!request.content_type.text or
                    !std.mem.eql(u8, request.request.message.payload, "text"))
                {
                    self.err = error.InvalidGrpcRequest;
                    return;
                }
                connection.writeUnaryWeb(
                    request.request.stream_id,
                    .{
                        .status = .ok,
                        .message = "reply",
                        .trailing_metadata = &.{
                            .{ .name = "x-trace", .value = "42" },
                        },
                    },
                    request.content_type,
                ) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();

    {
        var entity: [9]u8 = undefined;
        entity[0] = 0;
        std.mem.writeInt(u32, entity[1..5], 4, .big);
        @memcpy(entity[5..9], "ping");
        const headers = [_]http2.Hpack.HeaderField{
            .{ .name = "content-type", .value = "application/grpc-web" },
        };
        var response = try client.connection.request(.{
            .method = "POST",
            .path = "/demo.Echo/WebUnary",
            .authority = "localhost",
            .headers = &headers,
            .body = &entity,
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqualStrings(
            "application/grpc-web",
            grpcWebHeader(response.headers, "content-type").?,
        );
        try std.testing.expect(response.trailers.len == 0);
        // data frame
        try std.testing.expectEqual(@as(u8, 0), response.body[0]);
        try std.testing.expectEqual(
            @as(u32, 4),
            std.mem.readInt(u32, response.body[1..5], .big),
        );
        try std.testing.expectEqualStrings("pong", response.body[5..9]);
        // trailers frame
        try std.testing.expectEqual(@as(u8, 0x80), response.body[9]);
        const trailer_len = std.mem.readInt(
            u32,
            response.body[10..14],
            .big,
        );
        try std.testing.expectEqual(response.body.len - 14, trailer_len);
        try std.testing.expect(std.mem.startsWith(
            u8,
            response.body[14..],
            "grpc-status:0\r\n",
        ));
    }

    {
        var framed: [9]u8 = undefined;
        framed[0] = 0;
        std.mem.writeInt(u32, framed[1..5], 4, .big);
        @memcpy(framed[5..9], "text");
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(
            u8,
            encoder.calcSize(framed.len),
        );
        defer allocator.free(encoded);
        _ = encoder.encode(encoded, &framed);

        const headers = [_]http2.Hpack.HeaderField{
            .{ .name = "content-type", .value = "application/grpc-web-text" },
        };
        var response = try client.connection.request(.{
            .method = "POST",
            .path = "/demo.Echo/WebTextUnary",
            .authority = "localhost",
            .headers = &headers,
            .body = encoded,
        });
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings(
            "application/grpc-web-text",
            grpcWebHeader(response.headers, "content-type").?,
        );
        const decoder = std.base64.standard.Decoder;
        const decoded = try allocator.alloc(
            u8,
            decoder.calcSizeForSlice(response.body) catch return error.InvalidResponse,
        );
        defer allocator.free(decoded);
        try decoder.decode(decoded, response.body);
        try std.testing.expectEqual(@as(u8, 0), decoded[0]);
        try std.testing.expectEqual(
            @as(u32, 5),
            std.mem.readInt(u32, decoded[1..5], .big),
        );
        try std.testing.expectEqualStrings("reply", decoded[5..10]);
        try std.testing.expectEqual(@as(u8, 0x80), decoded[10]);
        const trailer_block = decoded[15..];
        try std.testing.expect(std.mem.startsWith(
            u8,
            trailer_block,
            "grpc-status:0\r\n",
        ));
        try std.testing.expect(std.mem.indexOf(u8, trailer_block, "x-trace:42\r\n") != null);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC-Web trailers-only error reaches the HTTP response headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnaryWeb() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            connection.writeUnaryWeb(
                request.request.stream_id,
                .{
                    .status = .unauthenticated,
                    .status_message = "denied",
                    .trailers_only = true,
                },
                request.content_type,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();

    var entity: [10]u8 = undefined;
    entity[0] = 0;
    std.mem.writeInt(u32, entity[1..5], 5, .big);
    @memcpy(entity[5..10], "close");
    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = "content-type", .value = "application/grpc-web" },
    };
    var response = try client.connection.request(.{
        .method = "POST",
        .path = "/demo.Echo/Closed",
        .authority = "localhost",
        .headers = &headers,
        .body = &entity,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), response.body.len);
    try std.testing.expectEqualStrings(
        "16",
        grpcWebHeader(response.headers, "grpc-status").?,
    );
    try std.testing.expectEqualStrings(
        "denied",
        grpcWebHeader(response.headers, "grpc-message").?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC-Web h2c server streaming frames all messages and trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const messages = [_][]const u8{ "one", "two", "three" };

    const Shared = struct {
        server: *grpc.runtime.Server,
        messages: []const []const u8,
        err: ?anyerror = null,

        const Counter = struct {
            count: usize = 0,
            fn consume(
                self: *@This(),
                message: grpc.StreamingMessage,
            ) !void {
                _ = message;
                self.count += 1;
            }
        };

        fn handleCall(
            connection: *grpc.runtime.ServerConnection,
            messages_slice: []const []const u8,
            text: bool,
        ) !void {
            var counter = Counter{};
            var request = try connection.readStreamingWeb(
                &counter,
                Counter.consume,
            );
            defer request.deinit();
            if (counter.count != 1 or
                text != request.content_type.text)
            {
                return error.InvalidGrpcRequest;
            }
            var writer = try connection.startStreamingWeb(
                request.request.transport.stream_id,
                .{},
                request.content_type,
            );
            defer writer.deinit();
            for (messages_slice) |message| {
                try writer.writeMessage(message);
            }
            try writer.finish(
                .ok,
                null,
                &.{.{ .name = "x-seq", .value = "7" }},
                &.{},
            );
        }

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            // Both calls multiplex on the one accepted connection.
            handleCall(
                &connection,
                self.messages,
                false,
            ) catch |err| {
                self.err = err;
                return;
            };
            handleCall(&connection, self.messages, true) catch |err| {
                self.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server, .messages = &messages };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();

    {
        var entity: [9]u8 = undefined;
        entity[0] = 0;
        std.mem.writeInt(u32, entity[1..5], 4, .big);
        @memcpy(entity[5..9], "ping");
        const headers = [_]http2.Hpack.HeaderField{
            .{ .name = "content-type", .value = "application/grpc-web" },
        };
        var response = try client.connection.request(.{
            .method = "POST",
            .path = "/demo.Echo/ServerStream",
            .authority = "localhost",
            .headers = &headers,
            .body = &entity,
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expect(response.trailers.len == 0);

        var offset: usize = 0;
        for (messages) |message| {
            try std.testing.expectEqual(@as(u8, 0), response.body[offset]);
            const len = std.mem.readInt(
                u32,
                response.body[offset + 1 ..][0..4],
                .big,
            );
            try std.testing.expectEqualStrings(
                message,
                response.body[offset + 5 ..][0..len],
            );
            offset += 5 + len;
        }
        try std.testing.expectEqual(@as(u8, 0x80), response.body[offset]);
        offset += 1;
        const trailer_len = std.mem.readInt(
            u32,
            response.body[offset..][0..4],
            .big,
        );
        offset += 4;
        try std.testing.expectEqual(response.body.len - offset, trailer_len);
        const block = response.body[offset..];
        try std.testing.expect(std.mem.startsWith(
            u8,
            block,
            "grpc-status:0\r\n",
        ));
        try std.testing.expect(std.mem.indexOf(
            u8,
            block,
            "x-seq:7\r\n",
        ) != null);
    }

    // Base64 text wire: one base64 request message and a base64 response.
    {
        var framed: [9]u8 = undefined;
        framed[0] = 0;
        std.mem.writeInt(u32, framed[1..5], 4, .big);
        @memcpy(framed[5..9], "ping");
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(
            u8,
            encoder.calcSize(framed.len),
        );
        defer allocator.free(encoded);
        _ = encoder.encode(encoded, &framed);

        const headers = [_]http2.Hpack.HeaderField{
            .{ .name = "content-type", .value = "application/grpc-web-text" },
        };
        var response = try client.connection.request(.{
            .method = "POST",
            .path = "/demo.Echo/TextServerStream",
            .authority = "localhost",
            .headers = &headers,
            .body = encoded,
        });
        defer response.deinit(allocator);
        const decoded = try grpc.web.base64DecodeAlloc(allocator, response.body);
        defer allocator.free(decoded);

        var offset: usize = 0;
        for (messages) |message| {
            try std.testing.expectEqual(@as(u8, 0), decoded[offset]);
            const len = std.mem.readInt(
                u32,
                decoded[offset + 1 ..][0..4],
                .big,
            );
            try std.testing.expectEqualStrings(
                message,
                decoded[offset + 5 ..][0..len],
            );
            offset += 5 + len;
        }
        try std.testing.expectEqual(@as(u8, 0x80), decoded[offset]);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "gRPC-Web streaming rejects more than one request message" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            const Context = struct {
                fn consume(_: *void, _: grpc.StreamingMessage) !void {}
            };
            var context: void = {};
            var request = connection.readStreamingWeb(
                &context,
                Context.consume,
            ) catch |err| {
                self.err = if (err == error.InvalidMessageCount) null else err;
                return;
            };
            request.deinit();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();

    var entity: [18]u8 = undefined;
    for (0..2) |index| {
        entity[index * 9] = 0;
        std.mem.writeInt(
            u32,
            entity[index * 9 + 1 ..][0..4],
            4,
            .big,
        );
        @memcpy(entity[index * 9 + 5 ..][0..4], "ping");
    }
    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = "content-type", .value = "application/grpc-web" },
    };
    try std.testing.expectError(
        error.StreamReset,
        client.connection.request(.{
            .method = "POST",
            .path = "/demo.Echo/ClientStream",
            .authority = "localhost",
            .headers = &headers,
            .body = &entity,
        }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn grpcWebHeader(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

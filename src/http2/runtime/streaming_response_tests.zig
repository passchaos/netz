const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Limits = runtime.Limits;
const Server = runtime.Server;
const StreamingResponse = runtime.StreamingResponse;

test "HTTP/2 streaming response consumes DATA without aggregation" {
    const allocator = std.testing.allocator;
    const body = "streaming-response-" ** 8192;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The body is larger than the receive stream window. Completion therefore
    // proves the callback path returns flow credit while DATA is still
    // arriving rather than buffering the whole response first.
    const limits: Limits = .{
        .max_body_bytes = body.len,
        .initial_window_size = 32 * 1024,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try connection.writeInformationalResponse(
                request.stream_id,
                103,
                &.{.{ .name = "link", .value = "</warm>; rel=preload" }},
            );
            try connection.writeResponse(request.stream_id, .{
                .body = body,
                .trailers = &.{.{
                    .name = "x-checksum",
                    .value = "complete",
                }},
            });
        }
    };

    const Consumer = struct {
        bytes: usize = 0,
        checksum: u64 = 0,
        calls: usize = 0,

        fn consume(self: *@This(), data: []const u8) !void {
            self.bytes += data.len;
            self.calls += 1;
            for (data) |byte| self.checksum +%= byte;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var consumer: Consumer = .{};
    var response = try client.requestStreaming(
        .{
            .path = "/stream-response",
            .authority = "localhost",
        },
        &consumer,
        Consumer.consume,
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    var expected_checksum: u64 = 0;
    for (body) |byte| expected_checksum +%= byte;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqual(body.len, response.body_bytes);
    try std.testing.expectEqual(body.len, consumer.bytes);
    try std.testing.expectEqual(expected_checksum, consumer.checksum);
    try std.testing.expect(consumer.calls > 1);
    try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
    try std.testing.expectEqualStrings(
        "x-checksum",
        response.trailers[0].name,
    );
    try std.testing.expectEqualStrings(
        "complete",
        response.trailers[0].value,
    );
    // The result owns only HPACK fields; DATA never becomes a body allocation.
    try std.testing.expect(!@hasField(StreamingResponse, "body"));
}

test "HTTP/2 streaming response callback failure cancels stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = 4096,
        .max_frame_payload = 4096,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);

            try runtime.testing.writeHeaders(
                &connection,
                request.stream_id,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "12" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                request.stream_id,
                "first",
                false,
            );
            var reset = try connection.readResetStream();
            defer reset.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                request.stream_id,
                reset.reset.stream_id,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
        }
    };

    const Consumer = struct {
        fn consume(_: void, _: []const u8) error{Stop}!void {
            return error.Stop;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    try std.testing.expectError(
        error.Stop,
        client.requestStreaming(
            .{
                .path = "/cancel-stream-response",
                .authority = "localhost",
            },
            {},
            Consumer.consume,
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming response enforces Content-Length" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_body_bytes = 4096, .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try runtime.testing.writeHeaders(
                &connection,
                request.stream_id,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "6" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                request.stream_id,
                "short",
                true,
            );
        }
    };

    const Consumer = struct {
        fn consume(_: void, _: []const u8) !void {}
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = 4096, .max_frame_payload = 4096 },
    );
    defer client.close();
    try std.testing.expectError(
        error.InvalidContentLength,
        client.requestStreaming(
            .{
                .path = "/bad-stream-length",
                .authority = "localhost",
            },
            {},
            Consumer.consume,
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

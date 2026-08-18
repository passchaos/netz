const std = @import("std");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Limits = runtime.Limits;
const Server = runtime.Server;

test "HTTP/2 response writer streams with flow control and trailers" {
    const allocator = std.testing.allocator;
    const first = "response-writer-first-" ** 2048;
    const second = "response-writer-second-" ** 2048;
    const expected_len = first.len + second.len;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = expected_len,
        .initial_window_size = 24 * 1024,
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

            var length_buffer: [32]u8 = undefined;
            const length = try std.fmt.bufPrint(
                &length_buffer,
                "{}",
                .{expected_len},
            );
            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = length,
                }} },
            );
            defer response.deinit();
            try response.write(first);
            try response.write(second);
            try response.finishTrailers(&.{.{
                .name = "x-stream-complete",
                .value = "yes",
            }});
            try std.testing.expect(response.finished);
            try std.testing.expectEqual(expected_len, response.written);
            try std.testing.expectError(
                error.ConnectionClosed,
                response.write("late"),
            );
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
            .path = "/stream-write",
            .authority = "localhost",
        },
        &consumer,
        Consumer.consume,
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    var expected_checksum: u64 = 0;
    for (first) |byte| expected_checksum +%= byte;
    for (second) |byte| expected_checksum +%= byte;
    try std.testing.expectEqual(expected_len, response.body_bytes);
    try std.testing.expectEqual(expected_len, consumer.bytes);
    try std.testing.expectEqual(expected_checksum, consumer.checksum);
    try std.testing.expect(consumer.calls > 2);
    try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
    try std.testing.expectEqualStrings(
        "yes",
        response.trailers[0].value,
    );
}

test "HTTP/2 response writer length errors are transactional" {
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

            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "5",
                }} },
            );
            defer response.deinit();
            try response.write("ab");
            try std.testing.expectError(
                error.InvalidContentLength,
                response.finishData("toolong"),
            );
            try std.testing.expectEqual(@as(usize, 2), response.written);
            try std.testing.expect(!response.finished);
            try response.finishData("cde");
        }
    };

    const Consumer = struct {
        storage: [5]u8 = undefined,
        len: usize = 0,

        fn consume(self: *@This(), data: []const u8) !void {
            @memcpy(self.storage[self.len..][0..data.len], data);
            self.len += data.len;
        }
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
    var consumer: Consumer = .{};
    var response = try client.requestStreaming(
        .{ .path = "/length-retry", .authority = "localhost" },
        &consumer,
        Consumer.consume,
    );
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("abcde", consumer.storage[0..consumer.len]);
}

test "HTTP/2 response writer ends HEAD response at headers" {
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
            var response = try connection.startResponse(
                request.stream_id,
                .{ .headers = &.{.{
                    .name = "content-length",
                    .value = "123",
                }} },
            );
            defer response.deinit();
            try std.testing.expect(response.finished);
            try std.testing.expectError(
                error.ConnectionClosed,
                response.finish(),
            );
        }
    };

    const Consumer = struct {
        fn consume(_: void, _: []const u8) !void {
            return error.UnexpectedBody;
        }
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
    var response = try client.requestStreaming(
        .{
            .method = "HEAD",
            .path = "/head-stream-writer",
            .authority = "localhost",
        },
        {},
        Consumer.consume,
    );
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
    try std.testing.expectEqualStrings(
        "123",
        runtime.testing.findHeader(
            response.headers,
            "content-length",
        ).?,
    );
}

test "HTTP/2 response writer deinit cancels unfinished response" {
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
            var response = try connection.startResponse(
                request.stream_id,
                .{},
            );
            response.deinit();
            try std.testing.expect(response.finished);
        }
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
        error.StreamReset,
        client.request(.{
            .path = "/abandoned-writer",
            .authority = "localhost",
        }),
    );
    thread.join();
    if (shared.err) |err| return err;
}

const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Limits = runtime.Limits;
const Server = runtime.Server;

test "HTTP/2 request writer streams with flow control and trailers" {
    const allocator = std.testing.allocator;
    const first = "request-writer-first-" ** 2048;
    const second = "request-writer-second-" ** 2048;
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
        bytes: usize = 0,
        checksum: u64 = 0,
        calls: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn consume(shared: *@This(), data: []const u8) !void {
            shared.bytes += data.len;
            shared.calls += 1;
            for (data) |byte| shared.checksum +%= byte;
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequestStreaming(
                shared,
                consume,
            );
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(expected_len, request.body_bytes);
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings(
                "complete",
                request.trailers[0].value,
            );
            try connection.writeResponse(request.stream_id, .{
                .body = "accepted",
            });
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

    var writer = try client.startRequest(.{
        .path = "/stream-upload",
        .authority = "localhost",
        .body_length = expected_len,
    });
    defer writer.deinit();
    try writer.write(first);
    try writer.write(second);
    try writer.finishTrailers(&.{.{
        .name = "x-upload-state",
        .value = "complete",
    }});
    var response = try writer.readResponse();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    var expected_checksum: u64 = 0;
    for (first) |byte| expected_checksum +%= byte;
    for (second) |byte| expected_checksum +%= byte;
    try std.testing.expectEqualStrings("accepted", response.body);
    try std.testing.expectEqual(expected_len, shared.bytes);
    try std.testing.expectEqual(expected_checksum, shared.checksum);
    try std.testing.expect(shared.calls > 2);
    try std.testing.expect(writer.body_finished);
    try std.testing.expect(writer.completed);
}

test "HTTP/2 request writer length errors are transactional" {
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
            try std.testing.expectEqualStrings("abcde", request.body);
            try connection.writeResponse(request.stream_id, .{});
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
    var writer = try client.startRequest(.{
        .path = "/length-retry",
        .authority = "localhost",
        .body_length = 5,
    });
    defer writer.deinit();
    try writer.write("ab");
    try std.testing.expectError(
        error.InvalidContentLength,
        writer.finishData("toolong"),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.written);
    try std.testing.expect(!writer.body_finished);
    try writer.finishData("cde");
    var response = try writer.readResponse();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer deinit cancels after body FIN" {
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
            var reset = try connection.readResetStream();
            defer reset.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                request.stream_id,
                reset.reset.stream_id,
            );
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
    var writer = try client.startRequest(.{
        .path = "/cancel-after-fin",
        .authority = "localhost",
        .body_length = 0,
    });
    try writer.finish();
    writer.deinit();
    try std.testing.expect(writer.completed);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer preserves early response while flow blocked" {
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
            const stream_id = try readRequestHeadersStreamId(&connection);
            try runtime.testing.writeHeaders(
                &connection,
                stream_id,
                &.{
                    .{ .name = ":status", .value = "413" },
                    .{ .name = "content-length", .value = "14" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                stream_id,
                "stop uploading",
                true,
            );
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
    var writer = try client.startRequest(.{
        .path = "/early-response",
        .authority = "localhost",
    });
    defer writer.deinit();

    // Permit exactly the first chunk. The second write must wait for peer
    // input, where it encounters the response HEADERS before WINDOW_UPDATE.
    client.send_connection_window.value = "first".len;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = "first".len;
    try writer.write("first");
    try std.testing.expectError(
        error.ResponseAvailable,
        writer.write("second"),
    );
    try std.testing.expectEqual(@as(usize, "first".len), writer.written);
    try std.testing.expect(writer.body_finished);
    var response = try writer.readResponse();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 413), response.status);
    try std.testing.expectEqualStrings("stop uploading", response.body);
    try std.testing.expect(writer.completed);
}

test "HTTP/2 request writer reports peer reset while flow blocked" {
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
            const stream_id = try readRequestHeadersStreamId(&connection);
            try runtime.testing.addActivePeerStream(
                &connection,
                stream_id,
            );
            try connection.sendResetStream(
                stream_id,
                .cancel,
            );
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
    var writer = try client.startRequest(.{
        .path = "/early-reset",
        .authority = "localhost",
    });
    defer writer.deinit();
    client.send_connection_window.value = "first".len;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = "first".len;
    try writer.write("first");
    try std.testing.expectError(
        error.StreamReset,
        writer.write("second"),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer streams response preserved during upload" {
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
            const stream_id = try readRequestHeadersStreamId(&connection);
            try runtime.testing.writeHeaders(
                &connection,
                stream_id,
                &.{
                    .{ .name = ":status", .value = "422" },
                    .{ .name = "content-length", .value = "5" },
                },
                false,
            );
            try runtime.testing.writeData(
                &connection,
                stream_id,
                "early",
                true,
            );
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
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/early-stream-response",
        .authority = "localhost",
    });
    defer writer.deinit();
    client.send_connection_window.value = 0;
    (try runtime.testing.sendStreamWindow(
        &client,
        writer.stream_id,
    )).value = 0;
    try std.testing.expectError(
        error.ResponseAvailable,
        writer.write("never-sent"),
    );
    var consumer: Consumer = .{};
    var response = try writer.readResponseStreaming(
        &consumer,
        Consumer.consume,
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 422), response.status);
    try std.testing.expectEqualStrings(
        "early",
        consumer.storage[0..consumer.len],
    );
}

fn readRequestHeadersStreamId(
    connection: *runtime.Connection,
) !u31 {
    while (true) {
        var frame = try runtime.testing.readOwnedFrame(connection);
        defer frame.deinit(connection.allocator);
        if (try runtime.testing.handleConnectionFrame(
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

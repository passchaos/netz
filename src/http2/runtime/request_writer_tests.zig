const std = @import("std");
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

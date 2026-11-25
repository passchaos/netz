const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const allocator = std.testing.allocator;
const limits: runtime.Limits = .{
    .max_head_bytes = 4096,
    .max_body_bytes = 2 * 1024 * 1024,
};

test "HTTP/1 pull body reader exposes chunked trailers" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits);
    defer server.deinit();

    const Peer = struct {
        fn run(listener: *runtime.Server) !void {
            var connection = try listener.accept();
            defer connection.close();
            var reader = try connection.readRequestBody(.{});
            defer reader.deinit();
            const head = try reader.head();
            try std.testing.expectEqual(http1.BodyFraming.chunked, head.body_framing);
            var total: usize = 0;
            while (try reader.next()) |chunk| total += chunk.len;
            try std.testing.expectEqual(@as(usize, "hello world".len), total);
            var request = try reader.takeRequest();
            defer request.deinit(listener.allocator);
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings("x-checksum", request.trailers[0].name);
            try std.testing.expectEqualStrings("1", request.trailers[0].value);
            try connection.writeResponse(.{ .body = "ok", .request_method = request.method });
        }
    };
    var task = try io.concurrent(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/chunked",
        .host = "localhost",
        .body = "hello world",
        .trailers = &.{.{ .name = "x-checksum", .value = "1" }},
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);
    try task.await(io);
}

test "HTTP/1 pull body reader cancellation closes the connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits);
    defer server.deinit();
    const body = try allocator.alloc(u8, 512 * 1024);
    defer allocator.free(body);
    @memset(body, 'x');

    const Peer = struct {
        fn run(listener: *runtime.Server) !void {
            var connection = try listener.accept();
            defer connection.close();
            var reader = try connection.readRequestBody(.{});
            _ = try reader.head();
            const first = try reader.next();
            try std.testing.expect(first != null);
            reader.deinit();
        }
    };
    var task = try io.concurrent(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    if (client.request(.{ .method = .POST, .target = "/cancel", .host = "localhost", .body = body })) |response_value| {
        var response = response_value;
        response.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |_| {}
    try task.await(io);
}

test "HTTP/1 pull body reader enforces max_body_bytes" {
    const small_limits: runtime.Limits = .{ .max_head_bytes = 4096, .max_body_bytes = 1024 };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, small_limits);
    defer server.deinit();
    const body = try allocator.alloc(u8, 4096);
    defer allocator.free(body);
    @memset(body, 'x');

    const Peer = struct {
        fn run(listener: *runtime.Server) !void {
            var connection = try listener.accept();
            defer connection.close();
            var reader = try connection.readRequestBody(.{});
            defer reader.deinit();
            _ = reader.head() catch |err| {
                try std.testing.expectEqual(error.BodyTooLarge, err);
                return;
            };
            var failure: ?anyerror = null;
            while (true) {
                const chunk = reader.next() catch |err| {
                    failure = err;
                    break;
                };
                if (chunk == null) break;
            }
            try std.testing.expectEqual(error.BodyTooLarge, failure.?);
        }
    };
    var task = try io.concurrent(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), small_limits);
    defer client.close();
    if (client.request(.{ .method = .POST, .target = "/limit", .host = "localhost", .body = body })) |response_value| {
        var response = response_value;
        response.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |_| {}
    try task.await(io);
}

test "HTTP/1 pull body head exposes a content decoder" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits);
    defer server.deinit();

    const Peer = struct {
        fn run(listener: *runtime.Server) !void {
            var connection = try listener.accept();
            defer connection.close();
            var reader = try connection.readRequestBody(.{});
            defer reader.deinit();
            const head = try reader.head();
            var decoder = try head.streamContentDecoder(listener.allocator, .{ .max_encoded_bytes = 1024, .max_decoded_bytes = 1024 });
            defer decoder.deinit();
            var output: [64]u8 = undefined;
            var written: usize = 0;
            while (try reader.next()) |chunk| {
                const result = try decoder.step(chunk, output[written..]);
                written += result.output_written;
            }
            const result = try decoder.finish(output[written..]);
            written += result.output_written;
            try std.testing.expectEqualStrings("hello", output[0..written]);
            var request = try reader.takeRequest();
            defer request.deinit(listener.allocator);
            try connection.writeResponse(.{ .body = "ok", .request_method = request.method });
        }
    };
    var task = try io.concurrent(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    var response = try client.request(.{ .method = .POST, .target = "/decode", .host = "localhost", .body = "hello" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);
    try task.await(io);
}

test "HTTP/1 pull body reader streams keeps alive and handles 100-continue" {
    try @import("../../internal/testing/native_protocol_io.zig").run(pullReaderRoundTrip);
}

fn pullReaderRoundTrip(io: std.Io) anyerror!void {
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, limits);
    defer server.deinit();
    const body = try allocator.alloc(u8, 200 * 1024);
    defer allocator.free(body);
    for (body, 0..) |*byte, index| byte.* = @intCast(index % 251);

    const Peer = struct {
        fn run(listener: *runtime.Server, expected: []const u8) !void {
            var connection = try listener.accept();
            defer connection.close();
            var reader = try connection.readRequestBody(.{});
            defer reader.deinit();
            const head = try reader.head();
            try std.testing.expect(head.method == .POST);
            try std.testing.expectEqualStrings("/upload", head.target);
            try std.testing.expectEqual(@as(?usize, expected.len), head.content_length);
            try std.testing.expect(!reader.requestReady());
            try std.testing.expectError(error.RequestNotComplete, reader.takeRequest());
            var total: usize = 0;
            var chunks: usize = 0;
            while (try reader.next()) |chunk| {
                total += chunk.len;
                chunks += 1;
            }
            try std.testing.expectEqual(expected.len, total);
            try std.testing.expect(chunks > 1);
            var request = try reader.takeRequest();
            defer request.deinit(listener.allocator);
            try std.testing.expectEqualStrings("/upload", request.target);
            try connection.writeResponse(.{ .body = "ok", .request_method = request.method });
            var second = try connection.readRequest(.{});
            defer second.deinit(listener.allocator);
            try std.testing.expectEqualStrings("/next", second.request.target);
            try connection.writeResponse(.{ .body = "next", .request_method = second.request.method });
        }
    };
    var task = try io.concurrent(Peer.run, .{ &server, body });
    defer _ = task.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    var first = try client.request(.{
        .method = .POST,
        .target = "/upload",
        .host = "localhost",
        .headers = &.{.{ .name = "expect", .value = "100-continue" }},
        .body = body,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("ok", first.response.body);
    var second = try client.request(.{ .target = "/next", .host = "localhost" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("next", second.response.body);
    try task.await(io);
}

test "HTTP/1 pull reader construction requires independent producer" {
    const Request = @import("body_reader.zig").Reader(error{FixtureEnd}).Request;
    const Connection = struct {
        io: std.Io,
        closed: bool = false,
        pub fn close(self: *@This()) void {
            self.closed = true;
        }
        pub fn readRequestStreamingWithOptionsAndHead(_: *@This(), _: http1.ParseOptions, context: anytype, comptime _: anytype, comptime consume: anytype) anyerror!Request {
            try consume(context, "a");
            try consume(context, "b");
            return error.FixtureEnd;
        }
    };
    const Pull = @import("body_pull.zig").Reader(Connection, error{FixtureEnd});
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    var connection: Connection = .{ .io = io };
    const Worker = struct {
        connection: *Connection,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            defer self.done.set(self.connection.io);
            const reader = Pull.init(allocator, self.connection, .{}, 1) catch |err| {
                self.err = err;
                return;
            };
            reader.deinit();
        }
    };
    var worker: Worker = .{ .connection = &connection };
    var future = try std.Io.concurrent(io, Worker.run, .{&worker});
    defer future.cancel(io);
    try worker.done.waitTimeout(io, .{ .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }) });
    future.await(io);
    if (worker.err) |err| return err;
}

test "HTTP/1 pull producer rejected admission releases allocation" {
    const Request = @import("body_reader.zig").Reader(error{FixtureEnd}).Request;
    const Connection = struct {
        io: std.Io,
        calls: usize = 0,
        closed: bool = false,
        pub fn close(self: *@This()) void {
            self.closed = true;
        }
        pub fn readRequestStreamingWithOptionsAndHead(self: *@This(), _: http1.ParseOptions, _: anytype, comptime _: anytype, comptime _: anytype) anyerror!Request {
            self.calls += 1;
            return error.FixtureEnd;
        }
    };
    const Pull = @import("body_pull.zig").Reader(Connection, error{FixtureEnd});
    var backend = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
    defer backend.deinit();
    var allocations = std.testing.FailingAllocator.init(allocator, .{});
    var connection: Connection = .{ .io = backend.io() };
    try std.testing.expectError(error.ConcurrencyUnavailable, Pull.init(allocations.allocator(), &connection, .{}, 1));
    try std.testing.expectEqual(allocations.allocated_bytes, allocations.freed_bytes);
    try std.testing.expectEqual(@as(usize, 0), connection.calls);
    try std.testing.expect(!connection.closed);
}

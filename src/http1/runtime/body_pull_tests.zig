const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const allocator = std.testing.allocator;
const limits: runtime.Limits = .{
    .max_head_bytes = 4096,
    .max_body_bytes = 2 * 1024 * 1024,
};

test "HTTP/1 pull body reader streams keeps alive and handles 100-continue" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
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

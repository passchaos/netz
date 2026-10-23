const std = @import("std");
const h2 = @import("../../runtime.zig");
const metadata = @import("../../../http/content_coding/response_tests.zig");

test "HTTP/2 push before parent preserves content metadata" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try h2.Server.listen(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        server: *h2.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(3));
            defer request.deinit(std.testing.allocator);
            const pushed = try connection.promisePush(request.stream_id, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" },
                .{ .name = ":path", .value = "/cached" },
            });
            // The push finishes before its parent, forcing its HEADERS into
            // the buffered pushed-response path while the client awaits /
            try connection.writePushedResponse(pushed, .{
                .status = 304,
                .headers = &.{
                    .{ .name = "content-encoding", .value = "gzip" },
                    .{ .name = "content-length", .value = "123" },
                },
            });
            try connection.writeResponse(request.stream_id, .{});
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try h2.Client.connect(std.testing.allocator, io, server.address(), .{
        .enable_push = true,
        .max_body_bytes = 1,
    });
    defer client.close();
    var parent = try client.requestWithTimeout(.{ .path = "/", .authority = "localhost" }, .fromSeconds(3));
    defer parent.deinit(std.testing.allocator);
    var promise = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
    defer promise.deinit(std.testing.allocator);
    var pushed = try client.readPushedResponse(promise);
    defer pushed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 304), pushed.status);
    try std.testing.expect(!pushed.body_allowed);
    try metadata.expectEmpty(pushed);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const allocator = std.testing.allocator;

test "gRPC unary transparently retries an unprocessed REFUSED_STREAM once" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_concurrent_streams = 1 });
    defer server.deinit();
    const Peer = struct {
        server: *http2.runtime.Server,
        attempts: usize = 0,
        first_timeout: ?i96 = null,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            for (0..3) |index| {
                var request = try connection.readRequestWithTimeout(.fromSeconds(2));
                defer request.deinit(allocator);
                self.attempts += 1;
                try std.testing.expect(grpc.call.headerValue(request.headers, "grpc-previous-rpc-attempts") == null);
                const timeout = try grpc.Timeout.parse(grpc.call.headerValue(request.headers, "grpc-timeout").?);
                if (index == 0) self.first_timeout = timeout.duration().nanoseconds;
                if (index == 1) try std.testing.expect(timeout.duration().nanoseconds <= self.first_timeout.?);
                var parsed = try grpc.parseUnaryRequest(allocator, &request, 1024);
                defer parsed.deinit();
                try std.testing.expectEqualStrings("request", parsed.message.payload);
                if (index == 0) try connection.sendResetStream(request.stream_id, .refused_stream) else try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{ .message = "reply" });
            }
        }
    };
    var peer: Peer = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try grpc.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.deinit();
    const options: grpc.UnaryCallOptions = .{ .path = "/fixture.Refused/Unary", .authority = "localhost", .message = "request", .timeout = .{ .value = 2, .unit = .second } };
    var response = try client.unary(options);
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("reply", response.message.?.payload);
    var healthy = try client.unary(options);
    defer healthy.deinit();
    try std.testing.expectEqual(grpc.Status.ok, healthy.status);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), peer.attempts);
}

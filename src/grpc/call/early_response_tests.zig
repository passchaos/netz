//! A terminal gRPC status can precede completion of a unary upload.
const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");

test "gRPC unary preserves early trailers-only status and channel reuse" {
    for ([_]bool{ false, true }) |retry| try exercise(retry, false);
}

test "gRPC unary preserves early status followed by NO_ERROR reset" {
    for ([_]bool{ false, true }) |retry| try exercise(retry, true);
}

fn exercise(retry: bool, server_reset: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .initial_window_size = 8, .max_concurrent_streams = 1 }, 1024);
    defer server.deinit();
    const Peer = struct {
        server: *grpc.runtime.Server,
        server_reset: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.deinit();
            {
                var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(2));
                defer stream.deinit();
                try stream.finish(.permission_denied, "early denial", &.{.{ .name = "x-denied", .value = "yes" }}, &.{});
                if (self.server_reset) {
                    try stream.transport.reset(.no_error);
                } else {
                    const drain = try stream.drainRequestAfterResponseWithDeadline(.fromNow(connection.connection.io, .{ .raw = .fromSeconds(2), .clock = .awake }));
                    switch (drain) {
                        .reset => |reset| try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code),
                        .finished => return error.ShortUploadFin,
                    }
                }
            }
            var request = try connection.readUnaryWithTimeout(.fromSeconds(2));
            defer request.deinit();
            try std.testing.expectEqualStrings("next", request.request.message.payload);
            try connection.writeUnary(request.request.stream_id, .{ .message = "healthy" });
        }
    };
    var peer: Peer = .{ .server = &server, .server_reset = server_reset };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try grpc.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.deinit();
    const options: grpc.UnaryCallOptions = .{ .path = "/fixture.Early/Unary", .authority = "localhost", .message = "upload" ** 32, .timeout = .{ .value = 2, .unit = .second } };
    var response = if (retry) try client.unaryWithRetry(options, .{ .max_attempts = 5, .initial_backoff = .fromMilliseconds(1), .max_backoff = .fromMilliseconds(10), .backoff_multiplier = 2, .retryable_status_codes = &.{.unavailable} }) else try client.unary(options);
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.permission_denied, response.status);
    try std.testing.expectEqualStrings("early denial", response.status_message);
    try std.testing.expect(response.transport.?.trailers_only);
    try std.testing.expect(response.reset == null);
    try std.testing.expect(response.message == null);
    try std.testing.expect(!client.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), client.connection.activeLocalStreamCount());
    var healthy = try client.unary(.{ .path = "/fixture.Early/Unary", .authority = "localhost", .message = "next", .timeout = .{ .value = 2, .unit = .second } });
    defer healthy.deinit();
    try std.testing.expectEqualStrings("healthy", healthy.message.?.payload);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

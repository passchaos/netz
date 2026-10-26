//! Public streaming APIs preserve body/trailer metadata under one deadline.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

test "HTTP/2 stream output deadline round trip preserves request and response trailers" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings("hello", request.body);
            try std.testing.expectEqualStrings("sent", runtime.testing.findHeader(request.trailers, "x-upload").?);
            const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromSeconds(2), .clock = .awake });
            var writer = try connection.startResponseWithDeadline(request.stream_id, .{ .status = 201, .headers = &.{.{ .name = "content-length", .value = "5" }} }, deadline);
            defer writer.deinit();
            try writer.writeWithDeadline("world", deadline);
            try writer.finishTrailersWithDeadline(&.{.{ .name = "x-response", .value = "received" }}, deadline);
            try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
            // A subsequent request demonstrates stream release and HPACK reuse.
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "next" });
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
    var upload = try client.startRequestWithDeadline(.{ .path = "/stream", .authority = "localhost", .body_length = 5 }, deadline);
    defer upload.deinit();
    try upload.writeWithDeadline("hello", deadline);
    try upload.finishTrailersWithDeadline(&.{.{ .name = "x-upload", .value = "sent" }}, deadline);
    try std.testing.expect(upload.body_finished);
    try std.testing.expectEqual(@as(usize, 1), client.activeLocalStreamCount());
    var response = try upload.readResponseWithDeadline(deadline);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), response.status);
    try std.testing.expectEqualStrings("world", response.body);
    try std.testing.expectEqualStrings("received", runtime.testing.findHeader(response.trailers, "x-response").?);
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());
    var next = try client.requestWithTimeout(.{ .path = "/next", .authority = "localhost" }, .fromSeconds(2));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

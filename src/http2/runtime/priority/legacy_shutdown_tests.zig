//! A graceful synchronization pump honors the same priority-ignore policy.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const legacyHeaders = @import("legacy_test_support.zig").legacyHeaders;
const allocator = std.testing.allocator;

test "HTTP/2 RFC9218 graceful preadmission ignores legacy dependencies and preserves admitted request" {
    try exercise();
}

fn exercise() !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .no_rfc7540_priorities = true });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            try connection.gracefulShutdownWithTimeout(.fromSeconds(2));
            try std.testing.expect(connection.gracefulShutdownComplete());
            try std.testing.expectEqual(@as(u31, 1), connection.local_goaway_last_stream_id.?);
            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings("/admitted", request.path);
            try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(request.headers, "x-sync").?);
            try connection.writeResponse(request.stream_id, .{ .body = "admitted" });
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var initial = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer initial.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u31), initial.goaway.last_stream_id);
    // This request raced the first GOAWAY and must be admitted before the
    // synchronization PING is acknowledged; its obsolete signals are ignored.
    try runtime.testing.addActiveLocalStream(&client, 1);
    try legacyHeaders(&client, 1, &.{
        .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/admitted" },
        .{ .name = "x-sync", .value = "preserved" },
    }, false);
    _ = try client.readPingWithTimeout(.fromSeconds(2));
    var final = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), final.goaway.last_stream_id);
    var response = try client.readResponseWithTimeout(1, "GET", false, .fromSeconds(2));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("admitted", response.body);
    try std.testing.expect(!client.aggregate_timeout_unusable);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

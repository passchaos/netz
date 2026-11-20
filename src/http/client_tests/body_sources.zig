//! The pooled H2 owner must apply the same BodySource contract as Client.
const std = @import("std");
const http = @import("../mod.zig");
const runtime = @import("../../http2/runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

test "unified HTTP pooled H2 body sources override fallback body under flow control" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .initial_window_size = 320,
        .max_concurrent_streams = 2,
    });
    defer server.deinit();
    var payload: [70 * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 7 + 3);
    const Worker = struct {
        fn run(listener: *runtime.Server, expected: []const u8) !void {
            var connection = try listener.acceptWithDeadline(deadline(listener.io));
            defer connection.close();
            for (0..4) |index| {
                var request = try connection.readRequestWithDeadline(deadline(listener.io));
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(if (index == 3) "" else expected, request.body);
                try std.testing.expectEqualStrings("done", request.trailers[0].value);
                try connection.writeResponseWithDeadline(request.stream_id, .{
                    .body = "correct-source",
                    .request_method = request.method,
                }, deadline(listener.io));
            }
            var later = try connection.readRequestWithDeadline(deadline(listener.io));
            defer later.deinit(allocator);
            try std.testing.expectEqualStrings("/later", later.path);
            try connection.writeResponseWithDeadline(later.stream_id, .{ .body = "reused" }, deadline(listener.io));
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, &payload });
    defer _ = serving.cancel(io) catch {};
    var pool = try http.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
        .client = .{ .cleartext_protocol = .http2_prior_knowledge },
        .http2_shared_requests = .{ .write_chunk_bytes = 1024 },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/upload", .{server.address().getPort()});
    defer allocator.free(uri);
    for (0..4) |index| {
        var reader = std.Io.Reader.fixed(if (index == 3) "" else &payload);
        var response = try pool.requestUriWithDeadline(uri, .{
            .method = "POST",
            .body = "wrong-fallback",
            .body_source = if (index == 0) .{ .slice = &payload } else .{ .reader = .{
                .reader = &reader,
                .length = if (index == 1) null else if (index == 3) 0 else payload.len,
            } },
            .trailers = &.{.{ .name = "x-upload", .value = "done" }},
        }, deadline(io));
        defer response.deinit();
        try std.testing.expectEqualStrings("correct-source", response.body());
    }
    const later_uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/later", .{server.address().getPort()});
    defer allocator.free(later_uri);
    var later = try pool.requestUriWithDeadline(later_uri, .{}, deadline(io));
    defer later.deinit();
    try std.testing.expectEqualStrings("reused", later.body());
    try serving.await(io);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
}

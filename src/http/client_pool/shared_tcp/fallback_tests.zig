//! CONNECT and explicit push keep their existing exclusive aggregate owners.
const std = @import("std");
const pool_mod = @import("../../client_pool.zig");
const runtime = @import("../../../http2/runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn exercise(comptime push: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        fn run(listener: *runtime.Server, worker_io: std.Io) !void {
            var connection = try listener.acceptWithDeadline(deadline(worker_io));
            defer connection.close();
            var request = try connection.readRequestWithDeadline(deadline(worker_io));
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings(if (push) "GET" else "CONNECT", request.method);
            if (push) {
                const promised = try connection.promisePush(request.stream_id, &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":authority", .value = request.authority.? },
                    .{ .name = ":path", .value = "/asset" },
                });
                // Push precedes the parent response, so a duplex owner that
                // rejects PUSH_PROMISE cannot silently pass this regression.
                try connection.writePushedResponse(promised, .{ .status = 304, .headers = &.{.{ .name = "content-length", .value = "123" }} });
            }
            try connection.writeResponseWithDeadline(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "x-exclusive", .value = if (push) "push" else "connect" }},
                .body = if (push) "parent" else "",
            }, deadline(worker_io));
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_total_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
        .client = .{ .cleartext_protocol = .http2_prior_knowledge, .http2_limits = .{ .enable_push = push } },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/parent", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try pool.requestUriWithDeadline(uri, .{ .method = if (push) "GET" else "CONNECT" }, deadline(io));
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status());
    try std.testing.expectEqualStrings(if (push) "push" else "connect", response.header("x-exclusive").?);
    try std.testing.expectEqualStrings(if (push) "parent" else "", response.body());
    if (!push) try std.testing.expect(!response.value.http2.body_allowed);
    try serving.await(io);
    pool.close();
    try std.testing.expectEqual(@as(usize, 0), pool.totalConnectionCount());
}

test "unified HTTP exclusive CONNECT preserves successful aggregate response semantics" {
    try exercise(false);
}

test "unified HTTP exclusive push opt in preserves parent response after PUSH_PROMISE" {
    try exercise(true);
}

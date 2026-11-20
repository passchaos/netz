//! Ordinary URI requests must admit late H2 siblings on one allowed TCP socket.
const std = @import("std");
const pool_mod = @import("../../client_pool.zig");
const client = @import("../../client.zig");
const runtime = @import("../../../http2/runtime.zig");
const backend_mod = @import("../../../runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

const Server = struct {
    io: std.Io,
    server: *runtime.Server,
    first_received: std.Io.Event = .unset,
    cancel_received: std.Io.Event = .unset,
    both_pending: std.Io.Event = .unset,
    release_survivor: std.Io.Event = .unset,
    accepts: usize = 0,
    observe_cancel_headers: bool = false,

    fn run(self: *Server) !void {
        var connection = try self.server.acceptWithDeadline(deadline(self.io));
        defer connection.close();
        self.accepts += 1;
        var first = try connection.readRequestWithDeadline(deadline(self.io));
        defer first.deinit(allocator);
        try std.testing.expectEqualStrings("/first", first.path);
        try std.testing.expectEqualStrings("first-body", first.body);
        try std.testing.expectEqualStrings("upload-done", field(first.trailers, "x-upload"));
        self.first_received.set(self.io);
        // The first response is deliberately unavailable until a later URI
        // request reaches this same connection. Prequeued batching cannot pass.
        var second = try connection.readRequestWithDeadline(deadline(self.io));
        defer second.deinit(allocator);
        try std.testing.expectEqualStrings("/second", second.path);
        const ids = [_]u31{ first.stream_id, second.stream_id };
        const responses = [_]runtime.ResponseOptions{
            .{ .status = 201, .body = "first", .headers = &.{.{ .name = "x-overlap", .value = "one-connection" }}, .trailers = &.{.{ .name = "x-finished", .value = "first" }} },
            .{ .status = 200, .body = "second" },
        };
        for (ids, responses) |id, response| try connection.writeResponseWithDeadline(id, response, deadline(self.io));

        var cancel = try connection.readRequestWithDeadline(deadline(self.io));
        defer cancel.deinit(allocator);
        try std.testing.expectEqualStrings("/cancel", cancel.path);
        var held_response: ?runtime.ResponseWriter = null;
        defer if (held_response) |*response| response.deinit();
        if (self.observe_cancel_headers) {
            held_response = try connection.startResponseWithDeadline(cancel.stream_id, .{
                .headers = &.{.{ .name = "x-held-response", .value = "packed-header-ownership" }},
            }, deadline(self.io));
        }
        self.cancel_received.set(self.io);
        var survivor = try connection.readRequestWithDeadline(deadline(self.io));
        defer survivor.deinit(allocator);
        try std.testing.expectEqualStrings("/survivor", survivor.path);
        self.both_pending.set(self.io);
        if (self.observe_cancel_headers) {
            var probe = try connection.readRequestWithDeadline(deadline(self.io));
            defer probe.deinit(allocator);
            try std.testing.expectEqualStrings("/cancel-head-seen", probe.path);
            // This head follows the held stream's head in HPACK wire order.
            // Receiving its whole response proves the owner already decoded
            // and retained the held head before the caller cancels it.
            try connection.writeResponseWithDeadline(probe.stream_id, .{ .body = "head-seen" }, deadline(self.io));
        }
        try self.release_survivor.waitTimeout(self.io, .{ .deadline = deadline(self.io) });
        try connection.writeResponseWithDeadline(survivor.stream_id, .{ .body = "survivor" }, deadline(self.io));

        // Reading the later request also consumes the canceled sibling's RST.
        // A lost connection or cancellation of the survivor fails this gate.
        var later = try connection.readRequestWithDeadline(deadline(self.io));
        defer later.deinit(allocator);
        try std.testing.expectEqualStrings("/later", later.path);
        try connection.writeResponseWithDeadline(later.stream_id, .{ .body = "later" }, deadline(self.io));
    }
};

fn request(pool: *pool_mod.Pool, uri: []const u8, options: client.RequestOptions) !client.OwnedResponse {
    return pool.requestUri(uri, options);
}

fn field(headers: anytype, name: []const u8) []const u8 {
    for (headers) |header| if (std.mem.eql(u8, header.name, name)) return header.value;
    return "";
}

fn exercise(io: std.Io, comptime observe_cancel_headers: bool) !void {
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_concurrent_streams = if (observe_cancel_headers) 3 else 2,
    });
    defer server.deinit();
    var worker = Server{ .io = io, .server = &server, .observe_cancel_headers = observe_cancel_headers };
    var serving = try io.concurrent(Server.run, .{&worker});
    defer _ = serving.cancel(io) catch {};
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_total_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
        .client = .{ .cleartext_protocol = .http2_prior_knowledge },
        .http2_shared_requests = .{ .write_chunk_bytes = 4 },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{server.address().ip4.port});
    defer allocator.free(base);
    const first_uri = try std.fmt.allocPrint(allocator, "{s}/first", .{base});
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(allocator, "{s}/second", .{base});
    defer allocator.free(second_uri);
    var first = try io.concurrent(request, .{ &pool, first_uri, client.RequestOptions{
        .method = "POST",
        .body = "first-body",
        .trailers = &.{.{ .name = "x-upload", .value = "upload-done" }},
    } });
    var first_consumed = false;
    defer if (!first_consumed) if (first.cancel(io)) |value| {
        var response = value;
        response.deinit();
    } else |_| {};
    try worker.first_received.waitTimeout(io, .{ .deadline = deadline(io) });
    var second = try io.concurrent(request, .{ &pool, second_uri, client.RequestOptions{} });
    var second_consumed = false;
    defer if (!second_consumed) if (second.cancel(io)) |value| {
        var response = value;
        response.deinit();
    } else |_| {};
    var second_response = try second.await(io);
    second_consumed = true;
    defer second_response.deinit();
    var first_response = try first.await(io);
    first_consumed = true;
    defer first_response.deinit();
    try std.testing.expectEqual(client.Protocol.http2, first_response.protocol());
    try std.testing.expectEqual(@as(u16, 201), first_response.status());
    try std.testing.expectEqualStrings("first", first_response.body());
    try std.testing.expectEqualStrings("first", first_response.trailer("x-finished").?);
    try std.testing.expectEqualStrings("one-connection", first_response.header("x-overlap").?);
    try std.testing.expectEqualStrings("second", second_response.body());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.totalConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    const cancel_uri = try std.fmt.allocPrint(allocator, "{s}/cancel", .{base});
    defer allocator.free(cancel_uri);
    const survivor_uri = try std.fmt.allocPrint(allocator, "{s}/survivor", .{base});
    defer allocator.free(survivor_uri);
    var canceled = try io.concurrent(request, .{ &pool, cancel_uri, client.RequestOptions{} });
    var cancel_consumed = false;
    defer if (!cancel_consumed) if (canceled.cancel(io)) |value| {
        var response = value;
        response.deinit();
    } else |_| {};
    try worker.cancel_received.waitTimeout(io, .{ .deadline = deadline(io) });
    var survivor = try io.concurrent(request, .{ &pool, survivor_uri, client.RequestOptions{} });
    var survivor_consumed = false;
    defer if (!survivor_consumed) if (survivor.cancel(io)) |value| {
        var response = value;
        response.deinit();
    } else |_| {};
    try worker.both_pending.waitTimeout(io, .{ .deadline = deadline(io) });
    if (observe_cancel_headers) {
        const probe_uri = try std.fmt.allocPrint(allocator, "{s}/cancel-head-seen", .{base});
        defer allocator.free(probe_uri);
        var probe = try pool.requestUriWithDeadline(probe_uri, .{}, deadline(io));
        defer probe.deinit();
        try std.testing.expectEqualStrings("head-seen", probe.body());
        try std.testing.expect(probe.value.http2.headers[0].block_storage != null);
    }
    try std.testing.expectError(error.Canceled, canceled.cancel(io));
    cancel_consumed = true;
    worker.release_survivor.set(io);
    var survived = try survivor.await(io);
    survivor_consumed = true;
    defer survived.deinit();
    try std.testing.expectEqualStrings("survivor", survived.body());
    const later_uri = try std.fmt.allocPrint(allocator, "{s}/later", .{base});
    defer allocator.free(later_uri);
    var later = try pool.requestUriWithDeadline(later_uri, .{}, deadline(io));
    defer later.deinit();
    try std.testing.expectEqualStrings("later", later.body());
    try serving.await(io);
    try std.testing.expectEqual(@as(usize, 1), worker.accepts);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.totalConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
    pool.close();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "unified HTTP ordinary H2 requests admit late siblings cancel independently and reuse one TCP connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try exercise(threaded.io(), false);
}

test "unified HTTP ordinary H2 zio cancels an owned packed response head and preserves sibling reuse" {
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    try exercise(backend.io(), true);
}

test "unified HTTP ordinary H2 wrapped zio keeps timed and untimed socket reads reusable" {
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    const delegate = backend.io();
    var vtable = delegate.vtable.*;
    const wrapped: std.Io = .{ .userdata = delegate.userdata, .vtable = &vtable };
    try exercise(wrapped, true);
}

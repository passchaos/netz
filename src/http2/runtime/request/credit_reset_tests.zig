const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");

const allocator = std.testing.allocator;

test "HTTP/2 request batch resets preserve shifted sibling DATA credit and replacement admission" {
    for ([_]usize{ 2, 17 }) |batch_len| {
        for ([_]u31{ 1, 3 }) |reset_id| {
            for ([_]bool{ false, true }) |completed| try exercise(batch_len, reset_id, completed);
        }
    }
}

fn exercise(batch_len: usize, reset_id: u31, completed: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const surviving_id: u31 = if (reset_id == 1) 3 else 1;
    const surviving_credit: usize = 2;
    const replacement_id: u31 = @intCast(batch_len * 2 + 1);
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        batch_len: usize,
        surviving_id: u31,
        surviving_credit: usize,
        replacement_id: u31,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn consume(_: *@This(), _: u31, _: []const u8) !void {}

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var storage: [17]runtime.StreamingRequest = undefined;
            const requests = storage[0..self.batch_len];
            try connection.readRequestBatchStreamingIntoWithTimeout(requests, .fromSeconds(2), self, @This().consume);
            defer for (requests) |*request| request.deinit(allocator);
            // One reset retires only its held credit. Stable compaction must
            // preserve the other stream's debit at its shifted slot, and an
            // earlier END_STREAM must not consume the replacement capacity.
            try std.testing.expectEqual(window.default_value - @as(i64, @intCast(self.surviving_credit)), connection.recv_connection_window.value);
            try std.testing.expectEqual(self.surviving_id, requests[0].stream_id);
            try std.testing.expectEqual(@as(usize, 2), requests[0].body_bytes);
            try std.testing.expectEqual(self.replacement_id, requests[requests.len - 1].stream_id);
            for (requests[1..]) |request| try std.testing.expectEqual(@as(usize, 0), request.body_bytes);
            for (requests) |request| try connection.writeResponse(request.stream_id, .{ .status = 204 });
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy" });
        }
    };
    var peer = Peer{
        .server = &server,
        .batch_len = batch_len,
        .surviving_id = surviving_id,
        .surviving_credit = surviving_credit,
        .replacement_id = replacement_id,
    };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    for (0..batch_len) |index| {
        const id: u31 = @intCast(index * 2 + 1);
        try runtime.testing.addActiveLocalStream(&client, id);
        try appendHead(&client, &bytes, id, if (index < 2) "2" else "0", index >= 2);
    }
    try wire.appendFrame(&bytes, allocator, .data, if (reset_id == 1 and completed) 1 else 0, 1, "ab");
    try wire.appendFrame(&bytes, allocator, .data, 0x08 | @as(u8, if (reset_id == 3 and completed) 1 else 0), 3, "\x02xy\x00\x00");
    try wire.appendFrame(&bytes, allocator, .rst_stream, 0, reset_id, &.{ 0, 0, 0, @intFromEnum(http2.ErrorCode.cancel) });
    try wire.appendFrame(&bytes, allocator, .data, 1, surviving_id, "");
    try runtime.testing.addActiveLocalStream(&client, replacement_id);
    try appendHead(&client, &bytes, replacement_id, "0", true);
    client.next_client_stream_id = replacement_id + 2;
    try client.send_connection_window.reserve(7);
    try (try runtime.testing.sendStreamWindow(&client, 1)).reserve(2);
    try (try runtime.testing.sendStreamWindow(&client, 3)).reserve(5);
    var writer = client.stream.writer(io, &.{});
    try writer.interface.writeAll(bytes.items);
    // Read complete responses in the batch's admitted order. This also
    // processes the target-only connection WINDOW_UPDATE before checking it.
    for (0..batch_len + 1) |index| {
        const id: u31 = @intCast(index * 2 + 1);
        if (id == reset_id) continue;
        var response = try client.readResponseWithTimeout(id, "POST", false, .fromSeconds(2));
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), response.status);
    }
    try std.testing.expectEqual(window.default_value - @as(i64, @intCast(surviving_credit)), client.send_connection_window.value);
    var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn appendHead(client: *runtime.Connection, bytes: *std.ArrayList(u8), id: u31, length: []const u8, finished: bool) !void {
    const block = try client.hpack_encoder.encodeBlockRetained(allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/reset-batch" },
        .{ .name = "content-length", .value = length },
    });
    try wire.appendFrame(bytes, allocator, .headers, 0x04 | @as(u8, if (finished) 1 else 0), id, block);
}

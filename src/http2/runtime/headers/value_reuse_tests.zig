const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

test "HTTP/2 field value rejection preserves request HPACK state and handler isolation" {
    for ([_]bool{ false, true }) |trailers| try exercise(true, trailers);
}

test "HTTP/2 field value rejection preserves response HPACK state and connection reuse" {
    for ([_]bool{ false, true }) |trailers| try exercise(false, trailers);
}

test "HTTP/2 field value preflight rejects before allocation stream IDs HPACK or I/O" {
    for ([_][]const u8{ " leading", "trailing\t" }) |value| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var connection = runtime.Connection{ .allocator = failing.allocator(), .io = undefined, .stream = undefined, .role = .client };
        defer connection.hpack_encoder.deinit(failing.allocator());
        try std.testing.expectError(error.InvalidHeader, connection.startRequest(.{ .path = "/invalid", .authority = "localhost", .headers = &.{.{ .name = "x-test", .value = value }} }));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
        try std.testing.expectEqual(@as(usize, 0), connection.hpack_encoder.dynamic_table.used);
    }
}

fn send(connection: *runtime.Connection, id: u31, fields: []const http2.Hpack.HeaderField, end: bool) !void {
    const block = try connection.hpack_encoder.encodeBlockRetained(allocator, fields);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try wire.appendFrame(&bytes, allocator, .headers, 0x04 | @as(u8, @intFromBool(end)), id, block);
    var writer = connection.stream.writer(connection.io, &.{});
    try writer.interface.writeAll(bytes.items);
}

fn requireIndexedSync(connection: *runtime.Connection) !void {
    const block = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{ .name = "x-sync", .value = "preserved" }});
    try std.testing.expectEqual(@as(usize, 1), block.len);
    try std.testing.expect(block[0] & 0x80 != 0);
}

fn sendInvalid(connection: *runtime.Connection, id: u31, request: bool, trailers: bool) !void {
    var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer fields.deinit(allocator);
    if (request) try fields.appendSlice(allocator, &.{
        .{ .name = ":method", .value = "GET" },    .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/invalid" }, .{ .name = ":authority", .value = "localhost" },
    }) else try fields.append(allocator, .{ .name = ":status", .value = "200" });
    if (!trailers) try fields.append(allocator, .{ .name = "x-bad", .value = " leading" });
    try fields.append(allocator, .{ .name = "x-sync", .value = "preserved" });
    try send(connection, id, fields.items, !trailers);
    if (trailers) try send(connection, id, &.{.{ .name = "x-bad", .value = "trailing\t" }}, true);
    try requireIndexedSync(connection);
}

fn exercise(comptime server_side: bool, trailers: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var server = try runtime.Server.listen(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        trailers: bool,
        calls: usize = 0,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn handler(self: *@This(), request: runtime.OwnedRequest) runtime.Error!runtime.ResponseOptions {
            self.calls += 1;
            if (!std.mem.eql(u8, "preserved", runtime.testing.findHeader(request.headers, "x-sync") orelse "")) return error.InvalidHeader;
            return .{ .body = "healthy" };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            if (server_side) {
                try std.testing.expectError(error.InvalidHeader, connection.serveOne(@This(), self, @This().handler));
                try std.testing.expectEqual(@as(usize, 0), self.calls);
                _ = try connection.serveOne(@This(), self, @This().handler);
                try std.testing.expectEqual(@as(usize, 1), self.calls);
            } else {
                var request = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer request.deinit(allocator);
                try sendInvalid(&connection, request.stream_id, false, self.trailers);
                var reset = try connection.readResetStreamWithTimeout(.fromSeconds(3));
                defer reset.deinit(allocator);
                try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
                var next = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer next.deinit(allocator);
                try connection.writeResponse(next.stream_id, .{ .body = "healthy", .headers = &.{.{ .name = "x-sync", .value = "preserved" }} });
            }
        }
    };
    var peer = Peer{ .server = &server, .trailers = trailers };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, threaded.io(), server.address(), .{});
    defer client.close();
    if (server_side) {
        try sendInvalid(&client, 1, true, trailers);
        client.next_client_stream_id = 3;
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(3));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
    } else try std.testing.expectError(error.InvalidHeader, client.requestWithTimeout(.{ .path = "/invalid", .authority = "localhost" }, .fromSeconds(3)));
    var healthy = try client.requestWithTimeout(.{
        .path = "/healthy",
        .authority = "localhost",
        .headers = if (server_side) &.{.{ .name = "x-sync", .value = "preserved" }} else &.{},
    }, .fromSeconds(3));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    if (!server_side) try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(healthy.headers, "x-sync").?);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

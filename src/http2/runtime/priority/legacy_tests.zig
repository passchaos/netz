//! Deprecated dependency semantics are ignored while framing remains validated.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

const legacyHeaders = @import("legacy_test_support.zig").legacyHeaders;

test "HTTP/2 RFC9218 legacy signals are ignored when local policy or client SETTINGS disables them" {
    for ([_]bool{ false, true }) |local_policy| {
        for ([_]bool{ false, true }) |fragmented| try requestCase(local_policy, fragmented);
    }
}

fn requestCase(local_policy: bool, fragmented: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .no_rfc7540_priorities = local_policy });
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
            var first = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer first.deinit(allocator);
            try std.testing.expectEqualStrings("/legacy", first.path);
            try std.testing.expectEqual(@as(u3, 1), first.priority.urgency);
            try std.testing.expect(first.priority.incremental);
            try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(first.headers, "x-sync").?);
            try connection.writeResponse(first.stream_id, .{ .body = "first" });
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(allocator);
            try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(next.headers, "x-sync").?);
            try connection.writeResponse(next.stream_id, .{ .body = "next" });
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{ .no_rfc7540_priorities = !local_policy });
    defer client.close();
    const id = try runtime.testing.reserveNextClientStreamId(&client);
    try legacyHeaders(&client, id, &.{
        .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/legacy" },
        .{ .name = "x-sync", .value = "preserved" },     .{ .name = "priority", .value = "u=1, i" },
    }, fragmented);
    var response = try client.readResponseWithTimeout(id, "GET", false, .fromSeconds(2));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("first", response.body);
    var next = try client.requestWithTimeout(.{ .path = "/next", .authority = "localhost", .headers = &.{.{ .name = "x-sync", .value = "preserved" }} }, .fromSeconds(2));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.body);
    try std.testing.expect(client.isReusable());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

const Mode = enum { aggregate, duplex, push };

test "HTTP/2 RFC9218 ignored legacy response signals preserve aggregate duplex and push HPACK" {
    inline for ([_]Mode{ .aggregate, .duplex, .push }) |mode| {
        for ([_]bool{ false, true }) |fragmented| try responseCase(mode, fragmented);
    }
}

fn responseCase(comptime mode: Mode, fragmented: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        fragmented: bool,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(allocator);
            const id = if (mode == .push) try connection.promisePush(request.stream_id, &.{
                .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/push" },
            }) else request.stream_id;
            try legacyHeaders(&connection, id, &.{ .{ .name = ":status", .value = "200" }, .{ .name = "x-sync", .value = "preserved" } }, self.fragmented);
            if (mode == .push) try connection.writeResponse(request.stream_id, .{ .body = "parent", .headers = &.{.{ .name = "x-sync", .value = "preserved" }} });
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "next", .headers = &.{.{ .name = "x-sync", .value = "preserved" }} });
        }
    };
    var peer = Peer{ .server = &server, .fragmented = fragmented };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{ .no_rfc7540_priorities = true, .enable_push = mode == .push });
    defer client.close();
    if (mode == .duplex) {
        var writer = try client.startRequest(.{ .path = "/legacy", .authority = "localhost" });
        defer writer.deinit();
        try writer.finish();
        var duplex = try writer.beginDuplex();
        defer duplex.deinit();
        var head = try duplex.readResponseEventWithTimeout(.fromSeconds(2));
        defer head.deinit(allocator);
        try std.testing.expect(head == .head);
        try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(head.head.headers, "x-sync").?);
        var finished = try duplex.readResponseEventWithTimeout(.fromSeconds(2));
        defer finished.deinit(allocator);
        try std.testing.expect(finished == .finished);
    } else {
        var response = try client.requestWithTimeout(.{ .path = "/legacy", .authority = "localhost" }, .fromSeconds(2));
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(response.headers, "x-sync").?);
        if (mode == .push) {
            var promise = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
            defer promise.deinit(allocator);
            var pushed = try client.readPushedResponseWithTimeout(promise, .fromSeconds(2));
            defer pushed.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), pushed.status);
            try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(pushed.headers, "x-sync").?);
        }
    }
    var next = try client.requestWithTimeout(.{ .path = "/next", .authority = "localhost" }, .fromSeconds(2));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.body);
    try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(next.headers, "x-sync").?);
    if (mode != .push) try std.testing.expect(client.isReusable());
    try std.testing.expect(!client.aggregate_timeout_unusable);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "HTTP/2 RFC9218 ignored legacy fields retain stream and framing validation" {
    var connection = runtime.Connection{ .allocator = allocator, .io = undefined, .stream = undefined, .role = .server };
    const priority = http2.Frame{ .header = .{ .length = 5, .frame_type = .priority, .flags = 0, .stream_id = 1 }, .payload = &.{ 0, 0, 0, 1, 16 } };
    try std.testing.expect(try runtime.testing.handleConnectionFrame(&connection, priority));
    connection.peer_no_rfc7540_priorities = true;
    try std.testing.expect(try runtime.testing.handleConnectionFrame(&connection, priority));
    connection.role = .client;
    connection.peer_no_rfc7540_priorities = false;
    try std.testing.expect(try runtime.testing.handleConnectionFrame(&connection, priority));
    connection.limits.no_rfc7540_priorities = true;
    var zero_id = priority;
    zero_id.header.stream_id = 0;
    try std.testing.expectError(error.InvalidStreamId, runtime.testing.handleConnectionFrame(&connection, zero_id));
    var short_priority = priority;
    short_priority.payload = priority.payload[0..4];
    try std.testing.expectError(error.InvalidFrameSize, runtime.testing.handleConnectionFrame(&connection, short_priority));
    const headers = http2.Frame{ .header = .{ .length = 9, .frame_type = .headers, .flags = 0x2d, .stream_id = 1 }, .payload = &.{ 2, 0, 0, 0, 1, 16, 0x88, 0, 0 } };
    try std.testing.expectError(error.InvalidStreamId, http2.HeadersPayload.parse(headers));
    const ignored = try http2.HeadersPayload.parseIgnoringPriority(headers);
    try std.testing.expect(ignored.priority == null);
    try std.testing.expectEqual(@as(u8, 2), ignored.padding_len);
    try std.testing.expectEqualSlices(u8, &.{0x88}, ignored.header_block);
    var truncated = headers;
    truncated.payload = headers.payload[0..5];
    try std.testing.expectError(error.InvalidFrameSize, http2.HeadersPayload.parseIgnoringPriority(truncated));
    var padded = headers;
    padded.payload = &.{ 5, 0, 0, 0, 1, 16, 0x88, 0, 0 };
    try std.testing.expectError(error.InvalidPadding, http2.HeadersPayload.parseIgnoringPriority(padded));
}

const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const Mode = enum { aggregate, streaming, independent, independent_streaming, connect };

const Observer = struct {
    errors: [2]?anyerror = .{ null, null },
    results: [2]usize = .{ 0, 0 },
    fn data(_: *@This(), _: []const u8) !void {}
    fn dataOpaque(_: *anyopaque, _: usize, _: []const u8) !void {}
    fn owned(context: *anyopaque, index: usize, result: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                response.deinit(allocator);
            },
        }
    }
    fn streamed(context: *anyopaque, index: usize, result: runtime.BatchStreamingResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.results[index] += 1;
        switch (result) {
            .err => |err| self.errors[index] = err,
            .response => |value| {
                var response = value;
                response.deinit(allocator);
            },
        }
    }
};

test "HTTP/2 push refill clears parent and independent response credit before later rejection" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Mode)) |mode| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        const peer = try listener.accept(io);
        defer peer.close(io);
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = .{ .enable_push = true }, .peer_enable_connect_protocol = true };
        defer connection.close();
        var head: std.ArrayList(u8) = .empty;
        defer head.deinit(allocator);
        try http2.Hpack.encodeLiteralBlock(&head, allocator, &.{ .{ .name = ":status", .value = if (mode == .connect) "403" else "200" }, .{ .name = "content-length", .value = "3" } });
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, head.items);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "ab");
        head.clearRetainingCapacity();
        try head.appendSlice(allocator, &.{ 0, 0, 0, 2 });
        try http2.Hpack.encodeLiteralBlock(&head, allocator, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/push" }, .{ .name = ":authority", .value = "localhost" } });
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .push_promise, 4, 1, head.items);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 2, "\x88");
        for (0..4) |index| try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (index == 3) 1 else 0, 2, "a" ** 8192);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, 1, "cd");
        const independent = mode == .independent or mode == .independent_streaming;
        if (independent) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, "\x88");
        var observed: Observer = .{};
        const options = runtime.RequestOptions{ .authority = "localhost" };
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake });
        switch (mode) {
            .aggregate => try std.testing.expectError(error.InvalidContentLength, connection.requestWithTimeout(options, .fromSeconds(1))),
            .streaming => try std.testing.expectError(error.InvalidContentLength, connection.requestStreamingWithTimeout(options, .fromSeconds(1), &observed, Observer.data)),
            .connect => try std.testing.expectError(error.InvalidContentLength, connection.openExtendedConnectAttemptWithTimeout(.{ .method = "CONNECT", .protocol = "websocket", .authority = "localhost" }, .fromSeconds(1))),
            .independent => try connection.requestBatchWithPerStreamDeadlines(&.{ options, options }, &.{ deadline, deadline }, .{ .context = &observed, .on_result = Observer.owned }),
            .independent_streaming => try connection.requestBatchStreamingWithPerStreamDeadlines(&.{ options, options }, &.{ deadline, deadline }, .{ .context = &observed, .on_data = Observer.dataOpaque, .on_result = Observer.streamed }),
        }
        if (independent) {
            try std.testing.expectEqual([2]usize{ 1, 1 }, observed.results);
            try std.testing.expectEqual(@as(?anyerror, error.InvalidContentLength), observed.errors[0]);
            try std.testing.expectEqual(@as(?anyerror, null), observed.errors[1]);
        }
        try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        var promise = connection.takePromisedRequest() orelse return error.MissingPromise;
        defer promise.deinit(allocator);
        var pushed = try connection.readPushedResponseWithTimeout(promise, .fromSeconds(1));
        defer pushed.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 32768), pushed.body.len);
    }
}

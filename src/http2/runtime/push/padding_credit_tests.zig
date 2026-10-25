const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;

test "HTTP/2 pushed DATA retains only content credit after padding release" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ false, true }) |content| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        const peer = try listener.accept(io);
        defer peer.close(io);
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = .{ .enable_push = true } };
        defer connection.close();
        var promise: std.ArrayList(u8) = .empty;
        defer promise.deinit(allocator);
        try promise.appendSlice(allocator, &.{ 0, 0, 0, 2 });
        try http2.Hpack.encodeLiteralBlock(&promise, allocator, &.{
            .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/push" },
        });
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .push_promise, 4, 1, promise.items);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 2, "\x88");
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 2, "\x03\x00\x00\x00");
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 2, if (content) "\x02ab\x00\x00" else "\x02\x00\x00");
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, "\x88");
        var parent = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
        defer parent.deinit(allocator);
        var pushed_request = connection.takePromisedRequest() orelse return error.MissingPromise;
        defer pushed_request.deinit(allocator);
        var response = try connection.readPushedResponseWithTimeout(pushed_request, .fromSeconds(1));
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings(if (content) "ab" else "", response.body);
        try std.testing.expectEqual(window.default_value - @as(i64, if (content) 2 else 0), connection.recv_connection_window.value);
    }
}

const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

const Mode = enum { aggregate, streaming, connect };

test "HTTP/2 short response body decodes trailer HPACK before stream rejection" {
    for (std.enums.values(Mode)) |mode| {
        for ([_]bool{ false, true }) |fragmented| {
            for ([_]bool{ false, true }) |bounded| try exercise(mode, fragmented, bounded);
        }
    }
}

fn consume(_: void, _: []const u8) !void {}

fn exercise(mode: Mode, fragmented: bool, bounded: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .next_client_stream_id = if (mode == .connect) 1 else 5, .peer_enable_connect_protocol = true };
    defer connection.close();
    if (mode != .connect) try runtime.testing.addActiveLocalStream(&connection, 1);
    try runtime.testing.addActiveLocalStream(&connection, 3);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":status", .value = if (mode == .connect) "403" else "200" },
        .{ .name = "content-length", .value = "3" },
    });
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, block.items);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "ab");
    // The rejected message's trailer inserts x=y as dynamic table index 62.
    const trailer = "\x40\x01x\x01y";
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (fragmented) 1 else 5, 1, if (fragmented) trailer[0..2] else trailer);
    if (fragmented) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 4, 1, trailer[2..]);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, "\x88\xbe");
    var request = runtime.RequestWriter{ .connection = &connection, .stream_id = 1, .expected_length = 0, .head_request = false, .body_finished = true };
    switch (mode) {
        .aggregate => try std.testing.expectError(error.InvalidContentLength, if (bounded) request.readResponseWithTimeout(.fromSeconds(1)) else request.readResponse()),
        .streaming => try std.testing.expectError(error.InvalidContentLength, if (bounded) request.readResponseStreamingWithTimeout(.fromSeconds(1), {}, consume) else request.readResponseStreaming({}, consume)),
        .connect => {
            const options = runtime.RequestOptions{ .method = "CONNECT", .protocol = "websocket", .authority = "localhost" };
            try std.testing.expectError(error.InvalidContentLength, if (bounded) connection.openExtendedConnectAttemptWithTimeout(options, .fromSeconds(1)) else connection.openExtendedConnectAttempt(options));
        },
    }
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    var healthy = try connection.readResponseWithTimeout(3, "POST", false, .fromSeconds(1));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("y", runtime.testing.findHeader(healthy.headers, "x").?);
}

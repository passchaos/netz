const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const Mode = enum { aggregate, streaming, batch, duplex, extended_connect };

test "HTTP/2 successful request DATA releases padding without refunding content" {
    for (std.enums.values(Mode)) |mode| {
        for ([_]bool{ false, true }) |content| try exercise(mode, content);
    }
}

fn data(delivered: *usize, bytes: []const u8) !void {
    delivered.* += bytes.len;
}
fn batchData(delivered: *usize, _: u31, bytes: []const u8) !void {
    try data(delivered, bytes);
}

fn exercise(mode: Mode, content: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .server, .limits = .{ .enable_connect_protocol = true } };
    defer connection.close();
    var head: std.ArrayList(u8) = .empty;
    defer head.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&head, allocator, &.{
        .{ .name = ":method", .value = if (mode == .extended_connect) "CONNECT" else "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/padding" },
        .{ .name = ":authority", .value = "localhost" },
    });
    if (mode == .extended_connect) try http2.Hpack.encodeLiteralBlock(&head, allocator, &.{.{ .name = ":protocol", .value = "websocket" }});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, head.items);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 1, "\x03\x00\x00\x00");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 8, 1, "\x00");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 1, if (content) "\x02ab\x00\x00" else "\x02\x00\x00");
    var delivered: usize = 0;
    switch (mode) {
        .aggregate, .extended_connect => {
            var request = try connection.readRequestWithTimeout(.fromSeconds(1));
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings(if (content) "ab" else "", request.body);
        },
        .streaming => {
            var request = try connection.readRequestStreamingWithTimeout(.fromSeconds(1), &delivered, data);
            defer request.deinit(allocator);
        },
        .batch => {
            var requests: [1]runtime.StreamingRequest = undefined;
            try connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(1), &delivered, batchData);
            defer requests[0].deinit(allocator);
        },
        .duplex => {
            var request = try connection.acceptDuplexRequestWithTimeout(.fromSeconds(1));
            defer request.deinit();
            while (true) {
                var event = try request.readRequestEventWithTimeout(.fromSeconds(1));
                defer event.deinit(allocator);
                if (event == .data) try data(&delivered, event.data.data);
                if (event == .finished) break;
            }
        },
    }
    try std.testing.expectEqual(window.default_value - @as(i64, if (content) 2 else 0), connection.recv_connection_window.value);
}

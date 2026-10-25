const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;

test "HTTP/2 CONNECT response allocation failure retires consumed state and prior DATA credit" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |bounded| {
        for ([_]bool{ false, true }) |accepted| {
            var completed = false;
            for (0..100) |fail_index| {
                const io = threaded.io();
                var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
                defer listener.deinit(io);
                const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
                const peer = try listener.accept(io);
                defer peer.close(io);
                var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .peer_enable_connect_protocol = true };
                defer connection.close();
                try appendResponse(&connection, accepted);
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
                connection.allocator = failing.allocator();
                const options = runtime.RequestOptions{ .method = "CONNECT", .protocol = "websocket", .path = "/connect", .authority = "localhost" };
                const outcome = if (bounded) connection.openExtendedConnectAttemptWithTimeout(options, .fromSeconds(1)) else connection.openExtendedConnectAttempt(options);
                connection.allocator = allocator;
                if (outcome) |value| {
                    var response = value;
                    response.deinit(allocator);
                    try std.testing.expect(!failing.has_induced_failure);
                    completed = true;
                    break;
                } else |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    try std.testing.expect(failing.has_induced_failure);
                    if (connection.frame_reader.start != 0) {
                        if (!connection.aggregate_timeout_unusable) {
                            std.debug.print("consumed CONNECT response at allocation {d} remains reusable\n", .{fail_index});
                            return error.DiscardedConnectResponseRemainsReusable;
                        }
                        try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
                        try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
                        try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
                    }
                }
            }
            try std.testing.expect(completed);
        }
    }
}

fn appendResponse(connection: *runtime.Connection, accepted: bool) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, block.items);
    block.clearRetainingCapacity();
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = ":status", .value = if (accepted) "200" else "403" }});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, block.items);
    if (accepted) return;
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0x08, 1, "\x02ab\x00\x00");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "a" ** 255);
    block.clearRetainingCapacity();
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "x-done", .value = "yes" }});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, block.items);
}

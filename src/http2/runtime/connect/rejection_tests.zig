const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

test "HTTP/2 Extended CONNECT rejection discards late DATA FIN and HPACK trailers before next admission" {
    for ([_]bool{ false, true }) |with_trailers| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        defer client.close(io);
        var connection: runtime.Connection = .{
            .allocator = allocator,
            .io = io,
            .stream = try listener.accept(io),
            .role = .server,
            .limits = .{ .enable_connect_protocol = true },
        };
        defer connection.close();
        var encoder: http2.Hpack.Encoder = .{};
        defer encoder.deinit(allocator);
        const fields = [_]http2.Hpack.HeaderField{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = ":path", .value = "/first" },
        };
        const first = try encoder.encodeBlockRetained(allocator, &fields);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, first);
        var rejected = try connection.readExtendedConnectRequest("websocket");
        defer rejected.deinit(allocator);
        const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
        try connection.rejectExtendedConnectWithBodyWithDeadline(1, 429, &.{}, "retry", &.{.{ .name = "x-retry", .value = "1" }}, until);

        // Already in flight before the client observes the server's reset.
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (with_trailers) 0 else 1, 1, "optimistic");
        const dynamic = http2.Hpack.HeaderField{ .name = "x-dynamic", .value = "late-trailer-value" };
        if (with_trailers) {
            const trailer = try encoder.encodeBlockRetained(allocator, &.{dynamic});
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 1, trailer);
        }
        var next_fields: [fields.len + 1]http2.Hpack.HeaderField = undefined;
        @memcpy(next_fields[0..fields.len], &fields);
        next_fields[4].value = "/second";
        next_fields[fields.len] = dynamic;
        const next_block = try encoder.encodeBlockRetained(allocator, &next_fields);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 3, next_block);
        var next = try connection.readExtendedConnectRequestWithDeadline("websocket", until);
        defer next.deinit(allocator);
        try std.testing.expectEqualStrings("/second", next.path);
        try std.testing.expectEqualStrings(dynamic.value, runtime.testing.findHeader(next.headers, dynamic.name).?);
        try std.testing.expectEqual(@as(i64, 65535), runtime.testing.recvConnectionWindowValue(&connection));
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expect(connection.active_peer_index.contains(3));
        try std.testing.expect(!connection.active_peer_index.contains(1));
    }
}

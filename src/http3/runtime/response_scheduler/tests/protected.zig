const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

test "HTTP/3 protected response scheduler honors request priority" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xc6, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xc7, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc9} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .response_scheduler_max_batch_packets = 2,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const low_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/low",
        .authority = "localhost",
        .headers = &.{.{ .name = "priority", .value = "u=6" }},
    });
    const high_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/high",
        .authority = "localhost",
        .headers = &.{.{ .name = "priority", .value = "u=1" }},
    });
    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try server.startResponse(first.from, low_id, .{ .status = 200 }, 3);
    try server.startResponse(first.from, high_id, .{ .status = 200 }, 4);
    try server.sendResponseBodiesPaced(first.from, &.{
        .{ .stream_id = low_id, .data = "low" },
        .{ .stream_id = high_id, .data = "high" },
    });

    var high = try client.receiveNextResponse();
    defer high.deinit(allocator);
    try std.testing.expect(high == .response);
    try std.testing.expectEqual(high_id, high.response.stream_id);
    try std.testing.expectEqualStrings(
        "high",
        high.response.value.response.body,
    );
    var low = try client.receiveNextResponse();
    defer low.deinit(allocator);
    try std.testing.expect(low == .response);
    try std.testing.expectEqual(low_id, low.response.stream_id);
    try std.testing.expectEqualStrings(
        "low",
        low.response.value.response.body,
    );
}

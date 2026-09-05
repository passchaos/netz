const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

const ProtectedServer = runtime.ProtectedServer;
const ProtectedClient = runtime.ProtectedClient;

test "HTTP/3 protected server drains GRO request batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x89, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x8a, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8b} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8c} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer client_endpoint.deinit();
    if (!server.quic_server.endpoint.groReceiveEnabled() or
        !client_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    }).write(&first, allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    }).write(&second, allocator);
    try std.testing.expectEqual(first.items.len, second.items.len);

    const frames0 = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = first.items,
        .fin = true,
    } }};
    const frames1 = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = second.items,
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &frames0, &frames1 };
    try quic.one_rtt.sendFramesBatch(
        &client_endpoint,
        server.address(),
        client_keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packets = &packets,
        },
    );

    var first_request = try server.receiveRequest();
    defer first_request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/gro-one",
        first_request.request.path,
    );
    try std.testing.expect(server.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        server.receive_packets.batch.?.packets.len -
            server.receive_packets.batch.?.next_index,
    );
    // The second packet was decrypted with the same GRO receive but has not
    // entered HTTP/3 stream storage before the application asks for it.
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.count(),
    );

    var second_request = try server.receiveRequest();
    defer second_request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/gro-two",
        second_request.request.path,
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        server.expected_packet_number,
    );
}

test "HTTP/3 protected client drains GRO response batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x8d, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x8e, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8f} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x90} ** quic.protection.secret_len,
    );
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer server_endpoint.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();
    if (!client.quic_client.endpoint.groReceiveEnabled() or
        !server_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    });
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "one",
    }).write(&first, allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "two",
    }).write(&second, allocator);
    try std.testing.expectEqual(first.items.len, second.items.len);

    const frames0 = [_]quic.Frame{.{ .stream = .{
        .stream_id = first_id,
        .data = first.items,
        .fin = true,
    } }};
    const frames1 = [_]quic.Frame{.{ .stream = .{
        .stream_id = second_id,
        .data = second.items,
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &frames0, &frames1 };
    try quic.one_rtt.sendFramesBatch(
        &server_endpoint,
        client.quic_client.address(),
        server_keys,
        .{
            .destination_connection_id = &client_cid,
            .first_packet_number = 0,
            .packets = &packets,
        },
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(first_id, first_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "one",
        first_event.response.value.response.body,
    );
    try std.testing.expect(client.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.receive_packets.batch.?.packets.len -
            client.receive_packets.batch.?.next_index,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.response_streams.count(),
    );

    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(second_id, second_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "two",
        second_event.response.value.response.body,
    );
}

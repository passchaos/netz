const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");

test "QUIC 1-RTT DATAGRAM response piggybacks pending ACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var traffic: quic.runtime.SocketTrafficCounters = .{};
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 1200,
            .socket_traffic_counters = &traffic,
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer client_endpoint.deinit();
    var client, var server = try connectionPair(
        &client_endpoint,
        &server_endpoint,
    );
    defer client.deinit();
    defer server.deinit();

    try client.sendDatagram("request");
    var storage: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "request",
        try server.receiveDatagramWithTimeout(&storage, .fromSeconds(1)),
    );
    try std.testing.expect(server.ackDelayDeadline() != null);
    const traffic_before = traffic.stats();

    try server.sendDatagramWithTimeout("response", .fromSeconds(1));
    try std.testing.expectEqual(@as(?u64, null), server.ackDelayDeadline());
    try std.testing.expectEqual(@as(u64, 1), server.datagramsSent());
    const traffic_after = traffic.stats().since(traffic_before);
    try std.testing.expectEqual(@as(u64, 1), traffic_after.sent_datagrams);

    var response = try client.receivePacket();
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), response.frames.len);
    try std.testing.expect(response.frames[0] == .datagram);
    try std.testing.expectEqualStrings(
        "response",
        response.frames[0].datagram.data,
    );
    try std.testing.expect(response.frames[1] == .ack);
    try std.testing.expectEqual(
        @as(u64, 0),
        response.frames[1].ack.largest_acknowledged,
    );
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight());
}

test "QUIC 1-RTT full-size DATAGRAM falls back with ACK still pending" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer client_endpoint.deinit();
    var client, var server = try connectionPair(
        &client_endpoint,
        &server_endpoint,
    );
    defer client.deinit();
    defer server.deinit();

    try client.sendDatagram("request");
    var storage: [32]u8 = undefined;
    _ = try server.receiveDatagramWithTimeout(&storage, .fromSeconds(1));
    const ack_deadline = server.ackDelayDeadline().?;
    const max_payload = server.maxDatagramPayloadSize().?;
    const payload = try allocator.alloc(u8, max_payload);
    defer allocator.free(payload);
    @memset(payload, 0xa5);

    try server.sendDatagram(payload);
    try std.testing.expectEqual(@as(u64, 1), server.datagramsSent());
    try std.testing.expectEqual(ack_deadline, server.ackDelayDeadline().?);
    var response = try client.receivePacket();
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), response.frames.len);
    try std.testing.expect(response.frames[0] == .datagram);
    try std.testing.expectEqualSlices(
        u8,
        payload,
        response.frames[0].datagram.data,
    );
}

fn connectionPair(
    client_endpoint: *quic.runtime.Endpoint,
    server_endpoint: *quic.runtime.Endpoint,
) !struct { one_rtt.Connection, one_rtt.Connection } {
    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    errdefer client.deinit();
    const server = try one_rtt.Connection.init(server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 25_000,
        .enable_pacing = false,
    });
    return .{ client, server };
}

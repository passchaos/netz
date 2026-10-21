const std = @import("std");
const runtime = @import("runtime.zig");
const packet_space = @import("packet_space.zig");
const socks5 = @import("../proxy/socks5.zig");

const net = std.Io.net;

test "SOCKS5 QUIC endpoint preserves framing progress and ownership" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var control_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer control_listener.deinit(io);
    const control_client = try control_listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const control_server = try control_listener.accept(io);
    defer control_server.close(io);

    const udp_bind = net.IpAddress{ .ip4 = .loopback(0) };
    const client_socket = try udp_bind.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    const relay = try udp_bind.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer relay.close(io);

    var association = socks5.UdpAssociation.init(
        io,
        .{ .io = io, .stream = control_client, .deadline = null },
        client_socket,
        relay.address,
    );
    var counters: runtime.SocketTrafficCounters = .{};
    var endpoint = try runtime.Endpoint.fromSocks5Association(
        allocator,
        &association,
        .{
            .max_datagram_size = 1200,
            .enable_gso_send = true,
            .enable_gro_receive = true,
            .socket_traffic_counters = &counters,
        },
    );
    var endpoint_closed = false;
    defer if (!endpoint_closed) endpoint.deinit();
    try std.testing.expect(endpoint.usesSocks5Udp());
    try std.testing.expect(!endpoint.gsoSendEnabled());
    try std.testing.expect(!endpoint.groReceiveEnabled());

    const peer_a = try net.IpAddress.parse("192.0.2.10", 443);
    const peer_b = try net.IpAddress.parse("198.51.100.20", 8443);
    try std.testing.expectError(
        error.EcnUnavailable,
        endpoint.sendBytesWithEcn(peer_a, "ecn", packet_space.EcnCodepoint.ect0),
    );
    try endpoint.sendBytes(peer_a, "one");
    const same_peer = [_][]const u8{ "two", "three" };
    const same_progress = try endpoint.sendManyBytesProgress(
        peer_a,
        &same_peer,
    );
    try std.testing.expectEqual(@as(usize, 2), same_progress.sent_count);
    try std.testing.expect(same_progress.send_error == null);
    const addressed = [_]runtime.AddressedDatagram{.{
        .to = peer_b,
        .bytes = "four",
    }};
    const addressed_progress = try endpoint.sendManyAddressedBytesProgress(
        &addressed,
    );
    try std.testing.expectEqual(@as(usize, 1), addressed_progress.sent_count);
    try std.testing.expect(addressed_progress.send_error == null);

    const expected_peers = [_]net.IpAddress{ peer_a, peer_a, peer_a, peer_b };
    const expected_payloads = [_][]const u8{ "one", "two", "three", "four" };
    for (expected_peers, expected_payloads) |expected_peer, expected_payload| {
        var request_storage: [256]u8 = undefined;
        const message = try relay.receiveTimeout(
            io,
            &request_storage,
            awakeTimeout(.fromSeconds(2)),
        );
        const request = try socks5.udp.decodeDatagram(message.data);
        try std.testing.expect(request.source.ip.eql(&expected_peer));
        try std.testing.expectEqualStrings(expected_payload, request.payload);

        var response_payload_storage: [64]u8 = undefined;
        const response_payload = try std.fmt.bufPrint(
            &response_payload_storage,
            "ack-{s}",
            .{expected_payload},
        );
        var response_storage: [256]u8 = undefined;
        const response = try socks5.udp.encodeDatagram(
            &response_storage,
            .{ .ip = expected_peer },
            response_payload,
        );
        try relay.send(io, &message.from, response);
    }

    const source = runtime.DatagramSource.fromEndpoint(&endpoint);
    try std.testing.expectEqual(@as(usize, 1222), source.receiveIntoCapacity());
    var first_storage: [1222]u8 = undefined;
    const first = (try source.receiveIntoTimeout(
        &first_storage,
        awakeTimeout(.fromSeconds(2)),
    )).?;
    try std.testing.expect(first.from.eql(&peer_a));
    try std.testing.expectEqualStrings("ack-one", first.bytes);
    try std.testing.expectEqual(packet_space.EcnCodepoint.not_ect, first.ecn);

    var second_storage: [1222]u8 = undefined;
    const second = try endpoint.receiveBytesBatchIntoTimeout(
        &second_storage,
        awakeTimeout(.fromSeconds(2)),
    );
    try std.testing.expect(second.from.eql(&peer_a));
    try std.testing.expectEqual(@as(usize, 1), second.segment_count);
    try std.testing.expectEqualStrings("ack-two", second.storage);

    var third = try endpoint.receiveBytesTimeout(awakeTimeout(.fromSeconds(2)));
    defer third.deinit(allocator);
    try std.testing.expect(third.from.eql(&peer_a));
    try std.testing.expectEqualStrings("ack-three", third.bytes);

    var fourth_storage: [1222]u8 = undefined;
    const fourth = try endpoint.receiveBytesIntoTimeout(
        &fourth_storage,
        awakeTimeout(.fromSeconds(2)),
    );
    try std.testing.expect(fourth.from.eql(&peer_b));
    try std.testing.expectEqualStrings("ack-four", fourth.bytes);

    const stats = counters.stats();
    try std.testing.expectEqual(@as(u64, 4), stats.sent_datagrams);
    try std.testing.expectEqual(@as(u64, 4), stats.received_datagrams);

    endpoint.deinit();
    endpoint_closed = true;
    var eof: [1]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        try readSome(io, control_server, &eof),
    );
}

fn awakeTimeout(duration: std.Io.Duration) std.Io.Timeout {
    return .{ .duration = .{ .raw = duration, .clock = .awake } };
}

fn readSome(io: std.Io, stream: net.Stream, output: []u8) !usize {
    var parts = [_][]u8{output};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &parts);
}

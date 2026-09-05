const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const control_receive = @import("../receive.zig");

fn findStreamFrame(frames: []const quic.Frame) ?quic.StreamFrame {
    for (frames) |frame| {
        if (frame == .stream) return frame.stream;
    }
    return null;
}

test "HTTP/3 connection control frames advance control stream offset" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );

    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();

    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendGoAway(0);
    var first = try quic.one_rtt.receive(
        &server.quic_server.endpoint,
        client_keys,
        server_cid.len,
        0,
        8,
    );
    defer first.deinit(allocator);
    const first_stream = findStreamFrame(first.frames) orelse
        return error.MissingStreamFrame;
    try std.testing.expectEqual(@as(u64, 0), first_stream.offset);
    try std.testing.expect(try control_receive.applyControlStreamFrame(
        &server.control,
        allocator,
        first_stream,
    ));

    var second = try quic.one_rtt.receive(
        &server.quic_server.endpoint,
        client_keys,
        server_cid.len,
        1,
        8,
    );
    defer second.deinit(allocator);
    const second_stream = findStreamFrame(second.frames) orelse
        return error.MissingStreamFrame;
    try std.testing.expect(second_stream.offset > 0);
    try std.testing.expect(try control_receive.applyControlStreamFrame(
        &server.control,
        allocator,
        second_stream,
    ));
    try std.testing.expectEqual(@as(?u64, 0), server.control.peer_goaway_id);

    try client.sendGoAway(0);
    var third = try quic.one_rtt.receive(
        &server.quic_server.endpoint,
        client_keys,
        server_cid.len,
        2,
        8,
    );
    defer third.deinit(allocator);
    const third_stream = findStreamFrame(third.frames) orelse
        return error.MissingStreamFrame;
    try std.testing.expect(third_stream.offset > second_stream.offset);
    try std.testing.expect(try control_receive.applyControlStreamFrame(
        &server.control,
        allocator,
        third_stream,
    ));
    try std.testing.expectEqual(@as(?u64, 0), server.control.peer_goaway_id);
}

test "HTTP/3 protected runtime sends and accumulates RFC 9412 origins" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe9} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xea} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try server.sendOrigins(client.quic_client.address(), &.{
        "https://Example.COM",
        "https://cdn.example.com:8443",
    });
    try server.sendOrigins(client.quic_client.address(), &.{
        "https://example.com:443",
        "https://img.example.com",
    });
    try std.testing.expectError(
        error.Timeout,
        client.pollControlWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try client.pollControlWithTimeout(.fromSeconds(1));
    while (client.peerOrigins().len < 3) {
        try client.pollControlWithDeadline(.fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }));
    }

    try std.testing.expect(client.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 3), client.peerOrigins().len);
    try std.testing.expect(client.peerOriginKnown(
        try http3.requestOrigin("https", "example.com"),
    ));
    try std.testing.expect(client.peerOriginKnown(
        try http3.requestOrigin("https", "CDN.EXAMPLE.COM:8443"),
    ));
    try std.testing.expect(client.peerOriginKnown(
        try http3.requestOrigin("https", "img.example.com:443"),
    ));
}

test "HTTP/3 protected client sends persistent priority updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xa2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa4} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendPriorityUpdate(0, .{ .urgency = 1 });
    try client.sendPriorityUpdate(0, .{
        .urgency = 6,
        .incremental = true,
    });
    try std.testing.expectError(
        error.UnexpectedFrame,
        client.sendPriorityUpdate(4, .{}),
    );

    while (server.control.latest_priority_update == null or
        server.control.latest_priority_update.?.priority().urgency != 6)
    {
        var packet = try quic.one_rtt.receive(
            &server.quic_server.endpoint,
            client_keys,
            server_cid.len,
            server.expected_packet_number,
            8,
        );
        defer packet.deinit(allocator);
        server.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            _ = try control_receive.applyControlStreamFrameForRole(
                &server.control,
                allocator,
                frame.stream,
                .server,
            );
        }
    }
    const update = server.control.latest_priority_update.?;
    try std.testing.expectEqual(@as(u64, 0), update.prioritized_element_id);
    try std.testing.expectEqual(@as(u3, 6), update.priority().urgency);
    try std.testing.expect(update.priority().incremental);
    try std.testing.expect(client.control_send.next_offset > 1);
}

test "HTTP/3 protected client advertises and cancels server push IDs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xc6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(4);
    try client.sendMaxPushId(8);
    try std.testing.expectError(
        error.MaxPushIdReduced,
        client.sendMaxPushId(7),
    );
    try std.testing.expectError(error.PushIdExceeded, client.cancelPush(9));
    try client.push_streams.registerPromise(7, 0);
    try client.push_streams.registerPromise(3, 0);
    try client.cancelPush(7);
    try client.cancelPush(3);

    while (server.control.peer_max_push_id != 8 or
        !server.control.pushCancelled(7) or
        !server.control.pushCancelled(3))
    {
        var packet = try quic.one_rtt.receive(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            server.expected_packet_number,
            server.config.max_frames_per_packet,
        );
        defer packet.deinit(allocator);
        server.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            if (try control_receive.applyControlStreamFrameForRole(
                &server.control,
                allocator,
                frame.stream,
                .server,
            )) {
                try control_receive.configureQpackEncoderFromPeerSettings(
                    server.control,
                    &server.qpack_encode,
                );
            }
        }
    }
    try std.testing.expectEqual(
        @as(?u64, 8),
        server.control.peer_max_push_id,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        server.control.peer_cancelled_push_ids.items.len,
    );
}

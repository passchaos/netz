const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;

test "QUIC 1-RTT connection performs key update and clears ACK gate" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x57} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x58} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.initiateKeyUpdate();
    try std.testing.expect(client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), client.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?u64, 0), client.pendingOneRttKeyUpdateAckThreshold());
    try std.testing.expectError(error.InvalidPacket, client.initiateKeyUpdate());

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "updated", .fin = true } }};
    try client.send(&frames);

    var updated = try server.receivePacket();
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(updated.packet.key_phase);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.peerOneRttKeyUpdateCount());
    try std.testing.expect(server.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?u64, 0), server.pendingOneRttKeyUpdateAckThreshold());
    try std.testing.expectEqualStrings("updated", updated.frames[0].stream.data);

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), ack.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(?u64, null), client.pendingOneRttKeyUpdateAckThreshold());

    try client.initiateKeyUpdate();
    try std.testing.expect(!client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 2), client.localOneRttKeyUpdateCount());
}

test "QUIC 1-RTT automatically updates before the AEAD confidentiality limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x69} ** quic.protection.secret_len);
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .aead_confidentiality_limit = 2,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .aead_confidentiality_limit = 2,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.send(&ping);
    try client.send(&ping);
    try std.testing.expectEqual(@as(u64, 2), client.encryptedPacketsWithCurrentKeys());
    try std.testing.expect(!client.localOneRttKeyPhase());

    // The next encryption advances first, so generation zero is never used
    // beyond its configured (and RFC-clamped) confidentiality limit.
    try client.send(&ping);
    try std.testing.expect(client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), client.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(u64, 1), client.encryptedPacketsWithCurrentKeys());
    try std.testing.expectEqual(@as(?u64, 2), client.pendingOneRttKeyUpdateAckThreshold());

    var packet0 = try server.receivePacket();
    defer packet0.deinit(allocator);
    var packet1 = try server.receivePacket();
    defer packet1.deinit(allocator);
    var packet2 = try server.receivePacket();
    defer packet2.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), packet0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), packet1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), packet2.packet.packet_number);
    try std.testing.expect(packet2.peer_initiated_key_update);

    // One more packet fills generation one. Without an ACK for packet 2 the
    // sender cannot safely initiate another update, so the following send
    // terminates locally rather than exceeding the AEAD limit.
    try client.send(&ping);
    try std.testing.expectError(error.AeadLimitReached, client.send(&ping));
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.TransportErrorCode.aead_limit_reached)),
        client.close_info.?.error_code,
    );
    try std.testing.expectEqual(@as(u64, 4), client.next_packet_number);
}

test "QUIC 1-RTT closes at the AEAD integrity limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const local_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const peer_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
        .aead_integrity_limit = 2,
    });
    defer connection.deinit();

    const sealed = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &local_cid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = &.{@intFromEnum(quic.FrameType.ping)},
    });
    defer allocator.free(sealed);
    sealed[sealed.len - 1] ^= 0x80; // Preserve header protection; corrupt only the AEAD tag.

    try std.testing.expectError(
        error.AuthenticationFailed,
        one_rtt.testing.processReceivedBytesAt(&connection, endpoint.address(), sealed, .not_ect, 1_000_000),
    );
    try std.testing.expectEqual(@as(u64, 1), connection.authenticationFailureCount());
    try std.testing.expect(!connection.closing());

    try std.testing.expectError(
        error.AeadLimitReached,
        one_rtt.testing.processReceivedBytesAt(&connection, endpoint.address(), sealed, .not_ect, 2_000_000),
    );
    try std.testing.expectEqual(@as(u64, 2), connection.authenticationFailureCount());
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.TransportErrorCode.aead_limit_reached)),
        connection.close_info.?.error_code,
    );
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    try std.testing.expectError(error.ConnectionClosed, connection.send(&.{.{ .ping = {} }}));
}

test "QUIC 1-RTT connection accepts delayed previous-key packets until discard" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x5a} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x5b} ** quic.protection.secret_len);
    const next_client_keys = quic.protection.nextAes128PacketProtectionKeys(client_keys);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const old_payload = try one_rtt.encodeFrames(allocator, &[_]quic.Frame{.{ .ping = {} }});
    defer allocator.free(old_payload);
    const old_packet = try quic.protection.sealShortPacket(allocator, client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .packet_number_len = 4,
        .key_phase = false,
        .payload = old_payload,
    });
    defer allocator.free(old_packet);

    const updated_payload = try one_rtt.encodeFrames(allocator, &[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .data = "new",
        .fin = false,
    } }});
    defer allocator.free(updated_payload);
    const updated_packet = try quic.protection.sealShortPacket(allocator, next_client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .packet_number_len = 4,
        .key_phase = true,
        .payload = updated_payload,
    });
    defer allocator.free(updated_packet);

    const route = quic.connection_router.Route{ .connection_index = 0 };
    var updated = try server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = updated_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    });
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.peerOneRttKeyUpdateCount());
    try std.testing.expect(server.peerOneRttRetainsKeyGeneration(0));

    var delayed_old = try server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = old_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    });
    defer delayed_old.deinit(allocator);
    try std.testing.expect(!delayed_old.peer_initiated_key_update);
    try std.testing.expect(!delayed_old.packet.key_phase);
    try std.testing.expect(server.peerOneRttKeyPhase());

    server.schedulePreviousOneRttKeyDiscard(10);
    try std.testing.expectEqual(@as(?i64, 10), server.oneRttKeyDiscardDeadline());
    try std.testing.expect(server.discardExpiredOneRttKeys(10));
    try std.testing.expect(!server.peerOneRttRetainsKeyGeneration(0));
    try std.testing.expectError(error.KeyUpdateError, server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = old_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    }));
}

test "QUIC 1-RTT connection sends and validates PMTU probes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    const server_cid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xba} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
    });
    defer server.deinit();

    try std.testing.expect(client.pmtudShouldProbe());
    const probe_size = (try client.sendPmtuProbeAt(1300, 10)).?;
    try std.testing.expectEqual(@as(usize, 1300), probe_size);
    try std.testing.expect(!client.pmtudShouldProbe());

    var raw = try server_endpoint.receiveBytes();
    defer raw.deinit(allocator);
    try std.testing.expectEqual(probe_size, raw.bytes.len);
    var received = try one_rtt.openReceivedBytes(
        &server_endpoint,
        raw.from,
        raw.bytes,
        keys,
        server.config.local_connection_id.len,
        server.expected_packet_number,
        server.config.max_frames_per_packet,
    );
    defer received.deinit(allocator);
    try one_rtt.testing.applyReceivedFrames(&server, received.packet.packet_number, received.frames, null, .not_ect);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 1300), client.sent.packets.items[0].pmtu_probe_size.?);

    const ack_frame = try server.received.ackFrame(allocator, 0);
    defer allocator.free(ack_frame.ranges);
    const ack_frames = [_]quic.Frame{.{ .ack = ack_frame }};
    try one_rtt.testing.applyReceivedFrames(&client, 99, &ack_frames, null, .not_ect);
    try std.testing.expectEqual(@as(usize, 1300), client.pmtudCurrentSize());
    try std.testing.expectEqual(@as(usize, 1300), client.currentSendDatagramSize());
}

test "QUIC 1-RTT PMTUD gates ordinary sends until probe succeeds" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xbd} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-send-local",
        .peer_connection_id = "pmtu-send-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .peer_max_datagram_frame_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, connection.currentSendDatagramSize());
    const initial_datagram_payload = connection.maxDatagramPayloadSize() orelse return error.TestUnexpectedResult;
    try std.testing.expect(initial_datagram_payload < 1250);
    try std.testing.expectError(error.DatagramTooLarge, connection.sendAt(&.{.{ .padding = .{ .len = 1250 } }}, 10));
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);

    connection.pmtud.onProbeAcked(1300, 1400);
    try std.testing.expectEqual(@as(usize, 1300), connection.currentSendDatagramSize());
    const raised_datagram_payload = connection.maxDatagramPayloadSize() orelse return error.TestUnexpectedResult;
    try std.testing.expect(raised_datagram_payload >= 1250);
    try connection.sendAt(&.{.{ .padding = .{ .len = 1250 } }}, 20);
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
}

test "QUIC 1-RTT PMTUD gates retransmission after path reset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xbd, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xbd, 0x04, 0x05, 0x06 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xbe} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer server.deinit();

    var body: [1250]u8 = .{0xaa} ** 1250;

    client.pmtud.onProbeAcked(1300, 1400);
    try client.sendAt(&.{.{ .stream = .{ .stream_id = 0, .data = &body } }}, 100); // packet 0, too large after reset.
    var dropped = try server_endpoint.receiveBytes();
    dropped.deinit(allocator);

    try client.sendAt(&.{.{ .ping = {} }}, 200); // packet 1 establishes a largest ACKed packet.
    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), received.packet.packet_number);
    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);

    client.pmtud.resetForPath();
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, client.currentSendDatagramSize());
    try std.testing.expectError(error.DatagramTooLarge, client.retransmitTimeThresholdLoss(1_000_000, 1));
    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
}

test "QUIC 1-RTT PMTU probe loss lowers next probe size" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbb} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-local",
        .peer_connection_id = "pmtu-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1400,
        .max_datagram_size = 1500,
    });
    defer connection.deinit();
    connection.pmtud.max_probe_failures = 2;

    const probe_size = (try connection.sendPmtuProbeAt(1400, 100)).?;
    connection.sent.packets.items[0].lost = false;
    const lost1 = connection.sent.detectTimeThresholdLoss(1_000, 1, 0);
    if (lost1.largest_pmtu_probe_size) |size| connection.pmtud.onProbeLost(size, connection.config.max_datagram_size);
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(probe_size, connection.pmtud.probeSize(1400).?);

    connection.pmtud.onProbeSent(probe_size);
    connection.pmtud.onProbeLost(probe_size, 1400);
    try std.testing.expect(connection.pmtudShouldProbe());
    const next = connection.pmtud.probeSize(1400).?;
    try std.testing.expect(next < probe_size);
    try std.testing.expect(next > quic.pmtu.min_udp_payload_size);
}

test "QUIC 1-RTT connection enforces anti-amplification budget" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x9a, 0x9b, 0x9c, 0x9d };
    const server_cid = [_]u8{ 0x9e, 0x9f, 0xa0, 0xa1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x9a} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    try std.testing.expect(server.peerAddressValidated());
    server.setPeerAddressValidated(false);
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), server.antiAmplificationLimitRemaining());

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try std.testing.expectError(error.AntiAmplificationLimited, server.sendAt(&ping, 10));
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), server.congestion.bytes_in_flight);

    server.recordPeerAddressBytesReceived(10);
    try std.testing.expectEqual(@as(?usize, 30), server.antiAmplificationLimitRemaining());
    try server.sendAt(&ping, 20);
    try std.testing.expectEqual(@as(usize, 1), server.pendingRecoveryCount());
    try std.testing.expectEqual(@as(?usize, 29), server.antiAmplificationLimitRemaining());

    var sent = try client_endpoint.receiveBytes();
    defer sent.deinit(allocator);
    try std.testing.expect(sent.bytes.len > 0);

    server.setPeerAddressValidated(true);
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT anti-amplification credit services expired PTO" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xaa, 0xab, 0xac, 0xad };
    const server_cid = [_]u8{ 0xae, 0xaf, 0xb0, 0xb1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xaa} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    server.setPeerAddressValidated(false);

    const ping = [_]quic.Frame{.{ .ping = {} }};
    server.recordPeerAddressBytesReceived(1);
    try server.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(@as(?usize, 2), server.antiAmplificationLimitRemaining());

    // Consume the tiny remaining budget so the server is blocked exactly when
    // another datagram arrives with enough credit to service the already-due PTO.
    server.peer_address_bytes_sent = 3;
    const serviced = (try server.recordPeerAddressDatagramReceived(210_000_000, 10)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), server.ptoBackoffCount());
    try std.testing.expect(server.antiAmplificationLimitRemaining().? < 30);

    var original = try client_endpoint.receiveBytes();
    defer original.deinit(allocator);
    var probe = try client_endpoint.receiveBytes();
    defer probe.deinit(allocator);
    try std.testing.expect(original.bytes.len > 0);
    try std.testing.expect(probe.bytes.len > 0);
}

test "QUIC 1-RTT connection enforces congestion send window" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_cid = [_]u8{ 0x55, 0x56, 0x57, 0x58 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xc2} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    client.congestion.congestion_window = 0;

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try std.testing.expectError(error.CongestionLimited, client.send(&ping));
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
}

test "QUIC 1-RTT routed datagrams dispatch to separate connections" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_a_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_a_endpoint.deinit();
    var client_b_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_b_endpoint.deinit();

    const client_a_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const client_b_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_a_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_b_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const keys_a = quic.protection.deriveAes128Keys([_]u8{0x31} ** quic.protection.secret_len);
    const keys_b = quic.protection.deriveAes128Keys([_]u8{0x32} ** quic.protection.secret_len);

    var server_a = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_a_endpoint.address(),
        .receive_keys = keys_a,
        .send_keys = keys_a,
        .local_connection_id = &server_a_cid,
        .peer_connection_id = &client_a_cid,
        .local_endpoint = .server,
    });
    defer server_a.deinit();
    var server_b = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_b_endpoint.address(),
        .receive_keys = keys_b,
        .send_keys = keys_b,
        .local_connection_id = &server_b_cid,
        .peer_connection_id = &client_b_cid,
        .local_endpoint = .server,
    });
    defer server_b.deinit();

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register(&server_a_cid, .{ .connection_index = 0 });
    try router.register(&server_b_cid, .{ .connection_index = 1 });

    const a_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "for-a", .fin = true } }};
    const b_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "for-b", .fin = true } }};
    try one_rtt.sendFrames(&client_a_endpoint, server_endpoint.address(), keys_a, .{
        .destination_connection_id = &server_a_cid,
        .packet_number = 0,
        .frames = &a_frames,
    });
    try one_rtt.sendFrames(&client_b_endpoint, server_endpoint.address(), keys_b, .{
        .destination_connection_id = &server_b_cid,
        .packet_number = 0,
        .frames = &b_frames,
    });

    var saw_a = false;
    var saw_b = false;
    for (0..2) |_| {
        var routed = try server_endpoint.receiveRoutedBytes(router);
        defer routed.deinit(allocator);
        switch (routed.route.connection_index) {
            0 => {
                var packet = try server_a.receiveRoutedDatagram(routed);
                defer packet.deinit(allocator);
                try std.testing.expectEqualStrings("for-a", packet.frames[0].stream.data);
                saw_a = true;
            },
            1 => {
                var packet = try server_b.receiveRoutedDatagram(routed);
                defer packet.deinit(allocator);
                try std.testing.expectEqualStrings("for-b", packet.frames[0].stream.data);
                saw_b = true;
            },
            else => return error.NoConnectionRoute,
        }
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test "QUIC 1-RTT path validation timeout retries then fails" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xda, 0xdb, 0xdc, 0xdd };
    const server_cid = [_]u8{ 0xde, 0xdf, 0xe0, 0xe1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xdd} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    client.path_validation.max_challenge_transmissions = 2;

    const challenge = [_]u8{ 0xda, 1, 2, 3, 4, 5, 6, 7 };
    try client.queuePathChallenge(challenge);
    try client.sendPendingPathChallengeAt(100, 50);
    try std.testing.expectEqual(@as(?u64, 150), client.pathValidationDeadline());
    try std.testing.expectEqual(@as(usize, 0), try client.checkPathValidationTimeouts(149));
    try std.testing.expectEqual(@as(usize, 1), try client.checkPathValidationTimeouts(150));
    try std.testing.expectEqual(@as(usize, 1), client.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.failedChallengeCount());

    try client.sendPendingPathChallengeAt(200, 50);
    try std.testing.expectEqual(@as(?u64, 250), client.pathValidationDeadline());
    try std.testing.expectEqual(@as(usize, 1), try client.checkPathValidationTimeouts(250));
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), client.path_validation.failedChallengeCount());
}

test "QUIC 1-RTT beginPeerMigration obeys disable_active_migration" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer peer_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xee} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .peer_disable_active_migration = true,
    });
    defer connection.deinit();

    try std.testing.expect(connection.peerActiveMigrationDisabled());
    try std.testing.expectError(error.ActiveMigrationDisabled, connection.beginPeerMigration(peer_endpoint.address(), [_]u8{0} ** 8));
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqual(endpoint.address(), connection.config.peer);
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.pendingChallengeCount());
}

test "QUIC 1-RTT receive commits NAT rebinding after non-probing packet" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var original_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_client_endpoint.deinit();
    var rebound_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer rebound_client_endpoint.deinit();

    const client_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xf1} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&rebound_client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .stream = .{ .stream_id = 0, .data = "rebinding" } }},
    });

    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings("rebinding", packet.frames[0].stream.data);
    try std.testing.expectEqual(rebound_client_endpoint.address(), server.config.peer);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT receive starts validation for new peer IP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    var previous_peer = client_endpoint.address();
    switch (previous_peer) {
        .ip4 => |*ip4| ip4.bytes = .{ 127, 0, 0, 2 },
        .ip6 => |*ip6| ip6.bytes[15] +%= 1,
    }
    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe1} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = previous_peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
    });
    defer server.deinit();
    server.pmtud.onProbeAcked(1300, 1300);
    server.pacer.onPacketSentAt(100, server.pacer.maxBurstSize(), server.congestionWindow(), server.rtt_stats.smoothedOrInitial());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .stream = .{ .stream_id = 0, .data = "new-path" } }},
    });

    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings("new-path", packet.frames[0].stream.data);
    try std.testing.expectEqual(client_endpoint.address(), server.config.peer);
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expect(server.antiAmplificationLimitRemaining().? > 0);
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, server.pmtudCurrentSize());
    try std.testing.expectEqual(server.pacer.maxBurstSize(), server.pacer.budget);
}

test "QUIC 1-RTT receive rejects active migration before mutation when disabled" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var original_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_client_endpoint.deinit();
    var rebound_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer rebound_client_endpoint.deinit();

    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .peer_disable_active_migration = true,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&rebound_client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .stream = .{ .stream_id = 0, .data = "blocked" } }},
    });
    try std.testing.expectError(error.ActiveMigrationDisabled, server.receivePacket());
    try std.testing.expectEqual(original_client_endpoint.address(), server.config.peer);
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.received.ranges.items.len);
}

test "QUIC 1-RTT migration resets path state and validates on PATH_RESPONSE" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var first_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer first_endpoint.deinit();
    var migrated_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer migrated_endpoint.deinit();

    const local_cid = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd };
    const peer_cid = [_]u8{ 0xce, 0xcf, 0xd0, 0xd1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xcc} ** quic.protection.secret_len);

    var connection = try one_rtt.Connection.init(&first_endpoint, .{
        .peer = first_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
    });
    defer connection.deinit();
    connection.setPeerAddressValidated(true);
    connection.pmtud.onProbeAcked(1300, 1300);
    connection.pacer.onPacketSentAt(100, connection.pacer.maxBurstSize(), connection.congestionWindow(), connection.rtt_stats.smoothedOrInitial());
    try std.testing.expectEqual(@as(usize, 1300), connection.pmtudCurrentSize());
    try std.testing.expectEqual(@as(usize, 0), connection.pacer.budget);

    const challenge = [_]u8{ 0xc0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerMigration(migrated_endpoint.address(), challenge);
    try std.testing.expectEqual(migrated_endpoint.address(), connection.config.peer);
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), connection.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, connection.pmtudCurrentSize());
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(connection.pacer.maxBurstSize(), connection.pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), connection.pacer.last_sent_time_ns);
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.pendingChallengeCount());

    var challenge_frame = try connection.path_validation.nextChallengeFrame();
    try std.testing.expectEqualSlices(u8, &challenge, &challenge_frame.path_challenge.data);
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.outstandingChallengeCount());

    const frames = [_]quic.Frame{.{ .path_response = .{ .data = challenge } }};
    try one_rtt.testing.applyReceivedFrames(&connection, 0, &frames, null, .not_ect);
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?usize, null), connection.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT preferred address migration selects address and CID" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var original_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_endpoint.deinit();
    var preferred_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer preferred_endpoint.deinit();

    const local_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const peer_cid = [_]u8{ 0xa4, 0xa5, 0xa6, 0xa7 };
    const preferred_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa0} ** quic.protection.secret_len);

    const preferred_address = quic.PreferredAddress{
        .ipv4_address = [_]u8{ 127, 0, 0, 1 },
        .ipv4_port = preferred_endpoint.address().ip4.port,
        .connection_id = &preferred_cid,
        .stateless_reset_token = [_]u8{0x5a} ** 16,
    };
    var connection = try one_rtt.Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .peer_preferred_address = preferred_address,
        .active_connection_id_limit = 4,
    });
    defer connection.deinit();

    try std.testing.expect(connection.peerPreferredAddress() != null);
    try std.testing.expectEqual(preferred_endpoint.address(), one_rtt.Connection.preferredAddressIp4(preferred_address).?);
    try std.testing.expect(one_rtt.Connection.preferredAddressIp6(preferred_address) == null);

    const challenge = [_]u8{ 0xa0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerPreferredAddressMigration(challenge, .ipv4);
    try std.testing.expectEqual(preferred_endpoint.address(), connection.config.peer);
    try std.testing.expectEqualSlices(u8, &preferred_cid, connection.config.peer_connection_id);
    try std.testing.expectEqual(@as(usize, 2), connection.peer_connection_ids.count());
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), connection.antiAmplificationLimitRemaining());
    var challenge_frame = try connection.path_validation.nextChallengeFrame();
    try std.testing.expectEqualSlices(u8, &challenge, &challenge_frame.path_challenge.data);

    var missing = try one_rtt.Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
    });
    defer missing.deinit();
    try std.testing.expectError(error.InvalidTransportParameter, missing.beginPeerPreferredAddressMigration(challenge, .ipv4));
}

test "QUIC 1-RTT connection exchanges PATH_CHALLENGE and PATH_RESPONSE" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const challenge = [_]u8{ 1, 3, 5, 7, 9, 11, 13, 15 };
    try client.queuePathChallenge(challenge);
    try client.sendPendingPathChallenge();

    var challenge_packet = try server.receivePacket();
    defer challenge_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingResponseCount());

    const saved_packet_number = server.next_packet_number;
    server.next_packet_number = quic.protection.max_packet_number + 1;
    try std.testing.expectError(error.InvalidPacketNumber, server.sendPendingPathResponse());
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingResponseCount());
    server.next_packet_number = saved_packet_number;

    try server.sendPendingPathResponse();

    var response_packet = try client.receivePacket();
    defer response_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.outstandingChallengeCount());
}

test "QUIC 1-RTT connection batches PATH_CHALLENGE and PATH_RESPONSE frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try std.testing.expectEqual(@as(usize, 0), try client.sendPendingPathChallengesAt(100, 50));
    try std.testing.expectEqual(@as(usize, 0), try server.sendPendingPathResponses());
    try std.testing.expectError(error.NoPendingPathChallenge, client.sendPendingPathChallengeAt(100, 50));
    try std.testing.expectError(error.NoPendingPathResponse, server.sendPendingPathResponse());

    const first = [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 };
    const second = [_]u8{ 2, 3, 5, 8, 13, 21, 34, 55 };
    try client.queuePathChallenge(first);
    try client.queuePathChallenge(second);
    try std.testing.expectEqual(@as(usize, 2), try client.sendPendingPathChallengesAt(100, 50));
    try std.testing.expectEqual(@as(usize, 2), client.path_validation.outstandingChallengeCount());

    var challenge_packet = try server.receivePacket();
    defer challenge_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), challenge_packet.frames.len);
    try std.testing.expectEqualSlices(u8, &first, &challenge_packet.frames[0].path_challenge.data);
    try std.testing.expectEqualSlices(u8, &second, &challenge_packet.frames[1].path_challenge.data);
    try std.testing.expectEqual(@as(usize, 2), server.path_validation.pendingResponseCount());

    try std.testing.expectEqual(@as(usize, 2), try server.sendPendingPathResponses());
    var response_packet = try client.receivePacket();
    defer response_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), response_packet.frames.len);
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.outstandingChallengeCount());
}

test "QUIC 1-RTT connection handles NEW and RETIRE connection IDs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe1} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try server.sendNewConnectionId("server-new-cid", [_]u8{0xaa} ** 16);
    var new_cid_packet = try client.receivePacket();
    defer new_cid_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());
    try std.testing.expectError(error.ActiveConnectionIdLimit, server.sendNewConnectionId("server-extra-cid", [_]u8{0xab} ** 16));
    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-new-cid", client.config.peer_connection_id);
    var reset_datagram: std.ArrayList(u8) = .empty;
    defer reset_datagram.deinit(allocator);
    try quic.stateless_reset.encode(&reset_datagram, allocator, &.{ 0x40, 1, 2, 3, 4 }, [_]u8{0xaa} ** 16);
    try std.testing.expectEqual(@as(?u64, 1), client.detectStatelessReset(reset_datagram.items));

    const retire = [_]quic.Frame{.{ .retire_connection_id = .{ .sequence_number = 0 } }};
    try client.send(&retire);
    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-new-cid", .{ .connection_index = 0, .sequence_number = 1 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire_packet = try server.receiveRoutedDatagram(routed);
    defer retire_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), server.local_connection_ids.count());
}

test "QUIC 1-RTT replacement CID can retire prior IDs at peer active limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x72, 0x73, 0x74, 0x75 };
    const server_cid = [_]u8{ 0x76, 0x77, 0x78, 0x79 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try server.sendNewConnectionId("server-first-cid", [_]u8{0xa1} ** 16);
    var first = try client.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());

    try std.testing.expectError(error.ActiveConnectionIdLimit, server.sendNewConnectionId("server-extra-cid", [_]u8{0xa2} ** 16));
    try server.sendNewConnectionIdRetiringPriorTo("server-rotated-cid", [_]u8{0xa3} ** 16, 1);
    var replacement = try client.receivePacket();
    defer replacement.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), replacement.frames[0].new_connection_id.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), replacement.frames[0].new_connection_id.retire_prior_to);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());
    try std.testing.expectEqual(@as(usize, 1), client.pendingRetireConnectionIdCount());

    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-rotated-cid", client.config.peer_connection_id);
    try std.testing.expectEqual(@as(usize, 1), try client.sendPendingRetireConnectionIds());
    try std.testing.expectEqual(@as(usize, 0), client.pendingRetireConnectionIdCount());

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-rotated-cid", .{ .connection_index = 0, .sequence_number = 2 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire = try server.receiveRoutedDatagram(routed);
    defer retire.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), server.local_connection_ids.count());
}

test "QUIC 1-RTT derives local CID stateless reset tokens from config key" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const reset_key = [_]u8{0x5c} ** quic.stateless_reset.static_key_len;
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_stateless_reset_key = reset_key,
    });
    defer server.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(reset_key, &server_cid),
        &server.local_connection_ids.entries[0].stateless_reset_token,
    );

    try server.sendNewConnectionIdWithDerivedToken("derived-cid");
    var packet = try client.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(reset_key, "derived-cid"),
        &packet.frames[0].new_connection_id.stateless_reset_token,
    );
}

test "QUIC 1-RTT sends QUIC-LB connection IDs with derived reset tokens" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const server_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const reset_key = [_]u8{0x6c} ** quic.stateless_reset.static_key_len;
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_stateless_reset_key = reset_key,
    });
    defer server.deinit();

    const config = quic.quic_lb.Config{
        .config_rotation = 3,
        .server_id_len = 3,
        .nonce_len = 4,
        .key = .{
            0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
            0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
        },
    };
    const server_id = [_]u8{ 0xed, 0x79, 0x3a };
    try server.sendNewConnectionIdQuicLb(
        config,
        &server_id,
        &.{ 0xee, 0x08, 0x0d, 0xbf },
        0,
    );
    var packet = try client.receivePacket();
    defer packet.deinit(allocator);
    const advertised = packet.frames[0].new_connection_id;
    var decoded: [3]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &server_id,
        try quic.quic_lb.decodeServerId(
            config,
            advertised.connection_id,
            &decoded,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(
            reset_key,
            advertised.connection_id,
        ),
        &advertised.stateless_reset_token,
    );
}

test "QUIC 1-RTT QUIC-LB issuance rolls back when sending fails" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    const reset_key = [_]u8{0x7c} ** quic.stateless_reset.static_key_len;
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_stateless_reset_key = reset_key,
    });
    defer connection.deinit();
    const before = connection.local_connection_ids;
    connection.pacer.budget = 0;
    connection.pacer.last_sent_time_ns = 0;
    connection.rtt_stats.has_measurement = true;
    connection.rtt_stats.smoothed_rtt = 100_000_000;

    try std.testing.expectError(
        error.PacingLimited,
        connection.sendNewConnectionIdQuicLbAt(
            .{
                .config_rotation = 1,
                .server_id_len = 2,
                .nonce_len = 4,
            },
            "id",
            "abcd",
            0,
            0,
            1,
        ),
    );
    try std.testing.expectEqualDeep(before, connection.local_connection_ids);
}

test "QUIC 1-RTT preflights RETIRE_CONNECTION_ID for packet destination CID" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x73, 0x74, 0x75, 0x76 };
    const server_cid = [_]u8{ 0x77, 0x78, 0x79, 0x7a };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe2} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    _ = try server.local_connection_ids.issue("server-new-cid", [_]u8{0x44} ** 16);
    try std.testing.expectEqual(@as(usize, 2), server.local_connection_ids.count());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = "server-new-cid",
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "must-not-commit", .fin = false } },
            .{ .retire_connection_id = .{ .sequence_number = 1 } },
        },
    });

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-new-cid", .{ .connection_index = 0, .sequence_number = 1 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);

    try std.testing.expectError(error.InvalidConnectionId, server.receiveRoutedDatagram(routed));
    try std.testing.expectEqual(@as(usize, 2), server.local_connection_ids.count());
    try std.testing.expectEqual(@as(usize, 0), server.received.ranges.items.len);
    try std.testing.expect(!one_rtt.testing.hasReceiveStream(&server, 0));
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.retire_connection_id)), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("retire connection id", server.close_info.?.reason_phrase);
}

test "QUIC 1-RTT queues RETIRE_CONNECTION_ID for retired peer IDs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe7} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .active_connection_id_limit = 4,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 1,
            .connection_id = "server-cid-two",
            .stateless_reset_token = [_]u8{0x77} ** 16,
        } }},
    });
    var new_cid_packet = try client.receivePacket();
    defer new_cid_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRetireConnectionIdCount());
    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-cid-two", client.config.peer_connection_id);

    try std.testing.expectEqual(@as(usize, 1), try client.sendPendingRetireConnectionIds());
    try std.testing.expectEqual(@as(usize, 0), client.pendingRetireConnectionIdCount());

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-cid-two", .{ .connection_index = 0, .sequence_number = 2 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire_packet = try server.receiveRoutedDatagram(routed);
    defer retire_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), server.local_connection_ids.count());
}

const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;

fn sealShortPacketWithReservedBits(
    allocator: std.mem.Allocator,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: u32,
    payload: []const u8,
) ![]u8 {
    const packet_number_len = 4;
    const packet_number_offset = 1 + destination_connection_id.len;
    const payload_offset = packet_number_offset + packet_number_len;
    const packet = try allocator.alloc(
        u8,
        payload_offset + payload.len + quic.protection.aead_tag_len,
    );
    errdefer allocator.free(packet);

    packet[0] = 0x40 | 0x08 | (packet_number_len - 1);
    @memcpy(packet[1..packet_number_offset], destination_connection_id);
    std.mem.writeInt(
        u32,
        packet[packet_number_offset..payload_offset][0..4],
        packet_number,
        .big,
    );
    const ciphertext = packet[payload_offset .. payload_offset + payload.len];
    const tag = packet[payload_offset + payload.len ..][0..quic.protection.aead_tag_len];
    try quic.protection.protectPayload(
        keys,
        packet_number,
        packet[0..payload_offset],
        payload,
        ciphertext,
        tag,
    );
    try quic.protection.applyHeaderProtectionForKeys(
        keys,
        .short,
        packet,
        packet_number_offset,
    );
    return packet;
}

const FixedClockIo = struct {
    delegate: std.Io,
    now_ns: i96,
    sleep_calls: usize = 0,

    fn now(userdata: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *FixedClockIo = @ptrCast(@alignCast(userdata));
        return .fromNanoseconds(self.now_ns);
    }

    fn sleep(
        userdata: ?*anyopaque,
        _: std.Io.Timeout,
    ) std.Io.Cancelable!void {
        const self: *FixedClockIo = @ptrCast(@alignCast(userdata));
        self.sleep_calls += 1;
        return error.Canceled;
    }
};

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

test "QUIC v2 1-RTT connection uses versioned key updates" {
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

    const version = quic.Version.version_2;
    const client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    const client_keys = try quic.protection.deriveAes128KeysForVersion(
        version.wireValue(),
        [_]u8{0x39} ** quic.protection.secret_len,
    );
    const server_keys = try quic.protection.deriveAes128KeysForVersion(
        version.wireValue(),
        [_]u8{0x3a} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .version = version,
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .version = version,
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.initiateKeyUpdate();
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "v2-updated",
        .fin = true,
    } }});
    var updated = try server.receivePacket();
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqualStrings(
        "v2-updated",
        updated.frames[0].stream.data,
    );
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

test "QUIC 1-RTT closes on authenticated short-header reserved bits" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const client_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x89} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const reserved = try sealShortPacketWithReservedBits(
        allocator,
        keys,
        &server_cid,
        0,
        &.{@intFromEnum(quic.FrameType.ping)},
    );
    defer allocator.free(reserved);
    try std.testing.expectError(error.InvalidReservedBits, server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = reserved },
        .route = .{ .connection_index = 0 },
        .destination_connection_id = &server_cid,
    }));
    try std.testing.expectEqual(@as(u64, 0), server.authenticationFailureCount());
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.TransportErrorCode.protocol_violation)),
        server.close_info.?.error_code,
    );
    try std.testing.expectEqual(@as(u64, 0), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings(
        "reserved bits",
        server.close_info.?.reason_phrase,
    );
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
    var updated = (try server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = updated_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    })).?;
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.peerOneRttKeyUpdateCount());
    try std.testing.expect(server.peerOneRttRetainsKeyGeneration(0));

    var delayed_old = (try server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = old_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    })).?;
    defer delayed_old.deinit(allocator);
    try std.testing.expect(!delayed_old.peer_initiated_key_update);
    try std.testing.expect(!delayed_old.packet.key_phase);
    try std.testing.expect(server.peerOneRttKeyPhase());

    server.schedulePreviousOneRttKeyDiscard(10);
    try std.testing.expectEqual(@as(?i64, 10), server.oneRttKeyDiscardDeadline());
    try std.testing.expect(server.discardExpiredOneRttKeys(10));
    try std.testing.expect(!server.peerOneRttRetainsKeyGeneration(0));
    try std.testing.expectError(error.AuthenticationFailed, server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = old_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    }));
    try std.testing.expectEqual(@as(u64, 1), server.authenticationFailureCount());
    try std.testing.expect(!server.closing());
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
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&client).?,
    );

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

test "QUIC 1-RTT PTO does not retransmit a PMTU probe as ordinary data" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbb} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-pto-local",
        .peer_connection_id = "pmtu-pto-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    _ = try connection.sendPmtuProbeAt(1400, 100);
    var probe = try receiver.receiveBytes();
    probe.deinit(allocator);

    // DPLPMTUD probes carry only PING/PADDING. Retrying that payload through
    // generic PTO recovery would strip probe identity and could never validate
    // the larger size, so it must remain an independent one-shot probe.
    try std.testing.expectEqual(@as(usize, 0), try connection.retransmitPtoProbesAt(1_000, 1));
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
}

test "QUIC 1-RTT lone PMTU probe keeps a loss-time deadline" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xba} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-timer-local",
        .peer_connection_id = "pmtu-timer-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    _ = try connection.sendPmtuProbeAt(1400, 100);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    const deadline = connection.lossDetectionTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.loss_time, deadline.kind);
    const result = try connection.serviceLossDetectionTimer(deadline.deadline_ns);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 0), connection.bytesInFlight());
    try std.testing.expect(connection.pmtudShouldProbe());
}

test "QUIC 1-RTT lone PMTU timer does not mark ordinary pre-ACK traffic lost" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb9} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-mixed-local",
        .peer_connection_id = "pmtu-mixed-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try connection.sendAt(&ping, 50);
    _ = try connection.sendPmtuProbeAt(1400, 100);
    const deadline = connection.lossDetectionTimerDeadline() orelse
        return error.TestUnexpectedResult;
    _ = try connection.serviceLossDetectionTimer(deadline.deadline_ns);

    try std.testing.expect(!connection.sent.packets.items[0].lost);
    try std.testing.expect(connection.sent.packets.items[1].lost);
    try std.testing.expect(connection.recovery.packetNumberCandidate(0) != null);
}

test "QUIC PMTU probes reuse connection packet construction storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var counting = std.testing.FailingAllocator.init(allocator, .{});
    var sender = try quic.runtime.Endpoint.bind(
        counting.allocator(),
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbc} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-reuse-local",
        .peer_connection_id = "pmtu-reuse-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const first_size = (try connection.sendPmtuProbeAt(1300, 100)).?;
    const payload_capacity = connection.send_frame_buffer.capacity;
    const payload_ptr = connection.send_frame_buffer.allocatedSlice().ptr;
    try std.testing.expectEqual(@as(usize, 0), connection.send_frame_buffer.items.len);
    var first_wire = try receiver.receiveBytes();
    first_wire.deinit(allocator);

    // Retire the first probe so recovery returns its payload storage to the
    // bounded cache, then re-arm the same size. This isolates connection and
    // recovery-scratch reuse from first-use durable ownership allocation.
    const ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    _ = try connection.recovery.applyAck(ack);
    _ = try connection.sent.applyAck(ack);
    connection.pmtud.should_probe = true;
    counting.fail_index = counting.alloc_index;
    counting.resize_fail_index = counting.resize_index;
    try std.testing.expectEqual(
        first_size,
        (try connection.sendPmtuProbeAt(1300, 200)).?,
    );
    try std.testing.expect(!counting.has_induced_failure);
    try std.testing.expectEqual(payload_capacity, connection.send_frame_buffer.capacity);
    try std.testing.expectEqual(payload_ptr, connection.send_frame_buffer.allocatedSlice().ptr);
    try std.testing.expectEqual(@as(usize, 0), connection.send_frame_buffer.items.len);
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

    connection.pmtud.onProbeSentWithIdentity(0, 1, 1300);
    connection.pmtud.onProbeAckedWithIdentity(0, 1, 1300, 1400, 20);
    connection.congestion.onMtuUpdate(connection.currentSendDatagramSize());
    connection.pacer.onMtuUpdate(connection.currentSendDatagramSize());
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
        .pto_jitter_percentage = 25,
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

    client.pmtud.onProbeSentWithIdentity(99, 1, 1300);
    client.pmtud.onProbeAckedWithIdentity(99, 1, 1300, 1400, 50);
    client.congestion.onMtuUpdate(client.currentSendDatagramSize());
    client.pacer.onMtuUpdate(client.currentSendDatagramSize());
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
    const jitter_epoch = client.ptoJitterEpoch();
    try std.testing.expectError(error.DatagramTooLarge, client.retransmitTimeThresholdLoss(1_000_000, 1));
    try std.testing.expect(client.ptoJitterEpoch() > jitter_epoch);
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
    const lost1 = connection.sent.detectTimeThresholdLossForProbe(
        1_000,
        1,
        0,
        connection.pmtud.active_probe_packet_number,
        connection.pmtud.active_probe_epoch,
    );
    if (lost1.active_pmtu_probe_packet_number) |probe_packet_number| {
        connection.pmtud.onProbeLostWithIdentity(
            probe_packet_number,
            lost1.active_pmtu_probe_epoch,
            lost1.active_pmtu_probe_size.?,
            connection.config.max_datagram_size,
            1_000,
        );
    }
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(probe_size, connection.pmtud.probeSize(1400).?);

    connection.pmtud.onProbeSentWithIdentity(1, connection.pmtu_probe_epoch, probe_size);
    connection.pmtud.onProbeLostWithIdentity(1, connection.pmtu_probe_epoch, probe_size, 1400, 2_000);
    try std.testing.expect(connection.pmtudShouldProbe());
    const next = connection.pmtud.probeSize(1400).?;
    try std.testing.expect(next < probe_size);
    try std.testing.expect(next > quic.pmtu.min_udp_payload_size);
}

test "QUIC 1-RTT ignores stale PMTU probe ACK after path reset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbc} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-stale-ack-local",
        .peer_connection_id = "pmtu-stale-ack-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    _ = try connection.sendPmtuProbeAt(1400, 100);
    const stale_packet_number = connection.pmtud.active_probe_packet_number.?;
    const stale_epoch = connection.pmtud.active_probe_epoch;
    connection.pmtud.resetForPath();
    connection.pmtu_probe_epoch +|= 1;
    if (connection.pmtu_probe_epoch == 0) connection.pmtu_probe_epoch = 1;

    connection.pmtud.onProbeAckedWithIdentity(
        stale_packet_number,
        stale_epoch,
        1300,
        1400,
        200,
    );
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        connection.currentSendDatagramSize(),
    );
}

test "QUIC 1-RTT PMTU probe loss does not reduce congestion window" {
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
        .local_connection_id = "pmtu-loss-l",
        .peer_connection_id = "pmtu-loss-p",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const initial_window = connection.congestionWindow();
    _ = try connection.sendPmtuProbeAt(1400, 100);
    const baseline_flight = connection.bytesInFlight();
    try std.testing.expect(baseline_flight > 0);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try connection.sendAt(&ping, 200);
    const ack_frames = [_]quic.Frame{.{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }};
    try one_rtt.testing.applyReceivedFrames(&connection, 99, &ack_frames, 300, .not_ect);
    try std.testing.expect(!try connection.retransmitTimeThresholdLoss(1_000, 1));
    try std.testing.expectEqual(@as(usize, 0), connection.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expectEqual(initial_window, connection.congestionWindow());
}

test "QUIC 1-RTT packet-threshold probe loss releases bytes_in_flight without cwnd reduction" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbe} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pktloss-l",
        .peer_connection_id = "pktloss-p",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const initial_window = connection.congestionWindow();
    _ = try connection.sendPmtuProbeAt(1400, 100);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try connection.sendAt(&ping, 200);
    try connection.sendAt(&ping, 300);
    try connection.sendAt(&ping, 400);
    const baseline_flight = connection.bytesInFlight();
    try std.testing.expect(baseline_flight > 0);
    const ack_frames = [_]quic.Frame{.{ .ack = .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 2,
    } }};
    try one_rtt.testing.applyReceivedFrames(&connection, 99, &ack_frames, 1_000, .not_ect);
    try std.testing.expectEqual(initial_window, connection.congestionWindow());
    try std.testing.expectEqual(@as(usize, 0), connection.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
}

test "QUIC 1-RTT time-threshold probe loss API does not attempt oversized ordinary retransmission" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbf} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "noretx-l",
        .peer_connection_id = "noretx-p",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer connection.deinit();

    _ = try connection.sendPmtuProbeAt(1400, 100);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try connection.sendAt(&ping, 200);
    const ack_frames = [_]quic.Frame{.{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }};
    try one_rtt.testing.applyReceivedFrames(&connection, 99, &ack_frames, 300, .not_ect);
    connection.pmtud.resetForPath();
    connection.pmtu_probe_epoch +|= 1;
    if (connection.pmtu_probe_epoch == 0) connection.pmtu_probe_epoch = 1;
    try std.testing.expect(!try connection.retransmitTimeThresholdLoss(1_000, 1));
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
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

    // The one-byte PING payload would fit a payload-only budget, but its full
    // protected datagram does not fit within 3 * 7 received bytes.
    server.recordPeerAddressBytesReceived(7);
    try std.testing.expectEqual(@as(?usize, 21), server.antiAmplificationLimitRemaining());
    try std.testing.expectError(error.AntiAmplificationLimited, server.sendAt(&ping, 20));
    server.recordPeerAddressBytesReceived(3);
    try std.testing.expectEqual(@as(?usize, 30), server.antiAmplificationLimitRemaining());
    try server.sendAt(&ping, 20);
    try std.testing.expectEqual(@as(usize, 1), server.pendingRecoveryCount());

    var sent = try client_endpoint.receiveBytes();
    defer sent.deinit(allocator);
    try std.testing.expect(sent.bytes.len > 0);
    try std.testing.expectEqual(
        @as(?usize, 30 - sent.bytes.len),
        server.antiAmplificationLimitRemaining(),
    );

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
    server.recordPeerAddressBytesReceived(9);
    try server.sendAt(&ping, 10_000_000);
    var original = try client_endpoint.receiveBytes();
    defer original.deinit(allocator);
    try std.testing.expectEqual(
        @as(?usize, 27 - original.bytes.len),
        server.antiAmplificationLimitRemaining(),
    );

    // Consume the tiny remaining budget so the server is blocked exactly when
    // another datagram arrives with enough credit to service the already-due PTO.
    server.peer_address_bytes_sent = 27;
    const serviced = (try server.recordPeerAddressDatagramReceived(335_000_000, 10)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), server.ptoBackoffCount());
    try std.testing.expect(server.antiAmplificationLimitRemaining().? < 30);

    var probe = try client_endpoint.receiveBytes();
    defer probe.deinit(allocator);
    try std.testing.expect(original.bytes.len > 0);
    try std.testing.expect(probe.bytes.len > 0);
}

test "QUIC PATH_CHALLENGE commits only after an anti-amplification-blocked send succeeds" {
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

    const client_cid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    const server_cid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc1 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xba} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    server.setPeerAddressValidated(false);

    const challenge = [_]u8{ 0xcc, 1, 2, 3, 4, 5, 6, 7 };
    try server.queuePathChallenge(challenge);
    try std.testing.expectError(
        error.AntiAmplificationLimited,
        server.sendPendingPathChallengeAt(100, 50),
    );
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?u64, null), server.pathValidationDeadline());
    try std.testing.expectEqual(@as(u64, 0), server.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());

    server.recordPeerAddressBytesReceived(400);
    try server.sendPendingPathChallengeAt(100, 50);
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?u64, 150), server.pathValidationDeadline());

    var packet = try client_endpoint.receiveBytes();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        packet.bytes.len,
    );
    var decoded = try one_rtt.openReceivedBytes(
        &client_endpoint,
        packet.from,
        packet.bytes,
        keys,
        client_cid.len,
        0,
        8,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &challenge,
        &decoded.frames[0].path_challenge.data,
    );
}

test "QUIC PATH_CHALLENGE batch preserves every pending item on send failure" {
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

    const client_cid = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd };
    const server_cid = [_]u8{ 0xce, 0xcf, 0xd0, 0xd1 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    server.setPeerAddressValidated(false);

    const first = [_]u8{ 0xd1, 0, 0, 0, 0, 0, 0, 1 };
    const second = [_]u8{ 0xd2, 0, 0, 0, 0, 0, 0, 2 };
    try server.queuePathChallenge(first);
    try server.queuePathChallenge(second);
    try std.testing.expectError(
        error.AntiAmplificationLimited,
        server.sendPendingPathChallengesAt(200, 75),
    );
    try std.testing.expectEqual(@as(usize, 2), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?u64, null), server.pathValidationDeadline());

    server.recordPeerAddressBytesReceived(400);
    try std.testing.expectEqual(
        @as(usize, 2),
        try server.sendPendingPathChallengesAt(200, 75),
    );
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 2), server.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?u64, 275), server.pathValidationDeadline());
}

test "QUIC blocked PATH_CHALLENGE timer remains armed until credit arrives" {
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
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-server",
        .peer_connection_id = "timer-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    server.setPeerAddressValidated(false);

    try server.queuePathChallenge([_]u8{0xd3} ** 8);
    try std.testing.expectError(
        error.AntiAmplificationLimited,
        server.sendPendingPathChallengeAt(100, 50),
    );
    const first_retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_validation,
        first_retry.kind,
    );
    try std.testing.expectEqual(
        @as(u64, 100 + std.time.ns_per_ms),
        first_retry.deadline_ns,
    );
    _ = try server.serviceNextTimerAt(first_retry.deadline_ns);
    const second_retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, first_retry.deadline_ns + std.time.ns_per_ms),
        second_retry.deadline_ns,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        server.path_validation.pendingChallengeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.path_validation.outstandingChallengeCount(),
    );

    server.recordPeerAddressBytesReceived(400);
    _ = try server.serviceNextTimerAt(second_retry.deadline_ns);
    try std.testing.expect(server.nextTimerDeadline() != null);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.path_validation.pendingChallengeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        server.path_validation.outstandingChallengeCount(),
    );
    var sent = try peer.receiveBytes();
    defer sent.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        sent.bytes.len,
    );
}

test "QUIC PATH_CHALLENGE timer does not wait for pacing" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "paced-client",
        .peer_connection_id = "paced-server",
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 95;
    try dispatcher.registerConnection(handle, &connection);

    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer endpoint.io = fixed_io.delegate;

    try connection.sendAt(
        &.{.{ .padding = .{ .len = 1160 } }},
        @intCast(fixed_io.now_ns),
    );
    const challenge = [_]u8{ 21, 34, 55, 89, 1, 2, 3, 5 };
    try connection.queuePathChallenge(challenge);
    try std.testing.expectError(
        error.PacingLimited,
        connection.sendPendingPathChallengeAt(
            @intCast(fixed_io.now_ns),
            1_000_000,
        ),
    );
    try dispatcher.refreshConnectionTimer(handle);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.path_validation.pendingChallengeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.path_validation.outstandingChallengeCount(),
    );
    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, timer.connection_id);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_validation,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    const serviced = (try dispatcher.serviceNextTimerAt(
        timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_validation,
        serviced.timer.kind,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.path_validation.pendingChallengeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.path_validation.outstandingChallengeCount(),
    );
}

test "QUIC congestion-blocked PATH_CHALLENGE retains retry deadline" {
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
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-client",
        .peer_connection_id = "timer-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    client.congestion.congestion_window = 0;

    try client.queuePathChallenge([_]u8{0xd4} ** 8);
    try std.testing.expectError(
        error.CongestionLimited,
        client.sendPendingPathChallengeAt(200, 50),
    );
    const retry = client.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_validation,
        retry.kind,
    );
    try std.testing.expectEqual(
        @as(u64, 200 + std.time.ns_per_ms),
        retry.deadline_ns,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.path_validation.pendingChallengeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.path_validation.outstandingChallengeCount(),
    );

    client.congestion.congestion_window = quic.congestion.initialWindow(1200);
    _ = try client.serviceNextTimerAt(retry.deadline_ns);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.path_validation.pendingChallengeCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.path_validation.outstandingChallengeCount(),
    );
    var sent = try peer.receiveBytes();
    defer sent.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        sent.bytes.len,
    );
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
                var packet = (try server_a.receiveRoutedDatagram(routed)).?;
                defer packet.deinit(allocator);
                try std.testing.expectEqualStrings("for-a", packet.frames[0].stream.data);
                saw_a = true;
            },
            1 => {
                var packet = (try server_b.receiveRoutedDatagram(routed)).?;
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
    try std.testing.expectEqual(@as(usize, 1), client.failedPathValidationCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        client.stats().failed_path_validations,
    );
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

test "QUIC 1-RTT duplicate migration challenge leaves current path unchanged" {
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
    var peer_b = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_b.deinit();
    var peer_c = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_c.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xef} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "duplicate-local",
        .peer_connection_id = "duplicate-peer",
    });
    defer connection.deinit();

    const challenge = [_]u8{ 0xd0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerMigration(peer_b.address(), challenge);
    const path_epoch = one_rtt.testing.currentPathEpoch(&connection);
    try std.testing.expectError(
        error.DuplicatePathChallenge,
        connection.beginPeerMigration(peer_c.address(), challenge),
    );
    try std.testing.expectEqual(peer_b.address(), connection.peerAddress());
    try std.testing.expectEqual(
        path_epoch,
        one_rtt.testing.currentPathEpoch(&connection),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.path_validation.pendingChallengeCount(),
    );
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
        .local_disable_active_migration = true,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
        .enable_spin_bit = true,
    });
    defer server.deinit();
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&server),
    );
    const old_path_epoch = one_rtt.testing.currentPathEpoch(&server);
    server.pmtud.onProbeSentWithIdentity(0, 1, 1300);
    server.pmtud.onProbeAckedWithIdentity(0, 1, 1300, 1300, 10);
    server.congestion.onMtuUpdate(server.currentSendDatagramSize());
    server.pacer.onMtuUpdate(server.currentSendDatagramSize());
    server.rtt_stats.updateAt(37_000_000, 0, true, 1);
    server.pto_count = 4;
    server.last_persistent_congestion_packet_number = 9;

    try one_rtt.sendFrames(&rebound_client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .spin_bit = true,
        .frames = &.{.{ .stream = .{ .stream_id = 0, .data = "rebinding" } }},
    });

    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings("rebinding", packet.frames[0].stream.data);
    try std.testing.expect(server.nextSpinBit());
    try std.testing.expectEqual(
        @as(?u64, 0),
        one_rtt.testing.spinLargestReceivedPacketNumber(&server),
    );
    try std.testing.expectEqual(rebound_client_endpoint.address(), server.config.peer);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&server),
    );
    try std.testing.expect(
        one_rtt.testing.currentPathEpoch(&server) != old_path_epoch,
    );
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, server.pmtudCurrentSize());
    try std.testing.expect(server.pmtudShouldProbe());
    try std.testing.expectEqual(
        quic.congestion.initialWindow(quic.pmtu.min_udp_payload_size),
        server.congestionWindow(),
    );
    try std.testing.expect(server.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(u64, 37_000_000), server.rtt_stats.latest_rtt);
    try std.testing.expectEqual(@as(u8, 0), server.ptoBackoffCount());
    try std.testing.expectEqual(
        @as(?u64, null),
        server.last_persistent_congestion_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(
        @as(usize, 0),
        server.pendingPathValidationCount(),
    );
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT spin bit keeps independent candidate path state" {
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
    var original_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_peer.deinit();
    var candidate_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0 } },
        .{ .max_datagram_size = 4096 },
    );
    defer candidate_peer.deinit();

    const local_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3 };
    const peer_cid = [_]u8{ 0xf4, 0xf5, 0xf6, 0xf7 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf8} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&endpoint, .{
        .peer = original_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
        .enable_spin_bit = true,
        .enable_pacing = false,
    });
    defer server.deinit();
    server.setPeerAddressValidated(true);

    const ping_payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .ping = {} }},
    );
    defer allocator.free(ping_payload);
    const current_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &local_cid,
            .packet_number = 2,
            .packet_number_len = 4,
            .spin_bit = false,
            .payload = ping_payload,
        },
    );
    defer allocator.free(current_packet);
    var current = try one_rtt.testing.processReceivedBytesAt(
        &server,
        original_peer.address(),
        current_packet,
        .not_ect,
        10,
    );
    current.deinit(allocator);
    try std.testing.expect(!server.nextSpinBit());
    try std.testing.expectEqual(
        @as(?u64, 2),
        one_rtt.testing.spinLargestReceivedPacketNumber(&server),
    );

    const challenge_payload = try one_rtt.encodeFrames(
        allocator,
        &.{
            .{ .path_challenge = .{
                .data = .{ 0xf9, 1, 2, 3, 4, 5, 6, 7 },
            } },
            .{ .padding = .{ .len = 1160 } },
        },
    );
    defer allocator.free(challenge_payload);
    const candidate_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &local_cid,
            .packet_number = 3,
            .packet_number_len = 4,
            .spin_bit = true,
            .payload = challenge_payload,
        },
    );
    defer allocator.free(candidate_packet);
    var candidate = try one_rtt.testing.processReceivedBytesAt(
        &server,
        candidate_peer.address(),
        candidate_packet,
        .not_ect,
        11,
    );
    candidate.deinit(allocator);
    try std.testing.expect(!server.nextSpinBit());
    const candidate_spin = one_rtt.testing.candidatePathSpinState(
        &server,
        candidate_peer.address(),
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(candidate_spin.value);
    try std.testing.expectEqual(
        @as(?u64, 3),
        candidate_spin.largest_received_packet_number,
    );
    const reordered_candidate_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &local_cid,
            .packet_number = 1,
            .packet_number_len = 4,
            .spin_bit = false,
            .payload = challenge_payload,
        },
    );
    defer allocator.free(reordered_candidate_packet);
    var reordered = try one_rtt.testing.processReceivedBytesAt(
        &server,
        candidate_peer.address(),
        reordered_candidate_packet,
        .not_ect,
        12,
    );
    reordered.deinit(allocator);
    const after_reorder = one_rtt.testing.candidatePathSpinState(
        &server,
        candidate_peer.address(),
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(after_reorder.value);
    try std.testing.expectEqual(
        @as(?u64, 3),
        after_reorder.largest_received_packet_number,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        try server.sendPendingPathResponses(),
    );
    var candidate_response = try candidate_peer.receiveBytes();
    defer candidate_response.deinit(allocator);
    try std.testing.expect(
        (candidate_response.bytes[0] & 0x20) != 0,
    );
    try std.testing.expect(!server.nextSpinBit());
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
        // The peer's transport parameter constrains this endpoint's own path
        // selection; it must not disable authenticated peer migration.
        .peer_disable_active_migration = true,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
    });
    defer server.deinit();
    server.pmtud.onProbeSentWithIdentity(0, 1, 1300);
    server.pmtud.onProbeAckedWithIdentity(0, 1, 1300, 1300, 10);
    server.congestion.onMtuUpdate(server.currentSendDatagramSize());
    server.pacer.onMtuUpdate(server.currentSendDatagramSize());
    server.pacer.onPacketSentAt(100, server.pacer.maxBurstSize(), server.congestionWindow(), server.rtt_stats.smoothedOrInitial());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .stream = .{ .stream_id = 0, .data = "new-path" } }},
    });

    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqualStrings("new-path", packet.frames[0].stream.data);
    try std.testing.expectEqual(client_endpoint.address(), server.peerAddress());
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expect(server.antiAmplificationLimitRemaining().? > 0);
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        server.pendingPathValidationCount(),
    );
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, server.pmtudCurrentSize());
    try std.testing.expectEqual(server.pacer.maxBurstSize(), server.pacer.budget);
}

test "QUIC 1-RTT owning receive skips a new client IP when migration is disabled" {
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
        .local_disable_active_migration = true,
    });
    defer server.deinit();

    const blocked_payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .stream = .{ .stream_id = 0, .data = "blocked" } }},
    );
    defer allocator.free(blocked_payload);
    const blocked_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .packet_number_len = 4,
            .payload = blocked_payload,
        },
    );
    defer allocator.free(blocked_packet);
    var different_ip = rebound_client_endpoint.address();
    different_ip.ip4.bytes = .{ 127, 0, 0, 2 };
    try server.preloadReceivedDatagram(
        different_ip,
        blocked_packet,
        .ce,
    );
    try one_rtt.sendFrames(
        &original_client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 1,
            .frames = &.{.{ .stream = .{
                .stream_id = 0,
                .data = "accepted",
            } }},
        },
    );
    const initial_stats = server.stats();
    const initial_epoch = one_rtt.testing.currentPathEpoch(&server);
    var accepted = try server.receivePacket();
    defer accepted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), accepted.packet.packet_number);
    try std.testing.expectEqualStrings("accepted", accepted.frames[0].stream.data);
    try std.testing.expectEqual(
        original_client_endpoint.address(),
        server.peerAddress(),
    );
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(initial_stats.packets_received + 1, server.stats().packets_received);
    try std.testing.expectEqual(
        initial_epoch,
        one_rtt.testing.currentPathEpoch(&server),
    );
    try std.testing.expectEqual(@as(u64, 0), server.authenticationFailureCount());
    try std.testing.expectEqual(@as(usize, 1), server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 1), server.received.ranges.items.len);
}

test "QUIC client drops unknown server tuples before decrypting" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var unknown_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer unknown_endpoint.deinit();

    const client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x51} ** quic.protection.secret_len,
    );
    const next_keys = quic.protection.nextAes128PacketProtectionKeys(keys);
    const reset_token = [_]u8{0x91} ** quic.stateless_reset.token_len;
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_stateless_reset_token = reset_token,
    });
    defer client.deinit();

    const payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .stream = .{ .stream_id = 1, .data = "spoofed" } }},
    );
    defer allocator.free(payload);
    const current_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 99,
            .packet_number_len = 4,
            .payload = payload,
        },
    );
    defer allocator.free(current_packet);
    const updated_packet = try quic.protection.sealShortPacket(
        allocator,
        next_keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 100,
            .packet_number_len = 4,
            .key_phase = true,
            .payload = payload,
        },
    );
    defer allocator.free(updated_packet);

    const initial_stats = client.stats();
    const initial_epoch = one_rtt.testing.currentPathEpoch(&client);
    const initial_expected_packet_number =
        one_rtt.testing.expectedPacketNumber(&client);
    const route = quic.connection_router.Route{ .connection_index = 0 };
    try std.testing.expect((try client.receiveRoutedDatagramOrDropAfterClose(.{
        .datagram = .{
            .from = unknown_endpoint.address(),
            .bytes = current_packet,
        },
        .route = route,
        .destination_connection_id = &client_cid,
    })) == null);

    var different_ip = unknown_endpoint.address();
    different_ip.ip4.bytes = .{ 127, 0, 0, 2 };
    try std.testing.expect((try one_rtt.testing
        .processReceivedBytesOrDropPeerAddressAt(
        &client,
        different_ip,
        updated_packet,
        .ce,
        10,
    )) == null);
    var reset_bytes = [_]u8{0x40} ** 32;
    @memcpy(
        reset_bytes[reset_bytes.len - quic.stateless_reset.token_len ..],
        &reset_token,
    );
    const reset_result = try client.receiveRoutedDatagramOrStatelessReset(
        .{
            .datagram = .{ .from = different_ip, .bytes = &reset_bytes },
            .route = route,
            .destination_connection_id = &client_cid,
        },
        20,
        30,
    );
    try std.testing.expect(reset_result == .dropped_peer_address);

    try std.testing.expectEqual(server_endpoint.address(), client.peerAddress());
    try std.testing.expect(client.peerAddressValidated());
    try std.testing.expectEqual(initial_epoch, one_rtt.testing.currentPathEpoch(&client));
    try std.testing.expectEqual(
        initial_expected_packet_number,
        one_rtt.testing.expectedPacketNumber(&client),
    );
    try std.testing.expectEqual(initial_stats, client.stats());
    try std.testing.expectEqual(@as(u64, 0), client.authenticationFailureCount());
    try std.testing.expect(!client.draining());
    try std.testing.expect(!client.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 0), client.peerOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.pendingPathValidationCount());
    try std.testing.expectEqual(
        @as(usize, 0),
        one_rtt.testing.candidatePathBudgetCount(&client),
    );

    var accepted = (try client.receiveRoutedDatagram(.{
        .datagram = .{
            .from = server_endpoint.address(),
            .bytes = current_packet,
        },
        .route = route,
        .destination_connection_id = &client_cid,
    })) orelse return error.TestUnexpectedResult;
    defer accepted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 99), accepted.packet.packet_number);
    try std.testing.expectEqualStrings("spoofed", accepted.frames[0].stream.data);
}

test "QUIC client owning batch and visitor skip unknown server tuple" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var unknown_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer unknown_endpoint.deinit();

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x81} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    const unknown_payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .ping = {} }},
    );
    defer allocator.free(unknown_payload);
    const owning_unknown_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 10,
            .packet_number_len = 4,
            .payload = unknown_payload,
        },
    );
    defer allocator.free(owning_unknown_packet);
    try client.preloadReceivedDatagram(
        unknown_endpoint.address(),
        owning_unknown_packet,
        .not_ect,
    );
    try one_rtt.sendFrames(
        &server_endpoint,
        client_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 0,
            .frames = &.{.{ .ping = {} }},
        },
    );
    var owning = try client.receivePacketAt(10);
    defer owning.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), owning.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), client.stats().packets_received);

    const batch_unknown_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 20,
            .packet_number_len = 4,
            .payload = unknown_payload,
        },
    );
    defer allocator.free(batch_unknown_packet);
    try client.preloadReceivedDatagram(
        unknown_endpoint.address(),
        batch_unknown_packet,
        .not_ect,
    );
    try one_rtt.sendFrames(
        &server_endpoint,
        client_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 1,
            .frames = &.{.{ .ping = {} }},
        },
    );
    var batch = try client.receivePacketBatchAt(20);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), batch.packets.len);
    try std.testing.expectEqual(
        @as(u64, 1),
        batch.packets[0].packet.packet_number,
    );
    try std.testing.expectEqual(@as(u64, 2), client.stats().packets_received);

    try one_rtt.sendFrames(
        &unknown_endpoint,
        client_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 21,
            .frames = &.{.{ .ping = {} }},
        },
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try client.servicePacketBatchAt(20),
    );
    try std.testing.expectEqual(@as(u64, 2), client.stats().packets_received);

    const unknown_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 22,
            .packet_number_len = 4,
            .payload = unknown_payload,
        },
    );
    defer allocator.free(unknown_packet);
    try client.preloadReceivedDatagram(
        unknown_endpoint.address(),
        unknown_packet,
        .not_ect,
    );
    try one_rtt.sendFrames(
        &server_endpoint,
        client_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 2,
            .frames = &.{.{ .stream = .{
                .stream_id = 1,
                .data = "accepted",
            } }},
        },
    );

    const Observed = struct {
        calls: usize = 0,
        from: ?std.Io.net.IpAddress = null,

        fn visit(observed: *@This(), packet: one_rtt.ReceivedPacketView) !void {
            observed.calls += 1;
            observed.from = packet.from;
            try std.testing.expectEqual(@as(u64, 2), packet.packet_number);
            try std.testing.expectEqualStrings(
                "accepted",
                packet.frames[0].stream.data,
            );
        }
    };
    var observed: Observed = .{};
    try client.visitPacketAt(30, &observed, Observed.visit);
    try std.testing.expectEqual(@as(usize, 1), observed.calls);
    try std.testing.expectEqual(server_endpoint.address(), observed.from.?);
    try std.testing.expectEqual(@as(u64, 3), client.stats().packets_received);
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
    connection.ecn_path.onValidatedAck();
    try std.testing.expectEqual(
        quic.ecn.ValidationState.capable,
        one_rtt.testing.ecnPathState(&connection),
    );
    const old_path_epoch = one_rtt.testing.currentPathEpoch(&connection);
    connection.pmtud.onProbeSentWithIdentity(0, 1, 1300);
    connection.pmtud.onProbeAckedWithIdentity(0, 1, 1300, 1300, 10);
    connection.congestion.onMtuUpdate(connection.currentSendDatagramSize());
    connection.pacer.onMtuUpdate(connection.currentSendDatagramSize());
    connection.congestion.congestion_window = 42_000;
    connection.rtt_stats.updateAt(33_000_000, 0, true, 50);
    connection.pto_count = 3;
    connection.pacing_blocked_until_ns = 999;
    connection.last_persistent_congestion_packet_number = 7;
    connection.pacer.onPacketSentAt(100, connection.pacer.maxBurstSize(), connection.congestionWindow(), connection.rtt_stats.smoothedOrInitial());
    try std.testing.expectEqual(@as(usize, 1300), connection.pmtudCurrentSize());
    try std.testing.expectEqual(@as(usize, 0), connection.pacer.budget);

    const challenge = [_]u8{ 0xc0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerMigration(migrated_endpoint.address(), challenge);
    try std.testing.expectEqual(
        migrated_endpoint.address(),
        connection.peerAddress(),
    );
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expect(
        one_rtt.testing.currentPathEpoch(&connection) != old_path_epoch,
    );
    try std.testing.expectEqual(@as(?usize, null), connection.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, connection.pmtudCurrentSize());
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(
        quic.congestion.initialWindow(quic.pmtu.min_udp_payload_size),
        connection.congestionWindow(),
    );
    try std.testing.expectEqual(quic.pacing.Pacer.init(true, quic.pmtu.min_udp_payload_size, quic.pacing.Pacer.default_max_burst_packets).maxBurstSize(), connection.pacer.maxBurstSize());
    try std.testing.expectEqual(connection.pacer.maxBurstSize(), connection.pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), connection.pacer.last_sent_time_ns);
    try std.testing.expect(!connection.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(u8, 0), connection.ptoBackoffCount());
    try std.testing.expectEqual(@as(?u64, null), connection.pacing_blocked_until_ns);
    try std.testing.expectEqual(
        @as(?u64, null),
        connection.last_persistent_congestion_packet_number,
    );
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.pendingChallengeCount());

    try connection.sendPendingPathChallenge();
    var challenge_datagram = try migrated_endpoint.receiveBytes();
    defer challenge_datagram.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        challenge_datagram.bytes.len,
    );
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.outstandingChallengeCount());

    const frames = [_]quic.Frame{.{ .path_response = .{ .data = challenge } }};
    try one_rtt.testing.applyReceivedFrames(&connection, 0, &frames, null, .not_ect);
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?usize, null), connection.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT delayed old-path response cannot validate current path" {
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
    var original_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_peer.deinit();
    var peer_b = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_b.deinit();
    var peer_c = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_c.deinit();

    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb1} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const challenge_b = [_]u8{ 0xb0, 1, 2, 3, 4, 5, 6, 7 };
    try server.beginPeerMigration(peer_b.address(), challenge_b);
    server.recordPeerAddressBytesReceived(400);
    const epoch_b = one_rtt.testing.currentPathEpoch(&server);
    try server.sendPendingPathChallenge();
    var packet_b = try peer_b.receiveBytes();
    packet_b.deinit(allocator);

    const challenge_c = [_]u8{ 0xc0, 1, 2, 3, 4, 5, 6, 7 };
    try server.beginPeerMigration(peer_c.address(), challenge_c);
    server.recordPeerAddressBytesReceived(400);
    const epoch_c = one_rtt.testing.currentPathEpoch(&server);
    try std.testing.expect(epoch_c != epoch_b);
    try server.sendPendingPathChallenge();
    var packet_c = try peer_c.receiveBytes();
    packet_c.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), server.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?usize, 0), server.antiAmplificationLimitRemaining());

    // A delayed response consumes B's token, but cannot validate C or release
    // C's server anti-amplification limit.
    try one_rtt.sendFrames(&peer_b, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .path_response = .{ .data = challenge_b } }},
    });
    var delayed = try server.receivePacket();
    delayed.deinit(allocator);
    try std.testing.expectEqual(peer_c.address(), server.peerAddress());
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), server.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.outstandingChallengeCount());
    try std.testing.expect(server.path_validation.hasChallengeForPathEpoch(epoch_c));

    // RFC 9000 permits PATH_RESPONSE to arrive on a different network path.
    // The token identifies C's challenge even though this packet also comes
    // from B's tuple.
    try one_rtt.sendFrames(&peer_b, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &.{.{ .path_response = .{ .data = challenge_c } }},
    });
    var current = try server.receivePacket();
    current.deinit(allocator);
    try std.testing.expectEqual(peer_c.address(), server.peerAddress());
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.outstandingChallengeCount());
}

test "QUIC 1-RTT late old-path ACK cannot mutate new-path recovery state" {
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
    var migrated_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer migrated_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "migration-local",
        .peer_connection_id = "migration-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    const old_epoch = one_rtt.testing.currentPathEpoch(&connection);
    try connection.sent.sentInFlightAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        true,
        100,
        1200,
        .not_ect,
        100,
        old_epoch,
    );
    _ = try connection.recovery.trackSent(
        0,
        &.{@intFromEnum(quic.FrameType.ping)},
    );
    try connection.congestion.reserve(100);
    connection.rtt_stats.updateAt(50_000_000, 0, true, 100);
    try connection.beginPeerMigration(
        migrated_endpoint.address(),
        [_]u8{ 8, 6, 7, 5, 3, 0, 9, 1 },
    );
    const new_epoch = one_rtt.testing.currentPathEpoch(&connection);
    try std.testing.expect(new_epoch != old_epoch);
    try std.testing.expect(!connection.rtt_stats.has_measurement);

    try connection.sent.sentInFlightAtWithDatagramSizeAndPathEpoch(
        1,
        true,
        true,
        200,
        1200,
        .not_ect,
        1_000,
        new_epoch,
    );
    try connection.congestion.reserve(200);
    connection.pto_count = 3;
    const new_path_cwnd = connection.congestionWindow();
    const new_path_flight = connection.bytesInFlight();
    const jitter_epoch = connection.ptoJitterEpoch();
    const pto_deadline = connection.ptoDeadline();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        10,
        &.{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        10_000,
        .not_ect,
    );
    try std.testing.expect(connection.sent.packets.items[0].acknowledged);
    try std.testing.expect(!connection.rtt_stats.has_measurement);
    try std.testing.expectEqual(new_path_cwnd, connection.congestionWindow());
    try std.testing.expectEqual(new_path_flight, connection.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u8, 3), connection.ptoBackoffCount());
    try std.testing.expectEqual(jitter_epoch, connection.ptoJitterEpoch());
    try std.testing.expectEqual(pto_deadline, connection.ptoDeadline());

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        11,
        &.{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        11_000,
        .not_ect,
    );
    try std.testing.expect(connection.rtt_stats.has_measurement);
    try std.testing.expectEqual(
        @as(u64, 10_000),
        connection.rtt_stats.latest_rtt,
    );
    try std.testing.expectEqual(@as(usize, 0), connection.bytesInFlight());
    try std.testing.expectEqual(@as(u8, 0), connection.ptoBackoffCount());
}

test "QUIC 1-RTT old-path loss does not reduce new-path congestion" {
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
    var migrated_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer migrated_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "loss-local",
        .peer_connection_id = "loss-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    const old_epoch = one_rtt.testing.currentPathEpoch(&connection);
    for (0..2) |packet_number| {
        try connection.sent.sentInFlightAtWithDatagramSizeAndPathEpoch(
            packet_number,
            true,
            true,
            100,
            1200,
            .not_ect,
            100 + packet_number,
            old_epoch,
        );
        _ = try connection.recovery.trackSent(
            packet_number,
            &.{@intFromEnum(quic.FrameType.ping)},
        );
    }
    try connection.congestion.reserve(200);
    try connection.beginPeerMigration(
        migrated_endpoint.address(),
        [_]u8{ 1, 3, 3, 7, 2, 1, 0, 8 },
    );
    connection.setPeerAddressValidated(true);
    const new_epoch = one_rtt.testing.currentPathEpoch(&connection);
    try connection.sent.sentInFlightAtWithDatagramSizeAndPathEpoch(
        4,
        true,
        true,
        200,
        1200,
        .not_ect,
        1_000,
        new_epoch,
    );
    try connection.congestion.reserve(200);
    const new_path_cwnd = connection.congestionWindow();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        20,
        &.{.{ .ack = .{
            .largest_acknowledged = 4,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        2_000,
        .not_ect,
    );
    try std.testing.expect(connection.sent.packets.items[0].lost);
    try std.testing.expect(connection.sent.packets.items[1].lost);
    try std.testing.expect(connection.sent.packets.items[2].acknowledged);
    try std.testing.expectEqual(new_path_cwnd, connection.congestionWindow());
    try std.testing.expectEqual(@as(usize, 0), connection.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 2), connection.pendingRecoveryCount());

    // Loss still makes reliable old-path payloads eligible. Their fresh
    // packet-number copies are sent under the new epoch and consume only the
    // replacement path's congestion budget.
    connection.next_packet_number = 5;
    try std.testing.expectEqual(
        @as(usize, 2),
        try connection.retransmitPacketThresholdLosses(2),
    );
    try std.testing.expectEqual(@as(usize, 2), connection.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 2), connection.bytesInFlight());
}

test "QUIC 1-RTT late old-path plain ACK does not fail fresh path ECN" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var original_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_endpoint.deinit();
    var migrated_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer migrated_endpoint.deinit();

    const local_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const peer_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);

    var connection = try one_rtt.Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .ping = {} }}); // packet 0 on old path, auto ECT(0)
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );

    const challenge = [_]u8{ 9, 7, 5, 3, 1, 2, 4, 6 };
    try connection.beginPeerMigration(migrated_endpoint.address(), challenge);
    // This test isolates ECN epoch handling rather than path-validation
    // pacing. Model a validated replacement path before sending application
    // traffic so the anti-amplification guard cannot obscure the ECN result.
    connection.setPeerAddressValidated(true);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&connection),
    );
    const new_path_epoch = one_rtt.testing.currentPathEpoch(&connection);

    try connection.send(&.{.{ .ping = {} }}); // packet 1 on new path, still auto ECT(0)
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );

    // A late plain ACK for only the old-path packet must not fail the new path.
    try one_rtt.testing.applyReceivedFrames(&connection, 10, &.{.{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }}, null, .not_ect);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expectEqual(
        new_path_epoch,
        one_rtt.testing.currentPathEpoch(&connection),
    );

    // The first advancing ACK_ECN after the late plain ACK establishes a
    // fresh cumulative counter baseline. It cannot prove which path supplied
    // the counter increase, so it deliberately does not validate the new path.
    try one_rtt.testing.applyReceivedFrames(&connection, 11, &.{.{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 2, .ect1_count = 0, .ecn_ce_count = 0 },
    } }}, null, .not_ect);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expect(!one_rtt.testing.ecnBaselinePending(&connection));

    try connection.send(&.{.{ .ping = {} }}); // packet 2, unambiguous new path
    try one_rtt.testing.applyReceivedFrames(&connection, 12, &.{.{ .ack = .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 3, .ect1_count = 0, .ecn_ce_count = 0 },
    } }}, null, .not_ect);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.capable,
        one_rtt.testing.ecnPathState(&connection),
    );
}

test "QUIC 1-RTT late old-path ACK_ECN still advances baseline without validating fresh path" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var original_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_endpoint.deinit();
    var migrated_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer migrated_endpoint.deinit();

    const local_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const peer_cid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);

    var connection = try one_rtt.Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .ping = {} }}); // packet 0 old path
    try connection.beginPeerMigration(migrated_endpoint.address(), [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 });
    connection.setPeerAddressValidated(true);
    try connection.send(&.{.{ .ping = {} }}); // packet 1 new path

    try one_rtt.testing.applyReceivedFrames(&connection, 20, &.{.{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 1, .ect1_count = 0, .ecn_ce_count = 0 },
    } }}, null, .not_ect);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expectEqual(@as(u64, 1), connection.sent.latest_ecn_counts.ect0_count);

    // Because the old-path-only ACK_ECN advanced the global baseline, the new-path
    // ACK_ECN must still account for packet 1 explicitly instead of reusing stale delta.
    try one_rtt.testing.applyReceivedFrames(&connection, 21, &.{.{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ecn_counts = .{ .ect0_count = 2, .ect1_count = 0, .ecn_ce_count = 0 },
    } }}, null, .not_ect);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.capable,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expectEqual(@as(u64, 2), connection.sent.latest_ecn_counts.ect0_count);
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
        .peer_disable_active_migration = true,
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
    try std.testing.expectEqual(@as(?usize, null), connection.antiAmplificationLimitRemaining());
    try connection.sendPendingPathChallenge();
    var challenge_packet = try preferred_endpoint.receiveBytes();
    defer challenge_packet.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        challenge_packet.bytes.len,
    );
    var decoded = try one_rtt.openReceivedBytes(
        &preferred_endpoint,
        challenge_packet.from,
        challenge_packet.bytes,
        keys,
        preferred_cid.len,
        0,
        8,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), decoded.frames.len);
    try std.testing.expectEqualSlices(
        u8,
        &challenge,
        &decoded.frames[0].path_challenge.data,
    );

    const route = quic.connection_router.Route{ .connection_index = 0 };
    const ping_payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .ping = {} }},
    );
    defer allocator.free(ping_payload);
    const old_path_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &local_cid,
            .packet_number = 0,
            .packet_number_len = 4,
            .payload = ping_payload,
        },
    );
    defer allocator.free(old_path_packet);
    var old_path_received = (try connection.receiveRoutedDatagram(.{
        .datagram = .{
            .from = original_endpoint.address(),
            .bytes = old_path_packet,
        },
        .route = route,
        .destination_connection_id = &local_cid,
    })) orelse return error.TestUnexpectedResult;
    defer old_path_received.deinit(allocator);

    const preferred_path_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &local_cid,
            .packet_number = 1,
            .packet_number_len = 4,
            .payload = ping_payload,
        },
    );
    defer allocator.free(preferred_path_packet);
    var preferred_path_received = (try connection.receiveRoutedDatagram(.{
        .datagram = .{
            .from = preferred_endpoint.address(),
            .bytes = preferred_path_packet,
        },
        .route = route,
        .destination_connection_id = &local_cid,
    })) orelse return error.TestUnexpectedResult;
    defer preferred_path_received.deinit(allocator);

    var third_tuple = preferred_endpoint.address();
    third_tuple.ip4.port +%= 1;
    const third_path_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &local_cid,
            .packet_number = 2,
            .packet_number_len = 4,
            .payload = ping_payload,
        },
    );
    defer allocator.free(third_path_packet);
    try std.testing.expect((try connection.receiveRoutedDatagram(.{
        .datagram = .{ .from = third_tuple, .bytes = third_path_packet },
        .route = route,
        .destination_connection_id = &local_cid,
    })) == null);
    try std.testing.expectEqual(preferred_endpoint.address(), connection.peerAddress());
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(@as(u64, 2), connection.stats().packets_received);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingPathValidationCount());

    var invalid_family = try one_rtt.Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .peer_preferred_address = preferred_address,
        .active_connection_id_limit = 4,
    });
    defer invalid_family.deinit();
    try std.testing.expectError(
        error.InvalidTransportParameter,
        invalid_family.beginPeerPreferredAddressMigration(challenge, .ipv6),
    );
    try std.testing.expectEqual(original_endpoint.address(), invalid_family.peerAddress());
    try std.testing.expectEqualSlices(u8, &peer_cid, invalid_family.config.peer_connection_id);
    try std.testing.expectEqual(@as(usize, 2), invalid_family.peer_connection_ids.count());
    try std.testing.expectEqual(@as(usize, 0), invalid_family.path_validation.pendingChallengeCount());

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    invalid_family.path_validation.allocator = failing.allocator();
    defer invalid_family.path_validation.allocator = allocator;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        invalid_family.beginPeerPreferredAddressMigration(challenge, .ipv4),
    );
    try std.testing.expectEqual(original_endpoint.address(), invalid_family.peerAddress());
    try std.testing.expectEqualSlices(u8, &peer_cid, invalid_family.config.peer_connection_id);
    try std.testing.expectEqual(@as(usize, 2), invalid_family.peer_connection_ids.count());
    try std.testing.expectEqual(@as(usize, 0), invalid_family.path_validation.pendingChallengeCount());

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

test "QUIC 1-RTT owns preferred address connection ID" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x64} ** quic.protection.secret_len,
    );
    var preferred_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const expected_cid = preferred_cid;
    const preferred = quic.PreferredAddress{
        .ipv4_address = .{ 127, 0, 0, 1 },
        .ipv4_port = 4433,
        .connection_id = &preferred_cid,
        .stateless_reset_token = [_]u8{0x69} ** 16,
    };
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .peer_preferred_address = preferred,
        .active_connection_id_limit = 2,
    });
    defer connection.deinit();
    preferred_cid[0] = 0xff;

    try std.testing.expectEqualSlices(
        u8,
        &expected_cid,
        connection.peerPreferredAddress().?.connection_id,
    );
    try std.testing.expectEqual(@as(usize, 2), connection.peer_connection_ids.count());
    try connection.beginPeerPreferredAddressMigration(
        [_]u8{ 0x6a, 1, 2, 3, 4, 5, 6, 7 },
        .ipv4,
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_cid,
        connection.config.peer_connection_id,
    );
}

test "QUIC failed preferred-address validation restores last validated address and CID" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var local_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer local_endpoint.deinit();
    var original_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_peer.deinit();
    var preferred_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer preferred_peer.deinit();

    const local_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const original_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const preferred_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x61} ** quic.protection.secret_len,
    );
    const preferred_address = quic.PreferredAddress{
        .ipv4_address = preferred_peer.address().ip4.bytes,
        .ipv4_port = preferred_peer.address().ip4.port,
        .connection_id = &preferred_cid,
        .stateless_reset_token = [_]u8{0x62} ** 16,
    };
    var connection = try one_rtt.Connection.init(&local_endpoint, .{
        .peer = original_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &original_cid,
        .peer_preferred_address = preferred_address,
        .active_connection_id_limit = 4,
        .enable_pacing = false,
    });
    defer connection.deinit();
    connection.path_validation.max_challenge_transmissions = 1;

    const challenge = [_]u8{ 0x63, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerPreferredAddressMigration(challenge, .ipv4);
    const failed_epoch = one_rtt.testing.currentPathEpoch(&connection);
    try connection.sendPendingPathChallengeAt(100, 50);
    var challenge_datagram = try preferred_peer.receiveBytes();
    challenge_datagram.deinit(allocator);

    try std.testing.expectEqual(
        @as(usize, 1),
        try connection.checkPathValidationTimeouts(150),
    );
    try std.testing.expectEqual(original_peer.address(), connection.peerAddress());
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqualSlices(
        u8,
        &original_cid,
        connection.config.peer_connection_id,
    );
    try std.testing.expectEqual(@as(usize, 0), connection.pendingPathValidationCount());
    try std.testing.expect(
        one_rtt.testing.currentPathEpoch(&connection) != failed_epoch,
    );

    try connection.send(&.{.{ .ping = {} }});
    var restored_datagram = try original_peer.receiveBytes();
    defer restored_datagram.deinit(allocator);
    var restored_packet = try one_rtt.openReceivedBytes(
        &original_peer,
        restored_datagram.from,
        restored_datagram.bytes,
        keys,
        original_cid.len,
        0,
        4,
    );
    defer restored_packet.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &original_cid,
        restored_packet.packet.destination_connection_id,
    );
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

test "QUIC 1-RTT PATH_RESPONSE returns to probing source address" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var original_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_client_endpoint.deinit();
    var probing_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer probing_endpoint.deinit();

    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const challenge = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const probing_frames = [_]quic.Frame{
        .{ .path_challenge = .{ .data = challenge } },
        .{ .padding = .{ .len = 1166 } },
    };
    try one_rtt.sendFrames(&probing_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &probing_frames,
    });

    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(original_client_endpoint.address(), server.config.peer);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingResponseCount());
    const received_budget = one_rtt.testing.candidatePathBudgetFor(
        &server,
        probing_endpoint.address(),
    ).?;
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        received_budget.received,
    );
    try std.testing.expectEqual(@as(usize, 0), received_budget.sent);

    try server.sendPendingPathResponse();
    var response_datagram = try probing_endpoint.receiveBytes();
    defer response_datagram.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        response_datagram.bytes.len,
    );
    const sent_budget = one_rtt.testing.candidatePathBudgetFor(
        &server,
        probing_endpoint.address(),
    ).?;
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        sent_budget.received,
    );
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        sent_budget.sent,
    );
    var response = try one_rtt.openReceivedBytes(
        &probing_endpoint,
        response_datagram.from,
        response_datagram.bytes,
        keys,
        client_cid.len,
        0,
        8,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(quic.Frame.path_response, std.meta.activeTag(response.frames[0]));
    try std.testing.expectEqualSlices(u8, &challenge, &response.frames[0].path_response.data);
}

test "QUIC client drops PATH_CHALLENGE from unknown server tuple" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    var original_server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_server_endpoint.deinit();
    var probing_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer probing_endpoint.deinit();

    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x41} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = original_server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();

    const challenge = [_]u8{ 4, 3, 2, 1, 5, 6, 7, 8 };
    try one_rtt.sendFrames(
        &probing_endpoint,
        client_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 0,
            .frames = &.{.{ .path_challenge = .{ .data = challenge } }},
        },
    );
    try one_rtt.sendFrames(
        &original_server_endpoint,
        client_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 1,
            .frames = &.{.{ .ping = {} }},
        },
    );
    var received = try client.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), received.packet.packet_number);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.path_validation.pendingResponseCount(),
    );
    try std.testing.expectEqual(@as(u64, 1), client.stats().packets_received);
}

test "QUIC candidate PATH_RESPONSE waits for its own amplification credit" {
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
    var original_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_endpoint.deinit();
    var probing_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer probing_endpoint.deinit();

    const client_cid = [_]u8{ 0x82, 0x83, 0x84, 0x85 };
    const server_cid = [_]u8{ 0x86, 0x87, 0x88, 0x89 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x82} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const challenge = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    try one_rtt.sendFrames(
        &probing_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .frames = &.{.{ .path_challenge = .{ .data = challenge } }},
        },
    );
    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectError(
        error.AntiAmplificationLimited,
        server.sendPendingPathResponse(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        server.path_validation.pendingResponseCount(),
    );
    const budget = one_rtt.testing.candidatePathBudgetFor(
        &server,
        probing_endpoint.address(),
    ).?;
    try std.testing.expect(budget.received < 400);
    try std.testing.expectEqual(@as(usize, 0), budget.sent);
    try std.testing.expectEqual(@as(u64, 0), server.next_packet_number);
    try std.testing.expectError(
        error.Timeout,
        probing_endpoint.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );
}

test "QUIC candidate amplification credit transfers when path becomes active" {
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
    var original_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_endpoint.deinit();
    var candidate_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .{
            .bytes = .{ 127, 0, 0, 2 },
            .port = 0,
        } },
        .{ .max_datagram_size = 4096 },
    );
    defer candidate_endpoint.deinit();

    const client_cid = [_]u8{ 0x92, 0x93, 0x94, 0x95 };
    const server_cid = [_]u8{ 0x96, 0x97, 0x98, 0x99 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x92} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const challenge = [_]u8{ 9, 7, 5, 3, 1, 2, 4, 6 };
    const probe_frames = [_]quic.Frame{
        .{ .path_challenge = .{ .data = challenge } },
        .{ .padding = .{ .len = 1166 } },
    };
    try one_rtt.sendFrames(
        &candidate_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .frames = &probe_frames,
        },
    );
    var probe = try server.receivePacket();
    probe.deinit(allocator);

    try one_rtt.sendFrames(
        &candidate_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 1,
            .frames = &.{.{ .stream = .{
                .stream_id = 0,
                .data = "select",
            } }},
        },
    );
    var selected = try server.receivePacket();
    selected.deinit(allocator);
    try std.testing.expectEqual(
        candidate_endpoint.address(),
        server.peerAddress(),
    );
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expect(
        one_rtt.testing.candidatePathBudgetFor(
            &server,
            candidate_endpoint.address(),
        ) == null,
    );
    try std.testing.expect(
        server.antiAmplificationLimitRemaining().? >=
            quic.pmtu.min_udp_payload_size,
    );
    try server.sendPendingPathChallenge();
    var sent = try candidate_endpoint.receiveBytes();
    defer sent.deinit(allocator);
    try std.testing.expectEqual(
        quic.pmtu.min_udp_payload_size,
        sent.bytes.len,
    );
}

test "QUIC late PATH_RESPONSE validates only its challenge path epoch" {
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
    var peer_b = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0 } },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_b.deinit();
    var peer_c = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 0 } },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_c.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa3} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "epoch-server",
        .peer_connection_id = "epoch-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    server.recordPeerAddressBytesReceived(400);

    const challenge_b = [_]u8{ 0xb1, 0, 0, 0, 0, 0, 0, 1 };
    try server.beginPeerMigration(peer_b.address(), challenge_b);
    server.recordPeerAddressBytesReceived(400);
    try server.sendPendingPathChallengeAt(100, 50);
    const epoch_b = one_rtt.testing.currentPathEpoch(&server);

    const challenge_c = [_]u8{ 0xc1, 0, 0, 0, 0, 0, 0, 2 };
    try server.beginPeerMigration(peer_c.address(), challenge_c);
    server.recordPeerAddressBytesReceived(400);
    try server.sendPendingPathChallengeAt(200, 50);
    const epoch_c = one_rtt.testing.currentPathEpoch(&server);
    try std.testing.expect(epoch_c != epoch_b);
    try std.testing.expectEqual(@as(usize, 2), server.path_validation.outstandingChallengeCount());

    try one_rtt.testing.applyReceivedFrames(
        &server,
        10,
        &.{.{ .path_response = .{ .data = challenge_b } }},
        300,
        .not_ect,
    );
    try std.testing.expectEqual(peer_c.address(), server.peerAddress());
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expect(server.antiAmplificationLimitRemaining() != null);
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.outstandingChallengeCount());

    // RFC 9000 permits a PATH_RESPONSE to arrive on a different path; the
    // challenge's recorded epoch, not the response source tuple, identifies
    // the path that becomes validated.
    const response_payload = try one_rtt.encodeFrames(allocator, &.{.{
        .path_response = .{ .data = challenge_c },
    }});
    defer allocator.free(response_payload);
    const response_datagram = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = "epoch-server",
            .packet_number = 11,
            .packet_number_len = 4,
            .payload = response_payload,
        },
    );
    defer allocator.free(response_datagram);
    var response = try one_rtt.testing.processReceivedBytesAt(
        &server,
        peer_b.address(),
        response_datagram,
        .not_ect,
        400,
    );
    response.deinit(allocator);
    try std.testing.expectEqual(peer_c.address(), server.peerAddress());
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.outstandingChallengeCount());
}

test "QUIC superseded path timeout cannot retry on current path" {
    const allocator = std.testing.allocator;
    var state = quic.path_validation.State.init(allocator);
    defer state.deinit();

    const challenge_b = [_]u8{ 0xb2, 0, 0, 0, 0, 0, 0, 1 };
    const challenge_c = [_]u8{ 0xc2, 0, 0, 0, 0, 0, 0, 2 };
    _ = try state.queueChallengeForPath(challenge_b, 2);
    var frames: [1]quic.Frame = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        try state.prepareChallengeFrames(&frames),
    );
    state.commitChallengeFrames(1, 100, 50, 2);

    _ = try state.queueChallengeForPath(challenge_c, 3);
    try std.testing.expectEqual(
        @as(usize, 1),
        try state.prepareChallengeFrames(&frames),
    );
    state.commitChallengeFrames(1, 200, 50, 3);

    const timeout = try state.checkTimeoutsForPathEpoch(150, 3);
    try std.testing.expectEqual(@as(usize, 1), timeout.expired);
    try std.testing.expectEqual(@as(usize, 0), timeout.failed);
    try std.testing.expect(!timeout.failed_current_path);
    try std.testing.expectEqual(@as(usize, 0), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), state.outstandingChallengeCount());
    try std.testing.expect(!state.receiveResponseValidated(challenge_b));
    try std.testing.expect(state.receiveResponseValidated(challenge_c));
}

test "QUIC one PATH_RESPONSE retires redundant current-path challenges" {
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
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x65} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "multi-local",
        .peer_connection_id = "multi-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    const first = [_]u8{ 0x66, 1, 2, 3, 4, 5, 6, 7 };
    const second = [_]u8{ 0x67, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerMigration(peer.address(), first);
    try connection.queuePathChallenge(second);
    try std.testing.expectEqual(
        @as(usize, 2),
        try connection.sendPendingPathChallengesAt(100, 50),
    );
    var datagram = try peer.receiveBytes();
    datagram.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.path_validation.outstandingChallengeCount(),
    );

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .path_response = .{ .data = first } }},
        125,
        .not_ect,
    );
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), connection.pendingPathValidationCount());
    try std.testing.expectEqual(@as(?u64, null), connection.pathValidationDeadline());
    try std.testing.expectEqual(
        @as(usize, 0),
        try connection.checkPathValidationTimeouts(150),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.failedPathValidationCount());
}

test "QUIC failed consecutive migration restores most recently validated path" {
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
    var peer_b = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0 } },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_b.deinit();
    var peer_c = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 0 } },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_c.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x64} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "fallback-local",
        .peer_connection_id = "fallback-peer",
        .enable_pacing = false,
        .enable_spin_bit = true,
    });
    defer connection.deinit();
    connection.path_validation.max_challenge_transmissions = 1;
    connection.spin_bit_value = true;
    connection.spin_largest_received_packet_number = 9;

    const challenge_b = [_]u8{ 0xb3, 0, 0, 0, 0, 0, 0, 1 };
    try connection.beginPeerMigration(peer_b.address(), challenge_b);
    try std.testing.expect(!connection.nextSpinBit());
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.spinLargestReceivedPacketNumber(&connection),
    );
    try connection.sendPendingPathChallengeAt(100, 50);
    var datagram_b = try peer_b.receiveBytes();
    datagram_b.deinit(allocator);
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .path_response = .{ .data = challenge_b } }},
        125,
        .not_ect,
    );
    try std.testing.expect(connection.peerAddressValidated());
    connection.spin_bit_value = true;
    connection.spin_largest_received_packet_number = 10;

    const challenge_c = [_]u8{ 0xc3, 0, 0, 0, 0, 0, 0, 2 };
    try connection.beginPeerMigration(peer_c.address(), challenge_c);
    try std.testing.expect(!connection.nextSpinBit());
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.spinLargestReceivedPacketNumber(&connection),
    );
    try connection.sendPendingPathChallengeAt(200, 50);
    var datagram_c = try peer_c.receiveBytes();
    datagram_c.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 1),
        try connection.checkPathValidationTimeouts(250),
    );
    try std.testing.expectEqual(peer_b.address(), connection.peerAddress());
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expect(connection.nextSpinBit());
    try std.testing.expectEqual(
        @as(?u64, 10),
        one_rtt.testing.spinLargestReceivedPacketNumber(&connection),
    );
}

test "QUIC candidate path budget is bounded without evicting referenced tuples" {
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
    var original_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_endpoint.deinit();

    const client_cid = [_]u8{ 0xa2, 0xa3, 0xa4, 0xa5 };
    const server_cid = [_]u8{ 0xa6, 0xa7, 0xa8, 0xa9 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    var packet_number: u64 = 0;
    for (0..quic.connection_id.max_pool_size) |index| {
        var peer = original_endpoint.address();
        peer.ip4.bytes = .{ 127, 0, 1, @intCast(index + 1) };
        const payload = try one_rtt.encodeFrames(allocator, &.{.{
            .path_challenge = .{ .data = .{
                0xb0, 0, 0, 0, 0, 0, 0, @intCast(index),
            } },
        }});
        defer allocator.free(payload);
        const datagram = try quic.protection.sealShortPacket(
            allocator,
            keys,
            .{
                .destination_connection_id = &server_cid,
                .packet_number = packet_number,
                .packet_number_len = 4,
                .payload = payload,
            },
        );
        defer allocator.free(datagram);
        var received = try one_rtt.testing.processReceivedBytesAt(
            &server,
            peer,
            datagram,
            .not_ect,
            packet_number + 1,
        );
        received.deinit(allocator);
        packet_number += 1;
    }
    try std.testing.expectEqual(
        quic.connection_id.max_pool_size,
        one_rtt.testing.candidatePathBudgetCount(&server),
    );

    var ninth = original_endpoint.address();
    ninth.ip4.bytes = .{ 127, 0, 2, 1 };
    const ninth_payload = try one_rtt.encodeFrames(allocator, &.{.{
        .path_challenge = .{ .data = [_]u8{0xbf} ** 8 },
    }});
    defer allocator.free(ninth_payload);
    const ninth_datagram = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = packet_number,
            .packet_number_len = 4,
            .payload = ninth_payload,
        },
    );
    defer allocator.free(ninth_datagram);
    try std.testing.expectError(
        error.PathValidationLimit,
        one_rtt.testing.processReceivedBytesAt(
            &server,
            ninth,
            ninth_datagram,
            .not_ect,
            packet_number + 1,
        ),
    );
    try std.testing.expectEqual(
        quic.connection_id.max_pool_size,
        one_rtt.testing.candidatePathBudgetCount(&server),
    );
    try std.testing.expect(
        one_rtt.testing.candidatePathBudgetFor(&server, ninth) == null,
    );
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
    try std.testing.expectEqual(@as(usize, 3), challenge_packet.frames.len);
    try std.testing.expectEqualSlices(u8, &first, &challenge_packet.frames[0].path_challenge.data);
    try std.testing.expectEqualSlices(u8, &second, &challenge_packet.frames[1].path_challenge.data);
    try std.testing.expectEqual(@as(usize, 2), server.path_validation.pendingResponseCount());
    try std.testing.expectEqual(@as(usize, 2), server.path_response_targets.items.len);

    try std.testing.expectEqual(@as(usize, 2), try server.sendPendingPathResponses());
    try std.testing.expectEqual(@as(usize, 0), server.path_response_targets.items.len);
    var response_packet = try client.receivePacket();
    defer response_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), response_packet.frames.len);
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.outstandingChallengeCount());
}

test "QUIC 1-RTT bounds pending PATH_RESPONSE state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();

    const local_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const peer_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x89} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
        .max_pending_path_responses = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const a = [_]u8{ 'a', 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 'b', 0, 0, 0, 0, 0, 0, 2 };
    const c = [_]u8{ 'c', 0, 0, 0, 0, 0, 0, 3 };
    const d = [_]u8{ 'd', 0, 0, 0, 0, 0, 0, 4 };
    const frames = [_]quic.Frame{
        .{ .path_challenge = .{ .data = a } },
        .{ .path_challenge = .{ .data = b } },
        .{ .path_challenge = .{ .data = c } },
        .{ .path_challenge = .{ .data = d } },
    };
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &frames,
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.path_validation.pendingResponseCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.path_response_targets.items.len,
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        connection.stats().path_challenges_dropped,
    );
    const response_capacity =
        one_rtt.testing.pendingPathResponseCapacity(&connection);
    const target_capacity =
        one_rtt.testing.pathResponseTargetCapacity(&connection);

    var packet_number: u64 = 1;
    for (0..32) |index| {
        const challenge = [_]u8{
            0xee,
            @intCast(index),
            1,
            2,
            3,
            4,
            5,
            6,
        };
        try one_rtt.testing.applyReceivedFrames(
            &connection,
            packet_number,
            &.{.{ .path_challenge = .{ .data = challenge } }},
            null,
            .not_ect,
        );
        packet_number += 1;
    }
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.path_validation.pendingResponseCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        one_rtt.testing.pendingPathResponseTargetCount(&connection),
    );
    try std.testing.expectEqual(
        response_capacity,
        one_rtt.testing.pendingPathResponseCapacity(&connection),
    );
    try std.testing.expectEqual(
        target_capacity,
        one_rtt.testing.pathResponseTargetCapacity(&connection),
    );
    try std.testing.expectEqual(
        @as(u64, 34),
        connection.stats().path_challenges_dropped,
    );

    for (0..32) |index| {
        one_rtt.testing.discardPendingPathResponses(&connection, 1);
        const challenge = [_]u8{
            0xef,
            @intCast(index),
            1,
            2,
            3,
            4,
            5,
            6,
        };
        try one_rtt.testing.applyReceivedFrames(
            &connection,
            packet_number,
            &.{.{ .path_challenge = .{ .data = challenge } }},
            null,
            .not_ect,
        );
        packet_number += 1;
        try std.testing.expectEqual(
            @as(usize, 2),
            connection.path_validation.pendingResponseCount(),
        );
    }
    try std.testing.expectEqual(
        response_capacity,
        one_rtt.testing.pendingPathResponseCapacity(&connection),
    );
    try std.testing.expectEqual(
        target_capacity,
        one_rtt.testing.pathResponseTargetCapacity(&connection),
    );
}

test "QUIC dispatcher schedules PATH_RESPONSE without receive-side wait" {
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
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const client_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer server.deinit();
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 94;
    try dispatcher.registerConnection(handle, &server);

    var fixed_io = FixedClockIo{
        .delegate = server_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = server_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    server_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer server_endpoint.io = fixed_io.delegate;
    try server.sendAt(
        &.{.{ .padding = .{ .len = 1160 } }},
        @intCast(fixed_io.now_ns),
    );
    var fill = try client.receivePacket();
    defer fill.deinit(allocator);

    const challenge = [_]u8{ 13, 21, 34, 55, 89, 1, 2, 3 };
    try client.queuePathChallenge(challenge);
    var challenge_frame: [1]quic.Frame = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        try client.path_validation.prepareChallengeFrames(&challenge_frame),
    );
    client.path_validation.commitChallengeFrames(
        1,
        @intCast(fixed_io.now_ns),
        1_000_000,
        0,
    );
    try one_rtt.testing.applyReceivedFrames(
        &server,
        0,
        &.{.{ .path_challenge = .{ .data = challenge } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    try dispatcher.refreshConnectionTimer(handle);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        @as(usize, 1),
        server.path_validation.pendingResponseCount(),
    );
    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, timer.connection_id);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_response,
        timer.timer.kind,
    );

    const first = (try dispatcher.serviceNextTimerAt(
        timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_response,
        first.timer.kind,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        server.path_validation.pendingResponseCount(),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    const retry = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.path_response,
        retry.timer.kind,
    );
    fixed_io.now_ns = @intCast(retry.timer.deadline_ns);
    _ = (try dispatcher.serviceNextTimerAt(retry.timer.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(usize, 0),
        server.path_validation.pendingResponseCount(),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    var response = try client.receivePacket();
    defer response.deinit(allocator);
    var found = false;
    for (response.frames) |frame| switch (frame) {
        .path_response => |path_response| {
            try std.testing.expectEqualSlices(
                u8,
                &challenge,
                &path_response.data,
            );
            found = true;
        },
        else => {},
    };
    try std.testing.expect(found);
}

test "QUIC queued PATH_RESPONSE retains exact source across migration" {
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
    var original_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer original_peer.deinit();
    var migrated_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer migrated_peer.deinit();

    const server_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const peer_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x35} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = original_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const peer_challenge = [_]u8{ 0x51, 1, 2, 3, 4, 5, 6, 7 };
    try one_rtt.sendFrames(&original_peer, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .path_challenge = .{ .data = peer_challenge } }},
    });
    var received = try server.receivePacket();
    received.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 1),
        server.path_validation.pendingResponseCount(),
    );

    try server.beginPeerMigration(
        migrated_peer.address(),
        [_]u8{ 0x52, 1, 2, 3, 4, 5, 6, 7 },
    );
    try server.sendPendingPathResponse();
    var response_datagram = try original_peer.receiveBytes();
    defer response_datagram.deinit(allocator);
    var response = try one_rtt.openReceivedBytes(
        &original_peer,
        response_datagram.from,
        response_datagram.bytes,
        keys,
        peer_cid.len,
        0,
        4,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &peer_challenge,
        &response.frames[0].path_response.data,
    );
}

test "QUIC 1-RTT PATH_RESPONSE targets use cursor discard" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd4} ** quic.protection.secret_len);

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

    const challenges = [_][8]u8{
        .{ 1, 0, 0, 0, 0, 0, 0, 1 },
        .{ 2, 0, 0, 0, 0, 0, 0, 2 },
        .{ 3, 0, 0, 0, 0, 0, 0, 3 },
        .{ 4, 0, 0, 0, 0, 0, 0, 4 },
    };
    for (challenges) |challenge| try client.queuePathChallenge(challenge);
    try std.testing.expectEqual(@as(usize, 4), try client.sendPendingPathChallengesAt(100, 50));

    var challenge_packet = try server.receivePacket();
    defer challenge_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), server.path_validation.pendingResponseCount());
    try std.testing.expectEqual(@as(usize, 4), server.path_response_targets.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.path_response_target_head);

    try server.sendPendingPathResponse();
    try std.testing.expectEqual(@as(usize, 3), server.path_validation.pendingResponseCount());
    try std.testing.expectEqual(@as(usize, 4), server.path_response_targets.items.len);
    try std.testing.expectEqual(@as(usize, 1), server.path_response_target_head);

    try std.testing.expectEqual(@as(usize, 3), try server.sendPendingPathResponses());
    try std.testing.expectEqual(@as(usize, 0), server.path_response_targets.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.path_response_target_head);
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
        .enable_spin_bit = true,
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
    const spin_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 7,
            .packet_number_len = 4,
            .spin_bit = false,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    defer allocator.free(spin_packet);
    var spin_received = try one_rtt.testing.processReceivedBytesAt(
        &client,
        server_endpoint.address(),
        spin_packet,
        .not_ect,
        1,
    );
    spin_received.deinit(allocator);
    try std.testing.expect(client.nextSpinBit());
    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-new-cid", client.config.peer_connection_id);
    try std.testing.expect(!client.nextSpinBit());
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
    try std.testing.expect((routed.datagram.bytes[0] & 0x20) == 0);
    var retire_packet = (try server.receiveRoutedDatagram(routed)).?;
    defer retire_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), server.local_connection_ids.count());
}

test "QUIC peer CID selection survives moving a connection value" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );
    var original = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "move-local",
        .peer_connection_id = "move-peer",
        .enable_pacing = false,
    });
    try one_rtt.testing.applyReceivedFrames(
        &original,
        0,
        &.{.{ .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 1,
            .connection_id = "moved-replacement",
            .stateless_reset_token = [_]u8{0xdb} ** 16,
        } }},
        null,
        .not_ect,
    );
    var moved = original;
    // Reuse the source object's inline CID pool after the move. The selected
    // destination must not be borrowing storage from that old address.
    original.peer_connection_ids = .{};
    original = undefined;
    defer moved.deinit();
    try std.testing.expectEqualStrings(
        "moved-replacement",
        moved.config.peer_connection_id,
    );

    try moved.send(&.{.{ .ping = {} }});
    var datagram = try peer_endpoint.receiveBytes();
    defer datagram.deinit(allocator);
    var opened = try one_rtt.openReceivedBytes(
        &peer_endpoint,
        datagram.from,
        datagram.bytes,
        keys,
        "moved-replacement".len,
        0,
        4,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqualStrings(
        "moved-replacement",
        opened.packet.destination_connection_id,
    );
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
    var retire = (try server.receiveRoutedDatagram(routed)).?;
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
    try std.testing.expectError(
        error.InvalidResetToken,
        server.sendNewConnectionId(
            "wrong-token-cid",
            [_]u8{0xa5} ** quic.stateless_reset.token_len,
        ),
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
        .enable_spin_bit = true,
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

    const spin_payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .ping = {} }},
    );
    defer allocator.free(spin_payload);
    const spin_packet = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 7,
        .packet_number_len = 4,
        .spin_bit = false,
        .payload = spin_payload,
    });
    defer allocator.free(spin_packet);
    var spin_received = try one_rtt.testing.processReceivedBytesAt(
        &client,
        server_endpoint.address(),
        spin_packet,
        .not_ect,
        1,
    );
    spin_received.deinit(allocator);
    try std.testing.expect(client.nextSpinBit());

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
    try std.testing.expectEqualStrings("server-cid-two", client.config.peer_connection_id);
    try std.testing.expect(!client.nextSpinBit());

    try client.send(&.{.{ .ping = {} }});
    var replacement_datagram = try server_endpoint.receiveBytes();
    defer replacement_datagram.deinit(allocator);
    var replacement_packet = try one_rtt.openReceivedBytes(
        &server_endpoint,
        replacement_datagram.from,
        replacement_datagram.bytes,
        keys,
        "server-cid-two".len,
        0,
        4,
    );
    defer replacement_packet.deinit(allocator);
    try std.testing.expect(!replacement_packet.packet.spin_bit);
    try std.testing.expectEqualStrings(
        "server-cid-two",
        replacement_packet.packet.destination_connection_id,
    );

    try std.testing.expectEqual(@as(usize, 1), try client.sendPendingRetireConnectionIds());
    try std.testing.expectEqual(@as(usize, 0), client.pendingRetireConnectionIdCount());

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-cid-two", .{ .connection_index = 0, .sequence_number = 2 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire_packet = (try server.receiveRoutedDatagram(routed)).?;
    defer retire_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), server.local_connection_ids.count());
}

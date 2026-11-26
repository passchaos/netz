const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;

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

test "QUIC 1-RTT validates configured stream-count limits" {
    const defaults: one_rtt.ConnectionConfig = .{
        .peer = undefined,
        .receive_keys = undefined,
        .send_keys = undefined,
        .local_connection_id = &.{},
        .peer_connection_id = &.{},
    };
    try std.testing.expectEqual(@as(u64, 100), defaults.initial_send_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 100), defaults.initial_send_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 100), defaults.initial_receive_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 100), defaults.initial_receive_max_streams_uni);

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    try std.testing.expectError(
        error.InvalidTransportParameter,
        one_rtt.Connection.init(&endpoint, .{
            .peer = endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "limit-local",
            .peer_connection_id = "limit-peer",
            .initial_receive_max_streams_bidi = quic.max_stream_count + 1,
        }),
    );
}

test "QUIC stable connection IDs survive moves and path migration" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe9} ** quic.protection.secret_len,
    );
    var first = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "stable-local-a",
        .peer_connection_id = "stable-peer-a",
    });
    const first_id = first.stableId();
    try std.testing.expect(first_id != 0);

    // WebTransport and endpoint promotion move established connection values.
    // The identifier belongs to the logical connection, not its address.
    var moved = first;
    first = undefined;
    defer moved.deinit();
    try std.testing.expectEqual(first_id, moved.stableId());
    try moved.beginPeerMigration(
        .{ .ip4 = .loopback(9443) },
        [_]u8{0x91} ** 8,
    );
    try std.testing.expectEqual(first_id, moved.stableId());

    var second = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "stable-local-b",
        .peer_connection_id = "stable-peer-b",
    });
    defer second.deinit();
    try std.testing.expect(second.stableId() != 0);
    try std.testing.expect(first_id != second.stableId());
}

test "QUIC 1-RTT installs maximum pacing rate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "paced-local",
        .peer_connection_id = "paced-peer",
        .max_pacing_rate_bytes_per_second = 10_000,
    });
    defer connection.deinit();

    try std.testing.expectEqual(
        @as(?u64, 10_000),
        connection.maxPacingRateBytesPerSecond(),
    );
    try std.testing.expectEqual(
        @as(?u64, 10_000),
        connection.pacingRateBytesPerSecond(),
    );
    try std.testing.expectEqual(
        @as(?u64, 10_000),
        connection.stats().pacing_rate_bytes_per_second,
    );
    try std.testing.expectEqual(
        @as(?u64, 10_000),
        connection.stats().max_pacing_rate_bytes_per_second,
    );
    one_rtt.testing.exhaustPacingAt(&connection, 0);
    try std.testing.expectEqual(
        @as(usize, 10),
        connection.pacingBudgetAt(1_000_000),
    );

    connection.pacing_blocked_until_ns = 9_000_000;
    connection.setMaxPacingRateBytesPerSecondAt(null, 1_000_000);
    try std.testing.expectEqual(
        @as(?u64, null),
        connection.maxPacingRateBytesPerSecond(),
    );
    try std.testing.expect(
        connection.pacingRateBytesPerSecond().? > 10_000,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        connection.config.max_pacing_rate_bytes_per_second,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        connection.pendingPacingDeadline(),
    );
    try std.testing.expect(connection.pacingBudgetAt(2_000_000) > 10);

    // An idempotent update leaves a currently published wake-up intact.
    connection.pacing_blocked_until_ns = 8_000_000;
    connection.setMaxPacingRateBytesPerSecondAt(null, 2_000_000);
    try std.testing.expectEqual(
        @as(?u64, 8_000_000),
        connection.pendingPacingDeadline(),
    );
    connection.setMaxPacingRateBytesPerSecond(20_000);
    try std.testing.expectEqual(
        @as(?u64, 20_000),
        connection.maxPacingRateBytesPerSecond(),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        connection.pendingPacingDeadline(),
    );
}

test "QUIC 1-RTT stateless reset enters draining" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xe2} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-cid",
        .peer_connection_id = "peer-cid",
    });
    defer connection.deinit();

    try connection.peer_connection_ids.addWithLimit(1, "reset-cid", [_]u8{0xaa} ** 16, 4);
    try connection.peer_connection_ids.markInUse(1);
    var reset_datagram: std.ArrayList(u8) = .empty;
    defer reset_datagram.deinit(allocator);
    try quic.stateless_reset.encode(&reset_datagram, allocator, &.{ 0x40, 1, 2, 3, 4 }, [_]u8{0xaa} ** 16);

    try std.testing.expectEqual(@as(?u64, 1), connection.processStatelessResetDatagram(reset_datagram.items, 10, 25));
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(
        @as(?one_rtt.PeerCloseInfo, null),
        connection.peerCloseInfo(),
    );
    try std.testing.expectEqual(@as(?u64, 85), connection.closeExpiryDeadlineMillis());
    try std.testing.expectError(error.ConnectionClosed, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
    try std.testing.expectEqual(@as(?u64, null), connection.processStatelessResetDatagram(&.{ 0x40, 1, 2 }, 11, 25));
}

test "QUIC routed receive detects stateless reset before decrypt" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-cid",
        .peer_connection_id = "peer-cid",
    });
    defer connection.deinit();

    const token = [_]u8{0x5d} ** 16;
    try connection.peer_connection_ids.addWithLimit(2, "reset-cid", token, 4);
    try connection.peer_connection_ids.markInUse(2);
    var reset_datagram: std.ArrayList(u8) = .empty;
    defer reset_datagram.deinit(allocator);
    try quic.stateless_reset.encode(&reset_datagram, allocator, &.{ 0x40, 9, 8, 7, 6 }, token);

    const raw = quic.runtime.OwnedBytes{
        .from = endpoint.address(),
        .bytes = try allocator.dupe(u8, reset_datagram.items),
    };
    var routed = quic.runtime.RoutedBytes{
        .datagram = raw,
        .route = .{ .connection_index = 0, .sequence_number = 2 },
        .destination_connection_id = "reset-cid",
    };
    defer routed.deinit(allocator);

    const result = try connection.receiveRoutedDatagramOrStatelessReset(routed, 20, 30);
    try std.testing.expectEqual(@as(u64, 2), result.stateless_reset);
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(@as(?u64, 110), connection.closeExpiryDeadlineMillis());
}

test "QUIC routed receive drops after stateless reset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-cid",
        .peer_connection_id = "peer-cid",
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = "done",
    } }}, null, .not_ect);
    try std.testing.expect(connection.draining());

    const raw = quic.runtime.OwnedBytes{
        .from = endpoint.address(),
        .bytes = try allocator.dupe(u8, &.{ 0x40, 1, 2, 3, 4, 5 }),
    };
    var routed = quic.runtime.RoutedBytes{
        .datagram = raw,
        .route = .{ .connection_index = 0 },
        .destination_connection_id = "local-cid",
    };
    defer routed.deinit(allocator);

    const result = try connection.receiveRoutedDatagramOrStatelessReset(routed, 20, 30);
    try std.testing.expect(result == .dropped_after_close);
}

test "QUIC 1-RTT rejects invalid NEW_CONNECTION_ID lifecycle updates" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe2} ** quic.protection.secret_len);
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .active_connection_id_limit = 2,
    });
    defer client.deinit();

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 0,
            .connection_id = "cid-1",
            .stateless_reset_token = [_]u8{0x11} ** 16,
        } }},
    });
    var first = try client.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 0,
            .connection_id = "cid-1",
            .stateless_reset_token = [_]u8{0x22} ** 16,
        } }},
    });
    try std.testing.expectError(error.DuplicateResetToken, client.receivePacket());
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), client.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.new_connection_id)), client.close_info.?.frame_type);
    try std.testing.expectEqualStrings("reset token reuse", client.close_info.?.reason_phrase);

    var client2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client2_endpoint.deinit();
    const client2_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    var client2 = try one_rtt.Connection.init(&client2_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client2_cid,
        .peer_connection_id = &server_cid,
        .active_connection_id_limit = 2,
    });
    defer client2.deinit();
    try client2.peer_connection_ids.add(1, "cid-1", [_]u8{0x11} ** 16);

    try one_rtt.sendFrames(&server_endpoint, client2_endpoint.address(), keys, .{
        .destination_connection_id = &client2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 0,
            .connection_id = "cid-2",
            .stateless_reset_token = [_]u8{0x33} ** 16,
        } }},
    });
    try std.testing.expectError(error.ActiveConnectionIdLimit, client2.receivePacket());
    try std.testing.expectEqual(@as(usize, 2), client2.peer_connection_ids.count());
    try std.testing.expect(client2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.connection_id_limit_error), client2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.new_connection_id)), client2.close_info.?.frame_type);
    try std.testing.expectEqualStrings("connection id limit", client2.close_info.?.reason_phrase);
}

test "QUIC 1-RTT handles server-only NEW_TOKEN and HANDSHAKE_DONE roles" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_cid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa4} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa5} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
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

    try std.testing.expectError(error.InvalidFrame, client.sendHandshakeDone());
    try std.testing.expectError(error.InvalidFrame, client.sendNewToken("client-token"));
    try std.testing.expectError(error.InvalidFrame, server.sendNewToken(""));

    try server.sendNewToken("future-token");
    var token_packet = try client.receivePacket();
    defer token_packet.deinit(allocator);
    try std.testing.expectEqualStrings("future-token", client.latestNewToken().?);

    const secret: quic.address_validation_token.Secret = [_]u8{0xc1} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0xc2} ** quic.address_validation_token.nonce_len;
    try server.sendAddressValidationToken(secret, 1_000, 5_000, "client-path", nonce);
    var address_token_packet = try client.receivePacket();
    defer address_token_packet.deinit(allocator);
    const issued = client.latestNewToken() orelse return error.TestUnexpectedResult;
    const validation = try quic.address_validation_token.validate(secret, .new_token, .version_1, 1_100, "client-path", issued);
    try std.testing.expectEqual(quic.address_validation_token.Kind.new_token, validation.kind);

    try server.sendHandshakeDone();
    var done_packet = try client.receivePacket();
    defer done_packet.deinit(allocator);
    try std.testing.expect(client.handshakeConfirmed());

    // RFC 9000 section 19.7 assigns an endpoint-specific error: a client
    // receiving an empty token closes with FRAME_ENCODING_ERROR, while a
    // server rejects every NEW_TOKEN below with PROTOCOL_VIOLATION.
    const empty_token_packet = try quic.protection.sealShortPacket(
        allocator,
        server_keys,
        .{
            .destination_connection_id = &client_cid,
            .packet_number = 3,
            .payload = &.{
                @intFromEnum(quic.FrameType.new_token),
                0,
            },
        },
    );
    defer allocator.free(empty_token_packet);
    try server_endpoint.sendBytes(
        client_endpoint.address(),
        empty_token_packet,
    );
    try std.testing.expectError(error.InvalidFrame, client.receivePacket());
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(
        @intFromEnum(quic.TransportErrorCode.frame_encoding_error),
        client.close_info.?.error_code,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.new_token)),
        client.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings(
        "empty new token",
        client.close_info.?.reason_phrase,
    );
    try std.testing.expectEqualStrings(
        issued,
        client.latestNewToken().?,
    );
    // Keep the server connection below available for its independent role
    // violation checks; consume the client's emitted close at the socket.
    var client_close_datagram = try server_endpoint.receiveBytes();
    defer client_close_datagram.deinit(allocator);

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .handshake_done = {} }},
    });
    try std.testing.expectError(error.InvalidFrame, server.receivePacket());
    // Servers confirm the handshake when TLS completes, independently of the
    // peer's illegal HANDSHAKE_DONE frame.
    try std.testing.expect(server.handshakeConfirmed());
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.handshake_done)), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("handshake done", server.close_info.?.reason_phrase);

    var server2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server2_endpoint.deinit();
    const server2_cid = [_]u8{ 0x65, 0x66, 0x77, 0x89 };
    var server2 = try one_rtt.Connection.init(&server2_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server2_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server2.deinit();

    try one_rtt.sendFrames(&client_endpoint, server2_endpoint.address(), client_keys, .{
        .destination_connection_id = &server2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_token = .{ .token = "illegal" } }},
    });
    try std.testing.expectError(error.InvalidFrame, server2.receivePacket());
    try std.testing.expectEqual(@as(?[]const u8, null), server2.latestNewToken());
    try std.testing.expect(server2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.new_token)), server2.close_info.?.frame_type);
    try std.testing.expectEqualStrings("new token", server2.close_info.?.reason_phrase);

    var server3_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server3_endpoint.deinit();
    const server3_cid = [_]u8{ 0x75, 0x76, 0x87, 0x99 };
    var server3 = try one_rtt.Connection.init(&server3_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server3_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server3.deinit();
    const server_empty_token_packet = try quic.protection.sealShortPacket(
        allocator,
        client_keys,
        .{
            .destination_connection_id = &server3_cid,
            .packet_number = 0,
            .payload = &.{
                @intFromEnum(quic.FrameType.new_token),
                0,
            },
        },
    );
    defer allocator.free(server_empty_token_packet);
    try client_endpoint.sendBytes(
        server3_endpoint.address(),
        server_empty_token_packet,
    );
    try std.testing.expectError(error.InvalidFrame, server3.receivePacket());
    try std.testing.expect(server3.closing());
    try std.testing.expectEqual(
        @intFromEnum(quic.TransportErrorCode.protocol_violation),
        server3.close_info.?.error_code,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.new_token)),
        server3.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings(
        "new token",
        server3.close_info.?.reason_phrase,
    );
}

test "QUIC 1-RTT generic send validates role and extension-gated frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const local_cid = [_]u8{ 0x72, 0x6f, 0x6c, 0x65 };
    const peer_cid = [_]u8{ 0x70, 0x65, 0x65, 0x72 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x72} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();

    try std.testing.expectError(error.MissingFrame, client.send(&.{}));
    try std.testing.expectError(error.InvalidFrame, client.send(&.{.{ .handshake_done = {} }}));
    try std.testing.expectError(error.InvalidFrame, client.send(&.{.{ .new_token = .{ .token = "client-token" } }}));
    try std.testing.expectError(error.DatagramsNotEnabled, client.send(&.{.{ .datagram = .{ .data = "disabled", .length_present = true } }}));
    try std.testing.expectError(error.AckFrequencyDisabled, client.send(&.{.{ .immediate_ack = {} }}));
    try std.testing.expectError(error.AckFrequencyDisabled, client.send(&.{.{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 2,
        .request_max_ack_delay = 10,
        .reordering_threshold = 2,
    } }}));

    var limited = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .peer_max_datagram_frame_size = 8,
    });
    defer limited.deinit();
    try std.testing.expectError(error.DatagramTooLarge, limited.send(&.{.{ .datagram = .{ .data = "1234567", .length_present = true } }}));
    try limited.send(&.{.{ .datagram = .{ .data = "1234567", .length_present = false } }});
    var datagram_packet = try endpoint.receiveBytes();
    defer datagram_packet.deinit(allocator);

    var server = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    try std.testing.expectError(error.InvalidFrame, server.send(&.{.{ .new_token = .{ .token = "" } }}));
}

test "QUIC 1-RTT connection closes with transport and application close frames" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xf1} ** quic.protection.secret_len);

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

    try client.closeTransport(0x100, @intFromEnum(quic.FrameType.stream), "done");
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].ack_eliciting);
    try std.testing.expectEqual(@as(usize, 0), client.recovery.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
    var close_packet = try server.receivePacket();
    defer close_packet.deinit(allocator);
    try std.testing.expect(server.draining());
    try std.testing.expect(!server.closed());
    try std.testing.expectEqual(@as(u64, 0x100), server.close_info.?.error_code);
    try std.testing.expectEqualStrings("done", server.close_info.?.reason_phrase);
    try std.testing.expectError(error.ConnectionClosed, server.send(&[_]quic.Frame{.{ .ping = {} }}));

    var client2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client2_endpoint.deinit();
    var server2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server2_endpoint.deinit();
    const c2 = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const s2 = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    var client2 = try one_rtt.Connection.init(&client2_endpoint, .{
        .peer = server2_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &c2,
        .peer_connection_id = &s2,
    });
    defer client2.deinit();
    var server2 = try one_rtt.Connection.init(&server2_endpoint, .{
        .peer = client2_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &s2,
        .peer_connection_id = &c2,
        .local_endpoint = .server,
    });
    defer server2.deinit();

    try server2.closeApplication(42, "app done");
    try std.testing.expectEqual(@as(usize, 1), server2.sent.packets.items.len);
    try std.testing.expect(!server2.sent.packets.items[0].ack_eliciting);
    try std.testing.expectEqual(@as(usize, 0), server2.recovery.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), server2.congestion.bytes_in_flight);
    var app_close = try client2.receivePacket();
    defer app_close.deinit(allocator);
    try std.testing.expect(client2.draining());
    try std.testing.expect(!client2.closed());
    try std.testing.expect(client2.close_info.?.application);
    try std.testing.expectEqual(@as(u64, 42), client2.close_info.?.error_code);
    try std.testing.expectEqualStrings("app done", client2.close_info.?.reason_phrase);
    switch (client2.peerCloseInfo().?) {
        .application => |close| {
            try std.testing.expectEqual(@as(u64, 42), close.error_code);
            try std.testing.expectEqualStrings(
                "app done",
                close.reason_phrase,
            );
        },
        .transport => return error.TestUnexpectedResult,
    }
}

test "QUIC 1-RTT close bypasses a saturated congestion window" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();

    const sender_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const receiver_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &sender_cid,
        .peer_connection_id = &receiver_cid,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &receiver_cid,
        .peer_connection_id = &sender_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer receiver.deinit();

    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "unacknowledged",
    } }});
    var data_packet = try receiver.receivePacket();
    defer data_packet.deinit(allocator);
    const saturated_flight = sender.bytesInFlight();
    try std.testing.expect(saturated_flight != 0);
    one_rtt.testing.clampCongestionWindowToBytesInFlight(&sender);
    try std.testing.expectEqual(@as(usize, 0), sender.congestionAvailable());
    try std.testing.expectError(
        error.CongestionLimited,
        sender.send(&.{.{ .ping = {} }}),
    );

    // CONNECTION_CLOSE is neither ack-eliciting nor in-flight under RFC 9000,
    // so a full congestion window must not strand the peer until idle timeout.
    try sender.closeApplication(77, "cancel saturated sender");
    try std.testing.expectEqual(saturated_flight, sender.bytesInFlight());
    var close_packet = try receiver.receivePacket();
    defer close_packet.deinit(allocator);
    const close = receiver.peerCloseInfo().?.application;
    try std.testing.expectEqual(@as(u64, 77), close.error_code);
    try std.testing.expectEqualStrings(
        "cancel saturated sender",
        close.reason_phrase,
    );
    try std.testing.expect(receiver.draining());
}

test "QUIC 1-RTT application close truncates reason within path MTU" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf4} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "close-sender",
        .peer_connection_id = "close-receiver",
        .local_endpoint = .server,
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "close-receiver",
        .peer_connection_id = "close-sender",
        .max_datagram_size = 1400,
        .enable_pacing = false,
    });
    defer receiver.deinit();

    const reason: []const u8 = "€" ** 700;
    sender.handshake_status = .{ .server_pending = null };
    try sender.closeApplication(quic.varint.max_value, reason);
    try std.testing.expect(sender.handshake_status.needsHandshakeDone());
    try std.testing.expectEqualStrings(
        reason,
        sender.close_info.?.reason_phrase,
    );
    var packet = try receiver.receivePacket();
    defer packet.deinit(allocator);
    const received = receiver.peerCloseInfo().?.application;
    try std.testing.expectEqual(quic.varint.max_value, received.error_code);
    try std.testing.expect(received.reason_phrase.len != 0);
    try std.testing.expect(received.reason_phrase.len < reason.len);
    try std.testing.expect(std.unicode.utf8ValidateSlice(
        received.reason_phrase,
    ));
    try std.testing.expectEqualSlices(
        u8,
        reason[0..received.reason_phrase.len],
        received.reason_phrase,
    );
    try std.testing.expectEqual(@as(usize, 1), sender.sent.packets.items.len);
    const initial_datagram_size = sender.sent.packets.items[0].datagram_size;
    try std.testing.expect(
        initial_datagram_size <=
            sender.currentSendDatagramSize(),
    );

    sender.pmtud.current_size = quic.pmtu.min_udp_payload_size;
    try sender.resendClose();
    try std.testing.expectEqual(@as(usize, 2), sender.sent.packets.items.len);
    const resent_datagram_size = sender.sent.packets.items[1].datagram_size;
    try std.testing.expect(
        resent_datagram_size <= quic.pmtu.min_udp_payload_size,
    );
    try std.testing.expect(resent_datagram_size < initial_datagram_size);
    try std.testing.expectEqualStrings(
        reason,
        sender.close_info.?.reason_phrase,
    );
}

test "QUIC 1-RTT local close installs state when socket send fails" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var transport_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer transport_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );

    var transport_output: std.Io.Writer.Allocating = .init(allocator);
    defer transport_output.deinit();
    var transport_trace = quic.qlog.Trace.init(
        &transport_output.writer,
        .{},
    );
    var transport_observer = quic.qlog.Observer.init(&transport_trace);
    var transport = try one_rtt.Connection.init(&transport_endpoint, .{
        .peer = transport_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "transport-local",
        .peer_connection_id = "transport-peer",
        .qlog_observer = &transport_observer,
    });
    defer transport.deinit();

    {
        var failed_transport_send = ObservedBatchSend{
            .delegate = transport_endpoint.io,
            .fail_after_prefix = 0,
        };
        transport_endpoint.io = failed_transport_send.io();
        defer transport_endpoint.io = failed_transport_send.delegate;

        try std.testing.expectError(
            error.NetworkDown,
            transport.closeTransportAt(
                0x100,
                @intFromEnum(quic.FrameType.stream),
                "transport send failed",
                100,
                25,
            ),
        );
        try std.testing.expectEqual(@as(usize, 1), failed_transport_send.calls);
        try std.testing.expectError(
            error.ConnectionClosed,
            transport.closeTransport(0x101, 0, "second close"),
        );
        try std.testing.expectEqual(@as(usize, 1), failed_transport_send.calls);
    }

    try std.testing.expect(transport.closing());
    try std.testing.expectEqual(@as(?u64, 175), transport.closeExpiryDeadlineMillis());
    try std.testing.expectEqual(@as(u64, 0x100), transport.close_info.?.error_code);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.stream)),
        transport.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings(
        "transport send failed",
        transport.close_info.?.reason_phrase,
    );
    try std.testing.expectEqual(@as(?one_rtt.PeerCloseInfo, null), transport.peerCloseInfo());
    try std.testing.expectEqual(@as(u64, 1), transport.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), transport.sent.packets.items.len);
    try std.testing.expectError(
        error.ConnectionClosed,
        transport.send(&.{.{ .ping = {} }}),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        transport_output.written(),
        "\"name\":\"connectivity:connection_closed\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        transport_output.written(),
        "\"trigger\":\"local_close\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        transport_output.written(),
        "\"reason\":\"transport send failed\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        transport_output.written(),
        "\"name\":\"quic:packet_sent\"",
    ) == null);

    // The owned diagnostic remains available for the dedicated retransmit
    // path after the original caller's send attempt has failed.
    try transport.resendClose();
    try std.testing.expectEqual(@as(u64, 2), transport.next_packet_number);
    try std.testing.expectEqual(@as(usize, 1), transport.sent.packets.items.len);

    var application_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer application_endpoint.deinit();
    var application_output: std.Io.Writer.Allocating = .init(allocator);
    defer application_output.deinit();
    var application_trace = quic.qlog.Trace.init(
        &application_output.writer,
        .{},
    );
    var application_observer = quic.qlog.Observer.init(&application_trace);
    var application = try one_rtt.Connection.init(&application_endpoint, .{
        .peer = application_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "application-local",
        .peer_connection_id = "application-peer",
        .qlog_observer = &application_observer,
    });
    defer application.deinit();

    {
        var failed_application_send = ObservedBatchSend{
            .delegate = application_endpoint.io,
            .fail_after_prefix = 0,
        };
        application_endpoint.io = failed_application_send.io();
        defer application_endpoint.io = failed_application_send.delegate;

        try std.testing.expectError(
            error.NetworkDown,
            application.closeApplicationAt(
                42,
                "application send failed",
                200,
                30,
            ),
        );
        try std.testing.expectEqual(@as(usize, 1), failed_application_send.calls);
    }

    try std.testing.expect(application.closing());
    try std.testing.expectEqual(@as(?u64, 290), application.closeExpiryDeadlineMillis());
    try std.testing.expect(application.close_info.?.application);
    try std.testing.expectEqual(@as(u64, 42), application.close_info.?.error_code);
    try std.testing.expectEqualStrings(
        "application send failed",
        application.close_info.?.reason_phrase,
    );
    try std.testing.expectEqual(@as(?one_rtt.PeerCloseInfo, null), application.peerCloseInfo());
    try std.testing.expectEqual(@as(u64, 1), application.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), application.sent.packets.items.len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        application_output.written(),
        "\"application_code\":42",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        application_output.written(),
        "\"reason\":\"application send failed\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        application_output.written(),
        "\"name\":\"quic:packet_sent\"",
    ) == null);
}

test "QUIC 1-RTT local close allocates reason before packet emission" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var counting = std.testing.FailingAllocator.init(allocator, .{});
    var endpoint = try quic.runtime.Endpoint.bind(
        counting.allocator(),
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf3} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    var observed_send = ObservedBatchSend{ .delegate = endpoint.io };
    endpoint.io = observed_send.io();
    defer endpoint.io = observed_send.delegate;
    counting.fail_index = counting.alloc_index;

    try std.testing.expectError(
        error.OutOfMemory,
        connection.closeTransportAt(7, 0, "must be owned", 10, 5),
    );
    try std.testing.expect(counting.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), observed_send.calls);
    try std.testing.expect(connection.close_info == null);
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), connection.sent.packets.items.len);
}

test "QUIC 1-RTT close lifecycle expires after three PTOs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try connection.closeTransportAt(0x10, @intFromEnum(quic.FrameType.stream), "closing", 100, 25);
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(@as(?u64, 175), connection.closeExpiryDeadlineMillis());
    try std.testing.expectError(error.ConnectionClosed, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
    try std.testing.expect(!connection.checkCloseExpired(174));
    try std.testing.expect(connection.closing());
    try std.testing.expect(connection.checkCloseExpired(175));
    try std.testing.expect(connection.closed());
}

test "QUIC 1-RTT default local close arms three-PTO expiry" {
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
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "default-close-local",
        .peer_connection_id = "default-close-peer",
        .enable_pacing = false,
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 1_000,
    });
    defer connection.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &ping,
        null,
        .not_ect,
    );
    try std.testing.expect(!try connection.sendAckForPacketIfNeeded(0, &ping));
    try std.testing.expect(connection.ackDelayDeadline() != null);

    const before_ns = std.Io.Clock.awake.now(io).nanoseconds;
    try connection.closeApplication(73, "default close");
    const after_ns = std.Io.Clock.awake.now(io).nanoseconds;
    const started_ms = connection.close_info.?.started_ms orelse
        return error.TestUnexpectedResult;
    const expiry_ms = connection.closeExpiryDeadlineMillis() orelse
        return error.TestUnexpectedResult;
    const pto_ms = std.math.divCeil(
        u64,
        connection.rtt_stats.pto(true),
        std.time.ns_per_ms,
    ) catch unreachable;
    const before_ms: u64 = @intCast(@divFloor(
        before_ns + std.time.ns_per_ms - 1,
        std.time.ns_per_ms,
    ));
    const after_ms: u64 = @intCast(@divFloor(
        after_ns + std.time.ns_per_ms - 1,
        std.time.ns_per_ms,
    ));

    try std.testing.expect(started_ms >= before_ms);
    try std.testing.expect(started_ms <= after_ms);
    try std.testing.expectEqual(started_ms + 3 * pto_ms, expiry_ms);
    const timer = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.close, timer.kind);
    try std.testing.expectEqual(expiry_ms * std.time.ns_per_ms, timer.deadline_ns);
    try std.testing.expect(!connection.checkCloseExpired(expiry_ms - 1));
    try std.testing.expect(connection.checkCloseExpired(expiry_ms));
    try std.testing.expect(connection.closed());
    try std.testing.expect(connection.nextTimerDeadline() == null);
}

test "QUIC 1-RTT default peer close arms three-PTO draining expiry" {
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
        [_]u8{0xc3} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "peer-close-local",
        .peer_connection_id = "peer-close-peer",
        .enable_pacing = false,
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 1_000,
    });
    defer connection.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &ping,
        null,
        .not_ect,
    );
    try std.testing.expect(!try connection.sendAckForPacketIfNeeded(0, &ping));
    try std.testing.expect(connection.ackDelayDeadline() != null);

    const before_ns = std.Io.Clock.awake.now(io).nanoseconds;
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .application_close = .{
            .error_code = 74,
            .reason_phrase = "peer close",
        } }},
        null,
        .not_ect,
    );
    const after_ns = std.Io.Clock.awake.now(io).nanoseconds;
    try std.testing.expect(connection.draining());
    const started_ms = connection.close_info.?.started_ms orelse
        return error.TestUnexpectedResult;
    const expiry_ms = connection.closeExpiryDeadlineMillis() orelse
        return error.TestUnexpectedResult;
    const pto_ms = std.math.divCeil(
        u64,
        connection.rtt_stats.pto(true),
        std.time.ns_per_ms,
    ) catch unreachable;
    const before_ms: u64 = @intCast(@divFloor(
        before_ns + std.time.ns_per_ms - 1,
        std.time.ns_per_ms,
    ));
    const after_ms: u64 = @intCast(@divFloor(
        after_ns + std.time.ns_per_ms - 1,
        std.time.ns_per_ms,
    ));

    try std.testing.expect(started_ms >= before_ms);
    try std.testing.expect(started_ms <= after_ms);
    try std.testing.expectEqual(started_ms + 3 * pto_ms, expiry_ms);
    const timer = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.close, timer.kind);
    try std.testing.expectEqual(expiry_ms * std.time.ns_per_ms, timer.deadline_ns);
}

test "QUIC 1-RTT connection handles RESET_STREAM final size" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x4a} ** quic.protection.secret_len);

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

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcde", .fin = false } }});
    var stream_packet = try server.receivePacket();
    defer stream_packet.deinit(allocator);
    try std.testing.expectEqualStrings("abcde", stream_packet.frames[0].stream.data);
    try std.testing.expectEqual(@as(u64, 5), server.recv_data_total);

    try client.resetStream(0, 77);
    var reset_packet = try server.receivePacket();
    defer reset_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), reset_packet.frames[0].reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 77), reset_packet.frames[0].reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 5), reset_packet.frames[0].reset_stream.final_size);
    const reset = server.streamResetReceived(0).?;
    try std.testing.expectEqual(@as(u64, 77), reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 5), reset.final_size);
    try std.testing.expectEqual(@as(u64, 5), server.recv_data_total);

    // A later RESET_STREAM with a different final size violates RFC 9000's
    // invariant that the final size, once known, is immutable.
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 78,
            .final_size = 4,
        } }},
    });
    try std.testing.expectError(error.FinalSizeMismatch, server.receivePacket());
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.final_size_error), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.reset_stream)), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("final size", server.close_info.?.reason_phrase);
}

test "QUIC 1-RTT connection answers STOP_SENDING with RESET_STREAM" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x4b} ** quic.protection.secret_len);

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

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "payload", .fin = false } }});
    var payload = try server.receivePacket();
    defer payload.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 7), server.recv_data_total);

    try server.sendStopSending(0, 44);
    var stop = try client.receivePacket();
    defer stop.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), stop.frames[0].stop_sending.stream_id);
    try std.testing.expectEqual(@as(u64, 44), stop.frames[0].stop_sending.application_error_code);
    try std.testing.expectEqual(@as(u64, 44), client.streamStopped(0).?.application_error_code);

    var reset = try server.receivePacket();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), reset.frames[0].reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 44), reset.frames[0].reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 7), reset.frames[0].reset_stream.final_size);
    try std.testing.expectEqual(@as(u64, 7), server.streamResetReceived(0).?.final_size);

    try std.testing.expectError(error.StreamStopped, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "more", .fin = false } }}));
    try std.testing.expectEqual(@as(u64, 7), client.send_flow.used);
}

test "QUIC STOP_SENDING defers paced automatic reset" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x4c} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&local_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "stop-local",
        .peer_connection_id = "stop-peer",
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &local_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 92;
    try dispatcher.registerConnection(handle, &connection);

    var fixed_io = FixedClockIo{
        .delegate = local_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = local_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    local_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer local_endpoint.io = fixed_io.delegate;

    try connection.sendAt(
        &.{
            .{ .stream = .{ .stream_id = 0, .data = "payload" } },
            .{ .padding = .{ .len = 1150 } },
        },
        @intCast(fixed_io.now_ns),
    );
    const packet_number = connection.next_packet_number;
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stop_sending = .{
            .stream_id = 0,
            .application_error_code = 92,
        } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    try dispatcher.refreshConnectionTimer(handle);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        connection.next_packet_number,
    );
    try std.testing.expectEqual(
        @as(u64, 92),
        connection.streamStopped(0).?.application_error_code,
    );
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);

    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, timer.connection_id);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.stop_sending_reset,
        timer.timer.kind,
    );
    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    const serviced = (try dispatcher.serviceNextTimerAt(
        timer.timer.deadline_ns,
    )) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, serviced.connection_handle);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.stop_sending_reset,
        serviced.timer.kind,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    const reset = connection.sendStreamStats(0).?.reset orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 92), reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 7), reset.final_size);
}

test "QUIC STREAMS_BLOCKED response is dispatcher retryable" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x4d} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&local_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "blocked-server",
        .peer_connection_id = "blocked-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 4,
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();
    var peer = try one_rtt.Connection.init(&peer_endpoint, .{
        .peer = local_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "blocked-client",
        .peer_connection_id = "blocked-server",
        .local_endpoint = .client,
        .enable_pacing = false,
    });
    defer peer.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &local_endpoint,
    );
    defer dispatcher.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 93;
    try dispatcher.registerConnection(handle, &connection);

    var fixed_io = FixedClockIo{
        .delegate = local_endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = local_endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    local_endpoint.io = .{
        .userdata = &fixed_io,
        .vtable = &fixed_vtable,
    };
    defer local_endpoint.io = fixed_io.delegate;

    try connection.sendAt(
        &.{.{ .padding = .{ .len = 1160 } }},
        @intCast(fixed_io.now_ns),
    );
    var fill = try peer.receivePacket();
    defer fill.deinit(allocator);
    const packet_number = connection.next_packet_number;
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .streams_blocked_bidi = .{ .maximum_streams = 1 } }},
        @intCast(fixed_io.now_ns),
        .not_ect,
    );
    try dispatcher.refreshConnectionTimer(handle);
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        packet_number,
        connection.next_packet_number,
    );
    const timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(handle, timer.connection_id);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.streams_blocked_response,
        timer.timer.kind,
    );

    fixed_io.now_ns = @intCast(timer.timer.deadline_ns);
    const serviced = (try dispatcher.serviceNextTimerAt(
        timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.streams_blocked_response,
        serviced.timer.kind,
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    var response = try peer.receivePacket();
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), response.frames.len);
    try std.testing.expect(response.frames[0] == .max_streams_bidi);
    try std.testing.expectEqual(
        @as(u64, 4),
        response.frames[0].max_streams_bidi.maximum_streams,
    );
}

test "QUIC 1-RTT connection applies sparse ACK ranges from peer" {
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
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

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

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.send(&ping); // packet 0
    try client.send(&ping); // packet 1, deliberately dropped below
    try client.send(&ping); // packet 2
    try std.testing.expectEqual(@as(usize, 3), client.pendingRecoveryCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);

    // Simulate a lost middle packet by removing packet 1 from the UDP one_rtt.receive
    // queue without recording it in the peer's ACK tracker.
    var dropped = try server_endpoint.receiveBytes();
    defer dropped.deinit(allocator);

    var third = try server.receivePacket();
    defer third.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), third.packet.packet_number);

    try server.sendAck(0);
    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 1), ack_packet.frames[0].ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.ranges[0].ack_range_length);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expect(!client.sent.packets.items[1].acknowledged);
    try std.testing.expect(client.sent.packets.items[2].acknowledged);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u64, 1), client.recovery.pending.items[0].packetNumberAt(0).?);
}

test "QUIC 1-RTT response piggybacks pending ACK" {
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

    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );

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

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "request",
    } }});
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    try server.sendWithPendingAck(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "response",
    } }}, 0);
    var response = try client.receivePacket();
    defer response.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), response.frames.len);
    try std.testing.expect(response.frames[0] == .stream);
    try std.testing.expectEqualStrings(
        "response",
        response.frames[0].stream.data,
    );
    try std.testing.expect(response.frames[1] == .ack);
    try std.testing.expectEqual(
        @as(u64, 0),
        response.frames[1].ack.largest_acknowledged,
    );
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
}

test "QUIC 1-RTT one-attempt response preserves pending ACK on failure" {
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

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "ack-try-server",
        .peer_connection_id = "ack-try-client",
        .local_endpoint = .server,
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 25_000,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var peer = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "ack-try-client",
        .peer_connection_id = "ack-try-server",
        .enable_pacing = false,
    });
    defer peer.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try peer.send(&ping);
    var request = try connection.receivePacket();
    defer request.deinit(allocator);
    try std.testing.expect(!try connection.sendAckForPacketIfNeeded(
        request.packet.packet_number,
        request.frames,
    ));
    const deadline = connection.ackDelayDeadline() orelse
        return error.TestUnexpectedResult;
    const too_large = [_]u8{0xa5} ** 4096;
    try std.testing.expectError(
        error.DatagramTooLarge,
        connection.trySendWithPendingAck(&.{.{ .stream = .{
            .stream_id = 1,
            .data = &too_large,
        } }}, 0),
    );
    try std.testing.expectEqual(deadline, connection.ackDelayDeadline().?);

    try connection.trySendWithPendingAck(&.{.{ .stream = .{
        .stream_id = 1,
        .data = "response",
    } }}, 0);
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());

    var packet = try peer.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), packet.frames.len);
    try std.testing.expect(packet.frames[0] == .stream);
    try std.testing.expect(packet.frames[1] == .ack);
}

test "QUIC 1-RTT opens local stream ids without eager state" {
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
        [_]u8{0xb3} ** quic.protection.secret_len,
    );

    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .initial_send_max_streams_bidi = 2,
        .initial_send_max_streams_uni = 1,
    });
    defer client.deinit();
    try std.testing.expectEqual(@as(u64, 0), try client.openStream());
    try std.testing.expectEqual(@as(u64, 4), try client.openStream());
    try std.testing.expectEqual(
        @as(u64, 2),
        try client.openUnidirectionalStream(),
    );
    try std.testing.expect(client.getSendStreamStats(0) == null);
    try std.testing.expect(client.getSendStreamStats(4) == null);
    try std.testing.expectEqual(
        @as(u64, 3),
        client.stats().outgoing_streams_created,
    );
    try std.testing.expectError(error.StreamLimitExceeded, client.openStream());
    try std.testing.expectError(
        error.StreamLimitExceeded,
        client.openUnidirectionalStream(),
    );

    var server = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
        .local_endpoint = .server,
        .initial_send_max_streams_bidi = 1,
        .initial_send_max_streams_uni = 1,
    });
    defer server.deinit();
    try std.testing.expectEqual(@as(u64, 1), try server.openStream());
    try std.testing.expectEqual(
        @as(u64, 3),
        try server.openUnidirectionalStream(),
    );
}

test "QUIC 1-RTT accepts peer frames for implicitly opened local streams" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
    );

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "implicit-client",
        .peer_connection_id = "implicit-server",
        .initial_send_max_streams_bidi = 3,
        .initial_send_max_streams_uni = 3,
        .initial_receive_max_streams_bidi = 3,
        .initial_receive_max_streams_uni = 3,
        .initial_send_max_stream_data_uni = 16,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "implicit-server",
        .peer_connection_id = "implicit-client",
        .local_endpoint = .server,
        .initial_send_max_streams_bidi = 3,
        .initial_send_max_streams_uni = 3,
        .initial_receive_max_streams_bidi = 3,
        .initial_receive_max_streams_uni = 3,
        .initial_send_max_stream_data_uni = 16,
        .enable_pacing = false,
    });
    defer server.deinit();

    // Using the third local stream of each type opens the two lower-numbered
    // streams even though they do not yet have transport state objects.
    try client.send(&.{
        .{ .stream = .{ .stream_id = 8, .data = "high-bidi" } },
        .{ .stream = .{ .stream_id = 10, .data = "high-uni" } },
    });
    var opened = try server.receivePacket();
    defer opened.deinit(allocator);
    try std.testing.expect(client.getSendStreamStats(0) == null);
    try std.testing.expect(client.getSendStreamStats(2) == null);
    try std.testing.expect(client.getSendStreamStats(4) == null);
    try std.testing.expect(client.getSendStreamStats(6) == null);

    try server.send(&.{
        .{ .stream = .{
            .stream_id = 0,
            .data = "response",
            .fin = true,
        } },
        .{ .reset_stream = .{
            .stream_id = 4,
            .application_error_code = 77,
            .final_size = 0,
        } },
        .{ .max_stream_data = .{
            .stream_id = 2,
            .maximum_stream_data = 1024,
        } },
        .{ .stop_sending = .{
            .stream_id = 6,
            .application_error_code = 42,
        } },
    });
    var peer_frames = try client.receivePacket();
    defer peer_frames.deinit(allocator);

    try std.testing.expectEqualStrings(
        "response",
        client.availableReceivedStream(0).?,
    );
    const reset = client.streamResetReceived(4) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 77), reset.application_error_code);
    const raised = client.getSendStreamStats(2) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1024), raised.send_limit);
    const stopped = client.getSendStreamStats(6) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 42),
        stopped.stopped.?.application_error_code,
    );
    try std.testing.expectEqual(
        @as(u64, 42),
        stopped.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        @as(u64, 6),
        client.stats().outgoing_streams_created,
    );

    var automatic_reset = try server.receivePacket();
    defer automatic_reset.deinit(allocator);
    const received_reset = server.streamResetReceived(6) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 42),
        received_reset.application_error_code,
    );

    // Exercise the opposite endpoint role and stream-ID parity on the same
    // authenticated connection.
    try server.send(&.{
        .{ .stream = .{ .stream_id = 9, .data = "server-high-bidi" } },
        .{ .stream = .{ .stream_id = 11, .data = "server-high-uni" } },
    });
    var server_opened = try client.receivePacket();
    defer server_opened.deinit(allocator);
    try std.testing.expect(server.getSendStreamStats(1) == null);
    try std.testing.expect(server.getSendStreamStats(3) == null);
    try std.testing.expect(server.getSendStreamStats(5) == null);
    try std.testing.expect(server.getSendStreamStats(7) == null);

    try client.send(&.{
        .{ .stream = .{
            .stream_id = 1,
            .data = "client-response",
            .fin = true,
        } },
        .{ .reset_stream = .{
            .stream_id = 5,
            .application_error_code = 88,
            .final_size = 0,
        } },
        .{ .max_stream_data = .{
            .stream_id = 3,
            .maximum_stream_data = 2048,
        } },
        .{ .stop_sending = .{
            .stream_id = 7,
            .application_error_code = 43,
        } },
    });
    var reverse_peer_frames = try server.receivePacket();
    defer reverse_peer_frames.deinit(allocator);

    try std.testing.expectEqualStrings(
        "client-response",
        server.availableReceivedStream(1).?,
    );
    const reverse_reset = server.streamResetReceived(5) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 88),
        reverse_reset.application_error_code,
    );
    const reverse_raised = server.getSendStreamStats(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 2048), reverse_raised.send_limit);
    const reverse_stopped = server.getSendStreamStats(7) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 43),
        reverse_stopped.stopped.?.application_error_code,
    );
    try std.testing.expectEqual(
        @as(u64, 43),
        reverse_stopped.reset.?.application_error_code,
    );
    try std.testing.expectEqual(
        @as(u64, 6),
        server.stats().outgoing_streams_created,
    );

    var reverse_automatic_reset = try client.receivePacket();
    defer reverse_automatic_reset.deinit(allocator);
    const client_received_reset = client.streamResetReceived(7) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(u64, 43),
        client_received_reset.application_error_code,
    );
}

test "QUIC 1-RTT rejects peer frames for unopened local streams" {
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
        [_]u8{0xb5} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "unopened-local",
        .peer_connection_id = "unopened-peer",
        .initial_send_max_streams_bidi = 2,
        .initial_send_max_streams_uni = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try std.testing.expectEqual(@as(u64, 0), try connection.openStream());
    try std.testing.expectEqual(
        @as(u64, 2),
        try connection.openUnidirectionalStream(),
    );
    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(
            &connection,
            0,
            &.{.{ .stream = .{
                .stream_id = 4,
                .data = "not-open",
            } }},
            null,
            .not_ect,
        ),
    );
    try std.testing.expect(connection.recvStreamStats(4) == null);
    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(
            &connection,
            0,
            &.{.{ .stop_sending = .{
                .stream_id = 6,
                .application_error_code = 9,
            } }},
            null,
            .not_ect,
        ),
    );
    try std.testing.expect(connection.getSendStreamStats(6) == null);
}

test "QUIC 1-RTT ACK of ACK prunes received packet history" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{
        .ip4 = .loopback(0),
    }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{
        .ip4 = .loopback(0),
    }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
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

    try client.send(&.{.{ .ping = {} }});
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try server.sendAck(0);
    var server_ack = try client.receivePacket();
    defer server_ack.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 1),
        server.stats().received_packet_stats.retained_packets,
    );

    try client.sendAck(0);
    var ack_of_ack = try server.receivePacket();
    defer ack_of_ack.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 1),
        server.stats().received_packet_stats.retained_packets,
    );
    try server.sendAck(0);
    var pruned_ack = try client.receivePacket();
    defer pruned_ack.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 1),
        pruned_ack.frames[0].ack.largest_acknowledged,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        pruned_ack.frames[0].ack.first_ack_range,
    );
}

test "QUIC 1-RTT connection retransmits PTO payload and clears recovery on ACK" {
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
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa2} ** quic.protection.secret_len);

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
        .initial_receive_max_data = 4,
        .initial_receive_max_stream_data = 4,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "lost", .fin = false } }};
    try client.send(&frames);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    try std.testing.expectEqualStrings("lost", first.frames[0].stream.data);

    try std.testing.expect(try client.retransmitPto());
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());

    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), retransmitted.packet.packet_number);
    try std.testing.expectEqualStrings("lost", retransmitted.frames[0].stream.data);
    try std.testing.expectEqual(@as(u64, 4), server.recv_data_total);

    try server.sendAck(0);
    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 1), ack_packet.frames[0].ack.first_ack_range);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expect(!(try client.retransmitPto()));
}

test "QUIC 1-RTT PTO service sends up to two probes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa9} ** quic.protection.secret_len);

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

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    try client.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());

    var observed_send = ObservedBatchSend{ .delegate = client.endpoint.io };
    client.endpoint.io = observed_send.io();
    defer client.endpoint.io = observed_send.delegate;

    const serviced = (try client.serviceLossDetectionTimer(335_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(usize, 1), observed_send.calls);
    if (client.endpoint.gsoSendEnabled()) {
        try std.testing.expectEqual(@as(usize, 1), observed_send.last_message_count);
        try std.testing.expect(observed_send.last_control_len != 0);
    } else {
        try std.testing.expectEqual(@as(usize, 2), observed_send.last_message_count);
        try std.testing.expectEqual(@as(usize, 0), observed_send.last_control_len);
    }
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[1].packetCount());

    var original0 = try server.receivePacket();
    defer original0.deinit(allocator);
    var original1 = try server.receivePacket();
    defer original1.deinit(allocator);
    var probe0 = try server.receivePacket();
    defer probe0.deinit(allocator);
    var probe1 = try server.receivePacket();
    defer probe1.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), original0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), original1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), probe0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 3), probe1.packet.packet_number);
}

test "QUIC 1-RTT PTO batch sends pacing-limited prefix" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd9} ** quic.protection.secret_len);

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

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    try client.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());

    const first_candidate = client.recovery.ptoCandidateAt(0) orelse return error.TestUnexpectedResult;
    const first_probe_packet_number = client.next_packet_number;
    const first_probe_packet_number_len = quic.protection.packetNumberLenForPayload(
        first_probe_packet_number,
        client.sent.largestAcknowledged(),
        first_candidate.payload.len,
    );
    const first_probe_packet_len = try quic.protection.shortPacketLen(.{
        .destination_connection_id = client.config.peer_connection_id,
        .packet_number = first_probe_packet_number,
        .packet_number_len = first_probe_packet_number_len,
        .payload = first_candidate.payload,
    });
    client.pacer.budget = first_probe_packet_len;
    client.pacer.setLastSentTimeNs(0);

    try std.testing.expectEqual(@as(usize, 1), try client.retransmitPtoProbesAt(0, 2));
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expect(client.pacing_blocked_until_ns != null);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(usize, 1), client.recovery.pending.items[1].packetCount());

    var original0 = try server.receivePacket();
    defer original0.deinit(allocator);
    var original1 = try server.receivePacket();
    defer original1.deinit(allocator);
    var probe0 = try server.receivePacket();
    defer probe0.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), original0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), original1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), probe0.packet.packet_number);
}

test "QUIC 1-RTT stateful batch commits stream flow and recovery" {
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

    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb9} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
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
        .enable_pacing = false,
    });
    defer server.deinit();

    const first = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .offset = 0,
            .data = "fi",
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = 2,
            .data = "rst",
        } },
    };
    const second = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .offset = 5,
            .data = "second",
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 4,
            .offset = 0,
            .data = "other",
        } },
    };
    const third = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = 5,
        .data = &.{},
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &first, &second, &third };
    try client.sendMany(&packets);

    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 16), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 11),
        one_rtt.testing.sendStreamUsed(&client, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 11),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 5),
        one_rtt.testing.sendStreamUsed(&client, 4).?,
    );
    try std.testing.expectEqual(
        @as(?u64, 5),
        one_rtt.testing.sendStreamFinalSize(&client, 4),
    );
    try std.testing.expectEqual(@as(usize, 3), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 3), client.sent.packets.items.len);

    var received0 = try server.receivePacket();
    defer received0.deinit(allocator);
    var received1 = try server.receivePacket();
    defer received1.deinit(allocator);
    var received2 = try server.receivePacket();
    defer received2.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received0.packet.packet_number);
    try std.testing.expectEqualStrings(
        "fi",
        received0.frames[0].stream.data,
    );
    try std.testing.expectEqualStrings(
        "rst",
        received0.frames[1].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 1), received1.packet.packet_number);
    try std.testing.expectEqualStrings(
        "second",
        received1.frames[0].stream.data,
    );
    try std.testing.expect(received1.frames[0].stream.fin);
    try std.testing.expectEqualStrings(
        "other",
        received1.frames[1].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 2), received2.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 0), received2.frames[0].stream.data.len);
    try std.testing.expect(received2.frames[0].stream.fin);
}

test "QUIC 1-RTT future packet length includes pending handshake done" {
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
        [_]u8{0xba} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .local_endpoint = .server,
    });
    defer client.deinit();

    client.handshake_status = .{ .server_pending = null };
    // Keep the base payload at three bytes so header-protection minimum packet
    // number sizing does not mask the extra HANDSHAKE_DONE byte.
    const frames = [_]quic.Frame{.{ .padding = .{ .len = 3 } }};
    const with_handshake_done = try client.packetLenForFramesAtOffset(
        0,
        &frames,
    );
    client.handshake_status = .confirmed;
    const without_handshake_done = try client.packetLenForFramesAtOffset(
        0,
        &frames,
    );
    try std.testing.expectEqual(
        without_handshake_done + 1,
        with_handshake_done,
    );
}

test "QUIC 1-RTT stateful batch splits at AEAD key generation boundary" {
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
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .aead_confidentiality_limit = 2,
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
        .aead_confidentiality_limit = 2,
        .enable_pacing = false,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &ping, &ping, &ping };
    try client.sendMany(&packets);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(
        @as(u64, 1),
        client.localOneRttKeyUpdateCount(),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        client.encryptedPacketsWithCurrentKeys(),
    );
    try std.testing.expectEqual(
        @as(?u64, 2),
        client.pendingOneRttKeyUpdateAckThreshold(),
    );

    var packet0 = try server.receivePacket();
    defer packet0.deinit(allocator);
    var packet1 = try server.receivePacket();
    defer packet1.deinit(allocator);
    var packet2 = try server.receivePacket();
    defer packet2.deinit(allocator);
    try std.testing.expect(!packet0.packet.key_phase);
    try std.testing.expect(!packet1.packet.key_phase);
    try std.testing.expect(packet2.packet.key_phase);
    try std.testing.expect(packet2.peer_initiated_key_update);
}

test "QUIC 1-RTT stateful batch stops at pacing deadline" {
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

    const client_cid = [_]u8{ 0xc3, 0xc4, 0xc5, 0xc6 };
    const server_cid = [_]u8{ 0xc7, 0xc8, 0xc9, 0xca };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
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
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    const payload_len = try ping[0].wireLen();
    const packet_number_len =
        quic.protection.packetNumberLenForPayload(0, null, payload_len);
    const packet_len = try quic.protection.shortPacketLen(.{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .packet_number_len = packet_number_len,
        .payload = &.{0},
    });
    client.pacer.budget = packet_len;
    client.pacer.setLastSentTimeNs(0);

    const packets = [_][]const quic.Frame{ &ping, &ping };
    const result = try client.sendManyProgressAt(&packets, 0);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 1), result.protected_count);
    try std.testing.expect(result.send_error == null);
    try std.testing.expect(client.pacing_blocked_until_ns != null);
    try std.testing.expectEqual(@as(u64, 1), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
}

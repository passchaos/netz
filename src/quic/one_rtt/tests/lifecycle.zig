const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;

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

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .handshake_done = {} }},
    });
    try std.testing.expectError(error.InvalidFrame, server.receivePacket());
    try std.testing.expect(!server.handshakeConfirmed());
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
    var observed_vtable = client.endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &observed_send,
        .vtable = &observed_vtable,
    };
    defer client.endpoint.io = observed_send.delegate;

    const serviced = (try client.serviceLossDetectionTimer(210_000_000)) orelse return error.TestUnexpectedResult;
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
    client.pacer.last_sent_time_ns = 0;

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

    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "first",
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .data = "second",
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    try client.sendMany(&packets);

    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 11), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 11),
        one_rtt.testing.sendStreamUsed(&client, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 11),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 0).?,
    );
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 2), client.sent.packets.items.len);

    var received0 = try server.receivePacket();
    defer received0.deinit(allocator);
    var received1 = try server.receivePacket();
    defer received1.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received0.packet.packet_number);
    try std.testing.expectEqualStrings(
        "first",
        received0.frames[0].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 1), received1.packet.packet_number);
    try std.testing.expectEqualStrings(
        "second",
        received1.frames[0].stream.data,
    );
    try std.testing.expect(received1.frames[0].stream.fin);
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
    client.pacer.last_sent_time_ns = 0;

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

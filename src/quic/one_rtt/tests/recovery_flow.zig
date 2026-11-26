const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;
const NativeSendIo = @import("../../../internal/testing/deadline_send_io.zig").Native;

test "QUIC server anti-amplification batch retains only sent wire bytes" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
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
        [_]u8{0xc0} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    server.setPeerAddressValidated(false);
    server.recordPeerAddressBytesReceived(20);
    const initial_credit = server.antiAmplificationLimitRemaining().?;

    var partial_send = ObservedBatchSend{
        .delegate = sender_endpoint.io,
        .fail_after_prefix = 1,
    };
    send_io.send_context = &partial_send;
    send_io.send_override = ObservedBatchSend.netSend;
    sender_endpoint.io = send_io.io();
    defer sender_endpoint.io = partial_send.delegate;

    const first = [_]quic.Frame{.{ .ping = {} }};
    const second = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &first, &second };
    const result = try server.sendManyProgressAt(&packets, 1_000);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 2), result.protected_count);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);

    var received = try receiver_endpoint.receiveBytes();
    defer received.deinit(allocator);
    try std.testing.expectEqual(
        @as(?usize, initial_credit - received.bytes.len),
        server.antiAmplificationLimitRemaining(),
    );
}

test "QUIC 1-RTT stateful batch rolls back unsent suffix and skips nonces" {
    const allocator = std.testing.allocator;

    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

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

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_cid = [_]u8{ 0xc5, 0xc6, 0xc7, 0xc8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc9} ** quic.protection.secret_len,
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

    client.endpoint.gso_send_enabled = false;
    var partial_send = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    send_io.send_context = &partial_send;
    send_io.send_override = ObservedBatchSend.netSend;
    client.endpoint.io = send_io.io();
    defer client.endpoint.io = partial_send.delegate;

    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "first",
    } }};
    const second = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .offset = 5,
            .data = "sec",
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = 8,
            .data = "ond",
        } },
    };
    const packets = [_][]const quic.Frame{ &first, &second };
    const result = try client.sendManyProgressAt(&packets, 1_000);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 2), result.protected_count);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);
    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 5), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 5),
        one_rtt.testing.sendStreamUsed(&client, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 5),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 0).?,
    );
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expectEqual(
        client.sent.packets.items[0].datagram_size,
        client.sent.packets.items[0].bytes,
    );
    try std.testing.expectEqual(
        client.sent.packets.items[0].bytes,
        client.bytesInFlight(),
    );
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        client.sent.packets.items[0].ecn,
    );
    try std.testing.expectEqual(@as(u64, 1), client.sent.stats().sent_ect0_count);
    try std.testing.expectEqual(
        @as(u64, 2),
        client.encryptedPacketsWithCurrentKeys(),
    );

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqualStrings(
        "first",
        received.frames[0].stream.data,
    );

    // Retry the unsent application suffix under packet number 2. The receiver
    // accepts the gap at packet 1, while flow/recovery state advances only now.
    client.endpoint.io = partial_send.delegate;
    try client.send(&second);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 11), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 11),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 0).?,
    );
    var retried = try server.receivePacket();
    defer retried.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), retried.packet.packet_number);
    try std.testing.expectEqualStrings(
        "sec",
        retried.frames[0].stream.data,
    );
    try std.testing.expectEqualStrings(
        "ond",
        retried.frames[1].stream.data,
    );
}

test "QUIC stateful sends charge only new highest stream offsets" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "credit-client",
        .peer_connection_id = "credit-server",
        .initial_send_max_data = 10,
        .initial_send_max_stream_data = 10,
        .enable_pacing = false,
    });
    defer sender.deinit();

    // A one-byte sparse write at offset five consumes the gap as six bytes of
    // both stream and connection credit, not merely its one payload byte.
    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .data = "x",
    } }});
    try std.testing.expectEqual(@as(u64, 6), sender.send_flow.used);
    try std.testing.expectEqual(
        @as(?u64, 6),
        one_rtt.testing.sendStreamUsed(&sender, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, 6),
        one_rtt.testing.sendStreamHighestSentEnd(&sender, 0),
    );

    // Fully overlapping retransmission-like application data consumes no new
    // flow credit, while extending the prior maximum by two consumes two.
    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 2,
        .data = "abc",
    } }});
    try std.testing.expectEqual(@as(u64, 6), sender.send_flow.used);
    try std.testing.expectEqual(
        @as(?u64, 6),
        one_rtt.testing.sendStreamUsed(&sender, 0),
    );
    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 4,
        .data = "wxyz",
    } }});
    try std.testing.expectEqual(@as(u64, 8), sender.send_flow.used);
    try std.testing.expectEqual(
        @as(?u64, 8),
        one_rtt.testing.sendStreamUsed(&sender, 0),
    );

    const packets_before = sender.stats().packets_sent;
    try std.testing.expectError(
        error.FlowControlBlocked,
        sender.send(&.{.{ .stream = .{
            .stream_id = 0,
            .offset = 10,
            .data = "z",
        } }}),
    );
    try std.testing.expectEqual(packets_before + 1, sender.stats().packets_sent);
    try std.testing.expectEqual(@as(u64, 8), sender.send_flow.used);
}

test "QUIC 1-RTT stateful batch keeps direct recovery payload bytes" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-recovery",
        .peer_connection_id = "peer-recovery",
        .enable_pacing = false,
    });
    defer connection.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "stable batch bytes",
        .fin = true,
    } }};
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(allocator);
    try frames[0].write(&expected, allocator);

    const packets = [_][]const quic.Frame{&frames};
    const result = try connection.sendManyProgressAt(&packets, 1_000);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 1), result.protected_count);
    try std.testing.expectEqualSlices(
        u8,
        expected.items,
        one_rtt.testing.recoveryPayloadForPacket(&connection, 0).?,
    );

    var raw = try receiver.receiveBytes();
    defer raw.deinit(allocator);
    var received = try one_rtt.openReceivedBytes(
        &receiver,
        raw.from,
        raw.bytes,
        keys,
        "peer-recovery".len,
        0,
        8,
    );
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings(
        "stable batch bytes",
        received.frames[0].stream.data,
    );
}

test "QUIC stateful batch omits DATAGRAM bytes from mixed recovery payload" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-mixed",
        .peer_connection_id = "peer-mixed",
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer connection.deinit();

    const unreliable_only = [_]quic.Frame{.{ .datagram = .{
        .data = "only-unreliable",
        .length_present = true,
    } }};
    const unreliable_packets = [_][]const quic.Frame{&unreliable_only};
    const unreliable_result = try connection.sendManyProgressAt(
        &unreliable_packets,
        500,
    );
    try std.testing.expectEqual(@as(usize, 1), unreliable_result.sent_count);
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&connection, 0) == null,
    );

    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "reliable", .fin = true } },
        .{ .datagram = .{ .data = "unreliable", .length_present = true } },
    };
    const packets = [_][]const quic.Frame{&frames};
    const result = try connection.sendManyProgressAt(&packets, 1_000);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);

    const recovery = one_rtt.testing.recoveryPayloadForPacket(
        &connection,
        1,
    ) orelse return error.TestUnexpectedResult;
    const parsed = try quic.parseFrame(recovery);
    try std.testing.expectEqual(recovery.len, parsed.consumed);
    try std.testing.expectEqual(
        quic.Frame.stream,
        @as(std.meta.Tag(quic.Frame), parsed.frame),
    );
    try std.testing.expectEqualStrings("reliable", parsed.frame.stream.data);

    const single = [_]quic.Frame{
        .{ .ping = {} },
        .{ .datagram = .{
            .data = "single-unreliable",
            .length_present = true,
        } },
    };
    try connection.sendAt(&single, 1_500);
    const single_recovery = one_rtt.testing.recoveryPayloadForPacket(
        &connection,
        2,
    ) orelse return error.TestUnexpectedResult;
    const single_parsed = try quic.parseFrame(single_recovery);
    try std.testing.expectEqual(single_recovery.len, single_parsed.consumed);
    try std.testing.expectEqual(
        quic.Frame.ping,
        @as(std.meta.Tag(quic.Frame), single_parsed.frame),
    );
}

test "QUIC imported 0-RTT DATAGRAM retains only a PING probe" {
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
        [_]u8{0xcc} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-local",
        .peer_connection_id = "early-peer",
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.importSentEarlyData(0, &.{.{ .datagram = .{
        .data = "early-unreliable",
        .length_present = true,
    } }});
    const recovery = one_rtt.testing.recoveryPayloadForPacket(
        &connection,
        0,
    ) orelse return error.TestUnexpectedResult;
    const parsed = try quic.parseFrame(recovery);
    try std.testing.expectEqual(recovery.len, parsed.consumed);
    try std.testing.expectEqual(
        quic.Frame.ping,
        @as(std.meta.Tag(quic.Frame), parsed.frame),
    );
}

test "QUIC accepted 0-RTT receive provenance survives 1-RTT continuation" {
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
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-recv-server",
        .peer_connection_id = "early-recv-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.applyEarlyDataFrames(0, &.{.{ .stream = .{
        .stream_id = 0,
        .data = "early-",
    } }});
    try std.testing.expect(connection.recvStreamReceivedEarlyData(0));

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 0,
            .offset = 6,
            .data = "continued",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.recvStreamReceivedEarlyData(0));

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        2,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = "ordinary",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(!connection.recvStreamReceivedEarlyData(4));
    try std.testing.expect(!connection.recvStreamReceivedEarlyData(8));

    try connection.applyEarlyDataFrames(3, &.{.{ .stream = .{
        .stream_id = 8,
        .data = "",
    } }});
    try std.testing.expect(!connection.recvStreamReceivedEarlyData(8));
    try connection.applyEarlyDataFrames(4, &.{.{ .stream = .{
        .stream_id = 12,
        .data = "",
        .fin = true,
    } }});
    try std.testing.expect(connection.recvStreamReceivedEarlyData(12));
}

test "QUIC imported 0-RTT copies preserve application packet numbers" {
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
        [_]u8{0xcd} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-local",
        .peer_connection_id = "early-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.importSentEarlyDataCopies(0, 3, &.{.{ .stream = .{
        .stream_id = 0,
        .data = "early",
        .fin = false,
    } }});
    try std.testing.expectEqual(@as(u64, 3), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 5), connection.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 5),
        connection.sendStreamStats(0).?.bytes_sent,
    );
    const stats = connection.stats();
    try std.testing.expectEqual(
        @as(usize, 3),
        stats.sent_packet_stats.tracked_packets,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        stats.recovery_queue_stats.pending_groups,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        stats.recovery_queue_stats.packet_number_copies,
    );
    var expected_flight: usize = 0;
    for (connection.sent.packets.items) |packet| {
        try std.testing.expectEqual(packet.datagram_size, packet.bytes);
        expected_flight += packet.bytes;
    }
    try std.testing.expectEqual(expected_flight, stats.bytes_in_flight);
    const one_copy_bytes = connection.sent.packets.items[0].bytes;
    try std.testing.expectEqual(one_copy_bytes * 3, expected_flight);
    for (0..3) |packet_number| {
        try std.testing.expect(one_rtt.testing.recoveryPayloadForPacket(
            &connection,
            packet_number,
        ) != null);
    }
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .ack = .{
            .largest_acknowledged = 2,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        @intCast(std.Io.Clock.awake.now(io).nanoseconds),
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.pendingRecoveryCount(),
    );
    try std.testing.expectEqual(
        one_copy_bytes * 2,
        connection.stats().bytes_in_flight,
    );
    try std.testing.expect(connection.ptoDeadline() != null);

    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(@as(u64, 4), connection.next_packet_number);
}

test "QUIC imported 0-RTT charges highest offsets transactionally" {
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
        [_]u8{0xce} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-local",
        .peer_connection_id = "early-peer",
        .initial_send_max_data = 16,
        .initial_send_max_stream_data = 16,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.importSentEarlyData(0, &.{
        .{ .stream = .{
            .stream_id = 0,
            .offset = 5,
            .data = "x",
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = 2,
            .data = "abc",
        } },
    });
    try std.testing.expectEqual(@as(u64, 6), connection.send_flow.used);
    try std.testing.expectEqual(
        @as(?u64, 6),
        one_rtt.testing.sendStreamUsed(&connection, 0),
    );

    var blocked = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "blocked-local",
        .peer_connection_id = "blocked-peer",
        .initial_send_max_data = 16,
        .initial_send_max_stream_data = 4,
        .enable_pacing = false,
    });
    defer blocked.deinit();
    try std.testing.expectError(
        error.FlowControlBlocked,
        blocked.importSentEarlyData(0, &.{
            .{ .stream = .{ .stream_id = 0, .data = "abc" } },
            .{ .stream = .{ .stream_id = 4, .offset = 4, .data = "x" } },
        }),
    );
    try std.testing.expectEqual(@as(u64, 0), blocked.send_flow.used);
    try std.testing.expectEqual(
        @as(?u64, 0),
        one_rtt.testing.sendStreamUsed(&blocked, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        one_rtt.testing.sendStreamUsed(&blocked, 4),
    );
    try std.testing.expectEqual(@as(u64, 0), blocked.next_packet_number);

    try std.testing.expectError(
        error.FinalSizeMismatch,
        blocked.importSentEarlyData(0, &.{
            .{ .stream = .{
                .stream_id = 8,
                .data = "a",
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .offset = 1,
                .data = "b",
            } },
        }),
    );
    try std.testing.expectEqual(@as(u64, 0), blocked.next_packet_number);
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamUsed(&blocked, 8),
    );
}

test "QUIC sparse 0-RTT import retires protected holes without tracking them" {
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
        [_]u8{0xcf} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-local",
        .peer_connection_id = "early-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.importSentEarlyDataPacketNumbers(
        0,
        4,
        &.{ 1, 3 },
        1234,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = "early",
            .fin = false,
        } }},
    );
    try std.testing.expectEqual(@as(u64, 4), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 5), connection.send_flow.used);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.stats().sent_packet_stats.tracked_packets,
    );
    try std.testing.expectEqual(
        @as(?usize, 1234),
        one_rtt.testing.lastSentPacketDatagramSize(&connection),
    );
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&connection, 0) == null,
    );
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&connection, 1) != null,
    );
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&connection, 2) == null,
    );
    try std.testing.expect(
        one_rtt.testing.recoveryPayloadForPacket(&connection, 3) != null,
    );
    try std.testing.expectError(
        error.InvalidAckFrame,
        connection.sent.validateAckCoversSentPackets(.{
            .largest_acknowledged = 2,
            .ack_delay = 0,
            .first_ack_range = 0,
        }),
    );

    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(@as(u64, 5), connection.next_packet_number);
}

test "QUIC sparse 0-RTT import rejects unordered or out-of-range packet numbers" {
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
        [_]u8{0xd0} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-local",
        .peer_connection_id = "early-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "early",
    } }};

    try std.testing.expectError(
        error.InvalidPacketNumber,
        connection.importSentEarlyDataPacketNumbers(
            0,
            4,
            &.{ 2, 1 },
            null,
            &frames,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketNumber,
        connection.importSentEarlyDataPacketNumbers(
            0,
            4,
            &.{4},
            null,
            &frames,
        ),
    );
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
}

test "QUIC rejected 0-RTT copies advance packet numbers without stream state" {
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
        [_]u8{0xce} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "early-local",
        .peer_connection_id = "early-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.discardSentEarlyDataCopies(0, 3);
    try std.testing.expectEqual(@as(u64, 3), connection.next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expect(connection.sendStreamStats(0) == null);
    try std.testing.expectError(
        error.InvalidAckFrame,
        connection.sent.validateAckCoversSentPackets(.{
            .largest_acknowledged = 2,
            .ack_delay = 0,
            .first_ack_range = 0,
        }),
    );

    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(@as(u64, 4), connection.next_packet_number);
}

test "QUIC DATAGRAM recovery probes without retransmitting unreliable payload" {
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

    const client_cid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const server_cid = [_]u8{ 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd9} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.sendDatagram("unreliable");
    // A pure DATAGRAM retains no application bytes in recovery. PTO creates a
    // fresh PING probe rather than replaying RFC 9221 unreliable data.
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expect(try client.retransmitPtoAt(1));
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var original = try server.receivePacket();
    defer original.deinit(allocator);
    try std.testing.expectEqual(quic.Frame.datagram, @as(std.meta.Tag(quic.Frame), original.frames[0]));
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), probe.frames.len);
    try std.testing.expectEqual(quic.Frame.ping, @as(std.meta.Tag(quic.Frame), probe.frames[0]));
    try std.testing.expectEqual(@as(u64, 1), server.datagramsReceived());

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());

    const mixed = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .data = "reliable",
            .fin = true,
        } },
        .{ .datagram = .{
            .data = "unreliable-mixed",
            .length_present = true,
        } },
    };
    try client.send(&mixed);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expect(try client.retransmitPtoAt(2));

    var mixed_original = try server.receivePacket();
    defer mixed_original.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), mixed_original.frames.len);
    var mixed_retry = try server.receivePacket();
    defer mixed_retry.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), mixed_retry.frames.len);
    try std.testing.expectEqual(
        quic.Frame.stream,
        @as(std.meta.Tag(quic.Frame), mixed_retry.frames[0]),
    );
    try std.testing.expectEqualStrings(
        "reliable",
        mixed_retry.frames[0].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 2), server.datagramsReceived());
}

test "QUIC negotiated PTO requests an immediate ACK for unreliable flight" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "immediate-client",
        .peer_connection_id = "immediate-server",
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "immediate-server",
        .peer_connection_id = "immediate-client",
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
        .local_ack_eliciting_threshold = 4,
    });
    defer server.deinit();

    try client.sendDatagram("unreliable");
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expect(try client.retransmitPtoAt(1));
    // IMMEDIATE_ACK is packet-specific and is not retained as reliable data.
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());

    var original = try server.receivePacket();
    defer original.deinit(allocator);
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), probe.frames.len);
    try std.testing.expect(probe.frames[0] == .immediate_ack);
    try std.testing.expect(server.immediateAckRequested());
    try std.testing.expect(try server.sendAckForPacketIfNeeded(
        probe.packet.packet_number,
        probe.frames,
    ));
}

test "QUIC negotiated PTO batch appends IMMEDIATE_ACK to every probe" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd6} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "batch-client",
        .peer_connection_id = "batch-server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "batch-server",
        .peer_connection_id = "batch-client",
        .local_endpoint = .server,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
    });
    defer server.deinit();

    try client.sendAt(&.{.{ .ping = {} }}, 1_000);
    try client.sendAt(&.{.{ .ping = {} }}, 1_000);
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.retransmitPtoProbesAt(2_000, 2),
    );
    var original0 = try server.receivePacket();
    defer original0.deinit(allocator);
    var original1 = try server.receivePacket();
    defer original1.deinit(allocator);
    var probe0 = try server.receivePacket();
    defer probe0.deinit(allocator);
    var probe1 = try server.receivePacket();
    defer probe1.deinit(allocator);
    for ([_]one_rtt.ReceivedPacket{ probe0, probe1 }) |probe| {
        try std.testing.expectEqual(@as(usize, 2), probe.frames.len);
        try std.testing.expect(probe.frames[0] == .ping);
        try std.testing.expect(probe.frames[1] == .immediate_ack);
    }
}

test "QUIC negotiated PTO preserves a full datagram without IMMEDIATE_ACK" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "c",
        .peer_connection_id = "s",
        .max_datagram_size = 23,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "s",
        .peer_connection_id = "c",
        .local_endpoint = .server,
        .max_datagram_size = 23,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "a",
    } }});
    try std.testing.expect(try client.retransmitPtoAt(1));
    var original = try server.receivePacket();
    defer original.deinit(allocator);
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), probe.frames.len);
    try std.testing.expect(probe.frames[0] == .stream);
    try std.testing.expect(!server.immediateAckRequested());
}

test "QUIC bounded DATAGRAM send waits for ACK congestion credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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

    const client_cid = [_]u8{ 0xda, 0xdb, 0xdc, 0xdd };
    const server_cid = [_]u8{ 0xde, 0xdf, 0xe0, 0xe1 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.sendDatagram("first");
    one_rtt.testing.clampCongestionWindowToBytesInFlight(&client);
    const before = client.stats();
    try std.testing.expectError(
        error.Timeout,
        client.trySendDatagramWithDeadline(
            "bad-clock",
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real }),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        client.trySendDatagramWithTimeout("zero-budget", .fromNanoseconds(0)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.trySendDatagramOnceWithTimeout("zero-once", .fromNanoseconds(0)),
    );
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramWithTimeout("blocked", .fromMilliseconds(10)),
    );
    const after_timeout = client.stats();
    try std.testing.expectEqual(before.datagrams_sent, after_timeout.datagrams_sent);
    try std.testing.expectEqual(before.packets_sent, after_timeout.packets_sent);

    const Shared = struct {
        server: *one_rtt.Connection,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.receivePacket();
            defer first.deinit(self.server.endpoint.allocator);
            try self.server.sendAck(0);
            var second = try self.server.receivePacket();
            defer second.deinit(self.server.endpoint.allocator);
            try std.testing.expectEqual(
                quic.Frame.datagram,
                @as(std.meta.Tag(quic.Frame), second.frames[0]),
            );
            try std.testing.expectEqualStrings("blocked", second.frames[0].datagram.data);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try client.sendDatagramWithTimeout(
        "blocked",
        .fromSeconds(2),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(before.datagrams_sent + 1, client.datagramsSent());
}

test "QUIC DATAGRAM batch validates all input and commits socket prefix" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gso_send = false },
    );
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x7a, 0x7b, 0x7c, 0x7d };
    const server_cid = [_]u8{ 0x7e, 0x7f, 0x80, 0x81 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .max_frames_per_packet = 1,
        .peer_max_datagram_frame_size = 1200,
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
        .local_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer server.deinit();

    var packet_number_boundary = try one_rtt.Connection.init(
        &client_endpoint,
        .{
            .peer = server_endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "boundary-local",
            .peer_connection_id = "boundary-peer",
            .max_frames_per_packet = 1,
            .peer_max_datagram_frame_size = 65_535,
            .enable_pacing = false,
        },
    );
    defer packet_number_boundary.deinit();
    one_rtt.testing.setNextPacketNumber(&packet_number_boundary, 126);
    const boundary_max = packet_number_boundary.maxDatagramPayloadSize() orelse
        return error.TestUnexpectedResult;
    const boundary_payload = try allocator.alloc(u8, boundary_max);
    defer allocator.free(boundary_payload);
    try packet_number_boundary.validateDatagrams(&.{boundary_payload});
    try std.testing.expectError(
        error.DatagramTooLarge,
        packet_number_boundary.validateDatagrams(&.{
            boundary_payload,
            boundary_payload,
        }),
    );
    try std.testing.expectEqual(
        @as(u64, 126),
        packet_number_boundary.next_packet_number,
    );

    const maximum = client.maxDatagramPayloadSize() orelse
        return error.TestUnexpectedResult;
    const oversized = try allocator.alloc(u8, maximum + 1);
    defer allocator.free(oversized);
    var committed: usize = 99;
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagramsWithDeadline(
            &.{ "valid", oversized },
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 0), client.datagramsSent());

    // The encoded DATAGRAM frame fits this payload-sized window, but the
    // complete protected QUIC packet does not.
    const initial_window = client.congestion.congestion_window;
    client.congestion.congestion_window = 5;
    try std.testing.expectError(
        error.CongestionLimited,
        client.trySendDatagrams(&.{"one"}, &committed),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight());
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
    client.congestion.congestion_window = initial_window;

    var partial_send = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    send_io.send_context = &partial_send;
    send_io.send_override = ObservedBatchSend.netSend;
    client.endpoint.io = send_io.io();
    defer client.endpoint.io = partial_send.delegate;

    const payloads = [_][]const u8{ "one", "two", "three" };
    try std.testing.expectError(
        error.NetworkDown,
        client.sendDatagramsWithDeadline(
            &payloads,
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expectEqual(@as(usize, 1), partial_send.calls);
    try std.testing.expectEqual(@as(usize, 3), partial_send.last_message_count);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 1), client.datagramsSent());

    client.endpoint.io = partial_send.delegate;
    try client.sendDatagramsWithTimeout(
        payloads[committed..],
        &committed,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(@as(usize, 2), committed);
    try std.testing.expectEqual(@as(u64, 5), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 3), client.datagramsSent());

    for (payloads, 0..) |expected, index| {
        var packet = try server.receivePacket();
        defer packet.deinit(allocator);
        try std.testing.expectEqual(
            quic.Frame.datagram,
            @as(std.meta.Tag(quic.Frame), packet.frames[0]),
        );
        try std.testing.expectEqualStrings(
            expected,
            packet.frames[0].datagram.data,
        );
        try std.testing.expectEqual(
            @as(u64, if (index == 0) 0 else index + 2),
            packet.packet.packet_number,
        );
    }
}

test "QUIC DATAGRAM batch continues across transport batch windows" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer receiver_endpoint.deinit();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "batch-window-local",
        .peer_connection_id = "batch-window-peer",
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer sender.deinit();

    var payload_storage: [one_rtt.max_batch_packets + 3][1]u8 = undefined;
    var payloads: [payload_storage.len][]const u8 = undefined;
    for (&payload_storage, &payloads, 0..) |*storage, *payload, index| {
        storage[0] = @intCast(index);
        payload.* = storage;
    }
    var committed: usize = 99;
    try sender.sendDatagramsWithTimeout(
        &payloads,
        &committed,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(payloads.len, committed);
    try std.testing.expectEqual(
        @as(u64, payloads.len),
        sender.datagramsSent(),
    );
    try std.testing.expectEqual(
        @as(u64, 5),
        sender.next_packet_number,
    );
}

test "QUIC DATAGRAM batch packs payloads into the MTU" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer receiver_endpoint.deinit();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "packed-local",
        .peer_connection_id = "packed-peer",
        .peer_max_datagram_frame_size = 1200,
        .max_frames_per_packet = 16,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "packed-peer",
        .peer_connection_id = "packed-local",
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .max_frames_per_packet = 16,
        .enable_pacing = false,
    });
    defer receiver.deinit();

    const payloads = [_][]const u8{ "one", "two", "three" };
    var committed: usize = 99;
    try sender.sendDatagramsWithTimeout(
        &payloads,
        &committed,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(payloads.len, committed);
    try std.testing.expectEqual(@as(u64, payloads.len), sender.datagramsSent());
    try std.testing.expectEqual(@as(u64, 1), sender.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), sender.pendingRecoveryCount());

    var packet = try receiver.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(payloads.len, packet.frames.len);
    for (payloads, packet.frames) |expected, frame| {
        try std.testing.expect(frame == .datagram);
        try std.testing.expectEqualStrings(expected, frame.datagram.data);
    }
    one_rtt.testing.setNextPacketNumber(
        &sender,
        quic.protection.max_packet_number,
    );
    try sender.validateDatagrams(&payloads);
    const too_many_for_last_packet = [_][]const u8{
        "1",  "2",  "3",  "4",  "5",  "6",  "7",  "8",  "9",
        "10", "11", "12", "13", "14", "15", "16", "17",
    };
    try std.testing.expectError(
        error.InvalidPacketNumber,
        sender.validateDatagrams(&too_many_for_last_packet),
    );
    one_rtt.testing.setNextPacketNumber(
        &sender,
        quic.protection.max_packet_number + 1,
    );
    try std.testing.expectError(
        error.InvalidPacketNumber,
        sender.validateDatagrams(&payloads),
    );
    one_rtt.testing.setNextPacketNumber(&sender, 2);

    var large_storage: [5][500]u8 = undefined;
    var large_payloads: [large_storage.len][]const u8 = undefined;
    for (&large_storage, &large_payloads, 0..) |*storage, *payload, index| {
        @memset(storage, @intCast(index));
        payload.* = storage;
    }
    var partial_send = ObservedBatchSend{
        .delegate = sender.endpoint.io,
        .fail_after_prefix = 1,
    };
    send_io.send_context = &partial_send;
    send_io.send_override = ObservedBatchSend.netSend;
    sender.endpoint.io = send_io.io();
    defer sender.endpoint.io = partial_send.delegate;
    try std.testing.expectError(
        error.NetworkDown,
        sender.sendDatagramsWithTimeout(
            &large_payloads,
            &committed,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), partial_send.calls);
    try std.testing.expectEqual(@as(usize, 3), partial_send.last_message_count);
    try std.testing.expectEqual(@as(usize, 2), committed);
    try std.testing.expectEqual(@as(u64, 5), sender.datagramsSent());
    try std.testing.expectEqual(@as(u64, 5), sender.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), sender.pendingRecoveryCount());
    var partial_packet = try receiver.receivePacket();
    defer partial_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), partial_packet.frames.len);
    for (large_payloads[0..2], partial_packet.frames) |expected, frame| {
        try std.testing.expect(frame == .datagram);
        try std.testing.expectEqualSlices(u8, expected, frame.datagram.data);
    }
}

test "QUIC 1-RTT single send builds frames in recovery ownership" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "single-local",
        .peer_connection_id = "single-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "single recovery bytes",
        .fin = true,
    } }};
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(allocator);
    try frames[0].write(&expected, allocator);

    try connection.sendAt(&frames, 1_000);
    try std.testing.expectEqualSlices(
        u8,
        expected.items,
        one_rtt.testing.recoveryPayloadForPacket(&connection, 0).?,
    );
    var raw = try receiver.receiveBytes();
    defer raw.deinit(allocator);
    var received = try one_rtt.openReceivedBytes(
        &receiver,
        raw.from,
        raw.bytes,
        keys,
        "single-peer".len,
        0,
        8,
    );
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings(
        "single recovery bytes",
        received.frames[0].stream.data,
    );
}

test "QUIC 1-RTT PTO batch commits a socket-sent prefix before returning error" {
    const allocator = std.testing.allocator;

    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe9} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    try client.sendAt(&ping, 10_000_000);
    const bytes_in_flight_before = client.bytesInFlight();
    client.endpoint.gso_send_enabled = false;

    // Replace only the client's send function after setup. The wrapper lets
    // the real socket emit the first datagram, then reproduces the partial
    // progress plus error result permitted by sendmmsg-style backends.
    var partial_send = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    send_io.send_context = &partial_send;
    send_io.send_override = ObservedBatchSend.netSend;
    client.endpoint.io = send_io.io();
    defer client.endpoint.io = partial_send.delegate;

    try std.testing.expectError(error.NetworkDown, client.retransmitPtoProbesAt(20_000_000, 2));
    try std.testing.expectEqual(@as(usize, 1), partial_send.calls);
    try std.testing.expectEqual(@as(u64, 4), client.next_packet_number);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(
        bytes_in_flight_before + client.sent.packets.items[2].datagram_size,
        client.bytesInFlight(),
    );
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
    try std.testing.expectEqual(@as(usize, 2), probe0.frames.len);
    try std.testing.expect(probe0.frames[0] == .ping);
    try std.testing.expect(probe0.frames[1] == .immediate_ack);

    client.endpoint.io = partial_send.delegate;
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.retransmitPtoProbesAt(30_000_000, 2),
    );
    try std.testing.expectEqual(@as(u64, 6), client.next_packet_number);
    var retry0 = try server.receivePacket();
    defer retry0.deinit(allocator);
    var retry1 = try server.receivePacket();
    defer retry1.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), retry0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 5), retry1.packet.packet_number);
    for ([_]one_rtt.ReceivedPacket{ retry0, retry1 }) |probe| {
        try std.testing.expectEqual(@as(usize, 2), probe.frames.len);
        try std.testing.expect(probe.frames[0] == .ping);
        try std.testing.expect(probe.frames[1] == .immediate_ack);
    }
}

test "QUIC 1-RTT PTO batch retires sealed nonces after zero socket progress" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xea} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
    });
    defer client.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    try client.sendAt(&ping, 10_000_000);
    const bytes_in_flight_before = client.bytesInFlight();
    var failed = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed;
    send_io.send_override = ObservedBatchSend.netSend;
    sender.io = send_io.io();
    defer sender.io = failed.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        client.retransmitPtoProbesAt(20_000_000, 2),
    );
    try std.testing.expectEqual(@as(u64, 4), client.next_packet_number);
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expectEqual(bytes_in_flight_before, client.bytesInFlight());
    try std.testing.expectEqual(
        @as(usize, 1),
        client.recovery.pending.items[0].packetCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.recovery.pending.items[1].packetCount(),
    );

    sender.io = failed.delegate;
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.retransmitPtoProbesAt(30_000_000, 2),
    );
    try std.testing.expectEqual(@as(u64, 6), client.next_packet_number);

    var original0 = try receiver.receiveBytes();
    defer original0.deinit(allocator);
    var original1 = try receiver.receiveBytes();
    defer original1.deinit(allocator);
    var probe0 = try receiver.receiveBytes();
    defer probe0.deinit(allocator);
    var probe1 = try receiver.receiveBytes();
    defer probe1.deinit(allocator);
    var opened0 = try quic.protection.openShortPacket(
        allocator,
        keys,
        probe0.bytes,
        "server".len,
        4,
    );
    defer opened0.deinit(allocator);
    var opened1 = try quic.protection.openShortPacket(
        allocator,
        keys,
        probe1.bytes,
        "server".len,
        5,
    );
    defer opened1.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), opened0.packet_number);
    try std.testing.expectEqual(@as(u64, 5), opened1.packet_number);
    for ([_][]const u8{ opened0.payload, opened1.payload }) |payload| {
        const first = try quic.parseFrame(payload);
        try std.testing.expect(first.frame == .ping);
        const second = try quic.parseFrame(payload[first.consumed..]);
        try std.testing.expect(second.frame == .immediate_ack);
        try std.testing.expectEqual(
            payload.len,
            first.consumed + second.consumed,
        );
    }
}

test "QUIC 1-RTT PTO retransmits unacked response stream packets after partial ACK" {
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

    const request0 = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "q0", .fin = true } }};
    const request1 = [_]quic.Frame{.{ .stream = .{ .stream_id = 4, .offset = 0, .data = "q1", .fin = true } }};
    const request2 = [_]quic.Frame{.{ .stream = .{ .stream_id = 8, .offset = 0, .data = "q2", .fin = true } }};
    const request3 = [_]quic.Frame{.{ .stream = .{ .stream_id = 12, .offset = 0, .data = "q3", .fin = true } }};
    try client.sendAt(&request0, 1_000_000);
    try client.sendAt(&request1, 1_000_000);
    try client.sendAt(&request2, 1_000_000);
    try client.sendAt(&request3, 1_000_000);
    var received_request0 = try server.receivePacketAt(2_000_000);
    received_request0.deinit(allocator);
    var received_request1 = try server.receivePacketAt(2_000_000);
    received_request1.deinit(allocator);
    var received_request2 = try server.receivePacketAt(2_000_000);
    received_request2.deinit(allocator);
    var received_request3 = try server.receivePacketAt(2_000_000);
    received_request3.deinit(allocator);

    const response0 = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "r0", .fin = true } }};
    const response1 = [_]quic.Frame{.{ .stream = .{ .stream_id = 4, .offset = 0, .data = "r1", .fin = true } }};
    const response2 = [_]quic.Frame{.{ .stream = .{ .stream_id = 8, .offset = 0, .data = "r2", .fin = true } }};
    const response3 = [_]quic.Frame{.{ .stream = .{ .stream_id = 12, .offset = 0, .data = "r3", .fin = true } }};

    try server.sendAt(&response0, 10_000_000);
    try server.sendAt(&response1, 10_000_000);
    try server.sendAt(&response2, 10_000_000);
    try server.sendAt(&response3, 10_000_000);
    try std.testing.expectEqual(@as(usize, 4), server.pendingRecoveryCount());

    var first = try client.receivePacketAt(20_000_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 0), first.frames[0].stream.stream_id);

    // Simulate local UDP loss for the remaining response packets: remove them
    // from the client socket without processing them, then ACK only packet 0.
    var dropped1 = try client.endpoint.receiveBytes();
    dropped1.deinit(allocator);
    var dropped2 = try client.endpoint.receiveBytes();
    dropped2.deinit(allocator);
    var dropped3 = try client.endpoint.receiveBytes();
    dropped3.deinit(allocator);

    try client.sendAck(0);
    var ack = try server.receivePacketAt(30_000_000);
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), server.pendingRecoveryCount());

    const deadline = server.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    _ = try server.serviceLossDetectionTimer(deadline.deadline_ns);

    var retransmitted = try client.receivePacketAt(deadline.deadline_ns + 1);
    defer retransmitted.deinit(allocator);
    try std.testing.expect(retransmitted.frames[0] == .stream);
    try std.testing.expect(retransmitted.frames[0].stream.stream_id == 4 or
        retransmitted.frames[0].stream.stream_id == 8 or
        retransmitted.frames[0].stream.stream_id == 12);
}

test "QUIC 1-RTT connection exposes PTO backoff deadlines and services timer" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const server_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);

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
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(u64, 325_000_000), client.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 335_000_000), client.ptoDeadline());
    const first_deadline = client.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, first_deadline.kind);
    try std.testing.expectEqual(@as(u64, 335_000_000), first_deadline.deadline_ns);

    try std.testing.expectEqual(@as(?one_rtt.LossDetectionTimerDeadline, null), try client.serviceLossDetectionTimer(334_999_999));
    const serviced = (try client.serviceLossDetectionTimer(335_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), probe.packet.packet_number);
    try std.testing.expectEqual(@as(?u64, 985_000_000), client.ptoDeadline());
    client.pto_count = 100;
    try std.testing.expectEqual(quic.rtt.max_pto_ns, client.ptoPeriod());

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(?one_rtt.LossDetectionTimerDeadline, null), client.lossDetectionTimerDeadline());
}

test "QUIC orphaned recovery group exposes a stable immediate PTO" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "orphan-local",
        .peer_connection_id = "orphan-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.sendAt(&.{.{ .ping = {} }}, 1_000);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
    connection.sent.packets.items[0].lost = true;
    try std.testing.expectEqual(@as(?u64, 0), connection.ptoDeadline());
    try std.testing.expectEqual(@as(?u64, 0), connection.ptoDeadline());
    const deadline = connection.lossDetectionTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.LossDetectionTimerKind.pto,
        deadline.kind,
    );
    try std.testing.expectEqual(@as(u64, 0), deadline.deadline_ns);
    const serviced = (try connection.serviceLossDetectionTimer(1)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), connection.ptoBackoffCount());
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.stats().recovery_queue_stats.packet_number_copies,
    );
}

test "QUIC 1-RTT jitter remains stable across PTO backoff and ACK rearm" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();
    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x6b} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "jitter-client",
        .peer_connection_id = "jitter-server",
        .pto_jitter_percentage = 25,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "jitter-server",
        .peer_connection_id = "jitter-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    const first_epoch = client.ptoJitterEpoch();
    const first_period = client.jitteredPtoPeriod();
    const first_deadline = client.ptoDeadline().?;
    try std.testing.expectEqual(first_deadline, client.ptoDeadline().?);

    _ = (try client.serviceLossDetectionTimer(first_deadline)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expect(client.ptoJitterEpoch() > first_epoch);
    const backed_off = client.jitteredPtoPeriod();
    try std.testing.expect(backed_off >= 487_500_000);
    try std.testing.expect(backed_off <= 812_500_000);
    try std.testing.expectEqual(client.ptoDeadline().?, client.ptoDeadline().?);

    var original = try server.receivePacket();
    defer original.deinit(allocator);
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try server.sendAck(0);
    const before_ack_epoch = client.ptoJitterEpoch();
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expect(client.ptoJitterEpoch() > before_ack_epoch);
    const base_after_ack = client.ptoPeriod();
    const jitter_after_ack = client.jitteredPtoPeriod();
    const maximum_offset = base_after_ack / 4;
    try std.testing.expect(jitter_after_ack >= base_after_ack - maximum_offset);
    try std.testing.expect(jitter_after_ack <= base_after_ack + maximum_offset);
    _ = first_period;
}

test "QUIC 1-RTT timer-aware GRO receive fires PTO before peer response" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .enable_gro_receive = true,
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .enable_gro_receive = true,
        },
    );
    defer client_endpoint.deinit();
    if (!client_endpoint.groReceiveEnabled()) return error.SkipZigTest;

    const client_cid = [_]u8{ 0x93, 0x94, 0x95, 0x96 };
    const server_cid = [_]u8{ 0x97, 0x98, 0x99, 0x9a };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9b} ** quic.protection.secret_len,
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

    const request = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "request",
        .fin = true,
    } }};
    try client.send(&request);
    var dropped = try server_endpoint.receiveBytes();
    dropped.deinit(allocator);

    const Shared = struct {
        server: *one_rtt.Connection,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *one_rtt.Connection) !void {
            var probe = try server_ptr.receivePacket();
            defer probe.deinit(server_ptr.endpoint.allocator);
            try std.testing.expectEqual(@as(u64, 1), probe.packet.packet_number);
            try std.testing.expectEqualStrings(
                "request",
                probe.frames[0].stream.data,
            );
            const response = [_]quic.Frame{.{ .stream = .{
                .stream_id = 0,
                .data = "response",
                .fin = true,
            } }};
            try server_ptr.send(&response);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var response = try client.receivePacketBatchServicingTimers();
    defer response.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(usize, 1), response.packets.len);
    try std.testing.expectEqualStrings(
        "response",
        response.packets[0].frames[0].stream.data,
    );
}

test "QUIC 1-RTT loss detection timer reports earliest loss or PTO deadline" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x92} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-local",
        .peer_connection_id = "timer-peer",
    });
    defer connection.deinit();

    connection.rtt_stats.updateAt(
        100_000_000,
        0,
        true,
        // This synthetic RTT sample represents a packet sent at time zero.
        0,
    );
    try connection.sent.sentAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        1200,
        1200,
        .not_ect,
        180_000_000,
        one_rtt.testing.currentPathEpoch(&connection),
    );
    _ = try connection.recovery.trackSent(0, "zero");
    try connection.sent.sentAtWithDatagramSizeAndPathEpoch(
        1,
        true,
        1200,
        1200,
        .not_ect,
        200_000_000,
        one_rtt.testing.currentPathEpoch(&connection),
    );
    _ = try connection.recovery.trackSent(1, "one");
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        250_000_000,
        .not_ect,
    );

    const loss_first = connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.loss_time, loss_first.kind);
    try std.testing.expectEqual(@as(u64, 285_468_750), loss_first.deadline_ns);
    try std.testing.expectEqual(
        @as(?u64, loss_first.deadline_ns),
        one_rtt.testing.cachedLossTimeDeadline(&connection),
    );

    // A newly sent packet is newer than the largest ACK and cannot alter the
    // already-computed time-threshold candidate. Timer reads remain stable
    // without rescanning the retained sent-packet history after each send.
    try connection.sent.sentAtWithDatagramSizeAndPathEpoch(
        2,
        true,
        1200,
        1200,
        .not_ect,
        300_000_000,
        one_rtt.testing.currentPathEpoch(&connection),
    );
    _ = try connection.recovery.trackSent(2, "two");
    try std.testing.expectEqual(loss_first, connection.lossDetectionTimerDeadline().?);
    try std.testing.expectEqual(
        @as(?u64, loss_first.deadline_ns),
        one_rtt.testing.cachedLossTimeDeadline(&connection),
    );

    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.cachedLossTimeDeadline(&connection),
    );
    const pto_first = connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, pto_first.kind);
    try std.testing.expectEqual(@as(u64, 618_750_000), pto_first.deadline_ns);
}

test "QUIC 1-RTT connection retransmits time-threshold losses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x4a, 0x4b, 0x4c, 0x4d };
    const server_cid = [_]u8{ 0x4e, 0x4f, 0x50, 0x51 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xbe} ** quic.protection.secret_len);

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
    try client.sendAt(&ping, 100); // packet 0, deliberately old enough below.
    try client.sendAt(&ping, 300); // packet 1, used to establish largest acked.

    var dropped = try server_endpoint.receiveBytes();
    dropped.deinit(allocator);
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), second.packet.packet_number);
    try server.sendAck(0);

    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expect(!client.sent.packets.items[0].lost);

    try std.testing.expect(try client.retransmitTimeThresholdLoss(260, 150));
    try std.testing.expect(client.sent.packets.items[0].lost);
    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), retransmitted.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expect(!(try client.retransmitTimeThresholdLoss(1_000, 150)));
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
}

test "QUIC 1-RTT ACK processing detects time-threshold losses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x7a, 0x7b, 0x7c, 0x7d };
    const server_cid = [_]u8{ 0x7e, 0x7f, 0x80, 0x81 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7c} ** quic.protection.secret_len);

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

    // Use already-populated RTT state so ACK-driven time loss uses the real
    // RFC 9002 9/8 loss delay instead of the larger initial fallback.
    client.rtt_stats.updateAt(
        100_000_000,
        0,
        true,
        // This synthetic RTT sample represents a packet sent at time zero.
        0,
    );
    const loss_delay = client.rtt_stats.lossDelay();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 100_000_000); // packet 0, should be lost by time threshold.
    try client.sendAt(&ping, 300_000_000); // packet 1, newest ACKed packet.

    var dropped = try server_endpoint.receiveBytes();
    dropped.deinit(allocator);
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), second.packet.packet_number);
    try server.sendAck(0);

    var ack = try client.receivePacketAt(100_000_000 + loss_delay);
    defer ack.deinit(allocator);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expect(client.sent.packets.items[0].lost);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    try std.testing.expect(try client.retransmitTimeThresholdLoss(500_000_000, loss_delay));
    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), retransmitted.packet.packet_number);
}

test "QUIC 1-RTT connection retransmits packet-threshold losses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x3a, 0x3b, 0x3c, 0x3d };
    const server_cid = [_]u8{ 0x3e, 0x3f, 0x40, 0x41 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xab} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xac} ** quic.protection.secret_len);

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
    // Keep all five sends and the ACK inside the initial 100ms time-loss
    // threshold. The test is specifically for packet-threshold loss; using
    // wall-clock `send`/`receivePacket` made a busy test host occasionally
    // classify packet 2 by time before the assertion below.
    for (0..5) |_| try client.sendAt(&ping, 0);
    try std.testing.expectEqual(@as(usize, 5), client.pendingRecoveryCount());

    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }

    var fifth = try server.receivePacket();
    defer fifth.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), fifth.packet.packet_number);
    try server.sendAck(0);

    var ack_packet = try client.receivePacketAt(1);
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expect(client.sent.packets.items[0].lost);
    try std.testing.expect(client.sent.packets.items[1].lost);
    try std.testing.expect(!client.sent.packets.items[2].lost);
    try std.testing.expect(client.sent.packets.items[4].acknowledged);
    try std.testing.expectEqual(@as(usize, 4), client.pendingRecoveryCount());

    try std.testing.expect(try client.retransmitPacketThresholdLoss());
    var first_retransmit = try server.receivePacket();
    defer first_retransmit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), first_retransmit.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());

    try std.testing.expect(try client.retransmitPacketThresholdLoss());
    var second_retransmit = try server.receivePacket();
    defer second_retransmit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), second_retransmit.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[1].packetCount());
    try std.testing.expect(!(try client.retransmitPacketThresholdLoss()));

    try server.sendAck(0);
    var second_ack = try client.receivePacket();
    defer second_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), second_ack.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), second_ack.frames[0].ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u64, 2), client.recovery.pending.items[0].packetNumberAt(0).?);
}

test "QUIC 1-RTT ACK does not grow an underutilized congestion window" {
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

    const client_cid = [_]u8{ 0x8a, 0x8b, 0x8c, 0x8d };
    const server_cid = [_]u8{ 0x8e, 0x8f, 0x90, 0x91 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xba} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbb} ** quic.protection.secret_len,
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

    const initial_window = client.congestionWindow();
    try client.sendAt(&.{.{ .ping = {} }}, 1);
    try std.testing.expect(!client.congestion.isCongestionWindowUtilized());
    var ping = try server.receivePacket();
    defer ping.deinit(allocator);
    try server.sendAck(0);
    var ack = try client.receivePacketAt(100_000_001);
    defer ack.deinit(allocator);

    try std.testing.expect(client.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight());
    try std.testing.expectEqual(initial_window, client.congestionWindow());
}

test "QUIC 1-RTT timer-servicing receive drains packet-threshold retransmissions" {
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

    const client_cid = [_]u8{ 0x42, 0x43, 0x44, 0x45 };
    const server_cid = [_]u8{ 0x46, 0x47, 0x48, 0x49 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xad} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xae} ** quic.protection.secret_len,
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

    const ping = [_]quic.Frame{.{ .ping = {} }};
    for (0..5) |_| try client.send(&ping);
    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var fifth = try server.receivePacket();
    defer fifth.deinit(allocator);
    try server.sendAck(0);
    // The blocking transport pump owns ACK-driven recovery. Callers should
    // receive the ACK and repaired payload as one transport-level progress
    // step instead of remembering a second protocol-specific recovery call.
    var ack_packet = try client.receivePacketServicingTimers();
    defer ack_packet.deinit(allocator);

    try std.testing.expectEqual(
        @as(usize, 0),
        try client.retransmitPacketThresholdLosses(8),
    );
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), first.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 6), second.packet.packet_number);
    try std.testing.expectEqual(
        @as(usize, 0),
        try client.retransmitPacketThresholdLosses(8),
    );
}

test "QUIC 1-RTT ACK-driven recovery defers transactionally when paced" {
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

    const client_cid = [_]u8{ 0x4a, 0x4b, 0x4c, 0x4d };
    const server_cid = [_]u8{ 0x4e, 0x4f, 0x50, 0x51 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xaf} ** quic.protection.secret_len,
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
    for (0..5) |_| try client.send(&ping);
    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var fifth = try server.receivePacket();
    defer fifth.deinit(allocator);
    try server.sendAck(0);

    // Pin the pacer's last-send timestamp in the future so processing the ACK
    // can identify loss but cannot immediately send a repair. A retryable
    // pacing result must not consume packet number 5 or an AEAD nonce.
    client.pacer.budget = 0;
    client.pacer.setLastSentTimeNs(std.math.maxInt(u64));
    const next_packet_number = client.next_packet_number;
    const encrypted_packets = client.encryptedPacketsWithCurrentKeys();
    var ack = try client.receivePacketServicingTimers();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(next_packet_number, client.next_packet_number);
    try std.testing.expectEqual(
        encrypted_packets,
        client.encryptedPacketsWithCurrentKeys(),
    );
    try std.testing.expectEqual(@as(usize, 4), client.pendingRecoveryCount());
    for (client.recovery.pending.items) |pending| {
        try std.testing.expectEqual(@as(usize, 1), pending.packetCount());
    }

    client.pacer.enabled = false;
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.retransmitPacketThresholdLosses(8),
    );
    try std.testing.expectEqual(next_packet_number + 2, client.next_packet_number);
}

test "QUIC held-packet flush failure cannot roll back visible successor" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var held_once = false;
    const HoldFirst = struct {
        fn hold(context: *anyopaque, _: []const u8) bool {
            const held: *bool = @ptrCast(@alignCast(context));
            if (held.*) return false;
            held.* = true;
            return true;
        }
    };
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
        .{
            .max_datagram_size = 4096,
            .enable_gso_send = false,
            .send_interceptor = .{
                .context = &held_once,
                .should_hold = HoldFirst.hold,
            },
        },
    );
    defer client_endpoint.deinit();

    const FailSecondSocketSend = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.calls == 2) return .{ error.NetworkDown, 0 };
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var failing = FailSecondSocketSend{ .delegate = client_endpoint.io };
    var vtable = failing.delegate.vtable.*;
    vtable.netSend = FailSecondSocketSend.netSend;
    client_endpoint.io = .{ .userdata = &failing, .vtable = &vtable };
    defer client_endpoint.io = failing.delegate;

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer client.deinit();

    try client.send(&.{.{ .ping = {} }});
    try client.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(@as(usize, 2), failing.calls);
    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());

    var received = try server_endpoint.receiveBytes();
    defer received.deinit(allocator);
    var opened = try quic.protection.openShortPacket(
        allocator,
        keys,
        received.bytes,
        "server".len,
        0,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), opened.packet_number);
}

test "QUIC single packet socket failure skips sealed nonce only" {
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
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .enable_pacing = false,
        .tls_handshake_complete = true,
    });
    defer client.deinit();

    var failed = ObservedBatchSend{
        .delegate = client_endpoint.io,
        .fail_after_prefix = 0,
    };
    client_endpoint.io = failed.io();
    defer client_endpoint.io = failed.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        client.send(&.{.{ .stream = .{
            .stream_id = 0,
            .data = "failed",
        } }}),
    );
    try std.testing.expectEqual(@as(u64, 1), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 1), client.encryptedPacketsWithCurrentKeys());
    try std.testing.expectEqual(@as(u64, 0), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 0),
        one_rtt.testing.sendStreamUsed(&client, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 0).?,
    );
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), client.sent.packets.items.len);

    client_endpoint.io = failed.delegate;
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "retry-safe",
    } }});
    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
    var received = try server_endpoint.receiveBytes();
    defer received.deinit(allocator);
    var opened = try quic.protection.openShortPacket(
        allocator,
        keys,
        received.bytes,
        "server".len,
        0,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), opened.packet_number);
}

test "QUIC 1-RTT connection applies persistent congestion response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x6a, 0x6b, 0x6c, 0x6d };
    const server_cid = [_]u8{ 0x6e, 0x6f, 0x70, 0x71 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x6c} ** quic.protection.secret_len);

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
    try client.sendAt(&ping, 0);
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try server.sendAck(0);

    var first_ack = try client.receivePacketAt(100_000_000);
    defer first_ack.deinit(allocator);
    try std.testing.expect(client.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(?u64, 0), client.rtt_stats.first_rtt_sample_sent_time_ns);

    try client.sendAt(&ping, 200_000_000); // packet 1, first lost boundary after the RTT sample.
    try client.sendAt(&ping, 500_000_000); // packet 2, interior lost packet.
    try client.sendAt(&ping, 1_200_000_000); // packet 3, last lost boundary.
    try client.sendAt(&ping, 1_300_000_000); // packet 4, largest acknowledged.

    for (0..3) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var acknowledged = try server.receivePacket();
    defer acknowledged.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), acknowledged.packet.packet_number);

    client.congestion.congestion_window = 24_000;
    client.congestion.slow_start_threshold = 24_000;
    client.pacer.budget = 0;
    client.pacer.setLastSentTimeNs(1_300_000_000);
    try server.sendAck(0);

    var ack = try client.receivePacketAt(1_400_000_000);
    defer ack.deinit(allocator);
    try std.testing.expectEqual(client.pacer.maxBurstSize(), client.pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), client.pacer.lastSentTimeNs());
    try std.testing.expect(try client.retransmitTimeThresholdLoss(1_400_000_000, client.rtt_stats.lossDelay()));

    try std.testing.expect(client.sent.packets.items[1].lost);
    try std.testing.expect(client.sent.packets.items[2].lost);
    try std.testing.expect(client.sent.packets.items[3].lost);
    try std.testing.expectEqual(quic.congestion.minimumWindow(client.config.max_datagram_size), client.congestion.congestion_window);
    try std.testing.expectEqual(@as(?u64, null), client.rtt_stats.first_rtt_sample_sent_time_ns);
    try std.testing.expectEqual(@as(?u64, 3), client.last_persistent_congestion_packet_number);

    // Each distinct lost recovery group is retransmitted. Drain all three so
    // the next ACK targets the fresh RTT probe rather than an older datagram.
    for (5..8) |packet_number| {
        var retransmitted = try server.receivePacket();
        defer retransmitted.deinit(allocator);
        try std.testing.expectEqual(
            @as(u64, packet_number),
            retransmitted.packet.packet_number,
        );
    }

    const old_min = client.rtt_stats.min_rtt;
    try client.sendAt(&ping, 1_500_000_000);
    var sample_packet = try server.receivePacket();
    defer sample_packet.deinit(allocator);
    try server.sendAck(0);

    var sample_ack = try client.receivePacketAt(1_700_000_000);
    defer sample_ack.deinit(allocator);
    try std.testing.expect(old_min != 200_000_000);
    try std.testing.expectEqual(@as(u64, 200_000_000), client.rtt_stats.min_rtt);
    try std.testing.expectEqual(@as(u64, 200_000_000), client.rtt_stats.smoothed_rtt);
    try std.testing.expectEqual(@as(?u64, 1_500_000_000), client.rtt_stats.first_rtt_sample_sent_time_ns);
}

test "QUIC 1-RTT connection emits DATA_BLOCKED and applies MAX_DATA" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const server_cid = [_]u8{ 0x15, 0x16, 0x17, 0x18 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x82} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 5,
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

    const too_much = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "123456", .fin = false } }};
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), blocked.frames[0].data_blocked.maximum_data);
    const blocked_stats = client.stats();
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    // DATA_BLOCKED is advisory. Repeating it at the same unchanged limit would
    // amplify an application retry loop into network traffic, so the sender
    // suppresses duplicates until MAX_DATA advances the limit.
    try std.testing.expectEqual(blocked_stats.packets_sent, client.stats().packets_sent);

    const grant = [_]quic.Frame{.{ .max_data = .{ .maximum_data = 10 } }};
    try server.send(&grant);
    var grant_packet = try client.receivePacket();
    defer grant_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 10), client.send_flow.limit);

    try client.send(&too_much);
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("123456", data.frames[0].stream.data);
}

test "QUIC bounded send acknowledges flow-control progress packets" {
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

    const client_cid = [_]u8{ 0x19, 0x1a, 0x1b, 0x1c };
    const server_cid = [_]u8{ 0x1d, 0x1e, 0x1f, 0x20 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x83} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x84} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 5,
        .initial_send_max_stream_data = 5,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const before_deadline_rejection = client.stats();
    try std.testing.expectError(
        error.Timeout,
        client.sendWithTimeout(&.{.{ .stream = .{
            .stream_id = 0,
            .data = "123456",
        } }}, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.sendWithDeadline(&.{.{ .stream = .{
            .stream_id = 0,
            .data = "123456",
        } }}, .{ .clock = .real, .raw = .zero }),
    );
    try std.testing.expectEqual(
        before_deadline_rejection.packets_sent,
        client.stats().packets_sent,
    );
    try std.testing.expectEqual(
        before_deadline_rejection.active_send_streams,
        client.stats().active_send_streams,
    );

    try server.send(&.{
        .{ .max_data = .{ .maximum_data = 10 } },
        .{ .max_stream_data = .{
            .stream_id = 0,
            .maximum_stream_data = 10,
        } },
        .{ .stream = .{
            .stream_id = 1,
            .data = "queued",
            .fin = true,
        } },
    });
    try std.testing.expectEqual(@as(usize, 1), server.pendingRecoveryCount());

    try client.sendWithDeadline(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "123456",
    } }}, .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    }));

    var saw_blocked = false;
    var saw_ack = false;
    var saw_stream = false;
    for (0..3) |_| {
        var packet = try server.receivePacket();
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .data_blocked => saw_blocked = true,
            .ack => saw_ack = true,
            .stream => |stream| {
                try std.testing.expectEqual(@as(u64, 0), stream.stream_id);
                try std.testing.expectEqualStrings("123456", stream.data);
                saw_stream = true;
            },
            else => {},
        };
    }
    try std.testing.expect(saw_blocked);
    try std.testing.expect(saw_ack);
    try std.testing.expect(saw_stream);
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());
    var queued: ["queued".len]u8 = undefined;
    const queued_event = (try client.pollStreamId(1, &queued)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(queued_event == .data);
    try std.testing.expectEqualStrings("queued", &queued);
    try std.testing.expect(queued_event.data.fin);
}

test "QUIC bounded stream send consumes positive credit tails" {
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

    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 5,
        .initial_send_max_stream_data = 5,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_data = 5,
        .receive_window = 5,
        .initial_receive_max_stream_data = 5,
        .stream_receive_window = 5,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    var expired_committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendStreamWithTimeout(
            4,
            0,
            "x",
            true,
            &expired_committed,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), expired_committed);
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamUsed(&client, 4),
    );

    var timed_committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendStreamWithTimeout(
            4,
            0,
            "123456",
            true,
            &timed_committed,
            .fromMilliseconds(5),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), timed_committed);
    try std.testing.expectEqual(
        @as(?u64, 5),
        one_rtt.testing.sendStreamUsed(&client, 4),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamFinalSize(&client, 4),
    );
    var timed_prefix: [5]u8 = undefined;
    const timed_event = try server.receiveStreamIdWithDeadline(
        4,
        &timed_prefix,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expect(timed_event == .data);
    try std.testing.expectEqualStrings("12345", &timed_prefix);
    try std.testing.expect(!timed_event.data.fin);
    var timed_resumed: usize = 99;
    try client.sendStreamWithDeadline(
        4,
        timed_committed,
        "6",
        true,
        &timed_resumed,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 1), timed_resumed);
    var timed_suffix: [1]u8 = undefined;
    const timed_final = try server.receiveStreamIdWithDeadline(
        4,
        &timed_suffix,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expect(timed_final == .data);
    try std.testing.expectEqualStrings("6", &timed_suffix);
    try std.testing.expect(timed_final.data.fin);

    const payload = "hello world!";
    const Shared = struct {
        server: *one_rtt.Connection,
        received: [payload.len]u8 = undefined,
        chunks: [3]usize = @splat(0),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const deadline = std.Io.Clock.Timestamp.fromNow(
                self.server.endpoint.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            );
            var offset: usize = 0;
            var chunk_count: usize = 0;
            var fin = false;
            while (!fin) {
                const event = try self.server.receiveStreamIdWithDeadline(
                    0,
                    self.received[offset..],
                    deadline,
                );
                const data = switch (event) {
                    .reset => return error.TestUnexpectedResult,
                    .data => |value| value,
                };
                if (chunk_count == self.chunks.len) {
                    return error.TestUnexpectedResult;
                }
                self.chunks[chunk_count] = data.bytes;
                chunk_count += 1;
                offset += data.bytes;
                fin = data.fin;
            }
            try std.testing.expectEqual(payload.len, offset);
            try std.testing.expectEqualSlices(u8, payload, &self.received);
            try std.testing.expectEqualSlices(
                usize,
                // The preceding timeout/resume case consumed one byte of
                // connection credit. The first chunk therefore exercises the
                // four-byte connection tail; later chunks exercise the full
                // five-byte stream window.
                &.{ 4, 5, 3 },
                self.chunks[0..chunk_count],
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var committed: usize = 99;
    try client.sendStreamWithDeadline(
        0,
        0,
        payload,
        true,
        &committed,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expectEqual(payload.len, committed);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "QUIC STREAM sender retains payload when only the header fits capacity" {
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
        [_]u8{0xa3} ** quic.protection.secret_len,
    );
    const stream_id: u64 = 1 << 14;
    const stream_count = (stream_id >> 2) + 1;
    const offset: u64 = 1 << 30;
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "capacity-client",
        .peer_connection_id = "capacity-server",
        .initial_send_max_streams_bidi = stream_count,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "capacity-server",
        .peer_connection_id = "capacity-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = stream_count,
        .enable_pacing = false,
    });
    defer server.deinit();

    const header_only = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_id,
        .offset = offset,
        .data = &.{},
    } }};
    const one_byte = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_id,
        .offset = offset,
        .data = "x",
    } }};
    const header_packet_len = try client.packetLenForFramesAtOffset(
        0,
        &header_only,
    );
    const payload_packet_len = try client.packetLenForFramesAtOffset(
        0,
        &one_byte,
    );
    try std.testing.expectEqual(header_packet_len + 1, payload_packet_len);

    const initial_window = client.congestion.congestion_window;
    const initial_connection_credit = client.connectionSendAvailable();
    client.congestion.congestion_window = header_packet_len;
    try std.testing.expectError(
        error.CongestionLimited,
        client.trySend(&one_byte),
    );
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight());
    try std.testing.expectEqual(
        initial_connection_credit,
        client.connectionSendAvailable(),
    );
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expectEqual(
        @as(u64, 0),
        client.stats().outgoing_streams_created,
    );
    try std.testing.expect(client.getSendStreamStats(stream_id) == null);

    client.congestion.congestion_window = initial_window;
    try client.trySend(&one_byte);
    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), received.frames.len);
    try std.testing.expect(received.frames[0] == .stream);
    try std.testing.expectEqual(offset, received.frames[0].stream.offset);
    try std.testing.expectEqualStrings("x", received.frames[0].stream.data);
    try std.testing.expectEqual(
        offset + 1,
        client.getSendStreamStats(stream_id).?.highest_sent_offset,
    );
}

test "QUIC bounded stream send reports socket-visible prefix" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

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
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_cid = [_]u8{ 0x55, 0x56, 0x57, 0x58 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa3} ** quic.protection.secret_len,
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

    var payload: [2000]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var failed = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    send_io.send_context = &failed;
    send_io.send_override = ObservedBatchSend.netSend;
    client.endpoint.io = send_io.io();
    defer client.endpoint.io = failed.delegate;

    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        client.sendStreamWithDeadline(
            0,
            0,
            &payload,
            true,
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        ),
    );
    try std.testing.expect(committed > 0);
    try std.testing.expect(committed < payload.len);
    try std.testing.expectEqual(
        @as(?u64, committed),
        one_rtt.testing.sendStreamUsed(&client, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, committed),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamFinalSize(&client, 0),
    );

    client.endpoint.io = failed.delegate;
    var resumed: usize = 99;
    try client.sendStreamWithTimeout(
        0,
        committed,
        payload[committed..],
        true,
        &resumed,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(payload.len - committed, resumed);
    try std.testing.expectEqual(
        @as(?u64, payload.len),
        one_rtt.testing.sendStreamFinalSize(&client, 0),
    );

    var received: [payload.len]u8 = undefined;
    var offset: usize = 0;
    var fin = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    );
    while (!fin) {
        const event = try server.receiveStreamIdWithDeadline(
            0,
            received[offset..],
            deadline,
        );
        const data = switch (event) {
            .reset => return error.TestUnexpectedResult,
            .data => |value| value,
        };
        offset += data.bytes;
        fin = data.fin;
    }
    try std.testing.expectEqual(payload.len, offset);
    try std.testing.expectEqualSlices(u8, &payload, &received);

    var empty_fin_committed: usize = 99;
    try client.sendStream(
        4,
        0,
        &.{},
        true,
        &empty_fin_committed,
    );
    try std.testing.expectEqual(@as(usize, 0), empty_fin_committed);
    var empty: [1]u8 = undefined;
    const empty_fin = try server.receiveStreamIdWithDeadline(
        4,
        &empty,
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    try std.testing.expect(empty_fin == .data);
    try std.testing.expectEqual(@as(usize, 0), empty_fin.data.bytes);
    try std.testing.expect(empty_fin.data.fin);
}

test "QUIC bounded stream slices cross boundaries and resume exact suffix" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa4} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .max_datagram_size = 512,
        .max_frames_per_packet = 4,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_frames_per_packet = 4,
        .enable_pacing = false,
    });
    defer server.deinit();

    var body: [2000]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @truncate(index);
    const parts = [_][]const u8{ "ab", &.{}, &body, "tail" };
    const total_len = 2 + body.len + 4;
    var expected: [total_len]u8 = undefined;
    @memcpy(expected[0..2], "ab");
    @memcpy(expected[2..][0..body.len], &body);
    @memcpy(expected[2 + body.len ..], "tail");

    var expired_committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendStreamSlicesWithTimeout(
            4,
            0,
            &parts,
            true,
            &expired_committed,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), expired_committed);
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamUsed(&client, 4),
    );

    var failed = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed;
    send_io.send_override = ObservedBatchSend.netSend;
    client.endpoint.io = send_io.io();
    defer client.endpoint.io = failed.delegate;

    var zero_committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        client.sendStreamSlicesWithDeadline(
            4,
            0,
            &parts,
            true,
            &zero_committed,
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), zero_committed);
    try std.testing.expectEqual(
        @as(?u64, 0),
        one_rtt.testing.sendStreamUsed(&client, 4),
    );
    try std.testing.expectEqual(
        @as(?u64, 0),
        one_rtt.testing.sendStreamHighestSentEnd(&client, 4),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamFinalSize(&client, 4),
    );

    failed.fail_after_prefix = 1;
    failed.calls = 0;
    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        client.sendStreamSlicesWithDeadline(
            0,
            0,
            &parts,
            true,
            &committed,
            .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
        ),
    );
    try std.testing.expect(committed > parts[0].len);
    try std.testing.expect(committed < total_len);
    try std.testing.expectEqual(@as(usize, 1), failed.calls);
    try std.testing.expectEqual(@as(usize, 1), failed.last_message_count);
    try std.testing.expectEqual(
        @as(?u64, committed),
        one_rtt.testing.sendStreamUsed(&client, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamFinalSize(&client, 0),
    );

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expect(first.frames.len > 1);
    try std.testing.expectEqualStrings("ab", first.frames[0].stream.data);

    client.endpoint.io = failed.delegate;
    var resumed: usize = 99;
    const body_offset = committed - parts[0].len;
    try client.sendStreamSlicesWithTimeout(
        0,
        committed,
        &.{ body[body_offset..], "tail" },
        true,
        &resumed,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(total_len - committed, resumed);
    try std.testing.expectEqual(
        @as(?u64, total_len),
        one_rtt.testing.sendStreamFinalSize(&client, 0),
    );

    var received: [total_len]u8 = undefined;
    var received_len: usize = 0;
    var finished = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    );
    while (!finished) {
        const event = try server.receiveStreamIdWithDeadline(
            0,
            received[received_len..],
            deadline,
        );
        const data = switch (event) {
            .reset => return error.TestUnexpectedResult,
            .data => |value| value,
        };
        received_len += data.bytes;
        finished = data.fin;
    }
    try std.testing.expectEqual(total_len, received_len);
    try std.testing.expectEqualSlices(u8, &expected, &received);

    var empty_fin_committed: usize = 99;
    try client.sendStreamSlices(8, 0, &.{ &.{}, &.{} }, true, &empty_fin_committed);
    try std.testing.expectEqual(@as(usize, 0), empty_fin_committed);
    try std.testing.expectEqual(
        @as(?u64, 0),
        one_rtt.testing.sendStreamFinalSize(&client, 8),
    );
    var empty: [1]u8 = undefined;
    const empty_fin = try server.receiveStreamIdWithDeadline(
        8,
        &empty,
        deadline,
    );
    try std.testing.expect(empty_fin == .data);
    try std.testing.expectEqual(@as(usize, 0), empty_fin.data.bytes);
    try std.testing.expect(empty_fin.data.fin);

    var tiny_parts: [34][]const u8 = undefined;
    var tiny_storage: [32][1]u8 = undefined;
    tiny_parts[0] = &.{};
    for (&tiny_storage, 0..) |*part, index| {
        part[0] = @intCast(index);
        tiny_parts[index + 1] = part;
    }
    tiny_parts[tiny_parts.len - 1] = &.{};
    var many_committed: usize = 99;
    try client.sendStreamSlices(12, 0, &tiny_parts, true, &many_committed);
    try std.testing.expectEqual(tiny_storage.len, many_committed);
    var many_received: [tiny_storage.len]u8 = undefined;
    var many_len: usize = 0;
    var many_fin = false;
    while (!many_fin) {
        const event = try server.receiveStreamIdWithDeadline(
            12,
            many_received[many_len..],
            deadline,
        );
        const data = switch (event) {
            .reset => return error.TestUnexpectedResult,
            .data => |value| value,
        };
        many_len += data.bytes;
        many_fin = data.fin;
    }
    try std.testing.expectEqual(tiny_storage.len, many_len);
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&tiny_storage),
        &many_received,
    );
}

test "QUIC bounded stream slices report credit-spanning timeout prefix" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    const local_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const peer_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa5} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .initial_send_max_data = 5,
        .initial_send_max_stream_data = 5,
        .enable_pacing = false,
    });
    defer sender.deinit();

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sender.sendStreamSlicesWithTimeout(
            0,
            0,
            &.{ "ab", &.{}, "cdef" },
            true,
            &committed,
            .fromMilliseconds(5),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), committed);
    try std.testing.expectEqual(
        @as(?u64, 5),
        one_rtt.testing.sendStreamHighestSentEnd(&sender, 0),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamFinalSize(&sender, 0),
    );

    const packets_before = sender.stats().packets_sent;
    const overflow_offset = quic.varint.max_value - 1;
    try std.testing.expectError(
        error.InvalidFrameLength,
        sender.sendStreamSlicesWithTimeout(
            4,
            overflow_offset,
            &.{ "a", "bc" },
            false,
            &committed,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(packets_before, sender.stats().packets_sent);
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamUsed(&sender, 4),
    );

    _ = try one_rtt.testing.clampSendStreamLimitToUsed(&sender, 4);
    try one_rtt.testing.applyReceivedFrames(
        &sender,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 15 } },
            .{ .max_stream_data = .{
                .stream_id = 4,
                .maximum_stream_data = 10,
            } },
        },
        null,
        .not_ect,
    );
    var sparse_committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sender.sendStreamSlicesWithTimeout(
            4,
            5,
            &.{ "ab", "cdefghij" },
            false,
            &sparse_committed,
            .fromMilliseconds(5),
        ),
    );
    // The five-byte gap plus five new payload bytes consume the entire
    // ten-byte stream/connection window; the untouched suffix is retryable.
    try std.testing.expectEqual(@as(usize, 5), sparse_committed);
    try std.testing.expectEqual(
        @as(?u64, 10),
        one_rtt.testing.sendStreamUsed(&sender, 4),
    );
    try std.testing.expectEqual(
        @as(?u64, 10),
        one_rtt.testing.sendStreamHighestSentEnd(&sender, 4),
    );
}

test "QUIC ordinary send preserves final size validation after credit planning" {
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
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa6} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "final-client",
        .peer_connection_id = "final-server",
        .enable_pacing = false,
    });
    defer sender.deinit();

    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "done",
        .fin = true,
    } }});
    const packets_before = sender.stats().packets_sent;
    try std.testing.expectError(
        error.FinalSizeMismatch,
        sender.send(&.{.{ .stream = .{
            .stream_id = 0,
            .offset = 4,
            .data = "x",
        } }}),
    );
    try std.testing.expectEqual(packets_before, sender.stats().packets_sent);
    try std.testing.expectEqual(
        @as(?u64, 4),
        one_rtt.testing.sendStreamFinalSize(&sender, 0),
    );

    const same_packet = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 4,
            .data = "a",
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 4,
            .offset = 1,
            .data = "b",
        } },
    };
    try std.testing.expectError(
        error.FinalSizeMismatch,
        sender.send(&same_packet),
    );
    try std.testing.expectEqual(packets_before, sender.stats().packets_sent);
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamUsed(&sender, 4),
    );

    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 8,
        .data = "a",
        .fin = true,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 8,
        .offset = 1,
        .data = "b",
    } }};
    try std.testing.expectError(
        error.FinalSizeMismatch,
        sender.sendMany(&.{ &first, &second }),
    );
    try std.testing.expectEqual(packets_before, sender.stats().packets_sent);
    try std.testing.expectEqual(
        @as(?u64, null),
        one_rtt.testing.sendStreamUsed(&sender, 8),
    );
}

test "QUIC 1-RTT connection handles stream-level flow control" {
    const allocator = std.testing.allocator;

    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x25, 0x26, 0x27, 0x28 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x92} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_stream_data = 3,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_stream_data = 6,
        .stream_receive_window = 6,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const too_much = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcd", .fin = false } }};
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), blocked.frames[0].stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 3), blocked.frames[0].stream_data_blocked.maximum_stream_data);
    const blocked_stats = client.stats();
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    try std.testing.expectEqual(blocked_stats.packets_sent, client.stats().packets_sent);

    const grant = [_]quic.Frame{.{ .max_stream_data = .{ .stream_id = 0, .maximum_stream_data = 8 } }};
    try server.send(&grant);
    var grant_packet = try client.receivePacket();
    defer grant_packet.deinit(allocator);

    try client.send(&too_much);
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", data.frames[0].stream.data);
    const max_stream = (try server.consumeStreamReceived(0, 4)).?;
    try std.testing.expectEqual(@as(u64, 0), max_stream.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 10), max_stream.max_stream_data.maximum_stream_data);

    const split_blocked = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 4,
            .data = "abc",
        } },
        .{ .stream = .{
            .stream_id = 4,
            .offset = 3,
            .data = "def",
        } },
    };
    try std.testing.expectError(
        error.FlowControlBlocked,
        client.send(&split_blocked),
    );
    var split_blocked_packet = try server.receivePacket();
    defer split_blocked_packet.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 4),
        split_blocked_packet.frames[0].stream_data_blocked.stream_id,
    );
    try std.testing.expectEqual(
        @as(u64, 3),
        split_blocked_packet.frames[0].stream_data_blocked.maximum_stream_data,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        one_rtt.testing.sendStreamUsed(&client, 4).?,
    );

    // The combined helper advances retained overlap-validation storage and
    // emits both connection- and stream-level credit transactionally.
    var combined_server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer combined_server_endpoint.deinit();
    var combined_client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer combined_client_endpoint.deinit();
    const combined_client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const combined_server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    var combined_client = try one_rtt.Connection.init(&combined_client_endpoint, .{
        .peer = combined_server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &combined_client_cid,
        .peer_connection_id = &combined_server_cid,
        .initial_send_max_data = 8,
        .initial_send_max_stream_data = 8,
    });
    defer combined_client.deinit();
    var combined_server = try one_rtt.Connection.init(&combined_server_endpoint, .{
        .peer = combined_client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &combined_server_cid,
        .peer_connection_id = &combined_client_cid,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .local_endpoint = .server,
    });
    defer combined_server.deinit();
    try combined_client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "123456",
    } }});
    var combined_data = try combined_server.receivePacket();
    defer combined_data.deinit(allocator);

    var failed_credit_send = ObservedBatchSend{
        .delegate = combined_server.endpoint.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed_credit_send;
    send_io.send_override = ObservedBatchSend.netSend;
    combined_server.endpoint.io = send_io.io();
    try std.testing.expectError(
        error.NetworkDown,
        combined_server.releaseReceivedCapacity(0, 6),
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        combined_server.recv_flow.limit,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        combined_server.recv_flow.consumed,
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        one_rtt.testing.receiveStreamLimit(&combined_server, 0).?,
    );
    try std.testing.expectEqual(
        @as(usize, 6),
        one_rtt.testing.receiveStreamAvailableLen(&combined_server, 0).?,
    );
    combined_server.endpoint.io = failed_credit_send.delegate;

    try combined_server.releaseReceivedCapacity(0, 6);
    try std.testing.expectEqual(
        @as(usize, 0),
        one_rtt.testing.receiveStreamAvailableLen(&combined_server, 0).?,
    );
    var credit = try combined_client.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), credit.frames.len);
    try std.testing.expectEqual(@as(u64, 14), credit.frames[0].max_data.maximum_data);
    try std.testing.expectEqual(
        @as(u64, 14),
        credit.frames[1].max_stream_data.maximum_stream_data,
    );
    try std.testing.expectEqual(@as(u64, 14), combined_client.send_flow.limit);
    try std.testing.expectEqual(
        @as(u64, 14),
        one_rtt.testing.sendStreamLimit(&combined_client, 0).?,
    );

    // A shared-endpoint response can return the just-consumed request credit
    // in the same packet. Pacing failure must preserve both the response
    // stream and receive cursor so the whole admission can be retried.
    var transactional_server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer transactional_server_endpoint.deinit();
    var transactional_peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer transactional_peer_endpoint.deinit();
    var transactional = try one_rtt.Connection.init(
        &transactional_server_endpoint,
        .{
            .peer = transactional_peer_endpoint.address(),
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = "transactional-server",
            .peer_connection_id = "transactional-peer",
            .local_endpoint = .server,
            .initial_receive_max_data = 8,
            .receive_window = 8,
            .initial_receive_max_stream_data = 8,
            .stream_receive_window = 8,
            .max_datagram_size = 1200,
            .pacing_max_burst_packets = 1,
        },
    );
    defer transactional.deinit();
    try one_rtt.testing.applyReceivedFrames(
        &transactional,
        0,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = "123456",
        } }},
        1_000_000,
        .not_ect,
    );
    const pacing_now: u64 = @intCast(@max(
        @as(i96, 0),
        std.Io.Clock.awake.now(io).nanoseconds,
    ));
    try transactional.sendAt(
        &.{.{ .padding = .{ .len = 1160 } }},
        pacing_now,
    );
    const before_packet_number = transactional.next_packet_number;
    const response_data = [_]u8{0xa5} ** 128;
    const response = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = &response_data,
    } }};
    try std.testing.expectError(
        error.PacingLimited,
        transactional.trySendAndReleaseReceivedCapacity(
            0,
            6,
            response[0],
        ),
    );
    try std.testing.expectEqual(
        before_packet_number,
        transactional.next_packet_number,
    );
    try std.testing.expectEqual(
        @as(usize, 6),
        one_rtt.testing.receiveStreamAvailableLen(&transactional, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        one_rtt.testing.receiveStreamLimit(&transactional, 0).?,
    );
    const retry_at = transactional.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pacing,
        retry_at.kind,
    );
    try one_rtt.testing.trySendAndReleaseReceivedCapacityAt(
        &transactional,
        0,
        6,
        response[0],
        retry_at.deadline_ns,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        one_rtt.testing.receiveStreamAvailableLen(&transactional, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 14),
        one_rtt.testing.receiveStreamLimit(&transactional, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, response_data.len),
        one_rtt.testing.sendStreamUsed(&transactional, 0).?,
    );

    var violating_server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer violating_server_endpoint.deinit();
    var violating_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer violating_client_endpoint.deinit();
    const violating_client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const violating_server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    var violating_server = try one_rtt.Connection.init(&violating_server_endpoint, .{
        .peer = violating_client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &violating_server_cid,
        .peer_connection_id = &violating_client_cid,
        .initial_receive_max_stream_data = 3,
        .stream_receive_window = 3,
        .local_endpoint = .server,
    });
    defer violating_server.deinit();

    try one_rtt.sendFrames(&violating_client_endpoint, violating_server_endpoint.address(), client_keys, .{
        .destination_connection_id = &violating_server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcd", .fin = false } }},
    });
    try std.testing.expectError(error.FlowControlViolation, violating_server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), violating_server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), violating_server.stream_recv_flows.items.len);
    try std.testing.expect(violating_server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.flow_control_error), violating_server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.stream) | 0x02), violating_server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("flow control", violating_server.close_info.?.reason_phrase);
}

test "QUIC 1-RTT connection enforces stream count limits and MAX_STREAMS" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 2,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "first", .fin = false } }});
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.frames[0].stream.data);

    try std.testing.expectError(error.StreamLimitExceeded, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "blocked", .fin = false } }}));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), blocked.frames[0].streams_blocked_bidi.maximum_streams);
    const blocked_stats = client.stats();
    try std.testing.expectError(error.StreamLimitExceeded, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "blocked", .fin = false } }}));
    try std.testing.expectEqual(blocked_stats.packets_sent, client.stats().packets_sent);

    try server.send(&[_]quic.Frame{.{ .max_streams_bidi = .{ .maximum_streams = 2 } }});
    var grant = try client.receivePacket();
    defer grant.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), client.peer_max_streams_bidi);

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "second", .fin = false } }});
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.frames[0].stream.data);

    try std.testing.expectError(error.StreamLimitExceeded, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 8, .data = "third", .fin = false } }}));
    var blocked_again = try server.receivePacket();
    defer blocked_again.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), blocked_again.frames[0].streams_blocked_bidi.maximum_streams);
}

test "QUIC socket-free stream open polling preserves blocked cursors" {
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
        [_]u8{0xa6} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "poll-local",
        .peer_connection_id = "poll-peer",
        .initial_send_max_streams_bidi = 1,
        .initial_send_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try std.testing.expectEqual(
        @as(?u64, 0),
        try connection.pollOpenStream(),
    );
    try std.testing.expectEqual(
        @as(?u64, 2),
        try connection.pollOpenUnidirectionalStream(),
    );
    const before = connection.stats();
    try std.testing.expectEqual(
        @as(?u64, null),
        try connection.pollOpenStream(),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        try connection.pollOpenUniStream(),
    );
    try std.testing.expectEqual(before.packets_sent, connection.stats().packets_sent);
    try std.testing.expectEqual(
        @as(u64, 4),
        connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(
        @as(u64, 6),
        connection.nextLocalUnidirectionalStreamId(),
    );

    connection.peer_max_streams_bidi = 2;
    connection.peer_max_streams_uni = 2;
    try std.testing.expectEqual(
        @as(?u64, 4),
        try connection.pollOpenStream(),
    );
    try std.testing.expectEqual(
        @as(?u64, 6),
        try connection.pollOpenUnidirectionalStream(),
    );
}

test "QUIC socket-free stream open polling rejects closed and idle connections" {
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
        [_]u8{0xa5} ** quic.protection.secret_len,
    );
    var closed = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "closed-local",
        .peer_connection_id = "closed-peer",
        .enable_pacing = false,
    });
    defer closed.deinit();
    try closed.closeApplication(0, "done");
    try std.testing.expectError(error.ConnectionClosed, closed.pollOpenStream());

    var idle = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "idle-local",
        .peer_connection_id = "idle-peer",
        .local_max_idle_timeout_ms = 1,
        .enable_pacing = false,
    });
    defer idle.deinit();
    idle.markActivity(0);
    try std.testing.expect(idle.checkIdleTimeout(std.math.maxInt(u64)));
    try std.testing.expectError(
        error.ConnectionClosed,
        idle.pollOpenUnidirectionalStream(),
    );
}

test "QUIC bounded stream open waits for cumulative MAX_STREAMS credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x25, 0x26, 0x27, 0x28 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try std.testing.expectEqual(@as(u64, 0), try client.openStream());
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "done",
        .fin = true,
    } }});

    const Shared = struct {
        server: *one_rtt.Connection,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(connection: *one_rtt.Connection) !void {
            var packet = try connection.receivePacket();
            defer packet.deinit(connection.endpoint.allocator);
            try connection.releaseReceivedCapacity(0, "done".len);
            // Complete the server's send half before returning the peer slot.
            try connection.resetStream(0, 1);
            // The reset has only been sent, not acknowledged. Requesting the
            // release now defers MAX_STREAMS until the peer's ACK arrives.
            try std.testing.expect(
                !try connection.releaseCompletedPeerStream(0),
            );
            while (connection.recv_max_streams_bidi == 1) {
                var progress = try connection.receivePacket();
                progress.deinit(connection.endpoint.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectEqual(
        @as(u64, 4),
        try client.openStreamWithTimeout(.fromSeconds(2)),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "QUIC bounded stream open does not outwait pacing deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa9} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "paced-local",
        .peer_connection_id = "paced-peer",
        .initial_send_max_streams_bidi = 0,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();

    // Exhaust the pacer's initial burst and use a synthetic long RTT so the
    // STREAMS_BLOCKED wakeup lies well beyond this operation's deadline.
    connection.rtt_stats.updateAt(
        10 * std.time.ns_per_s,
        0,
        true,
        0,
    );
    connection.pacer.budget = 0;
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    connection.pacer.setLastSentTimeNs(
        std.math.cast(u64, @max(now, 0)) orelse std.math.maxInt(u64),
    );
    const before = connection.stats();
    try std.testing.expectError(
        error.Timeout,
        connection.openStreamWithTimeout(.fromMilliseconds(2)),
    );
    try std.testing.expectEqual(
        before.packets_sent,
        connection.stats().packets_sent,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.stats().outgoing_streams_created,
    );
}

test "QUIC one-shot STREAM sends never wait for blocked notifications" {
    const FixedClockIo = struct {
        delegate: std.Io,
        now_ns: i96,
        sleep_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            return error.Canceled;
        }
    };
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
        [_]u8{0xaa} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "try-limit-local",
        .peer_connection_id = "try-limit-peer",
        .initial_send_max_streams_bidi = 0,
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();

    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    endpoint.io = .{ .userdata = &fixed_io, .vtable = &fixed_vtable };
    defer endpoint.io = fixed_io.delegate;

    one_rtt.testing.exhaustPacingAt(&connection, 1_000_000);
    const before = connection.stats();
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "blocked",
    } }};
    try std.testing.expectError(error.PacingLimited, connection.trySend(&frames));
    const packets = [_][]const quic.Frame{&frames};
    try std.testing.expectError(
        error.PacingLimited,
        connection.sendManyProgressAt(&packets, 1_000_000),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.waitForPacingAvailabilityWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(1_000_001),
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.waitForPacingAvailabilityWithDeadline(.{
            .clock = .real,
            .raw = .fromNanoseconds(std.time.ns_per_s),
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.waitForPacingAvailabilityWithTimeout(.fromNanoseconds(0)),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(before.packets_sent, connection.stats().packets_sent);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expect(connection.sendStreamStats(0) == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
}

test "QUIC bounded pacing wait rejects a later wake without sleeping" {
    const FixedClockIo = struct {
        delegate: std.Io,
        now_ns: i96,
        sleep_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            timeout: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            self.now_ns = switch (timeout) {
                .none => return error.Canceled,
                .duration => |duration| self.now_ns + duration.raw.nanoseconds,
                .deadline => |deadline| deadline.raw.nanoseconds,
            };
        }
    };
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xac} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pacing-wait-local",
        .peer_connection_id = "pacing-wait-peer",
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();
    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 1_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    endpoint.io = .{ .userdata = &fixed_io, .vtable = &fixed_vtable };
    defer endpoint.io = fixed_io.delegate;
    connection.rtt_stats.updateAt(
        10 * std.time.ns_per_s,
        0,
        true,
        0,
    );
    one_rtt.testing.exhaustPacingAt(
        &connection,
        1_000_000,
    );
    const frames = [_]quic.Frame{.{ .ping = {} }};
    try std.testing.expectError(error.PacingLimited, connection.trySend(&frames));
    const before = connection.stats();
    try std.testing.expectError(
        error.Timeout,
        connection.waitForPacingAvailabilityWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(1_000_001),
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(before.packets_sent, connection.stats().packets_sent);
    try connection.waitForPacingAvailabilityWithDeadline(.{
        .clock = .awake,
        .raw = .fromNanoseconds(60 * std.time.ns_per_s),
    });
    try std.testing.expectEqual(@as(usize, 1), fixed_io.sleep_calls);
    try connection.trySend(&frames);
    try std.testing.expectEqual(
        before.packets_sent + 1,
        connection.stats().packets_sent,
    );
}

test "QUIC bounded receive does not outwait timer pacing" {
    const FixedClockIo = struct {
        delegate: std.Io,
        now_ns: i96,
        sleep_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            return error.Canceled;
        }
    };
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xad} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-pace-local",
        .peer_connection_id = "timer-pace-peer",
        .local_endpoint = .server,
        .tls_handshake_complete = true,
        .keep_alive_period_ms = 1,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();
    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 300 * std.time.ns_per_ms,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    endpoint.io = .{ .userdata = &fixed_io, .vtable = &fixed_vtable };
    defer endpoint.io = fixed_io.delegate;

    connection.markPeerActivity(0);
    const keep_alive = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.keep_alive, keep_alive.kind);
    // RFC 9000's current application-data PTO includes the peer's advertised
    // max_ack_delay. Keep-alive raises its configured interval to 1.5x that
    // live PTO, so this assertion must not freeze an older RTT default.
    const pto_ns = connection.ptoPeriod();
    const keep_alive_floor_ns = pto_ns +| pto_ns / 2;
    const keep_alive_floor_ms = std.math.divCeil(
        u64,
        keep_alive_floor_ns,
        std.time.ns_per_ms,
    ) catch unreachable;
    try std.testing.expectEqual(
        keep_alive_floor_ms * std.time.ns_per_ms,
        keep_alive.deadline_ns,
    );
    fixed_io.now_ns = @intCast(keep_alive.deadline_ns);
    one_rtt.testing.exhaustPacingAt(&connection, keep_alive.deadline_ns);

    try std.testing.expectError(
        error.Timeout,
        connection.servicePacketServicingTimersDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(keep_alive.deadline_ns + 1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expect(!connection.keepAlivePingOutstanding());
}

test "QUIC batch stream-data blocked notification uses caller timestamp" {
    const FixedClockIo = struct {
        delegate: std.Io,
        now_ns: i96,
        sleep_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            userdata: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.sleep_calls += 1;
            return error.Canceled;
        }
    };
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xab} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "batch-block-local",
        .peer_connection_id = "batch-block-peer",
        .initial_send_max_streams_bidi = 1,
        .initial_send_max_stream_data_bidi_remote = 0,
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();

    var fixed_io = FixedClockIo{
        .delegate = endpoint.io,
        .now_ns = 2_000_000,
    };
    var fixed_vtable = endpoint.io.vtable.*;
    fixed_vtable.now = FixedClockIo.now;
    fixed_vtable.sleep = FixedClockIo.sleep;
    endpoint.io = .{ .userdata = &fixed_io, .vtable = &fixed_vtable };
    defer endpoint.io = fixed_io.delegate;

    one_rtt.testing.exhaustPacingAt(&connection, 2_000_000);
    const before = connection.stats();
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "blocked",
    } }};
    const packets = [_][]const quic.Frame{&frames};
    try std.testing.expectError(
        error.FlowControlBlocked,
        connection.sendManyProgressAt(
            &packets,
            2_000_000 + std.time.ns_per_s,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed_io.sleep_calls);
    try std.testing.expectEqual(
        before.packets_sent + 1,
        connection.stats().packets_sent,
    );
    const stream = connection.sendStreamStats(0) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
}

test "QUIC bounded stream open failures preserve the next ID" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    // Keep the peer socket deliberately silent. Pointing the connection back
    // at its own socket would make it authenticate its outgoing
    // STREAMS_BLOCKED packet with receive-direction keys.
    var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa8} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .initial_send_max_streams_uni = 0,
    });
    defer connection.deinit();

    const before = connection.stats();
    try std.testing.expectError(
        error.Timeout,
        connection.openUnidirectionalStreamWithDeadline(.{
            .raw = .fromNanoseconds(std.time.ns_per_s),
            .clock = .real,
        }),
    );
    try std.testing.expectEqual(
        before.packets_sent,
        connection.stats().packets_sent,
    );
    try std.testing.expectError(
        error.Timeout,
        connection.openUnidirectionalStreamWithTimeout(
            .fromMilliseconds(2),
        ),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.stats().outgoing_streams_created,
    );

    // Simulate the authenticated MAX_STREAMS state transition, then prove the
    // two failed waits did not skip the first client-uni ID.
    connection.peer_max_streams_uni = 1;
    try std.testing.expectEqual(
        @as(u64, 2),
        try connection.openUnidirectionalStream(),
    );
}

test "QUIC 1-RTT connection releases completed peer stream credit once" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb3} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "first",
        .fin = true,
    } }});
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try server.releaseReceivedCapacity(0, "first".len);
    try std.testing.expect(server.receivedStreamComplete(0));
    // A bidirectional stream is not closed until the local send half is also
    // terminal, even though all peer bytes have been consumed.
    try std.testing.expect(!try server.releaseCompletedPeerStream(0));

    try server.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "reply",
        .fin = true,
    } }});
    var reply = try client.receivePacket();
    defer reply.deinit(allocator);
    try std.testing.expectEqualStrings("reply", reply.frames[0].stream.data);
    try server.send(&.{.{ .ping = {} }});
    var later_ping = try client.receivePacket();
    defer later_ping.deinit(allocator);
    try std.testing.expect(later_ping.frames[0] == .ping);

    // A sent FIN is not terminal until acknowledged. The early release request
    // is remembered and completed automatically by ACK processing.
    try client.send(&.{.{ .ack = .{
        .largest_acknowledged = later_ping.packet.packet_number,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }});
    var unrelated_ack = try server.receivePacket();
    defer unrelated_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), server.recv_max_streams_bidi);

    try client.send(&.{.{ .ack = .{
        .largest_acknowledged = reply.packet.packet_number,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }});
    var reply_ack = try server.receivePacket();
    defer reply_ack.deinit(allocator);
    try std.testing.expect(server.peerStreamClosed(0));
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_receive_streams);
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_send_streams);
    try std.testing.expectEqual(@as(usize, 1), server.stats().closed_peer_stream_ranges);
    try std.testing.expect(server.recvStreamStats(0) == null);
    try std.testing.expect(server.sendStreamStats(0) == null);
    try std.testing.expectEqual(
        one_rtt.PeerStreamLifecycle.closed,
        server.peerStreamLifecycle(0),
    );
    try std.testing.expectEqual(
        one_rtt.PeerStreamLifecycle.unknown,
        server.peerStreamLifecycle(4),
    );
    try std.testing.expectEqual(@as(u64, 0), server.streamSendAvailable(0));
    try std.testing.expectError(
        error.StreamStateError,
        server.send(&.{.{ .stream = .{
            .stream_id = 0,
            .data = "reopen",
        } }}),
    );
    try std.testing.expectError(error.StreamStateError, server.resetStream(0, 9));
    try std.testing.expectError(
        error.StreamStateError,
        server.sendStopSending(0, 9),
    );
    const packets_after_release = server.stats().packets_sent;
    try std.testing.expect(!try server.releaseCompletedPeerStream(0));
    try std.testing.expectEqual(packets_after_release, server.stats().packets_sent);

    var credit = try client.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), credit.frames[0].max_streams_bidi.maximum_streams);
    try std.testing.expectEqual(@as(u64, 2), client.peer_max_streams_bidi);

    // Retransmission after compaction is ignored and cannot recreate either
    // transport-side stream entry.
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "first",
        .fin = true,
    } }});
    var late = try server.receivePacket();
    defer late.deinit(allocator);
    try std.testing.expect(server.peerStreamClosed(0));
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_receive_streams);
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_send_streams);

    try client.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = "second",
        .fin = true,
    } }});
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.frames[0].stream.data);
}

test "QUIC bounded STOP_SENDING validates deadline before commit" {
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
    const server_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
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

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "payload",
    } }});
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try std.testing.expect(server.recvStreamStats(0).?.stop_sending_sent == null);
    const before = server.stats();

    try std.testing.expectError(
        error.Timeout,
        server.sendStopSendingWithDeadline(0, 77, .{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        server.sendStopSendingWithTimeout(0, 77, .zero),
    );
    try std.testing.expectEqual(
        before.packets_sent,
        server.stats().packets_sent,
    );
    try std.testing.expect(server.recvStreamStats(0).?.stop_sending_sent == null);

    try server.sendStopSendingWithDeadline(
        0,
        77,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(
        @as(u64, 77),
        server.recvStreamStats(0).?.stop_sending_sent.?.application_error_code,
    );
    var cancellation = try client.receivePacketServicingTimersDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer cancellation.deinit(allocator);
    var observed = false;
    for (cancellation.frames) |frame| switch (frame) {
        .stop_sending => |stop| {
            try std.testing.expectEqual(@as(u64, 0), stop.stream_id);
            try std.testing.expectEqual(@as(u64, 77), stop.application_error_code);
            observed = true;
        },
        else => {},
    };
    try std.testing.expect(observed);
}

test "QUIC deferred peer stream credit retries from connection timer" {
    const allocator = std.testing.allocator;

    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

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

    const client_cid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c };
    const server_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbc} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "request",
        .fin = true,
    } }});
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try server.releaseReceivedCapacity(0, "request".len);
    try std.testing.expect(!try server.releaseCompletedPeerStream(0));

    try server.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "response",
        .fin = true,
    } }});
    var response = try client.receivePacket();
    defer response.deinit(allocator);

    var failed_credit_send = ObservedBatchSend{
        .delegate = server.endpoint.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed_credit_send;
    send_io.send_override = ObservedBatchSend.netSend;
    server.endpoint.io = send_io.io();
    defer server.endpoint.io = failed_credit_send.delegate;

    // ACK processing is committed even when the automatic MAX_STREAMS send
    // fails. The stream remains active and a timer is armed independently of
    // future peer packets.
    try one_rtt.testing.applyReceivedFrames(
        &server,
        server.expected_packet_number,
        &.{.{ .ack = .{
            .largest_acknowledged = response.packet.packet_number,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(@as(usize, 1), failed_credit_send.calls);
    // Packet 1 was sealed before the socket rejected it. Its nonce is consumed
    // even though recovery and sent-map state roll back with zero visibility.
    try std.testing.expectEqual(@as(u64, 2), server.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());
    try std.testing.expect(!server.peerStreamClosed(0));
    try std.testing.expectEqual(@as(u64, 1), server.recv_max_streams_bidi);
    try std.testing.expectEqual(@as(usize, 1), server.stats().active_receive_streams);
    try std.testing.expectEqual(@as(usize, 1), server.stats().active_send_streams);
    const retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.peer_stream_credit,
        retry.kind,
    );

    const first_serviced = (try server.serviceNextTimerAt(retry.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.peer_stream_credit,
        first_serviced.kind,
    );
    try std.testing.expectEqual(@as(usize, 2), failed_credit_send.calls);
    try std.testing.expectEqual(@as(u64, 3), server.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());
    try std.testing.expect(!server.peerStreamClosed(0));
    const second_retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.peer_stream_credit,
        second_retry.kind,
    );
    try std.testing.expect(second_retry.deadline_ns > retry.deadline_ns);

    server.endpoint.io = failed_credit_send.delegate;
    const serviced = (try server.serviceNextTimerAt(second_retry.deadline_ns)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.peer_stream_credit,
        serviced.kind,
    );
    try std.testing.expect(server.peerStreamClosed(0));
    try std.testing.expectEqual(@as(u64, 4), server.next_packet_number);
    try std.testing.expectEqual(@as(usize, 1), server.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_receive_streams);
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_send_streams);

    var credit = try client.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 2),
        credit.frames[0].max_streams_bidi.maximum_streams,
    );
}

test "QUIC committed receive credit retries from connection timer" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

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

    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbd} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 8,
        .initial_send_max_stream_data = 8,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "123456",
    } }});
    var data = try server.receivePacket();
    defer data.deinit(allocator);

    var failed_credit_send = ObservedBatchSend{
        .delegate = server.endpoint.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed_credit_send;
    send_io.send_override = ObservedBatchSend.netSend;
    server.endpoint.io = send_io.io();
    defer server.endpoint.io = failed_credit_send.delegate;

    // Parser ownership is committed even though the first credit packet
    // cannot reach the socket. The latest absolute limits remain queued.
    try server.commitReceivedThrough(0, 6);
    try std.testing.expectEqual(
        @as(usize, 0),
        one_rtt.testing.receiveStreamAvailableLen(&server, 0).?,
    );
    try std.testing.expectEqual(
        @as(u64, 14),
        one_rtt.testing.receiveStreamLimit(&server, 0).?,
    );
    const retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.receive_credit,
        retry.kind,
    );

    server.endpoint.io = failed_credit_send.delegate;
    _ = try server.serviceNextTimerAt(retry.deadline_ns);
    var credit = try client.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), credit.frames.len);
    try std.testing.expectEqual(
        @as(u64, 14),
        credit.frames[0].max_data.maximum_data,
    );
    try std.testing.expectEqual(
        @as(u64, 14),
        credit.frames[1].max_stream_data.maximum_stream_data,
    );
    try std.testing.expect(server.nextTimerDeadline() == null or
        server.nextTimerDeadline().?.kind != .receive_credit);
}

test "QUIC bounded receive credit preserves flow state across pacing timeout" {
    const allocator = std.testing.allocator;
    var fixed: NativeSendIo = .{ .backend = .init(allocator, .{}), .now_ns = .init(1_000_000) };
    defer fixed.backend.deinit();
    const io = fixed.backend.io();
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
        [_]u8{0xbf} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "credit-send",
        .peer_connection_id = "credit-recv",
        .initial_send_max_data = 8,
        .initial_send_max_stream_data = 8,
        .enable_pacing = false,
    });
    defer sender.deinit();
    var receiver = try one_rtt.Connection.init(&receiver_endpoint, .{
        .peer = sender_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "credit-recv",
        .peer_connection_id = "credit-send",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .local_endpoint = .server,
        .pacing_max_burst_packets = 1,
    });
    defer receiver.deinit();

    try sender.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "123456",
    } }});
    var packet = try receiver.receivePacket();
    defer packet.deinit(allocator);

    receiver.endpoint.io = fixed.io();
    defer receiver.endpoint.io = io;
    one_rtt.testing.exhaustPacingAt(&receiver, @intCast(fixed.now_ns.load(.acquire)));

    const packet_number = receiver.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        receiver.releaseReceivedCapacityWithTimeout(0, 6, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        receiver.releaseReceivedCapacityWithDeadline(0, 6, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), fixed.duration_sleep_calls.load(.acquire));
    try std.testing.expectEqual(packet_number, receiver.next_packet_number);
    try std.testing.expectEqual(
        @as(u64, 0),
        one_rtt.testing.receiveDataConsumed(&receiver),
    );
    try std.testing.expectEqual(
        @as(?u64, 8),
        one_rtt.testing.receiveStreamLimit(&receiver, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, 6),
        one_rtt.testing.receiveStreamAvailableLen(&receiver, 0),
    );

    one_rtt.testing.setPacingBudgetAt(
        &receiver,
        receiver.congestionWindow(),
        @intCast(fixed.now_ns.load(.acquire)),
    );
    try receiver.releaseReceivedCapacityWithDeadline(0, 6, .{
        .clock = .awake,
        .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + std.time.ns_per_s),
    });
    try std.testing.expectEqual(
        @as(u64, 6),
        one_rtt.testing.receiveDataConsumed(&receiver),
    );
    try std.testing.expectEqual(
        @as(?u64, 14),
        one_rtt.testing.receiveStreamLimit(&receiver, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        one_rtt.testing.receiveStreamAvailableLen(&receiver, 0),
    );

    var credit = try sender.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), credit.frames.len);
}

test "QUIC committed receive credit batches streams fairly" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

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

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbe} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 64,
        .initial_send_max_stream_data = 64,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_data = 64,
        .receive_window = 64,
        .max_receive_window = 64,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 2,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "aaaaaa",
    } }});
    var first_data = try server.receivePacket();
    defer first_data.deinit(allocator);
    try client.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = "bbbbbb",
    } }});
    var second_data = try server.receivePacket();
    defer second_data.deinit(allocator);

    var failed_credit_send = ObservedBatchSend{
        .delegate = server.endpoint.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed_credit_send;
    send_io.send_override = ObservedBatchSend.netSend;
    server.endpoint.io = send_io.io();
    defer server.endpoint.io = failed_credit_send.delegate;

    try server.commitReceivedThrough(0, 6);
    try server.commitReceivedThrough(4, 6);
    server.endpoint.io = failed_credit_send.delegate;

    try one_rtt.testing.applyReceivedFrames(
        &server,
        2,
        &.{.{ .stream = .{
            .stream_id = 0,
            .offset = 6,
            .data = "cccccc",
        } }},
        null,
        .not_ect,
    );
    try server.commitReceivedThrough(0, 12);
    var first_credit = try client.receivePacket();
    defer first_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), first_credit.frames.len);
    try std.testing.expectEqual(
        @as(u64, 0),
        first_credit.frames[0].max_stream_data.stream_id,
    );
    try std.testing.expectEqual(
        @as(u64, 4),
        first_credit.frames[1].max_stream_data.stream_id,
    );
    try std.testing.expect(server.nextTimerDeadline() == null or
        server.nextTimerDeadline().?.kind != .receive_credit);

    // Re-pending the lower-index stream after the batch starts a new fair
    // cycle; the higher ID was already unblocked by the first packet.
    try one_rtt.testing.applyReceivedFrames(
        &server,
        3,
        &.{.{ .stream = .{
            .stream_id = 0,
            .offset = 12,
            .data = "dddddd",
        } }},
        null,
        .not_ect,
    );
    try server.commitReceivedThrough(0, 18);
    var second_credit = try client.receivePacket();
    defer second_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), second_credit.frames.len);
    try std.testing.expectEqual(
        @as(u64, 0),
        second_credit.frames[0].max_stream_data.stream_id,
    );
}

test "QUIC STOP_SENDING automatically restores only connection credit" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "discard-server",
        .peer_connection_id = "discard-client",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 12,
        .stream_receive_window = 12,
        .max_stream_receive_window = 12,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 0, .data = "123456" } }},
        null,
        .not_ect,
    );
    try connection.sendStopSending(0, 41);
    try std.testing.expectEqual(
        @as(u64, 6),
        connection.recvStreamStats(0).?.bytes_read,
    );
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);
    var stop_packet = try one_rtt.openReceivedBytes(
        &sender,
        stop_datagram.from,
        stop_datagram.bytes,
        keys,
        "discard-client".len,
        0,
        8,
    );
    defer stop_packet.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        try connection.discardStoppedReceived(0),
    );
    try std.testing.expectEqual(
        @as(u64, 6),
        connection.recvStreamStats(0).?.bytes_read,
    );
    try std.testing.expectEqual(
        @as(u64, 12),
        connection.recvStreamStats(0).?.receive_limit,
    );
    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "discard-client".len,
        stop_packet.packet.packet_number + 1,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 14),
        credit.frames[0].max_data.maximum_data,
    );

    // Data sent before the peer processes STOP_SENDING can still arrive.
    // It is flow-controlled, discarded immediately, and returned only to the
    // connection window so a sibling stream can use the credit.
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 0,
            .offset = 6,
            .data = "789012",
        } }},
        null,
        .not_ect,
    );
    const late_stats = connection.recvStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 12), late_stats.bytes_read);
    try std.testing.expectEqual(@as(usize, 0), late_stats.available_bytes);
    try std.testing.expectEqual(@as(u64, 12), late_stats.receive_limit);

    var late_credit_datagram = try sender.receiveBytes();
    defer late_credit_datagram.deinit(allocator);
    var late_credit = try one_rtt.openReceivedBytes(
        &sender,
        late_credit_datagram.from,
        late_credit_datagram.bytes,
        keys,
        "discard-client".len,
        credit.packet.packet_number + 1,
        8,
    );
    defer late_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), late_credit.frames.len);
    try std.testing.expect(late_credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 20),
        late_credit.frames[0].max_data.maximum_data,
    );
}

test "QUIC stopped reset settles final-size connection credit across gaps" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-discard-server",
        .peer_connection_id = "reset-discard-client",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 0, .data = "12" } }},
        null,
        .not_ect,
    );
    try connection.sendStopSending(0, 42);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);
    var stop_packet = try one_rtt.openReceivedBytes(
        &sender,
        stop_datagram.from,
        stop_datagram.bytes,
        keys,
        "reset-discard-client".len,
        0,
        8,
    );
    defer stop_packet.deinit(allocator);

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 42,
            .final_size = 8,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try connection.discardStoppedReceived(0),
    );
    const stats = connection.recvStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 2), stats.bytes_read);
    try std.testing.expectEqual(@as(?u64, 8), stats.final_size);
    try std.testing.expect(stats.reset != null);
    try std.testing.expectEqual(@as(u64, 8), stats.receive_limit);

    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "reset-discard-client".len,
        stop_packet.packet.packet_number + 1,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 16),
        credit.frames[0].max_data.maximum_data,
    );
}

test "QUIC discarded reset restores only connection credit" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc9} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-only-server",
        .peer_connection_id = "reset-only-client",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 0, .data = "12" } },
            .{ .reset_stream = .{
                .stream_id = 0,
                .application_error_code = 43,
                .final_size = 8,
            } },
        },
        null,
        .not_ect,
    );
    try std.testing.expectError(
        error.StreamStateError,
        connection.discardStoppedReceived(0),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        try connection.discardResetReceived(0),
    );
    const stats = connection.recvStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 2), stats.bytes_read);
    try std.testing.expectEqual(@as(?u64, 8), stats.final_size);
    try std.testing.expect(stats.reset != null);
    try std.testing.expectEqual(@as(u64, 8), stats.receive_limit);

    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "reset-only-client".len,
        0,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 16),
        credit.frames[0].max_data.maximum_data,
    );
}

test "QUIC automatic stopped connection credit retries from timer" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xca} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "stale-credit-server",
        .peer_connection_id = "stale-credit-client",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 2,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 0, .data = "123456" } }},
        null,
        .not_ect,
    );
    var failed = ObservedBatchSend{
        .delegate = connection.endpoint.io,
        // STOP_SENDING reaches the socket; the immediately following
        // connection-credit update fails and must be retried by the timer.
        .fail_on_call = 2,
    };
    send_io.send_context = &failed;
    send_io.send_override = ObservedBatchSend.netSend;
    connection.endpoint.io = send_io.io();
    defer connection.endpoint.io = failed.delegate;
    try connection.sendStopSending(0, 44);
    try std.testing.expectEqual(@as(usize, 2), failed.calls);
    try std.testing.expectEqual(
        @as(u64, 6),
        connection.recvStreamStats(0).?.bytes_read,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try connection.discardStoppedReceived(0),
    );

    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);
    var stop_packet = try one_rtt.openReceivedBytes(
        &sender,
        stop_datagram.from,
        stop_datagram.bytes,
        keys,
        "stale-credit-client".len,
        0,
        8,
    );
    defer stop_packet.deinit(allocator);

    connection.endpoint.io = failed.delegate;
    const retry = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.receive_credit,
        retry.kind,
    );
    _ = try connection.serviceNextTimerAt(retry.deadline_ns);
    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "stale-credit-client".len,
        stop_packet.packet.packet_number + 1,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 14),
        credit.frames[0].max_data.maximum_data,
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        connection.recvStreamStats(0).?.receive_limit,
    );

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{ .stream_id = 4, .data = "abcdef" } }},
        null,
        .not_ect,
    );
    var observed = ObservedBatchSend{
        .delegate = connection.endpoint.io,
    };
    send_io.send_context = &observed;
    send_io.send_override = ObservedBatchSend.netSend;
    connection.endpoint.io = send_io.io();
    try connection.trySendStopSending(4, 45);
    try std.testing.expectEqual(@as(usize, 1), observed.calls);
    try std.testing.expectEqual(
        @as(u64, 6),
        connection.recvStreamStats(4).?.bytes_read,
    );
    connection.endpoint.io = observed.delegate;

    var second_stop_datagram = try sender.receiveBytes();
    defer second_stop_datagram.deinit(allocator);
    var second_stop = try one_rtt.openReceivedBytes(
        &sender,
        second_stop_datagram.from,
        second_stop_datagram.bytes,
        keys,
        "stale-credit-client".len,
        credit.packet.packet_number + 1,
        8,
    );
    defer second_stop.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), second_stop.frames.len);
    try std.testing.expect(second_stop.frames[0] == .stop_sending);

    const second_retry = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.receive_credit,
        second_retry.kind,
    );
    _ = try connection.serviceNextTimerAt(second_retry.deadline_ns);
    var second_credit_datagram = try sender.receiveBytes();
    defer second_credit_datagram.deinit(allocator);
    var second_credit = try one_rtt.openReceivedBytes(
        &sender,
        second_credit_datagram.from,
        second_credit_datagram.bytes,
        keys,
        "stale-credit-client".len,
        second_stop.packet.packet_number + 1,
        8,
    );
    defer second_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), second_credit.frames.len);
    try std.testing.expect(second_credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 20),
        second_credit.frames[0].max_data.maximum_data,
    );
}

test "QUIC committed receive credit batch respects send MTU" {
    const allocator = std.testing.allocator;
    var send_io: NativeSendIo = .{ .backend = .init(allocator, .{}), .fixed_clock = false };
    defer send_io.backend.deinit();
    const io = send_io.backend.io();

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
        [_]u8{0xbf} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "c",
        .peer_connection_id = "s",
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "s",
        .peer_connection_id = "c",
        // One three-byte MAX_STREAM_DATA frame fits the 19-byte protected
        // overhead; two do not.
        .max_datagram_size = 23,
        .initial_receive_max_data = 64,
        .receive_window = 64,
        .max_receive_window = 64,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 2,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "aaaaaa",
    } }});
    var first_data = try server.receivePacket();
    defer first_data.deinit(allocator);
    try client.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = "bbbbbb",
    } }});
    var second_data = try server.receivePacket();
    defer second_data.deinit(allocator);

    var failed_send = ObservedBatchSend{
        .delegate = server.endpoint.io,
        .fail_after_prefix = 0,
    };
    send_io.send_context = &failed_send;
    send_io.send_override = ObservedBatchSend.netSend;
    server.endpoint.io = send_io.io();
    defer server.endpoint.io = failed_send.delegate;
    try server.commitReceivedThrough(0, 6);
    try server.commitReceivedThrough(4, 6);
    server.endpoint.io = failed_send.delegate;

    const first_retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    _ = try server.serviceNextTimerAt(first_retry.deadline_ns);
    var first_credit = try client.receivePacket();
    defer first_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), first_credit.frames.len);
    try std.testing.expectEqual(
        @as(u64, 0),
        first_credit.frames[0].max_stream_data.stream_id,
    );

    const second_retry = server.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    _ = try server.serviceNextTimerAt(second_retry.deadline_ns);
    var second_credit = try client.receivePacket();
    defer second_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), second_credit.frames.len);
    try std.testing.expectEqual(
        @as(u64, 4),
        second_credit.frames[0].max_stream_data.stream_id,
    );
}

test "QUIC 1-RTT connection releases reset and unidirectional peer stream credit" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb4} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
        .initial_send_max_streams_uni = 1,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 1,
        .initial_receive_max_streams_uni = 1,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.resetStream(0, 71);
    var reset = try server.receivePacket();
    defer reset.deinit(allocator);
    // Peer RESET terminates only the receive half of a bidirectional stream.
    try std.testing.expect(!try server.releaseCompletedPeerStream(0));
    try server.resetStream(0, 72);
    var local_reset = try client.receivePacket();
    defer local_reset.deinit(allocator);
    try client.sendAck(0);
    var reset_ack = try server.receivePacket();
    defer reset_ack.deinit(allocator);
    var bidi_credit = try client.receivePacket();
    defer bidi_credit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), bidi_credit.frames[0].max_streams_bidi.maximum_streams);

    try client.send(&.{.{ .stream = .{
        .stream_id = 2,
        .data = "uni",
        .fin = true,
    } }});
    var uni = try server.receivePacket();
    defer uni.deinit(allocator);
    try server.releaseReceivedCapacity(2, "uni".len);
    // A peer-initiated unidirectional stream has no local send half.
    try std.testing.expect(try server.releaseCompletedPeerStream(2));
    try std.testing.expect(server.peerStreamClosed(2));
    try std.testing.expectEqual(@as(usize, 0), server.stats().active_receive_streams);
    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(
            &server,
            server.expected_packet_number,
            &.{.{ .max_stream_data = .{
                .stream_id = 2,
                .maximum_stream_data = 128,
            } }},
            null,
            .not_ect,
        ),
    );
    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(
            &server,
            server.expected_packet_number,
            &.{.{ .stop_sending = .{
                .stream_id = 2,
                .application_error_code = 9,
            } }},
            null,
            .not_ect,
        ),
    );
    var uni_credit = try client.receivePacket();
    defer uni_credit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), uni_credit.frames[0].max_streams_uni.maximum_streams);
}

test "QUIC application retirement consumes a fully received peer stream" {
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
        [_]u8{0xbd} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "retire-server",
        .peer_connection_id = "retire-client",
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .initial_receive_max_streams_uni = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 2, .data = "partial" } }},
        null,
        .not_ect,
    );
    try std.testing.expect(!try connection
        .requestCompletedPeerStreamRelease(2));
    try std.testing.expectEqual(
        one_rtt.PeerStreamLifecycle.active,
        connection.peerStreamLifecycle(2),
    );

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 2,
            .offset = "partial".len,
            .data = "!",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, "partial!".len),
        connection.availableReceivedStream(2).?.len,
    );
    try std.testing.expect(try connection
        .requestCompletedPeerStreamRelease(2));
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_receive_streams);
    try std.testing.expectEqual(@as(u64, 16), connection.recv_flow.limit);
}

test "QUIC empty FIN retains independent recovery until acknowledged" {
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
        [_]u8{0xbd} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "empty-fin-local",
        .peer_connection_id = "empty-fin-peer",
        .initial_send_max_streams_bidi = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "body",
    } }});
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());

    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = "body".len,
        .data = &.{},
        .fin = true,
    } }});
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
    const fin_candidate = connection.recovery.packetNumberCandidate(1) orelse
        return error.TestUnexpectedResult;
    const fin = try quic.parseFrame(fin_candidate.payload);
    try std.testing.expect(fin.frame == .stream);
    try std.testing.expectEqual(@as(u64, 0), fin.frame.stream.stream_id);
    try std.testing.expectEqual(@as(usize, 0), fin.frame.stream.data.len);
    try std.testing.expect(fin.frame.stream.fin);

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = &.{},
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(!try connection
        .requestCompletedLocalStreamRelease(0));
    try std.testing.expect(!connection.localStreamClosed(0));

    // Repeating the earlier data ACK cannot stand in for FIN delivery.
    _ = connection.markPacketAcknowledged(0);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
    try std.testing.expect(!connection.localStreamClosed(0));

    try std.testing.expect(connection.markPacketAcknowledged(1));
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expect(connection.localStreamClosed(0));
}

test "QUIC local stream retirement waits for FIN ACK and ignores late frames" {
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
        [_]u8{0xbe} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-retire-client",
        .peer_connection_id = "local-retire-server",
        .initial_send_max_streams_bidi = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "request",
        .fin = true,
    } }});
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = "response",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(!try connection
        .requestCompletedLocalStreamRelease(0));
    try std.testing.expect(!connection.localStreamClosed(0));

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.localStreamClosed(0));
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_send_streams);
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_receive_streams);
    try std.testing.expectEqual(@as(usize, 1), connection.stats().closed_local_stream_ranges);
    try std.testing.expectEqual(@as(u64, 0), connection.streamSendAvailable(0));
    try std.testing.expectError(
        error.StreamStateError,
        connection.send(&.{.{ .stream = .{
            .stream_id = 0,
            .data = "reopen",
        } }}),
    );

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        2,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = "late",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.localStreamClosed(0));
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_receive_streams);
}

test "QUIC local stream retirement waits for peer FIN" {
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
        [_]u8{0xbf} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-fin-client",
        .peer_connection_id = "local-fin-server",
        .initial_send_max_streams_bidi = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "request",
        .fin = true,
    } }});
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expect(!try connection
        .requestCompletedLocalStreamRelease(0));
    try std.testing.expect(!connection.localStreamClosed(0));

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 0,
            .data = "response",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.localStreamClosed(0));
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_send_streams);
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_receive_streams);
}

test "QUIC closed local unidirectional stream keeps direction validation" {
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
        [_]u8{0xc0} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-uni-client",
        .peer_connection_id = "local-uni-server",
        .initial_send_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .stream = .{
        .stream_id = 2,
        .data = "one-way",
        .fin = true,
    } }});
    try std.testing.expect(!try connection
        .requestCompletedLocalStreamRelease(2));
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expect(connection.localStreamClosed(2));

    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(
            &connection,
            0,
            &.{.{ .stream = .{
                .stream_id = 2,
                .data = "invalid direction",
                .fin = true,
            } }},
            null,
            .not_ect,
        ),
    );
}

test "QUIC local stream retirement batches closed-range capacity after ACK" {
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
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-batch-client",
        .peer_connection_id = "local-batch-server",
        .initial_send_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();

    for ([_]u62{ 0, 4, 8 }) |stream_id| {
        try connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .data = "request",
            .fin = true,
        } }});
    }
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 8, .data = "c", .fin = true } },
            .{ .stream = .{ .stream_id = 0, .data = "a", .fin = true } },
            .{ .stream = .{ .stream_id = 4, .data = "b", .fin = true } },
        },
        null,
        .not_ect,
    );
    for ([_]u62{ 8, 0, 4 }) |stream_id| {
        try std.testing.expect(!try connection
            .requestCompletedLocalStreamRelease(stream_id));
    }

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .ack = .{
            .largest_acknowledged = 2,
            .ack_delay = 0,
            .first_ack_range = 2,
        } }},
        null,
        .not_ect,
    );
    for ([_]u62{ 0, 4, 8 }) |stream_id| {
        try std.testing.expect(connection.localStreamClosed(stream_id));
    }
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_send_streams);
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_receive_streams);
    try std.testing.expectEqual(@as(usize, 1), connection.stats().closed_local_stream_ranges);
}

test "QUIC 1-RTT connection compacts long peer stream churn into closed ranges" {
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

    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb6} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_uni = 64,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_uni = 64,
        .local_endpoint = .server,
    });
    defer server.deinit();

    for (0..64) |sequence| {
        const stream_id: u64 = 2 + @as(u64, @intCast(sequence)) * 4;
        try client.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .data = "x",
            .fin = true,
        } }});
        var packet = try server.receivePacket();
        packet.deinit(allocator);
        try server.releaseReceivedCapacity(stream_id, 1);
        try std.testing.expect(try server.releaseCompletedPeerStream(stream_id));
        var credit = try client.receivePacket();
        credit.deinit(allocator);
    }

    const stats = server.stats();
    try std.testing.expectEqual(@as(usize, 0), stats.active_receive_streams);
    try std.testing.expectEqual(@as(usize, 0), stats.active_send_streams);
    try std.testing.expectEqual(@as(usize, 1), stats.closed_peer_stream_ranges);
    try std.testing.expect(server.peerStreamClosed(2));
    try std.testing.expect(server.peerStreamClosed(2 + 63 * 4));
}

test "QUIC receive stream ID pagination remains stable after reclamation" {
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
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "stable-page-server",
        .peer_connection_id = "stable-page-client",
        .initial_receive_max_streams_uni = 4,
        .local_endpoint = .server,
    });
    defer connection.deinit();

    for ([_]u62{ 2, 6, 10, 14 }) |stream_id| {
        try one_rtt.testing.applyReceivedFrames(
            &connection,
            connection.expected_packet_number,
            &.{.{ .stream = .{
                .stream_id = stream_id,
                .data = "x",
                .fin = true,
            } }},
            null,
            .not_ect,
        );
    }
    var first_page: [2]u62 = undefined;
    const first = connection.receivedStreamIdsAfterInto(null, &first_page);
    try std.testing.expectEqualSlices(u62, &.{ 2, 6 }, first);

    try connection.releaseReceivedCapacity(2, 1);
    try std.testing.expect(try connection.releaseCompletedPeerStream(2));
    var second_page: [2]u62 = undefined;
    const second = connection.receivedStreamIdsAfterInto(
        first[first.len - 1],
        &second_page,
    );
    try std.testing.expectEqualSlices(u62, &.{ 10, 14 }, second);
}

test "QUIC stream poll cursor follows entry moved by reclamation" {
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
        [_]u8{0xba} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cursor-server",
        .peer_connection_id = "cursor-client",
        .initial_receive_max_streams_uni = 4,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 2, .data = "aaaa" } },
            .{ .stream = .{ .stream_id = 6, .data = "b", .fin = true } },
            .{ .stream = .{ .stream_id = 10, .data = "c", .fin = true } },
            .{ .stream = .{ .stream_id = 14, .data = "d", .fin = true } },
        },
        null,
        .not_ect,
    );
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(
        @as(u62, 2),
        (try connection.pollStream(&byte)).?.data.stream_id,
    );
    try std.testing.expectEqual(
        @as(u62, 6),
        (try connection.pollStream(&byte)).?.data.stream_id,
    );
    try std.testing.expectEqual(
        @as(u62, 10),
        (try connection.pollStream(&byte)).?.data.stream_id,
    );

    try std.testing.expect(try connection.releaseCompletedPeerStream(6));
    const next = (try connection.pollStream(&byte)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 14), next.data.stream_id);
}

test "QUIC peer reset reclamation returns discarded connection flow credit" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 8,
        .initial_send_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .initial_receive_max_streams_bidi = 1,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "12345678",
    } }});
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try client.resetStream(0, 71);
    var reset = try server.receivePacket();
    defer reset.deinit(allocator);
    try std.testing.expect(!try server.releaseCompletedPeerStream(0));
    try server.resetStream(0, 72);
    var local_reset = try client.receivePacket();
    defer local_reset.deinit(allocator);
    try client.sendAck(0);
    var ack = try server.receivePacket();
    defer ack.deinit(allocator);

    var credit = try client.receivePacket();
    defer credit.deinit(allocator);
    var saw_max_data = false;
    var saw_max_streams = false;
    for (credit.frames) |frame| switch (frame) {
        .max_data => |value| {
            saw_max_data = value.maximum_data == 16;
        },
        .max_streams_bidi => |value| {
            saw_max_streams = value.maximum_streams == 2;
        },
        else => {},
    };
    try std.testing.expect(saw_max_data);
    try std.testing.expect(saw_max_streams);
    try std.testing.expect(server.peerStreamClosed(0));
}

test "QUIC closed peer stream keeps direction validation before ignore" {
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
        [_]u8{0xb9} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "direction-server",
        .peer_connection_id = "direction-client",
        .initial_receive_max_streams_uni = 1,
        .local_endpoint = .server,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 2, .data = "x", .fin = true } }},
        null,
        .not_ect,
    );
    try connection.releaseReceivedCapacity(2, 1);
    try std.testing.expect(try connection.releaseCompletedPeerStream(2));
    try std.testing.expect(connection.peerStreamClosed(2));

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{ .stream_id = 2, .data = "late", .fin = true } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expectEqual(@as(usize, 0), connection.stats().active_receive_streams);

    try std.testing.expectError(
        error.StreamStateError,
        one_rtt.testing.applyReceivedFrames(
            &connection,
            2,
            &.{.{ .max_stream_data = .{
                .stream_id = 2,
                .maximum_stream_data = 128,
            } }},
            null,
            .not_ect,
        ),
    );
}

test "QUIC acknowledged send half ignores late peer control until receive closes" {
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
        [_]u8{0xbb} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "half-server",
        .peer_connection_id = "half-client",
        .local_endpoint = .server,
        .initial_send_max_stream_data_bidi_local = 32,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{ .stream_id = 0, .data = "open" } }},
        null,
        .not_ect,
    );
    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "done",
        .fin = true,
    } }});
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expectEqual(one_rtt.PeerStreamLifecycle.active, connection.peerStreamLifecycle(0));

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stop_sending = .{
            .stream_id = 0,
            .application_error_code = 91,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect(connection.streamStopped(0) == null);
    try one_rtt.testing.applyReceivedFrames(
        &connection,
        2,
        &.{.{ .max_stream_data = .{
            .stream_id = 0,
            .maximum_stream_data = 1_000_000,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(u64, 28),
        connection.streamSendAvailable(0),
    );
}

test "QUIC reset stops recovery of superseded STREAM data" {
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
        [_]u8{0xbc} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-recovery-local",
        .peer_connection_id = "reset-recovery-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "superseded",
    } }});
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
    try connection.resetStream(0, 93);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingRecoveryCount());
    const reset_payload = one_rtt.testing.recoveryPayloadForPacket(
        &connection,
        1,
    ) orelse return error.TestUnexpectedResult;
    const reset = try quic.parseFrame(reset_payload);
    try std.testing.expect(reset.frame == .reset_stream);
    try std.testing.expectEqual(@as(u64, 0), reset.frame.reset_stream.stream_id);
    try std.testing.expect(one_rtt.testing.recoveryPayloadForPacket(
        &connection,
        0,
    ) == null);
}

test "QUIC 1-RTT connection batches completed peer stream credit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb5} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 2,
        .initial_send_max_streams_uni = 1,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 2,
        .initial_receive_max_streams_uni = 1,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&.{
        .{ .stream = .{ .stream_id = 0, .data = "first", .fin = true } },
        .{ .stream = .{ .stream_id = 4, .data = "second", .fin = true } },
        .{ .stream = .{ .stream_id = 2, .data = "uni", .fin = true } },
    });
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try server.releaseReceivedCapacity(0, "first".len);
    try server.releaseReceivedCapacity(4, "second".len);
    try server.releaseReceivedCapacity(2, "uni".len);
    try server.resetStream(0, 80);
    var first_reset = try client.receivePacket();
    defer first_reset.deinit(allocator);
    try server.resetStream(4, 84);
    var second_reset = try client.receivePacket();
    defer second_reset.deinit(allocator);
    // Both RESET_STREAM frames must be acknowledged before their send halves
    // are terminal and the corresponding peer stream credits can be returned.
    try client.sendAck(0);
    var reset_acks = try server.receivePacket();
    defer reset_acks.deinit(allocator);

    const packets_before = server.stats().packets_sent;
    try std.testing.expectError(
        error.StreamStateError,
        server.releaseCompletedPeerStreams(&.{ 0, 1, 4 }),
    );
    try std.testing.expectEqual(packets_before, server.stats().packets_sent);
    const released = try server.releaseCompletedPeerStreams(
        &.{ 0, 4, 2, 4 },
    );
    try std.testing.expectEqual(@as(usize, 3), released.streams_released);
    try std.testing.expect(released.update_sent);
    // One packet carries the final cumulative limit for both directions.
    try std.testing.expectEqual(
        packets_before + 1,
        server.stats().packets_sent,
    );

    var credit = try client.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), credit.frames.len);
    try std.testing.expectEqual(
        @as(u64, 4),
        credit.frames[0].max_streams_bidi.maximum_streams,
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        credit.frames[1].max_streams_uni.maximum_streams,
    );
    try std.testing.expectEqual(@as(u64, 4), client.peer_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 2), client.peer_max_streams_uni);

    const repeated = try server.releaseCompletedPeerStreams(&.{ 0, 2, 4 });
    try std.testing.expectEqual(@as(usize, 0), repeated.streams_released);
    try std.testing.expect(!repeated.update_sent);
    try std.testing.expectEqual(
        packets_before + 1,
        server.stats().packets_sent,
    );

    // Both returned bidi slots and the returned uni slot are usable.
    try std.testing.expectEqual(@as(u64, 8), try client.openStream());
    try std.testing.expectEqual(@as(u64, 12), try client.openStream());
    try std.testing.expectEqual(@as(u64, 6), try client.openUniStream());
}

test "QUIC 1-RTT connection rejects peer-created streams beyond receive limit" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 1,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "too many", .fin = false } }},
    });
    try std.testing.expectError(error.StreamLimitExceeded, server.receivePacket());
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
}

test "QUIC 1-RTT DATAGRAM send receive and queue limits" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd0} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
    });
    defer server.deinit();

    try std.testing.expect(client.datagramsEnabled());
    try std.testing.expect(server.datagramReceiveEnabled());
    try std.testing.expect((client.maxDatagramPayloadSize() orelse 0) > 1000);

    try client.sendDatagram("one");
    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), client.datagramsSent());
    try std.testing.expectEqual(@as(u64, 1), server.datagramsReceived());
    try std.testing.expectEqual(@as(usize, 1), server.datagramReceiveQueueLen());
    var out: [16]u8 = undefined;
    const popped = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("one", popped);
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());

    try client.send(&.{
        .{ .datagram = .{ .data = "two", .length_present = true } },
        .{ .datagram = .{ .data = "three", .length_present = true } },
        .{ .datagram = .{ .data = "drop", .length_present = true } },
    });
    var queued = try server.receivePacket();
    defer queued.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), server.datagramsReceived());
    try std.testing.expectEqual(@as(u64, 1), server.datagramsDroppedIncoming());
    try std.testing.expectEqual(@as(usize, 2), server.datagramReceiveQueueLen());

    const kept_first = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("three", kept_first);
    try std.testing.expectError(error.DatagramBufferTooSmall, server.popDatagram(out[0..2]));
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());

    try client.send(&.{
        .{ .datagram = .{ .data = "four", .length_present = true } },
        .{ .datagram = .{ .data = "five", .length_present = true } },
    });
    var wrapped = try server.receivePacket();
    defer wrapped.deinit(allocator);
    const wrapped_first = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("four", wrapped_first);
    const wrapped_second = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("five", wrapped_second);
}

test "QUIC 1-RTT DATAGRAM enforces negotiation and frame-size limits" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe0} ** quic.protection.secret_len);

    var no_dgram = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
    });
    defer no_dgram.deinit();
    var empty_committed: usize = 99;
    try no_dgram.validateDatagrams(&.{});
    try no_dgram.sendDatagrams(&.{}, &empty_committed);
    try std.testing.expectEqual(@as(usize, 0), empty_committed);
    try std.testing.expectError(error.DatagramsNotEnabled, no_dgram.sendDatagram("disabled"));
    try one_rtt.sendFrames(&endpoint, endpoint.address(), keys, .{
        .destination_connection_id = &cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .datagram = .{ .data = "disabled", .length_present = true } }},
    });
    try std.testing.expectError(error.InvalidFrame, no_dgram.receivePacket());
    try std.testing.expect(no_dgram.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), no_dgram.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.datagram_len)), no_dgram.close_info.?.frame_type);
    try std.testing.expectEqualStrings("datagram", no_dgram.close_info.?.reason_phrase);

    // The no-length DATAGRAM form has a distinct wire type and close
    // diagnostics must identify the frame that the peer actually sent.
    var no_length_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer no_length_endpoint.deinit();
    const no_length_cid = [_]u8{ 0xe9, 0xea, 0xeb, 0xec };
    var no_length_dgram = try one_rtt.Connection.init(&no_length_endpoint, .{
        .peer = no_length_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &no_length_cid,
        .peer_connection_id = &no_length_cid,
    });
    defer no_length_dgram.deinit();
    try one_rtt.sendFrames(&no_length_endpoint, no_length_endpoint.address(), keys, .{
        .destination_connection_id = &no_length_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .datagram = .{
            .data = "disabled",
            .length_present = false,
        } }},
    });
    try std.testing.expectError(error.InvalidFrame, no_length_dgram.receivePacket());
    try std.testing.expect(no_length_dgram.closing());
    try std.testing.expectEqual(
        @intFromEnum(quic.TransportErrorCode.protocol_violation),
        no_length_dgram.close_info.?.error_code,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.datagram)),
        no_length_dgram.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings(
        "datagram",
        no_length_dgram.close_info.?.reason_phrase,
    );

    var limited = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
        .local_max_datagram_frame_size = 8,
        .peer_max_datagram_frame_size = 8,
    });
    defer limited.deinit();
    try std.testing.expectEqual(@as(?usize, 6), limited.maxDatagramPayloadSize());
    try std.testing.expectError(error.DatagramTooLarge, limited.sendDatagram("1234567"));
    try std.testing.expectError(error.InvalidFrame, one_rtt.testing.validateDatagramFrame(limited, .{ .data = "1234567", .length_present = true }));
    try one_rtt.testing.validateDatagramFrame(limited, .{ .data = "1234567", .length_present = false });
    try std.testing.expectError(error.InvalidFrame, one_rtt.testing.validateDatagramFrame(limited, .{ .data = "12345678", .length_present = false }));

    var path_limited = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
        .max_datagram_size = 1200,
        .local_max_datagram_frame_size = 4096,
        .peer_max_datagram_frame_size = 4096,
    });
    defer path_limited.deinit();
    const path_payload_limit = path_limited.maxDatagramPayloadSize() orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(path_payload_limit < 1200);
    const fitting_payload = try allocator.alloc(u8, path_payload_limit);
    defer allocator.free(fitting_payload);
    try path_limited.sendDatagram(fitting_payload);
    const oversized_payload = try allocator.alloc(u8, path_payload_limit + 1);
    defer allocator.free(oversized_payload);
    try std.testing.expectError(
        error.DatagramTooLarge,
        path_limited.sendDatagram(oversized_payload),
    );

    var limited_rx_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer limited_rx_endpoint.deinit();
    const limited_rx_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    var limited_rx = try one_rtt.Connection.init(&limited_rx_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &limited_rx_cid,
        .peer_connection_id = &cid,
        .local_max_datagram_frame_size = 8,
        .peer_max_datagram_frame_size = 8,
    });
    defer limited_rx.deinit();
    try one_rtt.sendFrames(&endpoint, limited_rx_endpoint.address(), keys, .{
        .destination_connection_id = &limited_rx_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .datagram = .{ .data = "1234567", .length_present = true } }},
    });
    try std.testing.expectError(error.InvalidFrame, limited_rx.receivePacket());
    try std.testing.expect(limited_rx.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), limited_rx.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.datagram_len)), limited_rx.close_info.?.frame_type);
    try std.testing.expectEqualStrings("datagram", limited_rx.close_info.?.reason_phrase);
}

test "QUIC 1-RTT ACK_FREQUENCY and IMMEDIATE_ACK state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xf0} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
        .peer_min_ack_delay = 2_000,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 2_000,
        .peer_min_ack_delay = 1_000,
    });
    defer server.deinit();

    const sequence = try client.sendAckFrequency(4, 12_000, 5);
    try std.testing.expectEqual(@as(u64, 0), sequence);
    var frequency = try server.receivePacket();
    defer frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), server.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 12_000), server.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 5), server.ackReorderingThreshold());

    const immediate_sequence = try client.sendAckFrequency(0, 12_000, 0);
    try std.testing.expectEqual(@as(u64, 1), immediate_sequence);
    var immediate_frequency = try server.receivePacket();
    defer immediate_frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), server.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 0), server.ackReorderingThreshold());
    try std.testing.expectEqual(
        @as(u64, 2),
        client.ack_frequency_send_next_sequence,
    );
    try std.testing.expectError(
        error.InvalidFrame,
        client.sendAckFrequency(4, 1_999, 5),
    );
    try std.testing.expectError(
        error.InvalidFrame,
        client.sendAckFrequency(4, 16_384_000, 5),
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        client.ack_frequency_send_next_sequence,
    );

    const reverse_sequence = try server.sendAckFrequency(6, 34_000, 7);
    try std.testing.expectEqual(@as(u64, 0), reverse_sequence);
    var reverse_frequency = try client.receivePacket();
    defer reverse_frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 7), client.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 34_000), client.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 7), client.ackReorderingThreshold());

    const recovery_before_immediate_ack = client.pendingRecoveryCount();
    try client.sendImmediateAck();
    try std.testing.expectEqual(
        recovery_before_immediate_ack,
        client.pendingRecoveryCount(),
    );
    var immediate = try server.receivePacket();
    defer immediate.deinit(allocator);
    try std.testing.expect(server.immediateAckRequested());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 3,
        .frames = &[_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = 0,
            .ack_eliciting_threshold = 99,
            .request_max_ack_delay = 99,
            .reordering_threshold = 99,
        } }},
    });
    var stale = try server.receivePacket();
    defer stale.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), server.ackFrequencyThreshold());

    var disabled = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer disabled.deinit();
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 3,
        .frames = &[_]quic.Frame{.{ .immediate_ack = {} }},
    });
    try std.testing.expectError(error.AckFrequencyDisabled, disabled.receivePacket());
    try std.testing.expect(disabled.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), disabled.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.immediate_ack)), disabled.close_info.?.frame_type);
    try std.testing.expectEqualStrings("immediate ack", disabled.close_info.?.reason_phrase);

    var disabled2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer disabled2_endpoint.deinit();
    const disabled2_cid = [_]u8{ 0xf9, 0xfa, 0xfb, 0xfc };
    var disabled2 = try one_rtt.Connection.init(&disabled2_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &disabled2_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer disabled2.deinit();
    try one_rtt.sendFrames(&client_endpoint, disabled2_endpoint.address(), keys, .{
        .destination_connection_id = &disabled2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = 0,
            .ack_eliciting_threshold = 2,
            .request_max_ack_delay = 10,
            .reordering_threshold = 2,
        } }},
    });
    try std.testing.expectError(error.AckFrequencyDisabled, disabled2.receivePacket());
    try std.testing.expect(disabled2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), disabled2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.ack_frequency)), disabled2.close_info.?.frame_type);
    try std.testing.expectEqualStrings("ack frequency", disabled2.close_info.?.reason_phrase);
}

test "QUIC 1-RTT rejects invalid requested ACK delays transactionally" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );

    for ([_]u64{ 999, 16_384_000 }, 0..) |invalid_delay, index| {
        var receiver = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        defer receiver.deinit();
        var cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0 };
        cid[3] = @intCast(index);
        var connection = try one_rtt.Connection.init(&receiver, .{
            .peer = sender.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = &cid,
            .peer_connection_id = "peer",
            .local_endpoint = .server,
            .enable_ack_frequency = true,
            .local_min_ack_delay = 1_000,
        });
        defer connection.deinit();

        try one_rtt.sendFrames(
            &sender,
            receiver.address(),
            keys,
            .{
                .destination_connection_id = &cid,
                .packet_number = 0,
                .frames = &.{
                    .{ .ping = {} },
                    .{ .ack_frequency = .{
                        .sequence_number = 7,
                        .ack_eliciting_threshold = 9,
                        .request_max_ack_delay = invalid_delay,
                        .reordering_threshold = 11,
                    } },
                },
            },
        );
        try std.testing.expectError(
            error.InvalidFrame,
            connection.receivePacket(),
        );
        try std.testing.expect(connection.closing());
        try std.testing.expectEqual(
            @as(u64, @intFromEnum(quic.TransportErrorCode.protocol_violation)),
            connection.close_info.?.error_code,
        );
        try std.testing.expectEqual(
            @as(u64, @intFromEnum(quic.FrameType.ack_frequency)),
            connection.close_info.?.frame_type,
        );
        try std.testing.expectEqualStrings(
            "ack frequency",
            connection.close_info.?.reason_phrase,
        );
        try std.testing.expectEqual(
            @as(u64, 0),
            one_rtt.testing.ackFrequencyReceiveNextSequence(&connection),
        );
        try std.testing.expectEqual(
            @as(u64, 1),
            connection.ackFrequencyThreshold(),
        );
        try std.testing.expectEqual(
            @as(u64, 0),
            connection.requestedMaxAckDelay(),
        );
        try std.testing.expectEqual(
            @as(u64, quic.packet_space.default_packet_threshold),
            connection.ackReorderingThreshold(),
        );
        try std.testing.expectEqual(
            @as(u64, 0),
            one_rtt.testing.expectedPacketNumber(&connection),
        );
    }
}

test "QUIC 1-RTT ACK_FREQUENCY gates automatic ACK emission" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x9a} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .enable_ack_frequency = true,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 1,
        .request_max_ack_delay = 12_000,
        .reordering_threshold = 3,
    } }}, null, .not_ect);
    const packet0 = testReceivedPacket(1, &.{.{ .ping = {} }});
    const packet1 = testReceivedPacket(2, &.{.{ .ping = {} }});
    const packet2 = testReceivedPacket(3, &.{.{ .padding = .{ .len = 1 } }});

    try one_rtt.testing.applyReceivedFrames(&connection, 1, &.{.{ .ping = {} }}, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(&.{packet0}));
    try std.testing.expectEqual(@as(u64, 1), connection.ack_eliciting_since_last_ack);
    const delayed_deadline = connection.ackDelayDeadline() orelse return error.TestUnexpectedResult;
    try connection.serviceAckDelayTimerAt(delayed_deadline - 1);
    try std.testing.expectEqual(delayed_deadline, connection.ackDelayDeadline().?);
    try one_rtt.testing.applyReceivedFrames(&connection, 2, &.{.{ .ping = {} }}, null, .not_ect);
    try std.testing.expect(try connection.sendAckForPacketsIfNeeded(&.{packet1}));
    try std.testing.expectEqual(@as(u64, 0), connection.ack_eliciting_since_last_ack);
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());

    try one_rtt.testing.applyReceivedFrames(&connection, 3, &.{.{ .ack_frequency = .{
        .sequence_number = 1,
        .ack_eliciting_threshold = 10,
        .request_max_ack_delay = 12_000,
        .reordering_threshold = 3,
    } }}, null, .not_ect);
    try one_rtt.testing.applyReceivedFrames(&connection, 4, &.{.{ .immediate_ack = {} }}, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(&.{packet2}));
    try std.testing.expect(connection.immediateAckRequested());
    try one_rtt.testing.applyReceivedFrames(&connection, 5, &.{.{ .ping = {} }}, null, .not_ect);
    try std.testing.expect(try connection.sendAckForPacketsIfNeeded(&.{packet0}));
    try std.testing.expect(!connection.immediateAckRequested());
    try std.testing.expectEqual(@as(u64, 2), connection.next_packet_number);

    try one_rtt.testing.applyReceivedFrames(&connection, 6, &.{.{ .ping = {} }}, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(&.{testReceivedPacket(6, &.{.{ .ping = {} }})}));
    const timer_deadline = connection.ackDelayDeadline() orelse return error.TestUnexpectedResult;
    const timer = connection.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.ack_delay, timer.kind);
    try std.testing.expectEqual(timer_deadline, timer.deadline_ns);
    const serviced = try connection.serviceNextTimerAt(timer_deadline);
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.ack_delay, serviced.?.kind);
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());
    try std.testing.expectEqual(@as(u64, 3), connection.next_packet_number);

    try one_rtt.testing.applyReceivedFrames(&connection, 20, &.{.{ .ping = {} }}, null, .not_ect);
    try one_rtt.testing.applyReceivedFrames(&connection, 16, &.{.{ .ping = {} }}, null, .not_ect);
    try std.testing.expect(try connection.sendAckForPacketsIfNeeded(&.{testReceivedPacket(16, &.{.{ .ping = {} }})}));
    try std.testing.expectEqual(@as(u64, 4), connection.next_packet_number);
}

test "QUIC 1-RTT appends and retransmits negotiated ACK_FREQUENCY" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x96} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "auto-client",
        .peer_connection_id = "auto-server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
        .automatic_ack_frequency_request = .{
            .ack_eliciting_threshold = 3,
            .reordering_threshold = 3,
        },
        .tls_handshake_complete = true,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "auto-server",
        .peer_connection_id = "auto-client",
        .local_endpoint = .server,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 25_000,
    });
    defer server.deinit();

    try client.sendAt(&.{.{ .ping = {} }}, 1_000);
    try std.testing.expect(client.pending_ack_frequency_request == null);
    try std.testing.expectEqual(
        @as(u64, 1),
        client.ack_frequency_send_next_sequence,
    );
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), first.frames.len);
    try std.testing.expect(first.frames[0] == .ping);
    try std.testing.expect(first.frames[1] == .ack_frequency);
    try std.testing.expectEqual(
        @as(u64, 3),
        first.frames[1].ack_frequency.ack_eliciting_threshold,
    );
    try std.testing.expectEqual(@as(u64, 4), server.ackFrequencyThreshold());
    try std.testing.expectEqual(
        @as(u64, 25_000),
        server.requestedMaxAckDelay(),
    );

    try std.testing.expect(try client.retransmitPtoAt(2_000));
    var retry = try server.receivePacket();
    defer retry.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), retry.frames.len);
    try std.testing.expect(retry.frames[0] == .ping);
    try std.testing.expect(retry.frames[1] == .ack_frequency);
    try std.testing.expectEqual(
        @as(u64, 0),
        retry.frames[1].ack_frequency.sequence_number,
    );
    try std.testing.expect(retry.frames[2] == .immediate_ack);
    try std.testing.expect(server.immediateAckRequested());
    try std.testing.expectEqual(@as(u64, 4), server.ackFrequencyThreshold());
}

test "QUIC ACK_FREQUENCY custom delay conservatively updates PTO" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x95} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "delay-client",
        .peer_connection_id = "delay-server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
        .peer_max_ack_delay_ms = 25,
        .automatic_ack_frequency_request = .{
            .request_max_ack_delay_us = 80_000,
        },
        .tls_handshake_complete = true,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "delay-server",
        .peer_connection_id = "delay-client",
        .local_endpoint = .server,
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .local_min_ack_delay = 1_000,
    });
    defer server.deinit();

    client.rtt_stats.updateAt(10_000_000, 0, true, 0);
    try std.testing.expectEqual(
        @as(u64, 25_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expectEqual(@as(u64, 55_000_000), client.ptoPeriod());
    try client.sendAt(&.{.{ .ping = {} }}, 1_000);
    try std.testing.expectEqual(
        @as(u64, 80_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expectEqual(@as(u64, 110_000_000), client.ptoPeriod());
    var request = try server.receivePacket();
    defer request.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 80_000),
        request.frames[1].ack_frequency.request_max_ack_delay,
    );

    // The peer may already use 80 ms, so a later 10-ms request cannot lower
    // the PTO bound until that newer recovery group is acknowledged.
    try std.testing.expectEqual(
        @as(u64, 1),
        try client.sendAckFrequency(3, 10_000, 3),
    );
    try std.testing.expectEqual(
        @as(u64, 80_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expectEqual(@as(u64, 110_000_000), client.ptoPeriod());
    var lower = try server.receivePacket();
    defer lower.deinit(allocator);
    try one_rtt.testing.applyReceivedFrames(
        &client,
        0,
        &.{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(u64, 80_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expect(client.latest_in_flight_ack_frequency != null);
    try one_rtt.testing.applyReceivedFrames(
        &client,
        1,
        &.{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(u64, 10_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expectEqual(@as(u64, 40_000_000), client.ptoPeriod());
    try std.testing.expect(client.latest_in_flight_ack_frequency == null);
    try std.testing.expect(client.unconfirmed_max_ack_delay_us == null);
}

test "QUIC ACK_FREQUENCY retransmission copy commits requested PTO delay" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "copy-client",
        .peer_connection_id = "copy-server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
        .peer_max_ack_delay_ms = 25,
    });
    defer client.deinit();

    _ = try client.sendAckFrequency(3, 75_000, 3);
    try std.testing.expect(try client.retransmitPtoAt(2_000));
    try std.testing.expectEqual(
        @as(u64, 75_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    var original = try receiver.receiveBytes();
    defer original.deinit(allocator);
    var retransmission = try receiver.receiveBytes();
    defer retransmission.deinit(allocator);

    const ack = quic.AckFrame{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try one_rtt.sendFrames(&receiver, sender.address(), keys, .{
        .destination_connection_id = "copy-client",
        .packet_number = 0,
        .frames = &.{.{ .ack = ack }},
    });
    var received_ack = try client.receivePacket();
    defer received_ack.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 75_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expect(client.latest_in_flight_ack_frequency == null);

    _ = try client.sendAckFrequency(3, 9_000, 3);
    try std.testing.expectEqual(
        @as(u64, 75_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    try std.testing.expect(client.markPacketAcknowledged(2));
    try std.testing.expectEqual(
        @as(u64, 9_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
}

test "QUIC 1-RTT explicit ACK_FREQUENCY supersedes an automatic request" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x99} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "explicit-client",
        .peer_connection_id = "explicit-server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
        .automatic_ack_frequency_request = .{},
        .tls_handshake_complete = true,
    });
    defer client.deinit();

    try std.testing.expectEqual(
        @as(u64, 0),
        try client.sendAckFrequency(7, 25_000, 3),
    );
    try std.testing.expect(client.pending_ack_frequency_request == null);
    try std.testing.expectEqual(
        @as(u64, 1),
        client.ack_frequency_send_next_sequence,
    );
    var raw = try receiver.receiveBytes();
    defer raw.deinit(allocator);
    var opened = try one_rtt.openReceivedBytes(
        &receiver,
        raw.from,
        raw.bytes,
        keys,
        "explicit-server".len,
        0,
        4,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), opened.frames.len);
    try std.testing.expect(opened.frames[0] == .ack_frequency);
    try std.testing.expectEqual(
        @as(u64, 7),
        opened.frames[0].ack_frequency.ack_eliciting_threshold,
    );
}

test "QUIC 1-RTT automatic ACK_FREQUENCY retries after socket failure" {
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
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "retry-client",
        .peer_connection_id = "retry-server",
        .enable_pacing = false,
        .enable_ack_frequency = true,
        .peer_min_ack_delay = 1_000,
        .peer_max_ack_delay_ms = 25,
        .automatic_ack_frequency_request = .{
            .request_max_ack_delay_us = 80_000,
        },
        .tls_handshake_complete = true,
    });
    defer client.deinit();

    var failed = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 0,
    };
    sender.io = failed.io();
    defer sender.io = failed.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        client.sendAt(&.{.{ .ping = {} }}, 1_000),
    );
    try std.testing.expect(client.pending_ack_frequency_request != null);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.ack_frequency_send_next_sequence,
    );
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expectEqual(
        @as(u64, 25_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );

    sender.io = failed.delegate;
    try client.sendAt(&.{.{ .ping = {} }}, 2_000);
    try std.testing.expect(client.pending_ack_frequency_request == null);
    try std.testing.expectEqual(
        @as(u64, 1),
        client.ack_frequency_send_next_sequence,
    );
    try std.testing.expectEqual(
        @as(u64, 80_000_000),
        client.peerMaxAckDelayForPtoNanos(),
    );
    var raw = try receiver.receiveBytes();
    defer raw.deinit(allocator);
    var opened = try one_rtt.openReceivedBytes(
        &receiver,
        raw.from,
        raw.bytes,
        keys,
        "retry-server".len,
        1,
        4,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), opened.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), opened.frames.len);
    try std.testing.expect(opened.frames[1] == .ack_frequency);
}

test "QUIC 1-RTT automatic ACK_FREQUENCY requires peer negotiation" {
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
        [_]u8{0x98} ** quic.protection.secret_len,
    );
    try std.testing.expectError(
        error.InvalidTransportParameter,
        one_rtt.Connection.init(&endpoint, .{
            .peer = endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "unsupported-local",
            .peer_connection_id = "unsupported-peer",
            .automatic_ack_frequency_request = .{},
        }),
    );
    for ([_]u64{ 999, 16_384_000 }) |invalid_delay| {
        try std.testing.expectError(
            error.InvalidTransportParameter,
            one_rtt.Connection.init(&endpoint, .{
                .peer = endpoint.address(),
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "invalid-delay-local",
                .peer_connection_id = "invalid-delay-peer",
                .enable_ack_frequency = true,
                .peer_min_ack_delay = 1_000,
                .automatic_ack_frequency_request = .{
                    .request_max_ack_delay_us = invalid_delay,
                },
            }),
        );
    }
}

test "QUIC 1-RTT local ACK policy initializes cadence and rejects excessive delay" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa2} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 25_000,
        .local_ack_reordering_threshold = 3,
    });
    defer connection.deinit();
    try std.testing.expectEqual(@as(u64, 2), connection.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 25_000), connection.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 3), connection.ackReorderingThreshold());

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try one_rtt.testing.applyReceivedFrames(&connection, 1, &ping, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(1, &ping)},
    ));
    const first_deadline = connection.ackDelayDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectError(
        error.Timeout,
        connection.flushPendingAckWithDeadline(.{
            .clock = .awake,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.flushPendingAckWithTimeout(.fromNanoseconds(0)),
    );
    try std.testing.expectEqual(first_deadline, connection.ackDelayDeadline().?);
    try std.testing.expectError(
        error.Timeout,
        connection.flushPendingAckWithDeadline(.{
            .clock = .real,
            .raw = .fromNanoseconds(std.time.ns_per_s),
        }),
    );
    try std.testing.expectEqual(first_deadline, connection.ackDelayDeadline().?);
    try std.testing.expect(try connection.flushPendingAckWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    )));
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());
    try std.testing.expect(!try connection.flushPendingAck());
    try one_rtt.testing.applyReceivedFrames(&connection, 2, &ping, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(2, &ping)},
    ));
    try one_rtt.testing.applyReceivedFrames(&connection, 3, &ping, null, .not_ect);
    try std.testing.expect(try connection.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(3, &ping)},
    ));
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());

    try one_rtt.testing.applyReceivedFrames(&connection, 4, &ping, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(4, &ping)},
    ));
    const second_deadline = connection.ackDelayDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(second_deadline >= first_deadline);
    try connection.serviceAckDelayTimerAt(second_deadline);
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());

    try one_rtt.testing.applyReceivedFrames(&connection, 10, &ping, null, .not_ect);
    try std.testing.expect(!try connection.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(10, &ping)},
    ));
    try one_rtt.testing.applyReceivedFrames(&connection, 6, &ping, null, .not_ect);
    try std.testing.expect(try connection.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(6, &ping)},
    ));

    try std.testing.expectError(
        error.InvalidTransportParameter,
        one_rtt.Connection.init(&endpoint, .{
            .peer = endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "invalid-local",
            .peer_connection_id = "invalid-peer",
            .local_max_ack_delay_us = (@as(u64, 1) << 14) * 1000,
        }),
    );
    var zero_delay = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "zero-delay-local",
        .peer_connection_id = "zero-delay-peer",
        .local_ack_eliciting_threshold = 2,
    });
    defer zero_delay.deinit();
    try one_rtt.testing.applyReceivedFrames(
        &zero_delay,
        1,
        &ping,
        null,
        .not_ect,
    );
    try std.testing.expect(try zero_delay.sendAckForPacketsIfNeeded(
        &.{testReceivedPacket(1, &ping)},
    ));
    try std.testing.expectEqual(@as(?u64, null), zero_delay.ackDelayDeadline());
}

fn testReceivedPacket(packet_number: u64, frames: []const quic.Frame) one_rtt.ReceivedPacket {
    return .{
        .from = .{ .ip4 = .loopback(0) },
        .packet = .{
            .destination_connection_id = &.{},
            .packet_number = packet_number,
            .fixed_bit = true,
            .spin_bit = false,
            .key_phase = false,
            .payload = &.{},
        },
        .frames = @constCast(frames),
    };
}

test "QUIC 1-RTT qlog observer records packet and recovery events" {
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

    var client_output_storage: [32 * 1024]u8 = undefined;
    var client_output: std.Io.Writer = .fixed(&client_output_storage);
    var client_trace = quic.qlog.Trace.init(&client_output, .{});
    var client_observer = quic.qlog.Observer.init(&client_trace);
    var server_output_storage: [32 * 1024]u8 = undefined;
    var server_output: std.Io.Writer = .fixed(&server_output_storage);
    var server_trace = quic.qlog.Trace.init(&server_output, .{});
    var server_observer = quic.qlog.Observer.init(&server_trace);

    const client_cid = [_]u8{ 1, 2, 3, 4 };
    const server_cid = [_]u8{ 5, 6, 7, 8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .max_pacing_rate_bytes_per_second = 1,
        .qlog_observer = &client_observer,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .qlog_observer = &server_observer,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    // Explicit transport timestamps deliberately differ from the internal
    // awake-clock samples used by key update and close. The connection's qlog
    // adapter must preserve emission order across those timestamp sources.
    for (0..5) |_| try client.sendAt(&ping, 1_000_000);
    if (client.takeQlogError()) |err| return err;
    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var received = try server.receivePacketAt(2_000_000);
    defer received.deinit(allocator);
    if (server.takeQlogError()) |err| return err;
    try std.testing.expect(try server.sendAckForPacketsIfNeeded(&.{received}));
    if (server.takeQlogError()) |err| return err;
    var ack = try client.receivePacketAt(3_000_000);
    defer ack.deinit(allocator);
    if (client.takeQlogError()) |err| return err;
    try client.initiateKeyUpdate();
    if (client.takeQlogError()) |err| return err;
    try client.closeApplicationAt(42, "done", null, null);
    if (client.takeQlogError()) |err| return err;
    client.schedulePreviousOneRttKeyDiscard(std.math.maxInt(i64));
    try std.testing.expect(client.discardExpiredOneRttKeys(std.math.maxInt(i64)));

    if (client.takeQlogError()) |err| return err;
    if (server.takeQlogError()) |err| return err;
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"connectivity:connection_started\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"quic:parameters_set\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"owner\":\"local\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"owner\":\"remote\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"quic:packet_sent\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"quic:packet_received\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"recovery:metrics_updated\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"pacing_rate\":1",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"recovery:packet_lost\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"trigger\":\"packet_threshold\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"security:key_updated\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"key_type\":\"client_1rtt_secret\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"security:key_retired\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"generation\":0",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"name\":\"connectivity:connection_closed\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"trigger\":\"local_close\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"application_code\":42",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.buffered(),
        "\"reason\":\"done\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        server_output.buffered(),
        "\"frame_type\":\"ping\"",
    ) != null);
}

test "QUIC 1-RTT qlog observer reports sticky failures without rolling back send" {
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
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();

    var failing: std.Io.Writer = .failing;
    var trace = quic.qlog.Trace.init(&failing, .{});
    var observer = quic.qlog.Observer.init(&trace);
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    var sender = try one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .qlog_observer = &observer,
    });
    defer sender.deinit();

    try sender.sendAt(&.{.{ .ping = {} }}, 1);
    try std.testing.expectEqual(@as(u64, 1), sender.next_packet_number);
    try std.testing.expect(sender.qlogFailed());
    try std.testing.expectEqualStrings(
        "WriteFailed",
        @errorName(sender.takeQlogError() orelse
            return error.TestUnexpectedResult),
    );
    try std.testing.expect(!sender.qlogFailed());
}

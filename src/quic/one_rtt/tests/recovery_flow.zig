const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;

test "QUIC 1-RTT stateful batch rolls back unsent suffix and skips nonces" {
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
    var partial_vtable = client.endpoint.io.vtable.*;
    partial_vtable.netSend = ObservedBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &partial_send,
        .vtable = &partial_vtable,
    };
    defer client.endpoint.io = partial_send.delegate;

    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "first",
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .data = "second",
    } }};
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
        "second",
        retried.frames[0].stream.data,
    );
}

test "QUIC 1-RTT PTO batch commits a socket-sent prefix before returning error" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

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
    const bytes_in_flight_before = client.bytesInFlight();
    client.endpoint.gso_send_enabled = false;

    // Replace only the client's send function after setup. The wrapper lets
    // the real socket emit the first datagram, then reproduces the partial
    // progress plus error result permitted by sendmmsg-style backends.
    var partial_send = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    var partial_vtable = client.endpoint.io.vtable.*;
    partial_vtable.netSend = ObservedBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &partial_send,
        .vtable = &partial_vtable,
    };
    defer client.endpoint.io = partial_send.delegate;

    try std.testing.expectError(error.NetworkDown, client.retransmitPtoProbesAt(20_000_000, 2));
    try std.testing.expectEqual(@as(usize, 1), partial_send.calls);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(bytes_in_flight_before + 1, client.bytesInFlight());
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
    try std.testing.expectEqual(@as(u64, 200_000_000), client.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 210_000_000), client.ptoDeadline());
    const first_deadline = client.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, first_deadline.kind);
    try std.testing.expectEqual(@as(u64, 210_000_000), first_deadline.deadline_ns);

    try std.testing.expectEqual(@as(?one_rtt.LossDetectionTimerDeadline, null), try client.serviceLossDetectionTimer(209_999_999));
    const serviced = (try client.serviceLossDetectionTimer(210_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), probe.packet.packet_number);
    try std.testing.expectEqual(@as(?u64, 610_000_000), client.ptoDeadline());
    client.pto_count = 100;
    try std.testing.expectEqual(quic.rtt.max_pto_ns, client.ptoPeriod());

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(?one_rtt.LossDetectionTimerDeadline, null), client.lossDetectionTimerDeadline());
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
    try connection.sent.sentAt(0, true, 1200, .not_ect, 0);
    _ = try connection.recovery.trackSent(0, "zero");
    try connection.sent.sentAt(1, true, 1200, .not_ect, 200_000_000);
    _ = try connection.recovery.trackSent(1, "one");
    _ = connection.sent.markAcknowledged(1);

    const loss_first = connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.loss_time, loss_first.kind);
    try std.testing.expectEqual(@as(u64, 112_500_000), loss_first.deadline_ns);

    connection.sent.packets.items[0].lost = true;
    try connection.sent.sentAt(2, true, 1200, .not_ect, 200_000_000);
    _ = try connection.recovery.trackSent(2, "two");
    const pto_first = connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.LossDetectionTimerKind.pto, pto_first.kind);
    try std.testing.expectEqual(@as(u64, 525_000_000), pto_first.deadline_ns);
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
    for (0..5) |_| try client.send(&ping);
    try std.testing.expectEqual(@as(usize, 5), client.pendingRecoveryCount());

    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }

    var fifth = try server.receivePacket();
    defer fifth.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), fifth.packet.packet_number);
    try server.sendAck(0);

    var ack_packet = try client.receivePacket();
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
    client.pacer.last_sent_time_ns = std.math.maxInt(u64);
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
    client.pacer.last_sent_time_ns = 1_300_000_000;
    try server.sendAck(0);

    var ack = try client.receivePacketAt(1_400_000_000);
    defer ack.deinit(allocator);
    try std.testing.expectEqual(client.pacer.maxBurstSize(), client.pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), client.pacer.last_sent_time_ns);
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

test "QUIC 1-RTT connection handles stream-level flow control" {
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
    var failed_credit_vtable = combined_server.endpoint.io.vtable.*;
    failed_credit_vtable.netSend = ObservedBatchSend.netSend;
    combined_server.endpoint.io = .{
        .userdata = &failed_credit_send,
        .vtable = &failed_credit_vtable,
    };
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
    });
    defer server.deinit();

    const sequence = try client.sendAckFrequency(4, 12_000, 5);
    try std.testing.expectEqual(@as(u64, 0), sequence);
    var frequency = try server.receivePacket();
    defer frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), server.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 12_000), server.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 5), server.ackReorderingThreshold());

    try std.testing.expectError(error.InvalidFrame, client.sendAckFrequency(0, 12_000, 5));
    try std.testing.expectEqual(@as(u64, 1), client.ack_frequency_send_next_sequence);

    const reverse_sequence = try server.sendAckFrequency(6, 34_000, 7);
    try std.testing.expectEqual(@as(u64, 0), reverse_sequence);
    var reverse_frequency = try client.receivePacket();
    defer reverse_frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), client.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 34_000), client.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 7), client.ackReorderingThreshold());

    try client.sendImmediateAck();
    var immediate = try server.receivePacket();
    defer immediate.deinit(allocator);
    try std.testing.expect(server.immediateAckRequested());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = 0,
            .ack_eliciting_threshold = 99,
            .request_max_ack_delay = 99,
            .reordering_threshold = 99,
        } }},
    });
    var stale = try server.receivePacket();
    defer stale.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), server.ackFrequencyThreshold());

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
        .ack_eliciting_threshold = 2,
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

    var client_output: std.Io.Writer.Allocating = .init(allocator);
    defer client_output.deinit();
    var client_trace = quic.qlog.Trace.init(&client_output.writer, .{});
    var client_observer = quic.qlog.Observer.init(&client_trace);
    var server_output: std.Io.Writer.Allocating = .init(allocator);
    defer server_output.deinit();
    var server_trace = quic.qlog.Trace.init(&server_output.writer, .{});
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
    for (0..5) |_| try client.sendAt(&ping, 1_000_000);
    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var received = try server.receivePacketAt(2_000_000);
    defer received.deinit(allocator);
    try std.testing.expect(try server.sendAckForPacketsIfNeeded(&.{received}));
    var ack = try client.receivePacketAt(3_000_000);
    defer ack.deinit(allocator);
    try client.initiateKeyUpdate();
    try client.closeApplicationAt(42, "done", null, null);
    client.schedulePreviousOneRttKeyDiscard(std.math.maxInt(i64));
    try std.testing.expect(client.discardExpiredOneRttKeys(std.math.maxInt(i64)));

    try std.testing.expect(client.takeQlogError() == null);
    try std.testing.expect(server.takeQlogError() == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"connectivity:connection_started\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"quic:parameters_set\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"owner\":\"local\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"owner\":\"remote\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"quic:packet_sent\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"quic:packet_received\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"recovery:metrics_updated\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"recovery:packet_lost\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"trigger\":\"packet_threshold\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"security:key_updated\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"key_type\":\"client_1rtt_secret\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"security:key_retired\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"generation\":0",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"connectivity:connection_closed\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"trigger\":\"local_close\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"application_code\":42",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"reason\":\"done\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        server_output.written(),
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

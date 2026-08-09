const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");

test "QUIC integrated handshake coalesces HANDSHAKE_DONE after application frame" {
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

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        server_confirmed: bool = false,
        awaiting_ack: bool = false,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(
                shared.endpoint,
                .{
                    .local_connection_id = "server",
                    .random = [_]u8{0x91} ** 32,
                    .x25519_secret_key = [_]u8{0x92} ** 32,
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            shared.server_confirmed =
                established.connection.handshakeConfirmed();
            established.connection.send(&.{.{ .stream = .{
                .stream_id = 1,
                .data = "response-first",
                .fin = true,
            } }}) catch |err| {
                shared.err = err;
                return;
            };
            shared.awaiting_ack =
                established.connection.handshakeDoneAwaitingAck();

            var ack = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            ack.deinit(shared.endpoint.allocator);
            if (established.connection.handshakeDoneAwaitingAck()) {
                shared.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "done0001",
            .local_connection_id = "client",
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
        },
    );
    defer established.deinit();
    try std.testing.expect(established.connection.handshakeComplete());
    try std.testing.expect(!established.connection.handshakeConfirmed());

    var packet = try established.connection.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), packet.frames.len);
    try std.testing.expect(packet.frames[0] == .stream);
    try std.testing.expectEqualStrings(
        "response-first",
        packet.frames[0].stream.data,
    );
    try std.testing.expect(packet.frames[1] == .handshake_done);
    try std.testing.expect(established.connection.handshakeConfirmed());
    try established.connection.sendAck(0);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.server_confirmed);
    try std.testing.expect(shared.awaiting_ack);
}

test "QUIC HANDSHAKE_DONE survives PTO loss and confirms on ACK" {
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
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa5} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .tls_handshake_complete = true,
    });
    defer server.deinit();
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
        .tls_handshake_complete = true,
    });
    defer client.deinit();

    // The first datagram is intentionally consumed without opening it.
    try server.send(&.{.{ .ping = {} }});
    var dropped = try client_endpoint.receiveBytes();
    dropped.deinit(allocator);
    try std.testing.expect(server.handshakeDoneAwaitingAck());
    try std.testing.expectEqual(@as(usize, 1), server.pendingRecoveryCount());

    try std.testing.expect(try server.retransmitPtoAt(1_000_000_000));
    var recovered = try client.receivePacket();
    defer recovered.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), recovered.frames.len);
    try std.testing.expect(recovered.frames[0] == .ping);
    try std.testing.expect(recovered.frames[1] == .handshake_done);
    try std.testing.expect(client.handshakeConfirmed());

    try client.sendAck(0);
    var ack = try server.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expect(server.handshakeConfirmed());
    try std.testing.expect(!server.handshakeDoneAwaitingAck());
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());
}

test "QUIC client confirms when a valid ACK reaches its first 1-RTT packet" {
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
    const server_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc5} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
        .tls_handshake_complete = true,
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

    try client.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        @as(?u64, 0),
        client.lowestOneRttPacketNumber(),
    );
    try std.testing.expect(!client.handshakeConfirmed());

    var ping = try server.receivePacket();
    defer ping.deinit(allocator);
    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expect(client.handshakeConfirmed());
}

test "QUIC client ignores reordered ACK below its first 1-RTT packet" {
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

    const cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
        .local_endpoint = .client,
        .tls_handshake_complete = true,
    });
    defer client.deinit();

    // Simulate packet-number consumption before 1-RTT keys become available.
    client.next_packet_number = 4;
    try client.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        @as(?u64, 4),
        client.lowestOneRttPacketNumber(),
    );
    const stale = quic.AckFrame{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    // An ACK for an unsent packet is rejected before it can alter handshake
    // state. The direct status test above covers a valid below-threshold ACK.
    try std.testing.expectError(
        error.InvalidAckFrame,
        one_rtt.testing.applyReceivedFrames(
            &client,
            0,
            &.{.{ .ack = stale }},
            100,
            .not_ect,
        ),
    );
    try std.testing.expect(!client.handshakeConfirmed());
}

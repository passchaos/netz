const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");

fn registerResetToken(
    connection: *one_rtt.Connection,
    sequence_number: u64,
    token: [quic.stateless_reset.token_len]u8,
) !void {
    try connection.peer_connection_ids.addWithLimit(
        sequence_number,
        "reset-cid",
        token,
        4,
    );
    try connection.peer_connection_ids.markInUse(sequence_number);
}

/// Produce a datagram that reaches AEAD authentication before failing. Keeping
/// the payload larger than the header-protection sample ensures replacing the
/// tag with a reset token cannot perturb protected-header decoding.
fn makeResetDatagram(
    allocator: std.mem.Allocator,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    token: [quic.stateless_reset.token_len]u8,
) ![]u8 {
    const packet = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = destination_connection_id,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = &([_]u8{0} ** 32),
    });
    @memcpy(
        packet[packet.len - quic.stateless_reset.token_len ..],
        &token,
    );
    return packet;
}

test "QUIC ordinary receive authenticates before reset token comparison" {
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

    const local_cid = "server";
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x90} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const packet = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = local_cid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = &.{@intFromEnum(quic.FrameType.ping)},
    });
    defer allocator.free(packet);
    const tag_as_token = packet[packet.len -
        quic.stateless_reset.token_len ..][0..quic.stateless_reset.token_len].*;
    try registerResetToken(&connection, 1, tag_as_token);

    var received = try one_rtt.testing.processReceivedBytesAt(
        &connection,
        endpoint.address(),
        packet,
        .not_ect,
        1_000_000,
    );
    defer received.deinit(allocator);
    try std.testing.expect(received.frames[0] == .ping);
    try std.testing.expect(!connection.draining());
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
}

test "QUIC owning receive detects stateless reset only after authentication failure" {
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

    const local_cid = "server";
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const reset_token = [_]u8{0xa1} ** quic.stateless_reset.token_len;
    try registerResetToken(&connection, 1, reset_token);

    // A packet too short to carry a reset token is rejected by packet parsing
    // without entering reset detection or consuming the AEAD integrity budget.
    const short = [_]u8{0x40} ** (quic.stateless_reset.min_datagram_len - 1);
    try sender.sendBytes(receiver.address(), &short);
    try std.testing.expectError(
        error.InvalidInitialPacket,
        connection.receivePacketAt(1_000_000),
    );
    try std.testing.expect(!connection.draining());
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());

    const unknown = try makeResetDatagram(
        allocator,
        keys,
        local_cid,
        [_]u8{0xb2} ** quic.stateless_reset.token_len,
    );
    defer allocator.free(unknown);
    try sender.sendBytes(receiver.address(), unknown);
    try std.testing.expectError(
        error.AuthenticationFailed,
        connection.receivePacketAt(2_000_000),
    );
    try std.testing.expect(!connection.draining());
    try std.testing.expectEqual(@as(u64, 1), connection.authenticationFailureCount());

    const reset = try makeResetDatagram(allocator, keys, local_cid, reset_token);
    defer allocator.free(reset);
    try sender.sendBytes(receiver.address(), reset);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.receivePacketAt(3_000_000),
    );
    try std.testing.expect(connection.draining());
    // Initial application-data PTO is 200ms, so draining lasts three PTOs.
    try std.testing.expectEqual(
        @as(?u64, 603),
        connection.closeExpiryDeadlineMillis(),
    );
    try std.testing.expectEqual(@as(u64, 1), connection.authenticationFailureCount());
}

test "QUIC timer-aware borrowed visitor detects stateless reset" {
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

    const local_cid = "server";
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x92} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const token = [_]u8{0xa2} ** quic.stateless_reset.token_len;
    try registerResetToken(&connection, 2, token);
    const reset = try makeResetDatagram(allocator, keys, local_cid, token);
    defer allocator.free(reset);
    try sender.sendBytes(receiver.address(), reset);

    const Visitor = struct {
        fn visit(called: *bool, _: one_rtt.ReceivedPacketView) error{}!void {
            called.* = true;
        }
    };
    var called = false;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.visitPacketServicingTimers(&called, Visitor.visit),
    );
    try std.testing.expect(!called);
    try std.testing.expect(connection.draining());
    try std.testing.expect(connection.closeExpiryDeadlineMillis() != null);
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
}

test "QUIC batch service detects stateless reset after in-place decrypt failure" {
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

    const local_cid = "server";
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const token = [_]u8{0xa3} ** quic.stateless_reset.token_len;
    try registerResetToken(&connection, 3, token);
    const reset = try makeResetDatagram(allocator, keys, local_cid, token);
    defer allocator.free(reset);
    try sender.sendBytes(receiver.address(), reset);

    try std.testing.expectError(
        error.ConnectionClosed,
        connection.servicePacketBatchAt(4_000_000),
    );
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(
        @as(?u64, 604),
        connection.closeExpiryDeadlineMillis(),
    );
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
}

test "QUIC ordinary routed receive detects stateless reset after decrypt failure" {
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

    const local_cid = "server";
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const token = [_]u8{0xa4} ** quic.stateless_reset.token_len;
    try registerResetToken(&connection, 4, token);
    const reset = try makeResetDatagram(allocator, keys, local_cid, token);

    var routed: quic.runtime.RoutedBytes = .{
        .datagram = .{
            .from = endpoint.address(),
            .bytes = reset,
        },
        .route = .{ .connection_index = 0, .sequence_number = 4 },
        .destination_connection_id = local_cid,
    };
    defer routed.deinit(allocator);

    try std.testing.expectError(
        error.ConnectionClosed,
        connection.receiveRoutedDatagramAt(routed, 5_000_000),
    );
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(
        @as(?u64, 605),
        connection.closeExpiryDeadlineMillis(),
    );
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
}

test "QUIC initial peer CID without negotiated token rejects zero suffix" {
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
        [_]u8{0x95} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const packet = try makeResetDatagram(
        allocator,
        keys,
        "server",
        [_]u8{0} ** quic.stateless_reset.token_len,
    );
    defer allocator.free(packet);
    try std.testing.expectError(
        error.AuthenticationFailed,
        one_rtt.testing.processReceivedBytesAt(
            &connection,
            endpoint.address(),
            packet,
            .not_ect,
            6_000_000,
        ),
    );
    try std.testing.expect(!connection.draining());
    try std.testing.expectEqual(@as(u64, 1), connection.authenticationFailureCount());
}

test "QUIC server rejects a peer stateless reset transport token" {
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
        [_]u8{0x96} ** quic.protection.secret_len,
    );

    try std.testing.expectError(
        error.InvalidTransportParameter,
        one_rtt.Connection.init(&endpoint, .{
            .peer = endpoint.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "server",
            .peer_connection_id = "client",
            .local_endpoint = .server,
            .peer_stateless_reset_token = [_]u8{0xa5} ** quic.stateless_reset.token_len,
        }),
    );
}

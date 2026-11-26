const std = @import("std");
const quic = @import("../mod.zig");
const dispatcher_mod = @import("../endpoint_dispatcher.zig");
const one_rtt = @import("../one_rtt.zig");
const runtime = @import("../runtime.zig");
const ObservedBatchSend = @import(
    "../one_rtt/tests/observed_batch_send.zig",
).ObservedBatchSend;

const ConnectionHandle = dispatcher_mod.ConnectionHandle;
const Dispatcher = dispatcher_mod.Dispatcher;
const Event = dispatcher_mod.Event;

test {
    _ = @import("closing_tests.zig");
}

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

test "QUIC endpoint dispatcher owns CID routing across connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_a_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_a_endpoint.deinit();
    var client_b_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_b_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var server_a = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_a_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server-a",
        .peer_connection_id = "client-a",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server_a.deinit();
    var server_b = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_b_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server-b",
        .peer_connection_id = "client-b",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server_b.deinit();
    var client_a = try one_rtt.Connection.init(&client_a_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client-a",
        .peer_connection_id = "server-a",
        .enable_pacing = false,
    });
    defer client_a.deinit();
    var client_b = try one_rtt.Connection.init(&client_b_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client-b",
        .peer_connection_id = "server-b",
        .enable_pacing = false,
    });
    defer client_b.deinit();

    var dispatcher = Dispatcher.init(allocator, &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(10, &server_a);
    try dispatcher.registerConnection(20, &server_b);

    server_a.pacing_blocked_until_ns = 9_000_000;
    try dispatcher.refreshConnectionTimer(10);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pacing,
        dispatcher.nextTimerDeadline().?.timer.kind,
    );
    try dispatcher.setConnectionMaxPacingRateBytesPerSecondAt(
        10,
        125_000,
        1_000_000,
    );
    try std.testing.expectEqual(
        @as(?u64, 125_000),
        server_a.maxPacingRateBytesPerSecond(),
    );
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);
    try dispatcher.setConnectionMaxPacingRateBytesPerSecond(10, null);
    try std.testing.expectEqual(
        @as(?u64, null),
        server_a.maxPacingRateBytesPerSecond(),
    );
    try std.testing.expectError(
        error.UnknownConnectionHandle,
        dispatcher.setConnectionMaxPacingRateBytesPerSecond(99, 1),
    );

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client_b.send(&ping);
    try client_a.send(&ping);

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var first = try dispatcher.receive(&versions);
    defer first.deinit(allocator);
    var second = try dispatcher.receive(&versions);
    defer second.deinit(allocator);
    try std.testing.expect(first == .packet);
    try std.testing.expect(second == .packet);
    const first_handle = first.packet.connection_handle;
    const second_handle = second.packet.connection_handle;
    try std.testing.expect(
        (first_handle == 20 and second_handle == 10) or
            (first_handle == 10 and second_handle == 20),
    );
    try std.testing.expectEqual(@as(u64, 0), first.packet.connection_id_sequence);
    try std.testing.expectEqual(@as(u64, 0), second.packet.connection_id_sequence);
    try std.testing.expect(first.packet.packet.frames[0] == .ping);
    try std.testing.expect(second.packet.packet.frames[0] == .ping);
    try std.testing.expectEqual(@as(usize, 2), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), dispatcher.routeCount());

    // Mutating a connection outside the dispatcher requires one explicit
    // refresh. The endpoint timer index can then service that connection
    // without scanning peers or reading the UDP socket.
    try server_a.send(&ping);
    try dispatcher.refreshConnectionTimer(10);
    const deadline = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 10), deadline.connection_id);
    const timer = (try dispatcher.serviceNextTimerAt(
        deadline.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(ConnectionHandle, 10), timer.connection_handle);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pto,
        timer.timer.kind,
    );

    try client_a_endpoint.sendBytes(
        server_endpoint.address(),
        &.{ 0x40, 'u', 'n', 'k', 'n', 'o', 'w', 'n', 0 },
    );
    var unknown = try dispatcher.receive(&versions);
    defer unknown.deinit(allocator);
    try std.testing.expect(unknown == .unrouted);
    try std.testing.expectEqual(
        dispatcher_mod.UnroutedKind.unknown_short_header,
        unknown.unrouted.kind,
    );

    try std.testing.expect(try dispatcher.unregisterConnection(10));
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expect(!(try dispatcher.unregisterConnection(10)));
}

test "QUIC endpoint dispatcher consumes a short packet from a detached endpoint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var primary = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer primary.deinit();
    var detached = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer detached.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd9} ** quic.protection.secret_len,
    );
    const local_cid = "detached-local";
    var connection = try one_rtt.Connection.init(&primary, .{
        .peer = .{ .ip4 = .loopback(4433) },
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = "detached-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &primary);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(30, &connection);

    const payload = try one_rtt.encodeFrames(allocator, &.{.{ .ping = {} }});
    defer allocator.free(payload);
    const bytes = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = local_cid,
        .packet_number = 0,
        .payload = payload,
    });
    defer allocator.free(bytes);
    try peer.sendBytes(detached.address(), bytes);

    var storage: [4096]u8 = undefined;
    const datagram = try detached.receiveBytesIntoWithTimeout(
        &storage,
        .fromSeconds(1),
    );
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) !void {
            return error.TestUnexpectedResult;
        }
    };
    var event = try dispatcher.dispatchVisitingDatagram(
        datagram,
        {},
        Visitor.visit,
    );
    defer event.deinit(allocator);
    try std.testing.expect(event == .consumed);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.stats().packets_received,
    );

    const owned_bytes = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = local_cid,
        .packet_number = 1,
        .payload = payload,
    });
    var owned_event = try dispatcher.dispatch(.{
        .from = peer.address(),
        .received_on = &detached,
        .bytes = owned_bytes,
    });
    defer owned_event.deinit(allocator);
    try std.testing.expect(owned_event == .consumed);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.stats().packets_received,
    );
}

test "QUIC endpoint dispatcher admits its owned secondary endpoint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var primary = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer primary.deinit();
    var secondary = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer secondary.deinit();
    var foreign = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer foreign.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );
    var secondary_connection = try one_rtt.Connection.init(&secondary, .{
        .peer = foreign.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "secondary-local",
        .peer_connection_id = "secondary-peer",
        .enable_pacing = false,
    });
    defer secondary_connection.deinit();
    var foreign_connection = try one_rtt.Connection.init(&foreign, .{
        .peer = secondary.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "foreign-local",
        .peer_connection_id = "foreign-peer",
        .enable_pacing = false,
    });
    defer foreign_connection.deinit();

    var dispatcher = Dispatcher.initWithSecondaryEndpoint(
        allocator,
        &primary,
        &secondary,
    );
    defer dispatcher.deinit();
    try dispatcher.registerConnection(31, &secondary_connection);
    try std.testing.expectError(
        error.ConnectionEndpointMismatch,
        dispatcher.replaceConnection(31, &foreign_connection),
    );
    try std.testing.expect(try dispatcher.unregisterConnection(31));
    try std.testing.expectError(
        error.ConnectionEndpointMismatch,
        dispatcher.registerConnection(32, &foreign_connection),
    );
}

test "QUIC endpoint dispatcher immediately repairs packet-threshold loss" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    var server_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();

    const client_cid = "threshold-client";
    const server_cid = "threshold-server";
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
        .local_connection_id = client_cid,
        .peer_connection_id = server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = server_cid,
        .peer_connection_id = client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    var dispatcher = Dispatcher.init(allocator, &client_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(33, &client);

    const ping = [_]quic.Frame{.{ .ping = {} }};
    for (0..5) |_| try client.sendAt(&ping, 0);
    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var fifth = try server.receivePacketAt(1);
    defer fifth.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), fifth.packet.packet_number);
    try server.sendAck(0);

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var ack = try dispatcher.receive(&versions);
    defer ack.deinit(allocator);
    try std.testing.expect(ack == .packet);
    try std.testing.expectEqual(@as(ConnectionHandle, 33), ack.packet.connection_handle);
    try std.testing.expectEqual(@as(u64, 4), ack.packet.packet.frames[0].ack.largest_acknowledged);

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

test "QUIC endpoint dispatcher visits warmed routed packets without allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var server_endpoint = try runtime.Endpoint.bind(
        failing.allocator(),
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb3} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "visit-server",
        .peer_connection_id = "visit-client",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 3,
    });
    defer server.deinit();
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "visit-client",
        .peer_connection_id = "visit-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    var dispatcher = Dispatcher.init(failing.allocator(), &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(44, &server);

    const Observed = struct {
        expected_packet_number: u64,
        expected_sequence: u64,
        calls: usize = 0,

        fn visit(
            observed: *@This(),
            packet: dispatcher_mod.RoutedPacketView,
        ) !void {
            try std.testing.expectEqual(
                @as(ConnectionHandle, 44),
                packet.connection_handle,
            );
            try std.testing.expectEqual(
                observed.expected_sequence,
                packet.connection_id_sequence,
            );
            try std.testing.expectEqual(
                observed.expected_packet_number,
                packet.packet.packet_number,
            );
            try std.testing.expectEqual(@as(usize, 1), packet.packet.frames.len);
            try std.testing.expect(packet.packet.frames[0] == .stream);
            observed.calls += 1;
        }
    };
    var storage: [4096]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    for (0..2) |packet_number| {
        const destination_connection_id: []const u8 = if (packet_number == 0)
            "visit-server"
        else
            "v";
        if (packet_number == 0) {
            try client.send(&.{.{ .stream = .{
                .stream_id = 0,
                .offset = 0,
                .data = "a",
            } }});
        } else {
            try dispatcher.sendNewConnectionId(
                44,
                destination_connection_id,
                [_]u8{0x91} ** 16,
            );
            var new_cid_packet = try client_endpoint.receiveBytes();
            new_cid_packet.deinit(allocator);
            try one_rtt.sendFrames(
                &client_endpoint,
                server_endpoint.address(),
                keys,
                .{
                    .destination_connection_id = destination_connection_id,
                    .packet_number = 1,
                    .frames = &.{.{ .stream = .{
                        .stream_id = 0,
                        .offset = 1,
                        .data = "b",
                        .fin = true,
                    } }},
                },
            );
            failing.fail_index = failing.alloc_index;
        }
        var observed = Observed{
            .expected_packet_number = packet_number,
            .expected_sequence = packet_number,
        };
        var event = if (packet_number == 0)
            try dispatcher.receiveVisiting(
                &versions,
                &storage,
                &observed,
                Observed.visit,
            )
        else
            try dispatcher.receiveVisitingWithDeadline(
                &versions,
                &storage,
                deadline,
                &observed,
                Observed.visit,
            );
        defer event.deinit(failing.allocator());
        try std.testing.expect(event == .packet);
        try std.testing.expectEqual(@as(usize, 1), observed.calls);
    }
    try std.testing.expectEqualStrings(
        "ab",
        server.availableReceivedStream(0).?,
    );
    try std.testing.expect(!failing.has_induced_failure);
}

test "QUIC endpoint dispatcher visits a ready datagram batch without allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var server_endpoint = try runtime.Endpoint.bind(
        failing.allocator(),
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb6} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "batch-server",
        .peer_connection_id = "batch-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    var dispatcher = Dispatcher.init(failing.allocator(), &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(67, &server);

    // Warm retained frame/range storage before failing every later dispatcher
    // allocation. The following batch must remain caller-buffer-only.
    try one_rtt.sendFrames(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = "batch-server",
            .packet_number = 0,
            .frames = &.{.{ .ping = {} }},
        },
    );
    const Visitor = struct {
        fn visit(count: *usize, packet: dispatcher_mod.RoutedPacketView) !void {
            try std.testing.expectEqual(
                @as(ConnectionHandle, 67),
                packet.connection_handle,
            );
            try std.testing.expectEqual(
                @as(u64, count.*),
                packet.packet.packet_number,
            );
            count.* += 1;
        }
    };
    const versions = &.{quic.Version.version_1.wireValue()};
    var warm_storage: [4096]u8 = undefined;
    var count: usize = 0;
    var warm = try dispatcher.receiveVisitingWithDeadline(
        versions,
        &warm_storage,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        &count,
        Visitor.visit,
    );
    warm.deinit(failing.allocator());

    for (1..4) |packet_number| {
        try one_rtt.sendFrames(
            &client_endpoint,
            server_endpoint.address(),
            keys,
            .{
                .destination_connection_id = "batch-server",
                .packet_number = packet_number,
                .frames = &.{.{ .ping = {} }},
            },
        );
    }
    failing.fail_index = failing.alloc_index;
    var storage: [3 * 4096]u8 = undefined;
    var events: [3]dispatcher_mod.VisitEvent = undefined;
    const event_count = try dispatcher.receiveManyVisitingWithDeadline(
        versions,
        &storage,
        &events,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        &count,
        Visitor.visit,
    );
    defer for (events[0..event_count]) |*event| {
        event.deinit(failing.allocator());
    };
    try std.testing.expectEqual(@as(usize, 3), event_count);
    try std.testing.expectEqual(@as(usize, 4), count);
    for (events[0..event_count]) |event| {
        try std.testing.expect(event == .packet);
        try std.testing.expectEqual(
            @as(ConnectionHandle, 67),
            event.packet.connection_handle,
        );
    }
    try std.testing.expect(!failing.has_induced_failure);
}

test "QUIC endpoint dispatcher preserves visitor errors" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "error-server",
        .peer_connection_id = "error-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    var dispatcher = Dispatcher.init(allocator, &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(55, &server);
    try one_rtt.sendFrames(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = "error-server",
            .packet_number = 0,
            .frames = &.{.{ .stream = .{
                .stream_id = 0,
                .data = "committed",
                .fin = true,
            } }},
        },
    );
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{InvalidPacketNumber}!void {
            return error.InvalidPacketNumber;
        }
    };
    var storage: [4096]u8 = undefined;
    try std.testing.expectError(
        error.InvalidPacketNumber,
        dispatcher.receiveVisitingWithDeadline(
            &.{quic.Version.version_1.wireValue()},
            &storage,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectEqualStrings(
        "committed",
        server.availableReceivedStream(0).?,
    );
}

test "QUIC endpoint dispatcher retains batch suffix after visitor error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "suffix-server",
        .peer_connection_id = "suffix-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    var dispatcher = Dispatcher.init(allocator, &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(68, &server);
    for (0..2) |packet_number| {
        try one_rtt.sendFrames(
            &client_endpoint,
            server_endpoint.address(),
            keys,
            .{
                .destination_connection_id = "suffix-server",
                .packet_number = packet_number,
                .frames = &.{.{ .ping = {} }},
            },
        );
    }

    const Reject = struct {
        fn visit(
            _: void,
            _: dispatcher_mod.RoutedPacketView,
        ) error{Rejected}!void {
            return error.Rejected;
        }
    };
    var storage: [2 * 4096]u8 = undefined;
    var events: [2]dispatcher_mod.VisitEvent = undefined;
    try std.testing.expectError(
        error.Rejected,
        dispatcher.receiveManyVisitingWithDeadline(
            &.{quic.Version.version_1.wireValue()},
            &storage,
            &events,
            .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
            {},
            Reject.visit,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        dispatcher.buffered_datagrams.items.len,
    );

    const Observe = struct {
        fn visit(
            packet_number: *u64,
            packet: dispatcher_mod.RoutedPacketView,
        ) !void {
            packet_number.* = packet.packet.packet_number;
        }
    };
    var packet_number: u64 = std.math.maxInt(u64);
    const count = try dispatcher.receiveManyVisitingWithDeadline(
        &.{quic.Version.version_1.wireValue()},
        &storage,
        &events,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        &packet_number,
        Observe.visit,
    );
    defer for (events[0..count]) |*event| event.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u64, 1), packet_number);
    try std.testing.expect(events[0] == .packet);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.buffered_datagrams.items.len);
}

test "QUIC endpoint dispatcher visitor falls back for key updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb5} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "update-server",
        .peer_connection_id = "update-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "update-client",
        .peer_connection_id = "update-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    var dispatcher = Dispatcher.init(allocator, &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(66, &server);

    try client.initiateKeyUpdate();
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "updated",
        .fin = true,
    } }});
    const Observed = struct {
        called: bool = false,

        fn visit(
            observed: *@This(),
            packet: dispatcher_mod.RoutedPacketView,
        ) !void {
            try std.testing.expect(packet.packet.peer_initiated_key_update);
            try std.testing.expectEqualStrings(
                "updated",
                packet.packet.frames[0].stream.data,
            );
            observed.called = true;
        }
    };
    var storage: [4096]u8 = undefined;
    var observed: Observed = .{};
    var event = try dispatcher.receiveVisitingWithDeadline(
        &.{quic.Version.version_1.wireValue()},
        &storage,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
        &observed,
        Observed.visit,
    );
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expect(observed.called);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.peerOneRttKeyUpdateCount());
}

test "QUIC endpoint dispatcher polls stream credit without owning receive" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "poll-server",
        .peer_connection_id = "poll-client",
        .initial_send_max_streams_bidi = 1,
        .initial_send_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(77, &connection);

    try std.testing.expectError(
        error.UnknownConnectionHandle,
        dispatcher.pollOpenStream(78),
    );
    try std.testing.expectEqual(@as(?u64, 0), try dispatcher.pollOpenStream(77));
    try std.testing.expectEqual(
        @as(?u64, 2),
        try dispatcher.pollOpenUnidirectionalStream(77),
    );

    const grant_frames = [_]quic.Frame{
        .{ .max_streams_bidi = .{ .maximum_streams = 2 } },
        .{ .max_streams_uni = .{ .maximum_streams = 2 } },
    };
    try one_rtt.sendFrames(
        &peer_endpoint,
        endpoint.address(),
        keys,
        .{
            .destination_connection_id = "poll-server",
            .packet_number = 0,
            .frames = &grant_frames,
        },
    );

    const before = connection.stats();
    try std.testing.expectEqual(
        @as(?u64, null),
        try dispatcher.pollOpenStream(77),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        try dispatcher.pollOpenUniStream(77),
    );
    try std.testing.expectEqual(before.packets_sent, connection.stats().packets_sent);
    try std.testing.expectEqual(
        before.packets_received,
        connection.stats().packets_received,
    );
    try std.testing.expectEqual(
        @as(u64, 4),
        connection.nextLocalBidirectionalStreamId(),
    );
    try std.testing.expectEqual(
        @as(u64, 6),
        connection.nextLocalUnidirectionalStreamId(),
    );

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var event = try dispatcher.receive(&versions);
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(@as(ConnectionHandle, 77), event.packet.connection_handle);
    try std.testing.expectEqual(@as(?u64, 4), try dispatcher.pollOpenStream(77));
    try std.testing.expectEqual(
        @as(?u64, 6),
        try dispatcher.pollOpenUnidirectionalStream(77),
    );

    const connection_timer = connection.nextTimerDeadline();
    const endpoint_timer = dispatcher.nextTimerDeadline();
    if (connection_timer) |timer| {
        const scheduled = endpoint_timer orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(
            @as(ConnectionHandle, 77),
            scheduled.connection_id,
        );
        try std.testing.expectEqual(timer, scheduled.timer);
    } else {
        try std.testing.expect(endpoint_timer == null);
    }

    // A caller may close a registered connection between endpoint turns. The
    // failed poll still mirrors its newly armed close timer.
    try connection.closeApplication(0, "done");
    try std.testing.expectError(
        error.ConnectionClosed,
        dispatcher.pollOpenStream(77),
    );
    const close_timer = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    const endpoint_close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        @as(ConnectionHandle, 77),
        endpoint_close_timer.connection_id,
    );
    try std.testing.expectEqual(close_timer, endpoint_close_timer.timer);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close,
        endpoint_close_timer.timer.kind,
    );
}

test "QUIC endpoint dispatcher synchronizes local CID rotation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    const reset_key = [_]u8{0x5e} **
        quic.stateless_reset.static_key_len;
    var connection = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cid-zero",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 3,
        .local_stateless_reset_key = reset_key,
    });
    defer connection.deinit();
    const stable_id = connection.stableId();
    try std.testing.expect(stable_id != 0);
    var peer_connection = try one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "peer",
        .peer_connection_id = "cid-zero",
        .enable_pacing = false,
    });
    defer peer_connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &server_endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(11, &connection);
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    const initial_revision = connection.localConnectionIdRevision();
    try std.testing.expectEqual(
        @as(?u64, initial_revision),
        dispatcher.connections.getPtr(11).?.connection_id_revision,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        dispatcher.connections.getPtr(11).?.connection_id_sync_count,
    );
    // Drive an authenticated ordinary packet through the conditional path.
    // It must not enumerate/rewrite the unchanged CID set.
    try peer_connection.send(&.{.{ .ping = {} }});
    var ordinary = try dispatcher.receive(
        &.{quic.Version.version_1.wireValue()},
    );
    ordinary.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expectEqual(
        @as(?u64, initial_revision),
        dispatcher.connections.getPtr(11).?.connection_id_revision,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        dispatcher.connections.getPtr(11).?.connection_id_sync_count,
    );

    try dispatcher.sendNewConnectionIdWithDerivedTokenRetiringPriorTo(
        11,
        "cid-one",
        1,
    );
    try std.testing.expectEqual(initial_revision +% 1, connection.localConnectionIdRevision());
    try std.testing.expectEqual(
        @as(?u64, connection.localConnectionIdRevision()),
        dispatcher.connections.getPtr(11).?.connection_id_revision,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        dispatcher.connections.getPtr(11).?.connection_id_sync_count,
    );
    try std.testing.expectEqual(@as(usize, 2), dispatcher.routeCount());
    try std.testing.expectEqual(
        @as(u64, 1),
        (try dispatcher.router.lookup("cid-one")).?.sequence_number,
    );

    var new_cid = try peer_connection.receivePacket();
    defer new_cid.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 1),
        new_cid.frames[0].new_connection_id.retire_prior_to,
    );
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(reset_key, "cid-one"),
        &new_cid.frames[0].new_connection_id.stateless_reset_token,
    );
    // Sending NEW_CONNECTION_ID does not immediately invalidate the old
    // route. The peer first selects the replacement and confirms retirement.
    try std.testing.expect((try dispatcher.router.lookup("cid-zero")) != null);
    try std.testing.expectEqualStrings(
        "cid-one",
        peer_connection.config.peer_connection_id,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        peer_connection.pendingRetireConnectionIdCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        try peer_connection.sendPendingRetireConnectionIds(),
    );
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var retired = try dispatcher.receive(&versions);
    defer retired.deinit(allocator);
    try std.testing.expect(retired == .packet);
    try std.testing.expectEqual(
        @as(ConnectionHandle, 11),
        retired.packet.connection_handle,
    );
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expect((try dispatcher.router.lookup("cid-zero")) == null);
    try std.testing.expect((try dispatcher.router.lookup("cid-one")) != null);
    try std.testing.expectEqual(initial_revision +% 2, connection.localConnectionIdRevision());
    try std.testing.expectEqual(
        @as(?u64, connection.localConnectionIdRevision()),
        dispatcher.connections.getPtr(11).?.connection_id_revision,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        dispatcher.connections.getPtr(11).?.connection_id_sync_count,
    );

    const migrated_peer = std.Io.net.IpAddress{ .ip4 = .loopback(6553) };
    try connection.beginPeerMigration(
        migrated_peer,
        [_]u8{0x44} ** 8,
    );
    try std.testing.expectEqual(
        initial_revision +% 2,
        connection.localConnectionIdRevision(),
    );
    try dispatcher.syncConnectionIdsIfChanged(11);
    try std.testing.expect(
        (try dispatcher.router.lookup("cid-one")).?.peer_address.?
            .eql(&migrated_peer),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        dispatcher.connections.getPtr(11).?.connection_id_sync_count,
    );
    try std.testing.expectEqual(stable_id, connection.stableId());
    try std.testing.expect(stable_id != peer_connection.stableId());
}

test "QUIC endpoint dispatcher rejects cross-connection CID collisions transactionally" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    var first = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "first",
        .peer_connection_id = "peer-a",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 3,
    });
    defer first.deinit();
    var second = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "second",
        .peer_connection_id = "peer-b",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 3,
    });
    defer second.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &first);
    try dispatcher.registerConnection(2, &second);

    try dispatcher.sendNewConnectionId(
        1,
        "shared-cid",
        [_]u8{1} ** 16,
    );
    var before_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
    const second_before_count = (try second.localConnectionIdsInto(
        &before_storage,
    )).len;
    try std.testing.expectError(
        error.DuplicateConnectionId,
        dispatcher.sendNewConnectionId(
            2,
            "shared-cid",
            [_]u8{2} ** 16,
        ),
    );
    var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
    const second_after = try second.localConnectionIdsInto(&active_storage);
    try std.testing.expectEqual(second_before_count, second_after.len);
    try std.testing.expectEqual(@as(usize, 3), dispatcher.routeCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        (try dispatcher.router.lookup("shared-cid")).?.connection_index,
    );
}

test "QUIC endpoint dispatcher leaves no CID route after send failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe7} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "initial",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 3,
        .local_stateless_reset_key = [_]u8{0x6e} **
            quic.stateless_reset.static_key_len,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &connection);
    const revision_before = connection.localConnectionIdRevision();
    const sync_count_before =
        dispatcher.connections.getPtr(1).?.connection_id_sync_count;

    var failed_send = ObservedBatchSend{
        .delegate = endpoint.io,
        .fail_after_prefix = 0,
    };
    endpoint.io = failed_send.io();
    defer endpoint.io = failed_send.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        dispatcher.trySendNewConnectionIdsWithDerivedTokens(
            1,
            &.{ "failed-cid-a", "failed-cid-b" },
        ),
    );
    var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try connection.localConnectionIdsInto(&active_storage)).len,
    );
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expect((try dispatcher.router.lookup("failed-cid-a")) == null);
    try std.testing.expect((try dispatcher.router.lookup("failed-cid-b")) == null);
    try std.testing.expectEqual(
        revision_before,
        connection.localConnectionIdRevision(),
    );
    try std.testing.expectEqual(
        sync_count_before,
        dispatcher.connections.getPtr(1).?.connection_id_sync_count,
    );
}

test "QUIC endpoint dispatcher batches derived CID replenishment" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    const reset_key = [_]u8{0x7e} **
        quic.stateless_reset.static_key_len;
    const initial_cid = "batch-cid-init00";
    const peer_cid = "batch-peer-id-00";
    const new_cids = [_][]const u8{
        "batch-cid-one-01",
        "batch-cid-two-02",
        "batch-cid-tre-03",
    };
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = initial_cid,
        .peer_connection_id = peer_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 4,
        .local_stateless_reset_key = reset_key,
    });
    defer connection.deinit();
    var peer = try one_rtt.Connection.init(&peer_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = peer_cid,
        .peer_connection_id = initial_cid,
        .enable_pacing = false,
        .active_connection_id_limit = 4,
    });
    defer peer.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(7, &connection);

    var observed_send = ObservedBatchSend{ .delegate = endpoint.io };
    endpoint.io = observed_send.io();
    defer endpoint.io = observed_send.delegate;

    try std.testing.expectError(
        error.DuplicateConnectionId,
        dispatcher.trySendNewConnectionIdsWithDerivedTokens(
            7,
            &.{ "batch-duplicate0", "batch-duplicate0" },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), observed_send.calls);
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.localConnectionIdCount(),
    );
    try dispatcher.trySendNewConnectionIdsWithDerivedTokens(
        7,
        &new_cids,
    );
    try std.testing.expectEqual(@as(usize, 1), observed_send.calls);
    try std.testing.expectEqual(@as(usize, 4), dispatcher.routeCount());
    try std.testing.expectEqual(@as(usize, 4), connection.localConnectionIdCount());

    var packet = try peer.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(new_cids.len, packet.frames.len);
    for (packet.frames, new_cids, 1..) |frame, connection_id, sequence| {
        try std.testing.expect(frame == .new_connection_id);
        try std.testing.expectEqual(
            @as(u64, sequence),
            frame.new_connection_id.sequence_number,
        );
        try std.testing.expectEqualStrings(
            connection_id,
            frame.new_connection_id.connection_id,
        );
        try std.testing.expectEqualSlices(
            u8,
            &quic.stateless_reset.tokenForConnectionId(
                reset_key,
                connection_id,
            ),
            &frame.new_connection_id.stateless_reset_token,
        );
    }
}

test "QUIC endpoint dispatcher preserves unknown Initials and discards late long headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = .{ .ip4 = .loopback(4444) },
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "established",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
    });
    defer connection.deinit();

    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(7, &connection);

    const payload = [_]u8{0} ** 1160;
    const unknown_keys = try quic.protection.deriveInitialSecretsForVersion(
        quic.Version.version_1.wireValue(),
        "unknown-initial",
    );
    const unknown = try quic.protection.sealInitialPacket(
        allocator,
        unknown_keys.client,
        .{
            .destination_connection_id = "unknown-initial",
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &payload,
        },
    );
    var unknown_datagram = runtime.OwnedBytes{
        .from = .{ .ip4 = .loopback(4444) },
        .bytes = unknown,
    };
    var unknown_event = try dispatcher.dispatch(unknown_datagram);
    // Ownership moved into the event; avoid an accidental second cleanup in
    // future edits to this test.
    unknown_datagram = undefined;
    defer unknown_event.deinit(allocator);
    try std.testing.expect(unknown_event == .new_initial);
    try std.testing.expectEqual(
        quic.Version.version_1.wireValue(),
        unknown_event.new_initial.version,
    );
    try std.testing.expectEqualStrings(
        "unknown-initial",
        unknown_event.new_initial.destination_connection_id,
    );
    try std.testing.expectEqualStrings(
        "peer",
        unknown_event.new_initial.source_connection_id,
    );
    try std.testing.expectEqual(
        unknown_event.new_initial.datagram.bytes.len,
        unknown_event.new_initial.first_packet_len,
    );

    const late_keys = try quic.protection.deriveInitialSecretsForVersion(
        quic.Version.version_1.wireValue(),
        "established",
    );
    const late = try quic.protection.sealInitialPacket(
        allocator,
        late_keys.client,
        .{
            .destination_connection_id = "established",
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    var late_event = try dispatcher.dispatch(.{
        .from = .{ .ip4 = .loopback(4444) },
        .bytes = late,
    });
    defer late_event.deinit(allocator);
    try std.testing.expectEqual(
        @as(Event, .{ .discarded_long_header = 7 }),
        late_event,
    );
}

test "QUIC endpoint dispatcher admits only bounded unknown Initials" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    const from = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    const payload = [_]u8{0} ** 1160;

    for ([_]quic.Version{ .version_1, .version_2 }) |version| {
        const dcid = if (version == .version_1)
            "admit-v1"
        else
            "admit-v2";
        const secrets = try quic.protection.deriveInitialSecretsForVersion(
            version.wireValue(),
            dcid,
        );
        const bytes = try quic.protection.sealInitialPacket(
            allocator,
            secrets.client,
            .{
                .version = version.wireValue(),
                .destination_connection_id = dcid,
                .source_connection_id = "peer",
                .packet_number = 0,
                .payload = &payload,
            },
        );
        var event = try dispatcher.dispatch(.{ .from = from, .bytes = bytes });
        defer event.deinit(allocator);
        try std.testing.expect(event == .new_initial);
        try std.testing.expectEqual(version.wireValue(), event.new_initial.version);
        try std.testing.expectEqualStrings(
            dcid,
            event.new_initial.destination_connection_id,
        );
    }

    const short_dcid = "short";
    const short_secrets = try quic.protection.deriveInitialSecretsForVersion(
        quic.Version.version_1.wireValue(),
        short_dcid,
    );
    const short_initial = try quic.protection.sealInitialPacket(
        allocator,
        short_secrets.client,
        .{
            .destination_connection_id = short_dcid,
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &payload,
        },
    );
    var short_event = try dispatcher.dispatch(.{
        .from = from,
        .bytes = short_initial,
    });
    defer short_event.deinit(allocator);
    try std.testing.expectEqual(
        dispatcher_mod.UnroutedKind.undersized_initial,
        short_event.unrouted.kind,
    );

    const small_dcid = "small-id";
    const small_secrets = try quic.protection.deriveInitialSecretsForVersion(
        quic.Version.version_1.wireValue(),
        small_dcid,
    );
    const small_initial = try quic.protection.sealInitialPacket(
        allocator,
        small_secrets.client,
        .{
            .destination_connection_id = small_dcid,
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    var small_event = try dispatcher.dispatch(.{
        .from = from,
        .bytes = small_initial,
    });
    defer small_event.deinit(allocator);
    try std.testing.expectEqual(
        dispatcher_mod.UnroutedKind.undersized_initial,
        small_event.unrouted.kind,
    );

    const handshake = try quic.protection.sealHandshakePacket(
        allocator,
        quic.protection.deriveAes128Keys(
            [_]u8{0xe4} ** quic.protection.secret_len,
        ),
        .{
            .destination_connection_id = "handshake",
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    var handshake_event = try dispatcher.dispatch(.{
        .from = from,
        .bytes = handshake,
    });
    defer handshake_event.deinit(allocator);
    try std.testing.expectEqual(
        dispatcher_mod.UnroutedKind.non_initial_long_header,
        handshake_event.unrouted.kind,
    );

    const malformed = try allocator.dupe(u8, &.{ 0xc0, 0, 0, 0, 1 });
    var malformed_event = try dispatcher.dispatch(.{
        .from = from,
        .bytes = malformed,
    });
    defer malformed_event.deinit(allocator);
    try std.testing.expectEqual(
        dispatcher_mod.UnroutedKind.malformed_long_header,
        malformed_event.unrouted.kind,
    );
}

test "QUIC endpoint dispatcher defers batched Initial suffix until admission" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();

    const destination_connection_id = "batch-admission";
    const initial_keys = try quic.protection.deriveInitialSecretsForVersion(
        quic.Version.version_1.wireValue(),
        destination_connection_id,
    );
    const initial_payload = [_]u8{0} ** 1160;
    const initial = try quic.protection.sealInitialPacket(
        allocator,
        initial_keys.client,
        .{
            .destination_connection_id = destination_connection_id,
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &initial_payload,
        },
    );
    defer allocator.free(initial);
    try peer.sendBytes(endpoint.address(), initial);
    try one_rtt.sendFrames(
        &peer,
        endpoint.address(),
        quic.protection.deriveAes128Keys(
            [_]u8{0xb7} ** quic.protection.secret_len,
        ),
        .{
            .destination_connection_id = destination_connection_id,
            .packet_number = 0,
            .frames = &.{.{ .ping = {} }},
        },
    );

    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{}!void {}
    };
    const versions = &.{quic.Version.version_1.wireValue()};
    var storage: [2 * 4096]u8 = undefined;
    var events: [2]dispatcher_mod.VisitEvent = undefined;
    const count = try dispatcher.receiveManyVisitingWithDeadline(
        versions,
        &storage,
        &events,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        {},
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(events[0] == .new_initial);
    try std.testing.expectEqual(@as(usize, 1), dispatcher.buffered_datagrams.items.len);
    events[0].deinit(allocator);

    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{destination_connection_id},
        peer.address(),
        2,
    );
    defer inbox.deinit();
    try dispatcher.registerPendingHandshake(91, &inbox);
    const deferred = try dispatcher.receiveManyVisitingWithDeadline(
        versions,
        &storage,
        &events,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        {},
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 1), deferred);
    try std.testing.expectEqual(
        @as(dispatcher_mod.VisitEvent, .{ .pending_handshake = 91 }),
        events[0],
    );
    events[0].deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), inbox.applicationCount());
    try std.testing.expect(try dispatcher.unregisterPendingHandshake(91));
}

test "QUIC endpoint dispatcher wakes deadline receive for transport timers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe2} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-local",
        .peer_connection_id = "timer-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(9, &connection);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try connection.send(&ping);
    try dispatcher.refreshConnectionTimer(9);

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var event = try dispatcher.receiveWithDeadline(&versions, .fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    }));
    defer event.deinit(allocator);
    try std.testing.expect(event == .timer);
    try std.testing.expectEqual(@as(ConnectionHandle, 9), event.timer.connection_handle);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pto,
        event.timer.timer.kind,
    );
}

test "QUIC endpoint dispatcher batches each due connection once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    var first = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-a",
        .peer_connection_id = "peer-a",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer first.deinit();
    var second = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-b",
        .peer_connection_id = "peer-b",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer second.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &first);
    try dispatcher.registerConnection(2, &second);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try first.send(&ping);
    try second.send(&ping);
    try dispatcher.refreshConnectionTimer(1);
    try dispatcher.refreshConnectionTimer(2);

    const first_deadline = dispatcher.nextTimerDeadline().?.timer.deadline_ns;
    var events: [2]dispatcher_mod.TimerEvent = undefined;
    const count = try dispatcher.serviceDueTimersAt(
        first_deadline + 10 * std.time.ns_per_s,
        &events,
    );
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expect(events[0].connection_handle !=
        events[1].connection_handle);
    // PTO servicing rearms recovery, but the snapshot visits each connection
    // once; immediate retransmission cannot monopolize this batch.
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.pto, events[0].timer.kind);
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.pto, events[1].timer.kind);
}

test "QUIC endpoint dispatcher public batch bounds due timers before receive" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var first = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-public-a",
        .peer_connection_id = "peer-public-a",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer first.deinit();
    var second = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-public-b",
        .peer_connection_id = "peer-public-b",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer second.deinit();
    var third = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-public-c",
        .peer_connection_id = "peer-public-c",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer third.deinit();

    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &first);
    try dispatcher.registerConnection(2, &second);
    try dispatcher.registerConnection(3, &third);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{&ping};
    for ([_]*one_rtt.Connection{ &first, &second, &third }) |connection| {
        const sent = try connection.sendManyProgressAt(&packets, 1);
        try std.testing.expectEqual(@as(usize, 1), sent.sent_count);
        try std.testing.expectEqual(@as(usize, 1), sent.protected_count);
        try std.testing.expect(sent.send_error == null);
    }
    try dispatcher.refreshConnectionTimer(1);
    try dispatcher.refreshConnectionTimer(2);
    try dispatcher.refreshConnectionTimer(3);

    // Keep one valid datagram queued. Due timers must be returned before the
    // dispatcher enters the UDP receive path, so this remains for a later
    // call after all three timer handles have had a fair turn.
    try one_rtt.sendFrames(&peer, endpoint.address(), keys, .{
        .destination_connection_id = "timer-public-a",
        .packet_number = 0,
        .frames = &ping,
    });

    const Visitor = struct {
        fn visit(calls: *usize, packet: dispatcher_mod.RoutedPacketView) !void {
            calls.* += 1;
            try std.testing.expectEqual(
                @as(ConnectionHandle, 1),
                packet.connection_handle,
            );
        }
    };
    const versions = &.{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    });
    var visitor_calls: usize = 0;
    var storage: [2 * 4096]u8 = undefined;
    var events: [2]dispatcher_mod.VisitEvent = undefined;
    const first_count = try dispatcher.receiveManyVisitingWithDeadline(
        versions,
        &storage,
        &events,
        deadline,
        &visitor_calls,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 2), first_count);
    try std.testing.expect(events[0] == .timer);
    try std.testing.expect(events[1] == .timer);
    try std.testing.expect(
        events[0].timer.connection_handle !=
            events[1].timer.connection_handle,
    );
    try std.testing.expectEqual(@as(usize, 0), visitor_calls);

    var one_event: [1]dispatcher_mod.VisitEvent = undefined;
    const second_count = try dispatcher.receiveManyVisitingWithDeadline(
        versions,
        storage[0..4096],
        &one_event,
        deadline,
        &visitor_calls,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 1), second_count);
    try std.testing.expect(one_event[0] == .timer);
    try std.testing.expect(
        one_event[0].timer.connection_handle !=
            events[0].timer.connection_handle,
    );
    try std.testing.expect(
        one_event[0].timer.connection_handle !=
            events[1].timer.connection_handle,
    );
    try std.testing.expectEqual(@as(usize, 0), visitor_calls);

    const packet_count = try dispatcher.receiveManyVisitingWithDeadline(
        versions,
        storage[0..4096],
        &one_event,
        deadline,
        &visitor_calls,
        Visitor.visit,
    );
    defer for (one_event[0..packet_count]) |*event| event.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packet_count);
    try std.testing.expect(one_event[0] == .packet);
    try std.testing.expectEqual(@as(usize, 1), visitor_calls);
}

test "QUIC endpoint dispatcher timer batch continues past paced connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    var paced = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-paced",
        .peer_connection_id = "peer-paced",
        .local_endpoint = .server,
    });
    defer paced.deinit();
    var ready = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-ready",
        .peer_connection_id = "peer-ready",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer ready.deinit();

    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &paced);
    try dispatcher.registerConnection(2, &ready);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{&ping};
    for ([_]*one_rtt.Connection{ &paced, &ready }) |connection| {
        const sent = try connection.sendManyProgressAt(&packets, 1);
        try std.testing.expectEqual(@as(usize, 1), sent.sent_count);
    }
    try dispatcher.refreshConnectionTimer(1);
    try dispatcher.refreshConnectionTimer(2);

    const now_ns = dispatcher.nextTimerDeadline().?.timer.deadline_ns +
        10 * std.time.ns_per_s;
    one_rtt.testing.exhaustPacingAt(&paced, now_ns);
    var events: [2]dispatcher_mod.TimerEvent = undefined;
    const count = try dispatcher.serviceDueTimersAt(now_ns, &events);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(ConnectionHandle, 2), events[0].connection_handle);
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.pto, events[0].timer.kind);
    const paced_deadline = dispatcher.timers.deadlineForConnection(1) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pacing,
        paced_deadline.timer.kind,
    );
    try std.testing.expect(paced_deadline.timer.deadline_ns > now_ns);
}

test "QUIC endpoint dispatcher negotiates versions before Initial admission" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server.deinit();
    var client = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client.deinit();
    var dispatcher = Dispatcher.init(allocator, &server);
    defer dispatcher.deinit();

    const unsupported = [_]u8{
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        3,    's',  'r',  'v',  3,
        'c',  'l',  'i',  0,
    };
    try client.sendBytes(server.address(), &unsupported);

    const dcid = "admit-next";
    const secrets = try quic.protection.deriveInitialSecretsForVersion(
        quic.Version.version_1.wireValue(),
        dcid,
    );
    const initial = try quic.protection.sealInitialPacket(
        allocator,
        secrets.client,
        .{
            .destination_connection_id = dcid,
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &([_]u8{0} ** 1160),
        },
    );
    defer allocator.free(initial);
    try client.sendBytes(server.address(), initial);

    const supported = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var event = try dispatcher.receive(&supported);
    defer event.deinit(allocator);
    try std.testing.expect(event == .new_initial);
    try std.testing.expectEqualStrings(
        dcid,
        event.new_initial.destination_connection_id,
    );

    var response = try client.receiveBytes();
    defer response.deinit(allocator);
    var negotiation = try quic.parseVersionNegotiationPacket(
        allocator,
        response.bytes,
    );
    defer negotiation.deinit(allocator);
    try std.testing.expectEqualStrings("cli", negotiation.destination_connection_id);
    try std.testing.expectEqualStrings("srv", negotiation.source_connection_id);
    try std.testing.expectEqualSlices(u32, &supported, negotiation.versions);
}

test "QUIC endpoint dispatcher routes and promotes a pending handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{ "admitted", "pending-server" },
        peer,
        2,
    );
    defer inbox.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerPendingHandshake(41, &inbox);
    try std.testing.expectEqual(@as(usize, 1), dispatcher.pendingHandshakeCount());

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xef} ** quic.protection.secret_len,
    );
    const spoofed = try quic.protection.sealHandshakePacket(
        allocator,
        keys,
        .{
            .destination_connection_id = "pending-server",
            .source_connection_id = "peer",
            .packet_number = 0,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    var spoofed_peer = peer;
    spoofed_peer.ip4.bytes = .{ 127, 0, 0, 2 };
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(.{
        .from = spoofed_peer,
        .bytes = spoofed,
    }));
    try std.testing.expectEqual(@as(usize, 2), inbox.remainingCapacity());

    for ([_][]const u8{ "admitted", "pending-server" }) |cid| {
        const datagram = try quic.protection.sealHandshakePacket(
            allocator,
            keys,
            .{
                .destination_connection_id = cid,
                .source_connection_id = "peer",
                .packet_number = 0,
                .payload = &.{@intFromEnum(quic.FrameType.ping)},
            },
        );
        var event = try dispatcher.dispatch(.{
            .from = peer,
            .bytes = datagram,
        });
        defer event.deinit(allocator);
        try std.testing.expectEqual(
            @as(Event, .{ .pending_handshake = 41 }),
            event,
        );
        var received = try inbox.receive();
        defer received.deinit(allocator);
        const info = try quic.protection.peekProtectedLongPacketInfo(
            received.bytes,
        );
        try std.testing.expectEqualStrings(cid, info.destination_connection_id);
    }

    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pending-server",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    try dispatcher.promotePendingHandshake(41, 42, &connection);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expectError(error.Closed, inbox.receive());
    try std.testing.expect(try dispatcher.unregisterConnection(42));
}

test "QUIC endpoint dispatcher drains a coalesced packet after promotion" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf0} ** quic.protection.secret_len,
    );
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{ "admitted", "pending-server" },
        peer,
        1,
    );
    defer inbox.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerPendingHandshake(51, &inbox);

    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pending-server",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 0,
        .data = "coalesced",
        .fin = true,
    } }).write(&payload, allocator);
    const buffered = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "pending-server",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(buffered);
    try connection.preloadReceivedDatagram(peer, buffered, .not_ect);

    try dispatcher.promotePendingHandshake(51, 52, &connection);
    try std.testing.expectEqual(
        @as(usize, 1),
        dispatcher.pending_ready.?.handles.items.len,
    );
    var event = try dispatcher.receive(
        &.{quic.Version.version_1.wireValue()},
    );
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(
        @as(usize, 52),
        event.packet.connection_handle,
    );
    try std.testing.expectEqualStrings(
        "coalesced",
        event.packet.packet.frames[0].stream.data,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        dispatcher.pending_ready.?.handles.items.len,
    );
    try std.testing.expect((try dispatcher.pollPendingPacket()) == null);
    try std.testing.expect((try dispatcher.pollConnectionPacket(52)) == null);
    try std.testing.expect(try dispatcher.unregisterConnection(52));
}

test "QUIC endpoint dispatcher visits an externally received datagram" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "dispatch-view",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(71, &connection);

    try one_rtt.sendFrames(
        &peer_endpoint,
        endpoint.address(),
        keys,
        .{
            .destination_connection_id = "dispatch-view",
            .packet_number = 0,
            .frames = &.{.{ .ping = {} }},
        },
    );
    var storage: [4096]u8 = undefined;
    const datagram = try endpoint.receiveBytesInto(&storage);
    const Visitor = struct {
        fn visit(
            saw_ping: *bool,
            packet: dispatcher_mod.RoutedPacketView,
        ) !void {
            for (packet.packet.frames) |frame| {
                saw_ping.* = saw_ping.* or frame == .ping;
            }
        }
    };
    var saw_ping = false;
    var event = try dispatcher.dispatchVisitingDatagram(
        datagram,
        &saw_ping,
        Visitor.visit,
    );
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(
        @as(ConnectionHandle, 71),
        event.packet.connection_handle,
    );
    try std.testing.expect(saw_ping);
}

test "QUIC endpoint dispatcher ready index allocation failure is transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = .{ .ip4 = .loopback(5557) },
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "oom-ready",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var dispatcher = Dispatcher.init(failing.allocator(), &endpoint);
    defer dispatcher.deinit();
    try dispatcher.timers.ensureCapacity(1);
    try dispatcher.router.ensureCapacity(quic.connection_id.max_pool_size);
    // Creating PendingReady succeeds, then its first queue reservation fails.
    // The half-built index must not be published into the dispatcher.
    failing.fail_index = failing.alloc_index + 1;
    try std.testing.expectError(
        error.OutOfMemory,
        dispatcher.registerConnection(63, &connection),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(dispatcher.pending_ready == null);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.routeCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.timers.count());

    // A successful registration elsewhere proves the failed attempt did not
    // leave the caller-owned connection's observer bound.
    var verifier = Dispatcher.init(allocator, &endpoint);
    defer verifier.deinit();
    try verifier.registerConnection(64, &connection);
    try std.testing.expect(try verifier.unregisterConnection(64));
}

test "QUIC endpoint dispatcher promotion preserves pending routes when ready index allocation fails" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5558) };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf3} ** quic.protection.secret_len,
    );
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{ "oom-admitted", "oom-promote" },
        peer,
        1,
    );
    defer inbox.deinit();
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "oom-promote",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var dispatcher = Dispatcher.init(failing.allocator(), &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerPendingHandshake(65, &inbox);
    try dispatcher.timers.ensureCapacity(1);
    try dispatcher.router.ensureCapacity(quic.connection_id.max_pool_size);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        dispatcher.promotePendingHandshake(65, 66, &connection),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(dispatcher.pending_ready == null);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.routeCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.timers.count());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.pendingHandshakeCount());
    for (inbox.connectionIds()) |connection_id| {
        const route = (try dispatcher.pending_router.lookup(
            connection_id.slice(),
        )) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 65), route.connection_index);
    }

    var verifier = Dispatcher.init(allocator, &endpoint);
    defer verifier.deinit();
    try verifier.registerConnection(67, &connection);
    try std.testing.expect(try verifier.unregisterConnection(67));
    try std.testing.expect(try dispatcher.unregisterPendingHandshake(65));
}

test "QUIC endpoint dispatcher indexes pending packets for direct registrations" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5556) };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf1} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "direct-pending",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    var dispatcher_owned = true;
    defer if (dispatcher_owned) dispatcher.deinit();
    try dispatcher.registerConnection(61, &connection);
    try std.testing.expectEqual(
        @as(usize, 0),
        dispatcher.pending_ready.?.handles.items.len,
    );
    var competing = Dispatcher.init(allocator, &endpoint);
    defer competing.deinit();
    try std.testing.expectError(
        error.PendingDatagramObserverBound,
        competing.registerConnection(62, &connection),
    );
    try std.testing.expectEqual(@as(usize, 0), competing.connectionCount());
    var moved_dispatcher = dispatcher;
    dispatcher_owned = false;
    defer moved_dispatcher.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .ping = {} }).write(&payload, allocator);
    const buffered = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "direct-pending",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(buffered);
    try connection.preloadReceivedDatagram(peer, buffered, .not_ect);
    try std.testing.expectEqual(
        @as(usize, 1),
        moved_dispatcher.pending_ready.?.handles.items.len,
    );
    var consumed_directly = (try connection.receivePendingPacket()) orelse
        return error.TestUnexpectedResult;
    defer consumed_directly.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 1),
        moved_dispatcher.pending_ready.?.handles.items.len,
    );

    const reloaded = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "direct-pending",
        .packet_number = 1,
        .payload = payload.items,
    });
    defer allocator.free(reloaded);
    try connection.preloadReceivedDatagram(peer, reloaded, .not_ect);
    try std.testing.expectEqual(
        @as(usize, 1),
        moved_dispatcher.pending_ready.?.handles.items.len,
    );

    var event = (try moved_dispatcher.pollPendingPacket()) orelse
        return error.TestUnexpectedResult;
    defer event.packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 61), event.connection_handle);
    try std.testing.expect(event.packet.frames[0] == .ping);
    try std.testing.expect((try moved_dispatcher.pollPendingPacket()) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        moved_dispatcher.pending_ready.?.handles.items.len,
    );
    try std.testing.expect(try moved_dispatcher.unregisterConnection(61));

    const after_unregister = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = "direct-pending",
            .packet_number = 2,
            .payload = payload.items,
        },
    );
    defer allocator.free(after_unregister);
    try connection.preloadReceivedDatagram(
        peer,
        after_unregister,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        moved_dispatcher.pending_ready.?.handles.items.len,
    );
}

test "QUIC endpoint dispatcher bounds pending admission and generates CIDs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    const first_bytes = try allocator.dupe(u8, "first");
    var first_datagram = runtime.OwnedBytes{
        .from = peer,
        .bytes = first_bytes,
    };
    defer first_datagram.deinit(allocator);
    const first = dispatcher_mod.InitialDatagram{
        .datagram = first_datagram,
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = "first-dcid",
        .source_connection_id = "client",
        .first_packet_len = first_bytes.len,
    };
    const inbox = try dispatcher.admitPendingHandshake(61, first, 1, 2);
    defer {
        inbox.deinit();
        allocator.destroy(inbox);
    }
    defer dispatcher.deinit();
    try std.testing.expectEqual(@as(usize, 2), inbox.connectionIds().len);
    try std.testing.expectEqualStrings(
        "first-dcid",
        inbox.connectionIds()[0].slice(),
    );
    try std.testing.expectEqual(
        @as(usize, dispatcher_mod.default_server_connection_id_len),
        inbox.connectionIds()[1].slice().len,
    );

    const second_bytes = try allocator.dupe(u8, "second");
    var second_datagram = runtime.OwnedBytes{
        .from = peer,
        .bytes = second_bytes,
    };
    defer second_datagram.deinit(allocator);
    const second = dispatcher_mod.InitialDatagram{
        .datagram = second_datagram,
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = "second-dcid",
        .source_connection_id = "client",
        .first_packet_len = second_bytes.len,
    };
    try std.testing.expectError(
        error.PendingHandshakeLimitReached,
        dispatcher.admitPendingHandshake(62, second, 1, 2),
    );
    try std.testing.expect(try dispatcher.unregisterPendingHandshake(61));
}

test "QUIC endpoint dispatcher routes a pending preferred address CID" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    var preferred_peer = std.Io.net.IpAddress{ .ip4 = .loopback(5556) };
    preferred_peer.ip4.bytes = .{ 127, 0, 0, 2 };
    const initial_bytes = try allocator.dupe(u8, "initial");
    var initial_datagram = runtime.OwnedBytes{
        .from = peer,
        .bytes = initial_bytes,
    };
    defer initial_datagram.deinit(allocator);
    const initial = dispatcher_mod.InitialDatagram{
        .datagram = initial_datagram,
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = "original-dcid",
        .source_connection_id = "client",
        .first_packet_len = initial_bytes.len,
    };
    const inbox = try dispatcher.admitPendingHandshakeWithServerConnectionIds(
        62,
        initial,
        1,
        2,
        2,
    );
    defer {
        inbox.deinit();
        allocator.destroy(inbox);
    }
    try std.testing.expectEqual(@as(usize, 3), inbox.connectionIds().len);
    try std.testing.expect(!std.mem.eql(
        u8,
        inbox.connectionIds()[1].slice(),
        inbox.connectionIds()[2].slice(),
    ));

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf2} ** quic.protection.secret_len,
    );
    const original_path_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = inbox.connectionIds()[1].slice(),
            .packet_number = 0,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    var rejected = try dispatcher.dispatch(.{
        .from = preferred_peer,
        .bytes = original_path_packet,
    });
    defer rejected.deinit(allocator);
    try std.testing.expectEqual(@as(Event, .consumed), rejected);
    try std.testing.expectEqual(@as(usize, 0), inbox.applicationCount());

    const preferred_id = inbox.connectionIds()[2];
    const packet = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = preferred_id.slice(),
        .packet_number = 0,
        .payload = &.{@intFromEnum(quic.FrameType.ping)},
    });
    var event = try dispatcher.dispatch(.{
        .from = preferred_peer,
        .bytes = packet,
    });
    defer event.deinit(allocator);
    try std.testing.expectEqual(
        @as(Event, .{ .pending_handshake = 62 }),
        event,
    );
    try std.testing.expectEqual(@as(usize, 1), inbox.applicationCount());

    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = inbox.connectionIds()[1].slice(),
        .peer_connection_id = "client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    try connection.registerLocalPreferredAddress(.{
        .ipv4_address = .{ 127, 0, 0, 1 },
        .ipv4_port = endpoint.address().ip4.port,
        .connection_id = preferred_id.slice(),
        .stateless_reset_token = [_]u8{0xf3} ** 16,
    });
    try dispatcher.promotePendingHandshake(62, 63, &connection);
    var routed = try dispatcher.receive(
        &.{quic.Version.version_1.wireValue()},
    );
    defer routed.deinit(allocator);
    try std.testing.expect(routed == .packet);
    try std.testing.expectEqual(@as(usize, 63), routed.packet.connection_handle);
    try std.testing.expectEqual(@as(u64, 1), routed.packet.connection_id_sequence);
    try std.testing.expectEqual(preferred_peer, routed.packet.packet.from);
    try std.testing.expect(routed.packet.packet.frames[0] == .ping);
    try std.testing.expectEqual(preferred_peer, connection.peerAddress());
    try std.testing.expect(try dispatcher.unregisterConnection(63));
}

test "QUIC endpoint dispatcher routes generated preferred CID during handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    const initial_bytes = try allocator.dupe(u8, "initial");
    var initial_datagram = runtime.OwnedBytes{
        .from = peer,
        .bytes = initial_bytes,
    };
    defer initial_datagram.deinit(allocator);
    const initial = dispatcher_mod.InitialDatagram{
        .datagram = initial_datagram,
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = "original-dcid",
        .source_connection_id = "client",
        .first_packet_len = initial_bytes.len,
    };
    const inbox = try dispatcher.admitPendingHandshakeWithServerConnectionIds(
        62,
        initial,
        1,
        2,
        2,
    );
    defer {
        inbox.deinit();
        allocator.destroy(inbox);
    }
    try std.testing.expectEqual(@as(usize, 3), inbox.connectionIds().len);
    try std.testing.expect(!std.mem.eql(
        u8,
        inbox.connectionIds()[1].slice(),
        inbox.connectionIds()[2].slice(),
    ));

    var bytes = [_]u8{0} **
        (1 + dispatcher_mod.default_server_connection_id_len + 1);
    bytes[0] = 0x40;
    @memcpy(
        bytes[1..][0..dispatcher_mod.default_server_connection_id_len],
        inbox.connectionIds()[2].slice(),
    );
    var event = try dispatcher.dispatch(.{
        .from = peer,
        .bytes = try allocator.dupe(u8, &bytes),
    });
    defer event.deinit(allocator);
    try std.testing.expectEqual(
        @as(Event, .{ .pending_handshake = 62 }),
        event,
    );
    try std.testing.expectEqual(@as(usize, 1), inbox.applicationCount());
    try std.testing.expect(try dispatcher.unregisterPendingHandshake(62));
}

test "QUIC endpoint dispatcher retains early application packets until promotion" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(5555) };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf1} ** quic.protection.secret_len,
    );
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{ "admitted", "pending-server" },
        peer,
        2,
    );
    defer inbox.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerPendingHandshake(71, &inbox);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer,
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pending-server",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    for ([_][]const u8{ "early-one", "early-two" }, 0..) |body, pn| {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try (quic.Frame{ .stream = .{
            .stream_id = 0,
            .offset = if (pn == 0) 0 else "early-one".len,
            .data = body,
            .fin = pn == 1,
        } }).write(&payload, allocator);
        const datagram = try quic.protection.sealShortPacket(
            allocator,
            keys,
            .{
                .destination_connection_id = "pending-server",
                .packet_number = pn,
                .payload = payload.items,
            },
        );
        var event = try dispatcher.dispatch(.{
            .from = peer,
            .bytes = datagram,
        });
        defer event.deinit(allocator);
        try std.testing.expectEqual(
            @as(Event, .{ .pending_handshake = 71 }),
            event,
        );
    }
    try std.testing.expectEqual(@as(usize, 2), inbox.applicationCount());
    try dispatcher.promotePendingHandshake(71, 72, &connection);

    for ([_][]const u8{ "early-one", "early-two" }) |body| {
        var event = try dispatcher.receive(
            &.{quic.Version.version_1.wireValue()},
        );
        defer event.deinit(allocator);
        try std.testing.expect(event == .packet);
        try std.testing.expectEqual(@as(usize, 72), event.packet.connection_handle);
        try std.testing.expectEqualStrings(body, event.packet.packet.frames[0].stream.data);
    }
    try std.testing.expect(try dispatcher.unregisterConnection(72));
}

test "QUIC endpoint dispatcher caller timeout coexists with transport timers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();

    try std.testing.expectError(error.Timeout, dispatcher.receiveTimeout(
        &.{quic.Version.version_1.wireValue()},
        .{ .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(1),
        } },
    ));
}

test "QUIC endpoint dispatcher validates caller-owned deadlines" {
    const allocator = std.testing.allocator;
    // The native deadline contract runs on netz's supported asynchronous
    // backend. Foreign timed-I/O capability errors have separate coverage.
    var backend = try @import("../../runtime.zig").Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    const versions = &.{quic.Version.version_1.wireValue()};
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{}!void {}
    };
    var storage: [4096]u8 = undefined;
    var batch_storage: [2 * 4096]u8 = undefined;
    var batch_events: [2]dispatcher_mod.VisitEvent = undefined;
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveManyVisitingTimeout(
            versions,
            &batch_storage,
            &batch_events,
            .{ .duration = .{ .clock = .awake, .raw = .zero } },
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveManyVisitingWithDeadline(
            versions,
            &batch_storage,
            &batch_events,
            .{ .clock = .real, .raw = .zero },
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        dispatcher.receiveManyVisitingWithDeadline(
            versions,
            &storage,
            &batch_events,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
            {},
            Visitor.visit,
        ),
    );

    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveWithDeadline(
            versions,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveWithDeadline(versions, .fromNow(io, .{
            .clock = .awake,
            .raw = .zero,
        })),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveWithTimeout(versions, .fromNanoseconds(0)),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveVisitingWithTimeout(
            versions,
            &storage,
            .fromNanoseconds(0),
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveManyVisitingWithTimeout(
            versions,
            &storage,
            &batch_events,
            .fromNanoseconds(0),
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveVisitingWithDeadline(
            versions,
            &storage,
            .{ .clock = .real, .raw = .zero },
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveVisitingWithDeadline(
            versions,
            &storage,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .zero,
            }),
            {},
            Visitor.visit,
        ),
    );
    // The generic std.Io.Timeout API retains support for relative durations
    // on other clocks; internal awake transport timers compare remaining
    // durations instead of unrelated timestamp epochs.
    try std.testing.expectError(error.Timeout, dispatcher.receiveTimeout(
        versions,
        .{ .duration = .{
            .clock = .real,
            .raw = .fromMilliseconds(1),
        } },
    ));
    try std.testing.expectError(error.Timeout, dispatcher.receiveVisitingTimeout(
        versions,
        &storage,
        .{ .duration = .{
            .clock = .real,
            .raw = .fromMilliseconds(1),
        } },
        {},
        Visitor.visit,
    ));

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        dispatcher.receiveWithDeadline(versions, .fromNow(io, .{
            .clock = .awake,
            .raw = .fromMilliseconds(5),
        })),
    );
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            std.time.ns_per_s,
    );
}

test "QUIC endpoint dispatcher releases failed routed datagram once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe9} ** quic.protection.secret_len,
    );
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = .{ .ip4 = .loopback(443) },
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "dispatcher-local",
        .peer_connection_id = "dispatcher-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &connection);

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 1,
        .data = "first",
    } }).write(&payload, allocator);
    const first = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "dispatcher-local",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(first);
    var event = try dispatcher.dispatch(.{
        .from = connection.peerAddress(),
        .bytes = try allocator.dupe(u8, first),
    });
    defer event.deinit(allocator);

    payload.clearRetainingCapacity();
    try (quic.Frame{ .stream = .{
        .stream_id = 1,
        .data = "other",
    } }).write(&payload, allocator);
    const conflicting = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "dispatcher-local",
        .packet_number = 1,
        .payload = payload.items,
    });
    try std.testing.expectError(error.ConflictingStreamData, dispatcher.dispatch(.{
        .from = connection.peerAddress(),
        .bytes = conflicting,
    }));
    try std.testing.expect(connection.closing());
    const connection_timer = connection.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    const endpoint_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(ConnectionHandle, 1), endpoint_timer.connection_id);
    try std.testing.expectEqual(connection_timer, endpoint_timer.timer);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close,
        endpoint_timer.timer.kind,
    );
}

test "QUIC endpoint dispatcher rate limits close responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "closing-local",
        .peer_connection_id = "closing-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var peer = try one_rtt.Connection.init(&peer_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "closing-peer",
        .peer_connection_id = "closing-local",
        .enable_pacing = false,
    });
    defer peer.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(2, &connection);

    try connection.closeApplication(75, "closing");
    try dispatcher.refreshConnectionTimer(2);
    const close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close,
        close_timer.timer.kind,
    );
    var initial_close = try one_rtt.receive(
        &peer_endpoint,
        keys,
        "closing-peer".len,
        0,
        1,
    );
    defer initial_close.deinit(allocator);
    try std.testing.expect(initial_close.frames[0] == .application_close);
    try std.testing.expectEqual(
        @as(u64, 75),
        initial_close.frames[0].application_close.error_code,
    );

    // A valid packet carrying this CID from a different tuple cannot induce
    // reflected close traffic without authenticating migration first.
    try peer.send(&.{.{ .ping = {} }});
    var foreign_datagram = try endpoint.receiveBytes();
    foreign_datagram.from = .{ .ip4 = .loopback(6553) };
    try std.testing.expectEqual(
        Event.consumed,
        try dispatcher.dispatch(foreign_datagram),
    );
    try std.testing.expectEqual(
        close_timer,
        dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult,
    );

    try peer.send(&.{.{ .ping = {} }});
    const datagram = try endpoint.receiveBytes();
    const event = try dispatcher.dispatch(datagram);
    try std.testing.expectEqual(Event.consumed, event);
    try std.testing.expect(connection.closing());
    const response_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close_response,
        response_timer.timer.kind,
    );
    try std.testing.expectEqual(@as(ConnectionHandle, 2), response_timer.connection_id);
    try std.testing.expect(
        response_timer.timer.deadline_ns < close_timer.timer.deadline_ns,
    );
    try std.testing.expect(
        (try dispatcher.serviceNextTimerAt(
            response_timer.timer.deadline_ns - 1,
        )) == null,
    );
    var failed_send = ObservedBatchSend{
        .delegate = endpoint.io,
        .fail_after_prefix = 0,
    };
    endpoint.io = failed_send.io();
    defer endpoint.io = failed_send.delegate;
    const serviced = (try dispatcher.serviceNextTimerAt(
        response_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close_response,
        serviced.timer.kind,
    );
    try std.testing.expectEqual(@as(usize, 1), failed_send.calls);
    const retry_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close_response,
        retry_timer.timer.kind,
    );
    try std.testing.expect(
        retry_timer.timer.deadline_ns > response_timer.timer.deadline_ns,
    );

    endpoint.io = failed_send.delegate;
    const retried = (try dispatcher.serviceNextTimerAt(
        retry_timer.timer.deadline_ns,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close_response,
        retried.timer.kind,
    );
    var repeated_close = try one_rtt.receive(
        &peer_endpoint,
        keys,
        "closing-peer".len,
        1,
        1,
    );
    defer repeated_close.deinit(allocator);
    try std.testing.expect(repeated_close.frames[0] == .application_close);
    try std.testing.expectEqual(
        @as(u64, 75),
        repeated_close.frames[0].application_close.error_code,
    );
    try std.testing.expectEqual(
        close_timer,
        dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult,
    );

    // The response threshold doubles after each retransmission. One packet no
    // longer schedules work; the second arms another one-RTT debounce.
    try peer.send(&.{.{ .ping = {} }});
    const first_after_response = try endpoint.receiveBytes();
    try std.testing.expectEqual(
        Event.consumed,
        try dispatcher.dispatch(first_after_response),
    );
    try std.testing.expectEqual(
        close_timer,
        dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult,
    );
    try peer.send(&.{.{ .ping = {} }});
    const second_after_response = try endpoint.receiveBytes();
    try std.testing.expectEqual(
        Event.consumed,
        try dispatcher.dispatch(second_after_response),
    );
    const second_response_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close_response,
        second_response_timer.timer.kind,
    );
}

test "QUIC endpoint dispatcher keeps draining connections silent" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xec} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "draining-local",
        .peer_connection_id = "draining-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var peer = try one_rtt.Connection.init(&peer_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "draining-peer",
        .peer_connection_id = "draining-local",
        .enable_pacing = false,
    });
    defer peer.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(3, &connection);

    try one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .application_close = .{
            .error_code = 76,
            .reason_phrase = "draining",
        } }},
        1_000_000,
        .not_ect,
    );
    try dispatcher.refreshConnectionTimer(3);
    const close_timer = dispatcher.nextTimerDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.close,
        close_timer.timer.kind,
    );

    var observed_send = ObservedBatchSend{ .delegate = endpoint.io };
    endpoint.io = observed_send.io();
    defer endpoint.io = observed_send.delegate;

    try peer.send(&.{.{ .ping = {} }});
    const datagram = try endpoint.receiveBytes();
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(datagram));
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(@as(usize, 0), observed_send.calls);
    try std.testing.expect(
        one_rtt.testing.closeResponseDeadline(&connection) == null,
    );
    try std.testing.expectEqual(
        close_timer,
        dispatcher.nextTimerDeadline() orelse
            return error.TestUnexpectedResult,
    );
}

test "QUIC endpoint dispatcher atomically replaces connection storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xea} ** quic.protection.secret_len,
    );
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "replace-local",
        .peer_connection_id = "replace-peer",
        .enable_pacing = false,
    });
    var connection_owned = true;
    defer if (connection_owned) connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &connection);
    const sync_count_before =
        dispatcher.connections.getPtr(1).?.connection_id_sync_count;

    var moved = connection;
    connection_owned = false;
    defer moved.deinit();
    try dispatcher.replaceConnection(1, &moved);
    try std.testing.expectEqual(
        sync_count_before + 1,
        dispatcher.connections.getPtr(1).?.connection_id_sync_count,
    );
    try std.testing.expectEqual(
        @as(?u64, moved.localConnectionIdRevision()),
        dispatcher.connections.getPtr(1).?.connection_id_revision,
    );

    var pending_payload: std.ArrayList(u8) = .empty;
    defer pending_payload.deinit(allocator);
    try (quic.Frame{ .ping = {} }).write(&pending_payload, allocator);
    const pending = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "replace-local",
        .packet_number = 1,
        .payload = pending_payload.items,
    });
    defer allocator.free(pending);
    try moved.preloadReceivedDatagram(
        peer_endpoint.address(),
        pending,
        .not_ect,
    );
    var pending_event = (try dispatcher.pollPendingPacket()) orelse
        return error.TestUnexpectedResult;
    defer pending_event.packet.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 1),
        pending_event.connection_handle,
    );
    try std.testing.expect(pending_event.packet.frames[0] == .ping);

    var peer = try one_rtt.Connection.init(&peer_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "replace-peer",
        .peer_connection_id = "replace-local",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer peer.deinit();
    const frames = [_]quic.Frame{.{ .ping = {} }};
    try peer.sendAt(&frames, 1);
    var event = try dispatcher.receive(
        &.{quic.Version.version_1.wireValue()},
    );
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(@as(usize, 1), event.packet.connection_handle);
    try std.testing.expect(event.packet.packet.frames[0] == .ping);
}

test "QUIC endpoint dispatcher consumes unknown server tuple for client" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var server = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server.deinit();
    var unknown = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer unknown.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = server.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client-route",
        .peer_connection_id = "server-route",
        .peer_disable_active_migration = true,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(9, &connection);

    const payload = try one_rtt.encodeFrames(allocator, &.{.{ .ping = {} }});
    defer allocator.free(payload);
    const spoofed = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "client-route",
        .packet_number = 10,
        .packet_number_len = 4,
        .payload = payload,
    });
    var unknown_server_address = unknown.address();
    unknown_server_address.ip4.bytes = .{ 127, 0, 0, 2 };
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(.{
        .from = unknown_server_address,
        .bytes = spoofed,
    }));
    try std.testing.expectEqual(@as(u64, 0), connection.stats().packets_received);

    const accepted = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "client-route",
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = payload,
    });
    var event = try dispatcher.dispatch(.{
        .from = server.address(),
        .bytes = accepted,
    });
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(@as(u64, 0), event.packet.packet.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), connection.stats().packets_received);
}

test "QUIC endpoint dispatcher consumes disabled client migration before AEAD" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var client = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xec} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = client.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server-disabled",
        .peer_connection_id = "client-disabled",
        .local_endpoint = .server,
        .local_disable_active_migration = true,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(10, &connection);

    var spoofed = try allocator.alloc(
        u8,
        1 + "server-disabled".len + 32,
    );
    @memset(spoofed, 0xa5);
    spoofed[0] = 0x40;
    @memcpy(spoofed[1..][0.."server-disabled".len], "server-disabled");
    var different_ip = client.address();
    different_ip.ip4.bytes = .{ 127, 0, 0, 2 };
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(.{
        .from = different_ip,
        .bytes = spoofed,
    }));
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
    try std.testing.expectEqual(@as(u64, 0), connection.stats().packets_received);
    try std.testing.expect(!connection.closed());

    const payload = try one_rtt.encodeFrames(allocator, &.{.{ .ping = {} }});
    defer allocator.free(payload);
    const valid = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "server-disabled",
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = payload,
    });
    var event = try dispatcher.dispatch(.{
        .from = client.address(),
        .bytes = valid,
    });
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(@as(u64, 0), event.packet.packet.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), connection.stats().packets_received);
}

test "QUIC endpoint dispatcher consumes authentication failure until AEAD limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xed} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server-aead",
        .peer_connection_id = "client-aead",
        .local_endpoint = .server,
        .aead_integrity_limit = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(11, &connection);

    const payload = try one_rtt.encodeFrames(allocator, &.{.{ .ping = {} }});
    defer allocator.free(payload);

    const truncated = try allocator.alloc(u8, 1 + "server-aead".len);
    truncated[0] = 0x40;
    @memcpy(truncated[1..], "server-aead");
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(.{
        .from = peer.address(),
        .bytes = truncated,
    }));

    const missing_sample = try allocator.alloc(
        u8,
        1 + "server-aead".len + 1 + quic.protection.aead_tag_len,
    );
    @memset(missing_sample, 0);
    missing_sample[0] = 0x40;
    @memcpy(missing_sample[1..][0.."server-aead".len], "server-aead");
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(.{
        .from = peer.address(),
        .bytes = missing_sample,
    }));
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
    try std.testing.expect(!connection.closed());

    const corrupted = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "server-aead",
        .packet_number = 10,
        .packet_number_len = 4,
        .payload = payload,
    });
    corrupted[corrupted.len - 1] ^= 0x80;
    try std.testing.expectEqual(Event.consumed, try dispatcher.dispatch(.{
        .from = peer.address(),
        .bytes = corrupted,
    }));
    try std.testing.expectEqual(@as(u64, 1), connection.authenticationFailureCount());
    try std.testing.expect(!connection.closed());

    const valid = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "server-aead",
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = payload,
    });
    var event = try dispatcher.dispatch(.{
        .from = peer.address(),
        .bytes = valid,
    });
    defer event.deinit(allocator);
    try std.testing.expect(event == .packet);
    try std.testing.expectEqual(@as(u64, 0), event.packet.packet.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), connection.stats().packets_received);

    const limit = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "server-aead",
        .packet_number = 11,
        .packet_number_len = 4,
        .payload = payload,
    });
    limit[limit.len - 1] ^= 0x80;
    try std.testing.expectError(error.AeadLimitReached, dispatcher.dispatch(.{
        .from = peer.address(),
        .bytes = limit,
    }));
    try std.testing.expectEqual(@as(u64, 2), connection.authenticationFailureCount());
    try std.testing.expect(connection.closing());
}

test "QUIC endpoint dispatcher propagates authenticated reserved bits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xee} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server-reserved",
        .peer_connection_id = "client-reserved",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(12, &connection);

    const reserved = try sealShortPacketWithReservedBits(
        allocator,
        keys,
        "server-reserved",
        0,
        &.{@intFromEnum(quic.FrameType.ping)},
    );
    try std.testing.expectError(error.InvalidReservedBits, dispatcher.dispatch(.{
        .from = peer.address(),
        .bytes = reserved,
    }));
    try std.testing.expectEqual(@as(u64, 0), connection.authenticationFailureCount());
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.TransportErrorCode.protocol_violation)),
        connection.close_info.?.error_code,
    );
    try std.testing.expectEqual(@as(u64, 0), connection.close_info.?.frame_type);
}

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
    var connection = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cid-zero",
        .peer_connection_id = "peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .peer_active_connection_id_limit = 3,
    });
    defer connection.deinit();
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

    try dispatcher.sendNewConnectionIdRetiringPriorTo(
        11,
        "cid-one",
        [_]u8{1} ** 16,
        0,
    );
    try std.testing.expectEqual(@as(usize, 2), dispatcher.routeCount());
    try std.testing.expectEqual(
        @as(u64, 1),
        (try dispatcher.router.lookup("cid-one")).?.sequence_number,
    );

    var new_cid = try peer_connection.receivePacket();
    defer new_cid.deinit(allocator);
    try std.testing.expect(peer_connection.switchToNextPeerConnectionId());
    const retire = [_]quic.Frame{.{ .retire_connection_id = .{
        .sequence_number = 0,
    } }};
    try peer_connection.send(&retire);
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
    });
    defer connection.deinit();
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    try dispatcher.registerConnection(1, &connection);

    var failed_send = ObservedBatchSend{
        .delegate = endpoint.io,
        .fail_after_prefix = 0,
    };
    var failed_vtable = endpoint.io.vtable.*;
    failed_vtable.netSend = ObservedBatchSend.netSend;
    endpoint.io = .{
        .userdata = &failed_send,
        .vtable = &failed_vtable,
    };
    defer endpoint.io = failed_send.delegate;

    try std.testing.expectError(
        error.NetworkDown,
        dispatcher.sendNewConnectionId(
            1,
            "failed-cid",
            [_]u8{3} ** 16,
        ),
    );
    var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try connection.localConnectionIdsInto(&active_storage)).len,
    );
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expect((try dispatcher.router.lookup("failed-cid")) == null);
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

test "QUIC endpoint dispatcher wakes socket receive for transport timers" {
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
    var event = try dispatcher.receive(&versions);
    defer event.deinit(allocator);
    try std.testing.expect(event == .timer);
    try std.testing.expectEqual(@as(ConnectionHandle, 9), event.timer.connection_handle);
    try std.testing.expectEqual(
        one_rtt.TimerDeadlineKind.pto,
        event.timer.timer.kind,
    );
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

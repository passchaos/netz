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
    try std.testing.expect((try dispatcher.pollPendingPacket()) == null);
    try std.testing.expect((try dispatcher.pollConnectionPacket(52)) == null);
    try std.testing.expect(try dispatcher.unregisterConnection(52));
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
    var dispatcher = Dispatcher.init(allocator, &endpoint);
    defer dispatcher.deinit();
    const versions = &.{quic.Version.version_1.wireValue()};

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
    var failed_vtable = endpoint.io.vtable.*;
    failed_vtable.netSend = ObservedBatchSend.netSend;
    endpoint.io = .{
        .userdata = &failed_send,
        .vtable = &failed_vtable,
    };
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
    var observed_vtable = endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    endpoint.io = .{
        .userdata = &observed_send,
        .vtable = &observed_vtable,
    };
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

    var moved = connection;
    connection_owned = false;
    defer moved.deinit();
    try dispatcher.replaceConnection(1, &moved);

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
    try peer.send(&frames);
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

const std = @import("std");
const quic = @import("../mod.zig");
const dispatcher_mod = @import("../endpoint_dispatcher.zig");
const one_rtt = @import("../one_rtt.zig");
const runtime = @import("../runtime.zig");

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
    try dispatcher.registerConnectionId(10, "server-a", 0);
    try dispatcher.registerConnection(20, &server_b);
    try dispatcher.registerConnectionId(20, "server-b", 0);

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

    try std.testing.expect(try dispatcher.unregisterConnection(10));
    try std.testing.expectEqual(@as(usize, 1), dispatcher.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.routeCount());
    try std.testing.expect(!(try dispatcher.unregisterConnection(10)));
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
    try dispatcher.registerConnectionId(7, "established", 0);

    const payload = [_]u8{@intFromEnum(quic.FrameType.ping)};
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
    try std.testing.expect(unknown_event == .unrouted);

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
            .payload = &payload,
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
    try dispatcher.registerConnectionId(9, "timer-local", 0);
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

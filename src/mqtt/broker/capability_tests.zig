const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const ServeState = context.ServeStateType;
const joinServer = context.joinServerFn;

fn writeRawPublish(
    connection: *context.runtime_mod.Connection,
    protocol: mqtt.ProtocolVersion,
    qos: mqtt.QoS,
    retain: bool,
    packet_id: ?u16,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try mqtt.writePublish(
        &encoded,
        std.testing.allocator,
        protocol,
        "capability/violation",
        "blocked",
        .{
            .qos = qos,
            .retain = retain,
            .packet_id = packet_id,
        },
    );
    try connection.transport.writePacket(encoded.items);
}

fn expectPublishCapabilityDisconnect(
    maximum_qos: ?mqtt.QoS,
    retain_available: bool,
    publish_qos: mqtt.QoS,
    publish_retain: bool,
    expected_reason: u8,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .maximum_qos = maximum_qos,
                .retain_available = retain_available,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "capability-violation" },
    );
    defer client.close();

    // The high-level client honors CONNACK and refuses this PUBLISH locally.
    // Encode directly to exercise an uncooperative peer and the broker's
    // on-wire negative path.
    try writeRawPublish(
        &client,
        .v5,
        publish_qos,
        publish_retain,
        if (publish_qos == .at_most_once) null else 1,
    );

    var disconnect = try client.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        expected_reason,
        disconnect.disconnect.reason_code,
    );
    try joinServer(thread, &joined, &serve);
}

test "broker disconnects MQTT 5 publisher above Maximum QoS" {
    try expectPublishCapabilityDisconnect(
        .at_most_once,
        true,
        .at_least_once,
        false,
        0x9b,
    );
}

test "broker disconnects MQTT 5 retained publish when retain is unavailable" {
    try expectPublishCapabilityDisconnect(
        null,
        false,
        .at_most_once,
        true,
        0x9a,
    );
}

test "broker closes MQTT 3.1.1 publisher above Maximum QoS without DISCONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .maximum_qos = .at_most_once,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v3_1_1, .client_id = "v3-capability-violation" },
    );
    defer client.close();
    try writeRawPublish(
        &client,
        .v3_1_1,
        .at_least_once,
        false,
        1,
    );

    // MQTT 3.1.1 has no reason-bearing DISCONNECT. The very next read must
    // therefore be EOF (or an equivalent transport reset), not packet bytes.
    var byte: [1]u8 = undefined;
    var bufs = [_][]u8{&byte};
    const read_count = client.transport.tcp.io.vtable.netRead(
        client.transport.tcp.io.userdata,
        client.transport.tcp.stream.socket.handle,
        &bufs,
    ) catch |err| switch (err) {
        error.SocketUnconnected, error.ConnectionResetByPeer => 0,
        else => return err,
    };
    try std.testing.expectEqual(@as(usize, 0), read_count);
    try joinServer(thread, &joined, &serve);
}

test "broker disconnects MQTT 5 publisher that exceeds Receive Maximum" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .max_outgoing_inflight = 1,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "receive-maximum-violation" },
    );
    defer client.close();

    // Send two QoS 2 transactions without waiting for PUBREC. The first one
    // occupies the broker's sole inbound slot, so the second violates the
    // Receive Maximum advertised in CONNACK.
    try writeRawPublish(
        &client,
        .v5,
        .exactly_once,
        false,
        1,
    );
    try writeRawPublish(
        &client,
        .v5,
        .exactly_once,
        false,
        2,
    );

    var pubrec = try client.readPubRec();
    defer pubrec.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 1), pubrec.ack.packet_id);
    var disconnect = try client.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x93),
        disconnect.disconnect.reason_code,
    );
    try joinServer(thread, &joined, &serve);
}

test "broker disconnects MQTT 5 publisher with invalid Topic Alias" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .topic_alias_maximum = 1,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "topic-alias-violation" },
    );
    defer client.close();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.writePublish(
        &encoded,
        allocator,
        .v5,
        "topic/alias",
        "blocked",
        .{ .properties = &.{.{ .two_byte = .{
            .id = .topic_alias,
            .value = 2,
        } }} },
    );
    try client.transport.writePacket(encoded.items);

    var disconnect = try client.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x94),
        disconnect.disconnect.reason_code,
    );
    try joinServer(thread, &joined, &serve);
}

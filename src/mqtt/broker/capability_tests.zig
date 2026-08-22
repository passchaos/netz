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

fn expectSubscribeCapabilityDisconnect(
    subscription: mqtt.Subscription,
    properties: []const mqtt.Property,
    wildcard_available: bool,
    subscription_identifier_available: bool,
    shared_available: bool,
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
                .wildcard_subscription_available = wildcard_available,
                .subscription_identifier_available = subscription_identifier_available,
                .shared_subscription_available = shared_available,
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
        .{ .protocol = .v5, .client_id = "subscribe-capability" },
    );
    defer client.close();

    // Bypass the high-level client capability guard so this exercises the
    // server's response to a peer that violates the CONNACK contract.
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.Subscribe.write(
        &encoded,
        allocator,
        .v5,
        1,
        properties,
        &.{subscription},
    );
    try client.transport.writePacket(encoded.items);

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

test "broker disconnects MQTT 5 wildcard subscription when unavailable" {
    try expectSubscribeCapabilityDisconnect(
        .{ .topic_filter = "wildcard/+" },
        &.{},
        false,
        true,
        true,
        0xa2,
    );
}

test "broker disconnects MQTT 5 shared subscription when unavailable" {
    try expectSubscribeCapabilityDisconnect(
        .{ .topic_filter = "$share/workers/shared/topic" },
        &.{},
        true,
        true,
        false,
        0x9e,
    );
}

test "broker disconnects MQTT 5 subscription identifier when unavailable" {
    try expectSubscribeCapabilityDisconnect(
        .{ .topic_filter = "identifier/topic" },
        &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 7,
        } }},
        true,
        false,
        true,
        0xa1,
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

test "broker disconnects MQTT 5 peer after malformed control flags" {
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
            .accept = .{ .protocol = .v5 },
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
        .{ .protocol = .v5, .client_id = "invalid-flags" },
    );
    defer client.close();

    // PINGREQ requires flags zero. This raw frame reaches the broker parser
    // with the reserved low bit set and must elicit Protocol Error.
    var malformed = [_]u8{ 0xc1, 0x00 };
    try client.transport.writePacket(&malformed);
    var disconnect = try client.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x82),
        disconnect.disconnect.reason_code,
    );
    try joinServer(thread, &joined, &serve);
}

test "broker disconnects MQTT 5 peer after malformed UTF-8" {
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
            .accept = .{ .protocol = .v5 },
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
        .{ .protocol = .v5, .client_id = "malformed-utf8" },
    );
    defer client.close();

    // QoS 0 PUBLISH: two-byte Topic Name containing one invalid UTF-8 byte,
    // then an empty MQTT 5 property section.
    var malformed = [_]u8{ 0x30, 0x04, 0x00, 0x01, 0xff, 0x00 };
    try client.transport.writePacket(&malformed);
    var disconnect = try client.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x81),
        disconnect.disconnect.reason_code,
    );
    try joinServer(thread, &joined, &serve);
}

test "broker disconnects MQTT 5 peer after oversized packet declaration" {
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
                // CONNECT must fit, while the post-CONNECT declaration below
                // exceeds this limit before the broker allocates its body.
                .runtime = .{ .max_packet_size = 128 },
            },
            .accept = .{ .protocol = .v5 },
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
        .{ .protocol = .v5, .client_id = "oversized-packet" },
    );
    defer client.close();

    // Remaining Length 128 makes the complete packet 131 bytes. The body is
    // intentionally omitted: the broker rejects the declared size before it
    // waits for or allocates the payload.
    var oversized_header = [_]u8{ 0x30, 0x80, 0x01 };
    try client.transport.writePacket(&oversized_header);
    var disconnect = try client.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x95),
        disconnect.disconnect.reason_code,
    );
    try joinServer(thread, &joined, &serve);
}

test "broker enforces Application Message payload limit by QoS" {
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
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 2,
                .max_payload_size = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "payload-limit-sub" },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "payload/limit", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var publisher = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "payload-limit-pub" },
    );
    defer publisher.close();

    // A one-byte payload is accepted and delivered normally. Two-byte QoS 0
    // is discarded, while QoS 1/2 return Packet Too Large and never route.
    try publisher.publish("payload/limit", "A", .{});
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings("A", delivered.publish.payload);

    try publisher.publish("payload/limit", "AB", .{});
    _ = try publisher.writePublish("payload/limit", "AB", .{
        .qos = .at_least_once,
    });
    var puback = try publisher.readPubAck();
    defer puback.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x95), puback.ack.reason_code);

    _ = try publisher.writePublish("payload/limit", "AB", .{
        .qos = .exactly_once,
    });
    var pubrec = try publisher.readPubRec();
    defer pubrec.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x95), pubrec.ack.reason_code);
    try std.testing.expectError(
        error.PublishRefused,
        publisher.applyPubRec(pubrec.ack),
    );
    try publisher.ping();

    // PINGRESP must be next; any accidentally routed oversized PUBLISH would
    // make this typed read fail before it could hide behind later traffic.
    try subscriber.ping();
    try context.disconnectAllFn(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker refuses oversized Will payload before Session registration" {
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
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 1,
                .max_payload_size = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var refused = try context.runtime_mod.Client.connectAttempt(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "oversized-will",
            .will = .{
                .topic = "will/payload/limit",
                .payload = "AB",
            },
        },
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.accepted());
    try std.testing.expectEqual(
        @as(u8, 0x95),
        refused.connack.connack.reason_code,
    );

    var accepted = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "boundary-will",
            .will = .{
                .topic = "will/payload/limit",
                .payload = "A",
            },
        },
    );
    accepted.close();
    try joinServer(thread, &joined, &serve);
}

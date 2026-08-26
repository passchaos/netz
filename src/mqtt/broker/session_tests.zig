const std = @import("std");
const context = @import("../broker_tests.zig");

const mqtt = context.TestContext.mqtt_mod;
const ServeState = context.TestContext.ServeStateType;
const testBroker = context.TestContext.testBrokerFn;
const connect = context.TestContext.connectFn;
const disconnectAll = context.TestContext.disconnectAllFn;
const waitForPeerClose = context.TestContext.waitForPeerCloseFn;
const joinServer = context.TestContext.joinServerFn;

const session_expiry = [_]mqtt.Property{
    .{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 30,
    } },
};

test "broker caps durable Session delivery at Maximum QoS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.TestContext.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 3,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .max_outgoing_inflight = 64,
                .maximum_qos = .at_least_once,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "maximum-qos-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "maximum/session",
            .qos = .exactly_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{@intFromEnum(mqtt.QoS.at_least_once)},
        suback.suback.reason_codes,
    );
    try subscriber.disconnect(0);
    try waitForPeerClose(&subscriber);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "maximum-qos-session-pub",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "maximum/session",
        "queued",
        .{ .qos = .at_least_once },
    );
    try publisher.ping();

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "maximum-qos-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var delivered = try resumed.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        delivered.publish.qos,
    );
    try resumed.writePubAck(delivered.publish.packet_id.?, 0);

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker returns Session Present and restores persistent subscription" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var first_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "persistent-subscriber",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var first = first_result.connection;
    defer first.close();
    defer first_result.connack.deinit(allocator);
    try std.testing.expect(!first_result.connack.connack.session_present);
    var suback = try first.subscribe(
        &.{.{
            .topic_filter = "persistent/+",
            .qos = .at_least_once,
        }},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 17,
        } }} },
    );
    defer suback.deinit(allocator);
    try first.disconnect(0);

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "persistent-subscriber",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "persistent-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "persistent/value",
        "restored",
        .{ .qos = .at_least_once },
    );
    var delivered = try resumed.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "restored",
        delivered.publish.payload,
    );
    try std.testing.expectEqual(
        @as(?usize, 17),
        mqtt.subscriptionIdentifier(delivered.publish.properties),
    );
    try resumed.writePubAck(delivered.publish.packet_id.?, 0);

    try disconnectAll(&.{ &resumed, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker routes QoS 0 to an online persistent Session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "persistent-qos0",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "persistent/qos0" }},
        .{},
    );
    defer suback.deinit(allocator);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "persistent-qos0-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish("persistent/qos0", "live", .{});
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "live",
        delivered.publish.payload,
    );
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        delivered.publish.qos,
    );

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker Clean Start discards persistent subscriptions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var first = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "clean-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer first.close();
    var suback = try first.subscribe(
        &.{.{ .topic_filter = "clean/#" }},
        .{},
    );
    defer suback.deinit(allocator);
    try first.disconnect(0);

    var clean_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "clean-session",
            .clean_start = true,
            .properties = &session_expiry,
        },
    );
    var clean = clean_result.connection;
    defer clean.close();
    defer clean_result.connack.deinit(allocator);
    try std.testing.expect(!clean_result.connack.connack.session_present);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "clean-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish("clean/value", "not-delivered", .{});
    try clean.ping();

    try disconnectAll(&.{ &clean, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker drops QoS 0 while a persistent Session is offline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "offline-qos0",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "offline/qos0" }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.disconnect(0);
    // MQTT has no DISCONNECT acknowledgment. Wait until the broker closes its
    // side so the publication below is unambiguously an offline delivery.
    try waitForPeerClose(&subscriber);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "offline-qos0-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish("offline/qos0", "drop", .{});
    // QoS 0 has no publish acknowledgment. PINGRESP proves the broker has
    // routed the preceding PUBLISH while the durable Session is still
    // offline, before the reconnect can make that Session live again.
    try publisher.ping();

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "offline-qos0",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    // PINGRESP must be the next packet. If offline QoS 0 were incorrectly
    // queued, ping() would encounter PUBLISH and return UnexpectedPacket.
    try resumed.ping();

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker optionally queues QoS 0 while a persistent Session is offline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.TestContext.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 3,
                .max_queued_deliveries_per_connection = 8,
            },
            .queue_qos0_messages = true,
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 3 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "queued-offline-qos0",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "offline/qos0/queued" }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.disconnect(0);
    try waitForPeerClose(&subscriber);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "queued-offline-qos0-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish("offline/qos0/queued", "queued", .{});
    try publisher.ping();

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "queued-offline-qos0",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var delivery = try resumed.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, delivery.publish.qos);
    try std.testing.expectEqualStrings("queued", delivery.publish.payload);
    try resumed.ping();

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker Session Expiry override removes restored subscriptions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var first = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "expiry-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer first.close();
    var suback = try first.subscribe(
        &.{.{ .topic_filter = "expiry/#" }},
        .{},
    );
    defer suback.deinit(allocator);
    var disconnect_properties = [_]mqtt.Property{
        .{ .four_byte = .{
            .id = .session_expiry_interval,
            .value = 0,
        } },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.Disconnect.write(
        &encoded,
        allocator,
        .v5,
        0,
        &disconnect_properties,
    );
    try first.transport.writePacket(encoded.items);
    // Synchronize with broker processing before opening the next connection;
    // otherwise the two TCP streams may race at the accept boundary.
    var closed = false;
    while (!closed) {
        var scratch: [1]u8 = undefined;
        var bufs = [_][]u8{&scratch};
        const result = first.transport.tcp.io.vtable.netRead(
            first.transport.tcp.io.userdata,
            first.transport.tcp.stream.socket.handle,
            &bufs,
        );
        if (result) |read_count| {
            closed = read_count == 0;
        } else |err| switch (err) {
            error.SocketUnconnected,
            error.ConnectionResetByPeer,
            => closed = true,
            else => return err,
        }
    }

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "expiry-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(!resumed_result.connack.connack.session_present);

    try resumed.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker caps persistent Session lifetime across MQTT versions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try context.TestContext.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 11,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .persistent_session_expiry_seconds = 1,
        },
    );
    defer broker.deinit();
    var serve = ServeState{ .broker = &broker, .connection_count = 11 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const v5_long_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        const client_id = if (protocol == .v3_1_1)
            "global-expiry-v311"
        else
            "global-expiry-v5";
        const properties: []const mqtt.Property = if (protocol == .v5)
            &v5_long_expiry
        else
            &.{};
        var first = try mqtt.runtime.Client.connect(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = protocol,
                .client_id = client_id,
                .clean_start = false,
                .properties = properties,
            },
        );
        defer first.close();
        try first.disconnect(0);
        try waitForPeerClose(&first);

        // The configured global cap shortens both MQTT 3.1.1's otherwise
        // unbounded persistent Session and MQTT 5's longer requested expiry.
        try std.Io.sleep(io, .fromMilliseconds(1200), .awake);
        var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = protocol,
                .client_id = client_id,
                .clean_start = false,
                .properties = properties,
            },
        );
        var resumed = resumed_result.connection;
        defer resumed.close();
        defer resumed_result.connack.deinit(allocator);
        try std.testing.expect(
            !resumed_result.connack.connack.session_present,
        );
        try resumed.disconnect(0);
        try waitForPeerClose(&resumed);
    }

    // A shorter MQTT 5 request remains authoritative; the administrative cap
    // must not lengthen it.
    const short_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 0,
    } }};
    var transient = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "global-expiry-zero",
            .clean_start = false,
            .properties = &short_expiry,
        },
    );
    defer transient.close();
    try transient.disconnect(0);
    try waitForPeerClose(&transient);
    var transient_again = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "global-expiry-zero",
            .clean_start = false,
            .properties = &short_expiry,
        },
    );
    defer transient_again.connection.close();
    defer transient_again.connack.deinit(allocator);
    try std.testing.expect(!transient_again.connack.connack.session_present);
    try transient_again.connection.disconnect(0);
    try waitForPeerClose(&transient_again.connection);

    // A DISCONNECT Session Expiry property replaces the CONNECT value, but
    // it still cannot exceed the broker-wide administrative maximum. This is
    // the important edge that would otherwise bypass a CONNECT-only cap.
    const disconnect_long_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 120,
    } }};
    var overridden = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "global-expiry-disconnect",
            .clean_start = false,
            .properties = &v5_long_expiry,
        },
    );
    defer overridden.close();
    try overridden.writeDisconnectWithProperties(
        0,
        &disconnect_long_expiry,
    );
    try waitForPeerClose(&overridden);
    try std.Io.sleep(io, .fromMilliseconds(1200), .awake);

    var override_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "global-expiry-disconnect",
            .clean_start = false,
            .properties = &v5_long_expiry,
        },
    );
    defer override_result.connection.close();
    defer override_result.connack.deinit(allocator);
    try std.testing.expect(!override_result.connack.connack.session_present);
    try override_result.connection.disconnect(0);
    try waitForPeerClose(&override_result.connection);

    // The same effective expiry bounds Will Delay. Otherwise the Session
    // would disappear at the administrative deadline while its Will remained
    // hidden until the longer client-requested delay.
    var will_subscriber = try connect(
        allocator,
        io,
        broker,
        "global-expiry-will-subscriber",
        &.{},
    );
    defer will_subscriber.close();
    var will_suback = try will_subscriber.subscribe(
        &.{.{ .topic_filter = "global-expiry/will" }},
        .{},
    );
    defer will_suback.deinit(allocator);
    var delayed_will_properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .will_delay_interval,
        .value = 60,
    } }};
    var will_source = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "global-expiry-will",
            .clean_start = false,
            .properties = &v5_long_expiry,
            .will = .{
                .topic = "global-expiry/will",
                .payload = "expired",
                .properties = &delayed_will_properties,
            },
        },
    );
    defer will_source.close();
    try will_source.writeDisconnectWithProperties(0x04, &.{});
    var delivered_will = try will_subscriber.readPublish();
    defer delivered_will.deinit(allocator);
    try std.testing.expectEqualStrings(
        "expired",
        delivered_will.publish.payload,
    );
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try will_subscriber.disconnect(0);

    try joinServer(thread, &joined, &serve);
}

test "broker actively expires idle Session routing and QoS2 state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    // Keep one unrelated client connected for the entire expiry interval.
    // This makes the assertion exercise the broker's autonomous deadline task
    // rather than cleanup performed by a later CONNECT or PUBLISH operation.
    var keeper = try connect(
        allocator,
        io,
        broker,
        "expiry-idle-keeper",
        &.{},
    );
    defer keeper.close();
    const expires_in_one_second = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 1,
    } }};
    var expiring = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "expiry-idle-state",
            .clean_start = false,
            .properties = &expires_in_one_second,
        },
    );
    defer expiring.close();
    var suback = try expiring.subscribe(
        &.{.{ .topic_filter = "expiry/idle/#" }},
        .{},
    );
    defer suback.deinit(allocator);
    const packet_id = (try expiring.writePublish(
        "expiry/idle/qos2",
        "pending",
        .{ .qos = .exactly_once },
    )).?;
    var pubrec = try expiring.readPubRec();
    defer pubrec.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
    try expiring.disconnect(0);
    try waitForPeerClose(&expiring);

    const wait_deadline_ns = std.Io.Clock.awake.now(io).nanoseconds +
        3 * std.time.ns_per_s;
    while (true) {
        broker.state_mutex.lockUncancelable(io);
        const expired = broker.sessions.count() == 1 and
            broker.router.subscriptionCount() == 0 and
            broker.pending_qos2.count() == 0;
        broker.state_mutex.unlock(io);
        if (expired) break;
        if (std.Io.Clock.awake.now(io).nanoseconds >= wait_deadline_ns) {
            return error.TestExpectedEqual;
        }
        try std.Io.sleep(io, .fromMilliseconds(5), .awake);
    }

    // The lifecycle task must not disturb an unrelated live Network
    // Connection while retiring all state owned by the expired route.
    try keeper.ping();
    try keeper.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker Session reconnect survives stale expiry wake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const expires_in_one_second = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 1,
    } }};
    var first = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "expiry-reconnect",
            .clean_start = false,
            .properties = &expires_in_one_second,
        },
    );
    defer first.close();
    try first.disconnect(0);
    try waitForPeerClose(&first);

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "expiry-reconnect",
            .clean_start = false,
            .properties = &expires_in_one_second,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);

    // Reconnect leaves the old one-second cached deadline as a safe early
    // wake. Crossing it must repair the cache rather than remove a connected
    // Session or disturb its transport.
    try std.Io.sleep(io, .fromMilliseconds(1200), .awake);
    try resumed.ping();
    try resumed.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker duplicate ClientID takeover has one subscription owner" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var old = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "takeover-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer old.close();
    var suback = try old.subscribe(
        &.{.{ .topic_filter = "takeover/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var replacement_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "takeover-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var replacement = replacement_result.connection;
    defer replacement.close();
    defer replacement_result.connack.deinit(allocator);
    try std.testing.expect(
        replacement_result.connack.connack.session_present,
    );
    var takeover_disconnect = try old.readDisconnect();
    defer takeover_disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x8e),
        takeover_disconnect.disconnect.reason_code,
    );

    var publisher = try connect(
        allocator,
        io,
        broker,
        "takeover-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "takeover/value",
        "new-owner-only",
        .{ .qos = .at_least_once },
    );
    var delivered = try replacement.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "new-owner-only",
        delivered.publish.payload,
    );
    try replacement.writePubAck(delivered.publish.packet_id.?, 0);

    try disconnectAll(&.{ &replacement, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker ignores displaced normal DISCONNECT after Will takeover" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var old_will = [_]mqtt.Property{.{ .four_byte = .{
        .id = .will_delay_interval,
        .value = 30,
    } }};
    const stale_handle = try broker.wills.set(
        "takeover-disconnect-will",
        .{
            .topic = "takeover/disconnect",
            .payload = "stale",
            .properties = &old_will,
        },
        30,
    );
    try broker.will_publishers.put(allocator, stale_handle, 7);
    var replacement_properties = [_]mqtt.Property{session_expiry[0]};
    const replacement = mqtt.Connect{
        .protocol = .v5,
        .clean_start = false,
        .keep_alive_seconds = 60,
        .client_id = "takeover-disconnect-will",
        .properties = &replacement_properties,
        .will = null,
        .username = null,
        .password = null,
    };
    const accepted = try broker.wills.acceptConnect(
        replacement,
        .zero,
    );
    try std.testing.expectEqual(
        mqtt.will_scheduler.CloseResult.canceled,
        accepted.previous,
    );
    _ = broker.will_publishers.remove(stale_handle);
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());

    var displaced_slot = &broker.slots[0];
    displaced_slot.will_handle = stale_handle;
    displaced_slot.session_handle = null;
    broker.state_mutex.lockUncancelable(io);
    defer broker.state_mutex.unlock(io);
    try broker.closeWillForDisconnectLocked(
        displaced_slot,
        .{},
        .zero,
    );
    try std.testing.expect(displaced_slot.will_handle == null);
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());

    // Missing Will state is not generally ignorable. Retaining a Session
    // handle means this slot was not detached by takeover, so the same stale
    // handle remains an invariant violation visible to the broker.
    const live_session = try broker.sessions.open(
        "not-displaced",
        false,
        30,
        .zero,
    );
    displaced_slot.session_handle = live_session.handle;
    displaced_slot.will_handle = stale_handle;
    try std.testing.expectError(
        error.WillNotFound,
        broker.closeWillForDisconnectLocked(
            displaced_slot,
            .{},
            .zero,
        ),
    );
}

test "broker queues offline QoS 1 and drains on resume" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "offline-qos1",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "offline/qos1", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.disconnect(0);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "offline-qos1-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "offline/qos1",
        "queued",
        .{ .qos = .at_least_once },
    );

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "offline-qos1",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var delivered = try resumed.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings("queued", delivered.publish.payload);
    // DISCONNECT has no acknowledgment. If reconnect races the broker's prior
    // task teardown, it may legitimately have attempted this queued PUBLISH on
    // that previous Network Connection, in which case MQTT requires DUP=1.
    // The Store-level unsent-write test covers the stricter never-on-wire case.
    try resumed.writePubAck(delivered.publish.packet_id.?, 0);

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker merges overlapping subscriptions in an offline Session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "offline-overlap",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var exact_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "offline/overlap/value",
            .qos = .at_most_once,
        }},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 3,
        } }} },
    );
    defer exact_suback.deinit(allocator);
    var wildcard_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "offline/overlap/+",
            .qos = .at_least_once,
            .retain_as_published = true,
        }},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 9,
        } }} },
    );
    defer wildcard_suback.deinit(allocator);
    try subscriber.disconnect(0);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "offline-overlap-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "offline/overlap/value",
        "merged",
        .{ .qos = .at_least_once, .retain = true },
    );

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "offline-overlap",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);

    var delivered = try resumed.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "merged",
        delivered.publish.payload,
    );
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        delivered.publish.qos,
    );
    try std.testing.expect(delivered.publish.retain);
    var identifiers: [2]usize = undefined;
    var identifier_count: usize = 0;
    for (delivered.publish.properties) |property| {
        if (property == .varint and
            property.varint.id == .subscription_identifier)
        {
            if (identifier_count >= identifiers.len) {
                return error.TestUnexpectedResult;
            }
            identifiers[identifier_count] = property.varint.value;
            identifier_count += 1;
        }
    }
    try std.testing.expectEqualSlices(
        usize,
        &.{ 3, 9 },
        identifiers[0..identifier_count],
    );
    try resumed.writePubAck(delivered.publish.packet_id.?, 0);
    // A second durable enqueue would precede PINGRESP and make ping fail with
    // UnexpectedPacket, so this also verifies one queued Application Message.
    try resumed.ping();

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker retransmits persistent QoS 1 with DUP and original id" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "retry-live-qos1",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "retry/live", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    var publisher = try connect(
        allocator,
        io,
        broker,
        "retry-live-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "retry/live",
        "retry",
        .{ .qos = .at_least_once },
    );
    var first = try subscriber.readPublish();
    defer first.deinit(allocator);
    const packet_id = first.publish.packet_id.?;
    try std.testing.expect(!first.publish.dup);
    try subscriber.shutdown();

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "retry-live-qos1",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    var retry = try resumed.readPublish();
    defer retry.deinit(allocator);
    try std.testing.expect(retry.publish.dup);
    try std.testing.expectEqual(packet_id, retry.publish.packet_id.?);
    try resumed.writePubAck(packet_id, 0);

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker resumes QoS 2 PUBREL and honors Receive Maximum" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "retry-qos2-pubrel",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "retry/qos2", .qos = .exactly_once }},
        .{},
    );
    defer suback.deinit(allocator);
    var publisher = try connect(
        allocator,
        io,
        broker,
        "retry-qos2-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "retry/qos2",
        "qos2",
        .{ .qos = .exactly_once },
    );
    var first = try subscriber.readPublish();
    defer first.deinit(allocator);
    const packet_id = first.publish.packet_id.?;
    try subscriber.writePubRec(packet_id, 0);
    var pubrel = try subscriber.readPubRel();
    defer pubrel.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
    try subscriber.shutdown();

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "retry-qos2-pubrel",
            .clean_start = false,
            .properties = &.{
                .{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 30,
                } },
                .{ .two_byte = .{
                    .id = .receive_maximum,
                    .value = 1,
                } },
            },
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    var retry_pubrel = try resumed.readSessionPubRel();
    defer retry_pubrel.deinit(allocator);
    try std.testing.expectEqual(packet_id, retry_pubrel.ack.packet_id);
    try resumed.writePubComp(packet_id, 0);

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker drains persistent Session within Receive Maximum one" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "window-one",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "window/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.disconnect(0);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "window-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "window/one",
        "one",
        .{ .qos = .at_least_once },
    );
    try publisher.publish(
        "window/two",
        "two",
        .{ .qos = .at_least_once },
    );

    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "window-one",
            .clean_start = false,
            .properties = &.{
                .{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 30,
                } },
                .{ .two_byte = .{
                    .id = .receive_maximum,
                    .value = 1,
                } },
            },
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);

    var first = try resumed.readPublish();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.publish.payload);
    try resumed.writePubAck(first.publish.packet_id.?, 0);
    var second = try resumed.readPublish();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.publish.payload);
    try resumed.writePubAck(second.publish.packet_id.?, 0);

    try disconnectAll(&.{ &publisher, &resumed });
    try joinServer(thread, &joined, &serve);
}

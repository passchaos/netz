const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const ServeState = context.ServeStateType;
const testBroker = context.testBrokerFn;
const connectWithOptions = context.connectWithOptionsFn;
const joinServer = context.joinServerFn;
const waitForPeerClose = context.waitForPeerCloseFn;

fn connectV311(
    allocator: std.mem.Allocator,
    io: std.Io,
    broker: context.BrokerType,
    client_id: []const u8,
    clean_session: bool,
) !context.runtime_mod.Connection {
    return connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v3_1_1,
            .client_id = client_id,
            .clean_start = clean_session,
        },
    );
}

test "broker authorizes CONNECT before creating Session state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        calls: usize = 0,

        fn authorize(
            context_ptr: *anyopaque,
            connect: mqtt.Connect,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.calls += 1;
            return connect.username != null and
                connect.password != null and
                std.mem.eql(u8, connect.username.?, "user") and
                std.mem.eql(u8, connect.password.?, "password");
        }
    };

    var policy: Policy = .{};
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 4,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .connect_authorization = .{
                .context = &policy,
                .authorize = Policy.authorize,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 4 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        var attempt = try context.runtime_mod.Client.connectAttempt(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = protocol,
                .client_id = if (protocol == .v3_1_1)
                    "denied-v311"
                else
                    "denied-v5",
                .username = "user",
                .password = "wrong",
                .properties = if (protocol == .v5) &.{.{
                    .four_byte = .{
                        .id = .session_expiry_interval,
                        .value = 300,
                    },
                }} else &.{},
            },
        );
        defer attempt.deinit(allocator);
        try std.testing.expect(!attempt.accepted());
        try std.testing.expectEqual(
            @as(u8, if (protocol == .v3_1_1) 0x05 else 0x87),
            attempt.connack.connack.reason_code,
        );
        try std.testing.expect(!attempt.connack.connack.session_present);
    }
    var anonymous = try context.runtime_mod.Client.connectAttempt(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "denied-anonymous-v5",
            .properties = &.{.{
                .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 300,
                },
            }},
        },
    );
    defer anonymous.deinit(allocator);
    try std.testing.expect(!anonymous.accepted());
    try std.testing.expectEqual(
        @as(u8, 0x87),
        anonymous.connack.connack.reason_code,
    );
    try std.testing.expectEqual(@as(usize, 0), broker.sessions.count());
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expectEqual(@as(usize, 0), broker.router.subscriptionCount());

    var accepted = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "authorized",
            .username = "user",
            .password = "password",
        },
    );
    defer accepted.close();
    try accepted.ping();
    try accepted.disconnect(0);

    try joinServer(thread, &joined, &serve);
    try std.testing.expectEqual(@as(usize, 4), policy.calls);
}

test "broker access control denies before durable state mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        fn publish(
            _: *anyopaque,
            connect: mqtt.Connect,
            message: mqtt.Publish,
        ) bool {
            return std.mem.eql(u8, connect.client_id, "acl-client") and
                !std.mem.eql(u8, message.topic, "acl/denied");
        }

        fn subscribe(
            _: *anyopaque,
            connect: mqtt.Connect,
            subscription: mqtt.Subscription,
        ) bool {
            return std.mem.eql(u8, connect.client_id, "acl-client") and
                !std.mem.eql(
                    u8,
                    subscription.topic_filter,
                    "acl/denied",
                );
        }
    };
    var policy_context: u8 = 0;
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .access_control = .{
                .context = &policy_context,
                .authorize_publish = Policy.publish,
                .authorize_subscribe = Policy.subscribe,
            },
        },
    );
    defer broker.deinit();
    var serve = ServeState{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "acl-client" },
    );
    defer client.close();
    var denied_suback = try client.subscribe(
        &.{
            .{ .topic_filter = "acl/denied", .qos = .at_least_once },
            .{ .topic_filter = "acl/allowed/sub", .qos = .at_least_once },
        },
        .{},
    );
    defer denied_suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x87, 0x01 },
        denied_suback.suback.reason_codes,
    );
    try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());

    try std.testing.expectError(
        error.PublishRefused,
        client.publish(
            "acl/denied",
            "not-retained",
            .{ .qos = .exactly_once, .retain = true },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
    try std.testing.expectEqual(@as(usize, 0), broker.pending_qos2.count());

    try client.publish(
        "acl/allowed",
        "accepted",
        .{ .qos = .at_least_once },
    );
    try client.ping();
    try client.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker enforces unsubscribe and outgoing delivery access control" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        fn publish(
            _: *anyopaque,
            _: mqtt.Connect,
            _: mqtt.Publish,
        ) bool {
            return true;
        }

        fn subscribe(
            _: *anyopaque,
            _: mqtt.Connect,
            _: mqtt.Subscription,
        ) bool {
            return true;
        }

        fn unsubscribe(
            _: *anyopaque,
            _: mqtt.Connect,
            filter: []const u8,
        ) bool {
            return !std.mem.eql(u8, filter, "acl/kept");
        }

        fn delivery(
            _: *anyopaque,
            authorization: context.DeliveryAuthorization,
        ) bool {
            return !(std.mem.eql(
                u8,
                authorization.client_id,
                "acl-reader",
            ) and std.mem.eql(u8, authorization.topic, "acl/hidden"));
        }
    };
    var policy_context: u8 = 0;
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 3,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .access_control = .{
                .context = &policy_context,
                .authorize_publish = Policy.publish,
                .authorize_subscribe = Policy.subscribe,
                .authorize_unsubscribe = Policy.unsubscribe,
                .authorize_delivery = Policy.delivery,
            },
        },
    );
    defer broker.deinit();
    var serve = ServeState{ .broker = &broker, .connection_count = 3 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "acl-reader" },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{
            .{ .topic_filter = "acl/kept", .qos = .at_least_once },
            .{ .topic_filter = "acl/hidden", .qos = .at_least_once },
            .{ .topic_filter = "acl/visible", .qos = .at_least_once },
        },
        .{},
    );
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x01, 0x01 },
        suback.suback.reason_codes,
    );
    var unsuback = try subscriber.unsubscribe(
        &.{ "acl/kept", "acl/visible" },
        .{},
    );
    defer unsuback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x87, 0x00 },
        unsuback.unsuback.reason_codes,
    );

    var publisher = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "acl-writer" },
    );
    defer publisher.close();
    try publisher.publish(
        "acl/hidden",
        "secret",
        .{ .qos = .at_least_once, .retain = true },
    );
    try publisher.publish(
        "acl/kept",
        "visible",
        .{ .qos = .at_least_once },
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings("acl/kept", delivered.publish.topic);
    try std.testing.expectEqualStrings("visible", delivered.publish.payload);
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);
    var hidden_unsuback = try subscriber.unsubscribe(
        &.{"acl/hidden"},
        .{},
    );
    defer hidden_unsuback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x00},
        hidden_unsuback.unsuback.reason_codes,
    );
    var hidden_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "acl/hidden",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer hidden_suback.deinit(allocator);
    // A denied retained replay must not sit ahead of this PINGRESP.
    try subscriber.ping();

    // The outgoing denial is recipient-specific and does not suppress retained
    // storage. A different client receives the same Application Message as a
    // retained replay after subscribing later.
    var allowed_reader = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "acl-allowed-reader" },
    );
    defer allowed_reader.close();
    var allowed_suback = try allowed_reader.subscribe(
        &.{.{
            .topic_filter = "acl/hidden",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer allowed_suback.deinit(allocator);
    var retained = try allowed_reader.readPublish();
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings(
        "acl/hidden",
        retained.publish.topic,
    );
    try std.testing.expectEqualStrings("secret", retained.publish.payload);
    try std.testing.expect(retained.publish.retain);
    try allowed_reader.writePubAck(retained.publish.packet_id.?, 0);

    try subscriber.disconnect(0);
    try publisher.disconnect(0);
    try allowed_reader.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker rechecks delivery access before resumed Session transmission" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        allow_delivery: std.atomic.Value(bool) = .init(true),

        fn publish(
            _: *anyopaque,
            _: mqtt.Connect,
            _: mqtt.Publish,
        ) bool {
            return true;
        }

        fn subscribe(
            _: *anyopaque,
            _: mqtt.Connect,
            _: mqtt.Subscription,
        ) bool {
            return true;
        }

        fn delivery(
            context_ptr: *anyopaque,
            _: context.DeliveryAuthorization,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            return self.allow_delivery.load(.acquire);
        }
    };
    var policy: Policy = .{};
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 3,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .access_control = .{
                .context = &policy,
                .authorize_publish = Policy.publish,
                .authorize_subscribe = Policy.subscribe,
                .authorize_delivery = Policy.delivery,
            },
        },
    );
    defer broker.deinit();
    var serve = ServeState{ .broker = &broker, .connection_count = 3 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const session_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var subscriber = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "acl-durable-reader",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "acl/durable",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.disconnect(0);

    var publisher = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "acl-durable-writer" },
    );
    defer publisher.close();
    try publisher.publish(
        "acl/durable",
        "queued-before-policy-change",
        .{ .qos = .at_least_once },
    );
    policy.allow_delivery.store(false, .release);

    var resumed_result = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "acl-durable-reader",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    // If the denied queued PUBLISH were left at the Session head, this PING
    // would observe it instead of PINGRESP. Successful ping therefore proves
    // both suppression and forward progress after policy re-evaluation.
    try resumed.ping();

    try resumed.disconnect(0);
    try publisher.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker caps MQTT 5 subscriptions and live delivery at Maximum QoS" {
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
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber_result =
        try context.runtime_mod.Client.connectWithConnAck(
            allocator,
            io,
            broker.address(),
            .{ .protocol = .v5, .client_id = "maximum-qos-sub" },
        );
    var subscriber = subscriber_result.connection;
    defer subscriber.close();
    defer subscriber_result.connack.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        mqtt.maximumQoS(subscriber_result.connack.connack.properties).?,
    );
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "maximum/qos",
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

    var publisher = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "maximum-qos-pub" },
    );
    defer publisher.close();
    try publisher.publish(
        "maximum/qos",
        "capped",
        .{ .qos = .at_least_once },
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        delivered.publish.qos,
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);

    try subscriber.disconnect(0);
    try publisher.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker Keep Alive zero disables inactivity timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "keep-alive-disabled",
            .keep_alive_seconds = 0,
        },
    );
    defer client.close();
    // A one-second Keep Alive would expire at 1.5 seconds. Remaining usable
    // beyond that boundary proves zero is treated as disabled, not as an
    // immediate deadline.
    try std.Io.sleep(io, .fromMilliseconds(1700), .awake);
    try client.ping();

    try client.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker maximum Keep Alive replaces MQTT 5 and refuses MQTT 3.1.1" {
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
                .max_connections = 4,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .max_outgoing_inflight = 64,
                .maximum_keep_alive_seconds = 10,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 4,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]u16{ 11, 0 }) |requested| {
        var attempt = try context.runtime_mod.Client.connectAttempt(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = .v5,
                .client_id = "maximum-keep-alive-v5",
                .keep_alive_seconds = requested,
            },
        );
        defer attempt.deinit(allocator);
        try std.testing.expect(attempt.accepted());
        try std.testing.expectEqual(
            @as(?u16, 10),
            mqtt.serverKeepAlive(attempt.connack.connack.properties),
        );
        try std.testing.expectEqual(
            @as(u16, 10),
            attempt.connection.?.keep_alive_seconds,
        );
        try attempt.connection.?.disconnect(0);
    }

    for ([_]u16{ 11, 0 }) |requested| {
        var attempt = try context.runtime_mod.Client.connectAttempt(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = .v3_1_1,
                .client_id = "maximum-keep-alive-v311",
                .keep_alive_seconds = requested,
            },
        );
        defer attempt.deinit(allocator);
        try std.testing.expect(!attempt.accepted());
        try std.testing.expectEqual(
            @as(u8, 0x02),
            attempt.connack.connack.reason_code,
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            attempt.connack.connack.properties.len,
        );
    }

    try joinServer(thread, &joined, &serve);
}

test "broker auto-detects MQTT 3.1.1 and MQTT 5 on one listener" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 4, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 4,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var v3_subscriber = try connectV311(
        allocator,
        io,
        broker,
        "v311-subscriber",
        true,
    );
    defer v3_subscriber.close();
    var v5_subscriber = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "v5-subscriber",
        },
    );
    defer v5_subscriber.close();
    var v3_suback = try v3_subscriber.subscribe(
        &.{
            .{
                .topic_filter = "mixed/version",
                .qos = .at_least_once,
            },
            .{
                .topic_filter = "mixed/unused",
                .qos = .at_least_once,
            },
        },
        .{},
    );
    defer v3_suback.deinit(allocator);
    var v5_suback = try v5_subscriber.subscribe(
        &.{.{
            .topic_filter = "mixed/version",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer v5_suback.deinit(allocator);

    var v3_publisher = try connectV311(
        allocator,
        io,
        broker,
        "v311-publisher",
        true,
    );
    defer v3_publisher.close();
    try v3_publisher.publish(
        "mixed/version",
        "from-v3",
        .{ .qos = .at_least_once },
    );
    var to_v3 = try v3_subscriber.readPublish();
    defer to_v3.deinit(allocator);
    try std.testing.expectEqualStrings(
        "from-v3",
        to_v3.publish.payload,
    );
    try v3_subscriber.writePubAck(to_v3.publish.packet_id.?, 0);
    var to_v5 = try v5_subscriber.readPublish();
    defer to_v5.deinit(allocator);
    try std.testing.expectEqualStrings(
        "from-v3",
        to_v5.publish.payload,
    );
    try v5_subscriber.writePubAck(to_v5.publish.packet_id.?, 0);
    // MQTT 3.1.1 has no "No matching subscribers" PUBACK reason field. The
    // publish still completes successfully with the v3 success-only ACK.
    try v3_publisher.publish(
        "mixed/no-subscriber",
        "no-match",
        .{ .qos = .at_least_once },
    );

    var v5_publisher = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "v5-publisher",
        },
    );
    defer v5_publisher.close();
    try v5_publisher.publish(
        "mixed/version",
        "from-v5",
        .{
            .qos = .at_least_once,
            .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "source",
                .value = "v5",
            } }},
        },
    );
    var v3_delivery = try v3_subscriber.readPublish();
    defer v3_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "from-v5",
        v3_delivery.publish.payload,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        v3_delivery.publish.properties.len,
    );
    try v3_subscriber.writePubAck(
        v3_delivery.publish.packet_id.?,
        0,
    );
    var v5_delivery = try v5_subscriber.readPublish();
    defer v5_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "from-v5",
        v5_delivery.publish.payload,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        v5_delivery.publish.properties.len,
    );
    try std.testing.expectEqual(
        @as(?u16, 1),
        mqtt.topicAlias(v5_delivery.publish.properties),
    );
    try v5_subscriber.writePubAck(
        v5_delivery.publish.packet_id.?,
        0,
    );

    var v3_unsuback = try v3_subscriber.unsubscribe(
        &.{ "mixed/version", "mixed/unused" },
        .{},
    );
    defer v3_unsuback.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), v3_unsuback
        .unsuback.reason_codes.len);

    try v3_subscriber.disconnect(0);
    try v5_subscriber.disconnect(0);
    try v3_publisher.disconnect(0);
    try v5_publisher.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker applies MQTT 3.1.1 persistent and clean Session semantics" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 4, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 4,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var first_result =
        try context.runtime_mod.Client.connectWithConnAck(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = .v3_1_1,
                .client_id = "v311-persistent",
                .clean_start = false,
            },
        );
    var first = first_result.connection;
    defer first.close();
    defer first_result.connack.deinit(allocator);
    try std.testing.expect(
        !first_result.connack.connack.session_present,
    );
    var suback = try first.subscribe(
        &.{.{
            .topic_filter = "v311/offline",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try first.disconnect(0);
    try waitForPeerClose(&first);

    var publisher = try connectV311(
        allocator,
        io,
        broker,
        "v311-offline-publisher",
        true,
    );
    defer publisher.close();
    try publisher.publish(
        "v311/offline",
        "queued-v3",
        .{ .qos = .at_least_once },
    );

    var resumed_result =
        try context.runtime_mod.Client.connectWithConnAck(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = .v3_1_1,
                .client_id = "v311-persistent",
                .clean_start = false,
            },
        );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(
        resumed_result.connack.connack.session_present,
    );
    var queued = try resumed.readPublish();
    defer queued.deinit(allocator);
    try std.testing.expectEqualStrings(
        "queued-v3",
        queued.publish.payload,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        queued.publish.properties.len,
    );
    try resumed.writePubAck(queued.publish.packet_id.?, 0);
    try resumed.disconnect(0);
    try waitForPeerClose(&resumed);

    var clean_result =
        try context.runtime_mod.Client.connectWithConnAck(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = .v3_1_1,
                .client_id = "v311-persistent",
                .clean_start = true,
            },
        );
    var clean = clean_result.connection;
    defer clean.close();
    defer clean_result.connack.deinit(allocator);
    try std.testing.expect(
        !clean_result.connack.connack.session_present,
    );
    try publisher.publish("v311/offline", "not-restored", .{});
    // PINGRESP must be next. Receiving PUBLISH here would prove CleanSession=1
    // failed to remove the restored subscription.
    try clean.ping();

    try publisher.disconnect(0);
    try clean.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker completes MQTT 3.1.1 QoS 2 without v5 reason fields" {
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

    var subscriber = try connectV311(
        allocator,
        io,
        broker,
        "v311-qos2-subscriber",
        true,
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "v311/qos2",
            .qos = .exactly_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    var publisher = try connectV311(
        allocator,
        io,
        broker,
        "v311-qos2-publisher",
        true,
    );
    defer publisher.close();
    try publisher.publish(
        "v311/qos2",
        "exactly-once",
        .{ .qos = .exactly_once },
    );
    var delivery = try subscriber.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.exactly_once,
        delivery.publish.qos,
    );
    try subscriber.writePubRec(delivery.publish.packet_id.?, 0);
    var pubrel = try subscriber.readPubRel();
    defer pubrel.deinit(allocator);
    try subscriber.writePubComp(pubrel.ack.packet_id, 0);

    try subscriber.disconnect(0);
    try publisher.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker downgrades MQTT 3.1.1 QoS 2 quota rejection handshake" {
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
                .max_queued_deliveries_per_connection = 8,
                .max_pending_incoming_qos2 = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
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

    var held = try connectV311(
        allocator,
        io,
        broker,
        "v311-quota-held",
        true,
    );
    defer held.close();
    var rejected = try connectV311(
        allocator,
        io,
        broker,
        "v311-quota-rejected",
        true,
    );
    defer rejected.close();

    const held_id = (try held.writePublish(
        "v311/quota",
        "held",
        .{ .qos = .exactly_once },
    )).?;
    var held_pubrec = try held.readPubRec();
    defer held_pubrec.deinit(allocator);

    const rejected_id = (try rejected.writePublish(
        "v311/quota",
        "rejected",
        .{ .qos = .exactly_once },
    )).?;
    var rejected_pubrec = try rejected.readPubRec();
    defer rejected_pubrec.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0),
        rejected_pubrec.ack.reason_code,
    );
    try rejected.writePubRel(rejected_id, 0);
    var rejected_pubcomp = try rejected.readPubComp();
    defer rejected_pubcomp.deinit(allocator);
    try std.testing.expectEqual(
        rejected_id,
        rejected_pubcomp.ack.packet_id,
    );

    try held.writePubRel(held_id, 0);
    var held_pubcomp = try held.readPubComp();
    defer held_pubcomp.deinit(allocator);
    try held.disconnect(0);
    try rejected.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker assigns unique MQTT 5 anonymous Client Identifiers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var prefix = [_]u8{ 't', 'e', 's', 't', '-' };
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .auto_client_id_prefix = &prefix,
        },
    );
    defer broker.deinit();
    // `listen` owns the prefix rather than borrowing mutable caller storage.
    @memset(&prefix, 'x');

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var first = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = true,
        },
    );
    defer first.deinit(allocator);
    var second = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = true,
        },
    );
    defer second.deinit(allocator);

    const first_id = mqtt.assignedClientIdentifier(
        first.connack.connack.properties,
    ).?;
    const second_id = mqtt.assignedClientIdentifier(
        second.connack.connack.properties,
    ).?;
    try std.testing.expect(std.mem.startsWith(
        u8,
        first_id,
        "test-",
    ));
    try std.testing.expectEqual(@as(usize, 41), first_id.len);
    try std.testing.expect(!std.mem.eql(u8, first_id, second_id));
    try std.testing.expectEqualStrings(
        first_id,
        first.connection.assignedClientId().?,
    );

    var first_suback = try first.connection.subscribe(
        &.{.{ .topic_filter = "anonymous/first" }},
        .{},
    );
    defer first_suback.deinit(allocator);
    var second_suback = try second.connection.subscribe(
        &.{.{ .topic_filter = "anonymous/second" }},
        .{},
    );
    defer second_suback.deinit(allocator);
    // Both connections remain live. If the empty ClientID had been used as a
    // shared Session key, accepting `second` would have shut down `first`.
    try first.connection.ping();
    try second.connection.ping();

    try first.connection.disconnect(0);
    try second.connection.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker can reject zero-length Client Identifiers before registration" {
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
                .max_connections = 3,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .allow_zero_length_client_id = false },
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

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        var attempt = try context.runtime_mod.Client.connectAttempt(
            allocator,
            io,
            broker.address(),
            .{
                .protocol = protocol,
                .client_id = "",
                .clean_start = true,
            },
        );
        defer attempt.deinit(allocator);
        try std.testing.expect(!attempt.accepted());
        try std.testing.expectEqual(
            @as(u8, if (protocol == .v3_1_1) 0x02 else 0x80),
            attempt.connack.connack.reason_code,
        );
        try std.testing.expect(
            !attempt.connack.connack.session_present,
        );
    }

    // Refusal must not reserve the empty Client ID or any generated Session
    // identity. A subsequent named client is accepted and remains usable.
    var named = try connectWithOptions(
        allocator,
        io,
        broker,
        .{ .protocol = .v5, .client_id = "named-after-refusal" },
    );
    defer named.close();
    try named.ping();
    try named.disconnect(0);

    try joinServer(thread, &joined, &serve);
}

test "broker assigned MQTT 5 Client Identifier can resume Session" {
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

    var first = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = true,
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 30,
            } }},
        },
    );
    const assigned = try allocator.dupe(
        u8,
        mqtt.assignedClientIdentifier(
            first.connack.connack.properties,
        ).?,
    );
    defer allocator.free(assigned);
    defer first.deinit(allocator);
    var suback = try first.connection.subscribe(
        &.{.{ .topic_filter = "assigned/resume" }},
        .{},
    );
    defer suback.deinit(allocator);
    try first.connection.disconnect(0);
    try waitForPeerClose(&first.connection);

    var resumed = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = assigned,
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 30,
            } }},
        },
    );
    defer resumed.deinit(allocator);
    try std.testing.expect(resumed.connack.connack.session_present);
    try std.testing.expect(
        mqtt.assignedClientIdentifier(
            resumed.connack.connack.properties,
        ) == null,
    );
    try resumed.connection.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "runtime Client.connect retains assigned Client Identifier" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
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
        .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = true,
        },
    );
    defer client.close();
    try std.testing.expect(std.mem.startsWith(
        u8,
        client.assignedClientId().?,
        "netz-",
    ));
    try client.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker keeps assigned MQTT 3.1.1 Client Identifier internal" {
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

    var first = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v3_1_1,
            .client_id = "",
            .clean_start = true,
        },
    );
    defer first.deinit(allocator);
    var second = try context.runtime_mod.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v3_1_1,
            .client_id = "",
            .clean_start = true,
        },
    );
    defer second.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        first.connack.connack.properties.len,
    );
    try first.connection.ping();
    try second.connection.ping();

    try first.connection.disconnect(0);
    try second.connection.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker validates anonymous Client Identifier prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.InvalidProperty,
        context.BrokerType.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .auto_client_id_prefix = "x" ** 51 },
        ),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        context.BrokerType.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .auto_client_id_prefix = "bad\x00prefix" },
        ),
    );
}

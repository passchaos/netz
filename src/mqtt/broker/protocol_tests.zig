const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const ServeState = context.ServeStateType;
const testBroker = context.testBrokerFn;
const connectWithOptions = context.connectWithOptionsFn;
const disconnectAll = context.disconnectAllFn;
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

fn expectNoClientPacket(
    connection: *context.runtime_mod.Connection,
    timeout: std.Io.Duration,
) !void {
    try std.testing.expectError(
        error.Timeout,
        connection.readClientPacketEventWithTimeout(timeout),
    );
}

test "broker writes self-delivery before publisher acknowledgement" {
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

    var clients = [_]context.runtime_mod.Connection{
        try connectWithOptions(allocator, io, broker, .{
            .protocol = .v3_1_1,
            .client_id = "self-delivery-order-v311",
        }),
        try connectWithOptions(allocator, io, broker, .{
            .protocol = .v5,
            .client_id = "self-delivery-order-v5",
        }),
    };
    defer for (&clients) |*client| client.close();

    for (&clients) |*client| {
        var suback = try client.subscribe(
            &.{.{
                .topic_filter = "self/delivery/order",
                .qos = .at_least_once,
            }},
            .{},
        );
        defer suback.deinit(allocator);

        const published_id = (try client.writePublish(
            "self/delivery/order",
            "payload",
            .{ .qos = .at_least_once },
        )).?;
        const delivery_id = delivery: {
            var event = try client.readClientPacketEvent();
            defer event.deinit(allocator);
            break :delivery switch (event) {
                .publish => |owned| blk: {
                    try std.testing.expectEqualStrings(
                        "payload",
                        owned.publish.payload,
                    );
                    break :blk owned.publish.packet_id.?;
                },
                else => return error.UnexpectedPacket,
            };
        };

        {
            var event = try client.readClientPacketEvent();
            defer event.deinit(allocator);
            switch (event) {
                .puback => |owned| {
                    try std.testing.expectEqual(
                        published_id,
                        owned.ack.packet_id,
                    );
                    try client.applyPubAck(owned.ack);
                },
                else => return error.UnexpectedPacket,
            }
        }
        try client.writePubAck(delivery_id, 0);
        try client.disconnect(0);
    }

    try joinServer(thread, &joined, &serve);
}

test "broker tolerates unknown outbound acknowledgement identifiers" {
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

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }, 0..) |protocol, index| {
        var client = try connectWithOptions(
            allocator,
            io,
            broker,
            .{
                .protocol = protocol,
                .client_id = if (index == 0)
                    "unknown-ack-v311"
                else
                    "unknown-ack-v5",
            },
        );
        defer client.close();

        // A valid PUBACK/PUBCOMP for an identifier absent from both the
        // durable Session and this Network Connection is idempotently ignored.
        try client.writePubAck(41, 0);
        try client.ping();

        // An accepted PUBREC still advances the peer exchange with PUBREL even
        // when the sender no longer has its original PUBLISH state.
        try client.writePubRec(42, 0);
        var event = try client.readClientPacketEvent();
        defer event.deinit(allocator);
        switch (event) {
            .pubrel => |owned| try std.testing.expectEqual(
                @as(u16, 42),
                owned.ack.packet_id,
            ),
            else => return error.UnexpectedPacket,
        }
        try client.writePubComp(42, 0);
        try client.writePubComp(43, 0);
        try client.ping();
        try client.disconnect(0);
    }

    try joinServer(thread, &joined, &serve);
}

test "broker retransmits PUBREL after duplicate successful PUBREC" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 4, 64);
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 4 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }, 0..) |protocol, index| {
        var subscriber = try connectWithOptions(
            allocator,
            io,
            broker,
            .{
                .protocol = protocol,
                .client_id = if (index == 0)
                    "duplicate-pubrec-v311"
                else
                    "duplicate-pubrec-v5",
            },
        );
        defer subscriber.close();
        var suback = try subscriber.subscribe(
            &.{.{ .topic_filter = "duplicate/pubrec", .qos = .exactly_once }},
            .{},
        );
        defer suback.deinit(allocator);

        var publisher = try connectWithOptions(
            allocator,
            io,
            broker,
            .{
                .protocol = protocol,
                .client_id = if (index == 0)
                    "duplicate-publisher-v311"
                else
                    "duplicate-publisher-v5",
            },
        );
        defer publisher.close();
        try publisher.publish(
            "duplicate/pubrec",
            "payload",
            .{ .qos = .exactly_once },
        );

        var delivery = try subscriber.readPublish();
        defer delivery.deinit(allocator);
        const packet_id = delivery.publish.packet_id.?;
        try subscriber.writePubRec(packet_id, 0);
        var first_pubrel = try subscriber.readPubRel();
        defer first_pubrel.deinit(allocator);
        try std.testing.expectEqual(packet_id, first_pubrel.ack.packet_id);

        try subscriber.writePubRec(packet_id, 0);
        var repeated_pubrel = try subscriber.readPubRel();
        defer repeated_pubrel.deinit(allocator);
        try std.testing.expectEqual(packet_id, repeated_pubrel.ack.packet_id);
        try subscriber.writePubComp(packet_id, 0);
        try subscriber.ping();
        try disconnectAll(&.{ &publisher, &subscriber });
    }

    try joinServer(thread, &joined, &serve);
}

test "broker reports wrong-stage acknowledgements as protocol errors" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 4, 64);
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 4 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }, 0..) |protocol, index| {
        var subscriber = try connectWithOptions(
            allocator,
            io,
            broker,
            .{
                .protocol = protocol,
                .client_id = if (index == 0)
                    "wrong-ack-v311"
                else
                    "wrong-ack-v5",
            },
        );
        defer subscriber.close();
        var suback = try subscriber.subscribe(
            &.{.{ .topic_filter = "wrong/ack", .qos = .at_least_once }},
            .{},
        );
        defer suback.deinit(allocator);

        var publisher = try connectWithOptions(
            allocator,
            io,
            broker,
            .{
                .protocol = protocol,
                .client_id = if (index == 0)
                    "wrong-ack-publisher-v311"
                else
                    "wrong-ack-publisher-v5",
            },
        );
        defer publisher.close();
        try publisher.publish(
            "wrong/ack",
            "payload",
            .{ .qos = .at_least_once },
        );
        var delivery = try subscriber.readPublish();
        defer delivery.deinit(allocator);
        try publisher.disconnect(0);

        try subscriber.writePubRec(delivery.publish.packet_id.?, 0);
        if (protocol == .v5) {
            var event = try subscriber.readClientPacketEvent();
            defer event.deinit(allocator);
            switch (event) {
                .disconnect => |owned| try std.testing.expectEqual(
                    @as(u8, 0x82),
                    owned.disconnect.reason_code,
                ),
                else => return error.UnexpectedPacket,
            }
        }
        try waitForPeerClose(&subscriber);
    }

    try joinServer(thread, &joined, &serve);
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

test "broker CONNECT context exposes trusted PROXY identity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        called: bool = false,

        fn authorize(
            context_ptr: *anyopaque,
            request: context.ConnectContext,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.called = true;
            const proxy = request.proxy orelse return false;
            return proxy.version == .v1 and
                proxy.command == .proxy and
                request.peer_certificates == null and
                request.remote_address == .ip4 and
                request.remote_address.ip4.port == 6275 and
                std.mem.eql(
                    u8,
                    &request.remote_address.ip4.bytes,
                    &.{ 192, 0, 2, 5 },
                ) and
                std.mem.eql(
                    u8,
                    request.connect.client_id,
                    "proxy-context",
                );
        }
    };

    var policy: Policy = .{};
    var broker = try context.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{
                    .max_packet_size = 4096,
                    .proxy_protocol = .v1,
                },
            },
            .connect_context_authorization = .{
                .context = &policy,
                .authorize = Policy.authorize,
            },
        },
    );
    defer broker.deinit();
    var serve = ServeState{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try broker.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    var prefix = "PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n".*;
    var bufs = [_][]const u8{""};
    const remaining = try io.vtable.netWrite(
        io.userdata,
        stream.socket.handle,
        &prefix,
        &bufs,
        0,
    );
    try std.testing.expectEqual(prefix.len, remaining);
    var connection = context.runtime_mod.Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
        .protocol = .v5,
        .limits = .{ .max_packet_size = 4096 },
    };
    stream_owned = false;
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-context",
        .limits = .{ .max_packet_size = 4096 },
    });
    try std.testing.expect(attempt.accepted());
    var accepted = try attempt.requireAccepted();
    defer accepted.deinit(allocator);
    try accepted.connection.disconnect(0);

    try joinServer(thread, &joined, &serve);
    try std.testing.expect(policy.called);
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

test "broker returns mixed MQTT 5 SUBACK reasons for ACL denial and subscription quota" {
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
            subscription: mqtt.Subscription,
        ) bool {
            return !std.mem.eql(
                u8,
                subscription.topic_filter,
                "quota/v5/denied",
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
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .session = .{ .max_subscriptions_per_session = 1 },
            .access_control = .{
                .context = &policy_context,
                .authorize_publish = Policy.publish,
                .authorize_subscribe = Policy.subscribe,
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

    var publisher = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "quota-v5-publisher" },
    );
    defer publisher.close();
    var subscriber = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "quota-v5-subscriber" },
    );
    defer subscriber.close();

    try publisher.publish(
        "quota/v5/denied",
        "denied-retained",
        .{ .qos = .at_least_once, .retain = true },
    );
    try publisher.publish(
        "quota/v5/allowed",
        "allowed-retained",
        .{ .qos = .at_least_once, .retain = true },
    );
    try publisher.publish(
        "quota/v5/overflow",
        "overflow-retained",
        .{ .qos = .at_least_once, .retain = true },
    );

    var suback = try subscriber.subscribe(
        &.{
            .{ .topic_filter = "quota/v5/denied", .qos = .at_least_once },
            .{ .topic_filter = "quota/v5/allowed", .qos = .at_least_once },
            .{ .topic_filter = "quota/v5/overflow", .qos = .at_least_once },
        },
        .{},
    );
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x87, 0x01, 0x97 },
        suback.suback.reason_codes,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        broker.router.subscriptionCount(),
    );

    var retained = try subscriber.readPublish();
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings(
        "quota/v5/allowed",
        retained.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "allowed-retained",
        retained.publish.payload,
    );
    try std.testing.expect(retained.publish.retain);
    try subscriber.writePubAck(retained.publish.packet_id.?, 0);
    try expectNoClientPacket(
        &subscriber,
        std.Io.Duration.fromMilliseconds(50),
    );

    var unsuback = try subscriber.unsubscribe(
        &.{"quota/v5/allowed"},
        .{},
    );
    defer unsuback.deinit(allocator);
    var reused_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "quota/v5/overflow",
            .qos = .at_least_once,
            .retain_handling = 2,
        }},
        .{},
    );
    defer reused_suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x01},
        reused_suback.suback.reason_codes,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        broker.router.subscriptionCount(),
    );

    try publisher.publish(
        "quota/v5/overflow",
        "overflow-live",
        .{ .qos = .at_least_once },
    );

    var live = try subscriber.readPublish();
    defer live.deinit(allocator);
    try std.testing.expectEqualStrings("quota/v5/overflow", live.publish.topic);
    try std.testing.expectEqualStrings("overflow-live", live.publish.payload);
    try std.testing.expect(!live.publish.retain);
    try subscriber.writePubAck(live.publish.packet_id.?, 0);
    try expectNoClientPacket(
        &subscriber,
        std.Io.Duration.fromMilliseconds(50),
    );

    try subscriber.ping();
    try disconnectAll(&.{ &publisher, &subscriber });
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

test "broker rejects disabled protocol version before registration" {
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
            .accept = .{ .accepted_protocol_versions = .{
                .v3_1_1 = false,
            } },
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
            .protocol = .v3_1_1,
            .client_id = "disabled-v311",
        },
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.accepted());
    try std.testing.expectEqual(
        @as(u8, 0x01),
        refused.connack.connack.reason_code,
    );
    const after_refusal = broker.stats();
    try std.testing.expectEqual(@as(usize, 0), after_refusal.active_connections);
    try std.testing.expectEqual(@as(usize, 0), after_refusal.sessions);
    try std.testing.expectEqual(@as(usize, 0), after_refusal.subscriptions);
    try std.testing.expectEqual(@as(usize, 0), after_refusal.scheduled_wills);

    var allowed = try connectWithOptions(
        allocator,
        io,
        broker,
        .{ .protocol = .v5, .client_id = "allowed-v5" },
    );
    defer allowed.close();
    try allowed.ping();
    try allowed.disconnect(0);
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

test "broker returns mixed MQTT 3.1.1 SUBACK results for subscription quota" {
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
            .session = .{ .max_subscriptions_per_session = 1 },
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

    var publisher = try connectV311(
        allocator,
        io,
        broker,
        "quota-v311-publisher",
        true,
    );
    defer publisher.close();
    var subscriber = try connectV311(
        allocator,
        io,
        broker,
        "quota-v311-subscriber",
        true,
    );
    defer subscriber.close();

    try publisher.publish(
        "quota/v311/allowed",
        "allowed-retained",
        .{ .qos = .at_least_once, .retain = true },
    );
    try publisher.publish(
        "quota/v311/overflow",
        "overflow-retained",
        .{ .qos = .at_least_once, .retain = true },
    );

    var suback = try subscriber.subscribe(
        &.{
            .{ .topic_filter = "quota/v311/allowed", .qos = .at_least_once },
            .{ .topic_filter = "quota/v311/overflow", .qos = .at_least_once },
        },
        .{},
    );
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x80 },
        suback.suback.reason_codes,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        broker.router.subscriptionCount(),
    );

    var retained = try subscriber.readPublish();
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings(
        "quota/v311/allowed",
        retained.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "allowed-retained",
        retained.publish.payload,
    );
    try std.testing.expect(retained.publish.retain);
    try subscriber.writePubAck(retained.publish.packet_id.?, 0);
    try expectNoClientPacket(
        &subscriber,
        std.Io.Duration.fromMilliseconds(50),
    );

    try publisher.publish(
        "quota/v311/allowed",
        "allowed-live",
        .{ .qos = .at_least_once },
    );
    try publisher.publish(
        "quota/v311/overflow",
        "overflow-live",
        .{ .qos = .at_least_once },
    );

    var live = try subscriber.readPublish();
    defer live.deinit(allocator);
    try std.testing.expectEqualStrings(
        "quota/v311/allowed",
        live.publish.topic,
    );
    try std.testing.expectEqualStrings("allowed-live", live.publish.payload);
    try std.testing.expect(!live.publish.retain);
    try subscriber.writePubAck(live.publish.packet_id.?, 0);
    try expectNoClientPacket(
        &subscriber,
        std.Io.Duration.fromMilliseconds(50),
    );

    try subscriber.ping();
    try disconnectAll(&.{ &publisher, &subscriber });
    try joinServer(thread, &joined, &serve);
}

test "broker preserves existing subscription replacement at capacity" {
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
            subscription: mqtt.Subscription,
        ) bool {
            return !std.mem.eql(
                u8,
                subscription.topic_filter,
                "quota/replacement/denied",
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
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .session = .{ .max_subscriptions_per_session = 1 },
            .access_control = .{
                .context = &policy_context,
                .authorize_publish = Policy.publish,
                .authorize_subscribe = Policy.subscribe,
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

    var publisher = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "quota-replacement-publisher" },
    );
    defer publisher.close();
    var subscriber = try context.runtime_mod.Client.connect(
        allocator,
        io,
        broker.address(),
        .{ .protocol = .v5, .client_id = "quota-replacement-subscriber" },
    );
    defer subscriber.close();

    var initial_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "quota/replacement/existing",
            .qos = .at_most_once,
        }},
        .{},
    );
    defer initial_suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x00},
        initial_suback.suback.reason_codes,
    );

    var replacement_suback = try subscriber.subscribe(
        &.{
            .{
                .topic_filter = "quota/replacement/existing",
                .qos = .at_least_once,
                .retain_handling = 2,
            },
            .{
                .topic_filter = "quota/replacement/denied",
                .qos = .at_least_once,
            },
            .{
                .topic_filter = "quota/replacement/new",
                .qos = .at_least_once,
            },
        },
        .{},
    );
    defer replacement_suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x87, 0x97 },
        replacement_suback.suback.reason_codes,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        broker.router.subscriptionCount(),
    );

    try publisher.publish(
        "quota/replacement/existing",
        "existing-live",
        .{ .qos = .at_least_once },
    );
    try publisher.publish(
        "quota/replacement/denied",
        "denied-live",
        .{ .qos = .at_least_once },
    );
    try publisher.publish(
        "quota/replacement/new",
        "new-live",
        .{ .qos = .at_least_once },
    );

    var live = try subscriber.readPublish();
    defer live.deinit(allocator);
    try std.testing.expectEqualStrings(
        "quota/replacement/existing",
        live.publish.topic,
    );
    try std.testing.expectEqualStrings("existing-live", live.publish.payload);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, live.publish.qos);
    try subscriber.writePubAck(live.publish.packet_id.?, 0);
    try expectNoClientPacket(
        &subscriber,
        std.Io.Duration.fromMilliseconds(50),
    );

    try subscriber.ping();
    try disconnectAll(&.{ &publisher, &subscriber });
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
            // MQTT 5 allows an assigned identifier even without Clean Start.
            .clean_start = false,
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

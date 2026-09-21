const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const Broker = context.BrokerType;
const ServeState = context.ServeStateType;
const runtime = context.runtime_mod;
const testBroker = context.testBrokerFn;
const connectWithOptions = context.connectWithOptionsFn;
const joinServer = context.joinServerFn;
const waitForPeerClose = context.waitForPeerCloseFn;

fn expectNoClientPacket(
    connection: *context.runtime_mod.Connection,
    timeout: std.Io.Duration,
) !void {
    try std.testing.expectError(
        error.Timeout,
        connection.readClientPacketEventWithTimeout(timeout),
    );
}

const ListenerServeState = struct {
    broker: *Broker,
    listeners: []const mqtt.broker.Listener,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListeners(self.listeners) catch |err| {
            self.err = err;
        };
    }
};

test "broker reports post-parse PUBLISH property violations" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "invalid-publish-property",
    });
    defer client.close();
    var invalid_publish: std.ArrayList(u8) = .empty;
    defer invalid_publish.deinit(allocator);
    try mqtt.writePublish(&invalid_publish, allocator, .v5, "topic", "payload", .{
        .qos = .at_least_once,
        .packet_id = 1,
        .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 1,
        } }},
    });
    try client.transport.writePacket(invalid_publish.items);

    var event = try client.readClientPacketEvent();
    defer event.deinit(allocator);
    switch (event) {
        .disconnect => |owned| try std.testing.expectEqual(
            @as(u8, 0x82),
            owned.disconnect.reason_code,
        ),
        else => return error.UnexpectedPacket,
    }
    try waitForPeerClose(&client);
    try joinServer(thread, &joined, &serve);
}

test "broker distinguishes malformed and protocol-error SUBSCRIBE packets" {
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

    var malformed = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "malformed-subscribe-property-context",
    });
    defer malformed.close();
    // Payload Format Indicator is well-formed generically but is not valid in
    // a SUBSCRIBE. MQTT 5 section 2.2.2.2 classifies that packet as malformed.
    var malformed_subscribe = [_]u8{
        0x82, 0x09, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x01, 'p', 0x00,
    };
    try malformed.transport.writePacket(&malformed_subscribe);
    var malformed_disconnect = try malformed.readDisconnect();
    defer malformed_disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x81),
        malformed_disconnect.disconnect.reason_code,
    );
    try waitForPeerClose(&malformed);

    var semantic = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "semantic-subscribe-options",
    });
    defer semantic.close();
    // The packet is structurally complete, but Retain Handling value 3 is a
    // Protocol Error under MQTT 5 section 3.8.3.1.
    var semantic_subscribe = [_]u8{
        0x82, 0x07, 0x00, 0x02, 0x00, 0x00, 0x01, 'p', 0x30,
    };
    try semantic.transport.writePacket(&semantic_subscribe);
    var semantic_disconnect = try semantic.readDisconnect();
    defer semantic_disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x82),
        semantic_disconnect.disconnect.reason_code,
    );
    try waitForPeerClose(&semantic);
    try joinServer(thread, &joined, &serve);
}

test "broker reports unnegotiated reauthentication as protocol error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "unnegotiated-reauth",
    });
    defer client.close();
    try client.writeAuth(0x19, &.{.{ .utf8 = .{
        .id = .authentication_method,
        .value = "unexpected",
    } }});

    var event = try client.readClientPacketEvent();
    defer event.deinit(allocator);
    switch (event) {
        .disconnect => |owned| try std.testing.expectEqual(
            @as(u8, 0x82),
            owned.disconnect.reason_code,
        ),
        else => return error.UnexpectedPacket,
    }
    try waitForPeerClose(&client);
    try joinServer(thread, &joined, &serve);
}

test "broker protects reserved client publish topics by default" {
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

    var client = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "reserved-topic-policy",
    });
    defer client.close();
    for ([_][]const u8{
        "$SYS/broker/uptime",
        "$SYS/broker/connection/me",
        "$share/group/topic",
    }) |topic| {
        const packet_id = (try client.writePublish(
            topic,
            "blocked",
            .{ .qos = .exactly_once },
        )).?;
        var event = try client.readClientPacketEvent();
        defer event.deinit(allocator);
        switch (event) {
            .pubrec => |owned| {
                try std.testing.expectEqual(packet_id, owned.ack.packet_id);
                try std.testing.expectEqual(
                    @as(u8, 0x87),
                    owned.ack.reason_code,
                );
                try std.testing.expectError(
                    error.PublishRefused,
                    client.applyPubRec(owned.ack),
                );
            },
            else => return error.UnexpectedPacket,
        }
    }

    try client.publish(
        "$SYS/broker/connection/me/state",
        "allowed",
        .{ .qos = .exactly_once },
    );
    try client.publish(
        "$test/application",
        "allowed",
        .{ .qos = .exactly_once },
    );
    try client.disconnect(0);

    var legacy = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v3_1_1,
        .client_id = "reserved-topic-policy-v311",
    });
    defer legacy.close();
    var suback = try legacy.subscribe(
        &.{.{
            .topic_filter = "$SYS/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try legacy.publish(
        "$SYS/broker/uptime",
        "blocked",
        .{ .qos = .at_least_once },
    );
    try expectNoClientPacket(&legacy, .fromMilliseconds(20));
    try legacy.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker reserved client topic protection can be disabled" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .protect_reserved_topics = false,
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "reserved-topic-opt-out",
    });
    defer client.close();
    try client.publish(
        "$SYS/application-owned",
        "allowed",
        .{ .qos = .exactly_once, .retain = true },
    );
    try client.publish(
        "$share/application-owned",
        "allowed",
        .{ .qos = .exactly_once, .retain = true },
    );
    try client.disconnect(0);

    var will_source = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "reserved-will-opt-out",
        .will = .{
            .topic = "$SYS/application-will",
            .payload = "allowed-will",
            .qos = .at_least_once,
            .retain = true,
        },
    });
    try will_source.shutdown();
    defer will_source.close();
    try joinServer(thread, &joined, &serve);

    try std.testing.expectEqual(@as(usize, 3), broker.retained.count());
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    var storage: [1]mqtt.retained.Match = undefined;
    const matches = try broker.retained.matchInto(
        "$SYS/application-owned",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("allowed", matches[0].payload);
    const will_matches = try broker.retained.matchInto(
        "$SYS/application-will",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), will_matches.len);
    try std.testing.expectEqualStrings(
        "allowed-will",
        will_matches[0].payload,
    );
}

test "mounted listener cannot hide a reserved client publish or Will topic" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 4,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();
    var system_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer system_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "tenant/",
            ),
            .connection_count = 2,
        },
        .{
            .source = system_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init("$SYS/"),
            .connection_count = 2,
        },
    };
    var serve = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&serve},
    );
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "mounted-reserved-topic" },
    );
    defer client.close();
    const packet_id = (try client.writePublish(
        "$SYS/broker/uptime",
        "forged",
        .{ .qos = .exactly_once, .retain = true },
    )).?;
    var event = try client.readClientPacketEvent();
    defer event.deinit(allocator);
    switch (event) {
        .pubrec => |owned| {
            try std.testing.expectEqual(packet_id, owned.ack.packet_id);
            try std.testing.expectEqual(@as(u8, 0x87), owned.ack.reason_code);
            try std.testing.expectError(
                error.PublishRefused,
                client.applyPubRec(owned.ack),
            );
        },
        else => return error.UnexpectedPacket,
    }
    try client.disconnect(0);

    var will_source = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "mounted-reserved-will",
            .will = .{
                .topic = "$SYS/broker/uptime",
                .payload = "forged-will",
                .qos = .at_least_once,
                .retain = true,
            },
        },
    );
    try will_source.shutdown();
    defer will_source.close();

    var mapped_client = try runtime.Client.connect(
        allocator,
        io,
        system_server.address(),
        .{ .protocol = .v5, .client_id = "mapped-reserved-topic" },
    );
    defer mapped_client.close();
    const mapped_packet_id = (try mapped_client.writePublish(
        "application",
        "forged",
        .{ .qos = .exactly_once, .retain = true },
    )).?;
    var mapped_event = try mapped_client.readClientPacketEvent();
    defer mapped_event.deinit(allocator);
    switch (mapped_event) {
        .pubrec => |owned| {
            try std.testing.expectEqual(
                mapped_packet_id,
                owned.ack.packet_id,
            );
            try std.testing.expectEqual(@as(u8, 0x87), owned.ack.reason_code);
            try std.testing.expectError(
                error.PublishRefused,
                mapped_client.applyPubRec(owned.ack),
            );
        },
        else => return error.UnexpectedPacket,
    }
    try mapped_client.disconnect(0);

    var mapped_will = try runtime.Client.connect(
        allocator,
        io,
        system_server.address(),
        .{
            .protocol = .v5,
            .client_id = "mapped-reserved-will",
            .will = .{
                .topic = "application-will",
                .payload = "forged-mapped-will",
                .qos = .at_least_once,
                .retain = true,
            },
        },
    );
    try mapped_will.shutdown();
    defer mapped_will.close();
    thread.join();
    joined = true;
    if (serve.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
}

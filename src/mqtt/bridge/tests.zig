const std = @import("std");
const mqtt = @import("../mod.zig");
const bridge_mod = @import("../bridge.zig");
const broker_mod = @import("../broker.zig");
const runtime = @import("../runtime.zig");

const Rule = bridge_mod.Rule;
const session_expiry_properties = [_]mqtt.Property{.{ .four_byte = .{
    .id = .session_expiry_interval,
    .value = 60,
} }};

const BrokerRunner = struct {
    broker: *broker_mod.Broker,
    accept_concurrency: usize,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = self.accept_concurrency,
        }}, .{
            .shutdown = &self.shutdown,
        }) catch |err| {
            self.err = err;
        };
    }

    fn stop(
        self: *@This(),
        io: std.Io,
        thread: std.Thread,
    ) !void {
        self.shutdown.set(io);
        thread.join();
        if (self.err) |err| return err;
    }
};

fn expectUserProperty(
    properties: []const mqtt.Property,
    key: []const u8,
    value: []const u8,
) !void {
    for (properties) |property| {
        if (property == .utf8_pair and
            property.utf8_pair.id == .user_property and
            std.mem.eql(u8, property.utf8_pair.key, key) and
            std.mem.eql(u8, property.utf8_pair.value, value))
        {
            return;
        }
    }
    return error.TestExpectedEqual;
}

fn expectNoTopicAlias(properties: []const mqtt.Property) !void {
    for (properties) |property| {
        try std.testing.expect(!(property == .two_byte and
            property.two_byte.id == .topic_alias));
    }
}

fn expectSubscriptionIdentifier(
    properties: []const mqtt.Property,
    expected: usize,
) !void {
    var count: usize = 0;
    for (properties) |property| {
        if (property == .varint and
            property.varint.id == .subscription_identifier)
        {
            try std.testing.expectEqual(expected, property.varint.value);
            count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

fn expectNoPublish(
    connection: *runtime.Connection,
    timeout: std.Io.Duration,
) !void {
    try std.testing.expectError(
        error.Timeout,
        connection.readClientPacketEventWithTimeout(timeout),
    );
}

const InjectFailure = struct {
    seen: bool = false,
    packet_id: u16 = 0,

    fn failOnce(context: *anyopaque, remote: *const mqtt.Publish) bool {
        const self: *InjectFailure = @ptrCast(@alignCast(context));
        if (self.seen) return false;
        self.seen = true;
        self.packet_id = remote.packet_id.?;
        return true;
    }
};

test "bridge rule validates bounded inbound mappings" {
    try (Rule{
        .filter = "sensors/+/state",
        .qos = .at_least_once,
        .local_prefix = "upstream/",
    }).validate();
    try (Rule{
        .filter = "#",
        .qos = .at_most_once,
    }).validate();

    try std.testing.expectError(
        error.InvalidSubscription,
        (Rule{ .filter = "sensors/#/bad" }).validate(),
    );
    try std.testing.expectError(
        error.InvalidBridgeQoS,
        (Rule{ .filter = "#", .qos = .exactly_once }).validate(),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        (Rule{ .filter = "#", .local_prefix = "bad/+" }).validate(),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        (Rule{
            .filter = "#",
            .local_prefix = &[_]u8{ 0xff, '/' },
        }).validate(),
    );
}

test "bridge rule maps only matching remote Topic Names" {
    const allocator = std.testing.allocator;
    const rule = Rule{
        .filter = "sensors/+/state",
        .qos = .at_least_once,
        .local_prefix = "remote/site-a/",
    };
    const mapped = try rule.mapTopicAlloc(
        allocator,
        "sensors/room-1/state",
    );
    defer allocator.free(mapped);
    try std.testing.expectEqualStrings(
        "remote/site-a/sensors/room-1/state",
        mapped,
    );
    try std.testing.expectError(
        error.TopicOutsideBridgeRule,
        rule.mapTopicAlloc(allocator, "commands/room-1"),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        rule.mapTopicAlloc(allocator, "sensors/+/state"),
    );

    const system_rule = Rule{
        .filter = "+/#",
        .local_prefix = "remote/",
    };
    try std.testing.expectError(
        error.TopicOutsideBridgeRule,
        system_rule.mapTopicAlloc(allocator, "$SYS/broker/uptime"),
    );
}

test "bridge public configuration retains MQTT types" {
    const options = bridge_mod.Options{
        .connect = .{ .client_id = "bridge-test" },
        .rule = .{
            .filter = "remote/#",
            .qos = .at_least_once,
            .local_prefix = "local/",
        },
    };
    try std.testing.expectEqual(mqtt.QoS.at_least_once, options.rule.qos);
}

test "inbound bridge mirrors retained MQTT 5 QoS 1 publication end to end" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer local.deinit();
    var local_runner = BrokerRunner{
        .broker = &local,
        .accept_concurrency = 1,
    };
    const local_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&local_runner},
    );
    var local_joined = false;
    defer if (!local_joined) {
        local_runner.shutdown.set(io);
        local_thread.join();
    };

    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer remote.deinit();
    var remote_runner = BrokerRunner{
        .broker = &remote,
        .accept_concurrency = 2,
    };
    const remote_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&remote_runner},
    );
    var remote_joined = false;
    defer if (!remote_joined) {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    };

    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "bridge-local-subscriber",
            // Disable locally generated Topic Aliases so the assertion below
            // can prove the remote connection's alias did not cross brokers.
            .topic_alias_maximum = 0,
        },
        operation_timeout,
    );
    defer subscriber.close();
    var local_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "mirror/source/#",
            .qos = .at_least_once,
            .retain_as_published = true,
        }},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 71,
        } }} },
    );
    defer local_suback.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 1), local_suback.suback.reason_codes[0]);

    // Seed the upstream retained store before the bridge subscribes. This
    // requires the bridge's MQTT 5 subscription to request RAP and makes the
    // resulting retained bit observable at the local subscriber.
    var publisher = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "bridge-remote-publisher" },
        operation_timeout,
    );
    defer publisher.close();
    const remote_packet_id = (try publisher.writePublish(
        "source/device/state",
        "online",
        .{
            .qos = .at_least_once,
            .retain = true,
            .properties = &.{
                .{ .utf8_pair = .{
                    .id = .user_property,
                    .key = "origin",
                    .value = "remote",
                } },
                .{ .two_byte = .{
                    .id = .topic_alias,
                    .value = 1,
                } },
            },
        },
    )).?;
    var publisher_event = try publisher.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer publisher_event.deinit(allocator);
    switch (publisher_event) {
        .puback => |ack| {
            try std.testing.expectEqual(remote_packet_id, ack.ack.packet_id);
            try publisher.applyPubAck(ack.ack);
        },
        else => return error.TestUnexpectedResult,
    }
    try publisher.disconnect(0);

    var bridge_shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "inbound-bridge-e2e",
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .rule = .{
                .filter = "source/#",
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
        },
        &bridge_shutdown,
    );
    defer bridge.deinit();

    _ = try bridge.connect();
    try std.testing.expect(try bridge.step(.{
        .timeout = operation_timeout,
        .cancellation_check_interval = .fromMilliseconds(20),
    }));

    // PINGRESP is ordered after the bridge's PUBACK on the remote stream. Its
    // arrival therefore provides a deterministic barrier before inspecting
    // the remote broker's outgoing QoS state.
    try bridge.client.connection().?.pingWithTimeout(operation_timeout);
    try std.testing.expectEqual(
        @as(usize, 0),
        remote.stats().session_inflight_messages,
    );

    var local_event = try subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer local_event.deinit(allocator);
    switch (local_event) {
        .publish => |delivery| {
            try std.testing.expectEqualStrings(
                "mirror/source/device/state",
                delivery.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "online",
                delivery.publish.payload,
            );
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                delivery.publish.qos,
            );
            try std.testing.expect(delivery.publish.retain);
            try expectUserProperty(
                delivery.publish.properties,
                "origin",
                "remote",
            );
            try expectNoTopicAlias(delivery.publish.properties);
            try expectSubscriptionIdentifier(
                delivery.publish.properties,
                71,
            );
            try subscriber.writePubAck(delivery.publish.packet_id.?, 0);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), local.stats().retained_messages);

    try bridge.client.disconnect(0);
    try subscriber.disconnect(0);
    try remote_runner.stop(io, remote_thread);
    remote_joined = true;
    try local_runner.stop(io, local_thread);
    local_joined = true;
}

test "inbound bridge withholds upstream PUBACK until local injection succeeds" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);
    const short_timeout = std.Io.Duration.fromMilliseconds(150);

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer local.deinit();
    var local_runner = BrokerRunner{
        .broker = &local,
        .accept_concurrency = 1,
    };
    const local_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&local_runner},
    );
    var local_joined = false;
    defer if (!local_joined) {
        local_runner.shutdown.set(io);
        local_thread.join();
    };

    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer remote.deinit();
    var remote_runner = BrokerRunner{
        .broker = &remote,
        .accept_concurrency = 2,
    };
    const remote_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&remote_runner},
    );
    var remote_joined = false;
    defer if (!remote_joined) {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    };

    var bridge_shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "inbound-bridge-retry",
                .clean_start = false,
                .properties = &session_expiry_properties,
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(8),
            },
            .rule = .{
                .filter = "retry/#",
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
        },
        &bridge_shutdown,
    );
    defer bridge.deinit();

    const connected = try bridge.connect();
    try std.testing.expect(!connected.session_present);

    var upstream_publisher = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        remote.address(),
        .{
            .protocol = .v5,
            .client_id = "bridge-upstream-retry-publisher",
            .clean_start = false,
            .properties = &session_expiry_properties,
        },
        operation_timeout,
    );
    defer upstream_publisher.close();
    const upstream_packet_id = (try upstream_publisher.writePublish(
        "retry/device/state",
        "retry-once",
        .{
            .qos = .at_least_once,
            .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "attempt",
                .value = "first",
            } }},
        },
    )).?;
    var upstream_ack = try upstream_publisher.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer upstream_ack.deinit(allocator);
    switch (upstream_ack) {
        .puback => |ack| {
            try std.testing.expectEqual(upstream_packet_id, ack.ack.packet_id);
            try upstream_publisher.applyPubAck(ack.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    var first_delivery = (try bridge.client.pollWithTimeout(operation_timeout)).?;
    defer first_delivery.deinit(allocator);
    try std.testing.expect(first_delivery == .publish);
    try std.testing.expect(!first_delivery.publish.publish.dup);
    var inject_failure = InjectFailure{};
    try std.testing.expectError(
        error.TestExpectedError,
        bridge_mod.testing.injectPublishWithFault(
            &bridge,
            &first_delivery.publish.publish,
            .{
                .context = &inject_failure,
                .fail_once = InjectFailure.failOnce,
            },
        ),
    );
    try std.testing.expect(inject_failure.seen);
    try std.testing.expectEqual(
        first_delivery.publish.publish.packet_id.?,
        inject_failure.packet_id,
    );
    try std.testing.expectEqual(@as(usize, 0), local.stats().publish_messages_received);
    try std.testing.expectEqual(
        @as(usize, 1),
        remote.stats().session_inflight_messages,
    );

    bridge.client.disconnectTransport();
    const reconnected = try bridge.client.connectWithTimeout(operation_timeout);
    try std.testing.expect(reconnected.session_present);

    var redelivery = (try bridge.client.pollWithTimeout(operation_timeout)).?;
    defer redelivery.deinit(allocator);
    try std.testing.expect(redelivery == .publish);
    try std.testing.expect(redelivery.publish.publish.dup);
    try std.testing.expectEqual(
        inject_failure.packet_id,
        redelivery.publish.publish.packet_id.?,
    );
    try std.testing.expectEqualStrings(
        "retry/device/state",
        redelivery.publish.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "retry-once",
        redelivery.publish.publish.payload,
    );

    var local_subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "bridge-local-retry-subscriber",
            .clean_start = false,
            .properties = &session_expiry_properties,
        },
        operation_timeout,
    );
    defer local_subscriber.close();
    var local_suback = try local_subscriber.subscribe(
        &.{.{
            .topic_filter = "mirror/retry/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer local_suback.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 1),
        local_suback.suback.reason_codes[0],
    );
    try expectNoPublish(&local_subscriber, short_timeout);

    try bridge_mod.testing.injectPublish(
        &bridge,
        &redelivery.publish.publish,
    );

    var local_event = try local_subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer local_event.deinit(allocator);
    switch (local_event) {
        .publish => |delivery| {
            try std.testing.expectEqualStrings(
                "mirror/retry/device/state",
                delivery.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "retry-once",
                delivery.publish.payload,
            );
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                delivery.publish.qos,
            );
            try std.testing.expect(!delivery.publish.dup);
            try expectUserProperty(
                delivery.publish.properties,
                "attempt",
                "first",
            );
            try local_subscriber.writePubAck(
                delivery.publish.packet_id.?,
                0,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    try expectNoPublish(&local_subscriber, short_timeout);
    try std.testing.expectEqual(@as(usize, 1), local.stats().publish_messages_received);

    // A PINGREQ/PINGRESP round trip provides a deterministic barrier after the
    // bridge's upstream PUBACK and local flush sequence.
    try bridge.client.connection().?.pingWithTimeout(operation_timeout);
    try std.testing.expectEqual(
        @as(usize, 0),
        remote.stats().session_inflight_messages,
    );

    try bridge.client.disconnect(0);
    try local_subscriber.disconnect(0);
    try upstream_publisher.disconnect(0);
    try remote_runner.stop(io, remote_thread);
    remote_joined = true;
    try local_runner.stop(io, local_thread);
    local_joined = true;
}

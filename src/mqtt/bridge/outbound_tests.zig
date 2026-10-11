const std = @import("std");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");
const outbound = @import("outbound.zig");
const runtime = @import("../runtime.zig");

const session_expiry = [_]mqtt.Property{.{ .four_byte = .{
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

    fn stop(self: *@This(), io: std.Io, thread: std.Thread) !void {
        self.shutdown.set(io);
        thread.join();
        if (self.err) |err| return err;
    }
};

fn expectForwardProperties(
    expect_user_property: bool,
    properties: []const mqtt.Property,
) !void {
    var user_properties: usize = 0;
    for (properties) |property| switch (property) {
        .two_byte => |value| try std.testing.expect(
            value.id != .topic_alias,
        ),
        .varint => |value| try std.testing.expect(
            value.id != .subscription_identifier,
        ),
        .utf8_pair => |value| {
            if (value.id == .user_property and
                std.mem.eql(u8, value.key, "bridge") and
                std.mem.eql(u8, value.value, "outbound"))
            {
                user_properties += 1;
            }
        },
        else => {},
    };
    try std.testing.expectEqual(
        @as(usize, @intFromBool(expect_user_property)),
        user_properties,
    );
}

fn runQoS1ReconnectCase(
    source_protocol: mqtt.ProtocolVersion,
    target_protocol: mqtt.ProtocolVersion,
    target_session_present: bool,
    expire_before_reconnect: bool,
    source_reconnects_while_pending: bool,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer source_server.deinit();
    var target_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer target_server.deinit();

    const SourcePeer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        expire_before_reconnect: bool,
        reconnect_while_pending: bool,
        acked: *std.Io.Event,
        reconnected: *std.Io.Event,
        ping_count: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const properties = [_]mqtt.Property{
                .{ .two_byte = .{ .id = .topic_alias, .value = 7 } },
                .{ .varint = .{
                    .id = .subscription_identifier,
                    .value = 13,
                } },
                .{ .utf8_pair = .{
                    .id = .user_property,
                    .key = "bridge",
                    .value = "outbound",
                } },
                .{ .four_byte = .{
                    .id = .message_expiry_interval,
                    .value = 1,
                } },
            };
            const publish_properties = if (self.protocol == .v5)
                properties[0..if (self.expire_before_reconnect) 4 else 3]
            else
                &.{};
            var packet_id: u16 = undefined;
            {
                var accepted = try self.server.accept(.{
                    .protocol = self.protocol,
                });
                defer accepted.deinit(self.server.allocator);
                var subscribe = try accepted.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "local/sensors/+",
                    subscribe.subscribe.subscriptions[0].topic_filter,
                );
                try accepted.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x01},
                    &.{},
                );
                packet_id = (try accepted.connection.writePublish(
                    "local/sensors/room",
                    "temperature",
                    .{
                        .qos = .at_least_once,
                        .retain = true,
                        .properties = publish_properties,
                    },
                )).?;
                if (!self.reconnect_while_pending) {
                    try self.waitForAcknowledgement(&accepted, packet_id);
                    return;
                }
                try accepted.connection.shutdown();
            }

            var resumed = try self.server.accept(.{
                .protocol = self.protocol,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            const retry_packet_id = (try resumed.connection.writePublish(
                "local/sensors/room",
                "temperature",
                .{
                    .qos = .at_least_once,
                    .retain = true,
                    .dup = true,
                    .properties = publish_properties,
                },
            )).?;
            try std.testing.expectEqual(packet_id, retry_packet_id);
            self.reconnected.set(self.server.io);
            try self.waitForAcknowledgement(&resumed, packet_id);
        }

        fn waitForAcknowledgement(
            self: *@This(),
            accepted: *runtime.AcceptedClient,
            packet_id: u16,
        ) !void {
            while (true) {
                var event = try accepted.connection.readBrokerEvent();
                defer event.deinit(self.server.allocator);
                switch (event) {
                    .pingreq => {
                        self.ping_count += 1;
                        try accepted.connection.writePingResp();
                    },
                    .puback => |puback| {
                        try std.testing.expectEqual(
                            packet_id,
                            puback.ack.packet_id,
                        );
                        break;
                    },
                    else => return error.UnexpectedPacket,
                }
            }
            self.acked.set(self.server.io);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    const TargetPeer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        expect_user_property: bool,
        session_present: bool,
        expire_before_reconnect: bool,
        first_received: *std.Io.Event,
        allow_reconnect: *std.Io.Event,
        first_packet_id: u16 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{
                    .protocol = self.protocol,
                    .topic_alias_maximum = 0,
                });
                defer first.deinit(self.server.allocator);
                var publish = try first.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                try std.testing.expect(!publish.publish.dup);
                try std.testing.expect(publish.publish.retain);
                try std.testing.expectEqualStrings(
                    "remote/sensors/room",
                    publish.publish.topic,
                );
                try std.testing.expectEqualStrings(
                    "temperature",
                    publish.publish.payload,
                );
                try expectForwardProperties(
                    self.expect_user_property,
                    publish.publish.properties,
                );
                try std.testing.expectEqual(
                    if (self.expire_before_reconnect) @as(?u32, 1) else null,
                    mqtt.messageExpiryInterval(publish.publish.properties),
                );
                self.first_packet_id = publish.publish.packet_id.?;
                self.first_received.set(self.server.io);
                self.allow_reconnect.waitUncancelable(self.server.io);
                first.connection.shutdown() catch {};
            }
            var second = try self.server.accept(.{
                .protocol = self.protocol,
                .topic_alias_maximum = 0,
                .session_present = self.session_present,
            });
            defer second.deinit(self.server.allocator);
            if (self.expire_before_reconnect) {
                var disconnect = try second.connection.readDisconnect();
                defer disconnect.deinit(self.server.allocator);
                return;
            }
            var retry = try second.connection.readPublish();
            defer retry.deinit(self.server.allocator);
            try std.testing.expectEqual(
                self.session_present,
                retry.publish.dup,
            );
            if (self.session_present) {
                try std.testing.expectEqual(
                    self.first_packet_id,
                    retry.publish.packet_id.?,
                );
            }
            try std.testing.expectEqualStrings(
                "remote/sensors/room",
                retry.publish.topic,
            );
            try expectForwardProperties(
                self.expect_user_property,
                retry.publish.properties,
            );
            try second.connection.writePubAck(retry.publish.packet_id.?, 0);
            var disconnect = try second.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_acked: std.Io.Event = .unset;
    var source_reconnected: std.Io.Event = .unset;
    var target_first_received: std.Io.Event = .unset;
    var allow_target_reconnect: std.Io.Event = .unset;
    var source_peer = SourcePeer{
        .server = &source_server,
        .protocol = source_protocol,
        .expire_before_reconnect = expire_before_reconnect,
        .reconnect_while_pending = source_reconnects_while_pending,
        .acked = &source_acked,
        .reconnected = &source_reconnected,
    };
    var target_peer = TargetPeer{
        .server = &target_server,
        .protocol = target_protocol,
        .expect_user_property = source_protocol == .v5 and target_protocol == .v5,
        .session_present = target_session_present,
        .expire_before_reconnect = expire_before_reconnect,
        .first_received = &target_first_received,
        .allow_reconnect = &allow_target_reconnect,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        SourcePeer.run,
        .{&source_peer},
    );
    var source_joined = false;
    defer {
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(
        .{},
        TargetPeer.run,
        .{&target_peer},
    );
    var target_joined = false;
    defer {
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source_server.address(),
        target_server.address(),
        .{
            .source_connect = .{
                .protocol = source_protocol,
                .client_id = "outbound-source",
                .clean_start = false,
                .keep_alive_seconds = if (expire_before_reconnect) 1 else 30,
                .properties = if (source_protocol == .v5)
                    &session_expiry
                else
                    &.{},
            },
            .target_connect = .{
                .protocol = target_protocol,
                .client_id = "outbound-target",
                .clean_start = false,
                .properties = if (target_protocol == .v5)
                    &session_expiry
                else
                    &.{},
            },
            .source_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(8),
            },
            .target_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(8),
            },
            .rule = .{
                .filter = "sensors/+",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
        },
        &shutdown,
    );
    defer bridge.deinit();

    const connected = try bridge.connect();
    try std.testing.expect(!connected.source_session_present);
    try std.testing.expect(!connected.target_session_present);
    const Step = struct {
        bridge: *outbound.Bridge,
        result: ?anyerror = null,

        fn run(self: *@This()) void {
            const handled = self.bridge.step(.{
                .timeout = .fromSeconds(2),
                .cancellation_check_interval = .fromMilliseconds(5),
            }) catch |err| {
                self.result = err;
                return;
            };
            if (!handled) self.result = error.TestUnexpectedResult;
        }
    };
    var step = Step{ .bridge = &bridge };
    const step_thread = try std.Thread.spawn(.{}, Step.run, .{&step});
    var step_joined = false;
    defer {
        allow_target_reconnect.set(io);
        if (!step_joined) step_thread.join();
    }
    try target_first_received.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    try std.testing.expect(!source_acked.isSet());
    if (source_reconnects_while_pending) {
        try source_reconnected.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        } });
        try std.testing.expect(!source_acked.isSet());
    }
    if (expire_before_reconnect) {
        try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
        try std.testing.expect(!source_acked.isSet());
    }
    allow_target_reconnect.set(io);
    step_thread.join();
    step_joined = true;
    if (step.result) |err| return err;
    try source_acked.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    try bridge.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
    try std.testing.expect(source_acked.isSet());
    if (expire_before_reconnect) {
        try std.testing.expect(source_peer.ping_count >= 1);
    }
}

test "outbound bridge resumes target QoS1 before acknowledging source" {
    try runQoS1ReconnectCase(.v3_1_1, .v3_1_1, true, false, false);
    try runQoS1ReconnectCase(.v5, .v5, true, false, false);
}

test "outbound bridge republishes QoS1 when target Session is lost" {
    try runQoS1ReconnectCase(.v3_1_1, .v3_1_1, false, false, false);
    try runQoS1ReconnectCase(.v5, .v5, false, false, false);
}

test "outbound bridge does not extend expiry across target reconnect" {
    try runQoS1ReconnectCase(.v5, .v5, true, true, false);
    try runQoS1ReconnectCase(.v5, .v5, false, true, false);
}

test "outbound bridge crosses MQTT protocol versions" {
    try runQoS1ReconnectCase(.v3_1_1, .v5, true, false, false);
    try runQoS1ReconnectCase(.v5, .v3_1_1, true, false, false);
}

test "outbound bridge reconnects source while target QoS1 is pending" {
    try runQoS1ReconnectCase(.v5, .v5, true, false, true);
}

test "outbound bridge routes between two brokers" {
    const allocator = std.testing.allocator;
    const timeout = std.Io.Duration.fromSeconds(2);
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var source = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_connections = 2 } },
    );
    defer source.deinit();
    var source_runner = BrokerRunner{
        .broker = &source,
        .accept_concurrency = 2,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&source_runner},
    );
    var source_joined = false;
    defer if (!source_joined) {
        source_runner.shutdown.set(io);
        source_thread.join();
    };

    var target = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_connections = 2 } },
    );
    defer target.deinit();
    var target_runner = BrokerRunner{
        .broker = &target,
        .accept_concurrency = 2,
    };
    const target_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&target_runner},
    );
    var target_joined = false;
    defer if (!target_joined) {
        target_runner.shutdown.set(io);
        target_thread.join();
    };

    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        target.address(),
        .{ .protocol = .v5, .client_id = "outbound-subscriber", .topic_alias_maximum = 0 },
        timeout,
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{
        .topic_filter = "remote/plant/#",
        .qos = .at_least_once,
        .retain_as_published = true,
    }}, .{});
    defer suback.deinit(allocator);

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "outbound-broker-source",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "outbound-broker-target",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .rule = .{
                .filter = "plant/#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();

    var publisher = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        source.address(),
        .{ .protocol = .v5, .client_id = "outbound-publisher" },
        timeout,
    );
    defer publisher.close();
    const properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 9 } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "bridge",
            .value = "outbound",
        } },
    };
    const packet_id = (try publisher.writePublish(
        "local/plant/temperature",
        "21.5",
        .{
            .qos = .at_least_once,
            .retain = true,
            .properties = &properties,
        },
    )).?;
    try std.testing.expect(try bridge.step(.{
        .timeout = timeout,
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    var publisher_ack = try publisher.readPubAck();
    defer publisher_ack.deinit(allocator);
    try std.testing.expectEqual(packet_id, publisher_ack.ack.packet_id);

    var delivery = try subscriber.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "remote/plant/temperature",
        delivery.publish.topic,
    );
    try std.testing.expectEqualStrings("21.5", delivery.publish.payload);
    try std.testing.expect(delivery.publish.retain);
    try expectForwardProperties(true, delivery.publish.properties);
    try subscriber.writePubAck(delivery.publish.packet_id.?, 0);
    try std.testing.expectEqual(@as(usize, 1), target.stats().retained_messages);

    try bridge.disconnect(0);
    try publisher.disconnect(0);
    try subscriber.disconnect(0);
    try source_runner.stop(io, source_thread);
    source_joined = true;
    try target_runner.stop(io, target_thread);
    target_joined = true;
}

test "outbound bridge forwards QoS0 without inventing acknowledgements" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 64 },
    );
    defer target.deinit();

    const SourcePeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x00},
                &.{},
            );
            try accepted.connection.publish(
                "local/fire/oversize",
                "x" ** 80,
                .{},
            );
            try accepted.connection.publish(
                "local/fire/forget",
                "qos0",
                .{ .retain = true },
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqual(mqtt.QoS.at_most_once, publish.publish.qos);
            try std.testing.expectEqualStrings(
                "remote/fire/forget",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings("qos0", publish.publish.payload);
            try std.testing.expect(!publish.publish.retain);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_peer = SourcePeer{ .server = &source };
    var target_peer = TargetPeer{ .server = &target };
    const source_thread = try std.Thread.spawn(.{}, SourcePeer.run, .{&source_peer});
    var source_joined = false;
    defer {
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(.{}, TargetPeer.run, .{&target_peer});
    var target_joined = false;
    defer {
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "outbound-qos0-source",
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "outbound-qos0-target",
            },
            .rule = .{
                .filter = "fire/#",
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
            .preserve_retain = false,
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(!try bridge.step(.{
        .timeout = .fromMilliseconds(50),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try bridge.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge advances both idle Keep Alive state machines" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer source.deinit();
    var target = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer target.deinit();

    const Peer = struct {
        server: *runtime.Server,
        source: bool,
        saw_ping: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            if (self.source) {
                var subscribe = try accepted.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try accepted.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x00},
                    &.{},
                );
            }
            while (true) {
                var event = try accepted.connection.readBrokerEvent();
                defer event.deinit(self.server.allocator);
                switch (event) {
                    .pingreq => {
                        try accepted.connection.writePingResp();
                        self.saw_ping.set(self.server.io);
                    },
                    .disconnect => return,
                    else => return error.UnexpectedPacket,
                }
            }
        }
    };
    var source_peer = Peer{ .server = &source, .source = true };
    var target_peer = Peer{ .server = &target, .source = false };
    const source_thread = try std.Thread.spawn(.{}, Peer.run, .{&source_peer});
    var source_joined = false;
    defer {
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(.{}, Peer.run, .{&target_peer});
    var target_joined = false;
    defer {
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "idle-source",
                .keep_alive_seconds = 1,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "idle-target",
                .keep_alive_seconds = 1,
            },
            .rule = .{ .filter = "idle/#" },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(1),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(1),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try source_peer.saw_ping.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    try target_peer.saw_ping.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(1),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(1),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try bridge.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge propagates MQTT5 target rejection to its source Session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer source.deinit();
    var target = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer target.deinit();

    const SourcePeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x01},
                &.{},
            );
            const packet_id = (try accepted.connection.writePublish(
                "reject/source",
                "blocked",
                .{ .qos = .at_least_once },
            )).?;
            var puback = try accepted.connection.readPubAck();
            defer puback.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, puback.ack.packet_id);
            try std.testing.expectEqual(@as(u8, 0x87), puback.ack.reason_code);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0x87,
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_peer = SourcePeer{ .server = &source };
    var target_peer = TargetPeer{ .server = &target };
    const source_thread = try std.Thread.spawn(.{}, SourcePeer.run, .{&source_peer});
    var source_joined = false;
    defer {
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(.{}, TargetPeer.run, .{&target_peer});
    var target_joined = false;
    defer {
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "outbound-reject-source",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "outbound-reject-target",
            },
            .rule = .{
                .filter = "reject/#",
                .qos = .at_least_once,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try bridge.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge durably completes cross-broker QoS2" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();

    var target_pubrel_seen: std.Io.Event = .unset;
    var allow_target_pubcomp: std.Io.Event = .unset;
    const SourcePeer = struct {
        server: *runtime.Server,
        target_pubrel_seen: *std.Io.Event,
        allow_target_pubcomp: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.allow_target_pubcomp.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "local/sensors/+",
                subscribe.subscribe.subscriptions[0].topic_filter,
            );
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x02},
                &.{},
            );
            const source_packet_id = (try accepted.connection.writePublish(
                "local/sensors/room",
                "exactly once",
                .{ .qos = .exactly_once },
            )).?;
            try self.target_pubrel_seen.waitTimeout(
                self.server.io,
                .{ .duration = .{
                    .raw = .fromSeconds(1),
                    .clock = .awake,
                } },
            );
            try std.testing.expectError(
                error.Timeout,
                accepted.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.allow_target_pubcomp.set(self.server.io);
            var pubrec = try accepted.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(source_packet_id, pubrec.ack.packet_id);
            try accepted.connection.writePubRel(source_packet_id, 0);
            var pubcomp = try accepted.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expectEqual(source_packet_id, pubcomp.ack.packet_id);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        target_pubrel_seen: *std.Io.Event,
        allow_target_pubcomp: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.target_pubrel_seen.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.publish.qos);
            try std.testing.expect(!publish.publish.dup);
            try std.testing.expectEqualStrings(
                "remote/sensors/room",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "exactly once",
                publish.publish.payload,
            );
            const target_packet_id = publish.publish.packet_id.?;
            try accepted.connection.writePubRec(target_packet_id, 0);
            var pubrel = try accepted.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expectEqual(target_packet_id, pubrel.ack.packet_id);
            self.target_pubrel_seen.set(self.server.io);
            self.allow_target_pubcomp.waitUncancelable(self.server.io);
            try accepted.connection.writePubComp(target_packet_id, 0);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_peer = SourcePeer{
        .server = &source,
        .target_pubrel_seen = &target_pubrel_seen,
        .allow_target_pubcomp = &allow_target_pubcomp,
    };
    var target_peer = TargetPeer{
        .server = &target,
        .target_pubrel_seen = &target_pubrel_seen,
        .allow_target_pubcomp = &allow_target_pubcomp,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        SourcePeer.run,
        .{&source_peer},
    );
    var source_joined = false;
    defer {
        allow_target_pubcomp.set(io);
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(
        .{},
        TargetPeer.run,
        .{&target_peer},
    );
    var target_joined = false;
    defer {
        allow_target_pubcomp.set(io);
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "outbound-qos2-source",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "outbound-qos2-target",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .rule = .{
                .filter = "sensors/+",
                .qos = .exactly_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
            .coordinator = .{
                .bridge_id = [_]u8{0xa5} ** 16,
                .dir = tmp.dir,
                .sub_path = "outbound-qos2.log",
                .mode = .create,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(!bridge.hasPendingDurableQoS2());
    try bridge.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge restores QoS2 staged before either wire boundary" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();

    var staged: std.Io.Event = .unset;
    var source_first_closed: std.Io.Event = .unset;
    var target_first_closed: std.Io.Event = .unset;
    const SourcePeer = struct {
        server: *runtime.Server,
        staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            const packet_id: u16 = 1;
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var subscribe = try first.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try first.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x02},
                    &.{},
                );
                try std.testing.expectEqual(
                    packet_id,
                    (try first.connection.writePublish(
                        "local/restart/value",
                        "persisted before wire",
                        .{ .qos = .exactly_once },
                    )).?,
                );
                self.staged.waitUncancelable(self.server.io);
                try std.testing.expectError(
                    error.Timeout,
                    first.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            try std.testing.expectEqual(
                packet_id,
                (try resumed.connection.writePublish(
                    "local/restart/value",
                    "persisted before wire",
                    .{ .qos = .exactly_once, .dup = true },
                )).?,
            );
            var pubrec = try resumed.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            try resumed.connection.writePubRel(packet_id, 0);
            var pubcomp = try resumed.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                self.staged.waitUncancelable(self.server.io);
                try std.testing.expectError(
                    error.Timeout,
                    first.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            var publish = try resumed.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expect(publish.publish.dup);
            try std.testing.expectEqualStrings(
                "remote/restart/value",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "persisted before wire",
                publish.publish.payload,
            );
            const packet_id = publish.publish.packet_id.?;
            try resumed.connection.writePubRec(packet_id, 0);
            var pubrel = try resumed.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try resumed.connection.writePubComp(packet_id, 0);
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_peer = SourcePeer{
        .server = &source,
        .staged = &staged,
        .first_closed = &source_first_closed,
    };
    var target_peer = TargetPeer{
        .server = &target,
        .staged = &staged,
        .first_closed = &target_first_closed,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        SourcePeer.run,
        .{&source_peer},
    );
    var source_joined = false;
    defer {
        staged.set(io);
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(
        .{},
        TargetPeer.run,
        .{&target_peer},
    );
    var target_joined = false;
    defer {
        staged.set(io);
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    const common = outbound.Options{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "outbound-restore-source",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "outbound-restore-target",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .rule = .{
            .filter = "restart/#",
            .qos = .exactly_once,
            .local_prefix = "local/",
            .remote_prefix = "remote/",
        },
        .coordinator = .{
            .bridge_id = [_]u8{0x5a} ** 16,
            .dir = tmp.dir,
            .sub_path = "outbound-restore.log",
            .mode = .create,
        },
    };
    {
        var first = try outbound.Bridge.init(
            allocator,
            io,
            source.address(),
            target.address(),
            common,
            &shutdown,
        );
        _ = try first.connect();
        try outbound.testing.stageNextDurableQoS2(&first, .{
            .timeout = .fromSeconds(1),
        });
        try std.testing.expect(first.hasPendingDurableQoS2());
        staged.set(io);
        try source_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        try target_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first.deinit();
    }

    var restored_options = common;
    restored_options.coordinator.?.mode = .restore;
    var restored = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        restored_options,
        &shutdown,
    );
    defer restored.deinit();
    const connected = try restored.connect();
    try std.testing.expect(connected.source_session_present);
    try std.testing.expect(connected.target_session_present);
    try std.testing.expect(try restored.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(!restored.hasPendingDurableQoS2());
    try restored.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge restores target QoS2 at durable PUBREL boundary" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();

    var target_pubrec_sent: std.Io.Event = .unset;
    var staged_pubrel: std.Io.Event = .unset;
    var source_first_closed: std.Io.Event = .unset;
    var target_first_closed: std.Io.Event = .unset;
    const SourcePeer = struct {
        server: *runtime.Server,
        staged_pubrel: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            const packet_id: u16 = 1;
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var subscribe = try first.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try first.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x02},
                    &.{},
                );
                try std.testing.expectEqual(
                    packet_id,
                    (try first.connection.writePublish(
                        "local/pubrel/value",
                        "resume pubrel",
                        .{ .qos = .exactly_once },
                    )).?,
                );
                self.staged_pubrel.waitUncancelable(self.server.io);
                try std.testing.expectError(
                    error.Timeout,
                    first.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            var pubrec = try resumed.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            try resumed.connection.writePubRel(packet_id, 0);
            var pubcomp = try resumed.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        pubrec_sent: *std.Io.Event,
        staged_pubrel: *std.Io.Event,
        first_closed: *std.Io.Event,
        packet_id: u16 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.pubrec_sent.set(self.server.io);
                self.first_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var publish = try first.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                self.packet_id = publish.publish.packet_id.?;
                try first.connection.writePubRec(self.packet_id, 0);
                self.pubrec_sent.set(self.server.io);
                self.staged_pubrel.waitUncancelable(self.server.io);
                try std.testing.expectError(
                    error.Timeout,
                    first.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            try resumed.connection.resumeIncomingQoS2(self.packet_id);
            var pubrel = try resumed.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expectEqual(self.packet_id, pubrel.ack.packet_id);
            try resumed.connection.writePubComp(self.packet_id, 0);
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_peer = SourcePeer{
        .server = &source,
        .staged_pubrel = &staged_pubrel,
        .first_closed = &source_first_closed,
    };
    var target_peer = TargetPeer{
        .server = &target,
        .pubrec_sent = &target_pubrec_sent,
        .staged_pubrel = &staged_pubrel,
        .first_closed = &target_first_closed,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        SourcePeer.run,
        .{&source_peer},
    );
    var source_joined = false;
    defer {
        staged_pubrel.set(io);
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(
        .{},
        TargetPeer.run,
        .{&target_peer},
    );
    var target_joined = false;
    defer {
        staged_pubrel.set(io);
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    const common = outbound.Options{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "outbound-pubrel-source",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "outbound-pubrel-target",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .rule = .{
            .filter = "pubrel/#",
            .qos = .exactly_once,
            .local_prefix = "local/",
            .remote_prefix = "remote/",
        },
        .coordinator = .{
            .bridge_id = [_]u8{0x6b} ** 16,
            .dir = tmp.dir,
            .sub_path = "outbound-pubrel.log",
            .mode = .create,
        },
    };
    {
        var first = try outbound.Bridge.init(
            allocator,
            io,
            source.address(),
            target.address(),
            common,
            &shutdown,
        );
        _ = try first.connect();
        try outbound.testing.stageNextDurableQoS2(&first, .{
            .timeout = .fromSeconds(1),
        });
        try outbound.testing.flushDurableTarget(&first);
        try target_pubrec_sent.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        try outbound.testing.stageTargetPubRec(&first, .{
            .timeout = .fromSeconds(1),
        });
        staged_pubrel.set(io);
        try source_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        try target_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first.deinit();
    }

    var restored_options = common;
    restored_options.coordinator.?.mode = .restore;
    var restored = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        restored_options,
        &shutdown,
    );
    defer restored.deinit();
    const connected = try restored.connect();
    try std.testing.expect(connected.source_session_present);
    try std.testing.expect(connected.target_session_present);
    try std.testing.expect(try restored.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try std.testing.expect(!restored.hasPendingDurableQoS2());
    try restored.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge durably propagates negative QoS2 PUBREC" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();

    const SourcePeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x02},
                &.{},
            );
            const packet_id = (try accepted.connection.writePublish(
                "negative/qos2",
                "rejected",
                .{ .qos = .exactly_once },
            )).?;
            var pubrec = try accepted.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            try std.testing.expectEqual(@as(u8, 0x97), pubrec.ack.reason_code);
            try std.testing.expectError(
                error.Timeout,
                accepted.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            try accepted.connection.writeDisconnectWithProperties(0, &.{});
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try accepted.connection.writePubRec(
                publish.publish.packet_id.?,
                0x97,
            );
            try std.testing.expectError(
                error.Timeout,
                accepted.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            try accepted.connection.writeDisconnectWithProperties(0, &.{});
        }
    };
    var source_peer = SourcePeer{ .server = &source };
    var target_peer = TargetPeer{ .server = &target };
    const source_thread = try std.Thread.spawn(
        .{},
        SourcePeer.run,
        .{&source_peer},
    );
    var source_joined = false;
    defer if (!source_joined) source_thread.join();
    const target_thread = try std.Thread.spawn(
        .{},
        TargetPeer.run,
        .{&target_peer},
    );
    var target_joined = false;
    defer if (!target_joined) target_thread.join();

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "outbound-negative-source",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "outbound-negative-target",
                .clean_start = false,
                .properties = &session_expiry,
            },
            .rule = .{
                .filter = "negative/#",
                .qos = .exactly_once,
            },
            .coordinator = .{
                .bridge_id = [_]u8{0x97} ** 16,
                .dir = tmp.dir,
                .sub_path = "outbound-negative.log",
                .mode = .create,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    try outbound.testing.stageNextDurableQoS2(&bridge, .{
        .timeout = .fromSeconds(1),
    });
    try outbound.testing.flushDurableTarget(&bridge);
    try outbound.testing.completeDurableTarget(&bridge, .{
        .timeout = .fromSeconds(1),
    });
    try std.testing.expect(!bridge.hasPendingDurableQoS2());

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge fails closed when source Session is lost" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();
    var staged: std.Io.Event = .unset;
    var source_first_closed: std.Io.Event = .unset;
    var target_first_closed: std.Io.Event = .unset;
    const SourcePeer = struct {
        server: *runtime.Server,
        staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }
        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var subscribe = try first.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try first.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x02},
                    &.{},
                );
                _ = try first.connection.writePublish(
                    "local/lost/source",
                    "orphan forbidden",
                    .{ .qos = .exactly_once },
                );
                self.staged.waitUncancelable(self.server.io);
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);
            var fresh = try self.server.accept(.{
                .protocol = .v5,
                .session_present = false,
            });
            defer fresh.deinit(self.server.allocator);
            var subscribe = try fresh.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try fresh.connection.writeSubAck(subscribe.subscribe.packet_id, &.{0x02}, &.{});
            fresh.connection.shutdown() catch {};
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }
        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            self.staged.waitUncancelable(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                first.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            first.connection.shutdown() catch {};
            self.first_closed.set(self.server.io);
        }
    };
    var source_peer = SourcePeer{
        .server = &source,
        .staged = &staged,
        .first_closed = &source_first_closed,
    };
    var target_peer = TargetPeer{
        .server = &target,
        .staged = &staged,
        .first_closed = &target_first_closed,
    };
    const source_thread = try std.Thread.spawn(.{}, SourcePeer.run, .{&source_peer});
    var source_joined = false;
    defer {
        staged.set(io);
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(.{}, TargetPeer.run, .{&target_peer});
    var target_joined = false;
    defer {
        staged.set(io);
        if (!target_joined) target_thread.join();
    }
    var shutdown: std.Io.Event = .unset;
    const common = outbound.Options{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "lost-source",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "lost-source-target",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .rule = .{
            .filter = "lost/#",
            .qos = .exactly_once,
            .local_prefix = "local/",
        },
        .coordinator = .{
            .bridge_id = [_]u8{0x41} ** 16,
            .dir = tmp.dir,
            .sub_path = "lost-source.log",
            .mode = .create,
        },
    };
    {
        var first = try outbound.Bridge.init(
            allocator,
            io,
            source.address(),
            target.address(),
            common,
            &shutdown,
        );
        _ = try first.connect();
        try outbound.testing.stageNextDurableQoS2(&first, .{
            .timeout = .fromSeconds(1),
        });
        staged.set(io);
        try source_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        try target_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first.deinit();
    }
    var restored_options = common;
    restored_options.coordinator.?.mode = .restore;
    var restored = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        restored_options,
        &shutdown,
    );
    defer restored.deinit();
    try std.testing.expectError(error.SourceSessionLost, restored.connect());

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge fails closed when target Session is lost" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();
    var staged: std.Io.Event = .unset;
    var source_first_closed: std.Io.Event = .unset;
    var target_first_closed: std.Io.Event = .unset;
    const SourcePeer = struct {
        server: *runtime.Server,
        staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }
        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var subscribe = try first.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try first.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x02},
                    &.{},
                );
                _ = try first.connection.writePublish(
                    "local/lost/target",
                    "must not replay",
                    .{ .qos = .exactly_once },
                );
                self.staged.waitUncancelable(self.server.io);
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);
            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            resumed.connection.shutdown() catch {};
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }
        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                self.staged.waitUncancelable(self.server.io);
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);
            var fresh = try self.server.accept(.{
                .protocol = .v5,
                .session_present = false,
            });
            defer fresh.deinit(self.server.allocator);
            try std.testing.expectError(
                error.Timeout,
                fresh.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            fresh.connection.shutdown() catch {};
        }
    };
    var source_peer = SourcePeer{
        .server = &source,
        .staged = &staged,
        .first_closed = &source_first_closed,
    };
    var target_peer = TargetPeer{
        .server = &target,
        .staged = &staged,
        .first_closed = &target_first_closed,
    };
    const source_thread = try std.Thread.spawn(.{}, SourcePeer.run, .{&source_peer});
    var source_joined = false;
    defer {
        staged.set(io);
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(.{}, TargetPeer.run, .{&target_peer});
    var target_joined = false;
    defer {
        staged.set(io);
        if (!target_joined) target_thread.join();
    }
    var shutdown: std.Io.Event = .unset;
    const common = outbound.Options{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "lost-target-source",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "lost-target",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .rule = .{
            .filter = "lost/#",
            .qos = .exactly_once,
            .local_prefix = "local/",
        },
        .coordinator = .{
            .bridge_id = [_]u8{0x42} ** 16,
            .dir = tmp.dir,
            .sub_path = "lost-target.log",
            .mode = .create,
        },
    };
    {
        var first = try outbound.Bridge.init(
            allocator,
            io,
            source.address(),
            target.address(),
            common,
            &shutdown,
        );
        _ = try first.connect();
        try outbound.testing.stageNextDurableQoS2(&first, .{
            .timeout = .fromSeconds(1),
        });
        staged.set(io);
        try source_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        try target_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first.deinit();
    }
    var restored_options = common;
    restored_options.coordinator.?.mode = .restore;
    var restored = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        restored_options,
        &shutdown,
    );
    defer restored.deinit();
    try std.testing.expectError(error.TargetSessionLost, restored.connect());

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge restores after durable source completion before PUBCOMP" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer source.deinit();
    var target = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer target.deinit();

    var completion_staged: std.Io.Event = .unset;
    var source_first_closed: std.Io.Event = .unset;
    var target_first_closed: std.Io.Event = .unset;
    const SourcePeer = struct {
        server: *runtime.Server,
        completion_staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            const packet_id: u16 = 1;
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var subscribe = try first.connection.readSubscribe();
                defer subscribe.deinit(self.server.allocator);
                try first.connection.writeSubAck(
                    subscribe.subscribe.packet_id,
                    &.{0x02},
                    &.{},
                );
                try std.testing.expectEqual(
                    packet_id,
                    (try first.connection.writePublish(
                        "local/source-complete/value",
                        "clear before pubcomp",
                        .{ .qos = .exactly_once },
                    )).?,
                );
                var pubrec = try first.connection.readPubRec();
                defer pubrec.deinit(self.server.allocator);
                try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
                try first.connection.writePubRel(packet_id, 0);
                self.completion_staged.waitUncancelable(self.server.io);
                try std.testing.expectError(
                    error.Timeout,
                    first.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            try resumed.connection.writePubRel(packet_id, 0);
            var pubcomp = try resumed.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    const TargetPeer = struct {
        server: *runtime.Server,
        completion_staged: *std.Io.Event,
        first_closed: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                var publish = try first.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                try std.testing.expectEqual(
                    mqtt.QoS.exactly_once,
                    publish.publish.qos,
                );
                try std.testing.expectEqualStrings(
                    "remote/source-complete/value",
                    publish.publish.topic,
                );
                const packet_id = publish.publish.packet_id.?;
                try first.connection.writePubRec(packet_id, 0);
                var pubrel = try first.connection.readPubRel();
                defer pubrel.deinit(self.server.allocator);
                try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
                try first.connection.writePubComp(packet_id, 0);
                self.completion_staged.waitUncancelable(self.server.io);
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            var resumed = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer resumed.deinit(self.server.allocator);
            var disconnect = try resumed.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };

    var source_peer = SourcePeer{
        .server = &source,
        .completion_staged = &completion_staged,
        .first_closed = &source_first_closed,
    };
    var target_peer = TargetPeer{
        .server = &target,
        .completion_staged = &completion_staged,
        .first_closed = &target_first_closed,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        SourcePeer.run,
        .{&source_peer},
    );
    var source_joined = false;
    defer {
        completion_staged.set(io);
        if (!source_joined) source_thread.join();
    }
    const target_thread = try std.Thread.spawn(
        .{},
        TargetPeer.run,
        .{&target_peer},
    );
    var target_joined = false;
    defer {
        completion_staged.set(io);
        if (!target_joined) target_thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    const common = outbound.Options{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "outbound-source-complete-source",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "outbound-source-complete-target",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .rule = .{
            .filter = "source-complete/#",
            .qos = .exactly_once,
            .local_prefix = "local/",
            .remote_prefix = "remote/",
        },
        .coordinator = .{
            .bridge_id = [_]u8{0x3c} ** 16,
            .dir = tmp.dir,
            .sub_path = "outbound-source-complete.log",
            .mode = .create,
        },
    };
    {
        var first = try outbound.Bridge.init(
            allocator,
            io,
            source.address(),
            target.address(),
            common,
            &shutdown,
        );
        _ = try first.connect();
        try outbound.testing.stageNextDurableQoS2(&first, .{
            .timeout = .fromSeconds(1),
        });
        try outbound.testing.flushDurableTarget(&first);
        try outbound.testing.completeDurableTarget(&first, .{
            .timeout = .fromSeconds(1),
        });
        try outbound.testing.completeDurableTarget(&first, .{
            .timeout = .fromSeconds(1),
        });
        try outbound.testing.stageDurableSourcePubRel(&first, .{
            .timeout = .fromSeconds(1),
        });
        try std.testing.expect(!first.hasPendingDurableQoS2());
        completion_staged.set(io);
        try source_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        try target_first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first.deinit();
    }

    var restored_options = common;
    restored_options.coordinator.?.mode = .restore;
    var restored = try outbound.Bridge.init(
        allocator,
        io,
        source.address(),
        target.address(),
        restored_options,
        &shutdown,
    );
    defer restored.deinit();
    const connected = try restored.connect();
    try std.testing.expect(connected.source_session_present);
    try std.testing.expect(connected.target_session_present);
    _ = try restored.step(.{ .timeout = .fromSeconds(1) });
    try std.testing.expect(!restored.hasPendingDurableQoS2());
    try restored.disconnect(0);

    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}

test "outbound bridge rejects QoS2 without a durable coordinator" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var shutdown: std.Io.Event = .unset;
    const unused = std.Io.net.IpAddress{ .ip4 = .loopback(1) };
    try std.testing.expectError(
        error.QoS2RequiresDurableCoordinator,
        outbound.Bridge.init(
            allocator,
            threaded.io(),
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "unsafe-source",
                    .clean_start = false,
                    .properties = &session_expiry,
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "unsafe-target",
                    .clean_start = false,
                    .properties = &session_expiry,
                },
                .rule = .{
                    .filter = "unsafe/#",
                    .qos = .exactly_once,
                },
            },
            &shutdown,
        ),
    );
}

test "outbound bridge validates persistence and rule intersections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    const unused = std.Io.net.IpAddress{ .ip4 = .loopback(1) };
    const mapped_rule = outbound.Rule{
        .filter = "$share/workers/sensors/+",
        .local_prefix = "local/",
        .remote_prefix = "remote/",
    };
    const source_filter = try mapped_rule.sourceFilterAlloc(allocator);
    defer allocator.free(source_filter);
    try std.testing.expectEqualStrings(
        "$share/workers/local/sensors/+",
        source_filter,
    );
    const target_topic = try mapped_rule.mapTopicAlloc(
        allocator,
        "local/sensors/room",
    );
    defer allocator.free(target_topic);
    try std.testing.expectEqualStrings(
        "remote/sensors/room",
        target_topic,
    );
    const parent_rule = outbound.Rule{
        .filter = "#",
        .local_prefix = "local/",
        .remote_prefix = "remote/",
    };
    const parent_topic = try parent_rule.mapTopicAlloc(allocator, "local");
    defer allocator.free(parent_topic);
    try std.testing.expectEqualStrings("remote/", parent_topic);
    const system_topic = try parent_rule.mapTopicAlloc(
        allocator,
        "local/$SYS/status",
    );
    defer allocator.free(system_topic);
    try std.testing.expectEqualStrings(
        "remote/$SYS/status",
        system_topic,
    );
    try std.testing.expectError(
        error.EmptyMappedTopic,
        (outbound.Rule{
            .filter = "#",
            .local_prefix = "local/",
        }).mapTopicAlloc(allocator, "local"),
    );

    try std.testing.expectError(
        error.QoS1RequiresPersistentSourceSession,
        outbound.Bridge.init(
            allocator,
            io,
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "non-persistent-source",
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "unused-target",
                },
                .rule = .{
                    .filter = "source/#",
                    .qos = .at_least_once,
                },
            },
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.QoS2RequiresPersistentSourceSession,
        outbound.Bridge.init(
            allocator,
            io,
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-transient-source",
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-persistent-target",
                    .clean_start = false,
                    .properties = &session_expiry,
                },
                .rule = .{
                    .filter = "qos2/#",
                    .qos = .exactly_once,
                },
                .coordinator = .{
                    .bridge_id = [_]u8{0x31} ** 16,
                    .dir = tmp.dir,
                    .sub_path = "transient-source.log",
                    .mode = .create,
                },
            },
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.QoS2RequiresPersistentTargetSession,
        outbound.Bridge.init(
            allocator,
            io,
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-persistent-source",
                    .clean_start = false,
                    .properties = &session_expiry,
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-transient-target",
                },
                .rule = .{
                    .filter = "qos2/#",
                    .qos = .exactly_once,
                },
                .coordinator = .{
                    .bridge_id = [_]u8{0x32} ** 16,
                    .dir = tmp.dir,
                    .sub_path = "transient-target.log",
                    .mode = .create,
                },
            },
            &shutdown,
        ),
    );

    const identity_options = outbound.Options{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "identity-source",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "identity-target",
            .clean_start = false,
            .properties = &session_expiry,
        },
        .rule = .{
            .filter = "identity/#",
            .qos = .exactly_once,
            .remote_prefix = "remote/",
        },
        .coordinator = .{
            .bridge_id = [_]u8{0x33} ** 16,
            .dir = tmp.dir,
            .sub_path = "identity.log",
            .mode = .create,
        },
    };
    var identity_bridge = try outbound.Bridge.init(
        allocator,
        io,
        unused,
        unused,
        identity_options,
        &shutdown,
    );
    identity_bridge.deinit();
    var mismatched_identity = identity_options;
    mismatched_identity.rule.remote_prefix = "changed/";
    mismatched_identity.coordinator.?.mode = .restore;
    try std.testing.expectError(
        error.CoordinatorIdentityMismatch,
        outbound.Bridge.init(
            allocator,
            io,
            unused,
            unused,
            mismatched_identity,
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.OverlappingBridgeFilters,
        outbound.Bridge.initMany(
            allocator,
            io,
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "overlap-source",
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "overlap-target",
                },
                .rules = &.{
                    .{ .filter = "sensors/+", .local_prefix = "local/" },
                    .{ .filter = "sensors/#", .local_prefix = "local/" },
                },
            },
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.DuplicateBridgeFilter,
        outbound.Bridge.initMany(
            allocator,
            io,
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "duplicate-source",
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "duplicate-target",
                },
                .rules = &.{
                    .{ .filter = "same/#" },
                    .{ .filter = "same/#" },
                },
            },
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.NoBridgeRules,
        outbound.Bridge.initMany(
            allocator,
            io,
            unused,
            unused,
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "empty-source",
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "empty-target",
                },
                .rules = &.{},
            },
            &shutdown,
        ),
    );
}

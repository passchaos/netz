const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const broker_mod = @import("../broker.zig");
const outbound = @import("outbound.zig");

fn options(dir: std.Io.Dir, mode: outbound.CoordinatorMode) outbound.MultiOptions {
    return .{
        .source_connect = .{ .protocol = .v5, .client_id = "restore-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .protocol = .v5, .client_id = "restore-target", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .rules = &.{.{ .filter = "#", .qos = .exactly_once, .local_prefix = "local/", .remote_prefix = "remote/" }},
        .coordinator = .{ .bridge_id = [_]u8{0x52} ** 16, .dir = dir, .sub_path = "bridge.log", .mode = mode },
    };
}

const Runner = struct {
    broker: *broker_mod.Broker,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = 4,
        }}, .{ .shutdown = &self.shutdown }) catch |err| {
            self.err = err;
        };
    }
};

test "local bidirectional bridge rejects MQTT 5 without No Local" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;

    try std.testing.expectError(
        error.UnsafeBidirectionalBridge,
        outbound.LocalBridge.initEndpoints(
            allocator,
            io,
            .{ .broker = &local, .id = [_]u8{0x69} ** 16 },
            .{ .address = .{ .ip4 = .loopback(1) } },
            .{
                .source_connect = .{
                    .protocol = .v5,
                    .client_id = "unsafe-v5-local",
                },
                .target_connect = .{
                    .protocol = .v5,
                    .client_id = "unsafe-v5-remote",
                },
                .rules = &.{.{
                    .filter = "#",
                    .no_local = true,
                }},
                .inbound_rules = &.{.{
                    .filter = "remote/#",
                    .local_prefix = "local/",
                    .remote_prefix = "remote/",
                }},
            },
            &shutdown,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        local.local_consumer_routes.count(),
    );
}

test "local bidirectional bridge rejects legacy MQTT without private mode" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;

    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1 }) |protocol| {
        try std.testing.expectError(
            error.UnsafeBidirectionalBridge,
            outbound.LocalBridge.initEndpoints(
                allocator,
                io,
                .{ .broker = &local, .id = [_]u8{0x6a} ** 16 },
                .{ .address = .{ .ip4 = .loopback(1) } },
                .{
                    .source_connect = .{
                        .protocol = .v5,
                        .client_id = "unsafe-legacy-local",
                    },
                    .target_connect = .{
                        .protocol = protocol,
                        .client_id = "unsafe-legacy-remote",
                    },
                    .rules = &.{.{
                        .filter = "#",
                        .no_local = true,
                    }},
                    .inbound_rules = &.{.{
                        .filter = "remote/#",
                        .local_prefix = "local/",
                        .remote_prefix = "remote/",
                    }},
                },
                &shutdown,
            ),
        );
    }
    try std.testing.expectEqual(
        @as(usize, 0),
        local.local_consumer_routes.count(),
    );
}

test "local bidirectional bridge preserves its inbound filter during cleanup" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();

    const RemotePeer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(usize, 1),
                subscribe.subscribe.subscriptions.len,
            );
            const subscription = subscribe.subscribe.subscriptions[0];
            try std.testing.expectEqualStrings(
                "remote/#",
                subscription.topic_filter,
            );
            try std.testing.expect(subscription.no_local);
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x00},
                &.{},
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var remote_peer = RemotePeer{ .server = &remote };
    const remote_thread = try std.Thread.spawn(
        .{},
        RemotePeer.run,
        .{&remote_peer},
    );
    var remote_joined = false;
    defer if (!remote_joined) remote_thread.join();

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x6b} ** 16 },
        .{ .address = remote.address() },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "cleanup-duplex-local",
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "cleanup-duplex-remote",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .rules = &.{.{
                .filter = "#",
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .inbound_rules = &.{.{
                .filter = "remote/#",
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .attempt_target_unsubscribe = true,
        },
        &shutdown,
    );
    defer bridge.deinit();
    const connected = try bridge.connect();
    try std.testing.expect(connected.target_session_present);
    try bridge.disconnect(0);

    remote_thread.join();
    remote_joined = true;
    if (remote_peer.err) |err| return err;
}

test "local bidirectional bridge handles inbound QoS1 while awaiting outbound PUBACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();

    const RemotePeer = struct {
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

            var outbound_publish = try accepted.connection.readPublish();
            defer outbound_publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "remote/up",
                outbound_publish.publish.topic,
            );
            const inbound_packet_id = (try accepted.connection.writePublish(
                "remote/down",
                "interleaved-inbound",
                .{ .qos = .at_least_once },
            )).?;
            var inbound_ack = try accepted.connection.readPubAck();
            defer inbound_ack.deinit(self.server.allocator);
            try std.testing.expectEqual(
                inbound_packet_id,
                inbound_ack.ack.packet_id,
            );
            try accepted.connection.writePubAck(
                outbound_publish.publish.packet_id.?,
                0,
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var remote_peer = RemotePeer{ .server = &remote };
    const remote_thread = try std.Thread.spawn(
        .{},
        RemotePeer.run,
        .{&remote_peer},
    );
    var remote_joined = false;
    defer if (!remote_joined) remote_thread.join();

    var wake: broker_mod.LocalConsumerWake = .{};
    var observer = try local.openLocalConsumer(.{
        .id = [_]u8{0x6c} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "local/down",
            .qos = .at_least_once,
        }},
        .wake = &wake,
    });
    defer local.closeLocalConsumer(&observer);
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x6d} ** 16 },
        .{ .address = remote.address() },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "interleaved-duplex-local",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "interleaved-duplex-remote",
            },
            .rules = &.{.{
                .filter = "#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .inbound_rules = &.{.{
                .filter = "remote/#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();

    const generation = wake.observe();
    try local.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "local/up",
        .packet_id = null,
        .properties = &.{},
        .payload = "outbound",
    });
    try std.testing.expect(try bridge.step(.{
        .timeout = .fromSeconds(2),
        .cancellation_check_interval = .fromMilliseconds(5),
    }));
    try wake.waitForChange(io, generation);
    var event = (try local.pollLocalConsumer(&observer)) orelse
        return error.TestUnexpectedResult;
    defer event.deinit();
    try std.testing.expectEqualStrings(
        "interleaved-inbound",
        event.publish.value.payload,
    );
    _ = try local.acknowledgeLocalConsumer(
        &observer,
        .puback,
        event.publish.value.packet_id.?,
        0,
    );
    try std.testing.expectEqual(@as(usize, 0), try bridge.source.pendingCount());
    try bridge.disconnect(0);

    remote_thread.join();
    remote_joined = true;
    if (remote_peer.err) |err| return err;
}

test "local outbound bridge forwards all QoS without a source listener" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    try local.createCommitLog(tmp.dir, "broker.log", .{});
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var runner = Runner{ .broker = &remote };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    defer {
        runner.shutdown.set(io);
        thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "direct-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#", .qos = .at_most_once }}, .{});
    defer suback.deinit(allocator);
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x51} ** 16 }, .{ .address = remote.address() }, .{
        .source_connect = .{ .protocol = .v5, .client_id = "direct-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .protocol = .v5, .client_id = "direct-target", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .rules = &.{.{ .filter = "#", .qos = .exactly_once, .local_prefix = "local/", .remote_prefix = "remote/" }},
        .coordinator = .{ .bridge_id = [_]u8{0x51} ** 16, .dir = tmp.dir, .sub_path = "bridge.log", .mode = .create },
    }, &shutdown);
    defer bridge.deinit();
    _ = try bridge.connect();
    for ([_]mqtt.QoS{ .at_most_once, .at_least_once, .exactly_once }) |qos| {
        try local.publishLocal(.{ .dup = false, .qos = qos, .retain = false, .topic = "local/value", .packet_id = null, .properties = &.{}, .payload = "direct" });
        // step alternates source/target and consumes a complete coordinated
        // transaction once selected. A bounded second step reaches the source.
        _ = try bridge.step(.{ .timeout = .fromSeconds(2) });
        _ = try bridge.step(.{ .timeout = .fromSeconds(2) });
        var delivered = try subscriber.readPublish();
        defer delivered.deinit(allocator);
        try std.testing.expectEqualStrings("remote/value", delivered.publish.topic);
        try std.testing.expectEqualStrings("direct", delivered.publish.payload);
    }
    try subscriber.ping();
    try std.testing.expect(!bridge.hasPendingDurableQoS2());
    try std.testing.expectEqual(@as(usize, 0), local.stats().session_inflight_messages);
}

test "local bidirectional bridge shares one remote Session without loops" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();
    var remote_runner = Runner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, Runner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }

    var remote_observer = try runtime.Client.connect(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "duplex-remote-observer" },
    );
    defer remote_observer.close();
    var remote_suback = try remote_observer.subscribe(&.{.{
        .topic_filter = "remote/#",
        .qos = .at_least_once,
    }}, .{});
    defer remote_suback.deinit(allocator);
    var remote_publisher = try runtime.Client.connect(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "duplex-remote-publisher" },
    );
    defer remote_publisher.close();

    var local_wake: broker_mod.LocalConsumerWake = .{};
    var local_observer = try local.openLocalConsumer(.{
        .id = [_]u8{0x63} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "local/down",
            .qos = .at_least_once,
        }},
        .wake = &local_wake,
    });
    defer local.closeLocalConsumer(&local_observer);
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x62} ** 16 },
        .{ .address = remote.address() },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "duplex-local",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "duplex-remote",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .rules = &.{.{
                .filter = "#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .inbound_rules = &.{.{
                .filter = "remote/#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .inbound_bridge_id = [_]u8{0x61} ** 16,
            .attempt_target_unsubscribe = true,
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    const BridgeRunner = struct {
        bridge: *outbound.LocalBridge,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.bridge.run(.{
                .timeout = .fromSeconds(2),
                .cancellation_check_interval = .fromMilliseconds(10),
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var bridge_runner = BridgeRunner{ .bridge = &bridge };
    const bridge_thread = try std.Thread.spawn(.{}, BridgeRunner.run, .{
        &bridge_runner,
    });
    var bridge_joined = false;
    defer if (!bridge_joined) {
        shutdown.set(io);
        bridge_thread.join();
    };

    try local.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "local/up",
        .packet_id = null,
        .properties = &.{},
        .payload = "outbound",
    });
    var remote_delivery = try remote_observer.readPublish();
    defer remote_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "remote/up",
        remote_delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "outbound",
        remote_delivery.publish.payload,
    );
    try remote_observer.writePubAck(remote_delivery.publish.packet_id.?, 0);

    const local_generation = local_wake.observe();
    try remote_publisher.publish(
        "remote/down",
        "inbound",
        .{ .qos = .at_least_once },
    );
    try local_wake.waitForChange(io, local_generation);
    var local_event = (try local.pollLocalConsumer(&local_observer)) orelse
        return error.TestUnexpectedResult;
    defer local_event.deinit();
    const local_delivery = switch (local_event) {
        .publish => |*publish| publish,
        .pubrel => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("local/down", local_delivery.value.topic);
    try std.testing.expectEqualStrings("inbound", local_delivery.value.payload);
    _ = try local.acknowledgeLocalConsumer(
        &local_observer,
        .puback,
        local_delivery.value.packet_id.?,
        0,
    );
    try std.testing.expectEqual(@as(usize, 0), try bridge.source.pendingCount());

    shutdown.set(io);
    bridge_thread.join();
    bridge_joined = true;
    try std.testing.expect(bridge_runner.err == null);
}

test "local bidirectional bridge resumes remote QoS2 on the shared Session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    try local.createCommitLog(tmp.dir, "broker.log", .{});
    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();
    var remote_runner = Runner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, Runner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }

    var remote_publisher = try runtime.Client.connect(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "duplex-qos2-publisher" },
    );
    defer remote_publisher.close();
    var wake: broker_mod.LocalConsumerWake = .{};
    var local_observer = try local.openLocalConsumer(.{
        .id = [_]u8{0x66} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "local/down",
            .qos = .exactly_once,
        }},
        .wake = &wake,
    });
    defer local.closeLocalConsumer(&local_observer);
    var shutdown: std.Io.Event = .unset;
    const bridge_options = outbound.MultiOptions{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "duplex-qos2-local",
            .clean_start = true,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "duplex-qos2-remote",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 60,
            } }},
        },
        .rules = &.{.{
            .filter = "#",
            .qos = .at_most_once,
            .local_prefix = "local/",
            .remote_prefix = "remote/",
            .no_local = true,
        }},
        .inbound_rules = &.{.{
            .filter = "remote/down",
            .qos = .exactly_once,
            .local_prefix = "local/",
            .remote_prefix = "remote/",
            .no_local = true,
        }},
        .inbound_bridge_id = [_]u8{0x64} ** 16,
    };
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x65} ** 16 },
        .{ .address = remote.address() },
        bridge_options,
        &shutdown,
    );
    var bridge_live = true;
    defer if (bridge_live) bridge.deinit();
    _ = try bridge.connect();

    const publisher_packet_id = (try remote_publisher.writePublish(
        "remote/down",
        "durable-inbound",
        .{ .qos = .exactly_once },
    )).?;
    var publisher_pubrec = try remote_publisher.readPubRec();
    defer publisher_pubrec.deinit(allocator);
    try remote_publisher.applyPubRec(publisher_pubrec.ack);

    // Alternate past the local-source turn and stop after the shared remote
    // client has durably staged the inbound PUBLISH and emitted PUBREC.
    _ = try bridge.step(.{ .timeout = .fromSeconds(1) });
    _ = try bridge.step(.{ .timeout = .fromSeconds(1) });
    try std.testing.expectEqual(
        @as(usize, 1),
        (try bridge.target.outgoingStats()).incoming_qos2_count,
    );
    var publisher_pubcomp = try remote_publisher.readPubComp();
    defer publisher_pubcomp.deinit(allocator);
    try std.testing.expectEqual(
        publisher_packet_id,
        publisher_pubcomp.ack.packet_id,
    );
    try remote_publisher.applyPubComp(publisher_pubcomp.ack);

    const staged_epoch = bridge.inbound_session_epoch;
    bridge.deinit();
    bridge_live = false;
    bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x65} ** 16 },
        .{ .address = remote.address() },
        bridge_options,
        &shutdown,
    );
    bridge_live = true;
    const resumed = try bridge.connect();
    try std.testing.expect(resumed.target_session_present);
    try std.testing.expectEqual(staged_epoch, bridge.inbound_session_epoch);

    const generation = wake.observe();
    for (0..8) |_| {
        _ = try bridge.step(.{ .timeout = .fromSeconds(1) });
        if (try local.localConsumerPendingCount(&local_observer) != 0) break;
    }
    try wake.waitForChange(io, generation);
    var publish_event = (try local.pollLocalConsumer(&local_observer)) orelse
        return error.TestUnexpectedResult;
    defer publish_event.deinit();
    const publish = switch (publish_event) {
        .publish => |*value| value,
        .pubrel => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("local/down", publish.value.topic);
    try std.testing.expectEqualStrings("durable-inbound", publish.value.payload);
    const packet_id = publish.value.packet_id.?;
    _ = try local.acknowledgeLocalConsumer(
        &local_observer,
        .pubrec,
        packet_id,
        0,
    );
    var pubrel_event = (try local.pollLocalConsumer(&local_observer)) orelse
        return error.TestUnexpectedResult;
    defer pubrel_event.deinit();
    try std.testing.expectEqual(packet_id, pubrel_event.pubrel);
    _ = try local.acknowledgeLocalConsumer(
        &local_observer,
        .pubcomp,
        packet_id,
        0,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try bridge.target.outgoingStats()).incoming_qos2_count,
    );
    try std.testing.expectEqual(@as(usize, 0), try bridge.source.pendingCount());
}

test "local outbound bridge restores all QoS2 ownership boundaries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var runner = Runner{ .broker = &remote };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    defer {
        runner.shutdown.set(io);
        thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "restore-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#" }}, .{});
    defer suback.deinit(allocator);
    const poll: mqtt.reconnect.PollOptions = .{ .timeout = .fromSeconds(2) };
    for (0..5) |phase| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var shutdown: std.Io.Event = .unset;
        {
            var local = try broker_mod.Broker.init(allocator, io, .{});
            defer local.deinit();
            try local.createCommitLog(tmp.dir, "broker.log", .{});
            var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x52} ** 16 }, .{ .address = remote.address() }, options(tmp.dir, .create), &shutdown);
            defer bridge.deinit();
            _ = try bridge.connect();
            try local.publishLocal(.{ .dup = false, .qos = .exactly_once, .retain = false, .topic = "local/restart", .packet_id = null, .properties = &.{}, .payload = "once" });
            try outbound.testing.stageNextDurableQoS2(&bridge, poll);
            if (phase >= 1) {
                try outbound.testing.flushDurableTarget(&bridge);
                try outbound.testing.stageTargetPubRec(&bridge, poll);
            }
            if (phase >= 2) {
                try outbound.testing.flushDurableTarget(&bridge);
                try outbound.testing.completeDurableTarget(&bridge, poll);
            }
            if (phase == 3) {
                var release = (try bridge.source.pollWithOptions(poll)).?;
                defer release.deinit(allocator);
                try std.testing.expect(release == .pubrel);
            }
            if (phase == 4) try outbound.testing.stageDurableSourcePubRel(&bridge, poll);
            if (phase == 4) {
                // The coordinator is already empty while the broker still
                // holds PUBREL. Reopening must finish PUBCOMP, not republish.
                try std.testing.expect(!bridge.hasPendingDurableQoS2());
            }
        }
        {
            var local = try broker_mod.Broker.init(allocator, io, .{});
            defer local.deinit();
            try local.restoreCommitLog(tmp.dir, "broker.log", .{});
            var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x52} ** 16 }, .{ .address = remote.address() }, options(tmp.dir, .restore), &shutdown);
            defer bridge.deinit();
            _ = try bridge.connect();
            _ = try bridge.step(poll);
            _ = try bridge.step(poll);
            try std.testing.expect(!bridge.hasPendingDurableQoS2());
            try std.testing.expectEqual(@as(usize, 0), local.stats().session_inflight_messages);
        }
        var delivered = try subscriber.readPublish();
        defer delivered.deinit(allocator);
        try std.testing.expectEqualStrings("remote/restart", delivered.publish.topic);
        try std.testing.expectEqualStrings("once", delivered.publish.payload);
        try subscriber.ping();
    }
}

test "local outbound bridge initialization allocation failures release registrations" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initializeWithAllocator, .{threaded.io()});
}

test "local bidirectional bridge initialization allocation failures release state" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initializeDuplexWithAllocator,
        .{threaded.io()},
    );
}

fn initializeDuplexWithAllocator(
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    const Connector = struct {
        fn refused(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: runtime.ConnectOptions,
        ) runtime.Error!runtime.ConnectAttempt {
            return error.ConnectionRefused;
        }
    };
    var connector_context: u8 = 0;
    var local = try broker_mod.Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
    });
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    var bridge = outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x68} ** 16 },
        .{ .connector = .{
            .context = &connector_context,
            .connect_attempt = Connector.refused,
        } },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "duplex-allocation-source",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "duplex-allocation-target",
            },
            .rules = &.{.{
                .filter = "#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .inbound_rules = &.{.{
                .filter = "remote/#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
                .no_local = true,
            }},
            .inbound_bridge_id = [_]u8{0x67} ** 16,
        },
        &shutdown,
    ) catch |err| {
        try std.testing.expectEqual(
            @as(usize, 0),
            local.local_consumer_routes.count(),
        );
        return err;
    };
    bridge.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        local.local_consumer_routes.count(),
    );
}

fn initializeWithAllocator(allocator: std.mem.Allocator, io: std.Io) !void {
    var local = try broker_mod.Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    var bridge = outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x53} ** 16 }, .{ .address = .{ .ip4 = .loopback(1) } }, .{
        .source_connect = .{ .protocol = .v5, .client_id = "allocation-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .client_id = "allocation-target" },
        .rules = &.{.{ .filter = "allocation/#" }},
    }, &shutdown) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), local.local_consumer_routes.count());
        return err;
    };
    bridge.deinit();
    try std.testing.expectEqual(@as(usize, 0), local.local_consumer_routes.count());
}

test "local outbound bridge one-shot failure closes its local consumer" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Connector = struct {
        fn refused(_: *anyopaque, _: std.mem.Allocator, _: std.Io, _: runtime.ConnectOptions) runtime.Error!runtime.ConnectAttempt {
            return error.ConnectionRefused;
        }
    };
    var context: u8 = 0;
    var local = try broker_mod.Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x54} ** 16 }, .{ .connector = .{ .context = &context, .connect_attempt = Connector.refused } }, .{
        .source_connect = .{ .client_id = "once-source" },
        .target_connect = .{ .client_id = "once-target" },
        .target_reconnect_policy = .{ .max_attempts = 1 },
        .rules = &.{.{ .filter = "once/#" }},
    }, &shutdown);
    defer bridge.deinit();
    try std.testing.expectEqual(@as(usize, 1), local.local_consumer_routes.count());
    try std.testing.expectError(error.ConnectionUnavailable, bridge.runOnce(.{ .timeout = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 0), local.local_consumer_routes.count());
}

test "local outbound bridge adapts notification Will and target protocol" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();

    const Remote = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var pending = try self.server.acceptPending(.{
                    .protocol = .v5,
                });
                defer pending.deinit(self.server.allocator);
                const will = pending.connect.connect.will.?;
                try std.testing.expectEqual(
                    mqtt.QoS.at_least_once,
                    will.qos,
                );
                try std.testing.expect(will.retain);
                try pending.connection.writeConnAck(.{
                    .reason_code = 0x9b,
                    .properties = &.{.{ .byte = .{
                        .id = .maximum_qos,
                        .value = 0,
                    } }},
                });
            }

            {
                var pending = try self.server.acceptPending(.{
                    .protocol = .v5,
                });
                defer pending.deinit(self.server.allocator);
                const will = pending.connect.connect.will.?;
                try std.testing.expectEqual(
                    mqtt.QoS.at_most_once,
                    will.qos,
                );
                try std.testing.expect(will.retain);
                try pending.connection.writeConnAck(.{
                    .reason_code = 0x9a,
                    .properties = &.{.{ .byte = .{
                        .id = .retain_available,
                        .value = 0,
                    } }},
                });
            }

            {
                var pending = try self.server.acceptPending(.{
                    .protocol = .v5,
                });
                defer pending.deinit(self.server.allocator);
                const will = pending.connect.connect.will.?;
                try std.testing.expectEqual(
                    mqtt.QoS.at_most_once,
                    will.qos,
                );
                try std.testing.expect(!will.retain);
                try pending.connection.writeConnAck(.{
                    .reason_code = 0x84,
                });
            }

            var final_pending = try self.server.acceptPending(.{
                .protocol = .v3_1_1,
            });
            var final_pending_owned = true;
            defer if (final_pending_owned) {
                final_pending.deinit(self.server.allocator);
            };
            const final_will = final_pending.connect.connect.will.?;
            try std.testing.expectEqual(
                mqtt.ProtocolVersion.v3_1_1,
                final_pending.connect.connect.protocol,
            );
            try std.testing.expect(final_pending.connect.connect.bridge_mode);
            try std.testing.expectEqual(
                @as(usize, 0),
                final_pending.connect.connect.properties.len,
            );
            try std.testing.expectEqual(
                mqtt.QoS.at_most_once,
                final_will.qos,
            );
            try std.testing.expect(!final_will.retain);
            var accepted = try final_pending.finish(.{
                .protocol = .v3_1_1,
            });
            final_pending_owned = false;
            defer accepted.deinit(self.server.allocator);

            for ([_][]const u8{ "1", "0" }) |payload| {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "bridge/capability/state",
                    publish.publish.topic,
                );
                try std.testing.expectEqualStrings(
                    payload,
                    publish.publish.payload,
                );
            }
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(u8, 0),
                disconnect.disconnect.reason_code,
            );
        }
    };
    var remote_state = Remote{ .server = &remote };
    const remote_thread = try std.Thread.spawn(
        .{},
        Remote.run,
        .{&remote_state},
    );
    var joined = false;
    defer if (!joined) remote_thread.join();

    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x56} ** 16 },
        .{ .address = remote.address() },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "capability-source",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "capability-target",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .rules = &.{.{
                .filter = "capability/#",
                .qos = .at_most_once,
            }},
            .notifications = .{
                .topic = "bridge/capability/state",
                .publish_remote = true,
            },
            .target_protocol_fallback = .{
                .protocol = .v3_1_1,
                .bridge_mode = true,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    try bridge.disconnect(0);

    remote_thread.join();
    joined = true;
    if (remote_state.err) |err| return err;
}

test "local outbound lazy bridge connects at threshold and retires when idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();
    var remote_runner = Runner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, Runner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }
    var subscriber = try runtime.Client.connect(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "lazy-observer" },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{
        .{ .topic_filter = "bridge/lazy/state", .qos = .at_least_once },
        .{ .topic_filter = "remote/#", .qos = .at_least_once },
    }, .{});
    defer suback.deinit(allocator);

    const CountingConnector = struct {
        address: std.Io.net.IpAddress,
        attempts: std.atomic.Value(usize) = .init(0),

        fn connectAttempt(
            context: *anyopaque,
            connect_allocator: std.mem.Allocator,
            connect_io: std.Io,
            connect_options: runtime.ConnectOptions,
        ) runtime.Error!runtime.ConnectAttempt {
            const self: *@This() = @ptrCast(@alignCast(context));
            _ = self.attempts.fetchAdd(1, .monotonic);
            return runtime.Client.connectAttempt(
                connect_allocator,
                connect_io,
                self.address,
                connect_options,
            );
        }
    };
    var connector = CountingConnector{ .address = remote.address() };
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x55} ** 16 },
        .{ .connector = .{
            .context = &connector,
            .connect_attempt = CountingConnector.connectAttempt,
        } },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "lazy-source",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "lazy-target",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .rules = &.{.{
                .filter = "#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            }},
            .notifications = .{
                .topic = "bridge/lazy/state",
                .publish_remote = true,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    const LazyRunner = struct {
        bridge: *outbound.LocalBridge,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.bridge.source.io);
            self.bridge.runLazy(
                .{
                    .timeout = .fromSeconds(2),
                    .cancellation_check_interval = .fromMilliseconds(10),
                },
                2,
                .fromMilliseconds(100),
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var lazy_runner = LazyRunner{ .bridge = &bridge };
    const lazy_thread = try std.Thread.spawn(.{}, LazyRunner.run, .{&lazy_runner});
    var lazy_joined = false;
    defer if (!lazy_joined) {
        shutdown.set(io);
        lazy_thread.join();
    };
    try lazy_runner.started.wait(io);
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    try std.testing.expectEqual(
        @as(usize, 0),
        connector.attempts.load(.monotonic),
    );

    try publishLazy(&local, "one");
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    try std.testing.expectEqual(
        @as(usize, 0),
        connector.attempts.load(.monotonic),
    );
    try publishLazy(&local, "two");
    try expectLazyPublish(&subscriber, "bridge/lazy/state", "1");
    try expectLazyPublish(&subscriber, "remote/value", "one");
    try expectLazyPublish(&subscriber, "remote/value", "two");
    try expectLazyPublish(&subscriber, "bridge/lazy/state", "0");
    try std.testing.expectEqual(
        @as(usize, 1),
        connector.attempts.load(.monotonic),
    );

    try publishLazy(&local, "three");
    try std.Io.sleep(io, .fromMilliseconds(150), .awake);
    try std.testing.expectEqual(
        @as(usize, 1),
        connector.attempts.load(.monotonic),
    );
    try publishLazy(&local, "four");
    try expectLazyPublish(&subscriber, "bridge/lazy/state", "1");
    try expectLazyPublish(&subscriber, "remote/value", "three");
    try expectLazyPublish(&subscriber, "remote/value", "four");

    shutdown.set(io);
    lazy_thread.join();
    lazy_joined = true;
    try std.testing.expect(lazy_runner.err == null);
}

fn publishLazy(broker: *broker_mod.Broker, payload: []const u8) !void {
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "local/value",
        .packet_id = null,
        .properties = &.{},
        .payload = payload,
    });
}

fn expectLazyPublish(
    subscriber: *runtime.Connection,
    expected_topic: []const u8,
    expected_payload: []const u8,
) !void {
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(subscriber.allocator);
    try std.testing.expectEqualStrings(expected_topic, delivered.publish.topic);
    try std.testing.expectEqualStrings(
        expected_payload,
        delivered.publish.payload,
    );
}

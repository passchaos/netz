const std = @import("std");
const context = @import("../broker_tests.zig");

const mqtt = context.TestContext.mqtt_mod;
const ServeState = context.TestContext.ServeStateType;
const testBroker = context.TestContext.testBrokerFn;
const connect = context.TestContext.connectFn;
const disconnectAll = context.TestContext.disconnectAllFn;
const joinServer = context.TestContext.joinServerFn;

const session_expiry = [_]mqtt.Property{
    .{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 30,
    } },
};

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

    var publisher = try connect(
        allocator,
        io,
        broker,
        "offline-qos0-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish("offline/qos0", "drop", .{});

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

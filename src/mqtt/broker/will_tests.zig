const std = @import("std");
const context = @import("../broker_tests.zig");

const mqtt = context.TestContext.mqtt_mod;
const ServeState = context.TestContext.ServeStateType;
const testBroker = context.TestContext.testBrokerFn;
const connect = context.TestContext.connectFn;
const connectWithOptions = context.connectWithOptions;
const disconnectAll = context.TestContext.disconnectAllFn;
const joinServer = context.TestContext.joinServerFn;

fn will(
    delay_seconds: u32,
    retain: bool,
) mqtt.LastWill {
    const Properties = struct {
        var values: [2]mqtt.Property = undefined;
    };
    Properties.values[0] = .{ .four_byte = .{
        .id = .will_delay_interval,
        .value = delay_seconds,
    } };
    Properties.values[1] = .{ .utf8 = .{
        .id = .content_type,
        .value = "text/plain",
    } };
    return .{
        .topic = "will/status",
        .payload = "offline",
        .qos = .at_least_once,
        .retain = retain,
        .properties = &Properties.values,
    };
}

test "broker routes immediate Will on ungraceful close" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "will-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "will-source",
            .will = will(0, false),
        },
    );
    try source.shutdown();
    defer source.close();

    var publish = try subscriber.readPublish();
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings("will/status", publish.publish.topic);
    try std.testing.expectEqualStrings("offline", publish.publish.payload);
    try std.testing.expect(!publish.publish.retain);
    var found_content_type = false;
    for (publish.publish.properties) |property| {
        if (property == .utf8 and property.utf8.id == .content_type) {
            found_content_type = true;
        }
        try std.testing.expect(!(property == .four_byte and
            property.four_byte.id == .will_delay_interval));
    }
    try std.testing.expect(found_content_type);
    try subscriber.writePubAck(publish.publish.packet_id.?, 0);

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "finite broker serve drains the final immediate retained Will" {
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

    var source = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "finite-immediate-will-source",
        .will = will(0, true),
    });
    try source.shutdown();
    defer source.close();
    try joinServer(thread, &joined, &serve);

    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expectEqual(@as(usize, 1), broker.retained.count());
}

test "finite broker serve keeps the final future Will scheduled" {
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

    var source = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "finite-delayed-will-source",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{
            .id = .session_expiry_interval,
            .value = 120,
        } }},
        .will = will(60, true),
    });
    try source.shutdown();
    defer source.close();
    try joinServer(thread, &joined, &serve);

    try std.testing.expectEqual(@as(usize, 1), broker.wills.count());
    try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
    const deadline = broker.wills.nextDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(
        deadline.nanoseconds > std.Io.Clock.awake.now(io).nanoseconds,
    );
}

test "broker rejects zero to nonzero DISCONNECT expiry before cleanup" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "invalid-expiry-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "invalid-expiry-source",
            .clean_start = false,
            .will = will(0, false),
        },
    );
    defer source.close();
    const invalid_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 1,
    } }};
    var invalid_packet: std.ArrayList(u8) = .empty;
    defer invalid_packet.deinit(allocator);
    try mqtt.Disconnect.write(
        &invalid_packet,
        allocator,
        .v5,
        0,
        &invalid_expiry,
    );
    try source.transport.writePacket(invalid_packet.items);
    var protocol_error = try source.readDisconnect();
    defer protocol_error.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x82),
        protocol_error.disconnect.reason_code,
    );

    var published = try subscriber.readPublish();
    defer published.deinit(allocator);
    try std.testing.expectEqualStrings("will/status", published.publish.topic);
    try std.testing.expectEqualStrings("offline", published.publish.payload);
    try subscriber.writePubAck(published.publish.packet_id.?, 0);

    var resumed = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "invalid-expiry-source",
            .clean_start = false,
        },
    );
    defer resumed.connection.close();
    defer resumed.connack.deinit(allocator);
    try std.testing.expect(!resumed.connack.connack.session_present);

    try disconnectAll(&.{ &subscriber, &resumed.connection });
    try joinServer(thread, &joined, &serve);
}

test "broker write ACL suppresses Will before retained and route mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        calls: usize = 0,

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

        fn authorizeWill(
            context_ptr: *anyopaque,
            publication: context.TestContext.WillAuthorization,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.calls += 1;
            return !std.mem.eql(u8, publication.topic, "will/denied");
        }
    };
    var policy: Policy = .{};
    var broker = try context.TestContext.BrokerType.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .access_control = .{
                .context = &policy,
                .authorize_publish = Policy.publish,
                .authorize_subscribe = Policy.subscribe,
                .authorize_will = Policy.authorizeWill,
            },
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    var subscriber = try connect(
        allocator,
        io,
        broker,
        "denied-will-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "denied-will-source",
            .will = .{
                .topic = "will/denied",
                .payload = "secret",
                .qos = .at_least_once,
                .retain = true,
            },
        },
    );
    try source.shutdown();
    defer source.close();

    // Wait for the independent Will driver under the same state barrier used
    // for publication. Observing an empty scheduler after the callback proves
    // the denied Will was consumed, without relying on a guessed sleep.
    const deadline = std.Io.Clock.awake.now(io).addDuration(
        .fromSeconds(2),
    );
    while (std.Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        broker.state_mutex.lockUncancelable(io);
        const consumed = broker.wills.count() == 0;
        broker.state_mutex.unlock(io);
        if (consumed) break;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(usize, 1), policy.calls);
    // PINGRESP arriving first proves no Will was enqueued to the subscriber.
    try subscriber.ping();
    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
        try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
    }

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker reserved topic policy suppresses client Will" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "reserved-will-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "$SYS/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    var source = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "reserved-will-source",
        .will = .{
            .topic = "$SYS/broker/uptime",
            .payload = "forged",
            .qos = .at_least_once,
            .retain = true,
        },
    });
    try source.shutdown();
    defer source.close();

    const deadline = std.Io.Clock.awake.now(io).addDuration(
        .fromSeconds(2),
    );
    while (std.Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        broker.state_mutex.lockUncancelable(io);
        const consumed = broker.wills.count() == 0;
        broker.state_mutex.unlock(io);
        if (consumed) break;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }

    try subscriber.ping();
    try std.testing.expectError(
        error.Timeout,
        subscriber.readClientPacketEventWithTimeout(
            .fromMilliseconds(20),
        ),
    );
    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
        try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
    }

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker Keep Alive timeout routes Will and closes idle client" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "keep-alive-will-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "keep-alive-will-source",
            .keep_alive_seconds = 1,
            .will = will(0, false),
        },
    );
    defer source.close();

    const started = std.Io.Clock.awake.now(io);
    var publish = try subscriber.readPublish();
    defer publish.deinit(allocator);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    // Keep Alive=1 has an exact 1.5-second broker timeout. Allow scheduling
    // jitter without weakening this into the old whole-second truncation.
    try std.testing.expect(
        elapsed.nanoseconds >= 1400 * std.time.ns_per_ms,
    );
    try std.testing.expect(
        elapsed.nanoseconds < 4 * std.time.ns_per_s,
    );
    try std.testing.expectEqualStrings(
        "will/status",
        publish.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "offline",
        publish.publish.payload,
    );
    try subscriber.writePubAck(publish.publish.packet_id.?, 0);

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker normal DISCONNECT cancels Will" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "will-cancel-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#" }},
        .{},
    );
    defer suback.deinit(allocator);
    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "will-cancel-source",
            .will = will(0, false),
        },
    );
    defer source.close();
    try source.disconnect(0);
    try subscriber.ping();

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker DISCONNECT 0x04 honors Will Delay and Session Expiry minimum" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "will-delay-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "will-delay-source",
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 1,
            } }},
            .will = will(10, false),
        },
    );
    defer source.close();
    try source.disconnect(0x04);

    const started = std.Io.Clock.awake.now(io);
    var publish = try subscriber.readPublish();
    defer publish.deinit(allocator);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds >= 900 * std.time.ns_per_ms);
    try std.testing.expect(elapsed.nanoseconds < 4 * std.time.ns_per_s);
    try subscriber.writePubAck(publish.publish.packet_id.?, 0);

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

test "broker reconnect before Will deadline cancels continued session" {
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

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "will-reconnect-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#" }},
        .{},
    );
    defer suback.deinit(allocator);
    var old = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "will-reconnect",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 10,
            } }},
            .will = will(2, false),
        },
    );
    try old.shutdown();
    defer old.close();
    var resumed = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "will-reconnect",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 10,
            } }},
        },
    );
    defer resumed.close();
    try std.Io.sleep(io, .fromMilliseconds(2200), .awake);
    try subscriber.ping();

    try disconnectAll(&.{ &subscriber, &resumed });
    try joinServer(thread, &joined, &serve);
}

test "broker retained Will is replayed to a later subscriber" {
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

    var source = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "retained-will-source",
            .will = will(0, true),
        },
    );
    try source.shutdown();
    defer source.close();
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "retained-will-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "will/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    var replay = try subscriber.readPublish();
    defer replay.deinit(allocator);
    try std.testing.expect(replay.publish.retain);
    try std.testing.expectEqualStrings("offline", replay.publish.payload);
    try subscriber.writePubAck(replay.publish.packet_id.?, 0);

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);
}

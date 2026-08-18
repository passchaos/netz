const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const ServeState = context.ServeStateType;
const testBroker = context.testBrokerFn;
const connect = context.connectFn;
const disconnectAll = context.disconnectAllFn;
const joinServer = context.joinServerFn;

fn subscribeWithIdentifier(
    connection: *context.runtime_mod.Connection,
    subscription: mqtt.Subscription,
    identifier: usize,
) !context.runtime_mod.OwnedSubAck {
    return connection.subscribe(
        &.{subscription},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = identifier,
        } }} },
    );
}

test "broker stores retained publish and replays MQTT 5 delivery metadata" {
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

    var publisher = try connect(
        allocator,
        io,
        broker,
        "retained-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "retained/state",
        "online",
        .{
            .qos = .exactly_once,
            .retain = true,
            .properties = &.{
                .{ .utf8 = .{
                    .id = .content_type,
                    .value = "text/plain",
                } },
            },
        },
    );

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "retained-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscribeWithIdentifier(
        &subscriber,
        .{
            .topic_filter = "retained/+",
            .qos = .at_least_once,
        },
        23,
    );
    defer suback.deinit(allocator);

    var replay = try subscriber.readPublish();
    defer replay.deinit(allocator);
    try std.testing.expectEqualStrings(
        "retained/state",
        replay.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "online",
        replay.publish.payload,
    );
    try std.testing.expect(replay.publish.retain);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        replay.publish.qos,
    );
    try std.testing.expectEqual(
        @as(?usize, 23),
        mqtt.subscriptionIdentifier(replay.publish.properties),
    );
    var found_content_type = false;
    for (replay.publish.properties) |property| {
        if (property == .utf8 and
            property.utf8.id == .content_type)
        {
            try std.testing.expectEqualStrings(
                "text/plain",
                property.utf8.value,
            );
            found_content_type = true;
        }
    }
    try std.testing.expect(found_content_type);
    try subscriber.writePubAck(replay.publish.packet_id.?, 0);

    try disconnectAll(&.{ &publisher, &subscriber });
    try joinServer(thread, &joined, &serve);
}

test "broker honors retained replacement deletion and Retain Handling" {
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

    var publisher = try connect(
        allocator,
        io,
        broker,
        "retained-replace-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "state/value",
        "one",
        .{ .qos = .at_least_once, .retain = true },
    );
    try publisher.publish(
        "state/value",
        "two",
        .{ .qos = .at_least_once, .retain = true },
    );

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "retained-replace-subscriber",
        &.{},
    );
    defer subscriber.close();
    var first_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "state/#",
            .qos = .at_least_once,
            .retain_handling = 1,
        }},
        .{},
    );
    defer first_suback.deinit(allocator);
    var replay = try subscriber.readPublish();
    defer replay.deinit(allocator);
    try std.testing.expectEqualStrings("two", replay.publish.payload);
    try subscriber.writePubAck(replay.publish.packet_id.?, 0);

    // Retain Handling=1 sends only when the subscription is new.
    var replacement = try subscriber.subscribe(
        &.{.{
            .topic_filter = "state/#",
            .qos = .at_least_once,
            .retain_handling = 1,
        }},
        .{},
    );
    defer replacement.deinit(allocator);
    try subscriber.ping();

    // Empty retained payload deletes state. It is still a live delivery to the
    // existing subscriber, with RETAIN cleared because RAP defaults false.
    try publisher.publish(
        "state/value",
        "",
        .{ .qos = .at_least_once, .retain = true },
    );
    var deletion_live = try subscriber.readPublish();
    defer deletion_live.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), deletion_live.publish.payload.len);
    try std.testing.expect(!deletion_live.publish.retain);
    try subscriber.writePubAck(deletion_live.publish.packet_id.?, 0);

    var no_replay = try subscriber.subscribe(
        &.{.{
            .topic_filter = "state/#",
            .retain_handling = 0,
        }},
        .{},
    );
    defer no_replay.deinit(allocator);
    try subscriber.ping();

    try disconnectAll(&.{ &publisher, &subscriber });
    try joinServer(thread, &joined, &serve);
}

test "broker suppresses shared retained replay and applies No Local" {
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

    var owner = try connect(
        allocator,
        io,
        broker,
        "retained-owner",
        &.{},
    );
    defer owner.close();
    try owner.publish(
        "owner/state",
        "owned",
        .{ .retain = true },
    );
    var no_local = try owner.subscribe(
        &.{.{
            .topic_filter = "owner/#",
            .no_local = true,
        }},
        .{},
    );
    defer no_local.deinit(allocator);
    try owner.ping();

    var shared = try connect(
        allocator,
        io,
        broker,
        "retained-shared",
        &.{},
    );
    defer shared.close();
    var shared_suback = try shared.subscribe(
        &.{.{
            .topic_filter = "$share/g/owner/#",
        }},
        .{},
    );
    defer shared_suback.deinit(allocator);
    try shared.ping();

    try disconnectAll(&.{ &owner, &shared });
    try joinServer(thread, &joined, &serve);
}

test "broker drops retained replay that expired before subscribe" {
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

    var publisher = try connect(
        allocator,
        io,
        broker,
        "retained-expiry-publisher",
        &.{},
    );
    defer publisher.close();
    try publisher.publish(
        "expiry/state",
        "short",
        .{
            .retain = true,
            .properties = &.{.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 1,
            } }},
        },
    );
    try std.Io.sleep(io, .fromMilliseconds(1100), .awake);

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "retained-expiry-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "expiry/#" }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.ping();

    try disconnectAll(&.{ &publisher, &subscriber });
    try joinServer(thread, &joined, &serve);
}

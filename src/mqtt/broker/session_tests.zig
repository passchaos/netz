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

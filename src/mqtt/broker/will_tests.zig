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

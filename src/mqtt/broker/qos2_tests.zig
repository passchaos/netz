const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const Broker = context.BrokerType;
const ServeState = context.ServeStateType;
const testBroker = context.testBrokerFn;
const connect = context.connectFn;
const disconnectAll = context.disconnectAllFn;
const joinServer = context.joinServerFn;
const writeDuplicatePublish = context.writeDuplicatePublishFn;

test "broker routes inbound QoS 2 exactly once at PUBREL" {
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
        "qos2-subscriber",
        &.{},
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "qos2-publisher",
        &.{},
    );
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "qos2", .qos = .exactly_once }},
        .{},
    );
    defer suback.deinit(allocator);

    const packet_id = (try publisher.writePublish(
        "qos2",
        "exactly-once",
        .{ .qos = .exactly_once },
    )).?;
    var pubrec = try publisher.readPubRec();
    defer pubrec.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);

    // A lost PUBREC makes the sender repeat PUBLISH with DUP=1. The broker
    // acknowledges it again but must retain only one Application Message.
    try writeDuplicatePublish(
        &publisher,
        "qos2",
        "exactly-once",
        packet_id,
    );
    var duplicate_pubrec = try publisher.readPubRec();
    defer duplicate_pubrec.deinit(allocator);
    try std.testing.expectEqual(
        packet_id,
        duplicate_pubrec.ack.packet_id,
    );

    try publisher.writePubRel(packet_id, 0);
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.exactly_once,
        delivered.publish.qos,
    );
    try std.testing.expectEqualStrings(
        "exactly-once",
        delivered.publish.payload,
    );
    try subscriber.writePubRec(delivered.publish.packet_id.?, 0);
    var downstream_pubrel = try subscriber.readPubRel();
    defer downstream_pubrel.deinit(allocator);
    try subscriber.writePubComp(
        downstream_pubrel.ack.packet_id,
        0,
    );

    var pubcomp = try publisher.readPubComp();
    defer pubcomp.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);

    // PUBCOMP may be lost. As in Mosquitto, a repeated PUBREL receives another
    // PUBCOMP but cannot route the already-released message a second time.
    try publisher.writePubRel(packet_id, 0);
    var repeated_pubcomp = try publisher.readPubComp();
    defer repeated_pubcomp.deinit(allocator);
    try std.testing.expectEqual(
        packet_id,
        repeated_pubcomp.ack.packet_id,
    );

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker preserves QoS 2 message until PUBREL and applies subscriber QoS" {
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
        "qos1-from-qos2",
        &.{},
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "qos2-source",
        &.{},
    );
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "mixed", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    const packet_id = (try publisher.writePublish(
        "mixed",
        "delayed-route",
        .{ .qos = .exactly_once },
    )).?;
    var pubrec = try publisher.readPubRec();
    defer pubrec.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);

    try publisher.writePubRel(packet_id, 0);
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        delivered.publish.qos,
    );
    try std.testing.expectEqualStrings(
        "delayed-route",
        delivered.publish.payload,
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);
    var pubcomp = try publisher.readPubComp();
    defer pubcomp.deinit(allocator);

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker rejects QoS 2 above its aggregate pending quota" {
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

    var first = try connect(
        allocator,
        io,
        broker,
        "qos2-quota-first",
        &.{},
    );
    defer first.close();
    var second = try connect(
        allocator,
        io,
        broker,
        "qos2-quota-second",
        &.{},
    );
    defer second.close();

    const first_id = (try first.writePublish(
        "quota",
        "held",
        .{ .qos = .exactly_once },
    )).?;
    var first_pubrec = try first.readPubRec();
    defer first_pubrec.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), first_pubrec.ack.reason_code);

    const rejected_id = (try second.writePublish(
        "quota",
        "rejected",
        .{ .qos = .exactly_once },
    )).?;
    var rejected = try second.readPubRec();
    defer rejected.deinit(allocator);
    try std.testing.expectEqual(rejected_id, rejected.ack.packet_id);
    try std.testing.expectEqual(@as(u8, 0x97), rejected.ack.reason_code);
    try std.testing.expectError(
        error.PublishRefused,
        second.applyPubRec(rejected.ack),
    );

    // Completing the held transaction releases broker-wide quota. The same
    // connection may then start another QoS 2 transaction normally.
    try first.writePubRel(first_id, 0);
    var first_pubcomp = try first.readPubComp();
    defer first_pubcomp.deinit(allocator);
    const accepted_id = (try second.writePublish(
        "quota",
        "accepted",
        .{ .qos = .exactly_once },
    )).?;
    var accepted = try second.readPubRec();
    defer accepted.deinit(allocator);
    try std.testing.expectEqual(accepted_id, accepted.ack.packet_id);
    try std.testing.expectEqual(@as(u8, 0), accepted.ack.reason_code);
    try second.writePubRel(accepted_id, 0);
    var accepted_pubcomp = try second.readPubComp();
    defer accepted_pubcomp.deinit(allocator);

    try disconnectAll(&.{ &first, &second });
    try joinServer(thread, &joined, &serve);
}

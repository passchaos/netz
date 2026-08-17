const std = @import("std");
const mqtt = @import("../mod.zig");
const session = @import("mod.zig");

const Store = session.Store;
const Transmission = session.Transmission;
const second_ns: i96 = std.time.ns_per_s;

test "session clean start and expiry control Session Present" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    const first = try store.open("client", false, 10, now);
    try std.testing.expect(!first.session_present);
    try store.disconnect(first.handle, null, now);

    const resumed = try store.open(
        "client",
        false,
        10,
        std.Io.Timestamp.fromNanoseconds(5 * second_ns),
    );
    try std.testing.expect(resumed.session_present);
    try store.disconnect(resumed.handle, null, now);

    const clean = try store.open("client", true, 10, now);
    try std.testing.expect(!clean.session_present);
    try std.testing.expectError(
        error.SessionNotFound,
        store.subscriptionsInto(resumed.handle, &[_]session.Subscription{}),
    );
    try store.disconnect(clean.handle, null, now);

    const expiring = try store.open("expiring", false, 2, now);
    try store.disconnect(expiring.handle, null, now);
    try std.testing.expectEqual(
        @as(usize, 0),
        store.pruneExpired(
            std.Io.Timestamp.fromNanoseconds(second_ns),
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        store.pruneExpired(
            std.Io.Timestamp.fromNanoseconds(2 * second_ns),
        ),
    );
    const after_expiry = try store.open(
        "expiring",
        false,
        2,
        std.Io.Timestamp.fromNanoseconds(3 * second_ns),
    );
    try std.testing.expect(!after_expiry.session_present);
}

test "session maps MQTT versions to expiry semantics" {
    try std.testing.expectEqual(
        @as(u32, 0),
        Store.expiryForConnect(.v5, false, &.{}),
    );
    try std.testing.expectEqual(
        @as(u32, 12),
        Store.expiryForConnect(.v5, true, &.{
            .{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 12,
            } },
        }),
    );
    try std.testing.expectEqual(
        std.math.maxInt(u32),
        Store.expiryForConnect(.v3_1_1, false, &.{}),
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        Store.expiryForConnect(.v3_1_1, true, &.{}),
    );
}

test "session duplicate ClientID takeover invalidates prior handle" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const first = try store.open("duplicate", false, 60, .zero);
    const second = try store.open("duplicate", false, 60, .zero);
    try std.testing.expect(second.session_present);
    try std.testing.expect(second.replaced_connection);
    try std.testing.expectError(
        error.SessionNotFound,
        store.stats(first.handle),
    );
    const stats = try store.stats(second.handle);
    try std.testing.expect(stats.connected);
}

test "session openConnect and disconnectPacket apply MQTT 5 properties" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();

    const connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = false,
        .keep_alive_seconds = 30,
        .client_id = "packet-api",
        .properties = @constCast(&[_]mqtt.Property{
            .{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 60,
            } },
        }),
    };
    const opened = try store.openConnect(connect, .zero);
    try std.testing.expectEqual(
        @as(u32, 60),
        (try store.stats(opened.handle)).expiry_interval,
    );
    const disconnect = mqtt.Disconnect{
        .reason_code = 0,
        .properties = @constCast(&[_]mqtt.Property{
            .{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 5,
            } },
        }),
    };
    try store.disconnectPacket(
        opened.handle,
        .v5,
        disconnect,
        .zero,
    );
    const resumed = try store.open(
        "packet-api",
        false,
        60,
        std.Io.Timestamp.fromNanoseconds(4 * second_ns),
    );
    try std.testing.expect(resumed.session_present);
}

test "session restores complete subscription options and identifier" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open(
        "subscriber",
        false,
        60,
        .zero,
    );

    try std.testing.expect(!(try store.setSubscription(opened.handle, .{
        .topic_filter = "devices/+",
        .qos = .at_least_once,
        .no_local = true,
        .retain_as_published = true,
        .retain_handling = 1,
    }, 7)));
    try std.testing.expect(try store.setSubscription(opened.handle, .{
        .topic_filter = "devices/+",
        .qos = .exactly_once,
        .retain_handling = 2,
    }, 9));
    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("subscriber", false, 60, .zero);
    var subscriptions: [1]session.Subscription = undefined;
    const restored = try store.subscriptionsInto(
        resumed.handle,
        &subscriptions,
    );
    try std.testing.expectEqual(@as(usize, 1), restored.len);
    try std.testing.expectEqualStrings(
        "devices/+",
        restored[0].topic_filter,
    );
    try std.testing.expectEqual(
        mqtt.QoS.exactly_once,
        restored[0].qos,
    );
    try std.testing.expect(!restored[0].no_local);
    try std.testing.expectEqual(@as(u2, 2), restored[0].retain_handling);
    try std.testing.expectEqual(@as(?usize, 9), restored[0].subscription_identifier);
    const stats = try store.stats(resumed.handle);
    try std.testing.expectEqual(@as(usize, 1), stats.subscription_count);
    try std.testing.expect(try store.removeSubscription(
        resumed.handle,
        "devices/+",
    ));
}

test "session queues offline QoS and drains receive maximum" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("offline", false, 60, .zero);
    try store.disconnect(opened.handle, null, .zero);

    _ = try store.enqueuePublish(opened.handle, "jobs/one", "one", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    _ = try store.enqueuePublish(opened.handle, "jobs/two", "two", .{
        .qos = .exactly_once,
        .now = .zero,
    });
    try std.testing.expectError(
        error.InvalidQoS,
        store.enqueuePublish(opened.handle, "jobs/qos0", "zero", .{
            .qos = .at_most_once,
            .now = .zero,
        }),
    );

    const resumed = try store.open("offline", false, 60, .zero);
    var output: [2]Transmission = undefined;
    const first = try store.drainInto(
        resumed.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(@as(usize, 1), first.len);
    const first_publish = first[0].publish;
    try std.testing.expectEqualStrings("jobs/one", first_publish.topic);
    try std.testing.expect(!first_publish.dup);
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(
            resumed.handle,
            .puback,
            first_publish.packet_id,
            0,
        ),
    );

    const second = try store.drainInto(
        resumed.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqualStrings(
        "jobs/two",
        second[0].publish.topic,
    );
}

test "session reconnect retransmits QoS1 PUBLISH with DUP and original id" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("retry-qos1", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "retry/one", "value", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    var output: [1]Transmission = undefined;
    const sent = try store.drainInto(opened.handle, .zero, 10, &output);
    const original = sent[0].publish;
    try std.testing.expect(!original.dup);

    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("retry-qos1", false, 60, .zero);
    const retry = try store.drainInto(resumed.handle, .zero, 10, &output);
    try std.testing.expect(retry[0].publish.dup);
    try std.testing.expectEqual(
        original.packet_id,
        retry[0].publish.packet_id,
    );
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(
            resumed.handle,
            .puback,
            original.packet_id,
            0,
        ),
    );
}

test "session reconnect retransmits PUBREL and accepts out-of-order ack" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("retry-qos2", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "retry/two", "two", .{
        .qos = .exactly_once,
        .now = .zero,
    });
    _ = try store.enqueuePublish(opened.handle, "retry/one", "one", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    var output: [2]Transmission = undefined;
    const sent = try store.drainInto(opened.handle, .zero, 10, &output);
    const qos2_id = sent[0].publish.packet_id;
    const qos1_id = sent[1].publish.packet_id;
    try std.testing.expectEqual(
        session.AckAction.send_pubrel,
        try store.handleAck(opened.handle, .pubrec, qos2_id, 0),
    );
    // Complete the later QoS 1 packet first; rumqttd's audited Outgoing
    // rejects this valid out-of-order acknowledgement.
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(opened.handle, .puback, qos1_id, 0),
    );
    const pubrel = try store.drainInto(opened.handle, .zero, 10, &output);
    try std.testing.expectEqual(
        qos2_id,
        pubrel[0].pubrel.packet_id,
    );
    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("retry-qos2", false, 60, .zero);
    const retry = try store.drainInto(resumed.handle, .zero, 10, &output);
    try std.testing.expectEqual(
        qos2_id,
        retry[0].pubrel.packet_id,
    );
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(resumed.handle, .pubcomp, qos2_id, 0),
    );
}

test "session negative PUBREC completes without PUBREL" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("negative", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "negative/qos2", "v", .{
        .qos = .exactly_once,
        .now = .zero,
    });
    var output: [1]Transmission = undefined;
    const sent = try store.drainInto(opened.handle, .zero, 10, &output);
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(
            opened.handle,
            .pubrec,
            sent[0].publish.packet_id,
            0x80,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.drainInto(opened.handle, .zero, 10, &output)).len,
    );
}

test "session transmission writers preserve DUP and PUBREL identifiers" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("wire", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "wire/qos2", "value", .{
        .qos = .exactly_once,
        .now = .zero,
    });
    var output: [1]Transmission = undefined;
    const sent = try store.drainInto(opened.handle, .zero, 10, &output);
    const packet_id = sent[0].publish.packet_id;
    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("wire", false, 60, .zero);
    const retry = try store.drainInto(resumed.handle, .zero, 10, &output);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try retry[0].publish.write(&encoded, allocator, .v5);
    var publish = try mqtt.Publish.parse(allocator, .v5, encoded.items);
    defer publish.deinit(allocator);
    try std.testing.expect(publish.dup);
    try std.testing.expectEqual(packet_id, publish.packet_id.?);

    try std.testing.expectEqual(
        session.AckAction.send_pubrel,
        try store.handleAck(resumed.handle, .pubrec, packet_id, 0),
    );
    const pubrel = try store.drainInto(resumed.handle, .zero, 10, &output);
    encoded.clearRetainingCapacity();
    try pubrel[0].pubrel.write(&encoded, allocator, .v5);
    var ack = try mqtt.AckPacket.parse(allocator, .v5, encoded.items);
    defer ack.deinit(allocator);
    try std.testing.expectEqual(mqtt.PacketType.pubrel, ack.packet_type);
    try std.testing.expectEqual(packet_id, ack.packet_id);
}

test "session reconnect honors a lower Receive Maximum" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("lower-window", false, 60, .zero);
    for (0..2) |index| {
        var topic: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&topic, "window/{d}", .{index});
        _ = try store.enqueuePublish(opened.handle, name, "value", .{
            .qos = .at_least_once,
            .now = .zero,
        });
    }
    var output: [2]Transmission = undefined;
    try std.testing.expectEqual(
        @as(usize, 2),
        (try store.drainInto(opened.handle, .zero, 2, &output)).len,
    );
    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("lower-window", false, 60, .zero);
    try std.testing.expectEqual(
        @as(usize, 1),
        (try store.drainInto(resumed.handle, .zero, 1, &output)).len,
    );
}

test "session message expiry skips queued and publish retransmit" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("expiry", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "expiring", "v", .{
        .qos = .at_least_once,
        .properties = &.{
            .{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 2,
            } },
        },
        .now = .zero,
    });
    var output: [1]Transmission = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.drainInto(
            opened.handle,
            std.Io.Timestamp.fromNanoseconds(2 * second_ns),
            10,
            &output,
        )).len,
    );

    _ = try store.enqueuePublish(opened.handle, "remaining", "v", .{
        .qos = .at_least_once,
        .properties = &.{
            .{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 10,
            } },
        },
        .now = .zero,
    });
    const sent = try store.drainInto(
        opened.handle,
        std.Io.Timestamp.fromNanoseconds(3 * second_ns),
        10,
        &output,
    );
    try std.testing.expectEqual(
        @as(?u32, 7),
        sent[0].publish.message_expiry_interval,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try sent[0].publish.write(&encoded, allocator, .v5);
    var parsed = try mqtt.Publish.parse(allocator, .v5, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(
        @as(?u32, 7),
        mqtt.messageExpiryInterval(parsed.properties),
    );
}

test "session persists incoming QoS2 packet identifiers" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("incoming-qos2", false, 60, .zero);
    try std.testing.expect(!(try store.recordIncomingQoS2(
        opened.handle,
        42,
    )));
    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("incoming-qos2", false, 60, .zero);
    try std.testing.expect(try store.recordIncomingQoS2(
        resumed.handle,
        42,
    ));
    try store.completeIncomingQoS2(resumed.handle, 42);
}

test "session limits preserve existing state" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_sessions = 1,
        .max_subscriptions_per_session = 1,
        .max_queued_per_session = 1,
        .max_session_bytes = 256,
        .max_total_bytes = 256,
    });
    defer store.deinit();
    const opened = try store.open("limited", false, 60, .zero);
    try std.testing.expectError(
        error.SessionLimitExceeded,
        store.open("other", false, 60, .zero),
    );
    _ = try store.setSubscription(opened.handle, .{
        .topic_filter = "one",
    }, null);
    try std.testing.expectError(
        error.SubscriptionLimitExceeded,
        store.setSubscription(opened.handle, .{
            .topic_filter = "two",
        }, null),
    );
    _ = try store.enqueuePublish(opened.handle, "one", "value", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    try std.testing.expectError(
        error.QueueFull,
        store.enqueuePublish(opened.handle, "two", "value", .{
            .qos = .at_least_once,
            .now = .zero,
        }),
    );
}

test "session allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testSessionAllocationFailures,
        .{},
    );
}

fn testSessionAllocationFailures(allocator: std.mem.Allocator) !void {
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("allocated", false, 60, .zero);
    _ = try store.setSubscription(opened.handle, .{
        .topic_filter = "devices/+",
        .qos = .at_least_once,
    }, 5);
    _ = try store.enqueuePublish(opened.handle, "devices/one", "value", .{
        .qos = .exactly_once,
        .properties = &.{
            .{ .utf8_pair = .{
                .id = .user_property,
                .key = "key",
                .value = "value",
            } },
        },
        .now = .zero,
    });
}

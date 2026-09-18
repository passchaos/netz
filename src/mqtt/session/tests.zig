const std = @import("std");
const mqtt = @import("../mod.zig");
const persistence = @import("../persistence/codec.zig");
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

test "session optionally queues QoS0 without MQTT packet identifiers" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("offline-qos0", false, 60, .zero);
    try std.testing.expectEqual(
        session.EnqueueResult.queued,
        try store.enqueuePublish(
            opened.handle,
            "offline/qos0",
            "queued",
            .{ .qos = .at_most_once, .now = .zero },
        ),
    );
    var output: [1]Transmission = undefined;
    const selected = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(@as(usize, 1), selected.len);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, selected[0].publish.qos);
    try std.testing.expectEqual(@as(u16, 0), selected[0].publish.packet_id);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try selected[0].publish.write(&encoded, allocator, .v5);
    var parsed = try mqtt.Publish.parse(allocator, .v5, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, parsed.qos);
    try std.testing.expectEqual(@as(?u16, null), parsed.packet_id);
    try std.testing.expectEqualStrings("queued", parsed.payload);
    try store.completeQoS0Transmission(opened.handle, opened.route_id, 0);
    const stats = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_count);
    try std.testing.expectEqual(@as(usize, 0), stats.inflight_count);
}

test "session queued QoS0 rollback preserves ordering and byte accounting" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_inflight_per_session = 1,
        .max_queued_per_session = 2,
        .max_queued_payload_bytes_per_session = 7,
    });
    defer store.deinit();
    const opened = try store.open("qos0-rollback", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "queued/zero", "zero", .{
        .qos = .at_most_once,
        .now = .zero,
    });
    _ = try store.enqueuePublish(opened.handle, "queued/one", "one", .{
        .qos = .at_least_once,
        .now = .zero,
    });

    var output: [1]Transmission = undefined;
    const selected = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqualStrings(
        "queued/zero",
        selected[0].publish.topic,
    );
    try std.testing.expectEqual(
        @as(usize, 7),
        (try store.stats(opened.handle)).queued_payload_bytes,
    );
    try std.testing.expectError(
        error.QueueFull,
        store.enqueuePublish(opened.handle, "queued/two", "two", .{
            .qos = .at_most_once,
            .now = .zero,
        }),
    );
    var count_bounded = Store.init(allocator, .{
        .max_inflight_per_session = 1,
        .max_queued_per_session = 2,
    });
    defer count_bounded.deinit();
    const counted = try count_bounded.open(
        "qos0-count-bound",
        false,
        60,
        .zero,
    );
    _ = try count_bounded.enqueuePublish(
        counted.handle,
        "queued/zero",
        "zero",
        .{ .qos = .at_most_once, .now = .zero },
    );
    _ = try count_bounded.enqueuePublish(
        counted.handle,
        "queued/one",
        "one",
        .{ .qos = .at_least_once, .now = .zero },
    );
    _ = try count_bounded.drainInto(counted.handle, .zero, 1, &output);
    try std.testing.expectError(
        error.QueueFull,
        count_bounded.enqueuePublish(
            counted.handle,
            "queued/two",
            "two",
            .{ .qos = .at_most_once, .now = .zero },
        ),
    );
    try count_bounded.completeQoS0Transmission(
        counted.handle,
        counted.route_id,
        0,
    );
    try store.retryUnsentPublish(opened.handle, 0);
    try std.testing.expectEqual(
        @as(usize, 7),
        (try store.stats(opened.handle)).queued_payload_bytes,
    );

    const retried = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqualStrings(
        "queued/zero",
        retried[0].publish.topic,
    );
    try store.completeQoS0Transmission(opened.handle, opened.route_id, 0);
    const qos1 = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqualStrings(
        "queued/one",
        qos1[0].publish.topic,
    );
}

test "session queued QoS0 does not consume QoS1 inflight capacity" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_inflight_per_session = 1,
    });
    defer store.deinit();
    const opened = try store.open("qos0-window", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "window/zero", "zero", .{
        .qos = .at_most_once,
        .now = .zero,
    });
    _ = try store.enqueuePublish(opened.handle, "window/one", "one", .{
        .qos = .at_least_once,
        .now = .zero,
    });

    var output: [1]Transmission = undefined;
    const qos0 = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(mqtt.QoS.at_most_once, qos0[0].publish.qos);
    try store.completeQoS0Transmission(opened.handle, opened.route_id, 0);
    const qos1 = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(mqtt.QoS.at_least_once, qos1[0].publish.qos);
    try std.testing.expectEqual(@as(usize, 1), (try store.stats(opened.handle)).inflight_count);
}

test "session retires QoS1 transmission capped to wire QoS0" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("qos0-cap", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "cap/one", "one", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    var output: [1]Transmission = undefined;
    const selected = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    const packet_id = selected[0].publish.packet_id;
    try std.testing.expect(packet_id != 0);
    try store.completeQoS0Transmission(
        opened.handle,
        opened.route_id,
        packet_id,
    );
    const stats = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 0), stats.inflight_count);
    try std.testing.expect(!store.ownsPacketId(opened.handle, packet_id));
}

test "session snapshot preserves QoS0 selected for a live write" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("qos0-snapshot", false, 60, .zero);
    _ = try store.enqueuePublish(
        opened.handle,
        "snapshot/zero",
        "durable",
        .{ .qos = .at_most_once, .now = .zero },
    );
    var output: [1]Transmission = undefined;
    _ = try store.drainInto(opened.handle, .zero, 1, &output);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(&encoded, allocator, .zero);
    var restored = Store.init(allocator, .{});
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(&cursor, .zero, 0);
    try cursor.finish();

    const resumed = try restored.open(
        "qos0-snapshot",
        false,
        60,
        .zero,
    );
    const delivery = try restored.drainInto(
        resumed.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(@as(usize, 1), delivery.len);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, delivery[0].publish.qos);
    try std.testing.expectEqualStrings("durable", delivery[0].publish.payload);
    try restored.completeQoS0Transmission(
        resumed.handle,
        resumed.route_id,
        0,
    );
}

test "session takeover lets the original writer resolve pending QoS0" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const first = try store.open("qos0-takeover", false, 60, .zero);
    _ = try store.enqueuePublish(
        first.handle,
        "takeover/zero",
        "once",
        .{ .qos = .at_most_once, .now = .zero },
    );
    var output: [1]Transmission = undefined;
    _ = try store.drainInto(first.handle, .zero, 1, &output);

    const second = try store.open("qos0-takeover", false, 60, .zero);
    try std.testing.expectError(
        error.InflightFull,
        store.drainInto(second.handle, .zero, 1, &output),
    );
    try store.retryUnsentPublish(first.handle, 0);
    const retried = try store.drainInto(
        second.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqualStrings("once", retried[0].publish.payload);
    try std.testing.expectError(
        error.SessionNotFound,
        store.completeQoS0Transmission(first.handle, first.route_id, 0),
    );
    try store.completeQoS0Transmission(second.handle, second.route_id, 0);
}

test "session duplicate ClientID takeover invalidates prior handle" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const first = try store.open("duplicate", false, 60, .zero);
    const second = try store.open("duplicate", false, 60, .zero);
    try std.testing.expectEqual(first.route_id, second.route_id);
    try std.testing.expect(second.session_present);
    try std.testing.expect(second.replaced_connection);
    try std.testing.expectError(
        error.SessionNotFound,
        store.stats(first.handle),
    );
    const stats = try store.stats(second.handle);
    try std.testing.expect(stats.connected);
}

test "session route identity changes only after Session deletion" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const first = try store.open("route-id", false, 60, .zero);
    try std.testing.expectEqual(
        first.handle,
        store.handleForRouteId(first.route_id).?,
    );
    try store.disconnect(first.handle, 0, .zero);
    try std.testing.expectEqual(
        @as(?session.Handle, null),
        store.handleForRouteId(first.route_id),
    );
    const replacement = try store.open("route-id", false, 60, .zero);
    try std.testing.expect(replacement.route_id != first.route_id);
}

test "session due-expiry gate repairs stale reconnect deadline" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const first = try store.open("expiry-gate", false, 1, .zero);
    try store.disconnect(first.handle, null, .zero);
    try std.testing.expectEqual(
        second_ns,
        store.nextExpiryDeadline().?.nanoseconds,
    );
    const resumed = try store.open(
        "expiry-gate",
        false,
        10,
        std.Io.Timestamp.fromNanoseconds(second_ns),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        store.dueExpiryCount(
            std.Io.Timestamp.fromNanoseconds(second_ns),
        ),
    );
    try std.testing.expect(store.nextExpiryDeadline() == null);
    try store.disconnect(
        resumed.handle,
        null,
        std.Io.Timestamp.fromNanoseconds(second_ns),
    );
    try std.testing.expectEqual(
        11 * second_ns,
        store.nextExpiryDeadline().?.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        store.dueExpiryCount(
            std.Io.Timestamp.fromNanoseconds(10 * second_ns),
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        store.dueExpiryCount(
            std.Io.Timestamp.fromNanoseconds(11 * second_ns),
        ),
    );
    var route_ids: [1]u64 = undefined;
    const removed = try store.pruneExpiredInto(
        std.Io.Timestamp.fromNanoseconds(11 * second_ns),
        &route_ids,
    );
    try std.testing.expectEqualSlices(
        u64,
        &.{resumed.route_id},
        removed,
    );
    try std.testing.expect(store.nextExpiryDeadline() == null);
}

test "session expiry callback reports routes and advances deadline" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const first = try store.open("expiry-callback-1", false, 1, .zero);
    const second = try store.open("expiry-callback-2", false, 2, .zero);
    try store.disconnect(first.handle, null, .zero);
    try store.disconnect(second.handle, null, .zero);

    const Collector = struct {
        routes: [2]u64 = undefined,
        len: usize = 0,

        fn append(self: *@This(), route_id: u64) void {
            self.routes[self.len] = route_id;
            self.len += 1;
        }
    };
    var collector: Collector = .{};
    try std.testing.expectEqual(
        @as(usize, 1),
        store.pruneExpiredWithContext(
            std.Io.Timestamp.fromNanoseconds(second_ns),
            &collector,
            Collector.append,
        ),
    );
    try std.testing.expectEqualSlices(
        u64,
        &.{first.route_id},
        collector.routes[0..collector.len],
    );
    try std.testing.expectEqual(
        2 * second_ns,
        store.nextExpiryDeadline().?.nanoseconds,
    );

    try std.testing.expectEqual(
        @as(usize, 1),
        store.pruneExpiredWithContext(
            std.Io.Timestamp.fromNanoseconds(2 * second_ns),
            &collector,
            Collector.append,
        ),
    );
    try std.testing.expectEqualSlices(
        u64,
        &.{ first.route_id, second.route_id },
        collector.routes[0..collector.len],
    );
    try std.testing.expect(store.nextExpiryDeadline() == null);
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

test "live transient Session takeover starts fresh without Session Present" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();

    const transient = try store.open(
        "transient-takeover",
        true,
        0,
        .zero,
    );
    const replacement = try store.open(
        "transient-takeover",
        false,
        60,
        .zero,
    );
    try std.testing.expect(replacement.replaced_connection);
    try std.testing.expect(!replacement.session_present);
    try std.testing.expect(transient.route_id != replacement.route_id);
    try std.testing.expectError(
        error.SessionNotFound,
        store.stats(transient.handle),
    );
    try std.testing.expectEqual(
        @as(u32, 60),
        (try store.stats(replacement.handle)).expiry_interval,
    );
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
    _ = try store.enqueuePublish(opened.handle, "jobs/qos0", "zero", .{
        .qos = .at_most_once,
        .now = .zero,
    });

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

test "session drain reuses more inflight holes than newly available slots" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("inflight-holes", false, 60, .zero);
    for (0..3) |index| {
        var topic: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&topic, "holes/{d}", .{index});
        _ = try store.enqueuePublish(opened.handle, name, "value", .{
            .qos = .at_least_once,
            .now = .zero,
        });
    }
    var output: [3]Transmission = undefined;
    const first = try store.drainInto(
        opened.handle,
        .zero,
        3,
        &output,
    );
    try std.testing.expectEqual(@as(usize, 3), first.len);
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(
            opened.handle,
            .puback,
            first[0].publish.packet_id,
            0,
        ),
    );
    try std.testing.expectEqual(
        session.AckAction.completed,
        try store.handleAck(
            opened.handle,
            .puback,
            first[1].publish.packet_id,
            0,
        ),
    );
    _ = try store.enqueuePublish(
        opened.handle,
        "holes/next",
        "value",
        .{ .qos = .at_least_once, .now = .zero },
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (try store.drainInto(opened.handle, .zero, 2, &output)).len,
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

test "session inflight expiry releases Receive Maximum credit" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("inflight-expiry", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "expiry/first", "old", .{
        .qos = .at_least_once,
        .properties = &.{.{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 1,
        } }},
        .now = .zero,
    });
    _ = try store.enqueuePublish(
        opened.handle,
        "expiry/second",
        "new",
        .{ .qos = .at_least_once, .now = .zero },
    );

    var output: [1]Transmission = undefined;
    const first = try store.drainInto(opened.handle, .zero, 1, &output);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqualStrings(
        "old",
        first[0].publish.payload,
    );
    try std.testing.expectEqual(@as(u16, 1), first[0].publish.packet_id);

    var snapshot_changed = false;
    const second = try store.drainIntoTrackingSnapshotChange(
        opened.handle,
        std.Io.Timestamp.fromNanoseconds(second_ns),
        1,
        &output,
        &snapshot_changed,
    );
    try std.testing.expect(snapshot_changed);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqualStrings(
        "new",
        second[0].publish.payload,
    );
    try std.testing.expectEqual(@as(u16, 2), second[0].publish.packet_id);

    const stats = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_count);
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);
}

test "session tracked drain reports pruning and fresh inflight selection" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("tracked-drain", false, 60, .zero);
    _ = try store.enqueuePublish(opened.handle, "expired", "v", .{
        .qos = .at_least_once,
        .properties = &.{.{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 1,
        } }},
        .now = .zero,
    });

    var output: [1]Transmission = undefined;
    var snapshot_changed = false;
    const empty = try store.drainIntoTrackingSnapshotChange(
        opened.handle,
        std.Io.Timestamp.fromNanoseconds(second_ns),
        1,
        &output,
        &snapshot_changed,
    );
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    try std.testing.expect(snapshot_changed);

    _ = try store.enqueuePublish(
        opened.handle,
        "selected",
        "v",
        .{ .qos = .at_least_once, .now = .zero },
    );
    snapshot_changed = false;
    const selected = try store.drainIntoTrackingSnapshotChange(
        opened.handle,
        .zero,
        1,
        &output,
        &snapshot_changed,
    );
    try std.testing.expectEqual(@as(usize, 1), selected.len);
    try std.testing.expect(snapshot_changed);

    try store.retryUnsentPublish(opened.handle, selected[0].publish.packet_id);
    snapshot_changed = false;
    const retry = try store.drainIntoTrackingSnapshotChange(
        opened.handle,
        .zero,
        1,
        &output,
        &snapshot_changed,
    );
    try std.testing.expectEqual(@as(usize, 1), retry.len);
    try std.testing.expect(!snapshot_changed);
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
    try std.testing.expectEqual(
        session.IncomingQoS2State.await_pubrel,
        (try store.incomingQoS2State(opened.handle, 42)).?,
    );
    try store.markIncomingQoS2ReleasePending(opened.handle, 42);
    try std.testing.expectEqual(
        session.IncomingQoS2State.release_pending,
        (try store.incomingQoS2State(opened.handle, 42)).?,
    );
    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("incoming-qos2", false, 60, .zero);
    try std.testing.expect(try store.recordIncomingQoS2(
        resumed.handle,
        42,
    ));
    try std.testing.expectEqual(
        session.IncomingQoS2State.release_pending,
        (try store.incomingQoS2State(resumed.handle, 42)).?,
    );
    try store.completeIncomingQoS2(resumed.handle, 42);
}

test "session drops oversized PUBLISH without dropping PUBREL" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("oversized", false, 60, .zero);
    _ = try store.enqueuePublish(
        opened.handle,
        "oversized/qos1",
        "payload",
        .{ .qos = .at_least_once, .now = .zero },
    );
    _ = try store.enqueuePublish(
        opened.handle,
        "oversized/qos2",
        "payload",
        .{ .qos = .exactly_once, .now = .zero },
    );
    var output: [2]Transmission = undefined;
    const sent = try store.drainInto(
        opened.handle,
        .zero,
        2,
        &output,
    );
    const qos1_id = sent[0].publish.packet_id;
    const qos2_id = sent[1].publish.packet_id;
    try std.testing.expectEqual(
        session.DropAction.dropped,
        try store.dropOversizedPublish(opened.handle, qos1_id),
    );
    try std.testing.expectEqual(
        session.AckAction.send_pubrel,
        try store.handleAck(
            opened.handle,
            .pubrec,
            qos2_id,
            0,
        ),
    );
    try std.testing.expectEqual(
        session.DropAction.ignored,
        try store.dropOversizedPublish(opened.handle, qos2_id),
    );
    const stats = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);
}

test "session drops ACL-denied queued PUBLISH without blocking the queue" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const opened = try store.open("acl-drop", false, 60, .zero);
    try std.testing.expectEqualStrings(
        "acl-drop",
        try store.clientId(opened.handle),
    );
    _ = try store.enqueuePublish(
        opened.handle,
        "denied",
        "first",
        .{ .qos = .at_least_once, .now = .zero },
    );
    _ = try store.enqueuePublish(
        opened.handle,
        "allowed",
        "second",
        .{ .qos = .at_least_once, .now = .zero },
    );

    var output: [1]Transmission = undefined;
    const denied = try store.drainInto(opened.handle, .zero, 1, &output);
    try std.testing.expectEqualStrings("denied", denied[0].publish.topic);
    try std.testing.expectEqual(
        session.DropAction.dropped,
        try store.dropOutgoingPublish(
            opened.handle,
            denied[0].publish.packet_id,
        ),
    );
    const allowed = try store.drainInto(opened.handle, .zero, 1, &output);
    try std.testing.expectEqual(@as(usize, 1), allowed.len);
    try std.testing.expectEqualStrings("allowed", allowed[0].publish.topic);
    try std.testing.expectEqualStrings("second", allowed[0].publish.payload);
}

test "session unsent publish retry remains first delivery" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const opened = try store.open("unsent-retry", false, 60, .zero);
    _ = try store.enqueuePublish(
        opened.handle,
        "retry/topic",
        "payload",
        .{ .qos = .at_least_once, .now = .zero },
    );
    var output: [1]Transmission = undefined;
    const selected = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expect(!selected[0].publish.dup);
    const packet_id = selected[0].publish.packet_id;
    try store.retryUnsentPublish(opened.handle, packet_id);
    const retried = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expectEqual(packet_id, retried[0].publish.packet_id);
    try std.testing.expect(!retried[0].publish.dup);

    try store.disconnect(opened.handle, null, .zero);
    const resumed = try store.open("unsent-retry", false, 60, .zero);
    const after_reconnect = try store.drainInto(
        resumed.handle,
        .zero,
        1,
        &output,
    );
    try std.testing.expect(after_reconnect[0].publish.dup);
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

test "session queued payload bytes bound admission and recover budget" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_queued_per_session = 16,
        .max_queued_payload_bytes_per_session = 10,
    });
    defer store.deinit();
    const opened = try store.open("byte-bounded", false, 60, .zero);

    _ = try store.enqueuePublish(opened.handle, "queue/one", "123456", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    _ = try store.enqueuePublish(opened.handle, "queue/two", "789012", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    try std.testing.expectEqual(
        @as(usize, 12),
        (try store.stats(opened.handle)).queued_payload_bytes,
    );
    try std.testing.expectError(
        error.QueueFull,
        store.enqueuePublish(opened.handle, "queue/three", "x", .{
            .qos = .at_least_once,
            .now = .zero,
        }),
    );

    var transmissions: [1]Transmission = undefined;
    const drained = try store.drainInto(
        opened.handle,
        .zero,
        1,
        &transmissions,
    );
    try std.testing.expectEqual(@as(usize, 1), drained.len);
    try std.testing.expectEqual(
        @as(usize, 6),
        (try store.stats(opened.handle)).queued_payload_bytes,
    );
    _ = try store.enqueuePublish(opened.handle, "queue/three", "abcd", .{
        .qos = .at_least_once,
        .now = .zero,
    });
    try std.testing.expectEqual(
        @as(usize, 10),
        (try store.stats(opened.handle)).queued_payload_bytes,
    );
}

test "session expiry pruning releases queued payload byte budget" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_queued_per_session = 16,
        .max_queued_payload_bytes_per_session = 5,
    });
    defer store.deinit();
    const opened = try store.open("byte-expiry", false, 60, .zero);
    _ = try store.enqueuePublish(
        opened.handle,
        "queue/expiring",
        "12345",
        .{
            .qos = .at_least_once,
            .properties = &.{.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 1,
            } }},
            .now = .zero,
        },
    );
    _ = try store.enqueuePublish(
        opened.handle,
        "queue/replacement",
        "fresh",
        .{
            .qos = .at_least_once,
            .now = std.Io.Timestamp.fromNanoseconds(second_ns),
        },
    );
    const stats = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 1), stats.queued_count);
    try std.testing.expectEqual(@as(usize, 5), stats.queued_payload_bytes);
}

test "session inflight payload bytes gate queue drain" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_queued_per_session = 16,
        .max_inflight_per_session = 16,
        .max_inflight_payload_bytes_per_session = 10,
    });
    defer store.deinit();
    const opened = try store.open("inflight-bytes", false, 60, .zero);
    for ([_][]const u8{ "123456", "789012", "third" }) |payload| {
        _ = try store.enqueuePublish(
            opened.handle,
            "inflight/value",
            payload,
            .{ .qos = .at_least_once, .now = .zero },
        );
    }

    var transmissions: [3]Transmission = undefined;
    const first = try store.drainInto(
        opened.handle,
        .zero,
        3,
        &transmissions,
    );
    // Mosquitto admits the message that crosses max_inflight_bytes and stops
    // before the next one, rather than truncating the crossing message.
    try std.testing.expectEqual(@as(usize, 2), first.len);
    try std.testing.expectEqual(
        @as(usize, 12),
        (try store.stats(opened.handle)).inflight_payload_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 5),
        (try store.stats(opened.handle)).queued_payload_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.drainInto(opened.handle, .zero, 3, &transmissions)).len,
    );

    _ = try store.handleAck(
        opened.handle,
        .puback,
        first[0].publish.packet_id,
        0,
    );
    try std.testing.expectEqual(
        @as(usize, 6),
        (try store.stats(opened.handle)).inflight_payload_bytes,
    );
    const next = try store.drainInto(
        opened.handle,
        .zero,
        3,
        &transmissions,
    );
    try std.testing.expectEqual(@as(usize, 1), next.len);
    try std.testing.expectEqualStrings(
        "third",
        next[0].publish.payload,
    );
    const stats = try store.stats(opened.handle);
    try std.testing.expectEqual(@as(usize, 11), stats.inflight_payload_bytes);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_payload_bytes);
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

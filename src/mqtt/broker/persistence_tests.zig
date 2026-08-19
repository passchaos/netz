const std = @import("std");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");

const Broker = broker_mod.Broker;

fn createBroker(
    allocator: std.mem.Allocator,
    io: std.Io,
) !Broker {
    return Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
            },
        },
    );
}

fn delayedWill(
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
        .topic = "persist/will",
        .payload = "offline",
        .qos = .at_least_once,
        .retain = retain,
        .properties = &Properties.values,
    };
}

test "MQTT broker snapshot restores retained and durable Session state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    defer source.deinit();

    const now = std.Io.Clock.awake.now(io);
    const opened = try source.sessions.open(
        "durable",
        false,
        std.math.maxInt(u32),
        now,
    );
    _ = try source.sessions.setSubscription(
        opened.handle,
        .{
            .topic_filter = "persist/+",
            .qos = .exactly_once,
            .retain_as_published = true,
        },
        17,
    );
    _ = try source.sessions.enqueuePublish(
        opened.handle,
        "persist/queued",
        "offline",
        .{
            .qos = .at_least_once,
            .now = now,
        },
    );
    var first_send: [1]mqtt.session.Transmission = undefined;
    const sent = try source.sessions.drainInto(
        opened.handle,
        now,
        1,
        &first_send,
    );
    try std.testing.expectEqual(@as(usize, 1), sent.len);
    try std.testing.expectEqualStrings(
        "persist/queued",
        sent[0].publish.topic,
    );
    try source.sessions.disconnect(opened.handle, null, now);

    _ = try source.retained.applyPublish(
        "persist/retained",
        "value",
        .{
            .retain = true,
            .qos = .at_least_once,
            .now = now,
        },
    );

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    if (comptime @hasDecl(std.Io.File.Permissions, "toMode")) {
        const stat = try tmp.dir.statFile(io, "broker.db", .{});
        try std.testing.expectEqual(
            @as(std.posix.mode_t, 0o600),
            stat.permissions.toMode() & 0o777,
        );
    }

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");

    var retained_matches: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto(
        "persist/retained",
        std.Io.Clock.awake.now(io),
        &retained_matches,
    );
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("value", matches[0].payload);

    const handle = restored.sessions.find(
        "durable",
        std.Io.Clock.awake.now(io),
    ).?;
    const stats = try restored.sessions.stats(handle);
    try std.testing.expect(!stats.connected);
    try std.testing.expectEqual(@as(usize, 1), stats.subscription_count);
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);
    try std.testing.expectEqual(@as(usize, 0), stats.incoming_qos2_count);
    var subscriptions: [1]mqtt.session.Subscription = undefined;
    const restored_subscriptions =
        try restored.sessions.subscriptionsInto(handle, &subscriptions);
    try std.testing.expectEqualStrings(
        "persist/+",
        restored_subscriptions[0].topic_filter,
    );
    try std.testing.expectEqual(
        @as(?usize, 17),
        restored_subscriptions[0].subscription_identifier,
    );
    var retransmit: [1]mqtt.session.Transmission = undefined;
    const retransmissions = try restored.sessions.drainInto(
        handle,
        std.Io.Clock.awake.now(io),
        1,
        &retransmit,
    );
    try std.testing.expectEqual(@as(usize, 1), retransmissions.len);
    try std.testing.expect(retransmissions[0].publish.dup);
    try std.testing.expectEqual(@as(usize, 1), restored.router.subscriptionCount());
}

test "MQTT broker snapshot corruption preserves current state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    _ = try broker.retained.applyPublish(
        "existing",
        "safe",
        .{ .retain = true, .now = now },
    );

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try broker.saveSnapshot(tmp.dir, "broker.db");
    const bytes = try tmp.dir.readFileAlloc(
        io,
        "broker.db",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(bytes);
    bytes[bytes.len - 1] ^= 0xff;
    try tmp.dir.writeFile(io, .{
        .sub_path = "broker.db",
        .data = bytes,
        .flags = .{ .truncate = true },
    });
    try std.testing.expectError(
        error.CorruptSnapshot,
        broker.restoreSnapshot(tmp.dir, "broker.db"),
    );
    var out: [1]mqtt.retained.Match = undefined;
    const matches = try broker.retained.matchInto("existing", now, &out);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("safe", matches[0].payload);
}

test "MQTT snapshot deducts downtime from message and Session expiry" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var will_publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer will_publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.fromNanoseconds(
        100 * std.time.ns_per_s,
    );
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 5,
    } }};
    _ = try retained.applyPublish(
        "expires/retained",
        "gone",
        .{
            .retain = true,
            .properties = &expiry,
            .now = saved_monotonic,
        },
    );
    const short = try sessions.open(
        "expires-session",
        false,
        5,
        saved_monotonic,
    );
    try sessions.disconnect(short.handle, null, saved_monotonic);

    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &will_publishers,
            .pending_qos2 = &pending_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(1_006 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();

    var out: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto(
        "expires/retained",
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        &out,
    );
    try std.testing.expectEqual(@as(usize, 0), matches.len);
    try std.testing.expect(
        restored.sessions.find(
            "expires-session",
            std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        ) == null,
    );
}

test "MQTT atomic snapshot replacement keeps latest complete state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    _ = try broker.retained.applyPublish(
        "replace",
        "first",
        .{ .retain = true, .now = now },
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try broker.saveSnapshot(tmp.dir, "broker.db");
    _ = try broker.retained.applyPublish(
        "replace",
        "second",
        .{ .retain = true, .now = now },
    );
    try broker.saveSnapshot(tmp.dir, "broker.db");

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");
    var out: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto("replace", now, &out);
    try std.testing.expectEqualStrings("second", matches[0].payload);
}

test "MQTT snapshot save rejects live transient broker state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    broker.slots[0].active = true;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(
        error.SnapshotBusy,
        broker.saveSnapshot(tmp.dir, "broker.db"),
    );
}

test "MQTT broker restart resumes Session and live routing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    const now = std.Io.Clock.awake.now(io);
    const opened = try source.sessions.open(
        "restart-client",
        false,
        std.math.maxInt(u32),
        now,
    );
    _ = try source.sessions.setSubscription(
        opened.handle,
        .{
            .topic_filter = "restart/#",
            .qos = .at_least_once,
        },
        null,
    );
    _ = try source.sessions.enqueuePublish(
        opened.handle,
        "restart/before",
        "queued",
        .{ .qos = .at_least_once, .now = now },
    );
    try source.sessions.disconnect(opened.handle, null, now);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    source.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    try broker.restoreSnapshot(tmp.dir, "broker.db");
    const Serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(2) catch |err| {
                self.err = err;
            };
        }
    };
    var serve = Serve{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = std.math.maxInt(u32),
    } }};
    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "restart-client",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer resumed_result.connack.deinit(allocator);
    var resumed = resumed_result.connection;
    defer resumed.close();
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var queued = try resumed.readPublish();
    defer queued.deinit(allocator);
    try std.testing.expect(!queued.publish.dup);
    try std.testing.expectEqualStrings(
        "queued",
        queued.publish.payload,
    );
    try resumed.writePubAck(queued.publish.packet_id.?, 0);

    var publisher = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "restart-publisher",
        },
    );
    defer publisher.close();
    try publisher.publish(
        "restart/after",
        "routed",
        .{ .qos = .at_least_once },
    );
    var routed = try resumed.readPublish();
    defer routed.deinit(allocator);
    try std.testing.expectEqualStrings("routed", routed.publish.payload);
    try resumed.writePubAck(routed.publish.packet_id.?, 0);
    try resumed.disconnect(0);
    try publisher.disconnect(0);

    thread.join();
    joined = true;
    if (serve.err) |err| return err;
}

test "MQTT snapshot preserves PUBREL after message expiry" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var will_publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer will_publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.zero;
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const opened = try sessions.open(
        "qos2-pubrel",
        false,
        std.math.maxInt(u32),
        saved_monotonic,
    );
    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 1,
    } }};
    _ = try sessions.enqueuePublish(
        opened.handle,
        "qos2/expiry",
        "payload",
        .{
            .qos = .exactly_once,
            .properties = &expiry,
            .now = saved_monotonic,
        },
    );
    var transmission: [1]mqtt.session.Transmission = undefined;
    const initial = try sessions.drainInto(
        opened.handle,
        saved_monotonic,
        1,
        &transmission,
    );
    const packet_id = initial[0].publish.packet_id;
    try std.testing.expectEqual(
        mqtt.session.AckAction.send_pubrel,
        try sessions.handleAck(
            opened.handle,
            .pubrec,
            packet_id,
            0,
        ),
    );
    try sessions.disconnect(opened.handle, null, saved_monotonic);

    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &will_publishers,
            .pending_qos2 = &pending_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(1_010 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();
    const handle = restored.sessions.find(
        "qos2-pubrel",
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
    ).?;
    const resumed = try restored.sessions.drainInto(
        handle,
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        1,
        &transmission,
    );
    try std.testing.expectEqual(@as(usize, 1), resumed.len);
    try std.testing.expectEqual(packet_id, resumed[0].pubrel.packet_id);
}

test "MQTT scheduled Will snapshot deducts downtime and restores publisher" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.fromNanoseconds(
        100 * std.time.ns_per_s,
    );
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const handle = try wills.set(
        "will-source",
        delayedWill(10, true),
        60,
    );
    _ = try wills.close(handle, .ungraceful, saved_monotonic);
    try publishers.put(allocator, handle, 77);

    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &publishers,
            .pending_qos2 = &pending_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    const restored_now = std.Io.Timestamp.fromNanoseconds(
        50 * std.time.ns_per_s,
    );
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        restored_now,
        std.Io.Timestamp.fromNanoseconds(1_004 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();

    try std.testing.expectEqual(
        @as(i96, restored_now.nanoseconds + 6 * std.time.ns_per_s),
        restored.wills.nextDeadline().?.nanoseconds,
    );
    var due_storage: [1]mqtt.will_scheduler.Handle = undefined;
    const due = try restored.wills.pollDue(
        std.Io.Timestamp.fromNanoseconds(
            restored_now.nanoseconds + 6 * std.time.ns_per_s,
        ),
        &due_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), due.len);
    try std.testing.expectEqual(
        @as(?u64, 77),
        restored.will_publishers.get(due[0]).?,
    );
    const publish = try restored.wills.view(due[0]);
    try std.testing.expectEqualStrings("offline", publish.payload);
    try std.testing.expect(publish.retain);
}

test "MQTT restored scheduled Will is canceled by continued Session" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    const handle = try wills.set(
        "resume-will",
        delayedWill(30, false),
        60,
    );
    _ = try wills.close(handle, .ungraceful, .zero);
    try publishers.put(allocator, handle, null);
    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &publishers,
            .pending_qos2 = &pending_qos2,
        },
        .zero,
        std.Io.Timestamp.fromNanoseconds(1_000 * std.time.ns_per_s),
    );
    defer allocator.free(encoded);
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .zero,
        std.Io.Timestamp.fromNanoseconds(1_001 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();

    const restored_handle =
        restored.wills.handleForClient("resume-will").?;
    try std.testing.expectEqual(
        mqtt.will_scheduler.CloseResult.canceled,
        restored.wills.onReconnect("resume-will", false, .zero),
    );
    _ = restored.will_publishers.remove(restored_handle);
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
}

test "MQTT broker restart publishes due retained Will" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    const scheduled = try source.wills.set(
        "broker-will-source",
        delayedWill(1, true),
        60,
    );
    _ = try source.wills.close(
        scheduled,
        .ungraceful,
        std.Io.Clock.awake.now(io),
    );
    try source.will_publishers.put(
        allocator,
        scheduled,
        null,
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    source.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    try broker.restoreSnapshot(tmp.dir, "broker.db");
    const Serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    };
    var serve = Serve{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "will-after-restart",
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "persist/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    var publish = try subscriber.readPublish();
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings("persist/will", publish.publish.topic);
    try std.testing.expectEqualStrings("offline", publish.publish.payload);
    // Depending on whether the restored deadline or SUBSCRIBE wins, this is
    // either live fanout (default RAP=false, RETAIN=0) or retained replay
    // (RETAIN=1). The retained-store assertion below is path-independent.
    try subscriber.writePubAck(publish.publish.packet_id.?, 0);
    try subscriber.disconnect(0);

    thread.join();
    joined = true;
    if (serve.err) |err| return err;
    var retained_match: [1]mqtt.retained.Match = undefined;
    const retained = try broker.retained.matchInto(
        "persist/will",
        std.Io.Clock.awake.now(io),
        &retained_match,
    );
    try std.testing.expectEqual(@as(usize, 1), retained.len);
    try std.testing.expectEqualStrings("offline", retained[0].payload);
}

test "MQTT broker restart releases inbound QoS 2 exactly once at PUBREL" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    const saved_now = std.Io.Clock.awake.now(io);
    const publisher_session = try source.sessions.open(
        "durable-qos2-publisher",
        false,
        std.math.maxInt(u32),
        saved_now,
    );
    const durable_publisher_id = sessionRouteSubscriberId(
        publisher_session.route_id,
    );
    const packet_id: u16 = 71;
    _ = try source.pending_qos2.record(
        durable_publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "restart/inbound-qos2",
            .packet_id = packet_id,
            .payload = "exactly-once-after-restart",
        },
        saved_now,
    );
    try source.sessions.disconnect(
        publisher_session.handle,
        null,
        saved_now,
    );
    const subscriber_session = try source.sessions.open(
        "durable-qos2-subscriber",
        false,
        std.math.maxInt(u32),
        saved_now,
    );
    _ = try source.sessions.setSubscription(
        subscriber_session.handle,
        .{
            .topic_filter = "restart/inbound-qos2",
            .qos = .at_least_once,
        },
        null,
    );
    try source.sessions.disconnect(
        subscriber_session.handle,
        null,
        saved_now,
    );

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    source.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    try broker.restoreSnapshot(tmp.dir, "broker.db");
    try std.testing.expectEqual(@as(usize, 1), broker.pending_qos2.count());
    const Serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(2) catch |err| {
                self.err = err;
            };
        }
    };
    var serve = Serve{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = std.math.maxInt(u32),
    } }};
    var subscriber_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "durable-qos2-subscriber",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer subscriber_result.connack.deinit(allocator);
    var subscriber = subscriber_result.connection;
    defer subscriber.close();
    try std.testing.expect(
        subscriber_result.connack.connack.session_present,
    );

    var publisher_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "durable-qos2-publisher",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer publisher_result.connack.deinit(allocator);
    var publisher = publisher_result.connection;
    defer publisher.close();
    try std.testing.expect(
        publisher_result.connack.connack.session_present,
    );

    try publisher.writePubRel(packet_id, 0);
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "exactly-once-after-restart",
        delivered.publish.payload,
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);
    var pubcomp = try publisher.readPubComp();
    defer pubcomp.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);
    try std.testing.expectEqual(@as(usize, 0), broker.pending_qos2.count());

    // A repeated PUBREL acknowledges idempotently but has no pending body to
    // route a second time.
    try publisher.writePubRel(packet_id, 0);
    var repeated = try publisher.readPubComp();
    defer repeated.deinit(allocator);
    try std.testing.expectEqual(packet_id, repeated.ack.packet_id);
    try publisher.disconnect(0);
    try subscriber.disconnect(0);

    thread.join();
    joined = true;
    if (serve.err) |err| return err;
}

test "MQTT Clean Start removes pending inbound QoS 2 transaction" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    const old = try broker.sessions.open(
        "qos2-clean-start",
        false,
        std.math.maxInt(u32),
        now,
    );
    const old_publisher_id = sessionRouteSubscriberId(old.route_id);
    _ = try broker.pending_qos2.record(
        old_publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "qos2/clean",
            .packet_id = 9,
            .payload = "discard",
        },
        now,
    );

    // Mirror register's Clean Start transition: opening a new Session changes
    // the stable route, then the old route's pending transactions are retired.
    const replacement = try broker.sessions.open(
        "qos2-clean-start",
        true,
        0,
        now,
    );
    try std.testing.expect(replacement.route_id != old.route_id);
    _ = broker.pending_qos2.removePublisher(old_publisher_id);
    try std.testing.expectEqual(@as(usize, 0), broker.pending_qos2.count());
}

fn sessionRouteSubscriberId(route_id: u64) u64 {
    return (@as(u64, 1) << 63) | route_id;
}

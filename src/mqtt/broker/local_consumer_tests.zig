const std = @import("std");
const mqtt = @import("../mod.zig");
const Broker = @import("../broker.zig").Broker;
const LocalConsumerAckAction = @import("local_consumer.zig").AckAction;
const LocalConsumerWake = @import("local_consumer.zig").Wake;

test "broker local consumer reports pending messages and signals arrivals" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{});
    defer broker.deinit();
    var wake: LocalConsumerWake = .{};
    var consumer = try broker.openLocalConsumer(.{
        .id = [_]u8{0x79} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "lazy/#",
            .qos = .at_least_once,
        }},
        .wake = &wake,
    });
    defer broker.closeLocalConsumer(&consumer);
    try std.testing.expectEqual(
        @as(usize, 0),
        try broker.localConsumerPendingCount(&consumer),
    );
    const generation = wake.observe();
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "lazy/value",
        .packet_id = null,
        .properties = &.{},
        .payload = "queued",
    });
    try wake.waitForChange(io, generation);
    try std.testing.expectEqual(
        @as(usize, 1),
        try broker.localConsumerPendingCount(&consumer),
    );
    var event = (try broker.pollLocalConsumer(&consumer)).?;
    defer event.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        try broker.localConsumerPendingCount(&consumer),
    );
    _ = try broker.acknowledgeLocalConsumer(
        &consumer,
        .puback,
        event.publish.value.packet_id.?,
        0,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try broker.localConsumerPendingCount(&consumer),
    );
}

test "broker local publication honors source consumer No Local" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{});
    defer broker.deinit();
    var source = try broker.openLocalConsumer(.{
        .id = [_]u8{0x71} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "duplex/#",
            .qos = .at_least_once,
            .no_local = true,
        }},
    });
    defer broker.closeLocalConsumer(&source);
    var observer = try broker.openLocalConsumer(.{
        .id = [_]u8{0x72} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "duplex/#",
            .qos = .at_least_once,
        }},
    });
    defer broker.closeLocalConsumer(&observer);

    try broker.publishLocalFromConsumer(&source, .{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "duplex/value",
        .packet_id = null,
        .properties = &.{},
        .payload = "one-way",
    });
    try std.testing.expect((try broker.pollLocalConsumer(&source)) == null);
    var event = (try broker.pollLocalConsumer(&observer)).?;
    defer event.deinit();
    try std.testing.expectEqualStrings(
        "one-way",
        event.publish.value.payload,
    );
    _ = try broker.acknowledgeLocalConsumer(
        &observer,
        .puback,
        event.publish.value.packet_id.?,
        0,
    );
}

fn publishValue(broker: *Broker, topic: []const u8, payload: []const u8, qos: mqtt.QoS) !void {
    try broker.publishLocal(.{
        .dup = false,
        .qos = qos,
        .retain = false,
        .topic = topic,
        .packet_id = null,
        .properties = &.{},
        .payload = payload,
    });
}

test "broker local consumer close restores pending QoS0 and rejects stale handles" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(allocator, threaded.io(), .{});
    defer broker.deinit();
    const options: @import("local_consumer.zig").Options = .{
        .id = [_]u8{0x71} ** 16,
        .subscriptions = &.{.{ .topic_filter = "reopen/#", .qos = .exactly_once }},
    };
    var first = try broker.openLocalConsumer(options);
    try publishValue(&broker, "reopen/one", "one", .at_least_once);
    try publishValue(&broker, "reopen/zero", "zero", .at_most_once);
    var one = (try broker.pollLocalConsumer(&first)).?;
    defer one.deinit();
    var zero = (try broker.pollLocalConsumer(&first)).?;
    defer zero.deinit();
    var stale = first;
    broker.closeLocalConsumer(&first);
    var resumed = try broker.openLocalConsumer(options);
    defer broker.closeLocalConsumer(&resumed);
    try std.testing.expect(resumed.session_present);
    try std.testing.expectError(error.LocalConsumerClosed, broker.pollLocalConsumer(&stale));
    try std.testing.expectError(error.LocalConsumerClosed, broker.completeLocalConsumerQoS0(&stale));
    try std.testing.expectError(error.LocalConsumerClosed, broker.retryLocalConsumerEvent(&stale, zero));
    try std.testing.expectError(error.LocalConsumerClosed, broker.acknowledgeLocalConsumer(
        &stale,
        .puback,
        one.publish.value.packet_id.?,
        0,
    ));
    broker.closeLocalConsumer(&stale);
    var replay_one = (try broker.pollLocalConsumer(&resumed)).?;
    defer replay_one.deinit();
    try std.testing.expect(replay_one.publish.value.dup);
    try std.testing.expectEqual(one.publish.value.packet_id, replay_one.publish.value.packet_id);
    try broker.retryLocalConsumerEvent(&resumed, replay_one);
    var retried_one = (try broker.pollLocalConsumer(&resumed)).?;
    defer retried_one.deinit();
    try std.testing.expect(retried_one.publish.value.dup);
    _ = try broker.acknowledgeLocalConsumer(&resumed, .puback, retried_one.publish.value.packet_id.?, 0);
    var replay_zero = (try broker.pollLocalConsumer(&resumed)).?;
    defer replay_zero.deinit();
    try std.testing.expectEqualStrings("zero", replay_zero.publish.value.payload);
    try std.testing.expect(replay_zero.publish.value.packet_id == null);
    try broker.completeLocalConsumerQoS0(&resumed);
    try std.testing.expect((try broker.pollLocalConsumer(&resumed)) == null);
}

test "broker clean local consumer replaces and discards Session state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(allocator, threaded.io(), .{});
    defer broker.deinit();
    const id = [_]u8{0x70} ** 16;
    var persistent = try broker.openLocalConsumer(.{
        .id = id,
        .subscriptions = &.{.{
            .topic_filter = "old/#",
            .qos = .at_least_once,
        }},
    });
    try publishValue(&broker, "old/queued", "discard", .at_least_once);
    broker.closeLocalConsumer(&persistent);

    var clean = try broker.openLocalConsumer(.{
        .id = id,
        .subscriptions = &.{.{
            .topic_filter = "new/#",
            .qos = .at_least_once,
        }},
        .clean_session = true,
    });
    try std.testing.expect(!clean.session_present);
    try std.testing.expect((try broker.pollLocalConsumer(&clean)) == null);
    try publishValue(&broker, "old/ignored", "old", .at_least_once);
    try std.testing.expect((try broker.pollLocalConsumer(&clean)) == null);
    try publishValue(&broker, "new/value", "new", .at_least_once);
    var event = (try broker.pollLocalConsumer(&clean)).?;
    defer event.deinit();
    try std.testing.expectEqualStrings("new", event.publish.value.payload);
    _ = try broker.acknowledgeLocalConsumer(
        &clean,
        .puback,
        event.publish.value.packet_id.?,
        0,
    );
    broker.closeLocalConsumer(&clean);

    var reopened = try broker.openLocalConsumer(.{
        .id = id,
        .subscriptions = &.{.{
            .topic_filter = "new/#",
            .qos = .at_least_once,
        }},
    });
    defer broker.closeLocalConsumer(&reopened);
    try std.testing.expect(!reopened.session_present);
    try std.testing.expect((try broker.pollLocalConsumer(&reopened)) == null);
}

test "broker clean local consumer removal is journaled" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const options: @import("local_consumer.zig").Options = .{
        .id = [_]u8{0x6f} ** 16,
        .subscriptions = &.{.{
            .topic_filter = "clean/#",
            .qos = .at_least_once,
        }},
    };
    {
        var broker = try Broker.init(allocator, io, .{});
        defer broker.deinit();
        try broker.createCommitLog(tmp.dir, "clean.log", .{});
        var persistent = try broker.openLocalConsumer(options);
        broker.closeLocalConsumer(&persistent);
        var clean_options = options;
        clean_options.clean_session = true;
        var clean = try broker.openLocalConsumer(clean_options);
        broker.closeLocalConsumer(&clean);
    }
    var restored = try Broker.init(allocator, io, .{});
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "clean.log", .{});
    var reopened = try restored.openLocalConsumer(options);
    defer restored.closeLocalConsumer(&reopened);
    try std.testing.expect(!reopened.session_present);
}

test "broker local consumer restores every QoS2 journal phase" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const options: @import("local_consumer.zig").Options = .{
        .id = [_]u8{0x72} ** 16,
        .subscriptions = &.{.{ .topic_filter = "phases/#", .qos = .exactly_once }},
    };
    for (0..3) |phase| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var packet_id: u16 = undefined;
        {
            var source = try Broker.init(allocator, io, .{});
            defer source.deinit();
            try source.createCommitLog(tmp.dir, "phases.log", .{});
            var consumer = try source.openLocalConsumer(options);
            defer source.closeLocalConsumer(&consumer);
            try publishValue(&source, "phases/value", "durable", .exactly_once);
            var event = (try source.pollLocalConsumer(&consumer)).?;
            defer event.deinit();
            packet_id = event.publish.value.packet_id.?;
            if (phase >= 1) {
                _ = try source.acknowledgeLocalConsumer(&consumer, .pubrec, packet_id, 0);
            }
            if (phase == 2) {
                var pubrel = (try source.pollLocalConsumer(&consumer)).?;
                defer pubrel.deinit();
                try std.testing.expectEqual(packet_id, pubrel.pubrel);
            }
        }
        {
            var restored = try Broker.init(allocator, io, .{});
            defer restored.deinit();
            try restored.restoreCommitLog(tmp.dir, "phases.log", .{});
            var consumer = try restored.openLocalConsumer(options);
            defer restored.closeLocalConsumer(&consumer);
            try std.testing.expect(consumer.session_present);
            var event = (try restored.pollLocalConsumer(&consumer)).?;
            defer event.deinit();
            if (phase == 0) {
                try std.testing.expect(event.publish.value.dup);
                try std.testing.expectEqual(packet_id, event.publish.value.packet_id.?);
                try std.testing.expectEqualStrings("durable", event.publish.value.payload);
                _ = try restored.acknowledgeLocalConsumer(&consumer, .pubrec, packet_id, 0);
                var pubrel = (try restored.pollLocalConsumer(&consumer)).?;
                defer pubrel.deinit();
                try std.testing.expectEqual(packet_id, pubrel.pubrel);
            } else {
                try std.testing.expectEqual(packet_id, event.pubrel);
            }
            _ = try restored.acknowledgeLocalConsumer(&consumer, .pubcomp, packet_id, 0);
        }
        var completed = try Broker.init(allocator, io, .{});
        defer completed.deinit();
        try completed.restoreCommitLog(tmp.dir, "phases.log", .{});
        var consumer = try completed.openLocalConsumer(options);
        defer completed.closeLocalConsumer(&consumer);
        try std.testing.expect((try completed.pollLocalConsumer(&consumer)) == null);
    }
}

test "broker local consumer receive maximum and negative ACK release credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(allocator, threaded.io(), .{});
    defer broker.deinit();
    var consumer = try broker.openLocalConsumer(.{
        .id = [_]u8{0x73} ** 16,
        .subscriptions = &.{.{ .topic_filter = "credit", .qos = .exactly_once }},
        .receive_maximum = 1,
    });
    defer broker.closeLocalConsumer(&consumer);
    try publishValue(&broker, "credit", "first", .exactly_once);
    try publishValue(&broker, "credit", "second", .exactly_once);
    var first = (try broker.pollLocalConsumer(&consumer)).?;
    defer first.deinit();
    try std.testing.expect((try broker.pollLocalConsumer(&consumer)) == null);
    const generation = broker.persistent_generation;
    try std.testing.expectError(error.InvalidReasonCode, broker.acknowledgeLocalConsumer(
        &consumer,
        .pubrec,
        first.publish.value.packet_id.?,
        0x95,
    ));
    try std.testing.expectEqual(generation, broker.persistent_generation);
    try std.testing.expect((try broker.pollLocalConsumer(&consumer)) == null);
    try std.testing.expectEqual(LocalConsumerAckAction.completed, try broker.acknowledgeLocalConsumer(
        &consumer,
        .pubrec,
        first.publish.value.packet_id.?,
        0x80,
    ));
    var second = (try broker.pollLocalConsumer(&consumer)).?;
    defer second.deinit();
    try std.testing.expectEqualStrings("second", second.publish.value.payload);
}

test "broker local consumer registration allocation failures roll back routes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testRegistrationAllocations, .{threaded.io()});
}

fn testRegistrationAllocations(allocator: std.mem.Allocator, io: std.Io) !void {
    var broker = try Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer broker.deinit();
    var consumer = broker.openLocalConsumer(.{
        .id = [_]u8{0x74} ** 16,
        .subscriptions = &.{
            .{ .topic_filter = "allocations/one", .qos = .at_least_once },
            .{ .topic_filter = "allocations/two", .qos = .exactly_once },
        },
    }) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), broker.router.subscriptionCount());
        try std.testing.expectEqual(@as(usize, 0), broker.local_consumer_routes.count());
        try std.testing.expectEqual(@as(usize, 0), broker.sessions.count());
        return err;
    };
    defer broker.closeLocalConsumer(&consumer);
}

test "broker local consumer failed poll allocations preserve delivery" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var offset: usize = 0;
    while (true) : (offset += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var broker = try Broker.init(failing.allocator(), threaded.io(), .{
            .limits = .{ .max_connections = 1 },
        });
        defer broker.deinit();
        var consumer = try broker.openLocalConsumer(.{
            .id = [_]u8{0x75} ** 16,
            .subscriptions = &.{.{ .topic_filter = "allocation", .qos = .at_least_once }},
        });
        defer broker.closeLocalConsumer(&consumer);
        var properties = [_]mqtt.Property{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "key",
            .value = "owned value",
        } }};
        try broker.publishLocal(.{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "allocation",
            .packet_id = null,
            .properties = &properties,
            .payload = "preserved",
        });
        failing.fail_index = failing.alloc_index + offset;
        var event = broker.pollLocalConsumer(&consumer) catch |err| blk: {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            break :blk try broker.pollLocalConsumer(&consumer);
        };
        defer if (event) |*value| value.deinit();
        try std.testing.expect(event != null);
        try std.testing.expect(!event.?.publish.value.dup);
        try std.testing.expectEqualStrings("preserved", event.?.publish.value.payload);
        try std.testing.expectEqualStrings("owned value", event.?.publish.value.properties[0].utf8_pair.value);
        _ = try broker.acknowledgeLocalConsumer(&consumer, .puback, event.?.publish.value.packet_id.?, 0);
        try std.testing.expect((try broker.pollLocalConsumer(&consumer)) == null);
        if (!failing.has_induced_failure) break;
    }
}

test "broker local consumer PUBREL waits for retry of failed journal write" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const options: @import("local_consumer.zig").Options = .{
        .id = [_]u8{0x76} ** 16,
        .subscriptions = &.{.{ .topic_filter = "journal", .qos = .exactly_once }},
    };
    var packet_id: u16 = undefined;
    {
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var broker = try Broker.init(failing.allocator(), io, .{});
        defer broker.deinit();
        try broker.createCommitLog(tmp.dir, "retry.log", .{});
        var consumer = try broker.openLocalConsumer(options);
        defer broker.closeLocalConsumer(&consumer);
        try publishValue(&broker, "journal", "payload", .exactly_once);
        var event = (try broker.pollLocalConsumer(&consumer)).?;
        defer event.deinit();
        packet_id = event.publish.value.packet_id.?;
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, broker.acknowledgeLocalConsumer(&consumer, .pubrec, packet_id, 0));
        try std.testing.expectError(error.OutOfMemory, broker.pollLocalConsumer(&consumer));
        failing.fail_index = std.math.maxInt(usize);
        var pubrel = (try broker.pollLocalConsumer(&consumer)).?;
        defer pubrel.deinit();
        try std.testing.expectEqual(packet_id, pubrel.pubrel);
    }
    var restored = try Broker.init(allocator, io, .{});
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "retry.log", .{});
    var consumer = try restored.openLocalConsumer(options);
    defer restored.closeLocalConsumer(&consumer);
    var replay = (try restored.pollLocalConsumer(&consumer)).?;
    defer replay.deinit();
    try std.testing.expectEqual(packet_id, replay.pubrel);
}

test "broker local consumer closed queues retain trusted identity" {
    const Policy = struct {
        fn publish(_: *anyopaque, _: mqtt.Connect, _: mqtt.Publish) bool {
            return false;
        }
        fn subscribe(_: *anyopaque, _: mqtt.Connect, _: mqtt.Subscription) bool {
            return false;
        }
        fn delivery(_: *anyopaque, _: @import("../broker.zig").DeliveryAuthorization) bool {
            return false;
        }
    };
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var context: u8 = 0;
    var broker = try Broker.init(allocator, threaded.io(), .{
        .access_control = .{
            .context = &context,
            .authorize_publish = Policy.publish,
            .authorize_subscribe = Policy.subscribe,
            .authorize_delivery = Policy.delivery,
        },
    });
    defer broker.deinit();
    const options: @import("local_consumer.zig").Options = .{
        .id = [_]u8{0x77} ** 16,
        .subscriptions = &.{.{ .topic_filter = "trusted", .qos = .exactly_once }},
    };
    var consumer = try broker.openLocalConsumer(options);
    broker.closeLocalConsumer(&consumer);
    try publishValue(&broker, "trusted", "offline zero", .at_most_once);
    try publishValue(&broker, "trusted", "offline one", .at_least_once);
    consumer = try broker.openLocalConsumer(options);
    defer broker.closeLocalConsumer(&consumer);
    var one = (try broker.pollLocalConsumer(&consumer)).?;
    defer one.deinit();
    try std.testing.expectEqualStrings("offline one", one.publish.value.payload);
    _ = try broker.acknowledgeLocalConsumer(&consumer, .puback, one.publish.value.packet_id.?, 0);
    try std.testing.expect((try broker.pollLocalConsumer(&consumer)) == null);
    try publishValue(&broker, "trusted", "online zero", .at_most_once);
    var zero = (try broker.pollLocalConsumer(&consumer)).?;
    defer zero.deinit();
    try std.testing.expectEqualStrings("online zero", zero.publish.value.payload);
    try broker.completeLocalConsumerQoS0(&consumer);
}

test "broker local consumer owns QoS0 QoS1 and QoS2 delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{});
    defer broker.deinit();
    var consumer = try broker.openLocalConsumer(.{
        .id = [_]u8{0x31} ** 16,
        .subscriptions = &.{
            .{ .topic_filter = "local/zero", .qos = .at_most_once },
            .{ .topic_filter = "local/one", .qos = .at_least_once },
            .{ .topic_filter = "local/two", .qos = .exactly_once },
        },
    });
    defer broker.closeLocalConsumer(&consumer);
    try std.testing.expect(!consumer.session_present);

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "local/zero",
        .packet_id = null,
        .properties = &.{},
        .payload = "zero",
    });
    var zero = (try broker.pollLocalConsumer(&consumer)).?;
    defer zero.deinit();
    try std.testing.expect(zero == .publish);
    try std.testing.expectEqualStrings("zero", zero.publish.value.payload);
    try std.testing.expect(zero.publish.value.packet_id == null);
    try broker.completeLocalConsumerQoS0(&consumer);

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "local/one",
        .packet_id = null,
        .properties = &.{},
        .payload = "one",
    });
    var one = (try broker.pollLocalConsumer(&consumer)).?;
    defer one.deinit();
    try std.testing.expect(one == .publish);
    try std.testing.expectEqualStrings("one", one.publish.value.payload);
    try std.testing.expectEqual(
        LocalConsumerAckAction.completed,
        try broker.acknowledgeLocalConsumer(
            &consumer,
            .puback,
            one.publish.value.packet_id.?,
            0,
        ),
    );

    try broker.publishLocal(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "local/two",
        .packet_id = null,
        .properties = &.{},
        .payload = "two",
    });
    var two = (try broker.pollLocalConsumer(&consumer)).?;
    defer two.deinit();
    try std.testing.expect(two == .publish);
    const packet_id = two.publish.value.packet_id.?;
    try std.testing.expectEqual(
        LocalConsumerAckAction.send_pubrel,
        try broker.acknowledgeLocalConsumer(
            &consumer,
            .pubrec,
            packet_id,
            0,
        ),
    );
    var pubrel = (try broker.pollLocalConsumer(&consumer)).?;
    try std.testing.expectEqual(packet_id, pubrel.pubrel);
    try broker.retryLocalConsumerEvent(&consumer, pubrel);
    pubrel.deinit();
    var retried_pubrel = (try broker.pollLocalConsumer(&consumer)).?;
    defer retried_pubrel.deinit();
    try std.testing.expectEqual(packet_id, retried_pubrel.pubrel);
    try std.testing.expectEqual(
        LocalConsumerAckAction.completed,
        try broker.acknowledgeLocalConsumer(
            &consumer,
            .pubcomp,
            packet_id,
            0,
        ),
    );
    try std.testing.expect((try broker.pollLocalConsumer(&consumer)) == null);
}

test "broker local consumer replays retained and retryable delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{});
    defer broker.deinit();
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = true,
        .topic = "retained/source",
        .packet_id = null,
        .properties = &.{},
        .payload = "retained",
    });
    const subscriptions = [_]mqtt.Subscription{.{
        .topic_filter = "retained/#",
        .qos = .at_least_once,
        .retain_as_published = true,
    }};
    var consumer = try broker.openLocalConsumer(.{
        .id = [_]u8{0x42} ** 16,
        .subscriptions = &subscriptions,
    });
    var first = (try broker.pollLocalConsumer(&consumer)).?;
    try std.testing.expect(first == .publish);
    try std.testing.expect(first.publish.value.retain);
    try std.testing.expectEqualStrings("retained", first.publish.value.payload);
    try broker.retryLocalConsumerEvent(&consumer, first);
    first.deinit();
    var retried = (try broker.pollLocalConsumer(&consumer)).?;
    defer retried.deinit();
    try std.testing.expect(retried == .publish);
    try std.testing.expect(!retried.publish.value.dup);
    try std.testing.expectEqual(
        LocalConsumerAckAction.completed,
        try broker.acknowledgeLocalConsumer(
            &consumer,
            .puback,
            retried.publish.value.packet_id.?,
            0,
        ),
    );
    broker.closeLocalConsumer(&consumer);
    try std.testing.expectError(
        error.LocalConsumerClosed,
        broker.pollLocalConsumer(&consumer),
    );
}

test "broker local consumer restores unacknowledged QoS1 from journal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const id = [_]u8{0x57} ** 16;
    const subscriptions = [_]mqtt.Subscription{.{
        .topic_filter = "durable/#",
        .qos = .at_least_once,
    }};

    var source = try Broker.init(allocator, io, .{});
    var source_owned = true;
    defer if (source_owned) source.deinit();
    try source.createCommitLog(tmp.dir, "local-consumer.log", .{});
    var first_consumer = try source.openLocalConsumer(.{
        .id = id,
        .subscriptions = &subscriptions,
    });
    try std.testing.expectError(
        error.LocalConsumerAlreadyOpen,
        source.openLocalConsumer(.{
            .id = id,
            .subscriptions = &subscriptions,
        }),
    );
    try source.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "durable/value",
        .packet_id = null,
        .properties = &.{},
        .payload = "before-crash",
    });
    var first = (try source.pollLocalConsumer(&first_consumer)).?;
    const packet_id = first.publish.value.packet_id.?;
    first.deinit();
    source.closeLocalConsumer(&first_consumer);
    source.deinit();
    source_owned = false;

    var restored = try Broker.init(allocator, io, .{});
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "local-consumer.log", .{});
    var consumer = try restored.openLocalConsumer(.{
        .id = id,
        .subscriptions = &subscriptions,
    });
    defer restored.closeLocalConsumer(&consumer);
    try std.testing.expect(consumer.session_present);
    var replay = (try restored.pollLocalConsumer(&consumer)).?;
    defer replay.deinit();
    try std.testing.expect(replay == .publish);
    try std.testing.expect(replay.publish.value.dup);
    try std.testing.expectEqual(packet_id, replay.publish.value.packet_id.?);
    try std.testing.expectEqualStrings(
        "before-crash",
        replay.publish.value.payload,
    );
    try std.testing.expectEqual(
        LocalConsumerAckAction.completed,
        try restored.acknowledgeLocalConsumer(
            &consumer,
            .puback,
            packet_id,
            0,
        ),
    );
}

test "broker local consumer identity binds its subscriptions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(allocator, threaded.io(), .{});
    defer broker.deinit();
    const id = [_]u8{0x68} ** 16;
    var consumer = try broker.openLocalConsumer(.{
        .id = id,
        .subscriptions = &.{.{
            .topic_filter = "first/#",
            .qos = .at_least_once,
        }},
    });
    broker.closeLocalConsumer(&consumer);
    try std.testing.expectError(
        error.LocalConsumerIdentityMismatch,
        broker.openLocalConsumer(.{
            .id = id,
            .subscriptions = &.{.{
                .topic_filter = "second/#",
                .qos = .at_least_once,
            }},
        }),
    );
}

test "broker local consumer ACK waits outside locks for provisional CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer broker.deinit();
    try broker.createCommitLog(tmp.dir, "admission.log", .{});
    var consumer = try broker.openLocalConsumer(.{ .id = [_]u8{0x78} ** 16, .subscriptions = &.{.{ .topic_filter = "admission", .qos = .at_least_once }} });
    defer broker.closeLocalConsumer(&consumer);
    try publishValue(&broker, "admission", "durable", .at_least_once);
    var event = (try broker.pollLocalConsumer(&consumer)).?;
    defer event.deinit();
    broker.slots[0].state.active = true;
    var task = struct {
        broker: *Broker,
        consumer: *@import("local_consumer.zig").Handle,
        packet_id: u16,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            _ = self.broker.acknowledgeLocalConsumer(self.consumer, .puback, self.packet_id, 0) catch |err| {
                self.err = err;
            };
        }
    }{ .broker = &broker, .consumer = &consumer, .packet_id = event.publish.value.packet_id.? };
    const thread = try std.Thread.spawn(.{}, @TypeOf(task).run, .{&task});
    var joined = false;
    defer if (!joined) {
        broker.state_mutex.lockUncancelable(io);
        broker.slots[0].state.active = false;
        broker.state_mutex.unlock(io);
        thread.join();
    };
    // Wait for ACK state to advance, then prove the persistence waiter released
    // the state mutex so admission can finish and unblock its journal barrier.
    const deadline = std.Io.Clock.awake.now(io).addDuration(.fromSeconds(2));
    while (true) {
        broker.state_mutex.lockUncancelable(io);
        const owned = broker.sessions.ownsPacketId(consumer.session, task.packet_id);
        broker.state_mutex.unlock(io);
        if (!owned) break;
        if (std.Io.Clock.awake.now(io).nanoseconds >= deadline.nanoseconds) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    broker.state_mutex.lockUncancelable(io);
    broker.slots[0].state.active = false;
    broker.state_mutex.unlock(io);
    thread.join();
    joined = true;
    if (task.err) |err| return err;
    broker.closeLocalConsumer(&consumer);
    var restored = try Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "admission.log", .{});
    var resumed = try restored.openLocalConsumer(.{ .id = [_]u8{0x78} ** 16, .subscriptions = &.{.{ .topic_filter = "admission", .qos = .at_least_once }} });
    defer restored.closeLocalConsumer(&resumed);
    try std.testing.expect((try restored.pollLocalConsumer(&resumed)) == null);
}

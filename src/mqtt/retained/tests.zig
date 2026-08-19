const std = @import("std");
const mqtt = @import("../mod.zig");
const retained = @import("mod.zig");

const Store = retained.Store;
const StoreResult = retained.StoreResult;
const Match = retained.Match;
const Delivery = retained.Delivery;

const second_ns: i96 = std.time.ns_per_s;

test "retained store applies only retained publishes and owns bytes" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.fromNanoseconds(10 * second_ns);

    var topic = [_]u8{ 's', 't', 'a', 't', 'e' };
    var payload = [_]u8{ 'o', 'n' };
    var user_key = [_]u8{'k'};
    var user_value = [_]u8{'v'};
    try std.testing.expectEqual(
        StoreResult.ignored,
        try store.applyPublish(&topic, &payload, .{
            .retain = false,
            .now = now,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), store.count());

    try std.testing.expectEqual(
        StoreResult.inserted,
        try store.applyPublish(&topic, &payload, .{
            .retain = true,
            .qos = .at_least_once,
            .properties = &.{
                .{ .utf8_pair = .{
                    .id = .user_property,
                    .key = &user_key,
                    .value = &user_value,
                } },
            },
            .now = now,
        }),
    );
    @memset(&topic, 'x');
    @memset(&payload, 'x');
    @memset(&user_key, 'x');
    @memset(&user_value, 'x');

    var matches: [1]Match = undefined;
    const found = try store.matchInto(
        "state",
        now,
        &matches,
    );
    try std.testing.expectEqualStrings("state", found[0].topic);
    try std.testing.expectEqualStrings("on", found[0].payload);
    try std.testing.expectEqualStrings(
        "k",
        found[0].properties[0].utf8_pair.key,
    );
    try std.testing.expectEqualStrings(
        "v",
        found[0].properties[0].utf8_pair.value,
    );
}

test "retained store replaces and deletes only with retained empty publish" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    try std.testing.expectEqual(
        StoreResult.inserted,
        try store.applyPublish("state", "one", .{
            .retain = true,
            .now = now,
        }),
    );
    try std.testing.expectEqual(
        StoreResult.replaced,
        try store.applyPublish("state", "two", .{
            .retain = true,
            .qos = .exactly_once,
            .now = now,
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), store.count());

    // This is where rumqttd's audited implementation diverges: an empty
    // non-retained live PUBLISH must not remove retained state.
    try std.testing.expectEqual(
        StoreResult.ignored,
        try store.applyPublish("state", "", .{
            .retain = false,
            .now = now,
        }),
    );
    var match_storage: [1]Match = undefined;
    const still_retained = try store.matchInto(
        "state",
        now,
        &match_storage,
    );
    try std.testing.expectEqualStrings(
        "two",
        still_retained[0].payload,
    );
    try std.testing.expectEqual(
        mqtt.QoS.exactly_once,
        still_retained[0].qos,
    );

    try std.testing.expectEqual(
        StoreResult.removed,
        try store.applyPublish("state", "", .{
            .retain = true,
            .now = now,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "retained deliveries implement MQTT 5 retain handling and shared rule" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("sensors/one", "one", .{
        .retain = true,
        .qos = .exactly_once,
        .now = now,
    });
    _ = try store.applyPublish("sensors/two", "two", .{
        .retain = true,
        .qos = .at_most_once,
        .now = now,
    });

    var deliveries: [2]Delivery = undefined;
    const always = try store.deliveriesInto(.{
        .topic_filter = "sensors/+",
        .qos = .at_least_once,
        .retain_as_published = false,
        .retain_handling = 0,
    }, .{ .subscription_existed = true }, now, &deliveries);
    try std.testing.expectEqual(@as(usize, 2), always.len);
    try std.testing.expect(always[0].retain);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        always[0].qos,
    );
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        always[1].qos,
    );

    const new_only = mqtt.Subscription{
        .topic_filter = "sensors/+",
        .retain_handling = 1,
    };
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.deliveriesInto(
            new_only,
            .{ .subscription_existed = true },
            now,
            &deliveries,
        )).len,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        (try store.deliveriesInto(
            new_only,
            .{},
            now,
            &deliveries,
        )).len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.deliveriesInto(.{
            .topic_filter = "sensors/+",
            .retain_handling = 2,
        }, .{}, now, &deliveries)).len,
    );
    // MQTT 5 §3.8.4 explicitly sends no retained messages for shared
    // subscriptions, regardless of whether the shared group already existed.
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.deliveriesInto(.{
            .topic_filter = "$share/workers/sensors/+",
        }, .{}, now, &deliveries)).len,
    );
}

test "retained expiry is transactional and updates encoded property" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const stored_at = std.Io.Timestamp.fromNanoseconds(5 * second_ns);
    _ = try store.applyPublish("expiring", "value", .{
        .retain = true,
        .qos = .at_least_once,
        .properties = &.{
            .{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 10,
            } },
            .{ .utf8 = .{
                .id = .content_type,
                .value = "text/plain",
            } },
        },
        .now = stored_at,
    });

    var deliveries: [1]Delivery = undefined;
    const seven_seconds = std.Io.Timestamp.fromNanoseconds(
        12 * second_ns,
    );
    const active = try store.deliveriesInto(.{
        .topic_filter = "expiring",
        .qos = .exactly_once,
    }, .{
        .subscription_identifier = 7,
    }, seven_seconds, &deliveries);
    try std.testing.expectEqual(@as(?u32, 3), active[0].message_expiry_interval);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try active[0].writePublish(
        &encoded,
        allocator,
        .v5,
        42,
    );
    var publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        encoded.items,
    );
    defer publish.deinit(allocator);
    try std.testing.expectEqual(
        @as(?u32, 3),
        mqtt.messageExpiryInterval(publish.properties),
    );
    try std.testing.expectEqual(
        @as(?usize, 7),
        mqtt.subscriptionIdentifier(publish.properties),
    );
    try std.testing.expect(publish.retain);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        publish.qos,
    );

    const expired_at = std.Io.Timestamp.fromNanoseconds(
        15 * second_ns,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.matchInto(
            "expiring",
            expired_at,
            &[_]Match{},
        )).len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        store.pruneExpired(expired_at),
    );
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "retained store strips connection-scoped topic alias" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("aliased/topic", "value", .{
        .retain = true,
        .properties = &.{
            .{ .two_byte = .{
                .id = .topic_alias,
                .value = 1,
            } },
            .{ .utf8 = .{
                .id = .content_type,
                .value = "text/plain",
            } },
        },
        .now = now,
    });
    var matches: [1]Match = undefined;
    const found = try store.matchInto(
        "aliased/topic",
        now,
        &matches,
    );
    try std.testing.expectEqual(@as(usize, 1), found[0].properties.len);
    try std.testing.expectEqual(
        mqtt.PropertyId.content_type,
        found[0].properties[0].utf8.id,
    );

    try std.testing.expectError(
        error.InvalidProperty,
        store.applyPublish("invalid/subscription-id", "value", .{
            .retain = true,
            .properties = &.{
                .{ .varint = .{
                    .id = .subscription_identifier,
                    .value = 1,
                } },
            },
            .now = now,
        }),
    );
}

test "retained delivery applies no-local using stored publisher identity" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("bridge/state", "value", .{
        .retain = true,
        .publisher_id = 42,
        .now = now,
    });

    var deliveries: [1]Delivery = undefined;
    const subscription = mqtt.Subscription{
        .topic_filter = "bridge/state",
        .no_local = true,
    };
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.deliveriesInto(subscription, .{
            .subscriber_id = 42,
        }, now, &deliveries)).len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (try store.deliveriesInto(subscription, .{
            .subscriber_id = 43,
        }, now, &deliveries)).len,
    );
}

test "retained matchInto is allocation free and exact capacity" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("a/one", "1", .{
        .retain = true,
        .now = now,
    });
    _ = try store.applyPublish("a/two", "2", .{
        .retain = true,
        .now = now,
    });
    _ = try store.applyPublish("$SYS/uptime", "3", .{
        .retain = true,
        .now = now,
    });

    var too_small: [1]Match = undefined;
    try std.testing.expectError(
        error.MatchBufferTooSmall,
        store.matchInto("a/+", now, &too_small),
    );

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const saved_allocator = store.allocator;
    store.allocator = no_alloc.allocator();
    defer store.allocator = saved_allocator;
    var enough: [2]Match = undefined;
    const matches = try store.matchInto("a/#", now, &enough);
    try std.testing.expectEqual(@as(usize, 2), matches.len);
    try std.testing.expect(!no_alloc.has_induced_failure);

    // Capacity for the full retained store selects the one-pass wildcard
    // emitter even when expiry and the leading-$ rule reduce actual matches.
    var full_capacity: [3]Match = undefined;
    const one_pass = try store.matchInto("a/+", now, &full_capacity);
    try std.testing.expectEqual(@as(usize, 2), one_pass.len);

    // MQTT's leading-wildcard `$` rule applies to retained matching too.
    var system: [1]Match = undefined;
    const non_system = try store.matchInto("#", now, &enough);
    try std.testing.expectEqual(
        @as(usize, 2),
        non_system.len,
    );
    for (non_system) |match| {
        try std.testing.expect(!std.mem.startsWith(
            u8,
            match.topic,
            "$",
        ));
    }
    try std.testing.expectEqual(
        @as(usize, 1),
        (try store.matchInto("$SYS/#", now, &system)).len,
    );
}

test "retained delivery full-capacity wildcard fast path preserves filters" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("bridge/one", "1", .{
        .retain = true,
        .publisher_id = 42,
        .now = now,
    });
    _ = try store.applyPublish("bridge/two", "2", .{
        .retain = true,
        .publisher_id = 43,
        .now = now,
    });
    _ = try store.applyPublish("other/two", "3", .{
        .retain = true,
        .publisher_id = 43,
        .now = now,
    });

    var out: [3]Delivery = undefined;
    const deliveries = try store.deliveriesInto(.{
        .topic_filter = "bridge/+",
        .no_local = true,
        .qos = .at_least_once,
    }, .{
        .subscriber_id = 42,
        .subscription_identifier = 9,
    }, now, &out);
    try std.testing.expectEqual(@as(usize, 1), deliveries.len);
    try std.testing.expectEqualStrings("bridge/two", deliveries[0].topic);
    try std.testing.expectEqual(@as(?usize, 9), deliveries[0].subscription_identifier);
}

test "retained limits and failed replacement preserve old entry" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_messages = 1,
        .max_message_bytes = 128,
        .max_total_bytes = 128,
    });
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("state", "small", .{
        .retain = true,
        .now = now,
    });
    try std.testing.expectError(
        error.RetainedLimitExceeded,
        store.applyPublish("other", "value", .{
            .retain = true,
            .now = now,
        }),
    );
    var huge: [256]u8 = undefined;
    @memset(&huge, 'x');
    try std.testing.expectError(
        error.RetainedLimitExceeded,
        store.applyPublish("state", &huge, .{
            .retain = true,
            .now = now,
        }),
    );
    var matches: [1]Match = undefined;
    const found = try store.matchInto("state", now, &matches);
    try std.testing.expectEqualStrings("small", found[0].payload);
}

test "retained store allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testRetainedAllocationFailures,
        .{},
    );
}

fn testRetainedAllocationFailures(
    allocator: std.mem.Allocator,
) !void {
    var store = Store.init(allocator, .{});
    defer store.deinit();
    _ = try store.applyPublish("state/topic", "payload", .{
        .retain = true,
        .qos = .exactly_once,
        .properties = &.{
            .{ .binary = .{
                .id = .correlation_data,
                .value = "correlation",
            } },
            .{ .utf8_pair = .{
                .id = .user_property,
                .key = "key",
                .value = "value",
            } },
        },
        .now = std.Io.Timestamp.zero,
    });
}

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
    const upgraded = try store.deliveriesInto(.{
        .topic_filter = "sensors/two",
        .qos = .at_least_once,
    }, .{ .upgrade_outgoing_qos = true }, now, &deliveries);
    try std.testing.expectEqual(@as(usize, 1), upgraded.len);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        upgraded[0].qos,
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

test "retained store owns and exposes source client identity" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    var source = [_]u8{ 'w', 'r', 'i', 't', 'e', 'r' };
    var username = [_]u8{ 'a', 'l', 'i', 'c', 'e' };
    _ = try store.applyPublish("source/state", "value", .{
        .retain = true,
        .source_client_id = &source,
        .source_username = &username,
        .source_listener_id = 1883,
        .now = .zero,
    });
    source[0] = 'X';
    username[0] = 'X';

    var matches: [1]Match = undefined;
    const matched = try store.matchInto(
        "source/state",
        .zero,
        &matches,
    );
    try std.testing.expectEqualStrings(
        "writer",
        matched[0].source_client_id.?,
    );
    try std.testing.expectEqualStrings(
        "alice",
        matched[0].source_username.?,
    );
    try std.testing.expectEqual(@as(?u64, 1883), matched[0].source_listener_id);
    var deliveries: [1]Delivery = undefined;
    const replay = try store.deliveriesInto(
        .{ .topic_filter = "source/#" },
        .{},
        .zero,
        &deliveries,
    );
    try std.testing.expectEqualStrings(
        "writer",
        replay[0].source_client_id.?,
    );
    try std.testing.expectEqualStrings(
        "alice",
        replay[0].source_username.?,
    );
    try std.testing.expectEqual(@as(?u64, 1883), replay[0].source_listener_id);
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        replay[0].source_qos,
    );
}

test "retained store rejects source context without a client identity" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        store.applyPublish("source/invalid", "value", .{
            .retain = true,
            .source_username = "alice",
            .now = .zero,
        }),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        store.applyPublish("source/invalid", "value", .{
            .retain = true,
            .source_listener_id = 1883,
            .now = .zero,
        }),
    );
}

test "retained no-local survives a stable route identity change" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    _ = try store.applyPublish("source/no-local", "value", .{
        .retain = true,
        .publisher_id = 7,
        .source_client_id = "same-client",
        .now = .zero,
    });

    var deliveries: [1]Delivery = undefined;
    const replay = try store.deliveriesInto(
        .{
            .topic_filter = "source/no-local",
            .no_local = true,
        },
        .{
            .subscriber_id = 99,
            .subscriber_client_id = "same-client",
        },
        .zero,
        &deliveries,
    );
    try std.testing.expectEqual(@as(usize, 0), replay.len);
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

test "retained wildcard matching keeps entry order across slot reuse" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;
    _ = try store.applyPublish("a/z", "1", .{ .retain = true, .now = now });
    _ = try store.applyPublish("a/m", "2", .{ .retain = true, .now = now });
    _ = try store.applyPublish("a/a", "3", .{ .retain = true, .now = now });

    var matches: [3]Match = undefined;
    const found = try store.matchInto("a/+", now, &matches);
    try std.testing.expectEqual(@as(usize, 3), found.len);
    try std.testing.expectEqualStrings("a/z", found[0].topic);
    try std.testing.expectEqualStrings("a/m", found[1].topic);
    try std.testing.expectEqualStrings("a/a", found[2].topic);

    // Removing the middle entry and reusing its slot must keep table order.
    try std.testing.expect(store.remove("a/m"));
    _ = try store.applyPublish("a/x", "4", .{ .retain = true, .now = now });
    const reordered = try store.matchInto("a/#", now, &matches);
    try std.testing.expectEqual(@as(usize, 3), reordered.len);
    try std.testing.expectEqualStrings("a/z", reordered[0].topic);
    try std.testing.expectEqualStrings("a/x", reordered[1].topic);
    try std.testing.expectEqualStrings("a/a", reordered[2].topic);
}

test "retained wildcard matching handles very deep filters" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    var topic_buffer: [512]u8 = undefined;
    var filter_buffer: [512]u8 = undefined;
    var wrong_buffer: [512]u8 = undefined;
    const topic = try writeDeepTopic(&topic_buffer, 70, "leaf");
    const plus_filter = try writeDeepPlusFilter(&filter_buffer, 70);
    _ = try store.applyPublish(topic, "deep", .{
        .retain = true,
        .now = now,
    });

    var matches: [1]Match = undefined;
    const found = try store.matchInto(plus_filter, now, &matches);
    try std.testing.expectEqual(@as(usize, 1), found.len);
    try std.testing.expectEqualStrings(topic, found[0].topic);

    const exact = try store.matchInto(topic, now, &matches);
    try std.testing.expectEqual(@as(usize, 1), exact.len);

    const wrong = try writeDeepTopic(&wrong_buffer, 70, "other");
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.matchInto(wrong, now, &matches)).len,
    );

    // Deep filters allocate their traversal state on the heap. Both the level
    // array and the frame stack fall back to the linear scan when allocation
    // fails, so the match result must be identical in every case.
    for ([_]usize{ 0, 1 }) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = fail_index },
        );
        const saved = store.allocator;
        store.allocator = failing.allocator();
        defer store.allocator = saved;
        const fallback = try store.matchInto(plus_filter, now, &matches);
        try std.testing.expectEqual(@as(usize, 1), fallback.len);
        try std.testing.expectEqualStrings(topic, fallback[0].topic);
    }
}

test "retained index budget bounds deep topic amplification" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{
        .max_index_bytes = 1024,
    });
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    var topic_buffer: [4096]u8 = undefined;
    const deep = try writeDeepTopic(&topic_buffer, 40, "leaf");
    try std.testing.expectError(
        error.RetainedLimitExceeded,
        store.applyPublish(deep, "payload", .{
            .retain = true,
            .now = now,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), store.count());
    try std.testing.expectEqual(@as(usize, 0), store.indexBytes());

    _ = try store.applyPublish("a/b", "1", .{
        .retain = true,
        .now = now,
    });
    const shallow_index = store.indexBytes();
    try std.testing.expect(shallow_index > 0);

    try std.testing.expect(store.remove("a/b"));
    const retained_root = store.indexBytes();
    try std.testing.expect(retained_root < shallow_index);

    _ = try store.applyPublish("c/d", "2", .{
        .retain = true,
        .now = now,
    });
    try std.testing.expectEqual(shallow_index, store.indexBytes());
}

fn writeDeepTopic(
    buffer: []u8,
    levels: usize,
    last: []const u8,
) ![]const u8 {
    var used: usize = 0;
    for (0..levels - 1) |index| {
        const piece = try std.fmt.bufPrint(buffer[used..], "{s}l{d}", .{
            if (index == 0) "" else "/",
            index,
        });
        used += piece.len;
    }
    const tail = try std.fmt.bufPrint(buffer[used..], "/{s}", .{last});
    used += tail.len;
    return buffer[0..used];
}

fn writeDeepPlusFilter(buffer: []u8, levels: usize) ![]const u8 {
    var used: usize = 0;
    for (0..levels - 1) |index| {
        const piece = try std.fmt.bufPrint(buffer[used..], "{s}l{d}", .{
            if (index == 0) "" else "/",
            index,
        });
        used += piece.len;
    }
    const tail = try std.fmt.bufPrint(buffer[used..], "/+", .{});
    used += tail.len;
    return buffer[0..used];
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
        .source_client_id = "allocated-client",
        .source_username = "allocated-user",
        .source_listener_id = 1883,
        .now = std.Io.Timestamp.zero,
    });
}

test "retained deep wildcard matching covers sibling and subtree branches" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator, .{});
    defer store.deinit();
    const now = std.Io.Timestamp.zero;

    var topic_a_buffer: [1024]u8 = undefined;
    var topic_b_buffer: [1024]u8 = undefined;
    var filter_buffer: [1024]u8 = undefined;
    const topic_a = try writeDeepTopic(&topic_a_buffer, 70, "a");
    const topic_b = try writeDeepTopic(&topic_b_buffer, 70, "b");
    const plus_filter = try writeDeepPlusFilter(&filter_buffer, 70);
    _ = try store.applyPublish(topic_a, "a", .{
        .retain = true,
        .now = now,
    });
    _ = try store.applyPublish(topic_b, "b", .{
        .retain = true,
        .now = now,
    });

    var matches: [2]Match = undefined;
    const found = try store.matchInto(plus_filter, now, &matches);
    try std.testing.expectEqual(@as(usize, 2), found.len);

    var deeper_buffer: [1024]u8 = undefined;
    var hash_buffer: [1024]u8 = undefined;
    const deeper = try writeDeepTopic(&deeper_buffer, 80, "leaf");
    const hash_filter = try writeDeepTopic(&hash_buffer, 70, "#");
    _ = try store.applyPublish(deeper, "deep", .{
        .retain = true,
        .now = now,
    });

    var hash_matches: [3]Match = undefined;
    const hash_found = try store.matchInto(hash_filter, now, &hash_matches);
    try std.testing.expectEqual(@as(usize, 3), hash_found.len);
    try std.testing.expectEqualStrings(deeper, hash_found[2].topic);
}

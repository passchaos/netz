const std = @import("std");
const router_root = @import("../router.zig");

const mqtt = @import("../mod.zig");

const Match = router_root.Match;
const Router = router_root.Router;
const SubscriberId = router_root.SubscriberId;
const testSubscriptionAllocationFailures = router_root.testSubscriptionAllocationFailures;

test "MQTT router matches literal and wildcard subscriptions" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "sensors/temperature" });
    try router.subscribe(2, .{ .topic_filter = "sensors/+" });
    try router.subscribe(3, .{ .topic_filter = "sensors/#" });
    try router.subscribe(4, .{ .topic_filter = "+/temperature" });
    try router.subscribe(5, .{ .topic_filter = "$SYS/#" });
    try router.subscribe(6, .{ .topic_filter = "#" });

    var storage: [8]Match = undefined;
    const matches = try router.matchInto("sensors/temperature", &storage);
    try std.testing.expectEqual(@as(usize, 5), matches.len);
    var saw_exact = false;
    var saw_single = false;
    var saw_leading_single = false;
    var saw_prefix_multi = false;
    var saw_global = false;
    for (matches) |match| {
        if (match.subscriber_id == 1) saw_exact = true;
        if (match.subscriber_id == 2) saw_single = true;
        if (match.subscriber_id == 4) saw_leading_single = true;
        if (match.subscriber_id == 3) saw_prefix_multi = true;
        if (match.subscriber_id == 6) saw_global = true;
    }
    try std.testing.expect(saw_exact and saw_single and saw_leading_single and saw_prefix_multi and saw_global);

    const system = try router.matchInto("$SYS/uptime", &storage);
    try std.testing.expectEqual(@as(usize, 1), system.len);
    try std.testing.expectEqual(@as(SubscriberId, 5), system[0].subscriber_id);
}

test "MQTT router full-capacity normal fast path matches bounded count path" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "jobs/ready" });
    try router.subscribe(2, .{ .topic_filter = "jobs/+" });
    try router.subscribe(3, .{
        .topic_filter = "jobs/ready",
        .no_local = true,
    });
    try router.subscribe(4, .{ .topic_filter = "other/topic" });

    var full_storage: [4]Match = undefined;
    const fast = try router.matchIntoForPublisher(
        "jobs/ready",
        3,
        &full_storage,
    );
    // Capacity below subscriptionCount() forces the count-before-emit path,
    // while still fitting every actual match after No Local and topic checks.
    var bounded_storage: [3]Match = undefined;
    const bounded = try router.matchIntoForPublisher(
        "jobs/ready",
        3,
        &bounded_storage,
    );

    try std.testing.expectEqual(@as(usize, 2), fast.len);
    try std.testing.expectEqual(fast.len, bounded.len);
    for (fast, bounded) |fast_match, bounded_match| {
        try std.testing.expectEqual(
            fast_match.subscriber_id,
            bounded_match.subscriber_id,
        );
        try std.testing.expectEqualStrings(
            fast_match.subscription.topic_filter,
            bounded_match.subscription.topic_filter,
        );
    }
}

test "MQTT router combined trie preserves normal and shared ordering" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();
    try router.subscribe(1, .{ .topic_filter = "devices/+/state" });
    try router.subscribe(2, .{ .topic_filter = "devices/#" });
    try router.subscribe(10, .{
        .topic_filter = "$share/work/devices/+/state",
    });
    try router.subscribe(11, .{
        .topic_filter = "$share/work/devices/+/state",
    });

    var storage: [3]Match = undefined;
    const first = try router.matchInto("devices/a/state", &storage);
    try std.testing.expectEqual(@as(usize, 3), first.len);
    try std.testing.expectEqual(@as(SubscriberId, 2), first[0].subscriber_id);
    try std.testing.expectEqual(@as(SubscriberId, 1), first[1].subscriber_id);
    try std.testing.expectEqual(@as(SubscriberId, 10), first[2].subscriber_id);

    try std.testing.expectError(
        error.MatchBufferTooSmall,
        router.matchInto("devices/b/state", storage[0..2]),
    );
    const second = try router.matchInto("devices/b/state", &storage);
    // Capacity preflight is cursor-neutral despite sharing the trie pass.
    try std.testing.expectEqual(@as(SubscriberId, 11), second[2].subscriber_id);
}

test "MQTT router shared subscriptions round robin per filter" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(10, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(11, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(12, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(20, .{ .topic_filter = "$share/other/jobs/+" });

    var storage: [4]Match = undefined;
    const expected = [_]SubscriberId{ 10, 11, 12, 10 };
    for (expected) |subscriber| {
        const matches = try router.matchInto("jobs/one", &storage);
        try std.testing.expectEqual(@as(usize, 2), matches.len);
        try std.testing.expectEqual(subscriber, matches[0].subscriber_id);
        try std.testing.expectEqual(@as(SubscriberId, 20), matches[1].subscriber_id);
    }
}

test "MQTT router shared subscription strategies are configurable" {
    const allocator = std.testing.allocator;

    var sticky = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .sticky,
    });
    defer sticky.deinit();
    for (10..13) |subscriber_id| {
        try sticky.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
    }
    var storage: [1]Match = undefined;
    for (0..8) |_| {
        const matches = try sticky.matchInto("jobs/one", &storage);
        try std.testing.expectEqual(
            @as(SubscriberId, 10),
            matches[0].subscriber_id,
        );
    }

    var random_a = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 0x1234_5678,
    });
    defer random_a.deinit();
    var random_b = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 0x1234_5678,
    });
    defer random_b.deinit();
    for (10..13) |subscriber_id| {
        try random_a.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
        try random_b.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
    }
    var saw: [3]bool = .{ false, false, false };
    for (0..32) |_| {
        const first = try random_a.matchInto("jobs/random", &storage);
        const first_id = first[0].subscriber_id;
        var second_storage: [1]Match = undefined;
        const second = try random_b.matchInto(
            "jobs/random",
            &second_storage,
        );
        try std.testing.expectEqual(
            first_id,
            second[0].subscriber_id,
        );
        saw[first_id - 10] = true;
    }
    try std.testing.expect(saw[0] and saw[1] and saw[2]);
}

test "MQTT router random capacity failure preserves scheduler state" {
    const allocator = std.testing.allocator;
    var reference = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 42,
    });
    defer reference.deinit();
    var probed = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 42,
    });
    defer probed.deinit();
    for (1..4) |subscriber_id| {
        try reference.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/g/tasks/+" },
        );
        try probed.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/g/tasks/+" },
        );
    }
    // Add one ordinary match so empty storage fails after both count passes.
    try reference.subscribe(100, .{ .topic_filter = "tasks/#" });
    try probed.subscribe(100, .{ .topic_filter = "tasks/#" });

    try std.testing.expectError(
        error.MatchBufferTooSmall,
        probed.matchInto("tasks/a", &.{}),
    );
    var reference_storage: [2]Match = undefined;
    var probed_storage: [2]Match = undefined;
    const expected = try reference.matchInto("tasks/a", &reference_storage);
    const actual = try probed.matchInto("tasks/a", &probed_storage);
    try std.testing.expectEqual(
        expected[1].subscriber_id,
        actual[1].subscriber_id,
    );
}

test "MQTT router rendezvous strategy is stable and low-remapping" {
    const allocator = std.testing.allocator;
    var router = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .rendezvous_hash,
    });
    defer router.deinit();
    for (1..4) |subscriber_id| {
        try router.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
    }

    var before: [256]SubscriberId = undefined;
    var storage: [1]Match = undefined;
    var topic_buffer: [32]u8 = undefined;
    for (&before, 0..) |*selected, topic_index| {
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "jobs/{d}",
            .{topic_index},
        );
        const first = try router.matchInto(topic, &storage);
        const first_id = first[0].subscriber_id;
        var second_storage: [1]Match = undefined;
        const second = try router.matchInto(topic, &second_storage);
        try std.testing.expectEqual(
            first_id,
            second[0].subscriber_id,
        );
        selected.* = first_id;
    }

    try router.subscribe(
        4,
        .{ .topic_filter = "$share/workers/jobs/+" },
    );
    var remapped: usize = 0;
    for (before, 0..) |previous, topic_index| {
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "jobs/{d}",
            .{topic_index},
        );
        const selected = (try router.matchInto(topic, &storage))[0]
            .subscriber_id;
        if (selected != previous) {
            remapped += 1;
            // Rendezvous hashing can only remap an existing key to the newly
            // added member, unlike modulo hashing which reshuffles old peers.
            try std.testing.expectEqual(@as(SubscriberId, 4), selected);
        }
    }
    try std.testing.expect(remapped > 0);
    try std.testing.expect(remapped < before.len / 2);
}

test "MQTT router indexes shared groups by trie representative" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(10, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(11, .{ .topic_filter = "$share/workers/jobs/+" });

    const jobs_node, const jobs_multi = router.findFilterPath("jobs/+").?;
    try std.testing.expect(!jobs_multi);
    try std.testing.expectEqual(@as(usize, 1), router.nodes.items[jobs_node].terminal_entries.items.len);
    const jobs_group_index = router.findSharedGroup("workers", "jobs/+").?;

    var storage: [2]Match = undefined;
    const first = try router.matchInto("jobs/one", &storage);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(SubscriberId, 10), first[0].subscriber_id);

    // The trie stores one representative per shared group. Removing that
    // representative must swap in another live member so future matches stay
    // indexed and do not fall back to a scan over every shared group.
    try router.unsubscribe(10, "$share/workers/jobs/+");
    try std.testing.expectEqual(@as(usize, 1), router.nodes.items[jobs_node].terminal_entries.items.len);
    const second = try router.matchInto("jobs/two", &storage);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(@as(SubscriberId, 11), second[0].subscriber_id);

    try router.subscribe(12, .{ .topic_filter = "$share/workers/jobs/+" });
    try std.testing.expectEqual(@as(usize, 1), router.nodes.items[jobs_node].terminal_entries.items.len);
    const third = try router.matchInto("jobs/three", &storage);
    try std.testing.expectEqual(@as(SubscriberId, 11), third[0].subscriber_id);
    const fourth = try router.matchInto("jobs/four", &storage);
    try std.testing.expectEqual(@as(SubscriberId, 12), fourth[0].subscriber_id);

    try router.unsubscribe(11, "$share/workers/jobs/+");
    try router.unsubscribe(12, "$share/workers/jobs/+");
    try std.testing.expectEqual(@as(usize, 0), router.nodes.items[jobs_node].terminal_entries.items.len);
    try std.testing.expect(router.shared_groups.items[jobs_group_index] == null);

    try router.subscribe(20, .{ .topic_filter = "$share/audit/alerts/#" });
    try std.testing.expectEqual(jobs_group_index, router.findSharedGroup("audit", "alerts/#").?);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    const alert = try router.matchInto("alerts/security/high", &storage);
    try std.testing.expectEqual(@as(usize, 1), alert.len);
    try std.testing.expectEqual(@as(SubscriberId, 20), alert[0].subscriber_id);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router unsubscribe preserves shared cursor safety" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "$share/g/a/#" });
    try router.subscribe(2, .{ .topic_filter = "$share/g/a/#" });
    var storage: [2]Match = undefined;
    _ = try router.matchInto("a/b", &storage);
    try router.unsubscribe(2, "$share/g/a/#");
    const matches = try router.matchInto("a/c", &storage);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(SubscriberId, 1), matches[0].subscriber_id);
}

test "MQTT router cached subscription counts track replacement and removal" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try std.testing.expectEqual(@as(usize, 0), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), router.sharedSubscriptionCount());

    try router.subscribe(1, .{ .topic_filter = "devices/+" });
    try router.subscribe(2, .{ .topic_filter = "$share/work/devices/#" });
    try router.subscribe(3, .{ .topic_filter = "$share/work/devices/#" });
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());

    try std.testing.expectError(
        error.InvalidSubscription,
        router.subscribe(4, .{
            .topic_filter = "$share/work/devices/#",
            .no_local = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());

    try router.subscribe(2, .{
        .topic_filter = "$share/work/devices/#",
        .qos = .exactly_once,
    });
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());

    try router.unsubscribe(2, "$share/work/devices/#");
    try std.testing.expectEqual(@as(usize, 2), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), router.sharedSubscriptionCount());

    try std.testing.expectEqual(@as(usize, 1), try router.removeSubscriber(1));
    try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), router.sharedSubscriptionCount());

    try std.testing.expectEqual(@as(usize, 1), try router.removeSubscriber(3));
    try std.testing.expectEqual(@as(usize, 0), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), router.sharedSubscriptionCount());
}

test "MQTT router replaces repeated subscription options" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "a/+", .qos = .at_most_once });
    try router.subscribe(1, .{
        .topic_filter = "a/+",
        .qos = .exactly_once,
        .no_local = true,
        .retain_as_published = true,
        .retain_handling = 2,
    });
    try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());

    var storage: [1]Match = undefined;
    const matches = try router.matchIntoForPublisher("a/b", 2, &storage);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, matches[0].subscription.qos);
    try std.testing.expect(matches[0].subscription.no_local);
    try std.testing.expect(matches[0].subscription.retain_as_published);
    try std.testing.expectEqual(@as(u2, 2), matches[0].subscription.retain_handling);
}

test "MQTT router subscribeWithStatus reports replacement atomically" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try std.testing.expect(!(try router.subscribeWithIdentifierStatus(1, .{
        .topic_filter = "state/+",
        .retain_handling = 1,
    }, 7)));
    try std.testing.expect(try router.subscribeWithIdentifierStatus(1, .{
        .topic_filter = "state/+",
        .qos = .at_least_once,
        .retain_handling = 1,
    }, 9));
    try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
    var matches: [1]Match = undefined;
    const routed = try router.matchInto("state/value", &matches);
    try std.testing.expectEqual(
        @as(?usize, 9),
        routed[0].subscription_identifier,
    );
}

test "MQTT router enforces no-local semantics" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "events/#", .no_local = true });
    try router.subscribe(2, .{ .topic_filter = "events/#" });
    try std.testing.expectError(
        error.InvalidSubscription,
        router.subscribe(3, .{ .topic_filter = "$share/g/events/#", .no_local = true }),
    );

    var storage: [2]Match = undefined;
    const own = try router.matchIntoForPublisher("events/one", 1, &storage);
    try std.testing.expectEqual(@as(usize, 1), own.len);
    try std.testing.expectEqual(@as(SubscriberId, 2), own[0].subscriber_id);

    const remote = try router.matchIntoForPublisher("events/one", 99, &storage);
    try std.testing.expectEqual(@as(usize, 2), remote.len);
    try std.testing.expectError(
        error.InvalidTopic,
        router.matchIntoForPublisher("events/+", 99, &storage),
    );
}

test "MQTT router matchInto allocates nothing and preserves shared cursor on capacity error" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(10, .{ .topic_filter = "$share/g/tasks/+" });
    try router.subscribe(11, .{ .topic_filter = "$share/g/tasks/+" });
    try router.subscribe(20, .{ .topic_filter = "tasks/#" });
    try router.subscribe(21, .{ .topic_filter = "tasks/+" });

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    var too_small: [2]Match = undefined;
    try std.testing.expectError(error.MatchBufferTooSmall, router.matchInto("tasks/a", &too_small));
    try std.testing.expect(!no_alloc.has_induced_failure);

    var enough: [3]Match = undefined;
    const first = try router.matchInto("tasks/a", &enough);
    try std.testing.expectEqual(@as(usize, 3), first.len);
    try std.testing.expectEqual(@as(SubscriberId, 10), first[2].subscriber_id);
    try std.testing.expectEqualStrings("$share/g/tasks/+", first[2].subscription.topic_filter);

    const second = try router.matchInto("tasks/b", &enough);
    try std.testing.expectEqual(@as(SubscriberId, 11), second[2].subscriber_id);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router matchAlloc returns exact output" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "a/+" });
    try router.subscribe(2, .{ .topic_filter = "unmatched" });
    const matches = try router.matchAlloc(allocator, "a/b");
    defer allocator.free(matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(SubscriberId, 1), matches[0].subscriber_id);

    const none = try router.matchAlloc(allocator, "none/here");
    defer allocator.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "MQTT router indexes wide literal siblings" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    var filter_buffer: [32]u8 = undefined;
    for (0..1000) |i| {
        const filter = try std.fmt.bufPrint(&filter_buffer, "devices/{d}/state", .{i});
        try router.subscribe(@intCast(i), .{ .topic_filter = filter });
    }

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    var storage: [1]Match = undefined;
    const exact_topic = try std.fmt.bufPrint(&filter_buffer, "devices/{d}/state", .{777});
    const matches = try router.matchInto(exact_topic, &storage);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(SubscriberId, 777), matches[0].subscriber_id);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router falls back exactly when trie frontier is wider than stack storage" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    const level_count = 8;
    const subscription_count = 1 << level_count;
    var filter_buffer: [level_count * 2 - 1]u8 = undefined;
    for (0..subscription_count) |mask| {
        var pos: usize = 0;
        for (0..level_count) |level| {
            filter_buffer[pos] = if ((mask & (@as(usize, 1) << @intCast(level))) == 0) 'a' else '+';
            pos += 1;
            if (level + 1 != level_count) {
                filter_buffer[pos] = '/';
                pos += 1;
            }
        }
        try router.subscribe(@intCast(mask), .{ .topic_filter = filter_buffer[0..pos] });
    }

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    var matches: [subscription_count]Match = undefined;
    const found = try router.matchInto("a/a/a/a/a/a/a/a", &matches);
    try std.testing.expectEqual(@as(usize, subscription_count), found.len);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router handles empty topic levels" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "a//b" });
    try router.subscribe(2, .{ .topic_filter = "a/+/b" });
    try router.subscribe(3, .{ .topic_filter = "/#" });
    var storage: [3]Match = undefined;
    const matches = try router.matchInto("a//b", &storage);
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

test "MQTT router subscription allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testSubscriptionAllocationFailures,
        .{},
    );
}

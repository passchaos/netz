const std = @import("std");
const router_mod = @import("../router.zig");
const allocator = std.testing.allocator;

test "MQTT router churn bounds stored entries and trie paths by peak live subscriptions" {
    var router = try router_mod.Router.init(allocator);
    defer router.deinit();
    try router.subscribe(99, .{ .topic_filter = "keep/+/tail" });
    for (0..128) |index| {
        var storage: [128]u8 = undefined;
        const filter = try std.fmt.bufPrint(&storage, "changing/{d}/#", .{index});
        try router.subscribe(1, .{ .topic_filter = filter });
        try router.unsubscribe(1, filter);
        try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
        try std.testing.expect(router.entries.items.len <= 2);
        try std.testing.expect(router.nodes.items.len <= 6);
        try std.testing.expectEqual(@as(usize, 1), router.nodes.items[0].literal_children.count());
        var matches: [1]router_mod.Match = undefined;
        const found = try router.matchInto("keep/value/tail", &matches);
        try std.testing.expectEqual(@as(usize, 1), found.len);
        try std.testing.expectEqual(@as(u64, 99), found[0].subscriber_id);
    }
}

test "MQTT router churn prunes deep empty levels iteratively and reuses the root edge" {
    var router = try router_mod.Router.init(allocator);
    defer router.deinit();
    const filter = "/" ** 4096;
    try router.subscribe(1, .{ .topic_filter = filter });
    try router.unsubscribe(1, filter);
    try std.testing.expectEqual(@as(usize, 0), router.nodes.items[0].literal_children.count());
    const peak = router.nodes.items.len;
    try router.subscribe(2, .{ .topic_filter = "after" });
    try std.testing.expectEqual(peak, router.nodes.items.len);
    var matches: [1]router_mod.Match = undefined;
    try std.testing.expectEqual(@as(u64, 2), (try router.matchInto("after", &matches))[0].subscriber_id);
}

test "MQTT router churn reclaims shared filters and wildcard child slots" {
    var router = try router_mod.Router.init(allocator);
    defer router.deinit();
    try router.subscribe(99, .{ .topic_filter = "keep/+" });
    for ([_]bool{ false, true }) |shared| {
        for (0..128) |index| {
            var filter_storage: [128]u8 = undefined;
            const filter = if (shared)
                try std.fmt.bufPrint(&filter_storage, "$share/group{d}/branch/+/value{d}/#", .{ index, index })
            else
                try std.fmt.bufPrint(&filter_storage, "branch/+/value{d}/#", .{index});
            try router.subscribe(1, .{ .topic_filter = filter });
            var topic_storage: [128]u8 = undefined;
            const topic = try std.fmt.bufPrint(&topic_storage, "branch/any/value{d}/payload", .{index});
            var matches: [2]router_mod.Match = undefined;
            const found = try router.matchInto(topic, &matches);
            try std.testing.expectEqual(@as(usize, 1), found.len);
            try std.testing.expectEqual(@as(u64, 1), found[0].subscriber_id);
            try router.unsubscribe(1, filter);
            try std.testing.expect(router.entries.items.len <= 2);
            try std.testing.expect(router.nodes.items.len <= 6);
            try std.testing.expect(router.shared_groups.items.len <= 1);
            try std.testing.expectEqual(@as(usize, 1), router.nodes.items[0].literal_children.count());
        }
    }
}

test "MQTT router churn slot reuse preserves shared representatives and join order" {
    var router = try router_mod.Router.init(allocator);
    defer router.deinit();
    try router.subscribe(1, .{ .topic_filter = "$share/team/jobs/+" });
    try router.subscribe(2, .{ .topic_filter = "$share/team/jobs/+" });
    var matches: [3]router_mod.Match = undefined;
    try std.testing.expectEqual(@as(u64, 1), (try router.matchInto("jobs/one", &matches))[0].subscriber_id);
    try router.unsubscribe(1, "$share/team/jobs/+");
    // This ordinary route takes the old shared representative's entry slot.
    try router.subscribe(4, .{ .topic_filter = "other/#" });
    try std.testing.expectEqual(@as(u64, 2), (try router.matchInto("jobs/two", &matches))[0].subscriber_id);
    try std.testing.expectEqual(@as(u64, 4), (try router.matchInto("other/item", &matches))[0].subscriber_id);
    try router.subscribe(3, .{ .topic_filter = "$share/team/jobs/+" });
    try std.testing.expectEqual(@as(u64, 2), (try router.matchInto("jobs/three", &matches))[0].subscriber_id);
    try std.testing.expectEqual(@as(u64, 3), (try router.matchInto("jobs/four", &matches))[0].subscriber_id);
    try router.unsubscribe(2, "$share/team/jobs/+");
    try std.testing.expectEqual(@as(u64, 3), (try router.matchInto("jobs/five", &matches))[0].subscriber_id);
    try router.unsubscribe(3, "$share/team/jobs/+");
    try std.testing.expectEqual(@as(usize, 0), (try router.matchInto("jobs/six", &matches)).len);
    try std.testing.expectEqual(@as(u64, 4), (try router.matchInto("other/item", &matches))[0].subscriber_id);
}

test "MQTT router churn prunes partial insertion paths after every allocation failure" {
    for ([_]bool{ false, true }) |shared| {
        var succeeded = false;
        for (0..64) |fail_index| {
            var router = try router_mod.Router.init(allocator);
            defer router.deinit();
            try router.subscribe(99, .{ .topic_filter = "keep/#" });
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
            router.allocator = failing.allocator();
            const attempted = router.subscribe(1, .{ .topic_filter = if (shared) "$share/team/fresh/branch/+/leaf/#" else "fresh/branch/+/leaf/#" });
            router.allocator = allocator;
            if (failing.has_induced_failure) {
                try std.testing.expectError(error.OutOfMemory, attempted);
                try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
                try std.testing.expectEqual(@as(usize, 0), router.sharedSubscriptionCount());
                try std.testing.expectEqual(@as(usize, 1), router.nodes.items[0].literal_children.count());
                var matches: [1]router_mod.Match = undefined;
                try std.testing.expectEqual(@as(u64, 99), (try router.matchInto("keep/alive", &matches))[0].subscriber_id);
                try router.subscribe(2, .{ .topic_filter = "retry/branch/+/leaf/#" });
                try std.testing.expect(router.nodes.items.len <= 6);
                try std.testing.expect(router.entries.items.len <= 2);
            } else {
                try attempted;
                succeeded = true;
                try router.unsubscribe(1, if (shared) "$share/team/fresh/branch/+/leaf/#" else "fresh/branch/+/leaf/#");
                try std.testing.expectEqual(@as(usize, 1), router.nodes.items[0].literal_children.count());
                break;
            }
        }
        try std.testing.expect(succeeded);
    }
}

test "MQTT router churn cleanup needs no allocation and preserves overlapping routes" {
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var router = try router_mod.Router.init(failing.allocator());
    defer router.deinit();
    try router.subscribe(1, .{ .topic_filter = "parent/+/tail" });
    try router.subscribe(2, .{ .topic_filter = "parent/literal/tail" });
    try router.subscribe(3, .{ .topic_filter = "$share/team/parent/literal/#" });
    failing.fail_index = failing.alloc_index;
    try router.unsubscribe(2, "parent/literal/tail");
    var matches: [2]router_mod.Match = undefined;
    try std.testing.expectEqual(@as(usize, 2), (try router.matchInto("parent/literal/tail", &matches)).len);
    try std.testing.expectEqual(@as(usize, 1), try router.removeSubscriber(3));
    const left = try router.matchInto("parent/literal/tail", &matches);
    try std.testing.expectEqual(@as(usize, 1), left.len);
    try std.testing.expectEqual(@as(u64, 1), left[0].subscriber_id);
    try std.testing.expectEqual(@as(usize, 1), try router.removeSubscriber(1));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), router.nodes.items[0].literal_children.count());
    try std.testing.expect(router.nodes.items[0].single_wildcard_child == null);
}

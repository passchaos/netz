const std = @import("std");
const mqtt = @import("../mod.zig");
const router_mod = @import("../router.zig");
const Router = router_mod.Router;

test "MQTT router batch abort restores policies identifiers and shared cursor" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var router = try Router.init(failing.allocator());
    defer router.deinit();
    try initialRoutes(&router);
    var storage: [4]router_mod.Match = undefined;
    const first = try router.matchInto("jobs/first", &storage);
    try std.testing.expectEqual(@as(u64, 1), first[0].subscriber_id);
    var batch = try router.beginSubscriptionBatch(3, 3);
    try fillBatch(&batch);
    failing.fail_index = failing.alloc_index;
    batch.deinit();
    try std.testing.expect(!failing.has_induced_failure);
    try expectOriginalRoutes(&router);
    const next = try router.matchInto("jobs/next", &storage);
    try std.testing.expectEqual(@as(u64, 2), next[0].subscriber_id);
}

test "MQTT router batch commit and cleanup allocate nothing" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var router = try Router.init(failing.allocator());
    defer router.deinit();
    try initialRoutes(&router);
    var batch = try router.beginSubscriptionBatch(3, 3);
    try fillBatch(&batch);
    failing.fail_index = failing.alloc_index;
    batch.commit();
    batch.deinit();
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 5), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 3), router.sharedSubscriptionCount());
    var storage: [4]router_mod.Match = undefined;
    const ordinary = try router.matchInto("existing/item", &storage);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, ordinary[0].subscription.qos);
    try std.testing.expect(!ordinary[0].subscription.no_local);
    try std.testing.expectEqual(@as(?usize, 99), ordinary[0].subscription_identifier);
    const fresh = try router.matchInto("fresh/building/floor/one/status/value", &storage);
    try std.testing.expectEqual(@as(usize, 1), fresh.len);
    try std.testing.expectEqual(@as(u64, 3), fresh[0].subscriber_id);
}

test "MQTT router batch capacity failure leaves prior subscription resumable" {
    var router = try Router.init(std.testing.allocator);
    defer router.deinit();
    try initialRoutes(&router);
    var batch = try router.beginSubscriptionBatch(3, 1);
    _ = try batch.subscribe(.{ .topic_filter = "existing/#", .qos = .at_most_once }, 99);
    try std.testing.expectError(error.SubscriptionBatchFull, batch.subscribe(.{ .topic_filter = "blocked/#" }, null));
    batch.deinit();
    try expectOriginalRoutes(&router);
}

test "MQTT router batch allocation failures rollback committed prefixes" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailures, .{});
}

fn allocationFailures(allocator: std.mem.Allocator) !void {
    var router = try Router.init(allocator);
    defer router.deinit();
    try initialRoutes(&router);
    var batch = router.beginSubscriptionBatch(3, 3) catch |err| {
        try expectOriginalRoutes(&router);
        return err;
    };
    const attempted = fillBatch(&batch);
    batch.deinit();
    try expectOriginalRoutes(&router);
    try attempted;
}

fn initialRoutes(router: *Router) !void {
    _ = try router.subscribeWithIdentifierStatus(3, .{
        .topic_filter = "existing/#",
        .qos = .exactly_once,
        .no_local = true,
        .retain_as_published = true,
        .retain_handling = 1,
    }, 7);
    _ = try router.subscribeWithIdentifierStatus(1, .{ .topic_filter = "$share/team/jobs/+", .qos = .at_least_once }, 11);
    _ = try router.subscribeWithIdentifierStatus(2, .{ .topic_filter = "$share/team/jobs/+", .qos = .exactly_once }, 12);
}

fn fillBatch(batch: *router_mod.SubscriptionBatch) router_mod.Error!void {
    _ = try batch.subscribe(.{ .topic_filter = "existing/#", .qos = .at_most_once }, 99);
    _ = try batch.subscribe(.{ .topic_filter = "$share/team/jobs/+", .qos = .at_least_once }, 88);
    _ = try batch.subscribe(.{ .topic_filter = "fresh/building/floor/+/status/#", .qos = .at_least_once }, 100);
}

fn expectOriginalRoutes(router: *Router) !void {
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());
    var storage: [4]router_mod.Match = undefined;
    const ordinary = try router.matchInto("existing/item", &storage);
    try std.testing.expectEqual(@as(usize, 1), ordinary.len);
    try std.testing.expectEqual(@as(u64, 3), ordinary[0].subscriber_id);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, ordinary[0].subscription.qos);
    try std.testing.expect(ordinary[0].subscription.no_local);
    try std.testing.expect(ordinary[0].subscription.retain_as_published);
    try std.testing.expectEqual(@as(u2, 1), ordinary[0].subscription.retain_handling);
    try std.testing.expectEqual(@as(?usize, 7), ordinary[0].subscription_identifier);
    const fresh = try router.matchInto("fresh/building/floor/one/status/value", &storage);
    try std.testing.expectEqual(@as(usize, 0), fresh.len);
}

//! Prepare resumed subscription routing before Session ownership changes.

const std = @import("std");
const session = @import("../session/mod.zig");
const router_mod = @import("../router.zig");
const route = @import("session_route.zig");

pub fn prepare(
    allocator: std.mem.Allocator,
    router: *router_mod.Router,
    sessions: *session.Store,
    previous: ?session.Handle,
    clean_start: bool,
) (session.Error || router_mod.Error)!router_mod.SubscriptionBatch {
    if (clean_start) return router.beginSubscriptionBatch(0, 0);
    const handle = previous orelse return router.beginSubscriptionBatch(0, 0);
    const stats = try sessions.stats(handle);
    // A transient takeover cannot resume this state, even with Clean Start=0.
    if (stats.expiry_interval == 0) return router.beginSubscriptionBatch(0, 0);
    const subscriptions = try allocator.alloc(session.Subscription, stats.subscription_count);
    defer allocator.free(subscriptions);
    const restored = try sessions.subscriptionsInto(handle, subscriptions);
    var batch = try router.beginSubscriptionBatch(route.sessionSubscriberId(try sessions.routeId(handle)), restored.len);
    errdefer batch.deinit();
    for (restored) |subscription| {
        _ = try batch.subscribe(.{
            .topic_filter = subscription.topic_filter,
            .qos = subscription.qos,
            .no_local = subscription.no_local,
            .retain_as_published = subscription.retain_as_published,
            .retain_handling = subscription.retain_handling,
        }, subscription.subscription_identifier);
    }
    return batch;
}

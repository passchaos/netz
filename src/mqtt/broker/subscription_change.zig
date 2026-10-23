//! Commit one filter's Session policy and router index under the broker lock.

const std = @import("std");
const mqtt = @import("../mod.zig");
const session = @import("../session/mod.zig");
const router_mod = @import("../router.zig");
const route = @import("session_route.zig");

pub fn apply(
    sessions: *session.Store,
    router: *router_mod.Router,
    handle: session.Handle,
    subscription: mqtt.Subscription,
    identifier: ?usize,
) (session.Error || router_mod.Error)!bool {
    // Preserve packet-level quota refusals before route preparation allocates.
    try sessions.checkSubscriptionLimit(handle, subscription.topic_filter);
    const route_id = try sessions.routeId(handle);
    var prepared = try router.prepareSubscription(route.sessionSubscriberId(route_id), subscription, identifier);
    defer prepared.deinit();
    const existed = try sessions.setSubscription(handle, subscription, identifier);
    std.debug.assert(existed == prepared.existed);
    prepared.commit();
    return existed;
}

test "broker subscription change rolls back prepared route after Session failure" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |memory_limit| {
        var sessions = session.Store.init(allocator, .{});
        defer sessions.deinit();
        var router = try router_mod.Router.init(allocator);
        defer router.deinit();
        const opened = try sessions.open("paired", false, 120, .zero);
        _ = try apply(&sessions, &router, opened.handle, .{ .topic_filter = "prior", .qos = .at_least_once }, 11);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        if (memory_limit) sessions.options.max_total_bytes = sessions.totalBytes() else sessions.allocator = failing.allocator();
        const result = apply(&sessions, &router, opened.handle, .{ .topic_filter = "new", .qos = .exactly_once }, 12);
        try std.testing.expectError(if (memory_limit) error.SessionByteLimitExceeded else error.OutOfMemory, result);
        sessions.allocator = allocator;
        try std.testing.expectEqual(@as(usize, 1), (try sessions.stats(opened.handle)).subscription_count);
        try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
        try std.testing.expectEqual(@as(?usize, 11), router.entries.items[0].?.subscription_identifier);
    }
}

test "broker subscription count refusal precedes route allocation while replacements remain valid" {
    const allocator = std.testing.allocator;
    var sessions = session.Store.init(allocator, .{ .max_subscriptions_per_session = 1 });
    defer sessions.deinit();
    var router = try router_mod.Router.init(allocator);
    defer router.deinit();
    const opened = try sessions.open("quota", false, 120, .zero);
    _ = try apply(&sessions, &router, opened.handle, .{ .topic_filter = "same", .qos = .at_least_once }, 11);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    router.allocator = failing.allocator();
    defer router.allocator = allocator;
    try std.testing.expectError(error.SubscriptionLimitExceeded, apply(&sessions, &router, opened.handle, .{ .topic_filter = "new", .qos = .exactly_once }, 12));
    try std.testing.expect(try apply(&sessions, &router, opened.handle, .{ .topic_filter = "same", .qos = .exactly_once, .no_local = true }, 131));
    try std.testing.expect(!failing.has_induced_failure);
    var subscriptions: [1]session.Subscription = undefined;
    const stored = try sessions.subscriptionsInto(opened.handle, &subscriptions);
    try std.testing.expectEqual(@as(?usize, 131), stored[0].subscription_identifier);
    try std.testing.expect(stored[0].no_local and stored[0].qos == .exactly_once);
    try std.testing.expectEqual(@as(?usize, 131), router.entries.items[0].?.subscription_identifier);
    // Abandon a prepared replacement and recover the old policy/identifier
    // without allocating, including the No Local flag already accepted above.
    var pending = try router.prepareSubscription(route.sessionSubscriberId(opened.route_id), .{ .topic_filter = "same", .qos = .at_most_once }, 53);
    pending.deinit();
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(router.entries.items[0].?.subscription.no_local);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, router.entries.items[0].?.subscription.qos);
    try std.testing.expectEqual(@as(?usize, 131), router.entries.items[0].?.subscription_identifier);
}

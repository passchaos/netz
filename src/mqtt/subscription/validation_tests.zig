const std = @import("std");
const mqtt = @import("../mod.zig");
const Router = @import("../router.zig").Router;
const session_mod = @import("../session/mod.zig");
const allocator = std.testing.allocator;

test "MQTT subscription metadata rejects reserved retain handling before routing mutation" {
    const Mode = enum { direct, prepared, batch };
    for (std.enums.values(Mode)) |mode| {
        var router = try Router.init(allocator);
        defer router.deinit();
        _ = try router.subscribeWithIdentifierStatus(1, .{ .topic_filter = "old/#", .qos = .at_least_once }, 7);
        var batch = try router.beginSubscriptionBatch(1, 1);
        defer batch.deinit();
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        router.allocator = failing.allocator();
        defer router.allocator = allocator;
        const invalid = mqtt.Subscription{ .topic_filter = "old/#", .qos = .exactly_once, .retain_handling = 3 };
        switch (mode) {
            .direct => try std.testing.expectError(error.InvalidSubscription, router.subscribeWithIdentifierStatus(1, invalid, 9)),
            .prepared => {
                if (router.prepareSubscription(1, invalid, 9)) |value| {
                    var prepared = value;
                    prepared.deinit();
                    return error.TestUnexpectedResult;
                } else |err| try std.testing.expectEqual(error.InvalidSubscription, err);
            },
            .batch => try std.testing.expectError(error.InvalidSubscription, batch.subscribe(invalid, 9)),
        }
        try std.testing.expect(!failing.has_induced_failure);
        var matches: [1]@import("../router.zig").Match = undefined;
        const stored = try router.matchInto("old/value", &matches);
        try std.testing.expectEqual(@as(usize, 1), stored.len);
        try std.testing.expectEqual(mqtt.QoS.at_least_once, stored[0].subscription.qos);
        try std.testing.expectEqual(@as(?usize, 7), stored[0].subscription_identifier);
        try std.testing.expectEqual(@as(usize, 0), batch.count);
    }
}

test "MQTT subscription metadata invalid new routes preserve Router and Session state" {
    const Case = struct { subscription: mqtt.Subscription, identifier: ?usize = 9, expected: anyerror };
    const cases = [_]Case{
        .{ .subscription = .{ .topic_filter = "new/#", .retain_handling = 3 }, .expected = error.InvalidSubscription },
        .{ .subscription = .{ .topic_filter = "$share/team/new/#", .no_local = true }, .expected = error.InvalidSubscription },
        .{ .subscription = .{ .topic_filter = "new/#" }, .identifier = 0, .expected = error.InvalidProperty },
        .{ .subscription = .{ .topic_filter = "new/#" }, .identifier = 268_435_456, .expected = error.InvalidProperty },
        .{ .subscription = .{ .topic_filter = "new/#/suffix" }, .expected = error.InvalidSubscription },
    };
    for (cases) |case| {
        var router = try Router.init(allocator);
        defer router.deinit();
        var sessions = session_mod.Store.init(allocator, .{});
        defer sessions.deinit();
        const opened = try sessions.open("metadata", false, 120, .zero);
        const original = mqtt.Subscription{ .topic_filter = "old/#", .qos = .at_least_once };
        _ = try router.subscribeWithIdentifierStatus(1, original, 7);
        _ = try sessions.setSubscription(opened.handle, original, 7);
        const nodes = router.nodes.items.len;
        const bytes = sessions.totalBytes();
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        router.allocator = failing.allocator();
        defer router.allocator = allocator;
        sessions.allocator = failing.allocator();
        defer sessions.allocator = allocator;
        try std.testing.expectError(case.expected, router.subscribeWithIdentifierStatus(1, case.subscription, case.identifier));
        try std.testing.expectError(case.expected, sessions.setSubscription(opened.handle, case.subscription, case.identifier));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(nodes, router.nodes.items.len);
        try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
        try std.testing.expectEqual(@as(usize, 1), (try sessions.stats(opened.handle)).subscription_count);
        try std.testing.expectEqual(bytes, sessions.totalBytes());
    }
}

test "MQTT subscription metadata legitimate options agree across Router Session and codec" {
    for ([_]bool{ false, true }) |shared| {
        var router = try Router.init(allocator);
        defer router.deinit();
        var sessions = session_mod.Store.init(allocator, .{});
        defer sessions.deinit();
        const opened = try sessions.open("legitimate", false, 120, .zero);
        const filter = if (shared) "$share/team/items/#" else "items/#";
        for ([_]mqtt.QoS{ .at_most_once, .at_least_once, .exactly_once }) |qos| {
            for ([_]u2{ 0, 1, 2 }) |retain_handling| {
                for ([_]?usize{ null, 1, 268_435_455 }) |identifier| {
                    const subscription = mqtt.Subscription{ .topic_filter = filter, .qos = qos, .retain_handling = retain_handling, .retain_as_published = true, .no_local = !shared };
                    try mqtt.validateSubscription(subscription, identifier);
                    _ = try router.subscribeWithIdentifierStatus(1, subscription, identifier);
                    _ = try sessions.setSubscription(opened.handle, subscription, identifier);
                    var matches: [1]@import("../router.zig").Match = undefined;
                    const found = try router.matchInto("items/value", &matches);
                    try std.testing.expectEqual(qos, found[0].subscription.qos);
                    try std.testing.expectEqual(retain_handling, found[0].subscription.retain_handling);
                    try std.testing.expectEqual(identifier, found[0].subscription_identifier);
                    var stored: [1]session_mod.Subscription = undefined;
                    const listed = try sessions.subscriptionsInto(opened.handle, &stored);
                    try std.testing.expectEqual(qos, listed[0].qos);
                    try std.testing.expectEqual(retain_handling, listed[0].retain_handling);
                    try std.testing.expectEqual(identifier, listed[0].subscription_identifier);
                    var properties = [_]mqtt.Property{.{ .varint = .{ .id = .subscription_identifier, .value = identifier orelse 1 } }};
                    var bytes: std.ArrayList(u8) = .empty;
                    defer bytes.deinit(allocator);
                    try mqtt.Subscribe.write(&bytes, allocator, .v5, 1, if (identifier != null) &properties else &.{}, &.{subscription});
                    var parsed = try mqtt.Subscribe.parse(allocator, .v5, bytes.items);
                    defer parsed.deinit(allocator);
                    try std.testing.expectEqual(qos, parsed.subscriptions[0].qos);
                    try std.testing.expectEqual(retain_handling, parsed.subscriptions[0].retain_handling);
                    try std.testing.expectEqual(!shared, parsed.subscriptions[0].no_local);
                    try std.testing.expect(parsed.subscriptions[0].retain_as_published);
                    try std.testing.expectEqual(identifier, mqtt.subscriptionIdentifier(parsed.properties));
                }
            }
        }
    }
}

test "MQTT subscription metadata codec preflight preserves an existing output prefix" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        var storage = [_]u8{0xa5};
        var bytes = std.ArrayList(u8).initBuffer(&storage);
        bytes.items.len = 1;
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.InvalidSubscription, mqtt.Subscribe.write(&bytes, failing.allocator(), protocol, 1, &.{}, &.{
            .{ .topic_filter = "valid" }, .{ .topic_filter = "invalid", .retain_handling = 3 },
        }));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqualSlices(u8, &.{0xa5}, bytes.items);
    }
}

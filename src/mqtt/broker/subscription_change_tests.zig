const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

test "broker failed SUBSCRIBE route preparation preserves persistent Session subscriptions" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| try failedRoute(protocol);
}

fn failedRoute(protocol: mqtt.ProtocolVersion) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var router_allocator = std.testing.FailingAllocator.init(allocator, .{});
    var broker = try context.testBrokerFn(allocator, io, 1, 64);
    defer broker.deinit();
    broker.router.allocator = router_allocator.allocator();
    const Policy = struct {
        allocator: *std.testing.FailingAllocator,
        armed: bool = false,

        fn publish(_: *anyopaque, _: mqtt.Connect, _: mqtt.Publish) bool {
            return true;
        }

        fn subscribe(pointer: *anyopaque, _: mqtt.Connect, subscription: mqtt.Subscription) bool {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            if (std.mem.eql(u8, subscription.topic_filter, "failed/value")) {
                self.allocator.fail_index = self.allocator.alloc_index;
                self.armed = true;
            }
            return true;
        }
    };
    var policy = Policy{ .allocator = &router_allocator };
    broker.options.access_control = .{ .context = &policy, .authorize_publish = Policy.publish, .authorize_subscribe = Policy.subscribe };
    var serve = context.ServeStateType{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    defer router_allocator.fail_index = std.math.maxInt(usize);
    var subscriber = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{
        .protocol = protocol,
        .client_id = "subscription-prepare",
        .clean_start = false,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }} else &.{},
    }, .fromSeconds(3));
    defer subscriber.close();
    var warm = try subscriber.subscribe(&.{.{ .topic_filter = "prior/value", .qos = .at_least_once }}, .{});
    defer warm.deinit(allocator);
    if (subscriber.subscribe(&.{.{ .topic_filter = "failed/value", .qos = .at_least_once }}, .{})) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        subscriber.close();
        return error.TestUnexpectedResult;
    } else |_| {}
    thread.join();
    joined = true;
    try std.testing.expect(policy.armed);
    try std.testing.expect(router_allocator.has_induced_failure);
    router_allocator.fail_index = std.math.maxInt(usize);
    const handle = broker.sessions.find("subscription-prepare", std.Io.Clock.awake.now(io)).?;
    try std.testing.expectEqual(@as(usize, 1), (try broker.sessions.stats(handle)).subscription_count);
    try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());
    var subscriptions: [2]mqtt.session.Subscription = undefined;
    const stored = try broker.sessions.subscriptionsInto(handle, &subscriptions);
    try std.testing.expectEqual(@as(usize, 1), stored.len);
    try std.testing.expectEqualStrings("prior/value", stored[0].topic_filter);
    // A previously accepted route still delivers into this offline Session.
    try broker.publishLocal(.{ .topic = "prior/value", .payload = "kept", .qos = .at_least_once, .dup = false, .retain = false, .packet_id = null });
    try std.testing.expectEqual(@as(usize, 1), (try broker.sessions.stats(handle)).queued_count);
}

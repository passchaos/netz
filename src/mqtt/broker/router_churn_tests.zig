const std = @import("std");
const Broker = @import("../broker.zig").Broker;
const allocator = std.testing.allocator;

test "MQTT broker router churn bounds routes across transient local consumers" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(allocator, threaded.io(), .{});
    defer broker.deinit();
    for (0..128) |index| {
        var storage: [64]u8 = undefined;
        const topic = try std.fmt.bufPrint(&storage, "consumer/{d}", .{index});
        var consumer = try broker.openLocalConsumer(.{
            .id = [_]u8{0x39} ** 16,
            .clean_session = true,
            .subscriptions = &.{.{ .topic_filter = topic, .qos = .at_least_once }},
        });
        var owns_consumer = true;
        defer if (owns_consumer) broker.closeLocalConsumer(&consumer);
        try broker.publishLocal(.{ .topic = topic, .payload = "delivered", .qos = .at_least_once, .retain = false, .dup = false, .packet_id = null });
        var event = (try broker.pollLocalConsumer(&consumer)) orelse return error.TestUnexpectedResult;
        defer event.deinit();
        try std.testing.expectEqualStrings("delivered", event.publish.value.payload);
        _ = try broker.acknowledgeLocalConsumer(&consumer, .puback, event.publish.value.packet_id.?, 0);
        broker.closeLocalConsumer(&consumer);
        owns_consumer = false;
        try std.testing.expectEqual(@as(usize, 0), broker.router.subscriptionCount());
        try std.testing.expect(broker.router.entries.items.len <= 1);
        try std.testing.expect(broker.router.nodes.items.len <= 3);
        try std.testing.expectEqual(@as(usize, 0), broker.router.nodes.items[0].literal_children.count());
    }
}

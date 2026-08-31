const std = @import("std");
const mqtt = @import("../mod.zig");
const bridge_mod = @import("../bridge.zig");

const Rule = bridge_mod.Rule;

test "bridge rule validates bounded inbound mappings" {
    try (Rule{
        .filter = "sensors/+/state",
        .qos = .at_least_once,
        .local_prefix = "upstream/",
    }).validate();
    try (Rule{
        .filter = "#",
        .qos = .at_most_once,
    }).validate();

    try std.testing.expectError(
        error.InvalidSubscription,
        (Rule{ .filter = "sensors/#/bad" }).validate(),
    );
    try std.testing.expectError(
        error.InvalidBridgeQoS,
        (Rule{ .filter = "#", .qos = .exactly_once }).validate(),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        (Rule{ .filter = "#", .local_prefix = "bad/+" }).validate(),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        (Rule{
            .filter = "#",
            .local_prefix = &[_]u8{ 0xff, '/' },
        }).validate(),
    );
}

test "bridge rule maps only matching remote Topic Names" {
    const allocator = std.testing.allocator;
    const rule = Rule{
        .filter = "sensors/+/state",
        .qos = .at_least_once,
        .local_prefix = "remote/site-a/",
    };
    const mapped = try rule.mapTopicAlloc(
        allocator,
        "sensors/room-1/state",
    );
    defer allocator.free(mapped);
    try std.testing.expectEqualStrings(
        "remote/site-a/sensors/room-1/state",
        mapped,
    );
    try std.testing.expectError(
        error.TopicOutsideBridgeRule,
        rule.mapTopicAlloc(allocator, "commands/room-1"),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        rule.mapTopicAlloc(allocator, "sensors/+/state"),
    );

    const system_rule = Rule{
        .filter = "+/#",
        .local_prefix = "remote/",
    };
    try std.testing.expectError(
        error.TopicOutsideBridgeRule,
        system_rule.mapTopicAlloc(allocator, "$SYS/broker/uptime"),
    );
}

test "bridge public configuration retains MQTT types" {
    const options = bridge_mod.Options{
        .connect = .{ .client_id = "bridge-test" },
        .rule = .{
            .filter = "remote/#",
            .qos = .at_least_once,
            .local_prefix = "local/",
        },
    };
    try std.testing.expectEqual(mqtt.QoS.at_least_once, options.rule.qos);
}

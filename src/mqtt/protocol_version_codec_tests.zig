const std = @import("std");
const mqtt = @import("mod.zig");

test "MQTT 3.1 duplicate QoS control flags remain version scoped" {
    const allocator = std.testing.allocator;

    var duplicate_pubrel = try mqtt.AckPacket.parse(
        allocator,
        .v3_1,
        &.{ 0x6a, 0x02, 0x00, 0x2a },
    );
    defer duplicate_pubrel.deinit(allocator);
    try std.testing.expect(duplicate_pubrel.dup);
    try std.testing.expectEqual(
        mqtt.PacketType.pubrel,
        duplicate_pubrel.packet_type,
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.AckPacket.parse(
            allocator,
            .v3_1_1,
            &.{ 0x6a, 0x02, 0x00, 0x2a },
        ),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.AckPacket.parse(
            allocator,
            .v5,
            &.{ 0x6a, 0x02, 0x00, 0x2a },
        ),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.AckPacket.writeWithDup(
        &encoded,
        allocator,
        .v3_1,
        .pubrel,
        true,
        42,
        0,
        &.{},
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x6a, 0x02, 0x00, 0x2a },
        encoded.items,
    );
    var direct_ack: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        encoded.items,
        try mqtt.AckPacket.writeNoPropertiesIntoWithDup(
            &direct_ack,
            .v3_1,
            .pubrel,
            true,
            42,
            0,
        ),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.AckPacket.writeWithDup(
            &encoded,
            allocator,
            .v3_1_1,
            .pubrel,
            true,
            42,
            0,
            &.{},
        ),
    );

    const subscriptions = [_]mqtt.Subscription{.{
        .topic_filter = "v31/retry",
        .qos = .at_least_once,
    }};
    encoded.clearRetainingCapacity();
    try mqtt.Subscribe.writeWithDup(
        &encoded,
        allocator,
        .v3_1,
        true,
        11,
        &.{},
        &subscriptions,
    );
    try std.testing.expectEqual(@as(u8, 0x8a), encoded.items[0]);
    var subscribe = try mqtt.Subscribe.parse(allocator, .v3_1, encoded.items);
    defer subscribe.deinit(allocator);
    try std.testing.expect(subscribe.dup);
    try std.testing.expectEqual(@as(u16, 11), subscribe.packet_id);
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.Subscribe.parse(allocator, .v3_1_1, encoded.items),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.Subscribe.writeWithDup(
            &encoded,
            allocator,
            .v3_1_1,
            true,
            12,
            &.{},
            &subscriptions,
        ),
    );

    const filters = [_][]const u8{"v31/retry"};
    encoded.clearRetainingCapacity();
    try mqtt.Unsubscribe.writeWithDup(
        &encoded,
        allocator,
        .v3_1,
        true,
        13,
        &.{},
        &filters,
    );
    try std.testing.expectEqual(@as(u8, 0xaa), encoded.items[0]);
    var unsubscribe = try mqtt.Unsubscribe.parse(
        allocator,
        .v3_1,
        encoded.items,
    );
    defer unsubscribe.deinit(allocator);
    try std.testing.expect(unsubscribe.dup);
    try std.testing.expectEqual(@as(u16, 13), unsubscribe.packet_id);
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.Unsubscribe.parse(allocator, .v3_1_1, encoded.items),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.Unsubscribe.writeWithDup(
            &encoded,
            allocator,
            .v3_1_1,
            true,
            14,
            &.{},
            &filters,
        ),
    );
}

test "MQTT 3.1 CONNACK flags separate standard and Mosquitto semantics" {
    const allocator = std.testing.allocator;

    // MQTT 3.1 marks both fixed-header flags and its acknowledgement byte as
    // unused. Preserve the latter for explicit extensions without assigning
    // Session Present semantics in the standard codec.
    var connack = try mqtt.ConnAck.parse(
        allocator,
        .v3_1,
        &.{ 0x2f, 0x02, 0xff, 0x00 },
    );
    defer connack.deinit(allocator);
    try std.testing.expect(!connack.session_present);
    try std.testing.expectEqual(
        @as(u8, 0xff),
        connack.v3_1_acknowledgement_flags,
    );
    try std.testing.expect(connack.mosquittoV31SessionPresent());
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.ConnAck.parse(
            allocator,
            .v3_1_1,
            &.{ 0x2f, 0x02, 0xff, 0x00 },
        ),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.ConnAck.write(&encoded, allocator, .v3_1, false, 0, &.{});
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x02, 0x00, 0x00 },
        encoded.items,
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.ConnAck.write(&encoded, allocator, .v3_1, true, 0, &.{}),
    );

    encoded.clearRetainingCapacity();
    try mqtt.ConnAck.writeMosquittoV31(&encoded, allocator, true, 0);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x02, 0x01, 0x00 },
        encoded.items,
    );
    var direct: [mqtt.ConnAck.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        encoded.items,
        try mqtt.ConnAck.writeMosquittoV31Into(&direct, true, 0),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        mqtt.ConnAck.writeMosquittoV31Into(&direct, true, 2),
    );
}

//! Match source retransmissions against an already-owned bridge transaction.
const std = @import("std");
const mqtt = @import("../mod.zig");
const coordinator_mod = @import("outbound_coordinator.zig");
const stablePropertiesEqual = @import("outbound_delivery.zig").stablePropertiesEqual;

pub fn durablePublishMatches(
    transaction: coordinator_mod.Transaction,
    publish: mqtt.Publish,
) bool {
    if (publish.qos != .exactly_once or
        publish.packet_id != transaction.source_packet_id or
        publish.retain != transaction.source_retain or
        !std.mem.eql(u8, publish.topic, transaction.source_topic) or
        !std.mem.eql(u8, publish.payload, transaction.source_payload) or
        !stablePropertiesEqual(
            transaction.source_properties,
            publish.properties,
        ))
    {
        return false;
    }
    const retry_expiry = mqtt.messageExpiryInterval(publish.properties);
    if (retry_expiry == null and transaction.source_expiry_interval != null and
        transaction.phase != .target_await_pubrec)
    {
        // Some brokers omit Message Expiry on a late source retransmission.
        // Once target PUBREC or a terminal result is durable, only the
        // handshakes remain; no target PUBLISH can extend its lifetime.
        return true;
    }
    return if (transaction.source_expiry_interval) |original|
        retry_expiry != null and retry_expiry.? <= original
    else
        retry_expiry == null;
}

test "outbound source retry omitted expiry requires a durable target acceptance or terminal result" {
    var user = [_]mqtt.Property{.{ .utf8_pair = .{ .id = .user_property, .key = "bridge", .value = "stable" } }};
    var transaction = coordinator_mod.Transaction{
        .phase = .target_await_pubrec,
        .source_session_epoch = 1,
        .target_session_epoch = 1,
        .source_packet_id = 77,
        .target_packet_id = 1,
        .source_retain = false,
        .source_topic = "source/topic",
        .source_payload = "old",
        .source_properties = &user,
        .source_expiry_interval = 1,
    };
    var publish = mqtt.Publish{ .qos = .exactly_once, .dup = true, .retain = false, .packet_id = 77, .topic = "source/topic", .payload = "old", .properties = &user };
    for ([_]coordinator_mod.Phase{ .target_await_pubrec, .target_await_pubcomp, .target_complete, .target_rejected }) |phase| {
        transaction.phase = phase;
        try std.testing.expectEqual(phase != .target_await_pubrec, durablePublishMatches(transaction, publish));
        var decreased = user ++ [_]mqtt.Property{.{ .four_byte = .{ .id = .message_expiry_interval, .value = 0 } }};
        publish.properties = &decreased;
        try std.testing.expect(durablePublishMatches(transaction, publish));
        var increased = user ++ [_]mqtt.Property{.{ .four_byte = .{ .id = .message_expiry_interval, .value = 2 } }};
        publish.properties = &increased;
        try std.testing.expect(!durablePublishMatches(transaction, publish));
        publish.properties = &user;
        publish.payload = "changed";
        try std.testing.expect(!durablePublishMatches(transaction, publish));
        publish.payload = "old";
        publish.packet_id = 78;
        try std.testing.expect(!durablePublishMatches(transaction, publish));
        publish.packet_id = 77;
        publish.properties = &.{};
        try std.testing.expect(!durablePublishMatches(transaction, publish));
        publish.properties = &user;
    }
}

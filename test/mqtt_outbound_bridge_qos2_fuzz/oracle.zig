const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const transport = @import("transport.zig");

const mqtt = netz.mqtt;
const runtime = mqtt.runtime;

pub fn drainSubscriber(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    try connection.writePingReq();
    var pending_id: ?u16 = null;
    var delivered = false;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |publish| {
                if (pending_id != null or delivered) {
                    return error.UnexpectedTargetDelivery;
                }
                try validateDelivery(publish.publish, operation, index);
                pending_id = publish.publish.packet_id.?;
                try connection.writePubRec(pending_id.?, 0);
            },
            .pubrel => |release| {
                try std.testing.expectEqual(pending_id.?, release.ack.packet_id);
                try connection.writePubComp(release.ack.packet_id, 0);
                pending_id = null;
                delivered = true;
            },
            .pingresp => {
                if (pending_id != null) {
                    try connection.writePingReq();
                    continue;
                }
                try std.testing.expect(delivered);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

pub fn drainNoDelivery(connection: *runtime.Connection) !void {
    try connection.writePingReq();
    var event = try connection.readClientPacketEventWithTimeout(
        model.packet_timeout,
    );
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .pingresp);
}

fn validateDelivery(
    publish: mqtt.Publish,
    operation: u8,
    index: usize,
) !void {
    const payload = model.Payload.init(operation, index);
    try std.testing.expectEqualStrings(
        model.target_topics[model.topicIndex(operation)],
        publish.topic,
    );
    try std.testing.expectEqualSlices(
        u8,
        if (model.deletesRetained(operation)) &.{} else &payload.bytes,
        publish.payload,
    );
    try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.qos);
    try std.testing.expectEqual(model.retain(operation), publish.retain);
    try std.testing.expect(!publish.dup);
    var user_properties: usize = 0;
    var subscription_identifiers: usize = 0;
    for (publish.properties) |property| switch (property) {
        .utf8_pair => |value| if (value.id == .user_property) {
            try std.testing.expectEqualStrings("origin", value.key);
            try std.testing.expectEqualStrings("source-broker", value.value);
            user_properties += 1;
        },
        .varint => |value| if (value.id == .subscription_identifier) {
            try std.testing.expectEqual(
                model.local_subscription_id,
                value.value,
            );
            subscription_identifiers += 1;
        },
        .two_byte => |value| if (value.id == .topic_alias) {
            return error.SourceTopicAliasLeaked;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), user_properties);
    try std.testing.expectEqual(@as(usize, 1), subscription_identifiers);
}

pub fn verifyRetainedState(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_address: std.Io.net.IpAddress,
    public_key: [65]u8,
    comptime tls: bool,
    state: model.State,
    summary: *model.Summary,
) !void {
    var probe = try transport.connect(
        tls,
        allocator,
        io,
        target_address,
        "fuzz-outbound-qos2-retained-probe",
        public_key,
    );
    defer probe.close();
    for (model.target_topics, 0..) |topic, topic_index| {
        var suback = try probe.subscribe(&.{.{
            .topic_filter = topic,
            .qos = .exactly_once,
            .retain_as_published = true,
        }}, .{});
        defer suback.deinit(allocator);
        if (state.retained[topic_index]) |retained| {
            try drainRetained(&probe, topic_index, retained);
            summary.retained_probe_deliveries += 1;
        } else {
            try drainNoDelivery(&probe);
        }
    }
    try probe.disconnect(0);
}

fn drainRetained(
    connection: *runtime.Connection,
    topic_index: usize,
    retained: model.Retained,
) !void {
    try connection.writePingReq();
    var pending_id: ?u16 = null;
    var delivered = false;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |publish| {
                try std.testing.expectEqualStrings(
                    model.target_topics[topic_index],
                    publish.publish.topic,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    retained.payload[0..retained.payload_len],
                    publish.publish.payload,
                );
                try std.testing.expect(publish.publish.retain);
                pending_id = publish.publish.packet_id.?;
                try connection.writePubRec(pending_id.?, 0);
            },
            .pubrel => |release| {
                try std.testing.expectEqual(pending_id.?, release.ack.packet_id);
                try connection.writePubComp(release.ack.packet_id, 0);
                pending_id = null;
                delivered = true;
            },
            .pingresp => {
                if (pending_id != null) {
                    try connection.writePingReq();
                    continue;
                }
                try std.testing.expect(delivered);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

//! Stable delivery values and duplicate matching for outbound bridges.
const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const Error = @import("outbound_engine.zig").Error;

pub const CompletedSource = struct {
    session_epoch: u64,
    packet_id: u16,
    reason_code: u8,
    retain: bool,
    topic: []u8,
    payload: []u8,
    properties: []mqtt.Property,
    expiry_interval: ?u32,

    pub fn init(
        allocator: std.mem.Allocator,
        session_epoch: u64,
        reason_code: u8,
        publish: mqtt.Publish,
    ) Error!CompletedSource {
        const topic = try allocator.dupe(u8, publish.topic);
        errdefer allocator.free(topic);
        const payload = try allocator.dupe(u8, publish.payload);
        errdefer allocator.free(payload);
        const copied = try owned_properties.clone(
            allocator,
            publish.properties,
            keepStableProperty,
        );
        return .{
            .session_epoch = session_epoch,
            .packet_id = publish.packet_id.?,
            .reason_code = reason_code,
            .retain = publish.retain,
            .topic = topic,
            .payload = payload,
            .properties = copied.properties,
            .expiry_interval = mqtt.messageExpiryInterval(publish.properties),
        };
    }

    pub fn deinit(self: *CompletedSource, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.payload);
        allocator.free(self.topic);
        self.* = undefined;
    }

    pub fn matches(self: CompletedSource, publish: mqtt.Publish) bool {
        if (publish.qos != .at_least_once or !publish.dup or
            self.packet_id != publish.packet_id.? or
            self.retain != publish.retain or
            !std.mem.eql(u8, self.topic, publish.topic) or
            !std.mem.eql(u8, self.payload, publish.payload) or
            !stablePropertiesEqual(self.properties, publish.properties))
        {
            return false;
        }
        const retry_expiry = mqtt.messageExpiryInterval(publish.properties);
        return if (self.expiry_interval) |original|
            retry_expiry != null and retry_expiry.? <= original
        else
            retry_expiry == null;
    }
};

pub fn keepStableProperty(property: mqtt.Property) bool {
    return !((property == .two_byte and
        property.two_byte.id == .topic_alias) or
        (property == .varint and
            property.varint.id == .subscription_identifier) or
        (property == .four_byte and
            property.four_byte.id == .message_expiry_interval));
}

pub fn stablePropertiesEqual(
    stored: []const mqtt.Property,
    incoming: []const mqtt.Property,
) bool {
    var stored_index: usize = 0;
    for (incoming) |property| {
        if (!keepStableProperty(property)) continue;
        if (stored_index == stored.len or
            !propertyEqual(stored[stored_index], property))
        {
            return false;
        }
        stored_index += 1;
    }
    return stored_index == stored.len;
}

fn propertyEqual(left: mqtt.Property, right: mqtt.Property) bool {
    if (@intFromEnum(left) != @intFromEnum(right)) return false;
    return switch (left) {
        .byte => |value| right == .byte and
            value.id == right.byte.id and value.value == right.byte.value,
        .two_byte => |value| right == .two_byte and
            value.id == right.two_byte.id and value.value == right.two_byte.value,
        .four_byte => |value| right == .four_byte and
            value.id == right.four_byte.id and value.value == right.four_byte.value,
        .varint => |value| right == .varint and
            value.id == right.varint.id and value.value == right.varint.value,
        .binary => |value| right == .binary and
            value.id == right.binary.id and
            std.mem.eql(u8, value.value, right.binary.value),
        .utf8 => |value| right == .utf8 and
            value.id == right.utf8.id and
            std.mem.eql(u8, value.value, right.utf8.value),
        .utf8_pair => |value| right == .utf8_pair and
            value.id == right.utf8_pair.id and
            std.mem.eql(u8, value.key, right.utf8_pair.key) and
            std.mem.eql(u8, value.value, right.utf8_pair.value),
    };
}

test "outbound bridge source tombstone validates duplicate content" {
    const allocator = std.testing.allocator;
    var original_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 3 } },
        .{ .varint = .{
            .id = .subscription_identifier,
            .value = 5,
        } },
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 10,
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "source",
            .value = "stable",
        } },
    };
    const original = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = true,
        .topic = "source/tombstone",
        .packet_id = 17,
        .properties = &original_properties,
        .payload = "payload",
    };
    var completed = try CompletedSource.init(allocator, 4, 0x87, original);
    defer completed.deinit(allocator);

    var retry_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 9 } },
        .{ .varint = .{
            .id = .subscription_identifier,
            .value = 12,
        } },
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 7,
        } },
        original_properties[3],
    };
    var retry = original;
    retry.dup = true;
    retry.properties = &retry_properties;
    try std.testing.expect(completed.matches(retry));

    retry.payload = "changed";
    try std.testing.expect(!completed.matches(retry));
    retry.payload = original.payload;
    var increased_expiry = retry_properties;
    increased_expiry[2].four_byte.value = 11;
    retry.properties = &increased_expiry;
    try std.testing.expect(!completed.matches(retry));
}

pub fn publishRetryMatches(original: mqtt.Publish, retry: mqtt.Publish) bool {
    if (original.qos != .at_least_once or retry.qos != .at_least_once or
        !retry.dup or original.packet_id != retry.packet_id or
        original.retain != retry.retain or
        !std.mem.eql(u8, original.topic, retry.topic) or
        !std.mem.eql(u8, original.payload, retry.payload) or
        !stablePropertiesEqualFiltered(
            original.properties,
            retry.properties,
        ))
    {
        return false;
    }
    const original_expiry = mqtt.messageExpiryInterval(original.properties);
    const retry_expiry = mqtt.messageExpiryInterval(retry.properties);
    return if (original_expiry) |value|
        retry_expiry != null and retry_expiry.? <= value
    else
        retry_expiry == null;
}

fn stablePropertiesEqualFiltered(
    left: []const mqtt.Property,
    right: []const mqtt.Property,
) bool {
    var left_index: usize = 0;
    var right_index: usize = 0;
    while (true) {
        while (left_index < left.len and
            !keepStableProperty(left[left_index]))
        {
            left_index += 1;
        }
        while (right_index < right.len and
            !keepStableProperty(right[right_index]))
        {
            right_index += 1;
        }
        if (left_index == left.len or right_index == right.len) {
            return left_index == left.len and right_index == right.len;
        }
        if (!propertyEqual(left[left_index], right[right_index])) return false;
        left_index += 1;
        right_index += 1;
    }
}

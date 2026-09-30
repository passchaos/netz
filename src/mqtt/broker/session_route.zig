//! Stable broker routing identities and detached Session transmissions.
//!
//! Connection subscriber IDs are short-lived capabilities tied to a slot
//! generation. Session subscriber IDs survive disconnect and takeover so the
//! topic router can keep persistent subscriptions indexed while offline.
//! Keeping both namespaces here makes their disjoint bit layout explicit.

const std = @import("std");
const mqtt = @import("../mod.zig");
const router = @import("../router.zig");
const session = @import("../session/mod.zig");

const session_subscriber_tag: u64 = 1 << 63;
const max_connection_generation: u32 = (1 << 31) - 1;

pub const DetachedPacket = struct {
    transmission: session.Transmission,
    packet_id: u16,
    kind: enum {
        qos0_publish,
        publish,
        pubrel,
    },
};

pub fn detachTransmission(
    bytes: *std.ArrayList(u8),
    properties: *std.ArrayList(mqtt.Property),
    allocator: std.mem.Allocator,
    transmission: session.Transmission,
    maximum_qos: mqtt.QoS,
) session.Error!DetachedPacket {
    bytes.clearRetainingCapacity();
    properties.clearRetainingCapacity();
    errdefer {
        bytes.clearRetainingCapacity();
        properties.clearRetainingCapacity();
    }
    var packet_id: u16 = 0;
    var kind: @FieldType(DetachedPacket, "kind") = .pubrel;
    const detached: session.Transmission = switch (transmission) {
        .publish => |publish| blk: {
            var capped = publish;
            capped.qos = minQos(capped.qos, maximum_qos);
            packet_id = publish.packet_id;
            kind = if (capped.qos == .at_most_once)
                .qos0_publish
            else
                .publish;
            const byte_count = try detachedPublishByteCount(capped);
            try bytes.ensureTotalCapacity(
                allocator,
                byte_count,
            );
            try properties.ensureTotalCapacity(
                allocator,
                capped.properties.len,
            );
            bytes.items.len = byte_count;
            var offset: usize = 0;
            capped.topic = copyBytes(bytes.items, &offset, capped.topic);
            capped.payload = copyBytes(bytes.items, &offset, capped.payload);
            for (capped.properties) |property| {
                properties.appendAssumeCapacity(copyProperty(
                    bytes.items,
                    &offset,
                    property,
                ));
            }
            std.debug.assert(offset == bytes.items.len);
            capped.properties = properties.items;
            break :blk .{ .publish = capped };
        },
        .pubrel => |pubrel| {
            packet_id = pubrel.packet_id;
            return .{
                .transmission = .{ .pubrel = pubrel },
                .packet_id = packet_id,
                .kind = kind,
            };
        },
    };
    return .{
        .transmission = detached,
        .packet_id = packet_id,
        .kind = kind,
    };
}

fn detachedPublishByteCount(
    publish: session.PublishTransmission,
) session.Error!usize {
    var count = std.math.add(
        usize,
        publish.topic.len,
        publish.payload.len,
    ) catch return error.SessionByteLimitExceeded;
    for (publish.properties) |property| {
        const property_bytes = switch (property) {
            .binary => |value| value.value.len,
            .utf8 => |value| value.value.len,
            .utf8_pair => |value| std.math.add(
                usize,
                value.key.len,
                value.value.len,
            ) catch return error.SessionByteLimitExceeded,
            else => 0,
        };
        count = std.math.add(
            usize,
            count,
            property_bytes,
        ) catch return error.SessionByteLimitExceeded;
    }
    return count;
}

fn copyBytes(
    storage: []u8,
    offset: *usize,
    source: []const u8,
) []u8 {
    const destination = storage[offset.*..][0..source.len];
    @memcpy(destination, source);
    offset.* += source.len;
    return destination;
}

fn copyProperty(
    storage: []u8,
    offset: *usize,
    property: mqtt.Property,
) mqtt.Property {
    return switch (property) {
        .byte, .two_byte, .four_byte, .varint => property,
        .binary => |value| .{ .binary = .{
            .id = value.id,
            .value = copyBytes(storage, offset, value.value),
        } },
        .utf8 => |value| .{ .utf8 = .{
            .id = value.id,
            .value = copyBytes(storage, offset, value.value),
        } },
        .utf8_pair => |value| .{ .utf8_pair = .{
            .id = value.id,
            .key = copyBytes(storage, offset, value.key),
            .value = copyBytes(storage, offset, value.value),
        } },
    };
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

test "detached Session transmission caps publish QoS" {
    const allocator = std.testing.allocator;
    const transmission = session.Transmission{ .publish = .{
        .topic = "maximum/qos",
        .payload = "payload",
        .qos = .exactly_once,
        .retain = false,
        .dup = false,
        .packet_id = 7,
        .properties = &.{},
        .message_expiry_interval = null,
    } };
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    const detached = try detachTransmission(
        &bytes,
        &properties,
        allocator,
        transmission,
        .at_least_once,
    );
    try std.testing.expectEqual(.publish, detached.kind);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        detached.transmission.publish.qos,
    );
    try std.testing.expectEqual(@as(u16, 7), detached.packet_id);
}

test "detached Session transmission records QoS0 completion metadata" {
    const allocator = std.testing.allocator;
    const transmission = session.Transmission{ .publish = .{
        .topic = "maximum/qos0",
        .payload = "payload",
        .qos = .at_least_once,
        .retain = false,
        .dup = true,
        .packet_id = 7,
        .properties = &.{},
        .message_expiry_interval = null,
    } };
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    const detached = try detachTransmission(
        &bytes,
        &properties,
        allocator,
        transmission,
        .at_most_once,
    );
    try std.testing.expectEqual(.qos0_publish, detached.kind);
    try std.testing.expectEqual(@as(u16, 7), detached.packet_id);
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        detached.transmission.publish.qos,
    );
}

test "detached Session transmission owns bytes and reuses caller scratch" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = failing.allocator();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var property_scratch: std.ArrayList(mqtt.Property) = .empty;
    defer property_scratch.deinit(allocator);
    var topic = [_]u8{ 'd', 'u', 'r', 'a', 'b', 'l', 'e' };
    var payload = [_]u8{ 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
    var binary = [_]u8{ 'b', 'i', 'n' };
    var response_topic = [_]u8{ 'r', 'e', 'p', 'l', 'y' };
    var key = [_]u8{ 'k', 'e', 'y' };
    var value = [_]u8{ 'v', 'a', 'l', 'u', 'e' };
    var source_properties = [_]mqtt.Property{
        .{ .binary = .{
            .id = .correlation_data,
            .value = &binary,
        } },
        .{ .utf8 = .{
            .id = .response_topic,
            .value = &response_topic,
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = &key,
            .value = &value,
        } },
    };
    const transmission = session.Transmission{ .publish = .{
        .topic = &topic,
        .payload = &payload,
        .qos = .exactly_once,
        .retain = false,
        .dup = false,
        .packet_id = 9,
        .properties = &source_properties,
        .message_expiry_interval = null,
    } };
    const first = try detachTransmission(
        &bytes,
        &property_scratch,
        allocator,
        transmission,
        .exactly_once,
    );
    @memset(&topic, 'x');
    @memset(&payload, 'x');
    @memset(&binary, 'x');
    @memset(&response_topic, 'x');
    @memset(&key, 'x');
    @memset(&value, 'x');
    try std.testing.expectEqualStrings(
        "durable",
        first.transmission.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "payload",
        first.transmission.publish.payload,
    );
    try std.testing.expectEqualStrings(
        "bin",
        first.transmission.publish.properties[0].binary.value,
    );
    try std.testing.expectEqualStrings(
        "reply",
        first.transmission.publish.properties[1].utf8.value,
    );
    try std.testing.expectEqualStrings(
        "key",
        first.transmission.publish.properties[2].utf8_pair.key,
    );
    try std.testing.expectEqualStrings(
        "value",
        first.transmission.publish.properties[2].utf8_pair.value,
    );
    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;

    const detached = try detachTransmission(
        &bytes,
        &property_scratch,
        allocator,
        transmission,
        .exactly_once,
    );
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(@as(u16, 9), detached.packet_id);
    try std.testing.expectEqual(.publish, detached.kind);
}

pub fn connectionSubscriberId(
    index: usize,
    generation: u32,
) router.SubscriberId {
    std.debug.assert(
        generation != 0 and generation <= max_connection_generation,
    );
    return (@as(u64, generation) << 32) | @as(u32, @intCast(index));
}

pub fn nextConnectionGeneration(current: u32) u32 {
    return if (current >= max_connection_generation) 1 else current + 1;
}

pub fn sessionSubscriberId(route_id: u64) router.SubscriberId {
    std.debug.assert(route_id != 0 and route_id < session_subscriber_tag);
    return session_subscriber_tag | route_id;
}

pub fn sessionRouteId(id: router.SubscriberId) ?u64 {
    if ((id & session_subscriber_tag) == 0) return null;
    return id & ~session_subscriber_tag;
}

pub fn connectionIndex(
    id: router.SubscriberId,
    count: usize,
) ?usize {
    if (sessionRouteId(id) != null) return null;
    const index: usize = @intCast(@as(u32, @truncate(id)));
    return if (index < count) index else null;
}

test "Session and connection subscriber namespaces stay disjoint" {
    const connection_id = connectionSubscriberId(
        std.math.maxInt(u32),
        max_connection_generation,
    );
    try std.testing.expect(sessionRouteId(connection_id) == null);
    try std.testing.expectEqual(
        @as(u32, 1),
        nextConnectionGeneration(max_connection_generation),
    );

    const session_id = sessionSubscriberId(session_subscriber_tag - 1);
    try std.testing.expectEqual(
        session_subscriber_tag - 1,
        sessionRouteId(session_id).?,
    );
    try std.testing.expect(
        connectionIndex(session_id, std.math.maxInt(u32)) == null,
    );
}

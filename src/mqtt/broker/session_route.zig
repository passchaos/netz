//! Stable broker routing identities and detached Session packet encoding.
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

pub const EncodedPacket = struct {
    bytes: []u8,
    packet_id: u16,
    kind: enum {
        qos0_publish,
        publish,
        pubrel,
    },
};

pub fn encodeTransmission(
    encoded: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: mqtt.ProtocolVersion,
    transmission: session.Transmission,
    maximum_qos: mqtt.QoS,
) session.Error!EncodedPacket {
    encoded.clearRetainingCapacity();
    errdefer encoded.clearRetainingCapacity();
    var packet_id: u16 = 0;
    var kind: @FieldType(EncodedPacket, "kind") = .pubrel;
    switch (transmission) {
        .publish => |publish| {
            var capped = publish;
            capped.qos = minQos(capped.qos, maximum_qos);
            packet_id = publish.packet_id;
            kind = if (capped.qos == .at_most_once)
                .qos0_publish
            else
                .publish;
            try capped.write(
                encoded,
                allocator,
                protocol,
            );
        },
        .pubrel => |pubrel| {
            packet_id = pubrel.packet_id;
            try pubrel.write(encoded, allocator, protocol);
        },
    }
    return .{
        .bytes = encoded.items,
        .packet_id = packet_id,
        .kind = kind,
    };
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

test "Session transmission encoding caps publish QoS" {
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
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(allocator);
    const encoded = try encodeTransmission(
        &scratch,
        allocator,
        .v5,
        transmission,
        .at_least_once,
    );
    var parsed = try mqtt.Publish.parse(
        allocator,
        .v5,
        encoded.bytes,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, parsed.qos);
    try std.testing.expectEqual(@as(?u16, 7), parsed.packet_id);
}

test "Session transmission capped to QoS0 omits packet identifier" {
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
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(allocator);
    const encoded = try encodeTransmission(
        &scratch,
        allocator,
        .v5,
        transmission,
        .at_most_once,
    );
    try std.testing.expectEqual(.qos0_publish, encoded.kind);
    try std.testing.expectEqual(@as(u16, 7), encoded.packet_id);
    var parsed = try mqtt.Publish.parse(allocator, .v5, encoded.bytes);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, parsed.qos);
    try std.testing.expect(!parsed.dup);
    try std.testing.expectEqual(@as(?u16, null), parsed.packet_id);
}

test "Session transmission encoding reuses caller scratch" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = failing.allocator();
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(allocator);
    const transmission = session.Transmission{ .publish = .{
        .topic = "durable/reuse",
        .payload = "payload",
        .qos = .exactly_once,
        .retain = false,
        .dup = false,
        .packet_id = 9,
        .properties = &.{},
        .message_expiry_interval = null,
    } };
    _ = try encodeTransmission(
        &scratch,
        allocator,
        .v5,
        transmission,
        .exactly_once,
    );
    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;

    const encoded = try encodeTransmission(
        &scratch,
        allocator,
        .v5,
        transmission,
        .exactly_once,
    );
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(@as(u16, 9), encoded.packet_id);
    try std.testing.expectEqual(.publish, encoded.kind);
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

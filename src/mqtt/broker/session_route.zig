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
    allocator: std.mem.Allocator,
    bytes: []u8,
    packet_id: u16,
    kind: enum {
        publish,
        pubrel,
    },

    pub fn deinit(self: *EncodedPacket) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn encodeTransmission(
    allocator: std.mem.Allocator,
    protocol: mqtt.ProtocolVersion,
    transmission: session.Transmission,
    maximum_qos: mqtt.QoS,
) session.Error!EncodedPacket {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);
    const metadata: struct {
        packet_id: u16,
        kind: @FieldType(EncodedPacket, "kind"),
    } = switch (transmission) {
        .publish => |publish| .{
            .packet_id = publish.packet_id,
            .kind = .publish,
        },
        .pubrel => |pubrel| .{
            .packet_id = pubrel.packet_id,
            .kind = .pubrel,
        },
    };
    switch (transmission) {
        .publish => |publish| {
            var capped = publish;
            capped.qos = minQos(capped.qos, maximum_qos);
            try capped.write(
                &encoded,
                allocator,
                protocol,
            );
        },
        .pubrel => |pubrel| try pubrel.write(
            &encoded,
            allocator,
            protocol,
        ),
    }
    return .{
        .allocator = allocator,
        .bytes = try encoded.toOwnedSlice(allocator),
        .packet_id = metadata.packet_id,
        .kind = metadata.kind,
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
    var encoded = try encodeTransmission(
        allocator,
        .v5,
        transmission,
        .at_least_once,
    );
    defer encoded.deinit();
    var parsed = try mqtt.Publish.parse(
        allocator,
        .v5,
        encoded.bytes,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, parsed.qos);
    try std.testing.expectEqual(@as(?u16, 7), parsed.packet_id);
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

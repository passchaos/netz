const std = @import("std");
const wire = @import("../internal/wire.zig");
const ack_reason = @import("ack_reason.zig");

pub const validateAckReasonCode = ack_reason.validate;

pub const runtime = @import("runtime.zig");
pub const reconnect = @import("reconnect.zig");
pub const broker = @import("broker.zig");
pub const bridge = @import("bridge.zig");
pub const websocket_runtime = @import("websocket_runtime.zig");
pub const tls_runtime = @import("tls_runtime.zig");
pub const router = @import("router.zig");
pub const retained = @import("retained/mod.zig");
pub const session = @import("session/mod.zig");
pub const persistence = @import("persistence/mod.zig");
pub const redirect = @import("redirect.zig");
pub const proxy_protocol = @import("proxy_protocol.zig");
pub const listener_namespace = @import("listener_namespace.zig");
pub const broker_config = @import("broker_config.zig");
pub const password_file = @import("password_file.zig");
pub const acl_file = @import("acl_file.zig");
pub const will_scheduler = @import("will/mod.zig");
pub const testing = @import("testing/mod.zig");

test {
    _ = ack_reason;
    _ = listener_namespace;
    _ = broker_config;
    _ = password_file;
    _ = acl_file;
}

pub const Error = wire.Error || error{
    BufferTooShort,
    MalformedRemainingLength,
    RemainingLengthTooLarge,
    InvalidPacketType,
    ReservedPacketType,
    InvalidPacketDirection,
    InvalidFlags,
    InvalidProtocolName,
    InvalidProtocolLevel,
    InvalidUtf8,
    InvalidQoS,
    InvalidProperty,
    InvalidPropertyIdentifier,
    MalformedPropertyContext,
    InvalidReasonCode,
    InvalidTopic,
    InvalidSubscription,
    MalformedSubscriptionOptions,
    InvalidClientId,
    InvalidPacketIdentifier,
    IntegerOverflow,
} || std.mem.Allocator.Error;

pub const ProtocolVersion = enum(u8) {
    v3_1 = 3,
    v3_1_1 = 4,
    v5 = 5,

    pub fn byte(self: ProtocolVersion) u8 {
        return @intFromEnum(self);
    }

    pub fn isLegacy(self: ProtocolVersion) bool {
        return self != .v5;
    }
};

/// MQTT protocol versions a server listener permits during CONNECT.
///
/// All implemented versions are enabled by default. Keeping this independent
/// of the parser's initial protocol hint lets one listener auto-detect both
/// versions while still enforcing a listener-specific admission policy.
pub const AcceptedProtocolVersions = struct {
    v3_1: bool = true,
    v3_1_1: bool = true,
    v5: bool = true,

    pub fn allows(self: AcceptedProtocolVersions, version: ProtocolVersion) bool {
        return switch (version) {
            .v3_1 => self.v3_1,
            .v3_1_1 => self.v3_1_1,
            .v5 => self.v5,
        };
    }

    pub fn any(self: AcceptedProtocolVersions) bool {
        return self.v3_1 or self.v3_1_1 or self.v5;
    }
};

pub const PacketType = enum(u4) {
    connect = 1,
    connack = 2,
    publish = 3,
    puback = 4,
    pubrec = 5,
    pubrel = 6,
    pubcomp = 7,
    subscribe = 8,
    suback = 9,
    unsubscribe = 10,
    unsuback = 11,
    pingreq = 12,
    pingresp = 13,
    disconnect = 14,
    auth = 15,

    pub fn defaultFlags(self: PacketType) u4 {
        return switch (self) {
            .publish => 0, // PUBLISH carries DUP/QoS/retain in the low nibble.
            .pubrel, .subscribe, .unsubscribe => 0x2,
            else => 0x0,
        };
    }
};

pub const PacketSender = enum { client, server };

/// Validate the endpoint direction assigned to every MQTT Control Packet by
/// MQTT 5 Table 2-1. The same direction rules apply to MQTT 3.1.1; AUTH is
/// rejected separately by its version-aware codec when used outside MQTT 5.
pub fn validatePacketTypeForSender(
    packet_type: PacketType,
    sender: PacketSender,
) Error!void {
    switch (sender) {
        .client => switch (packet_type) {
            .connack, .suback, .unsuback, .pingresp => return error.InvalidPacketDirection,
            else => {},
        },
        .server => switch (packet_type) {
            .connect, .subscribe, .unsubscribe, .pingreq => return error.InvalidPacketDirection,
            else => {},
        },
    }
}

pub const FixedHeader = struct {
    packet_type: PacketType,
    flags: u4,
    remaining_len: usize,
    header_len: usize,

    pub fn parse(bytes: []const u8) Error!FixedHeader {
        if (bytes.len < 2) return error.BufferTooShort;
        const packet_type = try packetTypeFromFirstByte(bytes[0]);
        const decoded = try decodeRemainingLength(bytes[1..]);
        return .{
            .packet_type = packet_type,
            .flags = @truncate(bytes[0] & 0x0f),
            .remaining_len = decoded.value,
            .header_len = 1 + decoded.len,
        };
    }

    pub fn write(self: FixedHeader, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        if (self.remaining_len > 268_435_455) {
            return error.RemainingLengthTooLarge;
        }
        const encoded_len = 1 + remainingLengthEncodedLen(self.remaining_len);
        try list.ensureUnusedCapacity(allocator, encoded_len);
        list.appendAssumeCapacity(
            (@as(u8, @intFromEnum(self.packet_type)) << 4) | self.flags,
        );
        encodeRemainingLengthAssumeCapacity(list, self.remaining_len);
    }
};

/// Parse the Control Packet type as soon as the first fixed-header byte is
/// available. Stream framers use this before consuming Remaining Length so a
/// reserved type remains the primary Protocol Error even when later framing is
/// independently malformed.
pub fn packetTypeFromFirstByte(first: u8) Error!PacketType {
    const packet_nibble: u4 = @truncate(first >> 4);
    if (packet_nibble == 0) return error.ReservedPacketType;
    return std.enums.fromInt(PacketType, packet_nibble) orelse
        error.InvalidPacketType;
}

test "MQTT fixed header distinguishes reserved packet type zero" {
    try std.testing.expectError(
        error.ReservedPacketType,
        FixedHeader.parse(&.{ 0x00, 0x00 }),
    );
    try std.testing.expectError(
        error.ReservedPacketType,
        FixedHeader.parse(&.{ 0x0f, 0x00 }),
    );
}

test "MQTT fixed header write is transactional" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try encoded.ensureTotalCapacityPrecise(std.testing.allocator, 1);
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        (FixedHeader{
            .packet_type = .publish,
            .flags = 0,
            .remaining_len = 0,
            .header_len = 0,
        }).write(&encoded, failing.allocator()),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    try encoded.appendBounded(0xa5);
    try std.testing.expectError(
        error.RemainingLengthTooLarge,
        (FixedHeader{
            .packet_type = .publish,
            .flags = 0,
            .remaining_len = 268_435_456,
            .header_len = 0,
        }).write(&encoded, std.testing.allocator),
    );
    try std.testing.expectEqualSlices(u8, &.{0xa5}, encoded.items);

    var exact_storage: [5]u8 = undefined;
    var exact = std.ArrayList(u8).initBuffer(&exact_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try (FixedHeader{
        .packet_type = .publish,
        .flags = 0,
        .remaining_len = 268_435_455,
        .header_len = 0,
    }).write(&exact, no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0xff, 0xff, 0xff, 0x7f },
        exact.items,
    );
}

fn validateControlFlags(fixed: FixedHeader) Error!void {
    if (fixed.packet_type != .publish and fixed.flags != fixed.packet_type.defaultFlags()) return error.InvalidFlags;
}

/// Validate the complete fixed-header flag field for an established protocol
/// version. MQTT 3.1 used DUP on retransmitted QoS-1 control packets;
/// MQTT 3.1.1 replaced those shapes with one mandatory reserved pattern.
pub fn validatePacketFlags(
    protocol: ProtocolVersion,
    fixed: FixedHeader,
) Error!void {
    if (fixed.packet_type == .publish) {
        const qos_bits = (fixed.flags >> 1) & 0x03;
        if (qos_bits == 0x03) return error.InvalidQoS;
        if (qos_bits == 0 and (fixed.flags & 0x08) != 0) {
            return error.InvalidFlags;
        }
        return;
    }
    if (protocol == .v3_1 and
        (fixed.packet_type == .pubrel or
            fixed.packet_type == .subscribe or
            fixed.packet_type == .unsubscribe) and
        (fixed.flags == 0x02 or fixed.flags == 0x0a))
    {
        return;
    }
    try validateControlFlags(fixed);
}

fn validatePacketBounds(packet: []const u8, fixed: FixedHeader) Error!void {
    const total = std.math.add(usize, fixed.header_len, fixed.remaining_len) catch return error.RemainingLengthTooLarge;
    if (packet.len < total) return error.BufferTooShort;
    if (packet.len != total) return error.InvalidPacketType;
}

pub fn encodeRemainingLength(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: usize) Error!void {
    if (value > 268_435_455) return error.RemainingLengthTooLarge;
    try list.ensureUnusedCapacity(allocator, remainingLengthEncodedLen(value));
    encodeRemainingLengthAssumeCapacity(list, value);
}

fn encodeRemainingLengthInto(out: []u8, value: usize) Error!usize {
    if (value > 268_435_455) return error.RemainingLengthTooLarge;
    const required = remainingLengthEncodedLen(value);
    if (out.len < required) return error.BufferTooShort;
    var remaining = value;
    var index: usize = 0;
    while (true) : (index += 1) {
        var encoded: u8 = @intCast(remaining % 128);
        remaining /= 128;
        if (remaining != 0) encoded |= 0x80;
        out[index] = encoded;
        if (remaining == 0) return index + 1;
    }
}

pub fn decodeRemainingLength(bytes: []const u8) Error!struct { value: usize, len: usize } {
    var multiplier: usize = 1;
    var value: usize = 0;
    for (bytes, 0..) |byte, i| {
        value += @as(usize, byte & 127) * multiplier;
        if ((byte & 128) == 0) {
            const len = i + 1;
            if (remainingLengthEncodedLen(value) != len) return error.MalformedRemainingLength;
            return .{ .value = value, .len = len };
        }
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128) return error.MalformedRemainingLength;
    }
    return error.BufferTooShort;
}

fn remainingLengthEncodedLen(value: usize) usize {
    if (value < 128) return 1;
    if (value < 128 * 128) return 2;
    if (value < 128 * 128 * 128) return 3;
    return 4;
}

pub fn writeUtf8(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    if (value.len > std.math.maxInt(u16)) return error.InvalidUtf8;
    try validateMqttUtf8String(value);
    try list.ensureUnusedCapacity(allocator, 2 + value.len);
    appendLengthPrefixedAssumeCapacity(list, value);
}

pub fn readUtf8(cursor: *wire.Cursor) Error![]const u8 {
    const len = try cursor.readInt(u16, .big);
    const value = try cursor.readSlice(len);
    try validateMqttUtf8String(value);
    return value;
}

fn validateMqttUtf8String(value: []const u8) Error!void {
    return validateMqttUtf8StringWithPolicy(value, false);
}

fn validateMqttUtf8StringWithPolicy(
    value: []const u8,
    comptime reject_discouraged_controls: bool,
) Error!void {
    // MQTT identifiers and topic names are overwhelmingly ASCII. Validate that
    // prefix once and return without constructing a UTF-8 iterator when the
    // whole string is ASCII. Starting the general decoder at the first
    // non-ASCII byte also avoids rescanning a valid prefix on mixed strings.
    var first_non_ascii = value.len;
    for (value, 0..) |byte, index| {
        if (byte >= 0x80) {
            first_non_ascii = index;
            break;
        }
        if (byte == 0 or
            (reject_discouraged_controls and
                (byte <= 0x1f or byte == 0x7f)))
        {
            return error.InvalidUtf8;
        }
    }
    if (first_non_ascii == value.len) return;

    var view = std.unicode.Utf8View.init(
        value[first_non_ascii..],
    ) catch return error.InvalidUtf8;
    var it = view.iterator();
    while (it.nextCodepoint()) |codepoint| {
        // MQTT 5 section 1.5.4 requires UTF-8 Encoded Strings to exclude
        // U+0000 and every Unicode noncharacter. C0/C1 controls are only
        // "SHOULD NOT" and remain a policy decision handled by
        // validateStrictUtf8String.
        if (codepoint == 0 or
            (codepoint >= 0xfdd0 and codepoint <= 0xfdef) or
            (codepoint & 0xffff == 0xfffe) or
            (codepoint & 0xffff == 0xffff) or
            (reject_discouraged_controls and
                (codepoint <= 0x001f or
                    (codepoint >= 0x007f and codepoint <= 0x009f))))
        {
            return error.InvalidUtf8;
        }
    }
}

pub fn validateUtf8String(value: []const u8) Error!void {
    return validateMqttUtf8String(value);
}

/// Apply Mosquitto's stricter application policy to an MQTT UTF-8 Encoded
/// String. The wire codec intentionally accepts the specification's
/// discouraged C0/C1 controls; brokers that need Mosquitto-compatible input
/// rejection can opt into this additional check at the connection boundary.
pub fn validateStrictUtf8String(value: []const u8) Error!void {
    return validateMqttUtf8StringWithPolicy(value, true);
}

/// Apply the strict UTF-8 policy to every UTF-8 Encoded String carried by an
/// MQTT 5 property list. Binary Data remains opaque by definition.
pub fn validateStrictUtf8Properties(properties: []const Property) Error!void {
    for (properties) |property| switch (property) {
        .utf8 => |value| try validateStrictUtf8String(value.value),
        .utf8_pair => |value| {
            try validateStrictUtf8String(value.key);
            try validateStrictUtf8String(value.value);
        },
        else => {},
    };
}

pub fn writeBinary(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    if (value.len > std.math.maxInt(u16)) return error.InvalidProperty;
    try list.ensureUnusedCapacity(allocator, 2 + value.len);
    appendLengthPrefixedAssumeCapacity(list, value);
}

pub fn readBinary(cursor: *wire.Cursor) Error![]const u8 {
    const len = try cursor.readInt(u16, .big);
    return cursor.readSlice(len);
}

test "MQTT primitive encoders are transactional on allocation failure" {
    var remaining: std.ArrayList(u8) = .empty;
    defer remaining.deinit(std.testing.allocator);
    try remaining.ensureTotalCapacityPrecise(std.testing.allocator, 1);
    try std.testing.expectEqual(@as(usize, 1), remaining.capacity);
    var failing_remaining = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        encodeRemainingLength(
            &remaining,
            failing_remaining.allocator(),
            128,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);

    var utf8: std.ArrayList(u8) = .empty;
    defer utf8.deinit(std.testing.allocator);
    try utf8.ensureTotalCapacityPrecise(std.testing.allocator, 2);
    try std.testing.expectEqual(@as(usize, 2), utf8.capacity);
    var failing_utf8 = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeUtf8(&utf8, failing_utf8.allocator(), "x"),
    );
    try std.testing.expectEqual(@as(usize, 0), utf8.items.len);

    var binary: std.ArrayList(u8) = .empty;
    defer binary.deinit(std.testing.allocator);
    try binary.ensureTotalCapacityPrecise(std.testing.allocator, 2);
    try std.testing.expectEqual(@as(usize, 2), binary.capacity);
    var failing_binary = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeBinary(&binary, failing_binary.allocator(), "x"),
    );
    try std.testing.expectEqual(@as(usize, 0), binary.items.len);
}

pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,

    pub fn fromFlags(flags: u4) Error!QoS {
        const bits: u2 = @truncate((flags >> 1) & 0x03);
        return std.enums.fromInt(QoS, bits) orelse error.InvalidQoS;
    }
};

pub fn hasWildcards(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "+#") != null;
}

pub fn validTopicName(topic: []const u8) bool {
    return topic.len > 0 and
        topic.len <= std.math.maxInt(u16) and
        validMqttUtf8(topic) and
        !hasWildcards(topic);
}

pub fn validateTopicName(topic: []const u8) Error!void {
    if (!validTopicName(topic)) return error.InvalidTopic;
}

pub fn validTopicFilter(filter: []const u8) bool {
    if (filter.len == 0 or filter.len > std.math.maxInt(u16)) return false;
    if (!validMqttUtf8(filter)) return false;
    if (std.mem.startsWith(u8, filter, "$share/")) return validSharedTopicFilter(filter);
    return validTopicFilterLevels(filter);
}

fn validSharedTopicFilter(filter: []const u8) bool {
    return sharedTopicFilterInner(filter) != null;
}

fn sharedTopicFilterInner(filter: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, filter, "$share/")) return null;
    const rest = filter["$share/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const group = rest[0..slash];
    const shared_filter = rest[slash + 1 ..];
    // MQTT 5 shared subscriptions use "$share/{ShareName}/{TopicFilter}".
    // The share name is a literal name, not a topic level, so reject empty
    // groups and wildcard characters before validating the nested TopicFilter.
    if (group.len == 0 or !validMqttUtf8(group) or hasWildcards(group)) return null;
    if (!validTopicFilterLevels(shared_filter)) return null;
    return shared_filter;
}

fn validMqttUtf8(value: []const u8) bool {
    validateMqttUtf8String(value) catch return false;
    return true;
}

fn validTopicFilterLevels(filter: []const u8) bool {
    if (filter.len == 0) return false;

    var start: usize = 0;
    while (true) {
        const end = std.mem.indexOfScalarPos(u8, filter, start, '/') orelse filter.len;
        const level = filter[start..end];
        const last = end == filter.len;

        if (std.mem.indexOfScalar(u8, level, '#')) |_| {
            // Multi-level wildcard is legal only when it occupies the complete
            // final level.  This mirrors rumqtt's broker/client validation and
            // prevents ambiguous filters such as `sport/#/rank` or `sport#`.
            return level.len == 1 and last;
        }
        if (std.mem.indexOfScalar(u8, level, '+')) |_| {
            // Single-level wildcard must occupy a whole level.
            if (level.len != 1) return false;
        }

        if (last) break;
        start = end + 1;
    }
    return true;
}

pub fn validateTopicFilter(filter: []const u8) Error!void {
    if (!validTopicFilter(filter)) return error.InvalidSubscription;
}

pub fn topicMatchesFilter(topic: []const u8, filter: []const u8) bool {
    const effective_filter = if (std.mem.startsWith(u8, filter, "$share/"))
        sharedTopicFilterInner(filter) orelse return false
    else
        filter;

    // MQTT reserves `$` topics from being matched by a leading wildcard.  For
    // shared subscriptions the reservation applies to the nested Topic Filter,
    // not to the `$share/` wrapper itself; otherwise `$share/group/+` would
    // accidentally match `$SYS/...` topics.
    if (std.mem.startsWith(u8, topic, "$") and !std.mem.startsWith(u8, effective_filter, "$")) return false;

    var topic_levels = std.mem.splitScalar(u8, topic, '/');
    var filter_levels = std.mem.splitScalar(u8, effective_filter, '/');
    while (filter_levels.next()) |filter_level| {
        if (std.mem.eql(u8, filter_level, "#")) return true;

        const topic_level = topic_levels.next() orelse return false;
        if (std.mem.eql(u8, filter_level, "+")) continue;
        if (!std.mem.eql(u8, filter_level, topic_level)) return false;
    }

    return topic_levels.next() == null;
}

pub const PropertyId = enum(u8) {
    payload_format_indicator = 0x01,
    message_expiry_interval = 0x02,
    content_type = 0x03,
    response_topic = 0x08,
    correlation_data = 0x09,
    subscription_identifier = 0x0b,
    session_expiry_interval = 0x11,
    assigned_client_identifier = 0x12,
    server_keep_alive = 0x13,
    authentication_method = 0x15,
    authentication_data = 0x16,
    request_problem_information = 0x17,
    will_delay_interval = 0x18,
    request_response_information = 0x19,
    response_information = 0x1a,
    server_reference = 0x1c,
    reason_string = 0x1f,
    receive_maximum = 0x21,
    topic_alias_maximum = 0x22,
    topic_alias = 0x23,
    maximum_qos = 0x24,
    retain_available = 0x25,
    user_property = 0x26,
    maximum_packet_size = 0x27,
    wildcard_subscription_available = 0x28,
    subscription_identifier_available = 0x29,
    shared_subscription_available = 0x2a,
};

const PropertyWireType = enum {
    byte,
    two_byte,
    four_byte,
    varint,
    binary,
    utf8,
    utf8_pair,
};

fn propertyWireType(id: PropertyId) PropertyWireType {
    return switch (id) {
        .payload_format_indicator,
        .request_problem_information,
        .request_response_information,
        .maximum_qos,
        .retain_available,
        .wildcard_subscription_available,
        .subscription_identifier_available,
        .shared_subscription_available,
        => .byte,

        .server_keep_alive,
        .receive_maximum,
        .topic_alias_maximum,
        .topic_alias,
        => .two_byte,

        .message_expiry_interval,
        .session_expiry_interval,
        .will_delay_interval,
        .maximum_packet_size,
        => .four_byte,

        .subscription_identifier,
        => .varint,

        .correlation_data,
        .authentication_data,
        => .binary,

        .content_type,
        .response_topic,
        .assigned_client_identifier,
        .authentication_method,
        .response_information,
        .server_reference,
        .reason_string,
        => .utf8,

        .user_property,
        => .utf8_pair,
    };
}

pub const Property = union(enum) {
    byte: struct { id: PropertyId, value: u8 },
    two_byte: struct { id: PropertyId, value: u16 },
    four_byte: struct { id: PropertyId, value: u32 },
    varint: struct { id: PropertyId, value: usize },
    binary: struct { id: PropertyId, value: []const u8 },
    utf8: struct { id: PropertyId, value: []const u8 },
    utf8_pair: struct { id: PropertyId, key: []const u8, value: []const u8 },
};

pub fn parseProperties(allocator: std.mem.Allocator, cursor: *wire.Cursor) Error![]Property {
    const properties = try parsePropertiesRaw(allocator, cursor);
    errdefer allocator.free(properties);
    for (properties) |property| {
        try validateProperty(property);
    }
    return properties;
}

fn parsePropertiesRaw(
    allocator: std.mem.Allocator,
    cursor: *wire.Cursor,
) Error![]Property {
    const prop_len_decoded = try decodeRemainingLength(cursor.buf[cursor.pos..]);
    cursor.pos += prop_len_decoded.len;
    const prop_bytes = try cursor.readSlice(prop_len_decoded.value);
    var prop_cursor = wire.Cursor.init(prop_bytes);
    var props: std.ArrayList(Property) = .empty;
    errdefer props.deinit(allocator);
    while (!prop_cursor.eof()) {
        const decoded_id = try decodeRemainingLength(
            prop_cursor.buf[prop_cursor.pos..],
        );
        prop_cursor.pos += decoded_id.len;
        const id_value = std.math.cast(u8, decoded_id.value) orelse
            return error.InvalidPropertyIdentifier;
        const id = std.enums.fromInt(PropertyId, id_value) orelse
            return error.InvalidPropertyIdentifier;
        const prop = switch (propertyWireType(id)) {
            .byte => Property{ .byte = .{ .id = id, .value = try prop_cursor.readByte() } },
            .two_byte => Property{ .two_byte = .{ .id = id, .value = try prop_cursor.readInt(u16, .big) } },
            .four_byte => Property{ .four_byte = .{ .id = id, .value = try prop_cursor.readInt(u32, .big) } },
            .varint => blk: {
                const decoded = try decodeRemainingLength(prop_cursor.buf[prop_cursor.pos..]);
                prop_cursor.pos += decoded.len;
                break :blk Property{ .varint = .{ .id = id, .value = decoded.value } };
            },
            .binary => blk: {
                const len = try prop_cursor.readInt(u16, .big);
                break :blk Property{ .binary = .{ .id = id, .value = try prop_cursor.readSlice(len) } };
            },
            .utf8 => Property{ .utf8 = .{ .id = id, .value = try readUtf8(&prop_cursor) } },
            .utf8_pair => Property{ .utf8_pair = .{ .id = id, .key = try readUtf8(&prop_cursor), .value = try readUtf8(&prop_cursor) } },
        };
        // Response Topic is a Topic Name on the wire, not merely a property
        // value constraint. Preserve its Protocol Error precedence even when
        // the property itself is forbidden in the surrounding packet.
        if (prop == .utf8 and prop.utf8.id == .response_topic) {
            validateTopicName(prop.utf8.value) catch
                return error.InvalidProperty;
        }
        try validatePropertyNotDuplicate(prop, props.items);
        try props.append(allocator, prop);
    }
    return props.toOwnedSlice(allocator);
}

fn parsePropertiesFor(
    allocator: std.mem.Allocator,
    cursor: *wire.Cursor,
    context: PropertyContext,
) Error![]Property {
    const properties = try parsePropertiesRaw(allocator, cursor);
    errdefer allocator.free(properties);
    try validateParsedPropertiesFor(context, properties);
    return properties;
}

pub fn receiveMaximum(properties: []const Property) ?u16 {
    for (properties) |property| {
        if (property == .two_byte and property.two_byte.id == .receive_maximum) return property.two_byte.value;
    }
    return null;
}

/// Return the explicit CONNECT Request Problem Information preference. A null
/// result means the MQTT 5 default of enabled applies.
pub fn requestProblemInformation(
    properties: []const Property,
) ?bool {
    for (properties) |property| {
        if (property == .byte and
            property.byte.id == .request_problem_information)
        {
            return property.byte.value != 0;
        }
    }
    return null;
}

/// Return the explicit CONNECT Request Response Information preference. A null
/// result means the MQTT 5 default of disabled applies.
pub fn requestResponseInformation(
    properties: []const Property,
) ?bool {
    for (properties) |property| {
        if (property == .byte and
            property.byte.id == .request_response_information)
        {
            return property.byte.value != 0;
        }
    }
    return null;
}

pub fn maximumPacketSize(properties: []const Property) ?u32 {
    for (properties) |property| {
        if (property == .four_byte and property.four_byte.id == .maximum_packet_size) return property.four_byte.value;
    }
    return null;
}

pub fn assignedClientIdentifier(
    properties: []const Property,
) ?[]const u8 {
    for (properties) |property| {
        if (property == .utf8 and
            property.utf8.id == .assigned_client_identifier)
        {
            return property.utf8.value;
        }
    }
    return null;
}

/// Return the server-provided CONNACK Response Information value, if present.
pub fn responseInformation(
    properties: []const Property,
) ?[]const u8 {
    for (properties) |property| {
        if (property == .utf8 and
            property.utf8.id == .response_information)
        {
            return property.utf8.value;
        }
    }
    return null;
}

/// Return the MQTT 5 Server Reference carried by CONNACK or DISCONNECT.
/// Packet validation guarantees at most one such property.
pub fn serverReference(
    properties: []const Property,
) ?[]const u8 {
    for (properties) |property| {
        if (property == .utf8 and
            property.utf8.id == .server_reference)
        {
            return property.utf8.value;
        }
    }
    return null;
}

pub fn authenticationMethod(
    properties: []const Property,
) ?[]const u8 {
    for (properties) |property| {
        if (property == .utf8 and
            property.utf8.id == .authentication_method)
        {
            return property.utf8.value;
        }
    }
    return null;
}

pub fn authenticationData(
    properties: []const Property,
) ?[]const u8 {
    for (properties) |property| {
        if (property == .binary and
            property.binary.id == .authentication_data)
        {
            return property.binary.value;
        }
    }
    return null;
}

pub fn messageExpiryInterval(properties: []const Property) ?u32 {
    for (properties) |property| {
        if (property == .four_byte and
            property.four_byte.id == .message_expiry_interval)
        {
            return property.four_byte.value;
        }
    }
    return null;
}

pub fn sessionExpiryInterval(properties: []const Property) ?u32 {
    for (properties) |property| {
        if (property == .four_byte and
            property.four_byte.id == .session_expiry_interval)
        {
            return property.four_byte.value;
        }
    }
    return null;
}

/// Validate the state-dependent Session Expiry rule for a client DISCONNECT.
/// Packet-local property validation cannot enforce this because the original
/// value belongs to the earlier CONNECT packet.
pub fn validateDisconnectSessionExpiry(
    connect_expiry: u32,
    disconnect_expiry: ?u32,
) Error!void {
    const replacement = disconnect_expiry orelse return;
    if (connect_expiry == 0 and replacement != 0) {
        return error.InvalidProperty;
    }
}

pub fn willDelayInterval(properties: []const Property) ?u32 {
    for (properties) |property| {
        if (property == .four_byte and
            property.four_byte.id == .will_delay_interval)
        {
            return property.four_byte.value;
        }
    }
    return null;
}

pub fn validatePublishProperties(
    properties: []const Property,
) Error!void {
    return validatePropertiesFor(.publish, properties);
}

pub fn validateWillProperties(
    properties: []const Property,
    payload: []const u8,
) Error!void {
    try validatePropertiesFor(.will, properties);
    try validatePayloadFormat(properties, payload);
}

pub fn maximumQoS(properties: []const Property) ?QoS {
    for (properties) |property| {
        if (property == .byte and property.byte.id == .maximum_qos) {
            return std.enums.fromInt(QoS, @as(u2, @truncate(property.byte.value))) orelse null;
        }
    }
    return null;
}

pub fn retainAvailable(properties: []const Property) ?bool {
    for (properties) |property| {
        if (property == .byte and property.byte.id == .retain_available) return property.byte.value != 0;
    }
    return null;
}

pub fn wildcardSubscriptionAvailable(properties: []const Property) ?bool {
    for (properties) |property| {
        if (property == .byte and property.byte.id == .wildcard_subscription_available) return property.byte.value != 0;
    }
    return null;
}

pub fn subscriptionIdentifierAvailable(properties: []const Property) ?bool {
    for (properties) |property| {
        if (property == .byte and property.byte.id == .subscription_identifier_available) return property.byte.value != 0;
    }
    return null;
}

pub fn sharedSubscriptionAvailable(properties: []const Property) ?bool {
    for (properties) |property| {
        if (property == .byte and property.byte.id == .shared_subscription_available) return property.byte.value != 0;
    }
    return null;
}

pub fn serverKeepAlive(properties: []const Property) ?u16 {
    for (properties) |property| {
        if (property == .two_byte and property.two_byte.id == .server_keep_alive) return property.two_byte.value;
    }
    return null;
}

pub fn topicAlias(properties: []const Property) ?u16 {
    for (properties) |property| {
        if (property == .two_byte and property.two_byte.id == .topic_alias) return property.two_byte.value;
    }
    return null;
}

pub fn subscriptionIdentifier(properties: []const Property) ?usize {
    for (properties) |property| {
        if (property == .varint and property.varint.id == .subscription_identifier) return property.varint.value;
    }
    return null;
}

fn payloadFormatIsUtf8(properties: []const Property) bool {
    for (properties) |property| {
        if (property == .byte and property.byte.id == .payload_format_indicator) return property.byte.value == 1;
    }
    return false;
}

fn validatePayloadFormat(properties: []const Property, payload: []const u8) Error!void {
    if (payloadFormatIsUtf8(properties) and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
}

pub fn topicAliasMaximum(properties: []const Property) ?u16 {
    for (properties) |property| {
        if (property == .two_byte and property.two_byte.id == .topic_alias_maximum) return property.two_byte.value;
    }
    return null;
}

pub fn writeProperties(list: *std.ArrayList(u8), allocator: std.mem.Allocator, properties: []const Property) Error!void {
    const original_len = list.items.len;
    errdefer list.items.len = original_len;
    const encoded_len = try propertiesEncodedLen(properties);
    if (encoded_len > 268_435_455) return error.RemainingLengthTooLarge;
    const wire_len = std.math.add(
        usize,
        remainingLengthEncodedLen(encoded_len),
        encoded_len,
    ) catch return error.IntegerOverflow;
    try list.ensureUnusedCapacity(allocator, wire_len);
    writePropertiesAssumeCapacity(list, properties, encoded_len);
}

fn propertyEncodedLen(property: Property) Error!usize {
    try validateProperty(property);
    return switch (property) {
        .byte => 2,
        .two_byte => 3,
        .four_byte => 5,
        .varint => |p| blk: {
            if (p.value > 268_435_455) {
                return error.RemainingLengthTooLarge;
            }
            break :blk std.math.add(
                usize,
                1,
                remainingLengthEncodedLen(p.value),
            ) catch return error.IntegerOverflow;
        },
        .binary => |p| std.math.add(
            usize,
            1,
            try encodedLengthPrefixedLen(p.value, false),
        ) catch return error.IntegerOverflow,
        .utf8 => |p| blk: {
            try validateMqttUtf8String(p.value);
            break :blk std.math.add(
                usize,
                1,
                try encodedLengthPrefixedLen(p.value, true),
            ) catch return error.IntegerOverflow;
        },
        .utf8_pair => |p| blk: {
            try validateMqttUtf8String(p.key);
            try validateMqttUtf8String(p.value);
            break :blk std.math.add(
                usize,
                1,
                std.math.add(
                    usize,
                    try encodedLengthPrefixedLen(p.key, true),
                    try encodedLengthPrefixedLen(p.value, true),
                ) catch return error.IntegerOverflow,
            ) catch return error.IntegerOverflow;
        },
    };
}

fn encodedLengthPrefixedLen(
    value: []const u8,
    utf8: bool,
) Error!usize {
    if (value.len > std.math.maxInt(u16)) {
        return if (utf8) error.InvalidUtf8 else error.InvalidProperty;
    }
    return std.math.add(usize, 2, value.len) catch return error.IntegerOverflow;
}

fn propertiesEncodedLen(properties: []const Property) Error!usize {
    var len: usize = 0;
    for (properties, 0..) |property, index| {
        try validatePropertyNotDuplicate(property, properties[0..index]);
        len = std.math.add(usize, len, try propertyEncodedLen(property)) catch
            return error.IntegerOverflow;
    }
    return len;
}

fn writePropertiesAssumeCapacity(
    list: *std.ArrayList(u8),
    properties: []const Property,
    encoded_len: usize,
) void {
    encodeRemainingLengthAssumeCapacity(list, encoded_len);
    for (properties) |property| switch (property) {
        .byte => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            list.appendAssumeCapacity(p.value);
        },
        .two_byte => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            appendIntAssumeCapacity(list, u16, p.value);
        },
        .four_byte => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            appendIntAssumeCapacity(list, u32, p.value);
        },
        .varint => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            encodeRemainingLengthAssumeCapacity(list, p.value);
        },
        .binary => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            appendLengthPrefixedAssumeCapacity(list, p.value);
        },
        .utf8 => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            appendLengthPrefixedAssumeCapacity(list, p.value);
        },
        .utf8_pair => |p| {
            list.appendAssumeCapacity(@intFromEnum(p.id));
            appendLengthPrefixedAssumeCapacity(list, p.key);
            appendLengthPrefixedAssumeCapacity(list, p.value);
        },
    };
}

fn encodeRemainingLengthAssumeCapacity(
    list: *std.ArrayList(u8),
    value: usize,
) void {
    std.debug.assert(value <= 268_435_455);
    var remaining = value;
    while (true) {
        var encoded: u8 = @intCast(remaining % 128);
        remaining /= 128;
        if (remaining != 0) encoded |= 0x80;
        list.appendAssumeCapacity(encoded);
        if (remaining == 0) break;
    }
}

fn appendIntAssumeCapacity(
    list: *std.ArrayList(u8),
    comptime T: type,
    value: T,
) void {
    const start = list.items.len;
    list.items.len += @sizeOf(T);
    std.mem.writeInt(T, list.items[start..][0..@sizeOf(T)], value, .big);
}

fn appendLengthPrefixedAssumeCapacity(
    list: *std.ArrayList(u8),
    value: []const u8,
) void {
    appendIntAssumeCapacity(list, u16, @intCast(value.len));
    list.appendSliceAssumeCapacity(value);
}

fn writeFixedHeaderAssumeCapacity(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    packet_type: PacketType,
    flags: u4,
    remaining_len: usize,
) Error!void {
    if (remaining_len > 268_435_455) return error.RemainingLengthTooLarge;
    const header_len = 1 + remainingLengthEncodedLen(remaining_len);
    try list.ensureUnusedCapacity(
        allocator,
        try addEncodedComponent(header_len, remaining_len),
    );
    list.appendAssumeCapacity(
        (@as(u8, @intFromEnum(packet_type)) << 4) | flags,
    );
    encodeRemainingLengthAssumeCapacity(list, remaining_len);
}

fn validateProperty(property: Property) Error!void {
    if (!propertyHasExpectedWireType(property)) return error.InvalidProperty;

    switch (property) {
        .byte => |p| switch (p.id) {
            .payload_format_indicator,
            .request_problem_information,
            .request_response_information,
            .retain_available,
            .wildcard_subscription_available,
            .subscription_identifier_available,
            .shared_subscription_available,
            => if (p.value > 1) return error.InvalidProperty,
            .maximum_qos => if (p.value > @intFromEnum(QoS.at_least_once)) return error.InvalidProperty,
            else => {},
        },
        .two_byte => |p| switch (p.id) {
            .receive_maximum, .topic_alias => if (p.value == 0) return error.InvalidProperty,
            else => {},
        },
        .four_byte => |p| switch (p.id) {
            .maximum_packet_size => if (p.value == 0) return error.InvalidProperty,
            else => {},
        },
        .varint => |p| switch (p.id) {
            .subscription_identifier => if (p.value == 0) return error.InvalidProperty,
            else => {},
        },
        .utf8 => |p| switch (p.id) {
            .response_topic => validateTopicName(p.value) catch return error.InvalidProperty,
            // MQTT-3.2.2-16 requires this to identify a real Session; the
            // zero-length value is reserved for the client's CONNECT request.
            .assigned_client_identifier => if (p.value.len == 0) {
                return error.InvalidProperty;
            },
            else => {},
        },
        else => {},
    }
}

fn propertyHasExpectedWireType(property: Property) bool {
    return switch (property) {
        .byte => |p| propertyWireType(p.id) == .byte,
        .two_byte => |p| propertyWireType(p.id) == .two_byte,
        .four_byte => |p| propertyWireType(p.id) == .four_byte,
        .varint => |p| propertyWireType(p.id) == .varint,
        .binary => |p| propertyWireType(p.id) == .binary,
        .utf8 => |p| propertyWireType(p.id) == .utf8,
        .utf8_pair => |p| propertyWireType(p.id) == .utf8_pair,
    };
}

fn validatePropertyNotDuplicate(property: Property, previous: []const Property) Error!void {
    const id = propertyId(property);
    if (repeatableProperty(id)) return;
    for (previous) |prior| {
        if (propertyId(prior) == id) return error.InvalidProperty;
    }
}

fn repeatableProperty(id: PropertyId) bool {
    return switch (id) {
        .user_property,
        .subscription_identifier,
        => true,
        else => false,
    };
}

const PropertyContext = enum {
    connect,
    will,
    connack,
    publish,
    subscribe,
    unsubscribe,
    suback,
    ack,
    disconnect,
    auth,
};

fn validatePropertiesFor(context: PropertyContext, properties: []const Property) Error!void {
    for (properties, 0..) |property, index| {
        try validateProperty(property);
        const id = propertyId(property);
        if (!propertyAllowedInContext(context, id)) return error.InvalidProperty;
        try validatePropertyNotDuplicateForContext(context, property, properties[0..index]);
    }
    try validateAuthenticationPropertiesForContext(context, properties);
}

/// Validate properties decoded from the wire. MQTT 5 section 2.2.2.2 makes
/// a known Property Identifier in a Control Packet where it is not valid a
/// Malformed Packet. Local write APIs retain `InvalidProperty` for the same
/// caller mistake, while parsers preserve the peer-facing reason category.
fn validateParsedPropertiesFor(
    context: PropertyContext,
    properties: []const Property,
) Error!void {
    for (properties) |property| {
        if (!propertyAllowedInContext(context, propertyId(property))) {
            return error.MalformedPropertyContext;
        }
    }
    try validatePropertiesFor(context, properties);
}

fn validateAuthenticationPropertiesForContext(context: PropertyContext, properties: []const Property) Error!void {
    switch (context) {
        .connect, .connack, .auth => {},
        else => return,
    }
    var has_authentication_method = false;
    var has_authentication_data = false;
    for (properties) |property| {
        const id = propertyId(property);
        if (id == .authentication_method) has_authentication_method = true;
        if (id == .authentication_data) has_authentication_data = true;
    }
    // MQTT 5 binds Authentication Data to the selected Authentication Method:
    // opaque data is meaningful only after peers agree on the method name.
    // Rejecting orphan data keeps CONNECT/CONNACK/AUTH packets unambiguous at
    // the same context-validation boundary that enforces packet-specific
    // property allow-lists.
    if (has_authentication_data and !has_authentication_method) return error.InvalidProperty;
}

fn validatePropertyNotDuplicateForContext(context: PropertyContext, property: Property, previous: []const Property) Error!void {
    const id = propertyId(property);
    if (repeatablePropertyInContext(context, id)) return;
    for (previous) |prior| {
        if (propertyId(prior) == id) return error.InvalidProperty;
    }
}

fn repeatablePropertyInContext(context: PropertyContext, id: PropertyId) bool {
    return switch (id) {
        .user_property => true,
        // PUBLISH can carry multiple Subscription Identifiers because a message
        // may match several subscriptions.  SUBSCRIBE itself allows at most one
        // identifier; every other packet type forbids the property.
        .subscription_identifier => context == .publish,
        else => false,
    };
}

fn propertyAllowedInContext(context: PropertyContext, id: PropertyId) bool {
    return switch (context) {
        .connect => switch (id) {
            .session_expiry_interval,
            .receive_maximum,
            .maximum_packet_size,
            .topic_alias_maximum,
            .request_response_information,
            .request_problem_information,
            .user_property,
            .authentication_method,
            .authentication_data,
            => true,
            else => false,
        },
        .will => switch (id) {
            .will_delay_interval,
            .payload_format_indicator,
            .message_expiry_interval,
            .content_type,
            .response_topic,
            .correlation_data,
            .user_property,
            => true,
            else => false,
        },
        .connack => switch (id) {
            .session_expiry_interval,
            .receive_maximum,
            .maximum_qos,
            .retain_available,
            .maximum_packet_size,
            .assigned_client_identifier,
            .topic_alias_maximum,
            .reason_string,
            .user_property,
            .wildcard_subscription_available,
            .subscription_identifier_available,
            .shared_subscription_available,
            .server_keep_alive,
            .response_information,
            .server_reference,
            .authentication_method,
            .authentication_data,
            => true,
            else => false,
        },
        .publish => switch (id) {
            .payload_format_indicator,
            .message_expiry_interval,
            .topic_alias,
            .response_topic,
            .correlation_data,
            .user_property,
            .subscription_identifier,
            .content_type,
            => true,
            else => false,
        },
        .subscribe => switch (id) {
            .subscription_identifier,
            .user_property,
            => true,
            else => false,
        },
        .unsubscribe => id == .user_property,
        .suback, .ack => switch (id) {
            .reason_string,
            .user_property,
            => true,
            else => false,
        },
        .disconnect => switch (id) {
            .session_expiry_interval,
            .reason_string,
            .user_property,
            .server_reference,
            => true,
            else => false,
        },
        .auth => switch (id) {
            .authentication_method,
            .authentication_data,
            .reason_string,
            .user_property,
            => true,
            else => false,
        },
    };
}

pub const Connect = struct {
    protocol: ProtocolVersion,
    /// Mosquitto's private bridge marker carried in bit 7 of an MQTT 3.1 or
    /// MQTT 3.1.1 protocol level. It is never valid for MQTT 5.
    bridge_mode: bool = false,
    clean_start: bool,
    keep_alive_seconds: u16,
    client_id: []const u8,
    properties: []Property = &.{},
    will: ?LastWill = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,

    pub fn deinit(self: *Connect, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        if (self.will) |*will| will.deinit(allocator);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, packet: []const u8) Error!Connect {
        const prefix = try parseConnectProtocolPrefix(packet);
        const bridge_mode = (prefix.level & 0x80) != 0;
        const protocol_level = prefix.level & 0x7f;
        const protocol = std.enums.fromInt(
            ProtocolVersion,
            protocol_level,
        ) orelse return error.InvalidProtocolLevel;
        if ((prefix.name == .v3_1) != (protocol == .v3_1)) {
            return error.InvalidProtocolLevel;
        }
        if (bridge_mode and protocol == .v5) {
            return error.InvalidProtocolLevel;
        }
        var cursor = prefix.cursor;
        const connect_flags = try cursor.readByte();
        try validateConnectFlags(protocol, connect_flags);
        const keep_alive = try cursor.readInt(u16, .big);
        const props = if (protocol == .v5) try parsePropertiesFor(
            allocator,
            &cursor,
            .connect,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        const client_id = try readUtf8(&cursor);
        var will: ?LastWill = null;
        if ((connect_flags & 0x04) != 0) {
            const will_props = if (protocol == .v5) try parsePropertiesFor(
                allocator,
                &cursor,
                .will,
            ) else try allocator.alloc(Property, 0);
            errdefer allocator.free(will_props);
            const topic = try readUtf8(&cursor);
            try validateTopicName(topic);
            const payload = try readBinary(&cursor);
            try validatePayloadFormat(will_props, payload);
            will = .{
                .topic = topic,
                .payload = payload,
                .qos = std.enums.fromInt(QoS, @as(u2, @truncate((connect_flags >> 3) & 0x03))) orelse return error.InvalidQoS,
                .retain = (connect_flags & 0x20) != 0,
                .properties = will_props,
            };
        }
        errdefer if (will) |*owned_will| owned_will.deinit(allocator);
        const username = if ((connect_flags & 0x80) != 0) try readUtf8(&cursor) else null;
        const password = if ((connect_flags & 0x40) != 0) try readBinary(&cursor) else null;
        if (!cursor.eof()) return error.InvalidPacketType;
        const clean_start = (connect_flags & 0x02) != 0;
        try validateClientIdentifier(protocol, client_id, clean_start);
        return .{
            .protocol = protocol,
            .bridge_mode = bridge_mode,
            .clean_start = clean_start,
            .keep_alive_seconds = keep_alive,
            .client_id = client_id,
            .properties = props,
            .will = will,
            .username = username,
            .password = password,
        };
    }
};

const ConnectProtocolPrefix = struct {
    cursor: wire.Cursor,
    level: u8,
    name: enum { v3_1, modern },
};

fn parseConnectProtocolPrefix(
    packet: []const u8,
) Error!ConnectProtocolPrefix {
    const prefix = try inspectConnectProtocolPrefix(packet);
    const fixed = try FixedHeader.parse(packet);
    // MQTT 3.1 did not require the CONNECT fixed-header flags to be zero.
    // MQTT 3.1.1 [MQTT-2.2.2-1] introduced that requirement.
    if (prefix.name != .v3_1 and fixed.flags != 0) {
        return error.InvalidFlags;
    }
    return prefix;
}

fn inspectConnectProtocolPrefix(
    packet: []const u8,
) Error!ConnectProtocolPrefix {
    const fixed = try FixedHeader.parse(packet);
    if (fixed.packet_type != .connect) return error.InvalidPacketType;
    try validatePacketBounds(packet, fixed);
    var cursor = wire.Cursor.init(
        packet[fixed.header_len .. fixed.header_len + fixed.remaining_len],
    );
    const protocol_name = try readUtf8(&cursor);
    const name: @FieldType(ConnectProtocolPrefix, "name") =
        if (std.mem.eql(u8, protocol_name, "MQIsdp"))
            .v3_1
        else if (std.mem.eql(u8, protocol_name, "MQTT"))
            .modern
        else
            return error.InvalidProtocolName;
    const level = try cursor.readByte();
    return .{
        .cursor = cursor,
        .level = level,
        .name = name,
    };
}

/// Inspect a structurally complete CONNECT's protocol level without accepting
/// it as a supported protocol. Connection-owning servers use this after
/// `InvalidProtocolLevel` to select the required refusal CONNACK format.
pub fn connectProtocolLevel(packet: []const u8) Error!u8 {
    return (try inspectConnectProtocolPrefix(packet)).level;
}

pub const LastWill = struct {
    topic: []const u8,
    payload: []const u8,
    qos: QoS = .at_most_once,
    retain: bool = false,
    properties: []Property = &.{},

    pub fn deinit(self: *LastWill, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }
};

pub const ConnectPacketOptions = struct {
    client_id: []const u8,
    /// Emit Mosquitto's private bridge protocol-level bit for MQTT 3.1/3.1.1.
    bridge_mode: bool = false,
    clean_start: bool = true,
    keep_alive_seconds: u16 = 30,
    properties: []const Property = &.{},
    will: ?LastWill = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

fn validateConnectFlags(protocol: ProtocolVersion, flags: u8) Error!void {
    if (protocol != .v3_1 and (flags & 0x01) != 0) {
        return error.InvalidFlags;
    }

    const will_flag = (flags & 0x04) != 0;
    const will_qos = (flags >> 3) & 0x03;
    if (protocol != .v3_1 and !will_flag and (flags & 0x38) != 0) {
        return error.InvalidFlags;
    }
    if (will_qos == 0x03) return error.InvalidQoS;

    if (protocol.isLegacy() and (flags & 0xc0) == 0x40) {
        // MQTT 3.1.1 couples the login flags: a password can only appear after
        // a username.  MQTT 5 relaxed this for enhanced-authentication use
        // cases, so keep the stricter check version-scoped instead of rejecting
        // valid v5 password-only CONNECT packets.
        return error.InvalidFlags;
    }
}

pub const ConnAck = struct {
    /// Standard Session Present for MQTT 3.1.1/5. MQTT 3.1 has no such field;
    /// use `mosquittoV31SessionPresent` only when that extension was selected.
    session_present: bool,
    /// Raw MQTT 3.1 Topic Name Compression Response byte. The original
    /// protocol marks every bit reserved and unused, so strict callers ignore
    /// it while compatibility code can inspect the Mosquitto bit-0 extension.
    v3_1_acknowledgement_flags: u8 = 0,
    reason_code: u8,
    properties: []Property = &.{},

    /// Largest complete CONNACK without properties. MQTT 3.1 and 3.1.1 use
    /// four bytes, while MQTT 5 appends the mandatory zero Property Length.
    pub const no_properties_max_len: usize = 5;

    pub fn deinit(self: *ConnAck, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!ConnAck {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .connack) return error.InvalidPacketType;
        if (protocol != .v3_1) try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const ack_flags = try cursor.readByte();
        if (protocol != .v3_1 and (ack_flags & 0xfe) != 0) {
            return error.InvalidFlags;
        }
        const reason_code = try cursor.readByte();
        try validateConnAckReason(protocol, reason_code);
        if (protocol != .v3_1) {
            try validateConnAckSessionPresent(
                protocol,
                (ack_flags & 0x01) != 0,
                reason_code,
            );
        }
        const props = if (protocol == .v5) try parsePropertiesFor(
            allocator,
            &cursor,
            .connack,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (cursor.remaining() != 0) return error.InvalidPacketType;
        return .{
            .session_present = protocol != .v3_1 and
                (ack_flags & 0x01) != 0,
            .v3_1_acknowledgement_flags = if (protocol == .v3_1)
                ack_flags
            else
                0,
            .reason_code = reason_code,
            .properties = props,
        };
    }

    /// Interpret Mosquitto's non-standard MQTT 3.1 Session Present bit.
    pub fn mosquittoV31SessionPresent(self: ConnAck) bool {
        return (self.v3_1_acknowledgement_flags & 0x01) != 0;
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        session_present: bool,
        reason_code: u8,
        properties: []const Property,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        try validateConnAckReason(protocol, reason_code);
        try validateConnAckSessionPresent(
            protocol,
            session_present,
            reason_code,
        );
        const properties_len = if (protocol == .v5) blk: {
            try validatePropertiesFor(.connack, properties);
            break :blk try propertiesEncodedLen(properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        } else 0;
        const remaining_len = 2 + if (protocol == .v5)
            remainingLengthEncodedLen(properties_len) + properties_len
        else
            0;
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .connack,
            0,
            remaining_len,
        );
        list.appendAssumeCapacity(if (session_present) 0x01 else 0x00);
        list.appendAssumeCapacity(reason_code);
        if (protocol == .v5) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
    }

    /// Encode a property-free CONNACK directly into caller storage.
    ///
    /// This bounded form is useful for MQTT 3.1.1 and for MQTT 5 connection
    /// refusals, where a server should still be able to report the protocol
    /// result when its general-purpose allocator is exhausted.
    pub fn writeNoPropertiesInto(
        storage: *[no_properties_max_len]u8,
        protocol: ProtocolVersion,
        session_present: bool,
        reason_code: u8,
    ) Error![]u8 {
        try validateConnAckReason(protocol, reason_code);
        try validateConnAckSessionPresent(
            protocol,
            session_present,
            reason_code,
        );

        storage[0] = @as(u8, @intFromEnum(PacketType.connack)) << 4;
        storage[1] = if (protocol == .v5) 3 else 2;
        storage[2] = @intFromBool(session_present);
        storage[3] = reason_code;
        if (protocol == .v5) {
            storage[4] = 0;
            return storage;
        }
        return storage[0..4];
    }

    /// Encode Mosquitto's bit-0 Session Present extension for MQTT 3.1.
    pub fn writeMosquittoV31(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        session_present: bool,
        reason_code: u8,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        try validateConnAckReason(.v3_1, reason_code);
        if (session_present and reason_code != 0) return error.InvalidFlags;
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .connack,
            0,
            2,
        );
        list.appendAssumeCapacity(@intFromBool(session_present));
        list.appendAssumeCapacity(reason_code);
    }

    /// Caller-buffer form of `writeMosquittoV31`.
    pub fn writeMosquittoV31Into(
        storage: *[no_properties_max_len]u8,
        session_present: bool,
        reason_code: u8,
    ) Error![]u8 {
        try validateConnAckReason(.v3_1, reason_code);
        if (session_present and reason_code != 0) return error.InvalidFlags;
        storage[0] = @as(u8, @intFromEnum(PacketType.connack)) << 4;
        storage[1] = 2;
        storage[2] = @intFromBool(session_present);
        storage[3] = reason_code;
        return storage[0..4];
    }
};

pub const Publish = struct {
    dup: bool,
    qos: QoS,
    retain: bool,
    topic: []const u8,
    packet_id: ?u16,
    properties: []Property = &.{},
    payload: []const u8,

    pub fn deinit(self: *Publish, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!Publish {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .publish) return error.InvalidPacketType;
        try validatePacketFlags(protocol, fixed);
        try validatePacketBounds(packet, fixed);
        return parsePayloadValidated(
            allocator,
            protocol,
            fixed.flags,
            packet[fixed.header_len .. fixed.header_len + fixed.remaining_len],
        );
    }

    /// Parse a PUBLISH payload after a framing layer has already decoded and
    /// bounded the Fixed Header. The caller supplies the low four header bits
    /// and exactly the `remaining_len` bytes; all PUBLISH-specific flag,
    /// property, topic, identifier, and payload validation still applies.
    pub fn parsePayload(
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        flags: u4,
        payload_bytes: []const u8,
    ) Error!Publish {
        try validatePacketFlags(protocol, .{
            .packet_type = .publish,
            .flags = flags,
            .remaining_len = payload_bytes.len,
            .header_len = 0,
        });
        return parsePayloadValidated(
            allocator,
            protocol,
            flags,
            payload_bytes,
        );
    }

    fn parsePayloadValidated(
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        flags: u4,
        payload_bytes: []const u8,
    ) Error!Publish {
        var cursor = wire.Cursor.init(payload_bytes);
        const topic = try readUtf8(&cursor);
        const qos = try QoS.fromFlags(flags);
        const packet_id = if (qos == .at_most_once) null else blk: {
            const id = try cursor.readInt(u16, .big);
            if (id == 0) return error.InvalidPacketIdentifier;
            break :blk id;
        };
        const props = if (protocol == .v5) try parsePropertiesFor(
            allocator,
            &cursor,
            .publish,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (topic.len == 0) {
            if (protocol != .v5 or topicAlias(props) == null) return error.InvalidTopic;
        } else if (hasWildcards(topic)) {
            // readUtf8 above has already enforced the complete MQTT UTF-8
            // profile and the u16 wire length bounds this slice. Only the
            // Topic Name-specific wildcard rule remains here.
            return error.InvalidTopic;
        }
        const payload = cursor.buf[cursor.pos..];
        try validatePayloadFormat(props, payload);
        return .{
            .dup = (flags & 0x08) != 0,
            .qos = qos,
            .retain = (flags & 0x01) != 0,
            .topic = topic,
            .packet_id = packet_id,
            .properties = props,
            .payload = payload,
        };
    }
};

pub const AckPacket = struct {
    packet_type: PacketType,
    packet_id: u16,
    /// MQTT 3.1 uses bit 3 for a retransmitted PUBREL. MQTT 3.1.1 and MQTT 5
    /// require the fixed 0x2 pattern and therefore always decode false.
    dup: bool = false,
    reason_code: u8 = 0,
    properties: []Property = &.{},

    pub fn deinit(self: *AckPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!AckPacket {
        const fixed = try FixedHeader.parse(packet);
        switch (fixed.packet_type) {
            .puback, .pubrec, .pubrel, .pubcomp => {},
            else => return error.InvalidPacketType,
        }
        try validatePacketFlags(protocol, fixed);
        try validatePacketBounds(packet, fixed);
        return parsePayloadValidated(
            allocator,
            protocol,
            fixed.packet_type,
            fixed.flags,
            packet[fixed.header_len .. fixed.header_len + fixed.remaining_len],
        );
    }

    /// Parse an acknowledgement payload after a framing layer has already
    /// decoded and bounded the Fixed Header. The caller supplies exactly the
    /// `remaining_len` bytes; all packet-type, flag, identifier, reason-code,
    /// property, and trailing-byte validation still applies.
    pub fn parsePayload(
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_type: PacketType,
        flags: u4,
        payload_bytes: []const u8,
    ) Error!AckPacket {
        switch (packet_type) {
            .puback, .pubrec, .pubrel, .pubcomp => {},
            else => return error.InvalidPacketType,
        }
        try validatePacketFlags(protocol, .{
            .packet_type = packet_type,
            .flags = flags,
            .remaining_len = payload_bytes.len,
            .header_len = 0,
        });
        return parsePayloadValidated(
            allocator,
            protocol,
            packet_type,
            flags,
            payload_bytes,
        );
    }

    fn parsePayloadValidated(
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_type: PacketType,
        flags: u4,
        payload_bytes: []const u8,
    ) Error!AckPacket {
        var cursor = wire.Cursor.init(payload_bytes);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (protocol.isLegacy()) {
            if (!cursor.eof()) return error.InvalidPacketType;
            return .{
                .packet_type = packet_type,
                .packet_id = packet_id,
                .dup = (flags & 0x08) != 0,
                .properties = try allocator.alloc(Property, 0),
            };
        }

        var reason_code: u8 = 0;
        if (!cursor.eof()) reason_code = try cursor.readByte();
        try validateAckReasonCode(packet_type, reason_code);
        const props = if (!cursor.eof()) try parsePropertiesFor(
            allocator,
            &cursor,
            .ack,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        // The packet-type switch above establishes the ACK context. Apply
        // peer-facing Property validation here so a known Property Identifier
        // used in the wrong Control Packet remains Malformed Packet.
        if (!cursor.eof()) return error.InvalidPacketType;
        return .{
            .packet_type = packet_type,
            .packet_id = packet_id,
            .dup = false,
            .reason_code = reason_code,
            .properties = props,
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_type: PacketType,
        packet_id: u16,
        reason_code: u8,
        properties: []const Property,
    ) Error!void {
        return writeWithDup(
            list,
            allocator,
            protocol,
            packet_type,
            false,
            packet_id,
            reason_code,
            properties,
        );
    }

    /// Encode a QoS acknowledgement with the MQTT 3.1 retransmission bit.
    /// `dup=true` is valid only for MQTT 3.1 PUBREL.
    pub fn writeWithDup(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_type: PacketType,
        dup: bool,
        packet_id: u16,
        reason_code: u8,
        properties: []const Property,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        switch (packet_type) {
            .puback, .pubrec, .pubrel, .pubcomp => {},
            else => return error.InvalidPacketType,
        }
        if (protocol.isLegacy()) {
            if (reason_code != 0) return error.InvalidReasonCode;
            if (properties.len != 0) return error.InvalidProperty;
        } else {
            try validateAckReasonCode(packet_type, reason_code);
            try validateAckProperties(packet_type, properties);
        }
        const properties_len = if (protocol == .v5 and properties.len != 0)
            try propertiesEncodedLen(properties)
        else
            0;
        const include_reason = protocol == .v5 and
            (reason_code != 0 or properties.len != 0);
        const remaining_len = @as(usize, 2) + @intFromBool(include_reason) +
            if (properties.len != 0)
                remainingLengthEncodedLen(properties_len) + properties_len
            else
                0;
        const flags = packet_type.defaultFlags() |
            (if (dup) @as(u4, 0x08) else 0);
        try validatePacketFlags(protocol, .{
            .packet_type = packet_type,
            .flags = flags,
            .remaining_len = remaining_len,
            .header_len = 0,
        });
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            packet_type,
            flags,
            remaining_len,
        );
        appendIntAssumeCapacity(list, u16, packet_id);
        if (include_reason) list.appendAssumeCapacity(reason_code);
        if (properties.len != 0) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
    }

    /// Largest complete PUBACK/PUBREC/PUBREL/PUBCOMP packet that has no
    /// properties. Pre-v5 MQTT and an MQTT 5 success use four bytes; an MQTT 5
    /// non-success reason adds one byte.
    pub const no_properties_max_len: usize = 5;

    /// Encode a property-free acknowledgement directly into caller storage.
    ///
    /// QoS acknowledgements dominate broker control traffic. Keeping this
    /// bounded form independent of ArrayList lets a runtime put it on the
    /// stack while the general `write` path remains available for arbitrary
    /// Reason String and User Property values.
    pub fn writeNoPropertiesInto(
        storage: *[no_properties_max_len]u8,
        protocol: ProtocolVersion,
        packet_type: PacketType,
        packet_id: u16,
        reason_code: u8,
    ) Error![]u8 {
        return writeNoPropertiesIntoWithDup(
            storage,
            protocol,
            packet_type,
            false,
            packet_id,
            reason_code,
        );
    }

    /// Caller-buffer form of `writeWithDup` for property-free ACK packets.
    pub fn writeNoPropertiesIntoWithDup(
        storage: *[no_properties_max_len]u8,
        protocol: ProtocolVersion,
        packet_type: PacketType,
        dup: bool,
        packet_id: u16,
        reason_code: u8,
    ) Error![]u8 {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        switch (packet_type) {
            .puback, .pubrec, .pubrel, .pubcomp => {},
            else => return error.InvalidPacketType,
        }
        if (protocol.isLegacy()) {
            if (reason_code != 0) return error.InvalidReasonCode;
        } else {
            try validateAckReasonCode(packet_type, reason_code);
        }

        const include_reason = protocol == .v5 and reason_code != 0;
        const remaining_len: u8 = if (include_reason) 3 else 2;
        const flags = packet_type.defaultFlags() |
            (if (dup) @as(u4, 0x08) else 0);
        try validatePacketFlags(protocol, .{
            .packet_type = packet_type,
            .flags = flags,
            .remaining_len = remaining_len,
            .header_len = 0,
        });
        storage[0] = (@as(u8, @intFromEnum(packet_type)) << 4) |
            flags;
        storage[1] = remaining_len;
        std.mem.writeInt(u16, storage[2..4], packet_id, .big);
        if (include_reason) storage[4] = reason_code;
        return storage[0 .. 2 + @as(usize, remaining_len)];
    }

    pub fn accepted(self: AckPacket) bool {
        return self.reason_code < 0x80;
    }
};

fn validateAckProperties(packet_type: PacketType, properties: []const Property) Error!void {
    switch (packet_type) {
        .puback, .pubrec, .pubrel, .pubcomp => {},
        else => return error.InvalidPacketType,
    }
    try validatePropertiesFor(.ack, properties);
}

pub const Subscription = struct {
    topic_filter: []const u8,
    qos: QoS = .at_most_once,
    no_local: bool = false,
    retain_as_published: bool = false,
    retain_handling: u2 = 0,
};

pub const Subscribe = struct {
    /// MQTT 3.1 retransmission marker. Later protocol versions require false.
    dup: bool = false,
    packet_id: u16,
    properties: []Property = &.{},
    subscriptions: []Subscription,

    pub fn deinit(self: *Subscribe, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        allocator.free(self.subscriptions);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!Subscribe {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .subscribe) return error.InvalidPacketType;
        try validatePacketFlags(protocol, fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parsePropertiesFor(
            allocator,
            &cursor,
            .subscribe,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);

        var subs: std.ArrayList(Subscription) = .empty;
        errdefer subs.deinit(allocator);
        while (!cursor.eof()) {
            const topic_filter = try readUtf8(&cursor);
            const options = try cursor.readByte();
            try validateTopicFilter(topic_filter);
            try validateParsedSubscriptionOptions(protocol, options);
            try validateSharedSubscriptionOptions(protocol, topic_filter, options);
            try subs.append(allocator, .{
                .topic_filter = topic_filter,
                .qos = std.enums.fromInt(QoS, @as(u2, @truncate(options & 0x03))) orelse return error.InvalidQoS,
                .no_local = (options & 0x04) != 0,
                .retain_as_published = (options & 0x08) != 0,
                .retain_handling = @truncate((options >> 4) & 0x03),
            });
        }
        if (subs.items.len == 0) return error.InvalidSubscription;
        return .{
            .dup = (fixed.flags & 0x08) != 0,
            .packet_id = packet_id,
            .properties = props,
            .subscriptions = try subs.toOwnedSlice(allocator),
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_id: u16,
        properties: []const Property,
        subscriptions: []const Subscription,
    ) Error!void {
        return writeWithDup(
            list,
            allocator,
            protocol,
            false,
            packet_id,
            properties,
            subscriptions,
        );
    }

    /// Encode MQTT 3.1 retransmission state. Later versions reject `dup=true`.
    pub fn writeWithDup(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        dup: bool,
        packet_id: u16,
        properties: []const Property,
        subscriptions: []const Subscription,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (subscriptions.len == 0) return error.InvalidSubscription;
        const properties_len = if (protocol == .v5) blk: {
            try validatePropertiesFor(.subscribe, properties);
            break :blk try propertiesEncodedLen(properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        } else 0;
        var remaining_len: usize = 2;
        if (protocol == .v5) remaining_len = try addEncodedComponent(
            remaining_len,
            remainingLengthEncodedLen(properties_len) + properties_len,
        );
        for (subscriptions) |subscription| {
            try validateTopicFilter(subscription.topic_filter);
            const options: u8 = @intFromEnum(subscription.qos) |
                (if (subscription.no_local) @as(u8, 0x04) else 0) |
                (if (subscription.retain_as_published) @as(u8, 0x08) else 0) |
                (@as(u8, subscription.retain_handling) << 4);
            try validateSubscriptionOptions(protocol, options);
            try validateSharedSubscriptionOptions(protocol, subscription.topic_filter, options);
            remaining_len = try addEncodedComponent(
                remaining_len,
                1 + try encodedLengthPrefixedLen(
                    subscription.topic_filter,
                    true,
                ),
            );
        }
        const flags = PacketType.subscribe.defaultFlags() |
            (if (dup) @as(u4, 0x08) else 0);
        try validatePacketFlags(protocol, .{
            .packet_type = .subscribe,
            .flags = flags,
            .remaining_len = remaining_len,
            .header_len = 0,
        });
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .subscribe,
            flags,
            remaining_len,
        );
        appendIntAssumeCapacity(list, u16, packet_id);
        if (protocol == .v5) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
        for (subscriptions) |subscription| {
            appendLengthPrefixedAssumeCapacity(list, subscription.topic_filter);
            list.appendAssumeCapacity(
                @intFromEnum(subscription.qos) |
                    (if (subscription.no_local) @as(u8, 0x04) else 0) |
                    (if (subscription.retain_as_published) @as(u8, 0x08) else 0) |
                    (@as(u8, subscription.retain_handling) << 4),
            );
        }
    }
};

pub const SubAck = struct {
    packet_id: u16,
    properties: []Property = &.{},
    reason_codes: []u8,

    pub fn deinit(self: *SubAck, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        allocator.free(self.reason_codes);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!SubAck {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .suback) return error.InvalidPacketType;
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parsePropertiesFor(
            allocator,
            &cursor,
            .suback,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        const reason_codes = try allocator.dupe(u8, cursor.buf[cursor.pos..]);
        errdefer allocator.free(reason_codes);
        for (reason_codes) |code| try validateSubAckReason(protocol, code);
        cursor.pos = cursor.buf.len;
        if (reason_codes.len == 0) return error.InvalidReasonCode;
        return .{ .packet_id = packet_id, .properties = props, .reason_codes = reason_codes };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_id: u16,
        properties: []const Property,
        reason_codes: []const u8,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (reason_codes.len == 0) return error.InvalidReasonCode;
        const properties_len = if (protocol == .v5) blk: {
            try validatePropertiesFor(.suback, properties);
            break :blk try propertiesEncodedLen(properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        } else 0;
        for (reason_codes) |code| try validateSubAckReason(protocol, code);
        const remaining_len = @as(usize, 2) + reason_codes.len +
            if (protocol == .v5)
                remainingLengthEncodedLen(properties_len) +
                    properties_len
            else
                0;
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .suback,
            0,
            remaining_len,
        );
        appendIntAssumeCapacity(list, u16, packet_id);
        if (protocol == .v5) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
        list.appendSliceAssumeCapacity(reason_codes);
    }

    /// Encode a property-free SUBACK into caller storage. Call
    /// `noPropertiesWireLen` to obtain the exact required size first.
    pub fn writeNoPropertiesInto(
        out: []u8,
        protocol: ProtocolVersion,
        packet_id: u16,
        reason_codes: []const u8,
    ) Error![]u8 {
        const total_len = try noPropertiesWireLen(
            protocol,
            packet_id,
            reason_codes,
        );
        if (out.len < total_len) return error.BufferTooShort;

        const property_length: usize = @intFromBool(protocol == .v5);
        const remaining_len = 2 + property_length + reason_codes.len;
        const header_len = 1 + remainingLengthEncodedLen(remaining_len);
        out[0] = @as(u8, @intFromEnum(PacketType.suback)) << 4;
        const encoded_len = try encodeRemainingLengthInto(
            out[1..header_len],
            remaining_len,
        );
        std.debug.assert(encoded_len + 1 == header_len);
        std.mem.writeInt(u16, out[header_len..][0..2], packet_id, .big);
        var cursor = header_len + 2;
        if (protocol == .v5) {
            out[cursor] = 0;
            cursor += 1;
        }
        @memcpy(out[cursor..][0..reason_codes.len], reason_codes);
        return out[0..total_len];
    }

    pub fn noPropertiesWireLen(
        protocol: ProtocolVersion,
        packet_id: u16,
        reason_codes: []const u8,
    ) Error!usize {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (reason_codes.len == 0) return error.InvalidReasonCode;
        for (reason_codes) |code| try validateSubAckReason(protocol, code);
        const property_length: usize = @intFromBool(protocol == .v5);
        const remaining_len = std.math.add(
            usize,
            2 + property_length,
            reason_codes.len,
        ) catch return error.RemainingLengthTooLarge;
        if (remaining_len > 268_435_455) {
            return error.RemainingLengthTooLarge;
        }
        const header_len = 1 + remainingLengthEncodedLen(remaining_len);
        return std.math.add(usize, header_len, remaining_len) catch
            return error.RemainingLengthTooLarge;
    }
};

pub const Unsubscribe = struct {
    /// MQTT 3.1 retransmission marker. Later protocol versions require false.
    dup: bool = false,
    packet_id: u16,
    properties: []Property = &.{},
    topic_filters: [][]const u8,

    pub fn deinit(self: *Unsubscribe, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        allocator.free(self.topic_filters);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!Unsubscribe {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .unsubscribe) return error.InvalidPacketType;
        try validatePacketFlags(protocol, fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parsePropertiesFor(
            allocator,
            &cursor,
            .unsubscribe,
        ) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);

        var filters: std.ArrayList([]const u8) = .empty;
        errdefer filters.deinit(allocator);
        while (!cursor.eof()) {
            const filter = try readUtf8(&cursor);
            try validateTopicFilter(filter);
            try filters.append(allocator, filter);
        }
        if (filters.items.len == 0) return error.InvalidSubscription;
        return .{
            .dup = (fixed.flags & 0x08) != 0,
            .packet_id = packet_id,
            .properties = props,
            .topic_filters = try filters.toOwnedSlice(allocator),
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_id: u16,
        properties: []const Property,
        topic_filters: []const []const u8,
    ) Error!void {
        return writeWithDup(
            list,
            allocator,
            protocol,
            false,
            packet_id,
            properties,
            topic_filters,
        );
    }

    /// Encode MQTT 3.1 retransmission state. Later versions reject `dup=true`.
    pub fn writeWithDup(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        dup: bool,
        packet_id: u16,
        properties: []const Property,
        topic_filters: []const []const u8,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (topic_filters.len == 0) return error.InvalidSubscription;
        const properties_len = if (protocol == .v5) blk: {
            try validatePropertiesFor(.unsubscribe, properties);
            break :blk try propertiesEncodedLen(properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        } else 0;
        var remaining_len: usize = 2;
        if (protocol == .v5) remaining_len = try addEncodedComponent(
            remaining_len,
            remainingLengthEncodedLen(properties_len) + properties_len,
        );
        for (topic_filters) |filter| {
            try validateTopicFilter(filter);
            remaining_len = try addEncodedComponent(
                remaining_len,
                try encodedLengthPrefixedLen(filter, true),
            );
        }
        const flags = PacketType.unsubscribe.defaultFlags() |
            (if (dup) @as(u4, 0x08) else 0);
        try validatePacketFlags(protocol, .{
            .packet_type = .unsubscribe,
            .flags = flags,
            .remaining_len = remaining_len,
            .header_len = 0,
        });
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .unsubscribe,
            flags,
            remaining_len,
        );
        appendIntAssumeCapacity(list, u16, packet_id);
        if (protocol == .v5) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
        for (topic_filters) |filter| {
            appendLengthPrefixedAssumeCapacity(list, filter);
        }
    }
};

pub const UnsubAck = struct {
    packet_id: u16,
    properties: []Property = &.{},
    reason_codes: []u8,

    pub fn deinit(self: *UnsubAck, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        allocator.free(self.reason_codes);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!UnsubAck {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .unsuback) return error.InvalidPacketType;
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (protocol.isLegacy()) {
            if (!cursor.eof()) return error.InvalidPacketType;
            return .{
                .packet_id = packet_id,
                .properties = try allocator.alloc(Property, 0),
                .reason_codes = try allocator.dupe(u8, &[_]u8{0x00}),
            };
        }
        const props = try parsePropertiesFor(allocator, &cursor, .ack);
        errdefer allocator.free(props);
        const reason_codes = try allocator.dupe(u8, cursor.buf[cursor.pos..]);
        errdefer allocator.free(reason_codes);
        for (reason_codes) |code| try validateUnsubAckReason(code);
        cursor.pos = cursor.buf.len;
        if (reason_codes.len == 0) return error.InvalidReasonCode;
        return .{ .packet_id = packet_id, .properties = props, .reason_codes = reason_codes };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_id: u16,
        properties: []const Property,
        reason_codes: []const u8,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const properties_len: usize = if (protocol == .v5) blk: {
            if (reason_codes.len == 0) return error.InvalidReasonCode;
            try validatePropertiesFor(.ack, properties);
            break :blk try propertiesEncodedLen(properties);
        } else blk: {
            if (properties.len != 0) return error.InvalidProperty;
            if (reason_codes.len > 1) return error.InvalidReasonCode;
            if (reason_codes.len == 1 and reason_codes[0] != 0x00) return error.InvalidReasonCode;
            break :blk 0;
        };
        if (protocol == .v5) {
            for (reason_codes) |code| try validateUnsubAckReason(code);
        }
        const remaining_len = @as(usize, 2) + if (protocol == .v5)
            reason_codes.len +
                remainingLengthEncodedLen(properties_len) +
                properties_len
        else
            0;
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .unsuback,
            0,
            remaining_len,
        );
        appendIntAssumeCapacity(list, u16, packet_id);
        if (protocol == .v5) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
            list.appendSliceAssumeCapacity(reason_codes);
        }
    }

    /// Encode a property-free UNSUBACK into caller storage. MQTT 3.1.1 has no
    /// per-filter reasons; MQTT 5 requires at least one validated reason.
    pub fn writeNoPropertiesInto(
        out: []u8,
        protocol: ProtocolVersion,
        packet_id: u16,
        reason_codes: []const u8,
    ) Error![]u8 {
        const total_len = try noPropertiesWireLen(
            protocol,
            packet_id,
            reason_codes,
        );
        if (out.len < total_len) return error.BufferTooShort;

        const reason_length = if (protocol == .v5) reason_codes.len else 0;
        const property_length: usize = @intFromBool(protocol == .v5);
        const remaining_len = 2 + property_length + reason_length;
        const header_len = 1 + remainingLengthEncodedLen(remaining_len);
        out[0] = @as(u8, @intFromEnum(PacketType.unsuback)) << 4;
        const encoded_len = try encodeRemainingLengthInto(
            out[1..header_len],
            remaining_len,
        );
        std.debug.assert(encoded_len + 1 == header_len);
        std.mem.writeInt(u16, out[header_len..][0..2], packet_id, .big);
        if (protocol == .v5) {
            out[header_len + 2] = 0;
            @memcpy(out[header_len + 3 ..][0..reason_codes.len], reason_codes);
        }
        return out[0..total_len];
    }

    pub fn noPropertiesWireLen(
        protocol: ProtocolVersion,
        packet_id: u16,
        reason_codes: []const u8,
    ) Error!usize {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        switch (protocol) {
            .v3_1, .v3_1_1 => if (reason_codes.len != 0 and
                !(reason_codes.len == 1 and reason_codes[0] == 0))
            {
                return error.InvalidReasonCode;
            },
            .v5 => {
                if (reason_codes.len == 0) return error.InvalidReasonCode;
                for (reason_codes) |code| try validateUnsubAckReason(code);
            },
        }
        const property_length: usize = @intFromBool(protocol == .v5);
        const reason_length = if (protocol == .v5) reason_codes.len else 0;
        const remaining_len = std.math.add(
            usize,
            2 + property_length,
            reason_length,
        ) catch return error.RemainingLengthTooLarge;
        if (remaining_len > 268_435_455) {
            return error.RemainingLengthTooLarge;
        }
        const header_len = 1 + remainingLengthEncodedLen(remaining_len);
        return std.math.add(usize, header_len, remaining_len) catch
            return error.RemainingLengthTooLarge;
    }
};

pub const Disconnect = struct {
    reason_code: u8 = 0,
    properties: []Property = &.{},

    /// Largest complete DISCONNECT packet without properties. A normal
    /// disconnect is only the two-byte fixed header; MQTT 5 adds one optional
    /// Reason Code byte for every non-zero reason.
    pub const no_properties_max_len: usize = 3;

    pub fn deinit(self: *Disconnect, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!Disconnect {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .disconnect) return error.InvalidPacketType;
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        if (protocol.isLegacy() and fixed.remaining_len != 0) {
            return error.InvalidPacketType;
        }
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const reason_code = if (!cursor.eof()) try cursor.readByte() else 0;
        if (protocol == .v5) try validateDisconnectReason(reason_code);
        const props = if (protocol == .v5 and !cursor.eof())
            try parsePropertiesFor(allocator, &cursor, .disconnect)
        else
            try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (!cursor.eof()) return error.InvalidPacketType;
        return .{ .reason_code = reason_code, .properties = props };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        reason_code: u8,
        properties: []const Property,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (protocol.isLegacy()) {
            if (reason_code != 0) return error.InvalidReasonCode;
            if (properties.len != 0) return error.InvalidProperty;
        } else try validateDisconnectReason(reason_code);
        const include_reason = protocol == .v5 and
            (reason_code != 0 or properties.len != 0);
        const properties_len = if (protocol == .v5 and properties.len != 0) blk: {
            try validatePropertiesFor(.disconnect, properties);
            break :blk try propertiesEncodedLen(properties);
        } else 0;
        const remaining_len = @intFromBool(include_reason) +
            if (properties.len != 0)
                remainingLengthEncodedLen(properties_len) + properties_len
            else
                0;
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .disconnect,
            0,
            remaining_len,
        );
        if (include_reason) list.appendAssumeCapacity(reason_code);
        if (properties.len != 0) {
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
    }

    /// Encode a property-free DISCONNECT directly into caller storage.
    ///
    /// Normal shutdown is a frequent fixed-size control path. Keeping its
    /// storage under caller control avoids allocating solely to write two or
    /// three bytes, while `write` continues to support the unbounded property
    /// forms.
    pub fn writeNoPropertiesInto(
        storage: *[no_properties_max_len]u8,
        protocol: ProtocolVersion,
        reason_code: u8,
    ) Error![]u8 {
        if (protocol.isLegacy()) {
            if (reason_code != 0) return error.InvalidReasonCode;
        } else {
            try validateDisconnectReason(reason_code);
        }

        storage[0] = @as(u8, @intFromEnum(PacketType.disconnect)) << 4;
        if (protocol == .v5 and reason_code != 0) {
            storage[1] = 1;
            storage[2] = reason_code;
            return storage;
        }
        storage[1] = 0;
        return storage[0..2];
    }
};

pub const Auth = struct {
    reason_code: u8 = 0,
    properties: []Property = &.{},

    /// Largest complete AUTH packet without properties. Success uses the
    /// two-byte zero-length form; Continue/Re-authenticate must also carry the
    /// zero Property Length byte and therefore use four bytes.
    pub const no_properties_max_len: usize = 4;

    pub fn deinit(self: *Auth, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!Auth {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .auth) return error.InvalidPacketType;
        try validateControlFlags(fixed);
        if (protocol != .v5) return error.InvalidPacketType;
        try validatePacketBounds(packet, fixed);

        if (fixed.remaining_len == 0) {
            return .{ .reason_code = 0, .properties = try allocator.alloc(Property, 0) };
        }

        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const reason_code = try cursor.readByte();
        try validateAuthReason(reason_code);
        const props = try parsePropertiesFor(allocator, &cursor, .auth);
        errdefer allocator.free(props);
        if (!cursor.eof()) return error.InvalidPacketType;
        return .{ .reason_code = reason_code, .properties = props };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        reason_code: u8,
        properties: []const Property,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        if (protocol != .v5) return error.InvalidPacketType;
        try validateAuthReason(reason_code);
        try validateAuthProperties(properties);

        const include_reason = reason_code != 0 or properties.len != 0;
        const properties_len = if (include_reason)
            try propertiesEncodedLen(properties)
        else
            0;
        const remaining_len = @intFromBool(include_reason) +
            if (include_reason)
                remainingLengthEncodedLen(properties_len) + properties_len
            else
                0;
        try writeFixedHeaderAssumeCapacity(
            list,
            allocator,
            .auth,
            0,
            remaining_len,
        );
        if (include_reason) {
            list.appendAssumeCapacity(reason_code);
            writePropertiesAssumeCapacity(list, properties, properties_len);
        }
    }

    /// Encode a property-free MQTT 5 AUTH packet into caller storage.
    ///
    /// Unlike acknowledgement and DISCONNECT packets, a non-zero AUTH reason
    /// cannot omit its zero Property Length. Encoding both legal shapes here
    /// keeps that protocol distinction explicit while avoiding a tiny heap
    /// allocation in authentication completion/filtering paths.
    pub fn writeNoPropertiesInto(
        storage: *[no_properties_max_len]u8,
        protocol: ProtocolVersion,
        reason_code: u8,
    ) Error![]u8 {
        if (protocol != .v5) return error.InvalidPacketType;
        try validateAuthReason(reason_code);

        storage[0] = @as(u8, @intFromEnum(PacketType.auth)) << 4;
        if (reason_code == 0) {
            storage[1] = 0;
            return storage[0..2];
        }
        storage[1] = 2;
        storage[2] = reason_code;
        storage[3] = 0;
        return storage;
    }
};

fn validateConnAckSessionPresent(
    protocol: ProtocolVersion,
    session_present: bool,
    reason_code: u8,
) Error!void {
    // MQTT 3.1's acknowledgement byte is wholly reserved and has no standard
    // Session Present bit. The explicit Mosquitto encoder handles its extension.
    if (protocol == .v3_1 and session_present) return error.InvalidFlags;
    // MQTT 3.1.1/5 require Session Present to be 0 when the connection is
    // refused. Accepting it on failures can resume state after a rejected CONNECT.
    if (session_present and reason_code != 0) return error.InvalidFlags;
}

fn validateSubscriptionOptions(protocol: ProtocolVersion, options: u8) Error!void {
    if ((options & 0xc0) != 0) return error.InvalidSubscription;
    const qos_bits: u2 = @truncate(options & 0x03);
    if (qos_bits == 3) return error.InvalidQoS;
    switch (protocol) {
        .v3_1, .v3_1_1 => {
            // MQTT 3.1/3.1.1 SUBSCRIBE options only carry requested QoS in
            // bits 0..1.  MQTT 5 added No Local, Retain As Published and
            // Retain Handling in bits 2..5; reject those for v3 rather than
            // silently emitting or accepting a wire-incompatible packet.
            if ((options & 0xfc) != 0) return error.InvalidSubscription;
        },
        .v5 => {
            if (((options >> 4) & 0x03) == 3) return error.InvalidSubscription;
        },
    }
}

fn validateParsedSubscriptionOptions(
    protocol: ProtocolVersion,
    options: u8,
) Error!void {
    if ((options & 0xc0) != 0) {
        return error.MalformedSubscriptionOptions;
    }
    const qos_bits: u2 = @truncate(options & 0x03);
    switch (protocol) {
        .v3_1, .v3_1_1 => {
            if ((options & 0xfc) != 0 or qos_bits == 3) {
                return error.MalformedSubscriptionOptions;
            }
        },
        .v5 => {
            if (qos_bits == 3 or ((options >> 4) & 0x03) == 3) {
                return error.InvalidSubscription;
            }
        },
    }
}

fn validateSharedSubscriptionOptions(protocol: ProtocolVersion, topic_filter: []const u8, options: u8) Error!void {
    if (protocol != .v5) return;
    if ((options & 0x04) == 0) return;
    // MQTT 5 forbids No Local on Shared Subscriptions: delivery is mediated by
    // the shared group, not by an individual subscriber identity, so the option
    // is defined as a protocol error for `$share/{group}/{filter}` filters.
    if (std.mem.startsWith(u8, topic_filter, "$share/")) return error.InvalidSubscription;
}

fn validateSubAckReason(protocol: ProtocolVersion, code: u8) Error!void {
    switch (protocol) {
        .v3_1, .v3_1_1 => switch (code) {
            0x00, 0x01, 0x02, 0x80 => {},
            else => return error.InvalidReasonCode,
        },
        .v5 => switch (code) {
            0x00, 0x01, 0x02, 0x80, 0x83, 0x87, 0x8f, 0x91, 0x97, 0x9e, 0xa1, 0xa2 => {},
            else => return error.InvalidReasonCode,
        },
    }
}

fn validateUnsubAckReason(code: u8) Error!void {
    switch (code) {
        0x00, 0x11, 0x80, 0x83, 0x87, 0x8f, 0x91 => {},
        else => return error.InvalidReasonCode,
    }
}

fn validateConnAckReason(protocol: ProtocolVersion, code: u8) Error!void {
    switch (protocol) {
        // MQTT 3.1.1 CONNACK uses the legacy "connect return code" table
        // (0-5). MQTT 5 replaced those numeric failures with the reason-code
        // registry below, so keep the validation version-aware instead of
        // accidentally rejecting legitimate v3 refusal packets.
        .v3_1, .v3_1_1 => switch (code) {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05 => {},
            else => return error.InvalidReasonCode,
        },
        .v5 => switch (code) {
            0x00,
            0x80,
            0x81,
            0x82,
            0x83,
            0x84,
            0x85,
            0x86,
            0x87,
            0x88,
            0x89,
            0x8a,
            0x8c,
            0x90,
            0x95,
            0x97,
            0x99,
            0x9a,
            0x9b,
            0x9c,
            0x9d,
            0x9f,
            => {},
            else => return error.InvalidReasonCode,
        },
    }
}

fn validateDisconnectReason(code: u8) Error!void {
    switch (code) {
        0x00,
        0x04,
        0x80,
        0x81,
        0x82,
        0x83,
        0x87,
        0x89,
        0x8b,
        0x8d,
        0x8e,
        0x8f,
        0x90,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,
        0x98,
        0x99,
        0x9a,
        0x9b,
        0x9c,
        0x9d,
        0x9e,
        0x9f,
        0xa0,
        0xa1,
        0xa2,
        => {},
        else => return error.InvalidReasonCode,
    }
}

pub const DisconnectSender = enum { client, server };

/// Validate the endpoint direction from MQTT 5 Table 3-10 after the generic
/// DISCONNECT reason registry check. Packet codecs remain role-neutral; an
/// established runtime supplies the sender role from its CONNECT state.
pub fn validateDisconnectReasonForSender(
    code: u8,
    sender: DisconnectSender,
) Error!void {
    try validateDisconnectReason(code);
    switch (sender) {
        .client => switch (code) {
            0x87,
            0x89,
            0x8b,
            0x8d,
            0x8e,
            0x8f,
            0x9a,
            0x9b,
            0x9c,
            0x9d,
            0x9e,
            0x9f,
            0xa0,
            0xa1,
            0xa2,
            => return error.InvalidReasonCode,
            else => {},
        },
        .server => if (code == 0x04) return error.InvalidReasonCode,
    }
}

fn validateAuthReason(code: u8) Error!void {
    switch (code) {
        0x00, 0x18, 0x19 => {},
        else => return error.InvalidReasonCode,
    }
}

pub const AuthSender = enum { client, server };

/// Validate the endpoint direction from MQTT 5 Table 3-11. Success is a
/// server result, Continue Authentication is bidirectional, and only a Client
/// may initiate Re-authentication.
pub fn validateAuthReasonForSender(
    code: u8,
    sender: AuthSender,
) Error!void {
    try validateAuthReason(code);
    switch (sender) {
        .client => if (code == 0x00) return error.InvalidReasonCode,
        .server => if (code == 0x19) return error.InvalidReasonCode,
    }
}

fn validateAuthProperties(properties: []const Property) Error!void {
    try validatePropertiesFor(.auth, properties);
}

fn propertyId(property: Property) PropertyId {
    return switch (property) {
        .byte => |p| p.id,
        .two_byte => |p| p.id,
        .four_byte => |p| p.id,
        .varint => |p| p.id,
        .binary => |p| p.id,
        .utf8 => |p| p.id,
        .utf8_pair => |p| p.id,
    };
}

pub const ping_packet_len: usize = 2;

pub fn writePing(list: *std.ArrayList(u8), allocator: std.mem.Allocator, response: bool) Error!void {
    var storage: [ping_packet_len]u8 = undefined;
    try list.appendSlice(allocator, writePingInto(&storage, response));
}

/// Encode the complete fixed-size PINGREQ or PINGRESP packet without an
/// allocator. Both MQTT 3.1.1 and MQTT 5 use the same two-byte wire form.
pub fn writePingInto(
    storage: *[ping_packet_len]u8,
    response: bool,
) []u8 {
    const packet_type: PacketType = if (response) .pingresp else .pingreq;
    storage.* = .{ @as(u8, @intFromEnum(packet_type)) << 4, 0 };
    return storage;
}

pub fn validatePing(packet: []const u8, response: bool) Error!void {
    const fixed = try FixedHeader.parse(packet);
    const expected: PacketType = if (response) .pingresp else .pingreq;
    if (fixed.packet_type != expected) return error.InvalidPacketType;
    try validateControlFlags(fixed);
    try validatePacketBounds(packet, fixed);
    if (fixed.remaining_len != 0) return error.InvalidPacketType;
}

pub fn writeConnect(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    client_id: []const u8,
    clean_start: bool,
    keep_alive_seconds: u16,
) !void {
    try writeConnectPacket(list, allocator, protocol, .{
        .client_id = client_id,
        .clean_start = clean_start,
        .keep_alive_seconds = keep_alive_seconds,
    });
}

pub fn writeConnectPacket(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    options: ConnectPacketOptions,
) Error!void {
    const original_len = list.items.len;
    errdefer list.items.len = original_len;
    if (options.bridge_mode and protocol == .v5) {
        return error.InvalidProtocolLevel;
    }
    try validateClientIdentifier(
        protocol,
        options.client_id,
        options.clean_start,
    );
    const flags = connectFlags(options);
    try validateConnectFlags(protocol, flags);
    const connect_properties_len = if (protocol == .v5) blk: {
        try validatePropertiesFor(.connect, options.properties);
        break :blk try propertiesEncodedLen(options.properties);
    } else if (options.properties.len != 0) {
        return error.InvalidProperty;
    } else 0;
    try validateMqttUtf8String(options.client_id);
    var remaining_len: usize = if (protocol == .v3_1)
        12
    else
        10; // protocol name, level, flags, Keep Alive
    if (protocol == .v5) {
        remaining_len = try addEncodedComponent(
            remaining_len,
            remainingLengthEncodedLen(connect_properties_len) +
                connect_properties_len,
        );
    }
    remaining_len = try addEncodedComponent(
        remaining_len,
        try encodedLengthPrefixedLen(options.client_id, true),
    );
    var will_properties_len: usize = 0;
    if (options.will) |will| {
        try validateTopicName(will.topic);
        if (protocol == .v5) {
            try validatePropertiesFor(.will, will.properties);
            try validatePayloadFormat(will.properties, will.payload);
            will_properties_len = try propertiesEncodedLen(will.properties);
            remaining_len = try addEncodedComponent(
                remaining_len,
                remainingLengthEncodedLen(will_properties_len) +
                    will_properties_len,
            );
        } else if (will.properties.len != 0) {
            return error.InvalidProperty;
        }
        remaining_len = try addEncodedComponent(
            remaining_len,
            try encodedLengthPrefixedLen(will.topic, true),
        );
        remaining_len = try addEncodedComponent(
            remaining_len,
            try encodedLengthPrefixedLen(will.payload, false),
        );
    }
    if (options.username) |username| {
        try validateMqttUtf8String(username);
        remaining_len = try addEncodedComponent(
            remaining_len,
            try encodedLengthPrefixedLen(username, true),
        );
    }
    if (options.password) |password| {
        remaining_len = try addEncodedComponent(
            remaining_len,
            try encodedLengthPrefixedLen(password, false),
        );
    }
    if (remaining_len > 268_435_455) return error.RemainingLengthTooLarge;
    const encoded_len = try addEncodedComponent(
        1 + remainingLengthEncodedLen(remaining_len),
        remaining_len,
    );
    try list.ensureUnusedCapacity(allocator, encoded_len);
    list.appendAssumeCapacity(@as(u8, @intFromEnum(PacketType.connect)) << 4);
    encodeRemainingLengthAssumeCapacity(list, remaining_len);
    appendLengthPrefixedAssumeCapacity(
        list,
        if (protocol == .v3_1) "MQIsdp" else "MQTT",
    );
    list.appendAssumeCapacity(
        protocol.byte() | if (options.bridge_mode) @as(u8, 0x80) else 0,
    );
    list.appendAssumeCapacity(flags);
    appendIntAssumeCapacity(list, u16, options.keep_alive_seconds);
    if (protocol == .v5) {
        writePropertiesAssumeCapacity(
            list,
            options.properties,
            connect_properties_len,
        );
    }
    appendLengthPrefixedAssumeCapacity(list, options.client_id);
    if (options.will) |will| {
        if (protocol == .v5) {
            writePropertiesAssumeCapacity(
                list,
                will.properties,
                will_properties_len,
            );
        }
        appendLengthPrefixedAssumeCapacity(list, will.topic);
        appendLengthPrefixedAssumeCapacity(list, will.payload);
    }
    if (options.username) |username| {
        appendLengthPrefixedAssumeCapacity(list, username);
    }
    if (options.password) |password| {
        appendLengthPrefixedAssumeCapacity(list, password);
    }
}

fn addEncodedComponent(total: usize, component: usize) Error!usize {
    return std.math.add(usize, total, component) catch
        return error.IntegerOverflow;
}

fn connectFlags(options: ConnectPacketOptions) u8 {
    var flags: u8 = if (options.clean_start) 0x02 else 0x00;
    if (options.will) |will| {
        flags |= 0x04 | (@as(u8, @intFromEnum(will.qos)) << 3);
        if (will.retain) flags |= 0x20;
    }
    if (options.password != null) flags |= 0x40;
    if (options.username != null) flags |= 0x80;
    return flags;
}

/// Validate the Client Identifier rules attached to a CONNECT protocol level.
/// MQTT 3.1 has a strict 1-23-character bound; later versions deliberately
/// retain their distinct empty-identifier and server-assignment semantics.
pub fn validateClientIdentifier(
    protocol: ProtocolVersion,
    client_id: []const u8,
    clean_start: bool,
) Error!void {
    // MQTT 3.1 requires 1-23 characters. MQTT 3.1.1 permits an empty Client
    // Identifier only with CleanSession=1. MQTT 5 removed that restriction:
    // the Server assigns the identifier and returns it in CONNACK even when
    // Clean Start is 0.
    switch (protocol) {
        .v3_1 => {
            const character_count = std.unicode.utf8CountCodepoints(
                client_id,
            ) catch return error.InvalidUtf8;
            if (character_count == 0 or character_count > 23) {
                return error.InvalidClientId;
            }
        },
        .v3_1_1 => if (client_id.len == 0 and !clean_start) {
            return error.InvalidClientId;
        },
        .v5 => {},
    }
}

pub const PublishWriteOptions = struct {
    qos: QoS = .at_most_once,
    retain: bool = false,
    dup: bool = false,
    packet_id: ?u16 = null,
    properties: []const Property = &.{},
};

pub const PublishWireLengths = struct {
    prefix: usize,
    total: usize,
};

pub fn writePublish(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: PublishWriteOptions,
) !void {
    const original_len = list.items.len;
    errdefer list.items.len = original_len;
    const lengths = try publishWireLengths(
        protocol,
        topic,
        payload,
        options,
    );
    try list.ensureUnusedCapacity(allocator, lengths.total);
    writePublishPrefixAssumeCapacity(
        list,
        protocol,
        topic,
        options,
        payload.len,
    );
    list.appendSliceAssumeCapacity(payload);
}

test "MQTT PUBLISH codec rejects DUP at QoS zero transactionally" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try encoded.appendSlice(std.testing.allocator, "prefix");

    try std.testing.expectError(
        error.InvalidFlags,
        writePublish(
            &encoded,
            std.testing.allocator,
            .v5,
            "invalid/dup",
            "payload",
            .{ .qos = .at_most_once, .dup = true },
        ),
    );
    try std.testing.expectEqualStrings("prefix", encoded.items);
    try std.testing.expectError(
        error.InvalidFlags,
        Publish.parse(
            std.testing.allocator,
            .v5,
            &.{ 0x38, 0x04, 0x00, 0x01, 'a', 0x00 },
        ),
    );
}

test "MQTT PUBLISH prefix matches complete packet encoding" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        protocol: ProtocolVersion,
        topic: []const u8,
        payload: []const u8,
        options: PublishWriteOptions,
    }{
        .{
            .protocol = .v3_1_1,
            .topic = "sensors/temperature",
            .payload = "small",
            .options = .{},
        },
        .{
            .protocol = .v5,
            .topic = "sensors/temperature",
            .payload = &([_]u8{0xa5} ** 256),
            .options = .{
                .qos = .at_least_once,
                .retain = true,
                .dup = true,
                .packet_id = 42,
                .properties = &.{
                    .{ .two_byte = .{
                        .id = .topic_alias,
                        .value = 2,
                    } },
                    .{ .utf8_pair = .{
                        .id = .user_property,
                        .key = "source",
                        .value = "prefix-test",
                    } },
                },
            },
        },
    };
    for (cases) |case| {
        var complete: std.ArrayList(u8) = .empty;
        defer complete.deinit(allocator);
        try writePublish(
            &complete,
            allocator,
            case.protocol,
            case.topic,
            case.payload,
            case.options,
        );
        var prefix: std.ArrayList(u8) = .empty;
        defer prefix.deinit(allocator);
        const lengths = try writePublishPrefix(
            &prefix,
            allocator,
            case.protocol,
            case.topic,
            case.payload,
            case.options,
        );
        try std.testing.expectEqual(prefix.items.len, lengths.prefix);
        try std.testing.expectEqual(complete.items.len, lengths.total);
        try std.testing.expectEqualSlices(
            u8,
            complete.items[0..prefix.items.len],
            prefix.items,
        );
        try std.testing.expectEqualSlices(
            u8,
            case.payload,
            complete.items[prefix.items.len..],
        );
    }
}

/// Encode the MQTT fixed and variable PUBLISH headers without copying payload.
///
/// The returned total length includes `payload`; stream transports can submit
/// `list.items` and `payload` with scatter/gather I/O while WebSocket callers
/// can append the payload to preserve one-message masking semantics.
pub fn writePublishPrefix(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: PublishWriteOptions,
) !PublishWireLengths {
    const original_len = list.items.len;
    errdefer list.items.len = original_len;
    const lengths = try publishWireLengths(
        protocol,
        topic,
        payload,
        options,
    );
    try list.ensureUnusedCapacity(allocator, lengths.prefix);
    writePublishPrefixAssumeCapacity(
        list,
        protocol,
        topic,
        options,
        payload.len,
    );
    return lengths;
}

fn publishWireLengths(
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: PublishWriteOptions,
) Error!PublishWireLengths {
    if (topic.len == 0) {
        if (protocol != .v5 or topicAlias(options.properties) == null) return error.InvalidTopic;
    } else try validateTopicName(topic);
    if (protocol == .v5) {
        try validatePayloadFormat(options.properties, payload);
    } else if (options.properties.len != 0) {
        return error.InvalidProperty;
    }
    if (options.qos == .at_most_once) {
        if (options.dup) return error.InvalidFlags;
        if (options.packet_id != null) return error.InvalidPacketIdentifier;
    } else if (options.packet_id == null or options.packet_id.? == 0) {
        // Like rumqtt and the MQTT spec, QoS 1/2 PUBLISH packets must carry a
        // non-zero Packet Identifier.  Do not synthesize one in the stateless
        // writer: runtime connections own packet-id allocation and can avoid
        // collisions with their in-flight window.
        return error.InvalidPacketIdentifier;
    }
    const properties_len = if (protocol == .v5) blk: {
        try validatePropertiesFor(.publish, options.properties);
        break :blk try propertiesEncodedLen(options.properties);
    } else 0;
    const variable_len = std.math.add(
        usize,
        try encodedLengthPrefixedLen(topic, true),
        if (options.qos == .at_most_once) 0 else 2,
    ) catch return error.IntegerOverflow;
    const properties_wire_len = if (protocol == .v5)
        std.math.add(
            usize,
            remainingLengthEncodedLen(properties_len),
            properties_len,
        ) catch return error.IntegerOverflow
    else
        0;
    const remaining_len = std.math.add(
        usize,
        std.math.add(usize, variable_len, properties_wire_len) catch
            return error.IntegerOverflow,
        payload.len,
    ) catch return error.IntegerOverflow;
    if (remaining_len > 268_435_455) return error.RemainingLengthTooLarge;
    const prefix_len = std.math.add(
        usize,
        1 + remainingLengthEncodedLen(remaining_len),
        std.math.add(usize, variable_len, properties_wire_len) catch
            return error.IntegerOverflow,
    ) catch return error.IntegerOverflow;
    const total_len = std.math.add(usize, prefix_len, payload.len) catch
        return error.IntegerOverflow;
    return .{ .prefix = prefix_len, .total = total_len };
}

fn writePublishPrefixAssumeCapacity(
    list: *std.ArrayList(u8),
    protocol: ProtocolVersion,
    topic: []const u8,
    options: PublishWriteOptions,
    remaining_payload_len: usize,
) void {
    const variable_len = 2 + topic.len +
        if (options.qos == .at_most_once) @as(usize, 0) else 2;
    const properties_len = if (protocol == .v5)
        propertiesEncodedLen(options.properties) catch unreachable
    else
        0;
    const properties_wire_len = if (protocol == .v5)
        remainingLengthEncodedLen(properties_len) + properties_len
    else
        0;
    const remaining_len = variable_len + properties_wire_len +
        remaining_payload_len;
    const flags: u4 = (if (options.dup) @as(u4, 0x8) else 0) |
        (@as(u4, @intFromEnum(options.qos)) << 1) |
        (if (options.retain) @as(u4, 0x1) else 0);
    list.appendAssumeCapacity(
        (@as(u8, @intFromEnum(PacketType.publish)) << 4) | flags,
    );
    encodeRemainingLengthAssumeCapacity(list, remaining_len);
    appendLengthPrefixedAssumeCapacity(list, topic);
    if (options.qos != .at_most_once) {
        appendIntAssumeCapacity(list, u16, options.packet_id.?);
    }
    if (protocol == .v5) {
        writePropertiesAssumeCapacity(list, options.properties, properties_len);
    }
}

test "MQTT remaining length roundtrip" {
    const allocator = std.testing.allocator;
    const values = [_]usize{ 0, 127, 128, 16_384, 268_435_455 };
    for (values) |value| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encodeRemainingLength(&encoded, allocator, value);
        const decoded = try decodeRemainingLength(encoded.items);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(remainingLengthEncodedLen(value), decoded.len);
    }
    try std.testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0x80, 0x00 }));
    try std.testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0xff, 0x00 }));
}

test "MQTT PUBLISH direct encoding is allocation-free with exact capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .byte = .{ .id = .payload_format_indicator, .value = 1 } },
        .{ .four_byte = .{ .id = .message_expiry_interval, .value = 30 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 321 } },
        .{ .binary = .{ .id = .correlation_data, .value = "id" } },
        .{ .utf8 = .{ .id = .content_type, .value = "text/plain" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePublish(
        &encoded,
        allocator,
        .v5,
        "direct/topic",
        "payload",
        .{
            .qos = .at_least_once,
            .retain = true,
            .packet_id = 7,
            .properties = &properties,
        },
    );
    const expected = try allocator.dupe(u8, encoded.items);
    defer allocator.free(expected);
    encoded.clearRetainingCapacity();

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writePublish(
        &encoded,
        no_alloc.allocator(),
        .v5,
        "direct/topic",
        "payload",
        .{
            .qos = .at_least_once,
            .retain = true,
            .packet_id = 7,
            .properties = &properties,
        },
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, expected, encoded.items);
    var parsed = try Publish.parse(allocator, .v5, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("direct/topic", parsed.topic);
    try std.testing.expectEqualStrings("payload", parsed.payload);
    try std.testing.expectEqual(@as(?u16, 7), parsed.packet_id);
    try std.testing.expectEqual(properties.len, parsed.properties.len);

    const preserved_len = encoded.items.len;
    try std.testing.expectError(
        error.InvalidUtf8,
        writePublish(
            &encoded,
            allocator,
            .v5,
            "direct/topic",
            "payload",
            .{ .properties = &.{.{ .utf8 = .{
                .id = .content_type,
                .value = "bad\x00value",
            } }} },
        ),
    );
    try std.testing.expectEqual(preserved_len, encoded.items.len);
}

test "MQTT property writer reuses exact output capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .byte = .{ .id = .payload_format_indicator, .value = 1 } },
        .{ .two_byte = .{ .id = .topic_alias, .value = 7 } },
        .{ .four_byte = .{ .id = .message_expiry_interval, .value = 9 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 300 } },
        .{ .binary = .{ .id = .correlation_data, .value = "bytes" } },
        .{ .utf8 = .{ .id = .content_type, .value = "text/plain" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "value" } },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeProperties(&encoded, allocator, &properties);
    const expected = try allocator.dupe(u8, encoded.items);
    defer allocator.free(expected);
    encoded.clearRetainingCapacity();

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeProperties(&encoded, no_alloc.allocator(), &properties);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, expected, encoded.items);
    var cursor = wire.Cursor.init(encoded.items);
    const decoded = try parseProperties(allocator, &cursor);
    defer allocator.free(decoded);
    try std.testing.expectEqual(properties.len, decoded.len);
    try std.testing.expect(cursor.eof());

    const preserved_len = encoded.items.len;
    try std.testing.expectError(
        error.InvalidProperty,
        writeProperties(&encoded, allocator, &.{
            .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
            .{ .two_byte = .{ .id = .topic_alias, .value = 2 } },
        }),
    );
    try std.testing.expectEqual(preserved_len, encoded.items.len);
}

test "MQTT CONNECT direct encoding reuses exact output capacity" {
    const allocator = std.testing.allocator;
    const connect_properties = [_]Property{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 10 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "client", .value = "netz" } },
    };
    const will_properties = [_]Property{
        .{ .four_byte = .{ .id = .will_delay_interval, .value = 5 } },
        .{ .utf8 = .{ .id = .content_type, .value = "text/plain" } },
    };
    const options = ConnectPacketOptions{
        .client_id = "direct-client",
        .clean_start = false,
        .keep_alive_seconds = 45,
        .properties = &connect_properties,
        .will = .{
            .topic = "status/direct-client",
            .payload = "offline",
            .qos = .at_least_once,
            .retain = true,
            .properties = @constCast(&will_properties),
        },
        .username = "user",
        .password = "password",
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeConnectPacket(&encoded, allocator, .v5, options);
    const expected = try allocator.dupe(u8, encoded.items);
    defer allocator.free(expected);
    encoded.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeConnectPacket(&encoded, no_alloc.allocator(), .v5, options);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, expected, encoded.items);
    var parsed = try Connect.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("direct-client", parsed.client_id);
    try std.testing.expectEqualStrings("offline", parsed.will.?.payload);
    try std.testing.expectEqualStrings("user", parsed.username.?);
    try std.testing.expectEqualStrings("password", parsed.password.?);
}

test "MQTT CONNACK and publish acknowledgments reuse output capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .utf8 = .{ .id = .reason_string, .value = "accepted" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try ConnAck.write(&output, allocator, .v5, true, 0, &properties);
    const connack = try allocator.dupe(u8, output.items);
    defer allocator.free(connack);
    output.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try ConnAck.write(
        &output,
        no_alloc.allocator(),
        .v5,
        true,
        0,
        &properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, connack, output.items);

    output.clearRetainingCapacity();
    try AckPacket.write(
        &output,
        allocator,
        .v5,
        .puback,
        7,
        0x10,
        &properties,
    );
    const ack = try allocator.dupe(u8, output.items);
    defer allocator.free(ack);
    output.clearRetainingCapacity();
    no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try AckPacket.write(
        &output,
        no_alloc.allocator(),
        .v5,
        .puback,
        7,
        0x10,
        &properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, ack, output.items);
    var parsed = try AckPacket.parse(allocator, .v5, output.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 7), parsed.packet_id);
    try std.testing.expectEqual(@as(u8, 0x10), parsed.reason_code);

    const fixed = try FixedHeader.parse(output.items);
    var payload_parsed = try AckPacket.parsePayload(
        allocator,
        .v5,
        fixed.packet_type,
        fixed.flags,
        output.items[fixed.header_len..],
    );
    defer payload_parsed.deinit(allocator);
    try std.testing.expectEqual(parsed.packet_type, payload_parsed.packet_type);
    try std.testing.expectEqual(parsed.packet_id, payload_parsed.packet_id);
    try std.testing.expectEqual(parsed.reason_code, payload_parsed.reason_code);
}

test "MQTT subscription control writers reuse output capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .varint = .{ .id = .subscription_identifier, .value = 19 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "source", .value = "test" } },
    };
    const subscriptions = [_]Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .exactly_once, .no_local = true },
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try Subscribe.write(&output, allocator, .v5, 9, &properties, &subscriptions);
    const subscribe = try allocator.dupe(u8, output.items);
    defer allocator.free(subscribe);
    output.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try Subscribe.write(
        &output,
        no_alloc.allocator(),
        .v5,
        9,
        &properties,
        &subscriptions,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, subscribe, output.items);

    output.clearRetainingCapacity();
    const filters = [_][]const u8{ "sensors/+", "alerts/#" };
    try Unsubscribe.write(&output, allocator, .v5, 10, &.{}, &filters);
    const unsubscribe = try allocator.dupe(u8, output.items);
    defer allocator.free(unsubscribe);
    output.clearRetainingCapacity();
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try Unsubscribe.write(
        &output,
        no_alloc.allocator(),
        .v5,
        10,
        &.{},
        &filters,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, unsubscribe, output.items);
}

test "MQTT Assigned Client Identifier lookup" {
    const properties = [_]Property{
        .{ .utf8 = .{
            .id = .assigned_client_identifier,
            .value = "auto-client",
        } },
    };
    try std.testing.expectEqualStrings(
        "auto-client",
        assignedClientIdentifier(&properties).?,
    );
    try std.testing.expect(assignedClientIdentifier(&.{}) == null);
}

test "MQTT UTF-8 strings reject forbidden code points but allow discouraged controls" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try validateUtf8String("");
    try validateUtf8String("plain/ascii/topic");
    try std.testing.expectError(error.InvalidUtf8, writeUtf8(&out, std.testing.allocator, "bad\x00topic"));
    try std.testing.expectError(
        error.InvalidUtf8,
        validateUtf8String("valid\xc2\xa2\x00tail"),
    );

    var encoded: [4]u8 = undefined;
    var codepoint: u21 = 0xfdd0;
    while (codepoint <= 0xfdef) : (codepoint += 1) {
        const len = try std.unicode.utf8Encode(codepoint, &encoded);
        try std.testing.expectError(
            error.InvalidUtf8,
            validateUtf8String(encoded[0..len]),
        );
    }
    for (0..17) |plane| {
        const plane_base: u21 = @intCast(plane * 0x10000);
        for ([_]u21{ plane_base + 0xfffe, plane_base + 0xffff }) |noncharacter| {
            const len = try std.unicode.utf8Encode(noncharacter, &encoded);
            try std.testing.expectError(
                error.InvalidUtf8,
                validateUtf8String(encoded[0..len]),
            );
        }
    }
    for ([_]u21{ 0xfdcf, 0xfdf0, 0xfffd, 0x10000, 0x1fffd, 0x10fffd }) |allowed| {
        const len = try std.unicode.utf8Encode(allowed, &encoded);
        try validateUtf8String(encoded[0..len]);
    }
    try std.testing.expectError(
        error.InvalidUtf8,
        writeUtf8(&out, std.testing.allocator, "bad\xef\xbf\xbetopic"),
    );

    var raw = [_]u8{ 0, 5, 'h', 'e', 0, 'l', 'o' };
    var cursor = wire.Cursor.init(&raw);
    try std.testing.expectError(error.InvalidUtf8, readUtf8(&cursor));

    var noncharacter = [_]u8{ 0, 3, 0xef, 0xbf, 0xbe };
    cursor = wire.Cursor.init(&noncharacter);
    try std.testing.expectError(error.InvalidUtf8, readUtf8(&cursor));

    try writeUtf8(&out, std.testing.allocator, "ok\x1ftopic");
    try std.testing.expectEqualStrings("ok\x1ftopic", out.items[2..]);
    out.clearRetainingCapacity();

    var del = [_]u8{ 0, 3, 'b', 0x7f, 'd' };
    cursor = wire.Cursor.init(&del);
    try std.testing.expectEqualStrings("b\x7fd", try readUtf8(&cursor));
}

test "MQTT strict UTF-8 policy rejects discouraged controls" {
    for ([_][]const u8{
        "bad\x01value",
        "bad\x1fvalue",
        "bad\x7fvalue",
        "bad\xc2\x9fvalue",
    }) |value| {
        try std.testing.expectError(
            error.InvalidUtf8,
            validateStrictUtf8String(value),
        );
    }
    try validateStrictUtf8String("plain/ascii/value");
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8String("valid\xc2\xa2\x1ftail"),
    );
    try validateStrictUtf8String("valid\xf0\xaa\x9b\x94value");

    try validateStrictUtf8Properties(&.{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "valid reason",
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "valid value",
        } },
        .{ .binary = .{
            .id = .correlation_data,
            .value = "opaque\x00\xff",
        } },
    });
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8Properties(&.{.{ .utf8 = .{
            .id = .reason_string,
            .value = "bad\x7freason",
        } }}),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8Properties(&.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "bad\xef\xb7\x90key",
            .value = "value",
        } }}),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8Properties(&.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "key",
            .value = "bad\xc2\x9fvalue",
        } }}),
    );
}

test "MQTT ASCII validation preserves base and strict policies" {
    var value: [1]u8 = undefined;
    for (0..128) |raw| {
        value[0] = @intCast(raw);
        if (raw == 0) {
            try std.testing.expectError(
                error.InvalidUtf8,
                validateUtf8String(&value),
            );
        } else {
            try validateUtf8String(&value);
        }

        if (raw <= 0x1f or raw == 0x7f) {
            try std.testing.expectError(
                error.InvalidUtf8,
                validateStrictUtf8String(&value),
            );
        } else {
            try validateStrictUtf8String(&value);
        }
    }
}

test "MQTT ping packets reject trailing bytes" {
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(std.testing.allocator);
    try writePing(&ping, std.testing.allocator, false);
    try validatePing(ping.items, false);
    var direct: [ping_packet_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        ping.items,
        writePingInto(&direct, false),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xd0, 0x00 },
        writePingInto(&direct, true),
    );
    try ping.append(std.testing.allocator, 0);
    try std.testing.expectError(error.InvalidPacketType, validatePing(ping.items, false));
}

test "MQTT Control Packet types enforce sender direction" {
    const client_only = [_]PacketType{
        .connect,
        .subscribe,
        .unsubscribe,
        .pingreq,
    };
    const server_only = [_]PacketType{
        .connack,
        .suback,
        .unsuback,
        .pingresp,
    };
    const bidirectional = [_]PacketType{
        .publish,
        .puback,
        .pubrec,
        .pubrel,
        .pubcomp,
        .disconnect,
        .auth,
    };

    for (client_only) |packet_type| {
        try validatePacketTypeForSender(packet_type, .client);
        try std.testing.expectError(
            error.InvalidPacketDirection,
            validatePacketTypeForSender(packet_type, .server),
        );
    }
    for (server_only) |packet_type| {
        try validatePacketTypeForSender(packet_type, .server);
        try std.testing.expectError(
            error.InvalidPacketDirection,
            validatePacketTypeForSender(packet_type, .client),
        );
    }
    for (bidirectional) |packet_type| {
        try validatePacketTypeForSender(packet_type, .client);
        try validatePacketTypeForSender(packet_type, .server);
    }
}

test "MQTT fixed-header flags are classified as malformed" {
    const ordinary = [_]PacketType{
        .connect,
        .connack,
        .puback,
        .pubrec,
        .pubcomp,
        .suback,
        .unsuback,
        .pingreq,
        .pingresp,
        .disconnect,
        .auth,
    };
    for (ordinary) |packet_type| {
        try validatePacketFlags(.v5, .{
            .packet_type = packet_type,
            .flags = packet_type.defaultFlags(),
            .remaining_len = 0,
            .header_len = 2,
        });
        try std.testing.expectError(
            error.InvalidFlags,
            validatePacketFlags(.v5, .{
                .packet_type = packet_type,
                .flags = 0x01,
                .remaining_len = 0,
                .header_len = 2,
            }),
        );
    }

    for ([_]PacketType{ .pubrel, .subscribe, .unsubscribe }) |packet_type| {
        try validatePacketFlags(.v5, .{
            .packet_type = packet_type,
            .flags = 0x02,
            .remaining_len = 0,
            .header_len = 2,
        });
    }
    try std.testing.expectError(
        error.InvalidFlags,
        validatePacketFlags(.v3_1_1, .{
            .packet_type = .pubrel,
            .flags = 0x0a,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        validatePacketFlags(.v5, .{
            .packet_type = .pubrel,
            .flags = 0x0a,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );

    try validatePacketFlags(.v5, .{
        .packet_type = .publish,
        .flags = 0x0c,
        .remaining_len = 0,
        .header_len = 2,
    });
    try std.testing.expectError(
        error.InvalidFlags,
        validatePacketFlags(.v5, .{
            .packet_type = .publish,
            .flags = 0x08,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );
    try std.testing.expectError(
        error.InvalidQoS,
        validatePacketFlags(.v5, .{
            .packet_type = .publish,
            .flags = 0x06,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );
}

test "MQTT 3.1.1 private bridge CONNECT roundtrip is version scoped" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeConnectPacket(&encoded, allocator, .v3_1_1, .{
        .client_id = "private-bridge",
        .bridge_mode = true,
        .clean_start = false,
    });
    const level_index = (try FixedHeader.parse(encoded.items)).header_len +
        2 + "MQTT".len;
    try std.testing.expectEqual(@as(u8, 0x84), encoded.items[level_index]);
    var parsed = try Connect.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v3_1_1, parsed.protocol);
    try std.testing.expect(parsed.bridge_mode);

    encoded.items[level_index] = 0x85;
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        Connect.parse(allocator, encoded.items),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        writeConnectPacket(&encoded, allocator, .v5, .{
            .client_id = "invalid-private-v5",
            .bridge_mode = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
}

test "MQTT 3.1 CONNECT uses MQIsdp and legacy validation" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = "p",
        .clean_start = true,
        .keep_alive_seconds = 10,
    });
    try std.testing.expectEqualSlices(u8, &.{
        0x10, 0x0f,
        0x00, 0x06,
        'M',  'Q',
        'I',  's',
        'd',  'p',
        0x03, 0x02,
        0x00, 0x0a,
        0x00, 0x01,
        'p',
    }, encoded.items);
    var parsed = try Connect.parse(allocator, encoded.items);
    try std.testing.expectEqual(ProtocolVersion.v3_1, parsed.protocol);
    try std.testing.expect(parsed.clean_start);
    parsed.deinit(allocator);

    // MQTT 3.1 predates the MQTT 3.1.1 requirement that CONNECT's fixed
    // header flags and Connect Flags bit zero are reserved-zero.
    encoded.items[0] = 0x14;
    encoded.items[11] |= 0x01;
    parsed = try Connect.parse(allocator, encoded.items);
    parsed.deinit(allocator);

    encoded.items[10] = ProtocolVersion.v3_1_1.byte();
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        Connect.parse(allocator, encoded.items),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientId,
        writeConnectPacket(&encoded, allocator, .v3_1, .{
            .client_id = "",
            .clean_start = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    const maximum_ascii_id = "abcdefghijklmnopqrstuvw";
    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = maximum_ascii_id,
    });
    parsed = try Connect.parse(allocator, encoded.items);
    try std.testing.expectEqualStrings(maximum_ascii_id, parsed.client_id);
    parsed.deinit(allocator);

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientId,
        writeConnectPacket(&encoded, allocator, .v3_1, .{
            .client_id = "abcdefghijklmnopqrstuvwx",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    const maximum_multibyte_id = [_]u8{ 0xc3, 0xa9 } ** 23;
    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = &maximum_multibyte_id,
    });
    parsed = try Connect.parse(allocator, encoded.items);
    try std.testing.expectEqualSlices(
        u8,
        &maximum_multibyte_id,
        parsed.client_id,
    );
    parsed.deinit(allocator);

    const overlong_multibyte_id = [_]u8{ 0xc3, 0xa9 } ** 24;
    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientId,
        writeConnectPacket(&encoded, allocator, .v3_1, .{
            .client_id = &overlong_multibyte_id,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = "legacy-bridge",
        .bridge_mode = true,
        .clean_start = false,
    });
    const level_index = (try FixedHeader.parse(encoded.items)).header_len +
        2 + "MQIsdp".len;
    try std.testing.expectEqual(@as(u8, 0x83), encoded.items[level_index]);
    parsed = try Connect.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.bridge_mode);

    var connack_bytes: std.ArrayList(u8) = .empty;
    defer connack_bytes.deinit(allocator);
    try ConnAck.write(&connack_bytes, allocator, .v3_1, false, 0, &.{});
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x02, 0x00, 0x00 },
        connack_bytes.items,
    );
    var connack = try ConnAck.parse(allocator, .v3_1, connack_bytes.items);
    defer connack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), connack.reason_code);
}

test "MQTT connect and publish parse" {
    const allocator = std.testing.allocator;
    var connect_bytes: std.ArrayList(u8) = .empty;
    defer connect_bytes.deinit(allocator);
    var will_props = [_]Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 5 } }};
    try writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "client-1",
        .clean_start = true,
        .keep_alive_seconds = 30,
        .properties = &.{.{ .two_byte = .{ .id = .receive_maximum, .value = 10 } }},
        .will = .{
            .topic = "status/client-1",
            .payload = "offline",
            .qos = .at_least_once,
            .properties = &will_props,
        },
        .username = "rumq",
        .password = "mq",
    });
    var connect = try Connect.parse(allocator, connect_bytes.items);
    defer connect.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v5, connect.protocol);
    try std.testing.expect(!connect.bridge_mode);
    try std.testing.expect(connect.clean_start);
    try std.testing.expectEqualStrings("client-1", connect.client_id);
    try std.testing.expectEqual(@as(usize, 1), connect.properties.len);
    try std.testing.expectEqual(@as(u16, 10), connect.properties[0].two_byte.value);
    try std.testing.expectEqual(@as(?u16, 10), receiveMaximum(connect.properties));
    try std.testing.expectEqual(@as(?u32, null), maximumPacketSize(connect.properties));
    try std.testing.expectEqual(@as(?u16, null), topicAlias(connect.properties));
    try std.testing.expectEqualStrings("status/client-1", connect.will.?.topic);
    try std.testing.expectEqualStrings("offline", connect.will.?.payload);
    try std.testing.expectEqual(QoS.at_least_once, connect.will.?.qos);
    try std.testing.expectEqual(@as(u32, 5), connect.will.?.properties[0].four_byte.value);
    try std.testing.expectEqualStrings("rumq", connect.username.?);
    try std.testing.expectEqualStrings("mq", connect.password.?);

    connect_bytes.clearRetainingCapacity();
    try writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "",
        .clean_start = true,
    });
    connect.deinit(allocator);
    connect = try Connect.parse(allocator, connect_bytes.items);
    try std.testing.expectEqualStrings("", connect.client_id);
    try std.testing.expect(connect.clean_start);

    const protocol_level_index = (try FixedHeader.parse(
        connect_bytes.items,
    )).header_len + 2 + "MQTT".len;
    try std.testing.expectEqual(
        ProtocolVersion.v5.byte(),
        try connectProtocolLevel(connect_bytes.items),
    );
    connect_bytes.items[protocol_level_index] = 6;
    try std.testing.expectEqual(
        @as(u8, 6),
        try connectProtocolLevel(connect_bytes.items),
    );
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        Connect.parse(allocator, connect_bytes.items),
    );
    connect_bytes.items[protocol_level_index - 1] = 'X';
    try std.testing.expectError(
        error.InvalidProtocolName,
        connectProtocolLevel(connect_bytes.items),
    );
    connect_bytes.items[protocol_level_index - 1] = 'T';
    connect_bytes.items[protocol_level_index] = ProtocolVersion.v5.byte();
    connect_bytes.clearRetainingCapacity();
    try writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "",
        .clean_start = false,
    });
    connect.deinit(allocator);
    connect = try Connect.parse(allocator, connect_bytes.items);
    try std.testing.expectEqualStrings("", connect.client_id);
    try std.testing.expect(!connect.clean_start);
    try std.testing.expectError(error.InvalidClientId, writeConnectPacket(&connect_bytes, allocator, .v3_1_1, .{
        .client_id = "",
        .clean_start = false,
    }));

    var persistent_empty_id: std.ArrayList(u8) = .empty;
    defer persistent_empty_id.deinit(allocator);
    var persistent_variable: std.ArrayList(u8) = .empty;
    defer persistent_variable.deinit(allocator);
    try writeUtf8(&persistent_variable, allocator, "MQTT");
    try persistent_variable.append(allocator, ProtocolVersion.v3_1_1.byte());
    try persistent_variable.append(allocator, 0x00); // Clean Start false with an empty Client ID.
    try wire.appendInt(&persistent_variable, allocator, u16, 30, .big);
    try writeUtf8(&persistent_variable, allocator, "");
    try (FixedHeader{
        .packet_type = .connect,
        .flags = 0,
        .remaining_len = persistent_variable.items.len,
        .header_len = 0,
    }).write(&persistent_empty_id, allocator);
    try persistent_empty_id.appendSlice(allocator, persistent_variable.items);
    try std.testing.expectError(error.InvalidClientId, Connect.parse(allocator, persistent_empty_id.items));

    var bad_will_props = [_]Property{.{ .byte = .{ .id = .payload_format_indicator, .value = 1 } }};
    try std.testing.expectError(error.InvalidUtf8, writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "client-2",
        .will = .{ .topic = "status/client-2", .payload = "\xff", .properties = &bad_will_props },
    }));

    var publish_bytes: std.ArrayList(u8) = .empty;
    defer publish_bytes.deinit(allocator);
    try writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "21.5", .{ .qos = .at_least_once, .packet_id = 7, .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }} });
    var publish = try Publish.parse(allocator, .v5, publish_bytes.items);
    const publish_fixed = try FixedHeader.parse(publish_bytes.items);
    var payload_publish = try Publish.parsePayload(
        allocator,
        .v5,
        publish_fixed.flags,
        publish_bytes.items[publish_fixed.header_len..],
    );
    defer payload_publish.deinit(allocator);
    try std.testing.expectEqual(publish.qos, payload_publish.qos);
    try std.testing.expectEqual(publish.packet_id, payload_publish.packet_id);
    try std.testing.expectEqualStrings(publish.topic, payload_publish.topic);
    try std.testing.expectEqualStrings(publish.payload, payload_publish.payload);
    var trailing_publish = try publish_bytes.clone(allocator);
    defer trailing_publish.deinit(allocator);
    try trailing_publish.append(allocator, 0);
    try std.testing.expectError(error.InvalidPacketType, Publish.parse(allocator, .v5, trailing_publish.items));

    defer publish.deinit(allocator);
    try std.testing.expectEqual(QoS.at_least_once, publish.qos);
    try std.testing.expectEqual(@as(u16, 7), publish.packet_id.?);
    try std.testing.expectEqualStrings("21.5", publish.payload);
    try std.testing.expectEqual(@as(?u16, 2), topicAlias(publish.properties));
    try std.testing.expectError(
        error.InvalidFlags,
        Publish.parsePayload(
            allocator,
            .v5,
            0x08,
            publish_bytes.items[publish_fixed.header_len..],
        ),
    );

    var wildcard_publish = try publish_bytes.clone(allocator);
    defer wildcard_publish.deinit(allocator);
    const wildcard_fixed = try FixedHeader.parse(wildcard_publish.items);
    wildcard_publish.items[wildcard_fixed.header_len + 2] = '+';
    try std.testing.expectError(
        error.InvalidTopic,
        Publish.parse(allocator, .v5, wildcard_publish.items),
    );

    var invalid_topic_publish = try publish_bytes.clone(allocator);
    defer invalid_topic_publish.deinit(allocator);
    const invalid_topic_fixed = try FixedHeader.parse(
        invalid_topic_publish.items,
    );
    invalid_topic_publish.items[invalid_topic_fixed.header_len + 2] = 0xff;
    try std.testing.expectError(
        error.InvalidUtf8,
        Publish.parse(allocator, .v5, invalid_topic_publish.items),
    );
    try std.testing.expectError(error.InvalidPacketIdentifier, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "bad", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidPacketIdentifier, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "bad", .{ .qos = .at_least_once, .packet_id = 0 }));
    try std.testing.expectError(error.InvalidPacketIdentifier, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "bad", .{ .packet_id = 7 }));

    try std.testing.expectError(error.InvalidUtf8, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "\xff", .{
        .properties = &.{.{ .byte = .{ .id = .payload_format_indicator, .value = 1 } }},
    }));

    var invalid_payload = std.ArrayList(u8).empty;
    defer invalid_payload.deinit(allocator);
    try writePublish(&invalid_payload, allocator, .v5, "sensors/temp", "ok", .{
        .properties = &.{.{ .byte = .{ .id = .payload_format_indicator, .value = 1 } }},
    });
    invalid_payload.items[invalid_payload.items.len - 2] = 0xff;
    invalid_payload.items[invalid_payload.items.len - 1] = 0xff;
    try std.testing.expectError(error.InvalidUtf8, Publish.parse(allocator, .v5, invalid_payload.items));

    var alias_only_bytes: std.ArrayList(u8) = .empty;
    defer alias_only_bytes.deinit(allocator);
    try writePublish(&alias_only_bytes, allocator, .v5, "", "alias payload", .{ .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }} });
    var alias_only = try Publish.parse(allocator, .v5, alias_only_bytes.items);
    defer alias_only.deinit(allocator);
    try std.testing.expectEqualStrings("", alias_only.topic);
    try std.testing.expectEqual(@as(?u16, 2), topicAlias(alias_only.properties));

    var invalid_publish: std.ArrayList(u8) = .empty;
    defer invalid_publish.deinit(allocator);
    var invalid_variable: std.ArrayList(u8) = .empty;
    defer invalid_variable.deinit(allocator);
    try writeUtf8(&invalid_variable, allocator, "sensors/temp");
    try wire.appendInt(&invalid_variable, allocator, u16, 0, .big);
    try writeProperties(&invalid_variable, allocator, &.{});
    try invalid_variable.appendSlice(allocator, "bad");
    try (FixedHeader{
        .packet_type = .publish,
        .flags = @as(u4, @intFromEnum(QoS.at_least_once)) << 1,
        .remaining_len = invalid_variable.items.len,
        .header_len = 0,
    }).write(&invalid_publish, allocator);
    try invalid_publish.appendSlice(allocator, invalid_variable.items);
    try std.testing.expectError(error.InvalidPacketIdentifier, Publish.parse(allocator, .v5, invalid_publish.items));
}

test "MQTT v5 property values are validated" {
    const allocator = std.testing.allocator;

    var invalid_write: std.ArrayList(u8) = .empty;
    defer invalid_write.deinit(allocator);
    try std.testing.expectError(error.InvalidProperty, writeProperties(&invalid_write, allocator, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 0 } },
    }));
    // Public callers construct Property unions directly, so reject mismatched
    // union tags instead of serializing a semantically wrong property id with a
    // different wire width.  rumqtt models each packet's properties as typed
    // fields; this check preserves that safety for netz's compact union API.
    try std.testing.expectError(error.InvalidProperty, writeProperties(&invalid_write, allocator, &.{
        .{ .two_byte = .{ .id = .payload_format_indicator, .value = 1 } },
    }));

    const Cases = struct {
        fn expectInvalid(bytes: []const u8) !void {
            var cursor = wire.Cursor.init(bytes);
            try std.testing.expectError(error.InvalidProperty, parseProperties(std.testing.allocator, &cursor));
        }
    };
    const InvalidIdentifierCases = struct {
        fn expectInvalid(bytes: []const u8) !void {
            var cursor = wire.Cursor.init(bytes);
            try std.testing.expectError(
                error.InvalidPropertyIdentifier,
                parseProperties(std.testing.allocator, &cursor),
            );
        }
    };

    try InvalidIdentifierCases.expectInvalid(&.{ 0x02, 0x00, 0x01 });
    var noncanonical_identifier = wire.Cursor.init(
        &.{ 0x03, 0x80, 0x00, 0x01 },
    );
    try std.testing.expectError(
        error.MalformedRemainingLength,
        parseProperties(allocator, &noncanonical_identifier),
    );
    try InvalidIdentifierCases.expectInvalid(&.{ 0x02, 0x7f, 0x01 });

    var invalid_receive_maximum: std.ArrayList(u8) = .empty;
    defer invalid_receive_maximum.deinit(allocator);
    try encodeRemainingLength(&invalid_receive_maximum, allocator, 3);
    try invalid_receive_maximum.appendSlice(allocator, &.{ @intFromEnum(PropertyId.receive_maximum), 0, 0 });
    try Cases.expectInvalid(invalid_receive_maximum.items);

    var invalid_max_packet: std.ArrayList(u8) = .empty;
    defer invalid_max_packet.deinit(allocator);
    try encodeRemainingLength(&invalid_max_packet, allocator, 5);
    try invalid_max_packet.append(allocator, @intFromEnum(PropertyId.maximum_packet_size));
    try wire.appendInt(&invalid_max_packet, allocator, u32, 0, .big);
    try Cases.expectInvalid(invalid_max_packet.items);

    var invalid_response_topic: std.ArrayList(u8) = .empty;
    defer invalid_response_topic.deinit(allocator);
    try encodeRemainingLength(&invalid_response_topic, allocator, 12);
    try invalid_response_topic.append(allocator, @intFromEnum(PropertyId.response_topic));
    try wire.appendInt(&invalid_response_topic, allocator, u16, 9, .big);
    try invalid_response_topic.appendSlice(allocator, "reply/+/x");
    try Cases.expectInvalid(invalid_response_topic.items);

    var invalid_topic_alias: std.ArrayList(u8) = .empty;
    defer invalid_topic_alias.deinit(allocator);
    try encodeRemainingLength(&invalid_topic_alias, allocator, 3);
    try invalid_topic_alias.appendSlice(allocator, &.{ @intFromEnum(PropertyId.topic_alias), 0, 0 });
    try Cases.expectInvalid(invalid_topic_alias.items);

    var invalid_retain_available: std.ArrayList(u8) = .empty;
    defer invalid_retain_available.deinit(allocator);
    try encodeRemainingLength(&invalid_retain_available, allocator, 2);
    try invalid_retain_available.appendSlice(allocator, &.{ @intFromEnum(PropertyId.retain_available), 2 });
    try Cases.expectInvalid(invalid_retain_available.items);

    var invalid_max_qos: std.ArrayList(u8) = .empty;
    defer invalid_max_qos.deinit(allocator);
    try encodeRemainingLength(&invalid_max_qos, allocator, 2);
    try invalid_max_qos.appendSlice(allocator, &.{ @intFromEnum(PropertyId.maximum_qos), 2 });
    try Cases.expectInvalid(invalid_max_qos.items);

    var duplicate_receive_maximum: std.ArrayList(u8) = .empty;
    defer duplicate_receive_maximum.deinit(allocator);
    try encodeRemainingLength(&duplicate_receive_maximum, allocator, 6);
    try duplicate_receive_maximum.appendSlice(allocator, &.{ @intFromEnum(PropertyId.receive_maximum), 0, 1 });
    try duplicate_receive_maximum.appendSlice(allocator, &.{ @intFromEnum(PropertyId.receive_maximum), 0, 2 });
    try Cases.expectInvalid(duplicate_receive_maximum.items);

    var duplicate_write: std.ArrayList(u8) = .empty;
    defer duplicate_write.deinit(allocator);
    try std.testing.expectError(error.InvalidProperty, writeProperties(&duplicate_write, allocator, &.{
        .{ .four_byte = .{ .id = .maximum_packet_size, .value = 1024 } },
        .{ .four_byte = .{ .id = .maximum_packet_size, .value = 2048 } },
    }));

    try writeProperties(&duplicate_write, allocator, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "a", .value = "1" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "b", .value = "2" } },
    });
}

test "MQTT v5 packet-specific properties are validated" {
    const allocator = std.testing.allocator;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "client",
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }},
    }));
    var invalid_will_props = [_]Property{.{ .two_byte = .{ .id = .receive_maximum, .value = 1 } }};
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "client",
        .will = .{
            .topic = "status/client",
            .payload = "offline",
            .properties = &invalid_will_props,
        },
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v5, false, 0, &.{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v5, false, 0, &.{
        .{ .utf8 = .{ .id = .assigned_client_identifier, .value = "" } },
    }));
    try std.testing.expectError(
        error.InvalidProperty,
        ConnAck.parse(
            allocator,
            .v5,
            &.{ 0x20, 0x06, 0x00, 0x00, 0x03, 0x12, 0x00, 0x00 },
        ),
    );
    try std.testing.expectError(error.InvalidProperty, writePublish(&encoded, allocator, .v5, "topic", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .receive_maximum, .value = 1 } }},
    }));
    try std.testing.expectError(error.InvalidProperty, Subscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "not allowed" } },
    }, &.{.{ .topic_filter = "topic" }}));
    try std.testing.expectError(error.InvalidProperty, Subscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 2 } },
    }, &.{.{ .topic_filter = "topic" }}));
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v3_1_1, .{
        .client_id = "client",
        .properties = &.{.{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } }},
    }));
    var v3_will_props = [_]Property{.{ .utf8_pair = .{ .id = .user_property, .key = "will-k", .value = "will-v" } }};
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v3_1_1, .{
        .client_id = "client",
        .will = .{
            .topic = "status/client",
            .payload = "offline",
            .properties = &v3_will_props,
        },
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v3_1_1, false, 0, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }));
    try std.testing.expectError(error.InvalidProperty, writePublish(&encoded, allocator, .v3_1_1, "topic", "payload", .{
        .properties = &.{.{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } }},
    }));
    try std.testing.expectError(error.InvalidProperty, Subscribe.write(&encoded, allocator, .v3_1_1, 1, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }, &.{.{ .topic_filter = "topic" }}));
    try std.testing.expectError(error.InvalidProperty, Unsubscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
    }, &.{"topic"}));
    try std.testing.expectError(error.InvalidProperty, SubAck.write(&encoded, allocator, .v5, 1, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 1 } },
    }, &.{0}));
    try std.testing.expectError(error.InvalidProperty, Disconnect.write(&encoded, allocator, .v5, 0, &.{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidProperty, AckPacket.write(&encoded, allocator, .v5, .puback, 1, 0, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "client",
        .properties = &.{.{ .binary = .{ .id = .authentication_data, .value = "opaque" } }},
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v5, false, 0, &.{
        .{ .binary = .{ .id = .authentication_data, .value = "opaque" } },
    }));
    try std.testing.expectError(error.InvalidProperty, Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .binary = .{ .id = .authentication_data, .value = "opaque" } },
    }));
    try Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "opaque" } },
    });

    var invalid_connect: std.ArrayList(u8) = .empty;
    defer invalid_connect.deinit(allocator);
    var connect_variable: std.ArrayList(u8) = .empty;
    defer connect_variable.deinit(allocator);
    try writeUtf8(&connect_variable, allocator, "MQTT");
    try connect_variable.append(allocator, ProtocolVersion.v5.byte());
    try connect_variable.append(allocator, 0x02);
    try wire.appendInt(&connect_variable, allocator, u16, 30, .big);
    // Topic Alias is a PUBLISH-only property in rumqtt/MQTT v5 and must not be
    // accepted in CONNECT even though it is well-formed generically.
    try writeProperties(&connect_variable, allocator, &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try writeUtf8(&connect_variable, allocator, "client");
    try (FixedHeader{
        .packet_type = .connect,
        .flags = 0,
        .remaining_len = connect_variable.items.len,
        .header_len = 0,
    }).write(&invalid_connect, allocator);
    try invalid_connect.appendSlice(allocator, connect_variable.items);
    try std.testing.expectError(
        error.MalformedPropertyContext,
        Connect.parse(allocator, invalid_connect.items),
    );

    var invalid_suback: std.ArrayList(u8) = .empty;
    defer invalid_suback.deinit(allocator);
    var suback_variable: std.ArrayList(u8) = .empty;
    defer suback_variable.deinit(allocator);
    try wire.appendInt(&suback_variable, allocator, u16, 1, .big);
    try writeProperties(&suback_variable, allocator, &.{.{ .two_byte = .{ .id = .receive_maximum, .value = 1 } }});
    try suback_variable.append(allocator, 0x00);
    try (FixedHeader{
        .packet_type = .suback,
        .flags = 0,
        .remaining_len = suback_variable.items.len,
        .header_len = 0,
    }).write(&invalid_suback, allocator);
    try invalid_suback.appendSlice(allocator, suback_variable.items);
    try std.testing.expectError(
        error.MalformedPropertyContext,
        SubAck.parse(allocator, .v5, invalid_suback.items),
    );

    var duplicate_subscribe: std.ArrayList(u8) = .empty;
    defer duplicate_subscribe.deinit(allocator);
    var subscribe_variable: std.ArrayList(u8) = .empty;
    defer subscribe_variable.deinit(allocator);
    try wire.appendInt(&subscribe_variable, allocator, u16, 1, .big);
    try writeProperties(&subscribe_variable, allocator, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 2 } },
    });
    try writeUtf8(&subscribe_variable, allocator, "topic");
    try subscribe_variable.append(allocator, 0);
    try (FixedHeader{
        .packet_type = .subscribe,
        .flags = PacketType.subscribe.defaultFlags(),
        .remaining_len = subscribe_variable.items.len,
        .header_len = 0,
    }).write(&duplicate_subscribe, allocator);
    try duplicate_subscribe.appendSlice(allocator, subscribe_variable.items);
    try std.testing.expectError(error.InvalidProperty, Subscribe.parse(allocator, .v5, duplicate_subscribe.items));

    encoded.clearRetainingCapacity();
    try writePublish(&encoded, allocator, .v5, "topic", "payload", .{
        .properties = &.{
            .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
            .{ .varint = .{ .id = .subscription_identifier, .value = 2 } },
        },
    });
    var publish = try Publish.parse(allocator, .v5, encoded.items);
    defer publish.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), publish.properties.len);

    encoded.clearRetainingCapacity();
    try Subscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }, &.{.{ .topic_filter = "topic" }});
}

test "MQTT CONNECT validates flags and will topic" {
    const allocator = std.testing.allocator;
    var invalid_flags: std.ArrayList(u8) = .empty;
    defer invalid_flags.deinit(allocator);
    try (FixedHeader{ .packet_type = .connect, .flags = 0, .remaining_len = 12, .header_len = 0 }).write(&invalid_flags, allocator);
    try writeUtf8(&invalid_flags, allocator, "MQTT");
    try invalid_flags.append(allocator, ProtocolVersion.v3_1_1.byte());
    try invalid_flags.append(allocator, 0x20); // will retain without will flag
    try wire.appendInt(&invalid_flags, allocator, u16, 30, .big);
    try writeUtf8(&invalid_flags, allocator, "");
    try std.testing.expectError(error.InvalidFlags, Connect.parse(allocator, invalid_flags.items));

    var password_without_username_v3: std.ArrayList(u8) = .empty;
    defer password_without_username_v3.deinit(allocator);
    var password_v3_variable: std.ArrayList(u8) = .empty;
    defer password_v3_variable.deinit(allocator);
    try writeUtf8(&password_v3_variable, allocator, "MQTT");
    try password_v3_variable.append(allocator, ProtocolVersion.v3_1_1.byte());
    try password_v3_variable.append(allocator, 0x42); // Password + Clean Session, but no User Name.
    try wire.appendInt(&password_v3_variable, allocator, u16, 30, .big);
    try writeUtf8(&password_v3_variable, allocator, "client");
    try writeBinary(&password_v3_variable, allocator, "password");
    try (FixedHeader{
        .packet_type = .connect,
        .flags = 0,
        .remaining_len = password_v3_variable.items.len,
        .header_len = 0,
    }).write(&password_without_username_v3, allocator);
    try password_without_username_v3.appendSlice(allocator, password_v3_variable.items);
    try std.testing.expectError(error.InvalidFlags, Connect.parse(allocator, password_without_username_v3.items));
    try std.testing.expectError(error.InvalidFlags, writeConnectPacket(&password_without_username_v3, allocator, .v3_1_1, .{
        .client_id = "client",
        .password = "password",
    }));

    // MQTT 5 keeps the Username and Password payload flags independent for
    // enhanced-authentication deployments, so the v3.1.1 guard above must not
    // reject the same flag combination for protocol level 5.
    var password_without_username_v5: std.ArrayList(u8) = .empty;
    defer password_without_username_v5.deinit(allocator);
    try writeConnectPacket(&password_without_username_v5, allocator, .v5, .{
        .client_id = "client-5",
        .password = "password",
    });
    var parsed_password_only_v5 = try Connect.parse(allocator, password_without_username_v5.items);
    defer parsed_password_only_v5.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v5, parsed_password_only_v5.protocol);
    try std.testing.expect(parsed_password_only_v5.username == null);
    try std.testing.expectEqualStrings("password", parsed_password_only_v5.password.?);

    var invalid_will: std.ArrayList(u8) = .empty;
    defer invalid_will.deinit(allocator);
    try std.testing.expectError(error.InvalidTopic, writeConnectPacket(&invalid_will, allocator, .v5, .{
        .client_id = "client-2",
        .will = .{ .topic = "bad/+/topic", .payload = "offline" },
    }));
}

test "MQTT CONNECT releases Will Delay properties after invalid empty topic" {
    // Exact CONNECT shape from Mosquitto issue 573191. Parsing allocates the
    // Will property list before validating its empty Topic Name, so the error
    // path must release that list as well as the outer CONNECT properties.
    // std.testing.allocator turns either ownership leak into a test failure.
    const packet = [_]u8{
        0x10, 0x2a, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
        0x05, 0x06, 0x00, 0x3c, 0x03, 0x21, 0x00, 0x14,
        0x00, 0x10, 0x77, 0x69, 0x6c, 0x6c, 0x2d, 0x35,
        0x37, 0x33, 0x31, 0x39, 0x31, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x05, 0x18, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(
        error.InvalidTopic,
        Connect.parse(std.testing.allocator, &packet),
    );
}

test "MQTT topic validation and filter matching" {
    try std.testing.expect(validTopicName("sensors/temp"));
    try std.testing.expect(!validTopicName(""));
    try std.testing.expect(!validTopicName("wrong/#/path"));
    try std.testing.expect(!validTopicName("w/r/o/n/g+"));
    try std.testing.expect(!validTopicName("bad\x00topic"));
    try std.testing.expect(!validTopicName(&[_]u8{ 0xff, 0xfe }));

    try std.testing.expect(validTopicFilter("correct/filter/#"));
    try std.testing.expect(validTopicFilter("cor/+/rect/+"));
    try std.testing.expect(!validTopicFilter(""));
    try std.testing.expect(!validTopicFilter("wrong/#/filter"));
    try std.testing.expect(!validTopicFilter("wrong/wr#ng/filter"));
    try std.testing.expect(!validTopicFilter("wr/+o+/ng"));
    try std.testing.expect(!validTopicFilter("bad\x00/filter"));
    try std.testing.expect(!validTopicFilter(&[_]u8{ 'b', 'a', 'd', '/', 0xff }));
    try std.testing.expect(validTopicFilter("$share/group/sensors/+/temp"));
    try std.testing.expect(validTopicFilter("$share/group/#"));
    try std.testing.expect(!validTopicFilter("$share/group"));
    try std.testing.expect(!validTopicFilter("$share//sensors/temp"));
    try std.testing.expect(!validTopicFilter("$share/bad\x00group/sensors/temp"));
    try std.testing.expect(!validTopicFilter("$share/gr+oup/sensors/temp"));
    try std.testing.expect(!validTopicFilter("$share/group/bad/#/filter"));

    try std.testing.expect(topicMatchesFilter("a/b/c", "a/b/c"));
    try std.testing.expect(topicMatchesFilter("a/b/c/d/e", "a/+/c/+/e"));
    try std.testing.expect(topicMatchesFilter("a/b/c/d/e/f", "a/b/c/#"));
    try std.testing.expect(!topicMatchesFilter("a/b", "a/b/+"));
    try std.testing.expect(!topicMatchesFilter("$system/metrics", "+/+"));
    try std.testing.expect(topicMatchesFilter("$system/metrics", "$system/+"));
    try std.testing.expect(topicMatchesFilter("sensors/temp", "$share/workers/sensors/+"));
    try std.testing.expect(!topicMatchesFilter("$system/metrics", "$share/workers/+"));
    try std.testing.expect(topicMatchesFilter("$system/metrics", "$share/workers/$system/+"));
    try std.testing.expect(!topicMatchesFilter("sensors/temp", "$share//sensors/+"));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidTopic, writePublish(&encoded, std.testing.allocator, .v5, "bad/#", "payload", .{}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&encoded, std.testing.allocator, .v5, 1, &.{}, &[_]Subscription{.{ .topic_filter = "bad/#/filter" }}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&encoded, std.testing.allocator, .v5, 1, &.{}, &[_]Subscription{.{ .topic_filter = "$share/group" }}));
}

test "MQTT topic validation enforces the UTF-8 wire length transactionally" {
    const allocator = std.testing.allocator;
    const oversized = try allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'a');
    const maximum = oversized[0..std.math.maxInt(u16)];

    try std.testing.expect(validTopicName(maximum));
    try std.testing.expect(validTopicFilter(maximum));
    try std.testing.expectError(error.InvalidTopic, validateTopicName(oversized));
    try std.testing.expectError(
        error.InvalidSubscription,
        validateTopicFilter(oversized),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, "existing output");
    try std.testing.expectError(
        error.InvalidTopic,
        writePublish(&encoded, allocator, .v5, oversized, "payload", .{}),
    );
    try std.testing.expectEqualStrings("existing output", encoded.items);
    try std.testing.expectError(
        error.InvalidSubscription,
        Subscribe.write(
            &encoded,
            allocator,
            .v5,
            1,
            &.{},
            &.{.{ .topic_filter = oversized }},
        ),
    );
    try std.testing.expectEqualStrings("existing output", encoded.items);
}

test "MQTT connack ack and ping controls" {
    const allocator = std.testing.allocator;

    var connack_bytes: std.ArrayList(u8) = .empty;
    defer connack_bytes.deinit(allocator);
    try ConnAck.write(&connack_bytes, allocator, .v5, true, 0, &.{});
    var connack = try ConnAck.parse(allocator, .v5, connack_bytes.items);
    defer connack.deinit(allocator);
    try std.testing.expect(connack.session_present);
    try std.testing.expectEqual(@as(u8, 0), connack.reason_code);
    try std.testing.expectError(error.InvalidFlags, ConnAck.write(&connack_bytes, allocator, .v5, true, 0x80, &.{}));
    try std.testing.expectError(error.InvalidReasonCode, ConnAck.write(&connack_bytes, allocator, .v5, false, 0x8b, &.{}));
    connack_bytes.clearRetainingCapacity();
    try ConnAck.write(&connack_bytes, allocator, .v3_1_1, false, 0x05, &.{});
    connack.deinit(allocator);
    connack = try ConnAck.parse(allocator, .v3_1_1, connack_bytes.items);
    try std.testing.expectEqual(@as(u8, 0x05), connack.reason_code);
    try std.testing.expectError(error.InvalidReasonCode, ConnAck.write(&connack_bytes, allocator, .v3_1_1, false, 0x80, &.{}));

    var direct_connack: [ConnAck.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x03, 0x01, 0x00, 0x00 },
        try ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v5,
            true,
            0,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x03, 0x00, 0x80, 0x00 },
        try ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v5,
            false,
            0x80,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x02, 0x00, 0x05 },
        try ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v3_1_1,
            false,
            0x05,
        ),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v5,
            true,
            0x80,
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v3_1_1,
            false,
            0x80,
        ),
    );

    var invalid_connack: std.ArrayList(u8) = .empty;
    defer invalid_connack.deinit(allocator);
    try (FixedHeader{
        .packet_type = .connack,
        .flags = 0,
        .remaining_len = 3,
        .header_len = 0,
    }).write(&invalid_connack, allocator);
    try invalid_connack.appendSlice(allocator, &.{ 0x00, 0x8b, 0x00 });
    try std.testing.expectError(error.InvalidReasonCode, ConnAck.parse(allocator, .v5, invalid_connack.items));

    invalid_connack.clearRetainingCapacity();
    try (FixedHeader{
        .packet_type = .connack,
        .flags = 0,
        .remaining_len = 3,
        .header_len = 0,
    }).write(&invalid_connack, allocator);
    try invalid_connack.appendSlice(allocator, &.{ 0x01, 0x80, 0x00 });
    try std.testing.expectError(error.InvalidFlags, ConnAck.parse(allocator, .v5, invalid_connack.items));

    var puback_bytes: std.ArrayList(u8) = .empty;
    defer puback_bytes.deinit(allocator);
    try AckPacket.write(&puback_bytes, allocator, .v5, .puback, 42, 0x10, &.{});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x03, 0x00, 0x2a, 0x10 }, puback_bytes.items);
    var direct_ack: [AckPacket.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        puback_bytes.items,
        try AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .puback,
            42,
            0x10,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x02, 0x00, 0x2a },
        try AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .puback,
            42,
            0,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x62, 0x02, 0x12, 0x34 },
        try AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v3_1_1,
            .pubrel,
            0x1234,
            0,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .puback,
            0,
            0,
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v3_1_1,
            .puback,
            42,
            0x80,
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .pubrel,
            42,
            0x10,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketType,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .suback,
            42,
            0,
        ),
    );
    var puback = try AckPacket.parse(allocator, .v5, puback_bytes.items);
    defer puback.deinit(allocator);
    try std.testing.expectEqual(PacketType.puback, puback.packet_type);
    try std.testing.expectEqual(@as(u16, 42), puback.packet_id);
    try std.testing.expectEqual(@as(u8, 0x10), puback.reason_code);
    try std.testing.expect(puback.accepted());

    puback_bytes.clearRetainingCapacity();
    try AckPacket.write(&puback_bytes, allocator, .v5, .puback, 43, 0x80, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "quota" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "puback-negative" } },
    });
    puback.deinit(allocator);
    puback = try AckPacket.parse(allocator, .v5, puback_bytes.items);
    try std.testing.expectEqual(@as(u8, 0x80), puback.reason_code);
    try std.testing.expect(!puback.accepted());
    try std.testing.expectEqualStrings("quota", puback.properties[0].utf8.value);

    try std.testing.expectError(error.InvalidReasonCode, AckPacket.write(&puback_bytes, allocator, .v5, .pubrel, 44, 0x10, &.{}));
    try std.testing.expectError(error.InvalidProperty, AckPacket.write(&puback_bytes, allocator, .v5, .puback, 44, 0, &.{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidReasonCode, AckPacket.write(&puback_bytes, allocator, .v3_1_1, .puback, 44, 0x80, &.{}));
    try std.testing.expectError(error.InvalidPacketType, AckPacket.write(&puback_bytes, allocator, .v5, .unsuback, 44, 0, &.{}));
    puback_bytes.clearRetainingCapacity();
    try UnsubAck.write(&puback_bytes, allocator, .v5, 44, &.{}, &.{0x00});
    try std.testing.expectError(error.InvalidPacketType, AckPacket.parse(allocator, .v5, puback_bytes.items));

    try std.testing.expectError(
        error.InvalidFlags,
        AckPacket.parse(allocator, .v3_1_1, &.{ 0x6a, 0x02, 0x00, 0x2a }),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        AckPacket.parse(allocator, .v5, &.{ 0x6a, 0x02, 0x00, 0x2a }),
    );
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(allocator);
    try writePing(&ping, allocator, false);
    try validatePing(ping.items, false);
}

test "MQTT subscribe and suback controls" {
    const allocator = std.testing.allocator;
    const subs = [_]Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .at_most_once, .retain_as_published = true },
    };

    var subscribe_bytes: std.ArrayList(u8) = .empty;
    defer subscribe_bytes.deinit(allocator);
    try Subscribe.write(&subscribe_bytes, allocator, .v5, 9, &.{}, &subs);
    var subscribe = try Subscribe.parse(allocator, .v5, subscribe_bytes.items);
    defer subscribe.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 9), subscribe.packet_id);
    try std.testing.expectEqual(@as(usize, 2), subscribe.subscriptions.len);
    try std.testing.expectEqualStrings("sensors/+", subscribe.subscriptions[0].topic_filter);
    try std.testing.expectEqual(QoS.at_least_once, subscribe.subscriptions[0].qos);

    subscribe_bytes.clearRetainingCapacity();
    try Subscribe.write(&subscribe_bytes, allocator, .v3_1_1, 10, &.{}, &.{.{ .topic_filter = "v3/ok", .qos = .at_least_once }});
    subscribe.deinit(allocator);
    subscribe = try Subscribe.parse(allocator, .v3_1_1, subscribe_bytes.items);
    try std.testing.expectEqual(@as(u16, 10), subscribe.packet_id);
    try std.testing.expectEqual(QoS.at_least_once, subscribe.subscriptions[0].qos);
    try std.testing.expect(!subscribe.subscriptions[0].no_local);
    try std.testing.expect(!subscribe.subscriptions[0].retain_as_published);
    try std.testing.expectEqual(@as(u2, 0), subscribe.subscriptions[0].retain_handling);

    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&subscribe_bytes, allocator, .v3_1_1, 11, &.{}, &.{.{
        .topic_filter = "v3/no-local",
        .qos = .at_most_once,
        .no_local = true,
    }}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&subscribe_bytes, allocator, .v3_1_1, 12, &.{}, &.{.{
        .topic_filter = "v3/retain-handling",
        .retain_handling = 1,
    }}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&subscribe_bytes, allocator, .v5, 13, &.{}, &.{.{
        .topic_filter = "$share/workers/sensors/+",
        .no_local = true,
    }}));

    var invalid_v3_options: std.ArrayList(u8) = .empty;
    defer invalid_v3_options.deinit(allocator);
    var invalid_v3_variable: std.ArrayList(u8) = .empty;
    defer invalid_v3_variable.deinit(allocator);
    try wire.appendInt(&invalid_v3_variable, allocator, u16, 13, .big);
    try writeUtf8(&invalid_v3_variable, allocator, "v3/bad-options");
    try invalid_v3_variable.append(allocator, 0x04); // MQTT 5 No Local bit is reserved in 3.1.1.
    try (FixedHeader{
        .packet_type = .subscribe,
        .flags = PacketType.subscribe.defaultFlags(),
        .remaining_len = invalid_v3_variable.items.len,
        .header_len = 0,
    }).write(&invalid_v3_options, allocator);
    try invalid_v3_options.appendSlice(allocator, invalid_v3_variable.items);
    try std.testing.expectError(error.MalformedSubscriptionOptions, Subscribe.parse(allocator, .v3_1_1, invalid_v3_options.items));

    for ([_]u8{ 0x40, 0x80, 0xf0 }) |options| {
        const malformed = [_]u8{
            0x82, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p', options,
        };
        try std.testing.expectError(
            error.MalformedSubscriptionOptions,
            Subscribe.parse(allocator, .v5, &malformed),
        );
    }
    try std.testing.expectError(
        error.InvalidSubscription,
        Subscribe.parse(
            allocator,
            .v5,
            &.{ 0x82, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p', 0x30 },
        ),
    );

    // A complete UTF-8 Topic Filter still needs its Subscription Options
    // byte. Read the whole subscription tuple before applying semantic Topic
    // Filter checks so structural truncation remains a Malformed Packet.
    try std.testing.expectError(
        error.BufferTooShort,
        Subscribe.parse(
            allocator,
            .v5,
            &.{ 0x82, 0x06, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p' },
        ),
    );

    var invalid_shared_no_local: std.ArrayList(u8) = .empty;
    defer invalid_shared_no_local.deinit(allocator);
    var invalid_shared_variable: std.ArrayList(u8) = .empty;
    defer invalid_shared_variable.deinit(allocator);
    try wire.appendInt(&invalid_shared_variable, allocator, u16, 14, .big);
    try writeProperties(&invalid_shared_variable, allocator, &.{});
    try writeUtf8(&invalid_shared_variable, allocator, "$share/workers/sensors/+");
    try invalid_shared_variable.append(allocator, 0x04);
    try (FixedHeader{
        .packet_type = .subscribe,
        .flags = PacketType.subscribe.defaultFlags(),
        .remaining_len = invalid_shared_variable.items.len,
        .header_len = 0,
    }).write(&invalid_shared_no_local, allocator);
    try invalid_shared_no_local.appendSlice(allocator, invalid_shared_variable.items);
    try std.testing.expectError(error.InvalidSubscription, Subscribe.parse(allocator, .v5, invalid_shared_no_local.items));

    var suback_bytes: std.ArrayList(u8) = .empty;
    defer suback_bytes.deinit(allocator);
    const reasons = [_]u8{ 0x01, 0x00 };
    try SubAck.write(&suback_bytes, allocator, .v5, 9, &.{}, &reasons);
    var suback = try SubAck.parse(allocator, .v5, suback_bytes.items);
    defer suback.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 9), suback.packet_id);
    try std.testing.expectEqualSlices(u8, &reasons, suback.reason_codes);
    var direct_suback: [256]u8 = undefined;
    const direct_v5 = try SubAck.writeNoPropertiesInto(
        &direct_suback,
        .v5,
        9,
        &reasons,
    );
    try std.testing.expectEqualSlices(u8, suback_bytes.items, direct_v5);
    try std.testing.expectEqual(
        direct_v5.len,
        try SubAck.noPropertiesWireLen(.v5, 9, &reasons),
    );

    suback_bytes.clearRetainingCapacity();
    try SubAck.write(&suback_bytes, allocator, .v3_1_1, 9, &.{}, &.{0x80});
    suback.deinit(allocator);
    suback = try SubAck.parse(allocator, .v3_1_1, suback_bytes.items);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, suback.reason_codes);
    try std.testing.expectEqualSlices(
        u8,
        suback_bytes.items,
        try SubAck.writeNoPropertiesInto(
            &direct_suback,
            .v3_1_1,
            9,
            &.{0x80},
        ),
    );
    try std.testing.expectError(error.InvalidReasonCode, SubAck.write(&suback_bytes, allocator, .v3_1_1, 9, &.{}, &.{0x83}));
    try std.testing.expectError(
        error.BufferTooShort,
        SubAck.writeNoPropertiesInto(
            direct_suback[0 .. direct_v5.len - 1],
            .v5,
            9,
            &reasons,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        SubAck.noPropertiesWireLen(.v5, 0, &reasons),
    );
    var untouched_suback: [8]u8 = @splat(0xa5);
    try std.testing.expectError(
        error.InvalidReasonCode,
        SubAck.writeNoPropertiesInto(
            &untouched_suback,
            .v5,
            1,
            &.{0x03},
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** untouched_suback.len),
        &untouched_suback,
    );
    var many_reasons: [126]u8 = @splat(0);
    const direct_large = try SubAck.writeNoPropertiesInto(
        &direct_suback,
        .v5,
        0x1234,
        &many_reasons,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x90, 0x81, 0x01, 0x12, 0x34, 0x00 },
        direct_large[0..6],
    );
    try std.testing.expectEqual(@as(usize, 132), direct_large.len);

    var invalid_suback: std.ArrayList(u8) = .empty;
    defer invalid_suback.deinit(allocator);
    try (FixedHeader{
        .packet_type = .suback,
        .flags = 0,
        .remaining_len = 3,
        .header_len = 0,
    }).write(&invalid_suback, allocator);
    try invalid_suback.appendSlice(allocator, &.{ 0x00, 0x09, 0x83 });
    try std.testing.expectError(error.InvalidReasonCode, SubAck.parse(allocator, .v3_1_1, invalid_suback.items));
}

test "MQTT unsubscribe and unsuback controls" {
    const allocator = std.testing.allocator;
    const filters = [_][]const u8{ "sensors/+", "alerts/#" };

    var unsubscribe_bytes: std.ArrayList(u8) = .empty;
    defer unsubscribe_bytes.deinit(allocator);
    try Unsubscribe.write(&unsubscribe_bytes, allocator, .v5, 11, &.{}, &filters);
    var unsubscribe = try Unsubscribe.parse(allocator, .v5, unsubscribe_bytes.items);
    defer unsubscribe.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 11), unsubscribe.packet_id);
    try std.testing.expectEqual(@as(usize, 2), unsubscribe.topic_filters.len);

    try std.testing.expectEqualStrings("sensors/+", unsubscribe.topic_filters[0]);
    try std.testing.expectEqualStrings("alerts/#", unsubscribe.topic_filters[1]);

    unsubscribe_bytes.clearRetainingCapacity();
    try Unsubscribe.write(&unsubscribe_bytes, allocator, .v3_1_1, 12, &.{}, &filters);
    unsubscribe.deinit(allocator);
    unsubscribe = try Unsubscribe.parse(allocator, .v3_1_1, unsubscribe_bytes.items);
    try std.testing.expectEqual(@as(u16, 12), unsubscribe.packet_id);
    try std.testing.expectEqual(@as(usize, 2), unsubscribe.topic_filters.len);

    var unsuback_bytes: std.ArrayList(u8) = .empty;
    defer unsuback_bytes.deinit(allocator);
    const reasons = [_]u8{ 0x00, 0x11 };
    try UnsubAck.write(&unsuback_bytes, allocator, .v5, 11, &.{}, &reasons);
    var unsuback = try UnsubAck.parse(allocator, .v5, unsuback_bytes.items);
    defer unsuback.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 11), unsuback.packet_id);
    try std.testing.expectEqualSlices(u8, &reasons, unsuback.reason_codes);
    var direct_unsuback: [256]u8 = undefined;
    const direct_v5 = try UnsubAck.writeNoPropertiesInto(
        &direct_unsuback,
        .v5,
        11,
        &reasons,
    );
    try std.testing.expectEqualSlices(u8, unsuback_bytes.items, direct_v5);
    try std.testing.expectEqual(
        direct_v5.len,
        try UnsubAck.noPropertiesWireLen(.v5, 11, &reasons),
    );

    unsuback_bytes.clearRetainingCapacity();
    try UnsubAck.write(&unsuback_bytes, allocator, .v3_1_1, 12, &.{}, &.{});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb0, 0x02, 0x00, 0x0c }, unsuback_bytes.items);
    unsuback.deinit(allocator);
    unsuback = try UnsubAck.parse(allocator, .v3_1_1, unsuback_bytes.items);
    try std.testing.expectEqual(@as(u16, 12), unsuback.packet_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, unsuback.reason_codes);

    unsuback_bytes.clearRetainingCapacity();
    try UnsubAck.write(&unsuback_bytes, allocator, .v3_1_1, 13, &.{}, &.{0x00});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb0, 0x02, 0x00, 0x0d }, unsuback_bytes.items);
    try std.testing.expectEqualSlices(
        u8,
        unsuback_bytes.items,
        try UnsubAck.writeNoPropertiesInto(
            &direct_unsuback,
            .v3_1_1,
            13,
            &.{0x00},
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        UnsubAck.noPropertiesWireLen(.v5, 1, &.{}),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        UnsubAck.writeNoPropertiesInto(
            &direct_unsuback,
            .v3_1_1,
            1,
            &.{0x11},
        ),
    );
    var untouched_unsuback: [8]u8 = @splat(0x5a);
    try std.testing.expectError(
        error.InvalidReasonCode,
        UnsubAck.writeNoPropertiesInto(
            &untouched_unsuback,
            .v5,
            1,
            &.{0x42},
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0x5a} ** untouched_unsuback.len),
        &untouched_unsuback,
    );

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(error.InvalidSubscription, Unsubscribe.write(&invalid, allocator, .v5, 1, &.{}, &[_][]const u8{}));
    try std.testing.expectError(error.InvalidSubscription, Unsubscribe.write(&invalid, allocator, .v5, 1, &.{}, &[_][]const u8{"bad/#/filter"}));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v5, 1, &.{}, &[_]u8{0x42}));
    try std.testing.expectError(error.InvalidProperty, Unsubscribe.write(&invalid, allocator, .v3_1_1, 1, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }, &filters));
    try std.testing.expectError(error.InvalidProperty, UnsubAck.write(&invalid, allocator, .v3_1_1, 1, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "v3 has no properties" } },
    }, &[_]u8{0x00}));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v3_1_1, 1, &.{}, &[_]u8{ 0x00, 0x00 }));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v3_1_1, 1, &.{}, &[_]u8{0x11}));
}

test "MQTT disconnect control" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Disconnect.write(&encoded, allocator, .v5, 0x00, &.{});
    var disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), disconnect.reason_code);
    encoded.clearRetainingCapacity();
    try Disconnect.write(&encoded, allocator, .v5, 0x8d, &.{});
    disconnect.deinit(allocator);
    disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqual(@as(u8, 0x8d), disconnect.reason_code);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe0, 0x01, 0x8d }, encoded.items);
    encoded.clearRetainingCapacity();
    try encoded.appendSlice(allocator, &.{ 0xe0, 0x01, 0x8d });
    disconnect.deinit(allocator);
    disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqual(@as(u8, 0x8d), disconnect.reason_code);
    try std.testing.expectEqual(@as(usize, 0), disconnect.properties.len);
    try std.testing.expectError(error.InvalidReasonCode, Disconnect.write(&encoded, allocator, .v5, 0x05, &.{}));
    try std.testing.expectError(error.InvalidReasonCode, Disconnect.write(&encoded, allocator, .v3_1_1, 0x8d, &.{}));
    try std.testing.expectError(error.InvalidProperty, Disconnect.write(&encoded, allocator, .v3_1_1, 0, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "v3 has no properties" } },
    }));

    var direct: [Disconnect.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xe0, 0x00 },
        try Disconnect.writeNoPropertiesInto(&direct, .v5, 0),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xe0, 0x01, 0x8d },
        try Disconnect.writeNoPropertiesInto(&direct, .v5, 0x8d),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xe0, 0x00 },
        try Disconnect.writeNoPropertiesInto(&direct, .v3_1_1, 0),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        Disconnect.writeNoPropertiesInto(&direct, .v3_1_1, 0x8d),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        Disconnect.writeNoPropertiesInto(&direct, .v5, 0x05),
    );

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try (FixedHeader{
        .packet_type = .disconnect,
        .flags = 0,
        .remaining_len = 2,
        .header_len = 0,
    }).write(&invalid, allocator);
    try invalid.appendSlice(allocator, &.{ 0x05, 0x00 });
    try std.testing.expectError(error.InvalidReasonCode, Disconnect.parse(allocator, .v5, invalid.items));

    const server_reference = [_]Property{.{ .utf8 = .{
        .id = .server_reference,
        .value = "mqtt://other.example:1883",
    } }};
    encoded.clearRetainingCapacity();
    try Disconnect.write(
        &encoded,
        allocator,
        .v5,
        0x9c,
        &server_reference,
    );
    disconnect.deinit(allocator);
    disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqualStrings(
        "mqtt://other.example:1883",
        serverReference(disconnect.properties).?,
    );
}

test "MQTT DISCONNECT reason codes enforce sender direction" {
    const both = [_]u8{
        0x00, 0x80, 0x81, 0x82, 0x83, 0x90, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
    };
    for (both) |code| {
        try validateDisconnectReasonForSender(code, .client);
        try validateDisconnectReasonForSender(code, .server);
    }

    try validateDisconnectReasonForSender(0x04, .client);
    try std.testing.expectError(
        error.InvalidReasonCode,
        validateDisconnectReasonForSender(0x04, .server),
    );

    const server_only = [_]u8{
        0x87, 0x89, 0x8b, 0x8d, 0x8e, 0x8f, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2,
    };
    for (server_only) |code| {
        try validateDisconnectReasonForSender(code, .server);
        try std.testing.expectError(
            error.InvalidReasonCode,
            validateDisconnectReasonForSender(code, .client),
        );
    }
}

test "MQTT v5 AUTH control" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "client-first" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "auth-1" } },
    });
    var auth = try Auth.parse(allocator, .v5, encoded.items);
    defer auth.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x18), auth.reason_code);
    try std.testing.expectEqual(@as(usize, 3), auth.properties.len);
    try std.testing.expectEqual(PropertyId.authentication_method, auth.properties[0].utf8.id);
    try std.testing.expectEqualStrings("SCRAM-SHA-256", auth.properties[0].utf8.value);
    try std.testing.expectEqualStrings("client-first", auth.properties[1].binary.value);

    encoded.clearRetainingCapacity();
    try Auth.write(&encoded, allocator, .v5, 0x00, &.{});
    auth.deinit(allocator);
    auth = try Auth.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqual(@as(u8, 0), auth.reason_code);
    try std.testing.expectEqual(@as(usize, 0), auth.properties.len);

    var direct: [Auth.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x00 },
        try Auth.writeNoPropertiesInto(&direct, .v5, 0),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x02, 0x18, 0x00 },
        try Auth.writeNoPropertiesInto(&direct, .v5, 0x18),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x02, 0x19, 0x00 },
        try Auth.writeNoPropertiesInto(&direct, .v5, 0x19),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        Auth.writeNoPropertiesInto(&direct, .v5, 0x01),
    );
    try std.testing.expectError(
        error.InvalidPacketType,
        Auth.writeNoPropertiesInto(&direct, .v3_1_1, 0),
    );

    // MQTT 5 AUTH packets either omit the variable header entirely (remaining
    // length 0, implicit Success/no properties) or include both a reason code
    // and the following property-length varint.  A lone reason byte would make
    // the packet ambiguous for streaming parsers, so keep it rejected like
    // mature MQTT stacks such as rumqtt do.
    try std.testing.expectError(error.BufferTooShort, Auth.parse(allocator, .v5, &.{ 0xf0, 0x01, 0x18 }));

    try std.testing.expectError(error.InvalidReasonCode, Auth.write(&encoded, allocator, .v5, 0x01, &.{}));
    try std.testing.expectError(error.InvalidPacketType, Auth.write(&encoded, allocator, .v3_1_1, 0x00, &.{}));
    try std.testing.expectError(error.InvalidProperty, Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 10 } },
    }));
}

test "MQTT AUTH reason codes enforce sender direction" {
    try validateAuthReasonForSender(0x00, .server);
    try std.testing.expectError(
        error.InvalidReasonCode,
        validateAuthReasonForSender(0x00, .client),
    );
    try validateAuthReasonForSender(0x18, .client);
    try validateAuthReasonForSender(0x18, .server);
    try validateAuthReasonForSender(0x19, .client);
    try std.testing.expectError(
        error.InvalidReasonCode,
        validateAuthReasonForSender(0x19, .server),
    );
}

test "MQTT DISCONNECT and AUTH writers reuse output capacity" {
    const allocator = std.testing.allocator;
    const disconnect_properties = [_]Property{
        .{ .utf8 = .{ .id = .reason_string, .value = "moving" } },
        .{ .utf8 = .{ .id = .server_reference, .value = "other.example" } },
    };
    const auth_properties = [_]Property{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "server-final" } },
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    try Disconnect.write(
        &output,
        allocator,
        .v5,
        0x9c,
        &disconnect_properties,
    );
    const disconnect = try allocator.dupe(u8, output.items);
    defer allocator.free(disconnect);
    output.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try Disconnect.write(
        &output,
        no_alloc.allocator(),
        .v5,
        0x9c,
        &disconnect_properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, disconnect, output.items);
    var parsed_disconnect = try Disconnect.parse(allocator, .v5, output.items);
    defer parsed_disconnect.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x9c), parsed_disconnect.reason_code);

    output.clearRetainingCapacity();
    try Auth.write(&output, allocator, .v5, 0x18, &auth_properties);
    const auth = try allocator.dupe(u8, output.items);
    defer allocator.free(auth);
    output.clearRetainingCapacity();
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try Auth.write(
        &output,
        no_alloc.allocator(),
        .v5,
        0x18,
        &auth_properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, auth, output.items);
    var parsed_auth = try Auth.parse(allocator, .v5, output.items);
    defer parsed_auth.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x18), parsed_auth.reason_code);
    try std.testing.expectEqual(@as(usize, 2), parsed_auth.properties.len);
}

test "MQTT CONNECT information preference helpers use protocol defaults" {
    try std.testing.expectEqual(
        @as(?bool, null),
        requestProblemInformation(&.{}),
    );
    try std.testing.expectEqual(
        @as(?bool, null),
        requestResponseInformation(&.{}),
    );
    try std.testing.expectEqual(
        @as(?bool, false),
        requestProblemInformation(&.{.{ .byte = .{
            .id = .request_problem_information,
            .value = 0,
        } }}),
    );
    try std.testing.expectEqual(
        @as(?bool, true),
        requestResponseInformation(&.{.{ .byte = .{
            .id = .request_response_information,
            .value = 1,
        } }}),
    );
}

test {
    _ = runtime;
    _ = reconnect;
    _ = broker;
    _ = bridge;
    _ = websocket_runtime;
    _ = tls_runtime;
    _ = router;
    _ = retained;
    _ = session;
    _ = will_scheduler;
    _ = @import("runtime/packet_transport.zig");
    _ = @import("runtime/auth.zig");
    _ = @import("runtime/auth_tests.zig");
    _ = @import("runtime/connect_timeout_tests.zig");
    _ = @import("runtime/protocol_version_tests.zig");
    _ = @import("protocol_version_codec_tests.zig");
    _ = @import("runtime/tcp_endpoint_tests.zig");
    _ = @import("runtime/ping_timeout_tests.zig");
    _ = @import("runtime/reconnect_tests.zig");
    _ = @import("runtime/reconnect_snapshot_tests.zig");
    _ = @import("bridge/outbound_coordinator.zig");
    _ = @import("runtime/reconnect_publish_attempt_tests.zig");
    _ = @import("runtime/queued_run_tests.zig");
    _ = @import("runtime/reconnect_endpoint_tests.zig");
    _ = @import("reconnect/command_queue.zig");
    _ = @import("reconnect/event_queue.zig");
    _ = @import("reconnect/delivery_queue.zig");
    _ = @import("runtime/unix_tests.zig");
    _ = @import("runtime/information_preferences_tests.zig");
    _ = @import("tls_runtime_tests.zig");
    _ = @import("websocket_runtime_tests.zig");
    _ = @import("websocket_runtime/proxy_tests.zig");
    _ = @import("runtime/websocket_unix_tests.zig");
    _ = @import("websocket_keep_alive_tests.zig");
    _ = persistence.commit_log;
    _ = redirect;
    _ = proxy_protocol;
}

const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const runtime = @import("runtime.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    MalformedRemainingLength,
    RemainingLengthTooLarge,
    InvalidPacketType,
    InvalidFlags,
    InvalidProtocolName,
    InvalidProtocolLevel,
    InvalidUtf8,
    InvalidQoS,
    InvalidProperty,
    InvalidReasonCode,
    InvalidTopic,
    InvalidSubscription,
    InvalidClientId,
    InvalidPacketIdentifier,
    IntegerOverflow,
} || std.mem.Allocator.Error;

pub const ProtocolVersion = enum(u8) {
    v3_1_1 = 4,
    v5 = 5,

    pub fn byte(self: ProtocolVersion) u8 {
        return @intFromEnum(self);
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

pub const FixedHeader = struct {
    packet_type: PacketType,
    flags: u4,
    remaining_len: usize,
    header_len: usize,

    pub fn parse(bytes: []const u8) Error!FixedHeader {
        if (bytes.len < 2) return error.BufferTooShort;
        const packet_nibble: u4 = @truncate(bytes[0] >> 4);
        if (packet_nibble == 0) return error.InvalidPacketType;
        const packet_type: PacketType = std.enums.fromInt(PacketType, packet_nibble) orelse return error.InvalidPacketType;
        const decoded = try decodeRemainingLength(bytes[1..]);
        return .{
            .packet_type = packet_type,
            .flags = @truncate(bytes[0] & 0x0f),
            .remaining_len = decoded.value,
            .header_len = 1 + decoded.len,
        };
    }

    pub fn write(self: FixedHeader, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try list.append(allocator, (@as(u8, @intFromEnum(self.packet_type)) << 4) | self.flags);
        try encodeRemainingLength(list, allocator, self.remaining_len);
    }
};

fn validateControlFlags(fixed: FixedHeader) Error!void {
    if (fixed.packet_type != .publish and fixed.flags != fixed.packet_type.defaultFlags()) return error.InvalidFlags;
}

fn validatePacketBounds(packet: []const u8, fixed: FixedHeader) Error!void {
    const total = std.math.add(usize, fixed.header_len, fixed.remaining_len) catch return error.RemainingLengthTooLarge;
    if (packet.len < total) return error.BufferTooShort;
    if (packet.len != total) return error.InvalidPacketType;
}

pub fn encodeRemainingLength(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: usize) Error!void {
    if (value > 268_435_455) return error.RemainingLengthTooLarge;
    var x = value;
    while (true) {
        var encoded: u8 = @intCast(x % 128);
        x /= 128;
        if (x > 0) encoded |= 128;
        try list.append(allocator, encoded);
        if (x == 0) break;
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
    try wire.appendInt(list, allocator, u16, @intCast(value.len), .big);
    try list.appendSlice(allocator, value);
}

pub fn readUtf8(cursor: *wire.Cursor) Error![]const u8 {
    const len = try cursor.readInt(u16, .big);
    const value = try cursor.readSlice(len);
    try validateMqttUtf8String(value);
    return value;
}

fn validateMqttUtf8String(value: []const u8) Error!void {
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
    var view = std.unicode.Utf8View.init(value) catch return error.InvalidUtf8;
    var it = view.iterator();
    while (it.nextCodepoint()) |codepoint| {
        if (codepoint == 0 or (codepoint >= 0x01 and codepoint <= 0x1f) or (codepoint >= 0x7f and codepoint <= 0x9f)) {
            return error.InvalidUtf8;
        }
    }
}

pub fn writeBinary(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    if (value.len > std.math.maxInt(u16)) return error.InvalidProperty;
    try wire.appendInt(list, allocator, u16, @intCast(value.len), .big);
    try list.appendSlice(allocator, value);
}

pub fn readBinary(cursor: *wire.Cursor) Error![]const u8 {
    const len = try cursor.readInt(u16, .big);
    return cursor.readSlice(len);
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
    return topic.len > 0 and !hasWildcards(topic);
}

pub fn validateTopicName(topic: []const u8) Error!void {
    if (!validTopicName(topic)) return error.InvalidTopic;
}

pub fn validTopicFilter(filter: []const u8) bool {
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
    if (group.len == 0 or hasWildcards(group)) return null;
    if (!validTopicFilterLevels(shared_filter)) return null;
    return shared_filter;
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
    const prop_len_decoded = try decodeRemainingLength(cursor.buf[cursor.pos..]);
    cursor.pos += prop_len_decoded.len;
    const prop_bytes = try cursor.readSlice(prop_len_decoded.value);
    var prop_cursor = wire.Cursor.init(prop_bytes);
    var props: std.ArrayList(Property) = .empty;
    errdefer props.deinit(allocator);
    while (!prop_cursor.eof()) {
        const id_byte = try prop_cursor.readByte();
        const id = std.enums.fromInt(PropertyId, id_byte) orelse return error.InvalidProperty;
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
        try validateProperty(prop);
        try validatePropertyNotDuplicate(prop, props.items);
        try props.append(allocator, prop);
    }
    return props.toOwnedSlice(allocator);
}

pub fn receiveMaximum(properties: []const Property) ?u16 {
    for (properties) |property| {
        if (property == .two_byte and property.two_byte.id == .receive_maximum) return property.two_byte.value;
    }
    return null;
}

pub fn maximumPacketSize(properties: []const Property) ?u32 {
    for (properties) |property| {
        if (property == .four_byte and property.four_byte.id == .maximum_packet_size) return property.four_byte.value;
    }
    return null;
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
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    for (properties, 0..) |property, index| {
        try validateProperty(property);
        try validatePropertyNotDuplicate(property, properties[0..index]);
        switch (property) {
            .byte => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try encoded.append(allocator, p.value);
            },
            .two_byte => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try wire.appendInt(&encoded, allocator, u16, p.value, .big);
            },
            .four_byte => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try wire.appendInt(&encoded, allocator, u32, p.value, .big);
            },
            .varint => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try encodeRemainingLength(&encoded, allocator, p.value);
            },
            .binary => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try writeBinary(&encoded, allocator, p.value);
            },
            .utf8 => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try writeUtf8(&encoded, allocator, p.value);
            },
            .utf8_pair => |p| {
                try encoded.append(allocator, @intFromEnum(p.id));
                try writeUtf8(&encoded, allocator, p.key);
                try writeUtf8(&encoded, allocator, p.value);
            },
        }
    }

    try encodeRemainingLength(list, allocator, encoded.items.len);
    try list.appendSlice(allocator, encoded.items);
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
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .connect or fixed.flags != 0) return error.InvalidFlags;
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const protocol_name = try readUtf8(&cursor);
        if (!std.mem.eql(u8, protocol_name, "MQTT")) return error.InvalidProtocolName;
        const level = try cursor.readByte();
        const protocol = std.enums.fromInt(ProtocolVersion, level) orelse return error.InvalidProtocolLevel;
        const connect_flags = try cursor.readByte();
        try validateConnectFlags(protocol, connect_flags);
        const keep_alive = try cursor.readInt(u16, .big);
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.connect, props);
        const client_id = try readUtf8(&cursor);
        var will: ?LastWill = null;
        if ((connect_flags & 0x04) != 0) {
            const will_props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
            errdefer allocator.free(will_props);
            if (protocol == .v5) try validatePropertiesFor(.will, will_props);
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
        try validateConnectClientId(client_id, clean_start);
        return .{
            .protocol = protocol,
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
    clean_start: bool = true,
    keep_alive_seconds: u16 = 30,
    properties: []const Property = &.{},
    will: ?LastWill = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

fn validateConnectFlags(protocol: ProtocolVersion, flags: u8) Error!void {
    if ((flags & 0x01) != 0) return error.InvalidFlags;

    const will_flag = (flags & 0x04) != 0;
    const will_qos = (flags >> 3) & 0x03;
    if (!will_flag and (flags & 0x38) != 0) return error.InvalidFlags;
    if (will_qos == 0x03) return error.InvalidQoS;

    if (protocol == .v3_1_1 and (flags & 0xc0) == 0x40) {
        // MQTT 3.1.1 couples the login flags: a password can only appear after
        // a username.  MQTT 5 relaxed this for enhanced-authentication use
        // cases, so keep the stricter check version-scoped instead of rejecting
        // valid v5 password-only CONNECT packets.
        return error.InvalidFlags;
    }
}

pub const ConnAck = struct {
    session_present: bool,
    reason_code: u8,
    properties: []Property = &.{},

    pub fn deinit(self: *ConnAck, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!ConnAck {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .connack) return error.InvalidPacketType;
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const ack_flags = try cursor.readByte();
        if ((ack_flags & 0xfe) != 0) return error.InvalidFlags;
        const reason_code = try cursor.readByte();
        try validateConnAckReason(protocol, reason_code);
        try validateConnAckSessionPresent((ack_flags & 0x01) != 0, reason_code);
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.connack, props);
        if (cursor.remaining() != 0) return error.InvalidPacketType;
        return .{
            .session_present = (ack_flags & 0x01) != 0,
            .reason_code = reason_code,
            .properties = props,
        };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        session_present: bool,
        reason_code: u8,
        properties: []const Property,
    ) Error!void {
        try validateConnAckReason(protocol, reason_code);
        try validateConnAckSessionPresent(session_present, reason_code);
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try variable.append(allocator, if (session_present) 0x01 else 0x00);
        try variable.append(allocator, reason_code);
        if (protocol == .v5) {
            try validatePropertiesFor(.connack, properties);
            try writeProperties(&variable, allocator, properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        }
        try (FixedHeader{ .packet_type = .connack, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
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
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const topic = try readUtf8(&cursor);
        const qos = try QoS.fromFlags(fixed.flags);
        const packet_id = if (qos == .at_most_once) null else blk: {
            const id = try cursor.readInt(u16, .big);
            if (id == 0) return error.InvalidPacketIdentifier;
            break :blk id;
        };
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.publish, props);
        if (topic.len == 0) {
            if (protocol != .v5 or topicAlias(props) == null) return error.InvalidTopic;
        } else try validateTopicName(topic);
        const payload = cursor.buf[cursor.pos..];
        try validatePayloadFormat(props, payload);
        return .{
            .dup = (fixed.flags & 0x08) != 0,
            .qos = qos,
            .retain = (fixed.flags & 0x01) != 0,
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
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (protocol == .v3_1_1) {
            if (!cursor.eof()) return error.InvalidPacketType;
            return .{ .packet_type = fixed.packet_type, .packet_id = packet_id, .properties = try allocator.alloc(Property, 0) };
        }

        var reason_code: u8 = 0;
        if (!cursor.eof()) reason_code = try cursor.readByte();
        try validateAckReasonCode(fixed.packet_type, reason_code);
        const props = if (!cursor.eof()) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        try validateAckProperties(fixed.packet_type, props);
        if (!cursor.eof()) return error.InvalidPacketType;
        return .{ .packet_type = fixed.packet_type, .packet_id = packet_id, .reason_code = reason_code, .properties = props };
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
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        switch (packet_type) {
            .puback, .pubrec, .pubrel, .pubcomp => {},
            else => return error.InvalidPacketType,
        }
        if (protocol == .v3_1_1) {
            if (reason_code != 0) return error.InvalidReasonCode;
            if (properties.len != 0) return error.InvalidProperty;
        } else {
            try validateAckReasonCode(packet_type, reason_code);
            try validateAckProperties(packet_type, properties);
        }
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5 and properties.len != 0) {
            try variable.append(allocator, reason_code);
            try writeProperties(&variable, allocator, properties);
        } else if (protocol == .v5 and reason_code != 0) {
            // MQTT 5 lets PUBACK/PUBREC/PUBREL/PUBCOMP omit Property Length
            // when no properties are present.  Emit the shorter reason-only
            // form used by rumqtt instead of appending a redundant zero-length
            // property section.
            try variable.append(allocator, reason_code);
        }
        try (FixedHeader{ .packet_type = packet_type, .flags = packet_type.defaultFlags(), .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
    }

    pub fn accepted(self: AckPacket) bool {
        return self.reason_code < 0x80;
    }
};

fn validateAckReasonCode(packet_type: PacketType, reason_code: u8) Error!void {
    switch (packet_type) {
        .puback, .pubrec => switch (reason_code) {
            0x00, // Success.
            0x10, // No matching subscribers.
            0x80, // Unspecified error.
            0x83, // Implementation specific error.
            0x87, // Not authorized.
            0x90, // Topic Name invalid.
            0x91, // Packet Identifier in use.
            0x97, // Quota exceeded.
            0x99, // Payload format invalid.
            => {},
            else => return error.InvalidReasonCode,
        },
        .pubrel, .pubcomp => switch (reason_code) {
            0x00, // Success.
            0x92, // Packet Identifier not found.
            => {},
            else => return error.InvalidReasonCode,
        },
        else => return error.InvalidPacketType,
    }
}

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
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.subscribe, props);

        var subs: std.ArrayList(Subscription) = .empty;
        errdefer subs.deinit(allocator);
        while (!cursor.eof()) {
            const topic_filter = try readUtf8(&cursor);
            try validateTopicFilter(topic_filter);
            const options = try cursor.readByte();
            try validateSubscriptionOptions(protocol, options);
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
        return .{ .packet_id = packet_id, .properties = props, .subscriptions = try subs.toOwnedSlice(allocator) };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_id: u16,
        properties: []const Property,
        subscriptions: []const Subscription,
    ) Error!void {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (subscriptions.len == 0) return error.InvalidSubscription;
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5) {
            try validatePropertiesFor(.subscribe, properties);
            try writeProperties(&variable, allocator, properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        }
        for (subscriptions) |subscription| {
            try validateTopicFilter(subscription.topic_filter);
            try writeUtf8(&variable, allocator, subscription.topic_filter);
            const options: u8 = @intFromEnum(subscription.qos) |
                (if (subscription.no_local) @as(u8, 0x04) else 0) |
                (if (subscription.retain_as_published) @as(u8, 0x08) else 0) |
                (@as(u8, subscription.retain_handling) << 4);
            try validateSubscriptionOptions(protocol, options);
            try validateSharedSubscriptionOptions(protocol, subscription.topic_filter, options);
            try variable.append(allocator, options);
        }
        try (FixedHeader{ .packet_type = .subscribe, .flags = PacketType.subscribe.defaultFlags(), .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
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
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.suback, props);
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
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (reason_codes.len == 0) return error.InvalidReasonCode;
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5) {
            try validatePropertiesFor(.suback, properties);
            try writeProperties(&variable, allocator, properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        }
        for (reason_codes) |code| {
            try validateSubAckReason(protocol, code);
            try variable.append(allocator, code);
        }
        try (FixedHeader{ .packet_type = .suback, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
    }
};

pub const Unsubscribe = struct {
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
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.unsubscribe, props);

        var filters: std.ArrayList([]const u8) = .empty;
        errdefer filters.deinit(allocator);
        while (!cursor.eof()) {
            const filter = try readUtf8(&cursor);
            try validateTopicFilter(filter);
            try filters.append(allocator, filter);
        }
        if (filters.items.len == 0) return error.InvalidSubscription;
        return .{ .packet_id = packet_id, .properties = props, .topic_filters = try filters.toOwnedSlice(allocator) };
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: ProtocolVersion,
        packet_id: u16,
        properties: []const Property,
        topic_filters: []const []const u8,
    ) Error!void {
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (topic_filters.len == 0) return error.InvalidSubscription;
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5) {
            try validatePropertiesFor(.unsubscribe, properties);
            try writeProperties(&variable, allocator, properties);
        } else if (properties.len != 0) {
            return error.InvalidProperty;
        }
        for (topic_filters) |filter| {
            try validateTopicFilter(filter);
            try writeUtf8(&variable, allocator, filter);
        }
        try (FixedHeader{ .packet_type = .unsubscribe, .flags = PacketType.unsubscribe.defaultFlags(), .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
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
        if (protocol == .v3_1_1) {
            if (!cursor.eof()) return error.InvalidPacketType;
            return .{
                .packet_id = packet_id,
                .properties = try allocator.alloc(Property, 0),
                .reason_codes = try allocator.dupe(u8, &[_]u8{0x00}),
            };
        }
        const props = try parseProperties(allocator, &cursor);
        errdefer allocator.free(props);
        try validatePropertiesFor(.ack, props);
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
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5) {
            if (reason_codes.len == 0) return error.InvalidReasonCode;
            try validatePropertiesFor(.ack, properties);
            try writeProperties(&variable, allocator, properties);
            for (reason_codes) |code| {
                try validateUnsubAckReason(code);
                try variable.append(allocator, code);
            }
        } else {
            if (properties.len != 0) return error.InvalidProperty;
            if (reason_codes.len > 1) return error.InvalidReasonCode;
            if (reason_codes.len == 1 and reason_codes[0] != 0x00) return error.InvalidReasonCode;
        }
        try (FixedHeader{ .packet_type = .unsuback, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
    }
};

pub const Disconnect = struct {
    reason_code: u8 = 0,
    properties: []Property = &.{},

    pub fn deinit(self: *Disconnect, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
        self.* = undefined;
    }

    pub fn parse(allocator: std.mem.Allocator, protocol: ProtocolVersion, packet: []const u8) Error!Disconnect {
        const fixed = try FixedHeader.parse(packet);
        if (fixed.packet_type != .disconnect) return error.InvalidPacketType;
        try validateControlFlags(fixed);
        try validatePacketBounds(packet, fixed);
        if (protocol == .v3_1_1 and fixed.remaining_len != 0) return error.InvalidPacketType;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const reason_code = if (!cursor.eof()) try cursor.readByte() else 0;
        if (protocol == .v5) try validateDisconnectReason(reason_code);
        const props = if (protocol == .v5 and !cursor.eof()) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        if (protocol == .v5) try validatePropertiesFor(.disconnect, props);
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
        if (protocol == .v3_1_1) {
            if (reason_code != 0) return error.InvalidReasonCode;
            if (properties.len != 0) return error.InvalidProperty;
        } else try validateDisconnectReason(reason_code);
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        if (protocol == .v5 and reason_code != 0 and properties.len == 0) {
            try variable.append(allocator, reason_code);
        } else if (protocol == .v5 and (reason_code != 0 or properties.len != 0)) {
            try variable.append(allocator, reason_code);
            try validatePropertiesFor(.disconnect, properties);
            try writeProperties(&variable, allocator, properties);
        }
        try (FixedHeader{ .packet_type = .disconnect, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
    }
};

pub const Auth = struct {
    reason_code: u8 = 0,
    properties: []Property = &.{},

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
        const props = try parseProperties(allocator, &cursor);
        errdefer allocator.free(props);
        try validateAuthProperties(props);
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
        if (protocol != .v5) return error.InvalidPacketType;
        try validateAuthReason(reason_code);
        try validateAuthProperties(properties);

        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        if (reason_code != 0 or properties.len != 0) {
            try variable.append(allocator, reason_code);
            try writeProperties(&variable, allocator, properties);
        }
        try (FixedHeader{ .packet_type = .auth, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
    }
};

fn validateConnAckSessionPresent(session_present: bool, reason_code: u8) Error!void {
    // MQTT 3.1.1/5 both require Session Present to be 0 when the connection is
    // refused.  Accepting `session_present=true` on failures lets clients
    // mistakenly resume state after a rejected CONNECT.
    if (session_present and reason_code != 0) return error.InvalidFlags;
}

fn validateSubscriptionOptions(protocol: ProtocolVersion, options: u8) Error!void {
    if ((options & 0xc0) != 0) return error.InvalidSubscription;
    const qos_bits: u2 = @truncate(options & 0x03);
    if (qos_bits == 3) return error.InvalidQoS;
    switch (protocol) {
        .v3_1_1 => {
            // MQTT 3.1.1 SUBSCRIBE options only carry the requested QoS in
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
        .v3_1_1 => switch (code) {
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
        .v3_1_1 => switch (code) {
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

fn validateAuthReason(code: u8) Error!void {
    switch (code) {
        0x00, 0x18, 0x19 => {},
        else => return error.InvalidReasonCode,
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

pub fn writePing(list: *std.ArrayList(u8), allocator: std.mem.Allocator, response: bool) Error!void {
    const packet_type: PacketType = if (response) .pingresp else .pingreq;
    try (FixedHeader{ .packet_type = packet_type, .flags = 0, .remaining_len = 0, .header_len = 0 }).write(list, allocator);
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
    try validateConnectClientId(options.client_id, options.clean_start);
    const flags = connectFlags(options);
    try validateConnectFlags(protocol, flags);

    var variable: std.ArrayList(u8) = .empty;
    defer variable.deinit(allocator);
    try writeUtf8(&variable, allocator, "MQTT");
    try variable.append(allocator, protocol.byte());
    try variable.append(allocator, flags);
    try wire.appendInt(&variable, allocator, u16, options.keep_alive_seconds, .big);
    if (protocol == .v5) {
        try validatePropertiesFor(.connect, options.properties);
        try writeProperties(&variable, allocator, options.properties);
    } else if (options.properties.len != 0) {
        return error.InvalidProperty;
    }
    try writeUtf8(&variable, allocator, options.client_id);
    if (options.will) |will| {
        try validateTopicName(will.topic);
        if (protocol == .v5) {
            try validatePropertiesFor(.will, will.properties);
            try validatePayloadFormat(will.properties, will.payload);
            try writeProperties(&variable, allocator, will.properties);
        } else if (will.properties.len != 0) {
            return error.InvalidProperty;
        }
        try writeUtf8(&variable, allocator, will.topic);
        try writeBinary(&variable, allocator, will.payload);
    }
    if (options.username) |username| try writeUtf8(&variable, allocator, username);
    if (options.password) |password| try writeBinary(&variable, allocator, password);
    try (FixedHeader{ .packet_type = .connect, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
    try list.appendSlice(allocator, variable.items);
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

fn validateConnectClientId(client_id: []const u8, clean_start: bool) Error!void {
    // MQTT 3.1.1 and MQTT 5 allow a Server to assign a Client Identifier when
    // the CONNECT packet carries an empty Client ID, but only for a clean
    // session/start.  Persistent sessions need a stable identifier to resume;
    // rumqtt rejects this combination before constructing connection state.
    if (client_id.len == 0 and !clean_start) return error.InvalidClientId;
}

pub fn writePublish(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: struct { qos: QoS = .at_most_once, retain: bool = false, dup: bool = false, packet_id: ?u16 = null, properties: []const Property = &.{} },
) !void {
    if (topic.len == 0) {
        if (protocol != .v5 or topicAlias(options.properties) == null) return error.InvalidTopic;
    } else try validateTopicName(topic);
    if (protocol == .v5) {
        try validatePayloadFormat(options.properties, payload);
    } else if (options.properties.len != 0) {
        return error.InvalidProperty;
    }
    if (options.qos == .at_most_once) {
        if (options.packet_id != null) return error.InvalidPacketIdentifier;
    } else if (options.packet_id == null or options.packet_id.? == 0) {
        // Like rumqtt and the MQTT spec, QoS 1/2 PUBLISH packets must carry a
        // non-zero Packet Identifier.  Do not synthesize one in the stateless
        // writer: runtime connections own packet-id allocation and can avoid
        // collisions with their in-flight window.
        return error.InvalidPacketIdentifier;
    }
    var variable: std.ArrayList(u8) = .empty;
    defer variable.deinit(allocator);
    try writeUtf8(&variable, allocator, topic);
    if (options.qos != .at_most_once) try wire.appendInt(&variable, allocator, u16, options.packet_id.?, .big);
    if (protocol == .v5) {
        try validatePropertiesFor(.publish, options.properties);
        try writeProperties(&variable, allocator, options.properties);
    }
    try variable.appendSlice(allocator, payload);

    const flags: u4 = (if (options.dup) @as(u4, 0x8) else 0) |
        (@as(u4, @intFromEnum(options.qos)) << 1) |
        (if (options.retain) @as(u4, 0x1) else 0);
    try (FixedHeader{ .packet_type = .publish, .flags = flags, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
    try list.appendSlice(allocator, variable.items);
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

test "MQTT UTF-8 strings reject NUL" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidUtf8, writeUtf8(&out, std.testing.allocator, "bad\x00topic"));

    var raw = [_]u8{ 0, 5, 'h', 'e', 0, 'l', 'o' };
    var cursor = wire.Cursor.init(&raw);
    try std.testing.expectError(error.InvalidUtf8, readUtf8(&cursor));

    try std.testing.expectError(error.InvalidUtf8, writeUtf8(&out, std.testing.allocator, "bad\x1ftopic"));
    var del = [_]u8{ 0, 3, 'b', 0x7f, 'd' };
    cursor = wire.Cursor.init(&del);
    try std.testing.expectError(error.InvalidUtf8, readUtf8(&cursor));
}

test "MQTT ping packets reject trailing bytes" {
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(std.testing.allocator);
    try writePing(&ping, std.testing.allocator, false);
    try validatePing(ping.items, false);
    try ping.append(std.testing.allocator, 0);
    try std.testing.expectError(error.InvalidPacketType, validatePing(ping.items, false));
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
    try std.testing.expectError(error.InvalidClientId, writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "",
        .clean_start = false,
    }));

    var persistent_empty_id: std.ArrayList(u8) = .empty;
    defer persistent_empty_id.deinit(allocator);
    var persistent_variable: std.ArrayList(u8) = .empty;
    defer persistent_variable.deinit(allocator);
    try writeUtf8(&persistent_variable, allocator, "MQTT");
    try persistent_variable.append(allocator, ProtocolVersion.v5.byte());
    try persistent_variable.append(allocator, 0x00); // Clean Start false with an empty Client ID.
    try wire.appendInt(&persistent_variable, allocator, u16, 30, .big);
    try writeProperties(&persistent_variable, allocator, &.{});
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
    var trailing_publish = try publish_bytes.clone(allocator);
    defer trailing_publish.deinit(allocator);
    try trailing_publish.append(allocator, 0);
    try std.testing.expectError(error.InvalidPacketType, Publish.parse(allocator, .v5, trailing_publish.items));

    defer publish.deinit(allocator);
    try std.testing.expectEqual(QoS.at_least_once, publish.qos);
    try std.testing.expectEqual(@as(u16, 7), publish.packet_id.?);
    try std.testing.expectEqualStrings("21.5", publish.payload);
    try std.testing.expectEqual(@as(?u16, 2), topicAlias(publish.properties));
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
    try std.testing.expectError(error.InvalidProperty, Connect.parse(allocator, invalid_connect.items));

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
    try std.testing.expectError(error.InvalidProperty, SubAck.parse(allocator, .v5, invalid_suback.items));

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

test "MQTT topic validation and filter matching" {
    try std.testing.expect(validTopicName("sensors/temp"));
    try std.testing.expect(!validTopicName(""));
    try std.testing.expect(!validTopicName("wrong/#/path"));
    try std.testing.expect(!validTopicName("w/r/o/n/g+"));

    try std.testing.expect(validTopicFilter("correct/filter/#"));
    try std.testing.expect(validTopicFilter("cor/+/rect/+"));
    try std.testing.expect(!validTopicFilter(""));
    try std.testing.expect(!validTopicFilter("wrong/#/filter"));
    try std.testing.expect(!validTopicFilter("wrong/wr#ng/filter"));
    try std.testing.expect(!validTopicFilter("wr/+o+/ng"));
    try std.testing.expect(validTopicFilter("$share/group/sensors/+/temp"));
    try std.testing.expect(validTopicFilter("$share/group/#"));
    try std.testing.expect(!validTopicFilter("$share/group"));
    try std.testing.expect(!validTopicFilter("$share//sensors/temp"));
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
    try std.testing.expectError(error.InvalidSubscription, Subscribe.parse(allocator, .v3_1_1, invalid_v3_options.items));

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

    suback_bytes.clearRetainingCapacity();
    try SubAck.write(&suback_bytes, allocator, .v3_1_1, 9, &.{}, &.{0x80});
    suback.deinit(allocator);
    suback = try SubAck.parse(allocator, .v3_1_1, suback_bytes.items);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, suback.reason_codes);
    try std.testing.expectError(error.InvalidReasonCode, SubAck.write(&suback_bytes, allocator, .v3_1_1, 9, &.{}, &.{0x83}));

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

test {
    _ = runtime;
}

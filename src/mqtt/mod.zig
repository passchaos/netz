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
        if ((byte & 128) == 0) return .{ .value = value, .len = i + 1 };
        multiplier *= 128;
        if (multiplier > 128 * 128 * 128) return error.MalformedRemainingLength;
    }
    return error.BufferTooShort;
}

pub fn writeUtf8(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    if (value.len > std.math.maxInt(u16)) return error.InvalidUtf8;
    try wire.appendInt(list, allocator, u16, @intCast(value.len), .big);
    try list.appendSlice(allocator, value);
}

pub fn readUtf8(cursor: *wire.Cursor) Error![]const u8 {
    const len = try cursor.readInt(u16, .big);
    const value = try cursor.readSlice(len);
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
    return value;
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
    // MQTT reserves `$` topics from being matched by a leading wildcard.  A
    // filter that explicitly starts with `$` still matches normally.
    if (std.mem.startsWith(u8, topic, "$") and !std.mem.startsWith(u8, filter, "$")) return false;

    var topic_levels = std.mem.splitScalar(u8, topic, '/');
    var filter_levels = std.mem.splitScalar(u8, filter, '/');
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
        const prop = switch (id) {
            .payload_format_indicator,
            .request_problem_information,
            .request_response_information,
            .maximum_qos,
            .retain_available,
            .wildcard_subscription_available,
            .subscription_identifier_available,
            .shared_subscription_available,
            => Property{ .byte = .{ .id = id, .value = try prop_cursor.readByte() } },

            .server_keep_alive,
            .receive_maximum,
            .topic_alias_maximum,
            .topic_alias,
            => Property{ .two_byte = .{ .id = id, .value = try prop_cursor.readInt(u16, .big) } },

            .message_expiry_interval,
            .session_expiry_interval,
            .will_delay_interval,
            .maximum_packet_size,
            => Property{ .four_byte = .{ .id = id, .value = try prop_cursor.readInt(u32, .big) } },

            .subscription_identifier,
            => blk: {
                const decoded = try decodeRemainingLength(prop_cursor.buf[prop_cursor.pos..]);
                prop_cursor.pos += decoded.len;
                break :blk Property{ .varint = .{ .id = id, .value = decoded.value } };
            },

            .correlation_data,
            .authentication_data,
            => blk: {
                const len = try prop_cursor.readInt(u16, .big);
                break :blk Property{ .binary = .{ .id = id, .value = try prop_cursor.readSlice(len) } };
            },

            .content_type,
            .response_topic,
            .assigned_client_identifier,
            .authentication_method,
            .response_information,
            .server_reference,
            .reason_string,
            => Property{ .utf8 = .{ .id = id, .value = try readUtf8(&prop_cursor) } },

            .user_property,
            => Property{ .utf8_pair = .{ .id = id, .key = try readUtf8(&prop_cursor), .value = try readUtf8(&prop_cursor) } },
        };
        try props.append(allocator, prop);
    }
    return props.toOwnedSlice(allocator);
}

pub fn writeProperties(list: *std.ArrayList(u8), allocator: std.mem.Allocator, properties: []const Property) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    for (properties) |property| {
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const protocol_name = try readUtf8(&cursor);
        if (!std.mem.eql(u8, protocol_name, "MQTT")) return error.InvalidProtocolName;
        const level = try cursor.readByte();
        const protocol = std.enums.fromInt(ProtocolVersion, level) orelse return error.InvalidProtocolLevel;
        const connect_flags = try cursor.readByte();
        try validateConnectFlags(connect_flags);
        const keep_alive = try cursor.readInt(u16, .big);
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        const client_id = try readUtf8(&cursor);
        var will: ?LastWill = null;
        if ((connect_flags & 0x04) != 0) {
            const will_props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
            errdefer allocator.free(will_props);
            const topic = try readUtf8(&cursor);
            try validateTopicName(topic);
            const payload = try readBinary(&cursor);
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
        return .{
            .protocol = protocol,
            .clean_start = (connect_flags & 0x02) != 0,
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

fn validateConnectFlags(flags: u8) Error!void {
    if ((flags & 0x01) != 0) return error.InvalidFlags;

    const will_flag = (flags & 0x04) != 0;
    const will_qos = (flags >> 3) & 0x03;
    if (!will_flag and (flags & 0x38) != 0) return error.InvalidFlags;
    if (will_qos == 0x03) return error.InvalidQoS;
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const ack_flags = try cursor.readByte();
        if ((ack_flags & 0xfe) != 0) return error.InvalidFlags;
        const reason_code = try cursor.readByte();
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
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
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try variable.append(allocator, if (session_present) 0x01 else 0x00);
        try variable.append(allocator, reason_code);
        if (protocol == .v5) try writeProperties(&variable, allocator, properties);
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const topic = try readUtf8(&cursor);
        try validateTopicName(topic);
        const qos = try QoS.fromFlags(fixed.flags);
        const packet_id = if (qos == .at_most_once) null else try cursor.readInt(u16, .big);
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        return .{
            .dup = (fixed.flags & 0x08) != 0,
            .qos = qos,
            .retain = (fixed.flags & 0x01) != 0,
            .topic = topic,
            .packet_id = packet_id,
            .properties = props,
            .payload = cursor.buf[cursor.pos..],
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
            .puback, .pubrec, .pubrel, .pubcomp, .unsuback => {},
            else => return error.InvalidPacketType,
        }
        try validateControlFlags(fixed);
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        if (protocol == .v3_1_1) {
            if (!cursor.eof()) return error.InvalidPacketType;
            return .{ .packet_type = fixed.packet_type, .packet_id = packet_id, .properties = try allocator.alloc(Property, 0) };
        }

        var reason_code: u8 = 0;
        if (!cursor.eof()) reason_code = try cursor.readByte();
        const props = if (!cursor.eof()) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
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
            .puback, .pubrec, .pubrel, .pubcomp, .unsuback => {},
            else => return error.InvalidPacketType,
        }
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5 and (reason_code != 0 or properties.len != 0)) {
            try variable.append(allocator, reason_code);
            try writeProperties(&variable, allocator, properties);
        }
        try (FixedHeader{ .packet_type = packet_type, .flags = packet_type.defaultFlags(), .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
        try list.appendSlice(allocator, variable.items);
    }
};

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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);

        var subs: std.ArrayList(Subscription) = .empty;
        errdefer subs.deinit(allocator);
        while (!cursor.eof()) {
            const topic_filter = try readUtf8(&cursor);
            try validateTopicFilter(topic_filter);
            const options = try cursor.readByte();
            try validateSubscriptionOptions(options);
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
        if (protocol == .v5) try writeProperties(&variable, allocator, properties);
        for (subscriptions) |subscription| {
            try validateTopicFilter(subscription.topic_filter);
            if (subscription.retain_handling == 3) return error.InvalidSubscription;
            try writeUtf8(&variable, allocator, subscription.topic_filter);
            const options: u8 = @intFromEnum(subscription.qos) |
                (if (subscription.no_local) @as(u8, 0x04) else 0) |
                (if (subscription.retain_as_published) @as(u8, 0x08) else 0) |
                (@as(u8, subscription.retain_handling) << 4);
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        const reason_codes = try allocator.dupe(u8, cursor.buf[cursor.pos..]);
        errdefer allocator.free(reason_codes);
        for (reason_codes) |code| try validateSubAckReason(code);
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
        if (protocol == .v5) try writeProperties(&variable, allocator, properties);
        for (reason_codes) |code| {
            try validateSubAckReason(code);
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const packet_id = try cursor.readInt(u16, .big);
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);

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
        if (protocol == .v5) try writeProperties(&variable, allocator, properties);
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
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
        if (reason_codes.len == 0) return error.InvalidReasonCode;
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        try wire.appendInt(&variable, allocator, u16, packet_id, .big);
        if (protocol == .v5) {
            try writeProperties(&variable, allocator, properties);
            for (reason_codes) |code| {
                try validateUnsubAckReason(code);
                try variable.append(allocator, code);
            }
        } else if (reason_codes.len != 1 or reason_codes[0] != 0x00) {
            return error.InvalidReasonCode;
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;
        if (protocol == .v3_1_1 and fixed.remaining_len != 0) return error.InvalidPacketType;
        var cursor = wire.Cursor.init(packet[fixed.header_len .. fixed.header_len + fixed.remaining_len]);
        const reason_code = if (!cursor.eof()) try cursor.readByte() else 0;
        const props = if (protocol == .v5 and !cursor.eof()) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
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
        var variable: std.ArrayList(u8) = .empty;
        defer variable.deinit(allocator);
        if (protocol == .v5 and (reason_code != 0 or properties.len != 0)) {
            try variable.append(allocator, reason_code);
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
        if (packet.len < fixed.header_len + fixed.remaining_len) return error.BufferTooShort;

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

fn validateSubscriptionOptions(options: u8) Error!void {
    if ((options & 0xc0) != 0) return error.InvalidSubscription;
    const qos_bits: u2 = @truncate(options & 0x03);
    if (qos_bits == 3) return error.InvalidQoS;
    if (((options >> 4) & 0x03) == 3) return error.InvalidSubscription;
}

fn validateSubAckReason(code: u8) Error!void {
    switch (code) {
        0x00, 0x01, 0x02, 0x80, 0x83, 0x87, 0x8f, 0x91, 0x97, 0x9e, 0xa1, 0xa2 => {},
        else => return error.InvalidReasonCode,
    }
}

fn validateUnsubAckReason(code: u8) Error!void {
    switch (code) {
        0x00, 0x11, 0x80, 0x83, 0x87, 0x8f, 0x91 => {},
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
    for (properties) |property| {
        const id = propertyId(property);
        switch (id) {
            .authentication_method,
            .authentication_data,
            .reason_string,
            .user_property,
            => {},
            else => return error.InvalidProperty,
        }
    }
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
    if (fixed.remaining_len != 0 or packet.len < fixed.header_len) return error.InvalidPacketType;
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
    var variable: std.ArrayList(u8) = .empty;
    defer variable.deinit(allocator);
    try writeUtf8(&variable, allocator, "MQTT");
    try variable.append(allocator, protocol.byte());
    try variable.append(allocator, connectFlags(options));
    try wire.appendInt(&variable, allocator, u16, options.keep_alive_seconds, .big);
    if (protocol == .v5) try writeProperties(&variable, allocator, options.properties);
    try writeUtf8(&variable, allocator, options.client_id);
    if (options.will) |will| {
        try validateTopicName(will.topic);
        if (protocol == .v5) try writeProperties(&variable, allocator, will.properties);
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

pub fn writePublish(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: struct { qos: QoS = .at_most_once, retain: bool = false, dup: bool = false, packet_id: ?u16 = null },
) !void {
    try validateTopicName(topic);
    var variable: std.ArrayList(u8) = .empty;
    defer variable.deinit(allocator);
    try writeUtf8(&variable, allocator, topic);
    if (options.qos != .at_most_once) try wire.appendInt(&variable, allocator, u16, options.packet_id orelse 1, .big);
    if (protocol == .v5) try encodeRemainingLength(&variable, allocator, 0);
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
    }
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
    try std.testing.expectEqualStrings("status/client-1", connect.will.?.topic);
    try std.testing.expectEqualStrings("offline", connect.will.?.payload);
    try std.testing.expectEqual(QoS.at_least_once, connect.will.?.qos);
    try std.testing.expectEqual(@as(u32, 5), connect.will.?.properties[0].four_byte.value);
    try std.testing.expectEqualStrings("rumq", connect.username.?);
    try std.testing.expectEqualStrings("mq", connect.password.?);

    var publish_bytes: std.ArrayList(u8) = .empty;
    defer publish_bytes.deinit(allocator);
    try writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "21.5", .{ .qos = .at_least_once, .packet_id = 7 });
    var publish = try Publish.parse(allocator, .v5, publish_bytes.items);
    defer publish.deinit(allocator);
    try std.testing.expectEqual(QoS.at_least_once, publish.qos);
    try std.testing.expectEqual(@as(u16, 7), publish.packet_id.?);
    try std.testing.expectEqualStrings("21.5", publish.payload);
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

    try std.testing.expect(topicMatchesFilter("a/b/c", "a/b/c"));
    try std.testing.expect(topicMatchesFilter("a/b/c/d/e", "a/+/c/+/e"));
    try std.testing.expect(topicMatchesFilter("a/b/c/d/e/f", "a/b/c/#"));
    try std.testing.expect(!topicMatchesFilter("a/b", "a/b/+"));
    try std.testing.expect(!topicMatchesFilter("$system/metrics", "+/+"));
    try std.testing.expect(topicMatchesFilter("$system/metrics", "$system/+"));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidTopic, writePublish(&encoded, std.testing.allocator, .v5, "bad/#", "payload", .{}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&encoded, std.testing.allocator, .v5, 1, &.{}, &[_]Subscription{.{ .topic_filter = "bad/#/filter" }}));
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

    var puback_bytes: std.ArrayList(u8) = .empty;
    defer puback_bytes.deinit(allocator);
    try AckPacket.write(&puback_bytes, allocator, .v5, .puback, 42, 0x10, &.{});
    var puback = try AckPacket.parse(allocator, .v5, puback_bytes.items);
    defer puback.deinit(allocator);
    try std.testing.expectEqual(PacketType.puback, puback.packet_type);
    try std.testing.expectEqual(@as(u16, 42), puback.packet_id);
    try std.testing.expectEqual(@as(u8, 0x10), puback.reason_code);

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

    var suback_bytes: std.ArrayList(u8) = .empty;
    defer suback_bytes.deinit(allocator);
    const reasons = [_]u8{ 0x01, 0x00 };
    try SubAck.write(&suback_bytes, allocator, .v5, 9, &.{}, &reasons);
    var suback = try SubAck.parse(allocator, .v5, suback_bytes.items);
    defer suback.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 9), suback.packet_id);
    try std.testing.expectEqualSlices(u8, &reasons, suback.reason_codes);
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

    var unsuback_bytes: std.ArrayList(u8) = .empty;
    defer unsuback_bytes.deinit(allocator);
    const reasons = [_]u8{ 0x00, 0x11 };
    try UnsubAck.write(&unsuback_bytes, allocator, .v5, 11, &.{}, &reasons);
    var unsuback = try UnsubAck.parse(allocator, .v5, unsuback_bytes.items);
    defer unsuback.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 11), unsuback.packet_id);
    try std.testing.expectEqualSlices(u8, &reasons, unsuback.reason_codes);

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(error.InvalidSubscription, Unsubscribe.write(&invalid, allocator, .v5, 1, &.{}, &[_][]const u8{}));
    try std.testing.expectError(error.InvalidSubscription, Unsubscribe.write(&invalid, allocator, .v5, 1, &.{}, &[_][]const u8{"bad/#/filter"}));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v5, 1, &.{}, &[_]u8{0x42}));
}

test "MQTT disconnect control" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Disconnect.write(&encoded, allocator, .v5, 0x00, &.{});
    var disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), disconnect.reason_code);
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

    try std.testing.expectError(error.InvalidReasonCode, Auth.write(&encoded, allocator, .v5, 0x01, &.{}));
    try std.testing.expectError(error.InvalidPacketType, Auth.write(&encoded, allocator, .v3_1_1, 0x00, &.{}));
    try std.testing.expectError(error.InvalidProperty, Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 10 } },
    }));
}

test {
    _ = runtime;
}

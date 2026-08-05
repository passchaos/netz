const std = @import("std");
const wire = @import("../internal/wire.zig");

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

pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,

    pub fn fromFlags(flags: u4) Error!QoS {
        const bits: u2 = @truncate((flags >> 1) & 0x03);
        return std.enums.fromInt(QoS, bits) orelse error.InvalidQoS;
    }
};

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

pub const Connect = struct {
    protocol: ProtocolVersion,
    clean_start: bool,
    keep_alive_seconds: u16,
    client_id: []const u8,
    properties: []Property = &.{},

    pub fn deinit(self: *Connect, allocator: std.mem.Allocator) void {
        allocator.free(self.properties);
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
        const keep_alive = try cursor.readInt(u16, .big);
        const props = if (protocol == .v5) try parseProperties(allocator, &cursor) else try allocator.alloc(Property, 0);
        errdefer allocator.free(props);
        const client_id = try readUtf8(&cursor);
        return .{
            .protocol = protocol,
            .clean_start = (connect_flags & 0x02) != 0,
            .keep_alive_seconds = keep_alive,
            .client_id = client_id,
            .properties = props,
        };
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

pub fn writeConnect(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    client_id: []const u8,
    clean_start: bool,
    keep_alive_seconds: u16,
) !void {
    var variable: std.ArrayList(u8) = .empty;
    defer variable.deinit(allocator);
    try writeUtf8(&variable, allocator, "MQTT");
    try variable.append(allocator, protocol.byte());
    try variable.append(allocator, if (clean_start) 0x02 else 0x00);
    try wire.appendInt(&variable, allocator, u16, keep_alive_seconds, .big);
    if (protocol == .v5) try encodeRemainingLength(&variable, allocator, 0);
    try writeUtf8(&variable, allocator, client_id);
    try (FixedHeader{ .packet_type = .connect, .flags = 0, .remaining_len = variable.items.len, .header_len = 0 }).write(list, allocator);
    try list.appendSlice(allocator, variable.items);
}

pub fn writePublish(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: struct { qos: QoS = .at_most_once, retain: bool = false, dup: bool = false, packet_id: ?u16 = null },
) !void {
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
    try writeConnect(&connect_bytes, allocator, .v5, "client-1", true, 30);
    var connect = try Connect.parse(allocator, connect_bytes.items);
    defer connect.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v5, connect.protocol);
    try std.testing.expect(connect.clean_start);
    try std.testing.expectEqualStrings("client-1", connect.client_id);

    var publish_bytes: std.ArrayList(u8) = .empty;
    defer publish_bytes.deinit(allocator);
    try writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "21.5", .{ .qos = .at_least_once, .packet_id = 7 });
    var publish = try Publish.parse(allocator, .v5, publish_bytes.items);
    defer publish.deinit(allocator);
    try std.testing.expectEqual(QoS.at_least_once, publish.qos);
    try std.testing.expectEqual(@as(u16, 7), publish.packet_id.?);
    try std.testing.expectEqualStrings("21.5", publish.payload);
}

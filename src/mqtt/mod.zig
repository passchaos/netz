const std = @import("std");
const wire = @import("../internal/wire.zig");
const ack_reason = @import("ack_reason.zig");

pub const validateAckReasonCode = ack_reason.validate;
pub const validateSubscription = @import("subscription/validation.zig").validate;

pub const runtime = @import("runtime.zig");
pub const reconnect = @import("reconnect.zig");
pub const broker = @import("broker.zig");
pub const broker_prometheus = @import("broker/prometheus.zig");
pub const bridge = @import("bridge.zig");
pub const websocket_runtime = @import("websocket_runtime.zig");
pub const tls_runtime = @import("tls_runtime.zig");
pub const socks5_runtime = @import("socks5_runtime.zig");
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
    _ = @import("../internal/test_tmp_dir.zig");
    _ = ack_reason;
    _ = @import("subscription/validation_tests.zig");
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
    // PacketType exhaustively and contiguously covers every remaining u4
    // value (1...15), so the generic enum lookup has no failure case here.
    return @enumFromInt(packet_nibble);
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

pub fn remainingLengthEncodedLen(value: usize) usize {
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
    // Sixteen-byte chunks keep the common ASCII prefix off the scalar loop;
    // a chunk containing any high byte falls through to the scalar scan.
    var first_non_ascii = value.len;
    var index: usize = 0;
    const Vec = @Vector(16, u8);
    const high: Vec = @splat(0x80);
    const zero: Vec = @splat(0);
    const space: Vec = @splat(0x20);
    const del: Vec = @splat(0x7f);
    while (index + 16 <= value.len) : (index += 16) {
        const chunk: Vec = value[index..][0..16].*;
        if (@reduce(.Or, chunk >= high)) break;
        if (@reduce(.Or, chunk == zero)) return error.InvalidUtf8;
        if (reject_discouraged_controls and
            (@reduce(.Or, chunk < space) or
                @reduce(.Or, chunk == del)))
        {
            return error.InvalidUtf8;
        }
    }
    for (value[index..], index..) |byte, byte_index| {
        if (byte >= 0x80) {
            first_non_ascii = byte_index;
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
    if (topic.len == 0 or topic.len > std.math.maxInt(u16)) return false;

    // One vector pass rejects NUL, '+' and '#' for ASCII topic names. A high
    // byte falls back to the general UTF-8 validator and a wildcard scan.
    var index: usize = 0;
    const Vec = @Vector(16, u8);
    const high: Vec = @splat(0x80);
    const zero: Vec = @splat(0);
    const plus: Vec = @splat('+');
    const hash: Vec = @splat('#');
    while (index + 16 <= topic.len) : (index += 16) {
        const chunk: Vec = topic[index..][0..16].*;
        if (@reduce(.Or, chunk >= high)) break;
        if (@reduce(.Or, chunk == zero) or
            @reduce(.Or, chunk == plus) or
            @reduce(.Or, chunk == hash))
        {
            return false;
        }
    }
    for (topic[index..]) |byte| {
        if (byte >= 0x80) {
            return validMqttUtf8(topic) and !hasWildcards(topic);
        }
        if (byte == 0 or byte == '+' or byte == '#') return false;
    }
    return true;
}

pub fn validateTopicName(topic: []const u8) Error!void {
    if (!validTopicName(topic)) return error.InvalidTopic;
}

pub fn validTopicFilter(filter: []const u8) bool {
    if (filter.len == 0 or filter.len > std.math.maxInt(u16)) return false;
    if (!validMqttUtf8(filter)) return false;
    if (std.mem.startsWith(u8, filter, "$share/")) {
        return validSharedTopicFilterKind(filter) != null;
    }
    return validTopicFilterLevelsKind(filter) != null;
}

fn validSharedTopicFilterKind(filter: []const u8) ?bool {
    if (!std.mem.startsWith(u8, filter, "$share/")) return null;
    const rest = filter["$share/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const group = rest[0..slash];
    const shared_filter = rest[slash + 1 ..];
    if (group.len == 0 or !validMqttUtf8(group) or hasWildcards(group)) {
        return null;
    }
    return validTopicFilterLevelsKind(shared_filter);
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
    return validTopicFilterLevelsKind(filter) orelse false;
}

/// Validate wildcard placement and report whether any wildcard is present.
/// A null result is invalid; `false` is a valid literal filter; `true` is a
/// valid filter containing '+' or '#'. One scan serves both questions.
fn validTopicFilterLevelsKind(filter: []const u8) ?bool {
    if (filter.len == 0) return null;

    // Validate wildcard placement directly from each wildcard position instead
    // of splitting every level. A wildcard is legal only when it occupies the
    // complete level; '#' must also be the final level and final byte. A
    // filter with no wildcard needs one SIMD search and no level walk.
    var has_wildcards = false;
    var search: usize = 0;
    while (std.mem.indexOfAnyPos(u8, filter, search, "+#")) |position| {
        const level_start = position == 0 or filter[position - 1] == '/';
        const level_end = position + 1 == filter.len or
            filter[position + 1] == '/';
        if (!level_start or !level_end) return null;
        if (filter[position] == '#') {
            // Multi-level wildcard is legal only when it occupies the complete
            // final level. This mirrors rumqtt's broker/client validation and
            // prevents ambiguous filters such as `sport/#/rank` or `sport#`.
            if (position + 1 != filter.len) return null;
            return true;
        }
        has_wildcards = true;
        search = position + 1;
    }
    return has_wildcards;
}

pub fn validateTopicFilter(filter: []const u8) Error!void {
    _ = try validateTopicFilterKind(filter);
}

/// Validate a Topic Filter and report whether its effective filter contains
/// '+' or '#'. Retained lookups need both answers, so this avoids a second
/// wildcard scan after validation.
pub fn validateTopicFilterKind(filter: []const u8) Error!bool {
    if (filter.len == 0 or filter.len > std.math.maxInt(u16)) {
        return error.InvalidSubscription;
    }
    if (!validMqttUtf8(filter)) return error.InvalidSubscription;
    const kind = if (std.mem.startsWith(u8, filter, "$share/"))
        validSharedTopicFilterKind(filter)
    else
        validTopicFilterLevelsKind(filter);
    return kind orelse error.InvalidSubscription;
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

    /// Validate a borrowed ACK before encoding or applying protocol state.
    /// This performs no allocation and leaves the caller's properties intact.
    pub fn validate(self: AckPacket, protocol: ProtocolVersion) Error!void {
        try validateFields(protocol, self.packet_type, self.dup, self.packet_id, self.reason_code, self.properties);
    }

    fn validateFields(protocol: ProtocolVersion, packet_type: PacketType, dup: bool, packet_id: u16, reason_code: u8, properties: []const Property) Error!void {
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
        try validatePacketFlags(protocol, .{
            .packet_type = packet_type,
            .flags = packet_type.defaultFlags() | (if (dup) @as(u4, 0x08) else 0),
            .remaining_len = 2,
            .header_len = 0,
        });
    }

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
        // MQTT 3.1/3.1.1/5 permit every QoS acknowledgement to contain only its
        // Packet Identifier. This is the dominant broker form: an omitted
        // MQTT 5 reason means Success and also omits the Property Length.
        // Decode that complete payload directly instead of constructing the
        // general reason/property cursor path.
        if (payload_bytes.len == 2) {
            const packet_id = std.mem.readInt(
                u16,
                payload_bytes[0..2],
                .big,
            );
            if (packet_id == 0) return error.InvalidPacketIdentifier;
            return .{
                .packet_type = packet_type,
                .packet_id = packet_id,
                .dup = protocol == .v3_1 and (flags & 0x08) != 0,
            };
        }

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
        try validateFields(protocol, packet_type, dup, packet_id, reason_code, properties);
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
        try validateFields(protocol, packet_type, dup, packet_id, reason_code, &.{});

        const include_reason = protocol == .v5 and reason_code != 0;
        const remaining_len: u8 = if (include_reason) 3 else 2;
        const flags = packet_type.defaultFlags() |
            (if (dup) @as(u4, 0x08) else 0);
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
            try validateSubscription(subscription, null);
            const options: u8 = @intFromEnum(subscription.qos) |
                (if (subscription.no_local) @as(u8, 0x04) else 0) |
                (if (subscription.retain_as_published) @as(u8, 0x08) else 0) |
                (@as(u8, subscription.retain_handling) << 4);
            try validateSubscriptionOptions(protocol, options);
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

/// Validate one protocol-version-specific CONNACK reason code without
/// allocating or encoding a packet.
pub fn validateConnAckReason(protocol: ProtocolVersion, code: u8) Error!void {
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

const PublishWirePlan = struct {
    lengths: PublishWireLengths,
    properties_len: usize,
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
    const plan = try publishWirePlan(
        protocol,
        topic,
        payload,
        options,
    );
    try list.ensureUnusedCapacity(allocator, plan.lengths.total);
    writePublishPrefixAssumeCapacity(
        list,
        protocol,
        topic,
        options,
        payload.len,
        plan.properties_len,
    );
    list.appendSliceAssumeCapacity(payload);
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
    const plan = try publishWirePlan(
        protocol,
        topic,
        payload,
        options,
    );
    try list.ensureUnusedCapacity(allocator, plan.lengths.prefix);
    writePublishPrefixAssumeCapacity(
        list,
        protocol,
        topic,
        options,
        payload.len,
        plan.properties_len,
    );
    return plan.lengths;
}

fn publishWirePlan(
    protocol: ProtocolVersion,
    topic: []const u8,
    payload: []const u8,
    options: PublishWriteOptions,
) Error!PublishWirePlan {
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
    return .{
        .lengths = .{ .prefix = prefix_len, .total = total_len },
        .properties_len = properties_len,
    };
}

fn writePublishPrefixAssumeCapacity(
    list: *std.ArrayList(u8),
    protocol: ProtocolVersion,
    topic: []const u8,
    options: PublishWriteOptions,
    remaining_payload_len: usize,
    properties_len: usize,
) void {
    const variable_len = 2 + topic.len +
        if (options.qos == .at_most_once) @as(usize, 0) else 2;
    std.debug.assert(protocol == .v5 or properties_len == 0);
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
    _ = @import("runtime/resolver_tests.zig");
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
    _ = @import("websocket_runtime/redirect_tests.zig");
    _ = @import("runtime/websocket_unix_tests.zig");
    _ = @import("websocket_keep_alive_tests.zig");
    _ = persistence.commit_log;
    _ = redirect;
    _ = proxy_protocol;
}

test {
    _ = @import("tests.zig");
}

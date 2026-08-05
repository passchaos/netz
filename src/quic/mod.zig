const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const varint = @import("varint.zig");

pub const Version = enum(u32) {
    version_1 = 0x00000001,
    version_2 = 0x6b3343cf,
    negotiation = 0x00000000,
    _,

    pub fn wireValue(self: Version) u32 {
        return @intFromEnum(self);
    }
};

pub const PacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

pub const LongHeader = struct {
    fixed_bit: bool,
    packet_type: PacketType,
    type_specific_bits: u4,
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{},
    length: ?u64 = null,
    packet_number: []const u8 = &.{},

    pub fn parse(bytes: []const u8) !LongHeader {
        var cursor = wire.Cursor.init(bytes);
        const first = try cursor.readByte();
        if ((first & 0x80) == 0) return error.InvalidEncoding;
        const version_value = try cursor.readInt(u32, .big);
        const dcid_len = try cursor.readByte();
        const dcid = try cursor.readSlice(dcid_len);
        const scid_len = try cursor.readByte();
        const scid = try cursor.readSlice(scid_len);
        const packet_type: PacketType = @enumFromInt((first >> 4) & 0x03);
        var token: []const u8 = &.{};
        var payload_len: ?u64 = null;
        var packet_number: []const u8 = &.{};
        if (packet_type == .initial) {
            const token_len = try varint.decode(&cursor);
            token = try cursor.readSlice(std.math.cast(usize, token_len) orelse return error.IntegerOverflow);
            payload_len = try varint.decode(&cursor);
            const pn_len: usize = @as(usize, (first & 0x03)) + 1;
            packet_number = try cursor.readSlice(pn_len);
        } else if (packet_type == .zero_rtt or packet_type == .handshake) {
            payload_len = try varint.decode(&cursor);
            const pn_len: usize = @as(usize, (first & 0x03)) + 1;
            packet_number = try cursor.readSlice(pn_len);
        }
        return .{
            .fixed_bit = (first & 0x40) != 0,
            .packet_type = packet_type,
            .type_specific_bits = @truncate(first & 0x0f),
            .version = version_value,
            .destination_connection_id = dcid,
            .source_connection_id = scid,
            .token = token,
            .length = payload_len,
            .packet_number = packet_number,
        };
    }
};

pub const TransportParameterId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    max_datagram_frame_size = 0x20,
    _,
};

pub const TransportParameter = struct {
    id: u64,
    value: []const u8,
};

pub fn encodeTransportParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, id: u64, value: []const u8) !void {
    try varint.encode(list, allocator, id);
    try varint.encode(list, allocator, value.len);
    try list.appendSlice(allocator, value);
}

pub fn parseTransportParameters(allocator: std.mem.Allocator, bytes: []const u8) ![]TransportParameter {
    var cursor = wire.Cursor.init(bytes);
    var params: std.ArrayList(TransportParameter) = .empty;
    errdefer params.deinit(allocator);
    while (!cursor.eof()) {
        const id = try varint.decode(&cursor);
        const len = try varint.decode(&cursor);
        const value = try cursor.readSlice(std.math.cast(usize, len) orelse return error.IntegerOverflow);
        try params.append(allocator, .{ .id = id, .value = value });
    }
    return params.toOwnedSlice(allocator);
}

pub const StreamId = struct {
    value: u62,

    pub fn init(value: u62) StreamId {
        return .{ .value = value };
    }

    pub fn initiator(self: StreamId) enum { client, server } {
        return if ((self.value & 0x1) == 0) .client else .server;
    }

    pub fn direction(self: StreamId) enum { bidirectional, unidirectional } {
        return if ((self.value & 0x2) == 0) .bidirectional else .unidirectional;
    }
};

pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    datagram = 0x30,
    datagram_len = 0x31,
    _,

    pub fn isStream(value: u64) bool {
        return (value & 0xf8) == 0x08;
    }
};

comptime {
    _ = varint;
}

test "QUIC long initial header parse" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.append(allocator, 0xc3); // long header, fixed bit, Initial, 4-byte PN
    try wire.appendInt(&bytes, allocator, u32, 1, .big);
    try bytes.append(allocator, 4);
    try bytes.appendSlice(allocator, "dcid");
    try bytes.append(allocator, 4);
    try bytes.appendSlice(allocator, "scid");
    try varint.encode(&bytes, allocator, 0);
    try varint.encode(&bytes, allocator, 4);
    try bytes.appendSlice(allocator, &.{ 0, 0, 0, 1 });

    const parsed = try LongHeader.parse(bytes.items);
    try std.testing.expect(parsed.fixed_bit);
    try std.testing.expectEqual(PacketType.initial, parsed.packet_type);
    try std.testing.expectEqualStrings("dcid", parsed.destination_connection_id);
    try std.testing.expectEqual(@as(u64, 4), parsed.length.?);
}

test "QUIC transport parameter parser" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try encodeTransportParameter(&bytes, allocator, @intFromEnum(TransportParameterId.initial_max_data), &.{ 0x40, 0x64 });
    const params = try parseTransportParameters(allocator, bytes.items);
    defer allocator.free(params);
    try std.testing.expectEqual(@as(u64, 0x04), params[0].id);
    try std.testing.expectEqualStrings(&.{ 0x40, 0x64 }, params[0].value);
}

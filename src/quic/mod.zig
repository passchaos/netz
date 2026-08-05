const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const varint = @import("varint.zig");
pub const runtime = @import("runtime.zig");
pub const protection = @import("protection.zig");
pub const crypto_stream = @import("crypto_stream.zig");
pub const initial_exchange = @import("initial_exchange.zig");
pub const tls_client_hello = @import("tls_client_hello.zig");
pub const handshake = @import("handshake.zig");
pub const one_rtt = @import("one_rtt.zig");
pub const packet_space = @import("packet_space.zig");
pub const stream_state = @import("stream.zig");
pub const flow_control = @import("flow_control.zig");
pub const recovery = @import("recovery.zig");
pub const connection_router = @import("connection_router.zig");
pub const connection_id = @import("connection_id.zig");
pub const stateless_reset = @import("stateless_reset.zig");
pub const congestion = @import("congestion.zig");
pub const path_validation = @import("path_validation.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    IntegerOverflow,
    InvalidFrame,
    InvalidFrameLength,
    InvalidAckRange,
    InvalidConnectionIdLength,
    InvalidTransportParameter,
    InvalidTransportParameterLength,
    DuplicateTransportParameter,
    TransportParameterForbidden,
    UnsupportedFrameType,
} || std.mem.Allocator.Error;

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

pub const TransportParameterSource = enum {
    client,
    server,
};

pub const default_max_udp_payload_size: u64 = 65_527;
pub const default_ack_delay_exponent: u64 = 3;
pub const default_max_ack_delay_ms: u64 = 25;
pub const default_active_connection_id_limit: u64 = 2;
pub const max_stream_count: u64 = 1 << 60;

pub const PreferredAddress = struct {
    ipv4_address: [4]u8 = [_]u8{0} ** 4,
    ipv4_port: u16 = 0,
    ipv6_address: [16]u8 = [_]u8{0} ** 16,
    ipv6_port: u16 = 0,
    connection_id: []const u8 = &.{},
    stateless_reset_token: [16]u8 = [_]u8{0} ** 16,
};

/// Typed QUIC transport parameters with RFC defaults.
///
/// Decoded byte slices borrow from the input buffer, matching the lower-level
/// parser below.  The struct is intentionally allocation-free so handshakes can
/// validate peer parameters before deriving 1-RTT state without introducing
/// ownership surprises.
pub const TransportParameters = struct {
    original_destination_connection_id: ?[]const u8 = null,
    max_idle_timeout: u64 = 0,
    stateless_reset_token: ?[16]u8 = null,
    max_udp_payload_size: u64 = default_max_udp_payload_size,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = default_ack_delay_exponent,
    max_ack_delay: u64 = default_max_ack_delay_ms,
    disable_active_migration: bool = false,
    preferred_address: ?PreferredAddress = null,
    active_connection_id_limit: u64 = default_active_connection_id_limit,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    max_datagram_frame_size: ?u64 = null,
};

/// Practical defaults for netz's in-repository QUIC/H3/WebTransport runtimes.
/// The RFC defaults are intentionally conservative (all flow-control limits are
/// zero), which is useful for parsers but makes an integrated handshake unable
/// to exchange application data unless the caller constructs parameters by
/// hand.  These values mirror the shape used by production stacks such as
/// quic-zig, tquic, s2n-quic, and quicz: advertise enough initial credit for
/// request/response traffic while still keeping bounded windows.
pub const practical_transport_parameters = TransportParameters{
    .initial_max_data = 1024 * 1024,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_stream_data_uni = 256 * 1024,
    .initial_max_streams_bidi = 100,
    .initial_max_streams_uni = 100,
    .active_connection_id_limit = 4,
    .max_datagram_frame_size = 65_535,
};

pub fn encodeTransportParameters(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    params: TransportParameters,
) Error!void {
    if (params.original_destination_connection_id) |cid| {
        try validateTransportConnectionId(cid, false);
        try encodeTransportParameter(list, allocator, @intFromEnum(TransportParameterId.original_destination_connection_id), cid);
    }
    if (params.max_idle_timeout != 0) try encodeIntegerTransportParameter(list, allocator, .max_idle_timeout, params.max_idle_timeout);
    if (params.stateless_reset_token) |token| {
        try encodeTransportParameter(list, allocator, @intFromEnum(TransportParameterId.stateless_reset_token), &token);
    }
    if (params.max_udp_payload_size != default_max_udp_payload_size) {
        try encodeIntegerTransportParameter(list, allocator, .max_udp_payload_size, params.max_udp_payload_size);
    }
    if (params.initial_max_data != 0) try encodeIntegerTransportParameter(list, allocator, .initial_max_data, params.initial_max_data);
    if (params.initial_max_stream_data_bidi_local != 0) try encodeIntegerTransportParameter(list, allocator, .initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local);
    if (params.initial_max_stream_data_bidi_remote != 0) try encodeIntegerTransportParameter(list, allocator, .initial_max_stream_data_bidi_remote, params.initial_max_stream_data_bidi_remote);
    if (params.initial_max_stream_data_uni != 0) try encodeIntegerTransportParameter(list, allocator, .initial_max_stream_data_uni, params.initial_max_stream_data_uni);
    if (params.initial_max_streams_bidi != 0) try encodeIntegerTransportParameter(list, allocator, .initial_max_streams_bidi, params.initial_max_streams_bidi);
    if (params.initial_max_streams_uni != 0) try encodeIntegerTransportParameter(list, allocator, .initial_max_streams_uni, params.initial_max_streams_uni);
    if (params.ack_delay_exponent != default_ack_delay_exponent) try encodeIntegerTransportParameter(list, allocator, .ack_delay_exponent, params.ack_delay_exponent);
    if (params.max_ack_delay != default_max_ack_delay_ms) try encodeIntegerTransportParameter(list, allocator, .max_ack_delay, params.max_ack_delay);
    if (params.disable_active_migration) try encodeTransportParameter(list, allocator, @intFromEnum(TransportParameterId.disable_active_migration), &.{});
    if (params.preferred_address) |preferred| try encodePreferredAddressTransportParameter(list, allocator, preferred);
    if (params.active_connection_id_limit != default_active_connection_id_limit) try encodeIntegerTransportParameter(list, allocator, .active_connection_id_limit, params.active_connection_id_limit);
    if (params.initial_source_connection_id) |cid| {
        try validateTransportConnectionId(cid, false);
        try encodeTransportParameter(list, allocator, @intFromEnum(TransportParameterId.initial_source_connection_id), cid);
    }
    if (params.retry_source_connection_id) |cid| {
        try validateTransportConnectionId(cid, false);
        try encodeTransportParameter(list, allocator, @intFromEnum(TransportParameterId.retry_source_connection_id), cid);
    }
    if (params.max_datagram_frame_size) |size| try encodeIntegerTransportParameter(list, allocator, .max_datagram_frame_size, size);
}

pub fn validateTransportParameters(params: TransportParameters, source: TransportParameterSource) Error!void {
    if (source == .client) {
        if (params.original_destination_connection_id != null or
            params.stateless_reset_token != null or
            params.preferred_address != null or
            params.retry_source_connection_id != null)
        {
            return error.TransportParameterForbidden;
        }
    }

    if (params.original_destination_connection_id) |cid| try validateTransportConnectionId(cid, false);
    if (params.initial_source_connection_id) |cid| try validateTransportConnectionId(cid, false);
    if (params.retry_source_connection_id) |cid| try validateTransportConnectionId(cid, false);
    if (params.preferred_address) |preferred| try validatePreferredAddress(preferred);

    try validateTransportInteger(.max_udp_payload_size, params.max_udp_payload_size);
    try validateTransportInteger(.initial_max_streams_bidi, params.initial_max_streams_bidi);
    try validateTransportInteger(.initial_max_streams_uni, params.initial_max_streams_uni);
    try validateTransportInteger(.ack_delay_exponent, params.ack_delay_exponent);
    try validateTransportInteger(.max_ack_delay, params.max_ack_delay);
    try validateTransportInteger(.active_connection_id_limit, params.active_connection_id_limit);
    if (params.max_datagram_frame_size) |size| try validateTransportInteger(.max_datagram_frame_size, size);
}

pub fn parseTransportParametersTyped(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    source: TransportParameterSource,
) Error!TransportParameters {
    var cursor = wire.Cursor.init(bytes);
    var params = TransportParameters{};
    var seen: std.ArrayList(u64) = .empty;
    defer seen.deinit(allocator);

    while (!cursor.eof()) {
        const id = try varint.decode(&cursor);
        for (seen.items) |seen_id| {
            if (seen_id == id) return error.DuplicateTransportParameter;
        }
        try seen.append(allocator, id);

        const len = try usizeFromVarint(try varint.decode(&cursor));
        const value = try cursor.readSlice(len);

        if (id == @intFromEnum(TransportParameterId.original_destination_connection_id)) {
            if (source == .client) return error.TransportParameterForbidden;
            try validateTransportConnectionId(value, false);
            params.original_destination_connection_id = value;
        } else if (id == @intFromEnum(TransportParameterId.max_idle_timeout)) {
            params.max_idle_timeout = try parseTransportInteger(.max_idle_timeout, value);
        } else if (id == @intFromEnum(TransportParameterId.stateless_reset_token)) {
            if (source == .client) return error.TransportParameterForbidden;
            if (value.len != 16) return error.InvalidTransportParameterLength;
            params.stateless_reset_token = value[0..16].*;
        } else if (id == @intFromEnum(TransportParameterId.max_udp_payload_size)) {
            params.max_udp_payload_size = try parseTransportInteger(.max_udp_payload_size, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_max_data)) {
            params.initial_max_data = try parseTransportInteger(.initial_max_data, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_max_stream_data_bidi_local)) {
            params.initial_max_stream_data_bidi_local = try parseTransportInteger(.initial_max_stream_data_bidi_local, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_max_stream_data_bidi_remote)) {
            params.initial_max_stream_data_bidi_remote = try parseTransportInteger(.initial_max_stream_data_bidi_remote, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_max_stream_data_uni)) {
            params.initial_max_stream_data_uni = try parseTransportInteger(.initial_max_stream_data_uni, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_max_streams_bidi)) {
            params.initial_max_streams_bidi = try parseTransportInteger(.initial_max_streams_bidi, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_max_streams_uni)) {
            params.initial_max_streams_uni = try parseTransportInteger(.initial_max_streams_uni, value);
        } else if (id == @intFromEnum(TransportParameterId.ack_delay_exponent)) {
            params.ack_delay_exponent = try parseTransportInteger(.ack_delay_exponent, value);
        } else if (id == @intFromEnum(TransportParameterId.max_ack_delay)) {
            params.max_ack_delay = try parseTransportInteger(.max_ack_delay, value);
        } else if (id == @intFromEnum(TransportParameterId.disable_active_migration)) {
            if (value.len != 0) return error.InvalidTransportParameterLength;
            params.disable_active_migration = true;
        } else if (id == @intFromEnum(TransportParameterId.preferred_address)) {
            if (source == .client) return error.TransportParameterForbidden;
            params.preferred_address = try parsePreferredAddress(value);
        } else if (id == @intFromEnum(TransportParameterId.active_connection_id_limit)) {
            params.active_connection_id_limit = try parseTransportInteger(.active_connection_id_limit, value);
        } else if (id == @intFromEnum(TransportParameterId.initial_source_connection_id)) {
            try validateTransportConnectionId(value, false);
            params.initial_source_connection_id = value;
        } else if (id == @intFromEnum(TransportParameterId.retry_source_connection_id)) {
            if (source == .client) return error.TransportParameterForbidden;
            try validateTransportConnectionId(value, false);
            params.retry_source_connection_id = value;
        } else if (id == @intFromEnum(TransportParameterId.max_datagram_frame_size)) {
            params.max_datagram_frame_size = try parseTransportInteger(.max_datagram_frame_size, value);
        } else {
            // Unknown parameters, including greasing identifiers of the form
            // 31*N+27, are intentionally ignored after duplicate detection as
            // required by RFC 9000.
        }
    }

    try validateTransportParameters(params, source);
    return params;
}

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

fn encodeIntegerTransportParameter(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    id: TransportParameterId,
    value: u64,
) Error!void {
    try validateTransportInteger(id, value);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try varint.encode(&encoded, allocator, value);
    try encodeTransportParameter(list, allocator, @intFromEnum(id), encoded.items);
}

fn encodePreferredAddressTransportParameter(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    preferred: PreferredAddress,
) Error!void {
    try validatePreferredAddress(preferred);

    var value: std.ArrayList(u8) = .empty;
    defer value.deinit(allocator);
    try value.appendSlice(allocator, &preferred.ipv4_address);
    try wire.appendInt(&value, allocator, u16, preferred.ipv4_port, .big);
    try value.appendSlice(allocator, &preferred.ipv6_address);
    try wire.appendInt(&value, allocator, u16, preferred.ipv6_port, .big);
    try value.append(allocator, @intCast(preferred.connection_id.len));
    try value.appendSlice(allocator, preferred.connection_id);
    try value.appendSlice(allocator, &preferred.stateless_reset_token);
    try encodeTransportParameter(list, allocator, @intFromEnum(TransportParameterId.preferred_address), value.items);
}

fn parseTransportInteger(id: TransportParameterId, value: []const u8) Error!u64 {
    if (value.len == 0) return error.InvalidTransportParameterLength;
    var cursor = wire.Cursor.init(value);
    const parsed = try varint.decode(&cursor);
    if (!cursor.eof()) return error.InvalidTransportParameterLength;
    try validateTransportInteger(id, parsed);
    return parsed;
}

fn validateTransportInteger(id: TransportParameterId, value: u64) Error!void {
    if (value > varint.max_value) return error.InvalidTransportParameter;
    switch (id) {
        .max_udp_payload_size => {
            if (value < 1200 or value > default_max_udp_payload_size) return error.InvalidTransportParameter;
        },
        .initial_max_streams_bidi, .initial_max_streams_uni => {
            if (value > max_stream_count) return error.InvalidTransportParameter;
        },
        .ack_delay_exponent => {
            if (value > 20) return error.InvalidTransportParameter;
        },
        .max_ack_delay => {
            if (value >= (@as(u64, 1) << 14)) return error.InvalidTransportParameter;
        },
        .active_connection_id_limit => {
            if (value < default_active_connection_id_limit) return error.InvalidTransportParameter;
        },
        else => {},
    }
}

fn parsePreferredAddress(value: []const u8) Error!PreferredAddress {
    var cursor = wire.Cursor.init(value);
    const ipv4 = (try cursor.readSlice(4))[0..4].*;
    const ipv4_port = try cursor.readInt(u16, .big);
    const ipv6 = (try cursor.readSlice(16))[0..16].*;
    const ipv6_port = try cursor.readInt(u16, .big);
    const cid_len = try cursor.readByte();
    const cid = try cursor.readSlice(cid_len);
    try validateTransportConnectionId(cid, true);
    const token = (try cursor.readSlice(16))[0..16].*;
    if (!cursor.eof()) return error.InvalidTransportParameterLength;
    return .{
        .ipv4_address = ipv4,
        .ipv4_port = ipv4_port,
        .ipv6_address = ipv6,
        .ipv6_port = ipv6_port,
        .connection_id = cid,
        .stateless_reset_token = token,
    };
}

fn validatePreferredAddress(preferred: PreferredAddress) Error!void {
    try validateTransportConnectionId(preferred.connection_id, true);
}

fn validateTransportConnectionId(cid: []const u8, require_non_empty: bool) Error!void {
    if ((require_non_empty and cid.len == 0) or cid.len > 20) {
        return error.InvalidTransportParameter;
    }
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

pub const PaddingFrame = struct {
    len: usize,
};

pub const AckRange = struct {
    gap: u64,
    ack_range_length: u64,
};

pub const EcnCounts = struct {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
};

pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ranges: []const AckRange = &.{},
    ecn_counts: ?EcnCounts = null,
};

pub const ResetStreamFrame = struct {
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
};

pub const StopSendingFrame = struct {
    stream_id: u64,
    application_error_code: u64,
};

pub const NewTokenFrame = struct {
    token: []const u8,
};

pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64 = 0,
    fin: bool = false,
    data: []const u8,
};

pub const MaxDataFrame = struct {
    maximum_data: u64,
};

pub const MaxStreamDataFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const MaxStreamsFrame = struct {
    maximum_streams: u64,
};

pub const DataBlockedFrame = struct {
    maximum_data: u64,
};

pub const StreamDataBlockedFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const StreamsBlockedFrame = struct {
    maximum_streams: u64,
};

pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
};

pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
};

pub const PathFrame = struct {
    data: [8]u8,
};

pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: u64,
    reason_phrase: []const u8,
};

pub const ApplicationCloseFrame = struct {
    error_code: u64,
    reason_phrase: []const u8,
};

pub const DatagramFrame = struct {
    data: []const u8,
    length_present: bool = true,
};

pub const Frame = union(enum) {
    padding: PaddingFrame,
    ping: void,
    ack: AckFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    new_token: NewTokenFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: MaxStreamsFrame,
    max_streams_uni: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked_bidi: StreamsBlockedFrame,
    streams_blocked_uni: StreamsBlockedFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathFrame,
    path_response: PathFrame,
    connection_close: ConnectionCloseFrame,
    application_close: ApplicationCloseFrame,
    handshake_done: void,
    datagram: DatagramFrame,

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        switch (self) {
            .padding => |padding| try list.appendNTimes(allocator, @intFromEnum(FrameType.padding), padding.len),
            .ping => try varint.encode(list, allocator, @intFromEnum(FrameType.ping)),
            .ack => |ack| {
                try varint.encode(list, allocator, if (ack.ecn_counts == null) @intFromEnum(FrameType.ack) else @intFromEnum(FrameType.ack_ecn));
                try writeAckFields(list, allocator, ack);
            },
            .reset_stream => |reset| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.reset_stream));
                try varint.encode(list, allocator, reset.stream_id);
                try varint.encode(list, allocator, reset.application_error_code);
                try varint.encode(list, allocator, reset.final_size);
            },
            .stop_sending => |stop| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.stop_sending));
                try varint.encode(list, allocator, stop.stream_id);
                try varint.encode(list, allocator, stop.application_error_code);
            },
            .new_token => |new_token| {
                if (new_token.token.len == 0) return error.InvalidFrame;
                try varint.encode(list, allocator, @intFromEnum(FrameType.new_token));
                try varint.encode(list, allocator, new_token.token.len);
                try list.appendSlice(allocator, new_token.token);
            },
            .crypto => |crypto| {
                try validateEndOffset(crypto.offset, crypto.data.len);
                try varint.encode(list, allocator, @intFromEnum(FrameType.crypto));
                try varint.encode(list, allocator, crypto.offset);
                try varint.encode(list, allocator, crypto.data.len);
                try list.appendSlice(allocator, crypto.data);
            },
            .stream => |stream| {
                try validateEndOffset(stream.offset, stream.data.len);
                var frame_type: u64 = @intFromEnum(FrameType.stream) | 0x02; // always include Length for unambiguous composition.
                if (stream.offset != 0) frame_type |= 0x04;
                if (stream.fin) frame_type |= 0x01;
                try varint.encode(list, allocator, frame_type);
                try varint.encode(list, allocator, stream.stream_id);
                if (stream.offset != 0) try varint.encode(list, allocator, stream.offset);
                try varint.encode(list, allocator, stream.data.len);
                try list.appendSlice(allocator, stream.data);
            },
            .max_data => |max_data| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.max_data));
                try varint.encode(list, allocator, max_data.maximum_data);
            },
            .max_stream_data => |max_stream_data| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.max_stream_data));
                try varint.encode(list, allocator, max_stream_data.stream_id);
                try varint.encode(list, allocator, max_stream_data.maximum_stream_data);
            },
            .max_streams_bidi => |max_streams| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.max_streams_bidi), max_streams.maximum_streams),
            .max_streams_uni => |max_streams| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.max_streams_uni), max_streams.maximum_streams),
            .data_blocked => |blocked| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.data_blocked), blocked.maximum_data),
            .stream_data_blocked => |blocked| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.stream_data_blocked));
                try varint.encode(list, allocator, blocked.stream_id);
                try varint.encode(list, allocator, blocked.maximum_stream_data);
            },
            .streams_blocked_bidi => |blocked| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.streams_blocked_bidi), blocked.maximum_streams),
            .streams_blocked_uni => |blocked| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.streams_blocked_uni), blocked.maximum_streams),
            .new_connection_id => |new_connection_id| {
                try validateConnectionIdLen(new_connection_id.connection_id.len);
                if (new_connection_id.retire_prior_to > new_connection_id.sequence_number) return error.InvalidFrame;
                try varint.encode(list, allocator, @intFromEnum(FrameType.new_connection_id));
                try varint.encode(list, allocator, new_connection_id.sequence_number);
                try varint.encode(list, allocator, new_connection_id.retire_prior_to);
                try list.append(allocator, @intCast(new_connection_id.connection_id.len));
                try list.appendSlice(allocator, new_connection_id.connection_id);
                try list.appendSlice(allocator, &new_connection_id.stateless_reset_token);
            },
            .retire_connection_id => |retire| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.retire_connection_id), retire.sequence_number),
            .path_challenge => |path| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.path_challenge));
                try list.appendSlice(allocator, &path.data);
            },
            .path_response => |path| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.path_response));
                try list.appendSlice(allocator, &path.data);
            },
            .connection_close => |close| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.connection_close));
                try varint.encode(list, allocator, close.error_code);
                try varint.encode(list, allocator, close.frame_type);
                try varint.encode(list, allocator, close.reason_phrase.len);
                try list.appendSlice(allocator, close.reason_phrase);
            },
            .application_close => |close| {
                try varint.encode(list, allocator, @intFromEnum(FrameType.connection_close_app));
                try varint.encode(list, allocator, close.error_code);
                try varint.encode(list, allocator, close.reason_phrase.len);
                try list.appendSlice(allocator, close.reason_phrase);
            },
            .handshake_done => try varint.encode(list, allocator, @intFromEnum(FrameType.handshake_done)),
            .datagram => |datagram| {
                try varint.encode(list, allocator, if (datagram.length_present) @intFromEnum(FrameType.datagram_len) else @intFromEnum(FrameType.datagram));
                if (datagram.length_present) try varint.encode(list, allocator, datagram.data.len);
                try list.appendSlice(allocator, datagram.data);
            },
        }
    }
};

pub fn deinitOwnedFrame(frame: *Frame, allocator: std.mem.Allocator) void {
    switch (frame.*) {
        // `parseFrameOwned` allocates ACK ranges because the wire can carry an
        // arbitrary number of sparse ranges.  Other frame payload slices still
        // borrow from the containing packet/datagram bytes.
        .ack => |ack| allocator.free(ack.ranges),
        else => {},
    }
    frame.* = undefined;
}

pub fn deinitOwnedFrameSlice(frames: []Frame, allocator: std.mem.Allocator) void {
    for (frames) |*frame| deinitOwnedFrame(frame, allocator);
}

pub const ParsedFrame = struct {
    frame: Frame,
    consumed: usize,

    pub fn deinitOwned(self: *ParsedFrame, allocator: std.mem.Allocator) void {
        deinitOwnedFrame(&self.frame, allocator);
        self.* = undefined;
    }
};

pub fn parseFrame(bytes: []const u8) Error!ParsedFrame {
    return parseFrameWithAllocator(null, bytes);
}

pub fn parseFrameOwned(allocator: std.mem.Allocator, bytes: []const u8) Error!ParsedFrame {
    return parseFrameWithAllocator(allocator, bytes);
}

fn parseFrameWithAllocator(allocator: ?std.mem.Allocator, bytes: []const u8) Error!ParsedFrame {
    var cursor = wire.Cursor.init(bytes);
    const frame_type = try varint.decode(&cursor);

    if (frame_type == @intFromEnum(FrameType.padding)) {
        while (!cursor.eof() and cursor.buf[cursor.pos] == @intFromEnum(FrameType.padding)) {
            cursor.pos += 1;
        }
        return .{ .frame = .{ .padding = .{ .len = cursor.pos } }, .consumed = cursor.pos };
    }

    const frame = try parseFrameAfterType(allocator, frame_type, &cursor, bytes);
    return .{ .frame = frame, .consumed = cursor.pos };
}

fn parseFrameAfterType(allocator: ?std.mem.Allocator, frame_type: u64, cursor: *wire.Cursor, packet_payload: []const u8) Error!Frame {
    if (frame_type == @intFromEnum(FrameType.ping)) return .{ .ping = {} };

    if (frame_type == @intFromEnum(FrameType.ack) or frame_type == @intFromEnum(FrameType.ack_ecn)) {
        return .{ .ack = try parseAckFrame(allocator, cursor, frame_type == @intFromEnum(FrameType.ack_ecn)) };
    }

    if (frame_type == @intFromEnum(FrameType.reset_stream)) {
        return .{ .reset_stream = .{
            .stream_id = try varint.decode(cursor),
            .application_error_code = try varint.decode(cursor),
            .final_size = try varint.decode(cursor),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.stop_sending)) {
        return .{ .stop_sending = .{
            .stream_id = try varint.decode(cursor),
            .application_error_code = try varint.decode(cursor),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.new_token)) {
        const len = try usizeFromVarint(try varint.decode(cursor));
        if (len == 0) return error.InvalidFrame;
        return .{ .new_token = .{ .token = try cursor.readSlice(len) } };
    }

    if (frame_type == @intFromEnum(FrameType.crypto)) {
        const offset = try varint.decode(cursor);
        const len = try usizeFromVarint(try varint.decode(cursor));
        try validateEndOffset(offset, len);
        return .{ .crypto = .{ .offset = offset, .data = try cursor.readSlice(len) } };
    }

    if (frame_type == @intFromEnum(FrameType.max_data)) {
        return .{ .max_data = .{ .maximum_data = try varint.decode(cursor) } };
    }

    if (frame_type == @intFromEnum(FrameType.max_stream_data)) {
        return .{ .max_stream_data = .{
            .stream_id = try varint.decode(cursor),
            .maximum_stream_data = try varint.decode(cursor),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.max_streams_bidi)) return .{ .max_streams_bidi = .{ .maximum_streams = try varint.decode(cursor) } };
    if (frame_type == @intFromEnum(FrameType.max_streams_uni)) return .{ .max_streams_uni = .{ .maximum_streams = try varint.decode(cursor) } };
    if (frame_type == @intFromEnum(FrameType.data_blocked)) return .{ .data_blocked = .{ .maximum_data = try varint.decode(cursor) } };

    if (frame_type == @intFromEnum(FrameType.stream_data_blocked)) {
        return .{ .stream_data_blocked = .{
            .stream_id = try varint.decode(cursor),
            .maximum_stream_data = try varint.decode(cursor),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.streams_blocked_bidi)) return .{ .streams_blocked_bidi = .{ .maximum_streams = try varint.decode(cursor) } };
    if (frame_type == @intFromEnum(FrameType.streams_blocked_uni)) return .{ .streams_blocked_uni = .{ .maximum_streams = try varint.decode(cursor) } };

    if (frame_type == @intFromEnum(FrameType.new_connection_id)) {
        const sequence_number = try varint.decode(cursor);
        const retire_prior_to = try varint.decode(cursor);
        if (retire_prior_to > sequence_number) return error.InvalidFrame;
        const connection_id_len = try cursor.readByte();
        try validateConnectionIdLen(connection_id_len);
        const cid = try cursor.readSlice(connection_id_len);
        const stateless_reset_token = (try cursor.readSlice(16))[0..16].*;
        return .{ .new_connection_id = .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = cid,
            .stateless_reset_token = stateless_reset_token,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.retire_connection_id)) {
        return .{ .retire_connection_id = .{ .sequence_number = try varint.decode(cursor) } };
    }

    if (frame_type == @intFromEnum(FrameType.path_challenge)) return .{ .path_challenge = .{ .data = (try cursor.readSlice(8))[0..8].* } };
    if (frame_type == @intFromEnum(FrameType.path_response)) return .{ .path_response = .{ .data = (try cursor.readSlice(8))[0..8].* } };

    if (FrameType.isStream(frame_type)) {
        const has_offset = (frame_type & 0x04) != 0;
        const has_length = (frame_type & 0x02) != 0;
        const stream_id = try varint.decode(cursor);
        const offset = if (has_offset) try varint.decode(cursor) else 0;
        const len = if (has_length) try usizeFromVarint(try varint.decode(cursor)) else cursor.remaining();
        try validateEndOffset(offset, len);
        return .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .fin = (frame_type & 0x01) != 0,
            .data = try cursor.readSlice(len),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.connection_close)) {
        const error_code = try varint.decode(cursor);
        const triggering_frame_type = try varint.decode(cursor);
        const reason_len = try usizeFromVarint(try varint.decode(cursor));
        return .{ .connection_close = .{
            .error_code = error_code,
            .frame_type = triggering_frame_type,
            .reason_phrase = try cursor.readSlice(reason_len),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.connection_close_app)) {
        const error_code = try varint.decode(cursor);
        const reason_len = try usizeFromVarint(try varint.decode(cursor));
        return .{ .application_close = .{
            .error_code = error_code,
            .reason_phrase = try cursor.readSlice(reason_len),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.handshake_done)) return .{ .handshake_done = {} };

    if (frame_type == @intFromEnum(FrameType.datagram)) {
        const payload = packet_payload[cursor.pos..];
        cursor.pos = packet_payload.len;
        return .{ .datagram = .{ .data = payload, .length_present = false } };
    }

    if (frame_type == @intFromEnum(FrameType.datagram_len)) {
        const len = try usizeFromVarint(try varint.decode(cursor));
        return .{ .datagram = .{ .data = try cursor.readSlice(len), .length_present = true } };
    }

    return error.UnsupportedFrameType;
}

fn parseAckFrame(allocator: ?std.mem.Allocator, cursor: *wire.Cursor, has_ecn: bool) Error!AckFrame {
    const largest_acknowledged = try varint.decode(cursor);
    const ack_delay = try varint.decode(cursor);
    const range_count = try usizeFromVarint(try varint.decode(cursor));
    const first_ack_range = try varint.decode(cursor);

    const ranges: []AckRange = if (allocator) |gpa| try gpa.alloc(AckRange, range_count) else ranges: {
        if (range_count != 0) return error.InvalidAckRange;
        break :ranges &.{};
    };
    errdefer if (allocator) |gpa| gpa.free(ranges);
    for (ranges) |*range| {
        range.* = .{
            .gap = try varint.decode(cursor),
            .ack_range_length = try varint.decode(cursor),
        };
    }

    const ecn_counts: ?EcnCounts = if (has_ecn) .{
        .ect0_count = try varint.decode(cursor),
        .ect1_count = try varint.decode(cursor),
        .ecn_ce_count = try varint.decode(cursor),
    } else null;

    return .{
        .largest_acknowledged = largest_acknowledged,
        .ack_delay = ack_delay,
        .first_ack_range = first_ack_range,
        .ranges = ranges,
        .ecn_counts = ecn_counts,
    };
}

fn writeAckFields(list: *std.ArrayList(u8), allocator: std.mem.Allocator, ack: AckFrame) Error!void {
    try varint.encode(list, allocator, ack.largest_acknowledged);
    try varint.encode(list, allocator, ack.ack_delay);
    try varint.encode(list, allocator, ack.ranges.len);
    try varint.encode(list, allocator, ack.first_ack_range);
    for (ack.ranges) |range| {
        try varint.encode(list, allocator, range.gap);
        try varint.encode(list, allocator, range.ack_range_length);
    }
    if (ack.ecn_counts) |ecn| {
        try varint.encode(list, allocator, ecn.ect0_count);
        try varint.encode(list, allocator, ecn.ect1_count);
        try varint.encode(list, allocator, ecn.ecn_ce_count);
    }
}

fn writeSingleVarintFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64, value: u64) Error!void {
    try varint.encode(list, allocator, frame_type);
    try varint.encode(list, allocator, value);
}

fn usizeFromVarint(value: u64) Error!usize {
    return std.math.cast(usize, value) orelse error.IntegerOverflow;
}

fn validateEndOffset(offset: u64, data_len: usize) Error!void {
    const data_len_u64 = std.math.cast(u64, data_len) orelse return error.InvalidFrameLength;
    const end = std.math.add(u64, offset, data_len_u64) catch return error.InvalidFrameLength;
    if (end > varint.max_value) return error.InvalidFrameLength;
}

fn validateConnectionIdLen(len: usize) Error!void {
    if (len == 0 or len > 20) return error.InvalidConnectionIdLength;
}

comptime {
    _ = varint;
}

test {
    _ = runtime;
    _ = protection;
    _ = crypto_stream;
    _ = initial_exchange;
    _ = tls_client_hello;
    _ = handshake;
    _ = one_rtt;
    _ = packet_space;
    _ = stream_state;
    _ = flow_control;
    _ = recovery;
    _ = connection_router;
    _ = connection_id;
    _ = stateless_reset;
    _ = congestion;
    _ = path_validation;
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

test "QUIC typed transport parameters roundtrip and validate" {
    const allocator = std.testing.allocator;
    const client_cid = [_]u8{ 1, 2, 3, 4 };
    const params = TransportParameters{
        .max_udp_payload_size = 1400,
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 1024,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 4,
        .ack_delay_exponent = 10,
        .max_ack_delay = 50,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = &client_cid,
        .max_datagram_frame_size = 1200,
    };

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try encodeTransportParameters(&bytes, allocator, params);
    const decoded = try parseTransportParametersTyped(allocator, bytes.items, .client);

    try std.testing.expectEqual(@as(u64, 1400), decoded.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 4096), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 2048), decoded.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 10), decoded.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 50), decoded.max_ack_delay);
    try std.testing.expectEqual(@as(u64, 4), decoded.active_connection_id_limit);
    try std.testing.expectEqual(@as(?u64, 1200), decoded.max_datagram_frame_size);
    try std.testing.expectEqualSlices(u8, &client_cid, decoded.initial_source_connection_id.?);

    var duplicate: std.ArrayList(u8) = .empty;
    defer duplicate.deinit(allocator);
    try encodeTransportParameter(&duplicate, allocator, @intFromEnum(TransportParameterId.max_idle_timeout), &.{1});
    try encodeTransportParameter(&duplicate, allocator, @intFromEnum(TransportParameterId.max_idle_timeout), &.{2});
    try std.testing.expectError(error.DuplicateTransportParameter, parseTransportParametersTyped(allocator, duplicate.items, .client));

    var invalid_udp: std.ArrayList(u8) = .empty;
    defer invalid_udp.deinit(allocator);
    try encodeTransportParameter(&invalid_udp, allocator, @intFromEnum(TransportParameterId.max_udp_payload_size), &.{1});
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, invalid_udp.items, .client));

    var forbidden: std.ArrayList(u8) = .empty;
    defer forbidden.deinit(allocator);
    const token = [_]u8{0xaa} ** 16;
    try encodeTransportParameter(&forbidden, allocator, @intFromEnum(TransportParameterId.stateless_reset_token), &token);
    try std.testing.expectError(error.TransportParameterForbidden, parseTransportParametersTyped(allocator, forbidden.items, .client));
}

test "QUIC server transport parameters include preferred address" {
    const allocator = std.testing.allocator;
    const original_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const server_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const preferred_cid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const token = [_]u8{0x99} ** 16;
    const params = TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .stateless_reset_token = token,
        .preferred_address = .{
            .ipv4_address = .{ 127, 0, 0, 1 },
            .ipv4_port = 4433,
            .connection_id = &preferred_cid,
            .stateless_reset_token = token,
        },
        .active_connection_id_limit = 4,
        .initial_source_connection_id = &server_cid,
    };

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try encodeTransportParameters(&bytes, allocator, params);
    const decoded = try parseTransportParametersTyped(allocator, bytes.items, .server);

    try std.testing.expectEqualSlices(u8, &original_dcid, decoded.original_destination_connection_id.?);
    try std.testing.expectEqualSlices(u8, &server_cid, decoded.initial_source_connection_id.?);
    try std.testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);
    try std.testing.expectEqual(@as(u16, 4433), decoded.preferred_address.?.ipv4_port);
    try std.testing.expectEqualSlices(u8, &preferred_cid, decoded.preferred_address.?.connection_id);
}

test "QUIC stream and crypto frame codec" {
    const allocator = std.testing.allocator;

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try (Frame{ .stream = .{ .stream_id = 7, .offset = 64, .fin = true, .data = "hello" } }).write(&stream_bytes, allocator);
    const parsed_stream = try parseFrame(stream_bytes.items);
    try std.testing.expectEqual(@as(usize, stream_bytes.items.len), parsed_stream.consumed);
    try std.testing.expectEqual(@as(u64, 7), parsed_stream.frame.stream.stream_id);
    try std.testing.expectEqual(@as(u64, 64), parsed_stream.frame.stream.offset);
    try std.testing.expect(parsed_stream.frame.stream.fin);
    try std.testing.expectEqualStrings("hello", parsed_stream.frame.stream.data);

    var crypto_bytes: std.ArrayList(u8) = .empty;
    defer crypto_bytes.deinit(allocator);
    try (Frame{ .crypto = .{ .offset = 0, .data = "tls" } }).write(&crypto_bytes, allocator);
    const parsed_crypto = try parseFrame(crypto_bytes.items);
    try std.testing.expectEqualStrings("tls", parsed_crypto.frame.crypto.data);
}

test "QUIC ack close datagram and padding frames" {
    const allocator = std.testing.allocator;
    var ack_bytes: std.ArrayList(u8) = .empty;
    defer ack_bytes.deinit(allocator);
    try (Frame{ .ack = .{
        .largest_acknowledged = 10,
        .ack_delay = 1,
        .first_ack_range = 10,
        .ecn_counts = .{ .ect0_count = 1, .ect1_count = 2, .ecn_ce_count = 3 },
    } }).write(&ack_bytes, allocator);
    const ack = try parseFrame(ack_bytes.items);
    try std.testing.expectEqual(@as(u64, 10), ack.frame.ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 3), ack.frame.ack.ecn_counts.?.ecn_ce_count);

    var close_bytes: std.ArrayList(u8) = .empty;
    defer close_bytes.deinit(allocator);
    try (Frame{ .connection_close = .{ .error_code = 0, .frame_type = @intFromEnum(FrameType.stream), .reason_phrase = "done" } }).write(&close_bytes, allocator);
    const close = try parseFrame(close_bytes.items);
    try std.testing.expectEqualStrings("done", close.frame.connection_close.reason_phrase);

    var datagram_bytes: std.ArrayList(u8) = .empty;
    defer datagram_bytes.deinit(allocator);
    try (Frame{ .datagram = .{ .data = "dgram", .length_present = false } }).write(&datagram_bytes, allocator);
    const datagram = try parseFrame(datagram_bytes.items);
    try std.testing.expect(!datagram.frame.datagram.length_present);
    try std.testing.expectEqualStrings("dgram", datagram.frame.datagram.data);

    const padding = try parseFrame(&.{ 0, 0, 0, @intFromEnum(FrameType.ping) });
    try std.testing.expectEqual(@as(usize, 3), padding.frame.padding.len);
    try std.testing.expectEqual(@as(usize, 3), padding.consumed);
}

test "QUIC ACK frame owned parser preserves sparse ranges" {
    const allocator = std.testing.allocator;
    const ranges = [_]AckRange{
        .{ .gap = 0, .ack_range_length = 1 },
        .{ .gap = 2, .ack_range_length = 0 },
    };
    const frame = Frame{ .ack = .{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    } };

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try frame.write(&bytes, allocator);

    try std.testing.expectError(error.InvalidAckRange, parseFrame(bytes.items));
    var parsed = try parseFrameOwned(allocator, bytes.items);
    defer parsed.deinitOwned(allocator);

    try std.testing.expectEqual(@as(u64, 10), parsed.frame.ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), parsed.frame.ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), parsed.frame.ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), parsed.frame.ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 1), parsed.frame.ack.ranges[0].ack_range_length);
    try std.testing.expectEqual(@as(u64, 2), parsed.frame.ack.ranges[1].gap);
    try std.testing.expectEqual(@as(u64, 0), parsed.frame.ack.ranges[1].ack_range_length);
}

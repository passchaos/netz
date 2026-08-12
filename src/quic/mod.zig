const std = @import("std");
const wire = @import("../internal/wire.zig");
const vail = @import("vail");

pub const varint = @import("varint.zig");
pub const runtime = @import("runtime.zig");
pub const protection = @import("protection.zig");
pub const crypto_stream = @import("crypto_stream.zig");
pub const initial_exchange = @import("initial_exchange.zig");
pub const tls_client_hello = @import("tls_client_hello.zig");
pub const tls = @import("tls/mod.zig");
pub const handshake = @import("handshake.zig");
pub const zero_rtt = @import("zero_rtt/mod.zig");
pub const one_rtt = @import("one_rtt.zig");
pub const packet_space = @import("packet_space.zig");
pub const stream_state = @import("stream.zig");
pub const flow_control = @import("flow_control.zig");
pub const recovery = @import("recovery.zig");
pub const connection_router = @import("connection_router.zig");
pub const endpoint_timers = @import("endpoint_timers.zig");
pub const connection_id = @import("connection_id.zig");
pub const stateless_reset = @import("stateless_reset.zig");
pub const congestion = @import("congestion.zig");
pub const pacing = @import("pacing.zig");
pub const hystart = @import("hystart.zig");
pub const path_validation = @import("path_validation.zig");
pub const rtt = @import("rtt.zig");
pub const pmtu = @import("pmtu.zig");
pub const address_validation_token = @import("address_validation_token.zig");
pub const retry_flow = @import("retry_flow.zig");
pub const version_negotiation = @import("version_negotiation.zig");
pub const qlog = @import("observability/qlog/mod.zig");
pub const keylog = @import("observability/keylog/mod.zig");
pub const quic_lb = @import("load_balancing/quic_lb/mod.zig");
pub const resumption = @import("resumption/mod.zig");

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
    InvalidVersionNegotiation,
} || std.mem.Allocator.Error;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

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

pub const retry_integrity_tag_len = 16;

const retry_integrity_key_v1: [Aes128Gcm.key_length]u8 = .{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const retry_integrity_nonce_v1: [Aes128Gcm.nonce_length]u8 = .{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };
const retry_integrity_key_v2: [Aes128Gcm.key_length]u8 = .{ 0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92 };
const retry_integrity_nonce_v2: [Aes128Gcm.nonce_length]u8 = .{ 0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a };

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
    retry_integrity_tag: ?[retry_integrity_tag_len]u8 = null,

    pub fn parse(bytes: []const u8) Error!LongHeader {
        return parseWithFixedBitPolicy(bytes, false);
    }

    pub fn parseWithFixedBitPolicy(
        bytes: []const u8,
        allow_zero_fixed_bit: bool,
    ) Error!LongHeader {
        var cursor = wire.Cursor.init(bytes);
        const first = try cursor.readByte();
        if ((first & 0x80) == 0) return error.InvalidEncoding;
        // RFC 9000 §17.2 requires the fixed bit to be set on long-header
        // packets.  Version Negotiation is parsed by parseVersionNegotiationPacket
        // because its first byte is intentionally version-independent; all other
        // long-header parsers should fail closed instead of letting random UDP
        // traffic or ossification probes advance into packet-type-specific logic.
        if (!allow_zero_fixed_bit and (first & 0x40) == 0) {
            return error.InvalidEncoding;
        }
        const version_value = try cursor.readInt(u32, .big);
        if (version_value == Version.negotiation.wireValue()) return error.InvalidVersionNegotiation;
        const dcid_len = try cursor.readByte();
        try validatePacketConnectionIdLen(dcid_len);
        const dcid = try cursor.readSlice(dcid_len);
        const scid_len = try cursor.readByte();
        try validatePacketConnectionIdLen(scid_len);
        const scid = try cursor.readSlice(scid_len);
        const packet_type = longHeaderPacketType(first, version_value);
        var token: []const u8 = &.{};
        var payload_len: ?u64 = null;
        var packet_number: []const u8 = &.{};
        var retry_tag: ?[retry_integrity_tag_len]u8 = null;
        if (packet_type == .initial) {
            const token_len = try varint.decode(&cursor);
            token = try cursor.readSlice(std.math.cast(usize, token_len) orelse return error.IntegerOverflow);
            payload_len = try varint.decode(&cursor);
            const pn_len: usize = @as(usize, (first & 0x03)) + 1;
            try validateLongHeaderPayloadBounds(bytes.len, cursor.pos, payload_len.?, pn_len);
            packet_number = try cursor.readSlice(pn_len);
        } else if (packet_type == .zero_rtt or packet_type == .handshake) {
            payload_len = try varint.decode(&cursor);
            const pn_len: usize = @as(usize, (first & 0x03)) + 1;
            try validateLongHeaderPayloadBounds(bytes.len, cursor.pos, payload_len.?, pn_len);
            packet_number = try cursor.readSlice(pn_len);
        } else if (packet_type == .retry) {
            const remaining = bytes[cursor.pos..];
            if (remaining.len < retry_integrity_tag_len) return error.BufferTooShort;
            token = remaining[0 .. remaining.len - retry_integrity_tag_len];
            if (token.len == 0) return error.InvalidFrame;
            retry_tag = remaining[remaining.len - retry_integrity_tag_len ..][0..retry_integrity_tag_len].*;
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
            .retry_integrity_tag = retry_tag,
        };
    }
};

fn validateLongHeaderPayloadBounds(datagram_len: usize, payload_offset: usize, payload_len: u64, pn_len: usize) Error!void {
    const payload_len_usize = std.math.cast(usize, payload_len) orelse return error.IntegerOverflow;
    if (payload_len_usize < pn_len) return error.InvalidFrameLength;
    const packet_end = std.math.add(usize, payload_offset, payload_len_usize) catch return error.IntegerOverflow;
    if (datagram_len < packet_end) return error.BufferTooShort;
}

pub const RetryPacket = struct {
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8,
    integrity_tag: [retry_integrity_tag_len]u8,
    consumed: usize,
};

pub const RetryPacketOptions = struct {
    version: u32 = Version.version_1.wireValue(),
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8,
    original_destination_connection_id: []const u8,
    /// RFC 9000 leaves Retry's four low bits unused; allowing callers to set
    /// them makes exact interop/vector testing possible while the default uses
    /// all ones like RFC 9001 Appendix A.4.
    type_specific_bits: u4 = 0x0f,
};

pub const VersionNegotiationPacket = struct {
    first_byte: u8,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    versions: []u32,

    pub fn deinit(self: *VersionNegotiationPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.versions);
        self.* = undefined;
    }
};

pub const VersionNegotiationPacketOptions = struct {
    first_byte: u8 = 0x80,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    versions: []const u32,
};

pub fn parseVersionNegotiationPacket(allocator: std.mem.Allocator, bytes: []const u8) Error!VersionNegotiationPacket {
    var cursor = wire.Cursor.init(bytes);
    const first = try cursor.readByte();
    if ((first & 0x80) == 0) return error.InvalidVersionNegotiation;
    const version = try cursor.readInt(u32, .big);
    if (version != Version.negotiation.wireValue()) return error.InvalidVersionNegotiation;
    const dcid_len = try cursor.readByte();
    try validatePacketConnectionIdLen(dcid_len);
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    try validatePacketConnectionIdLen(scid_len);
    const scid = try cursor.readSlice(scid_len);
    if (cursor.remaining() == 0 or (cursor.remaining() % 4) != 0) return error.InvalidVersionNegotiation;
    const version_count = cursor.remaining() / 4;
    const versions = try allocator.alloc(u32, version_count);
    errdefer allocator.free(versions);
    for (versions) |*out| {
        const value = try cursor.readInt(u32, .big);
        if (value == Version.negotiation.wireValue()) return error.InvalidVersionNegotiation;
        out.* = value;
    }
    return .{
        .first_byte = first,
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .versions = versions,
    };
}

pub fn writeVersionNegotiationPacket(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: VersionNegotiationPacketOptions,
) Error!void {
    if ((options.first_byte & 0x80) == 0) return error.InvalidVersionNegotiation;
    try validatePacketConnectionIdLen(options.destination_connection_id.len);
    try validatePacketConnectionIdLen(options.source_connection_id.len);
    if (options.versions.len == 0) return error.InvalidVersionNegotiation;
    for (options.versions) |version| {
        if (version == Version.negotiation.wireValue()) return error.InvalidVersionNegotiation;
    }
    const versions_len = std.math.mul(usize, options.versions.len, 4) catch
        return error.InvalidVersionNegotiation;
    var total_len: usize = 1 + 4 + 1 + 1;
    total_len = try addWireLen(total_len, options.destination_connection_id.len);
    total_len = try addWireLen(total_len, options.source_connection_id.len);
    total_len = try addWireLen(total_len, versions_len);
    try list.ensureUnusedCapacity(allocator, total_len);
    list.appendAssumeCapacity(options.first_byte);
    appendU32AssumeCapacity(list, Version.negotiation.wireValue());
    list.appendAssumeCapacity(@intCast(options.destination_connection_id.len));
    list.appendSliceAssumeCapacity(options.destination_connection_id);
    list.appendAssumeCapacity(@intCast(options.source_connection_id.len));
    list.appendSliceAssumeCapacity(options.source_connection_id);
    for (options.versions) |version| appendU32AssumeCapacity(list, version);
}

pub fn parseRetryPacket(bytes: []const u8) Error!RetryPacket {
    const header = try LongHeader.parse(bytes);
    if (header.packet_type != .retry) return error.InvalidFrame;
    return .{
        .version = header.version,
        .destination_connection_id = header.destination_connection_id,
        .source_connection_id = header.source_connection_id,
        .token = header.token,
        .integrity_tag = header.retry_integrity_tag orelse return error.InvalidFrame,
        .consumed = bytes.len,
    };
}

pub fn writeRetryPacket(list: *std.ArrayList(u8), allocator: std.mem.Allocator, options: RetryPacketOptions) Error!void {
    _ = try retryIntegrityProfile(options.version);
    try validatePacketConnectionIdLen(options.destination_connection_id.len);
    try validatePacketConnectionIdLen(options.source_connection_id.len);
    try validatePacketConnectionIdLen(options.original_destination_connection_id.len);
    if (options.token.len == 0) return error.InvalidFrame;

    const start = list.items.len;
    const type_bits = longHeaderPacketTypeBits(options.version, .retry);
    var retry_len: usize = 1 + 4 + 1 + 1 + retry_integrity_tag_len;
    retry_len = try addWireLen(retry_len, options.destination_connection_id.len);
    retry_len = try addWireLen(retry_len, options.source_connection_id.len);
    retry_len = try addWireLen(retry_len, options.token.len);
    try list.ensureUnusedCapacity(allocator, retry_len);
    list.appendAssumeCapacity(0x80 | 0x40 | (type_bits << 4) | @as(u8, options.type_specific_bits));
    appendU32AssumeCapacity(list, options.version);
    list.appendAssumeCapacity(@intCast(options.destination_connection_id.len));
    list.appendSliceAssumeCapacity(options.destination_connection_id);
    list.appendAssumeCapacity(@intCast(options.source_connection_id.len));
    list.appendSliceAssumeCapacity(options.source_connection_id);
    list.appendSliceAssumeCapacity(options.token);

    const tag = try retryIntegrityTag(allocator, options.original_destination_connection_id, list.items[start..]);
    list.appendSliceAssumeCapacity(&tag);
}

pub fn retryIntegrityTag(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_without_integrity_tag: []const u8,
) Error![retry_integrity_tag_len]u8 {
    try validatePacketConnectionIdLen(original_destination_connection_id.len);
    if (retry_without_integrity_tag.len < 1 + 4 + 2) return error.BufferTooShort;

    const version = std.mem.readInt(u32, retry_without_integrity_tag[1..5], .big);
    const profile = try retryIntegrityProfile(version);
    const pseudo_len = std.math.add(usize, 1 + original_destination_connection_id.len, retry_without_integrity_tag.len) catch return error.IntegerOverflow;
    const pseudo_packet = try allocator.alloc(u8, pseudo_len);
    defer allocator.free(pseudo_packet);
    pseudo_packet[0] = @intCast(original_destination_connection_id.len);
    @memcpy(pseudo_packet[1..][0..original_destination_connection_id.len], original_destination_connection_id);
    @memcpy(pseudo_packet[1 + original_destination_connection_id.len ..], retry_without_integrity_tag);

    const plaintext: [0]u8 = .{};
    var ciphertext: [0]u8 = .{};
    var tag: [retry_integrity_tag_len]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, &plaintext, pseudo_packet, profile.nonce, profile.key);
    return tag;
}

pub fn verifyRetryIntegrityTag(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_datagram: []const u8,
) Error!bool {
    if (retry_datagram.len < retry_integrity_tag_len) return false;
    const retry_without_tag = retry_datagram[0 .. retry_datagram.len - retry_integrity_tag_len];
    const expected = try retryIntegrityTag(allocator, original_destination_connection_id, retry_without_tag);
    const received = retry_datagram[retry_datagram.len - retry_integrity_tag_len ..][0..retry_integrity_tag_len].*;
    return vail.crypto.mac.verifyTruncated(
        retry_integrity_tag_len,
        expected,
        received,
    );
}

fn longHeaderPacketType(first_byte: u8, version: u32) PacketType {
    const bits: u2 = @truncate((first_byte >> 4) & 0x03);
    if (version == Version.version_2.wireValue()) {
        return switch (bits) {
            0 => .retry,
            1 => .initial,
            2 => .zero_rtt,
            3 => .handshake,
        };
    }
    return @enumFromInt(bits);
}

fn longHeaderPacketTypeBits(version: u32, packet_type: PacketType) u8 {
    if (version == Version.version_2.wireValue()) {
        return switch (packet_type) {
            .retry => 0,
            .initial => 1,
            .zero_rtt => 2,
            .handshake => 3,
        };
    }
    return @intFromEnum(packet_type);
}

fn retryIntegrityProfile(version: u32) Error!struct { key: [Aes128Gcm.key_length]u8, nonce: [Aes128Gcm.nonce_length]u8 } {
    if (version == Version.version_2.wireValue()) {
        return .{ .key = retry_integrity_key_v2, .nonce = retry_integrity_nonce_v2 };
    }
    if (version == Version.version_1.wireValue()) {
        return .{ .key = retry_integrity_key_v1, .nonce = retry_integrity_nonce_v1 };
    }
    return error.InvalidVersionNegotiation;
}

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
    version_information = 0x11,
    max_datagram_frame_size = 0x20,
    grease_quic_bit = 0x2ab2,
    min_ack_delay = 0xff04de1b,
    _,
};

pub fn isReservedTransportParameterId(id: u64) bool {
    // RFC 9000 reserves identifiers of the form 31*N+27 for transport-parameter
    // greasing.  Mature stacks such as quicz expose an explicit encoder for
    // these values so endpoints can verify peers ignore unknown parameters
    // without accidentally greasing with a real extension identifier.
    return id <= varint.max_value and id % 31 == 27;
}

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
pub const max_idle_timeout_ms_cap: u64 = @as(u64, 1) << 32;
pub const max_stream_count: u64 = 1 << 60;

pub const PreferredAddress = struct {
    ipv4_address: [4]u8 = [_]u8{0} ** 4,
    ipv4_port: u16 = 0,
    ipv6_address: [16]u8 = [_]u8{0} ** 16,
    ipv6_port: u16 = 0,
    connection_id: []const u8 = &.{},
    stateless_reset_token: [16]u8 = [_]u8{0} ** 16,
};

/// RFC 9368 version_information transport parameter value.
///
/// The available-version list is kept as borrowed network-order bytes so typed
/// transport-parameter parsing remains allocation-free like the rest of this
/// module.  Helpers below expose typed iteration for validation and selection.
pub const VersionInformation = struct {
    chosen_version: Version,
    available_versions_wire: []const u8 = &.{},

    pub fn availableVersionCount(self: VersionInformation) usize {
        return self.available_versions_wire.len / 4;
    }

    pub fn availableVersionAt(self: VersionInformation, index: usize) ?Version {
        if (index >= self.availableVersionCount()) return null;
        const start = index * 4;
        return @enumFromInt(std.mem.readInt(u32, self.available_versions_wire[start..][0..4], .big));
    }

    pub fn containsAvailableVersion(self: VersionInformation, version: Version) bool {
        var i: usize = 0;
        while (i < self.availableVersionCount()) : (i += 1) {
            const available = self.availableVersionAt(i) orelse return false;
            if (available.wireValue() == version.wireValue()) return true;
        }
        return false;
    }
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
    version_information: ?VersionInformation = null,
    max_datagram_frame_size: ?u64 = null,
    /// RFC 9287 support advertisement. Presence is encoded as an empty value.
    grease_quic_bit: bool = false,
    min_ack_delay: ?u64 = null,
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

/// Encodes QUIC transport parameters advertised by `source`.
///
/// RFC 9000 defines several parameters as server-only.  Production stacks such
/// as tquic gate those parameters during encoding as well as decoding so a
/// misconfigured client cannot emit an extension block the peer must reject.
/// Validate the complete typed set before appending anything; callers can rely
/// on `list` remaining untouched when directionality validation fails.
pub fn encodeTransportParametersForSource(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    params: TransportParameters,
    source: TransportParameterSource,
) Error!void {
    try validateTransportParameters(params, source);
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
    if (params.version_information) |version_information| {
        try encodeVersionInformationTransportParameter(list, allocator, version_information);
    }
    if (params.max_datagram_frame_size) |size| try encodeIntegerTransportParameter(list, allocator, .max_datagram_frame_size, size);
    if (params.grease_quic_bit) {
        try encodeTransportParameter(
            list,
            allocator,
            @intFromEnum(TransportParameterId.grease_quic_bit),
            &.{},
        );
    }
    if (params.min_ack_delay) |delay| try encodeIntegerTransportParameter(list, allocator, .min_ack_delay, delay);
}

/// Legacy source-agnostic encoder retained for callers that already assemble
/// role-correct parameter sets.  Server semantics preserve compatibility with
/// existing users that include server-only parameters such as preferred_address.
pub fn encodeTransportParameters(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    params: TransportParameters,
) Error!void {
    try encodeTransportParametersForSource(list, allocator, params, .server);
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
    if (params.version_information) |version_information| try validateVersionInformation(version_information);

    try validateTransportInteger(.max_udp_payload_size, params.max_udp_payload_size);
    try validateTransportInteger(.initial_max_streams_bidi, params.initial_max_streams_bidi);
    try validateTransportInteger(.initial_max_streams_uni, params.initial_max_streams_uni);
    try validateTransportInteger(.ack_delay_exponent, params.ack_delay_exponent);
    try validateTransportInteger(.max_ack_delay, params.max_ack_delay);
    try validateTransportInteger(.active_connection_id_limit, params.active_connection_id_limit);
    if (params.max_datagram_frame_size) |size| try validateTransportInteger(.max_datagram_frame_size, size);
    if (params.min_ack_delay) |delay| try validateTransportInteger(.min_ack_delay, delay);
    try validateMinAckDelayBounds(params.max_ack_delay, params.min_ack_delay);
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
        } else if (id == @intFromEnum(TransportParameterId.version_information)) {
            params.version_information = try parseVersionInformation(value);
        } else if (id == @intFromEnum(TransportParameterId.max_datagram_frame_size)) {
            params.max_datagram_frame_size = try parseTransportInteger(.max_datagram_frame_size, value);
        } else if (id == @intFromEnum(TransportParameterId.grease_quic_bit)) {
            if (value.len != 0) return error.InvalidTransportParameterLength;
            params.grease_quic_bit = true;
        } else if (id == @intFromEnum(TransportParameterId.min_ack_delay)) {
            params.min_ack_delay = try parseTransportInteger(.min_ack_delay, value);
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
    const id_len = try varint.length(id);
    const value_len_len = try varint.length(value.len);
    const total_len = try addWireLen(try addWireLen(id_len, value_len_len), value.len);
    try list.ensureUnusedCapacity(allocator, total_len);
    try appendVarintAssumeCapacity(list, id);
    try appendVarintAssumeCapacity(list, value.len);
    list.appendSliceAssumeCapacity(value);
}

pub fn encodeReservedTransportParameter(list: *std.ArrayList(u8), allocator: std.mem.Allocator, id: u64, value: []const u8) !void {
    if (!isReservedTransportParameterId(id)) return error.InvalidTransportParameter;
    try encodeTransportParameter(list, allocator, id, value);
}

pub fn encodeVersionInformationFromVersions(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chosen_version: Version,
    available_versions: []const Version,
) Error!void {
    try validateChosenVersion(chosen_version);
    const value_len = std.math.add(
        usize,
        4,
        std.math.mul(usize, available_versions.len, 4) catch return error.InvalidTransportParameterLength,
    ) catch return error.InvalidTransportParameterLength;
    const id = @intFromEnum(TransportParameterId.version_information);
    const total_len = try addWireLen(try addWireLen(try varint.length(id), try varint.length(value_len)), value_len);
    try list.ensureUnusedCapacity(allocator, total_len);
    try appendVarintAssumeCapacity(list, id);
    try appendVarintAssumeCapacity(list, value_len);
    appendU32AssumeCapacity(list, chosen_version.wireValue());
    for (available_versions) |available| {
        try validateAvailableVersion(available);
        appendU32AssumeCapacity(list, available.wireValue());
    }
}

pub fn parseTransportParameters(allocator: std.mem.Allocator, bytes: []const u8) ![]TransportParameter {
    var cursor = wire.Cursor.init(bytes);
    var count: usize = 0;
    while (!cursor.eof()) {
        _ = try varint.decode(&cursor);
        const len = try varint.decode(&cursor);
        try cursor.skip(std.math.cast(usize, len) orelse return error.IntegerOverflow);
        count += 1;
    }

    const params = try allocator.alloc(TransportParameter, count);
    errdefer allocator.free(params);
    cursor = wire.Cursor.init(bytes);
    for (params) |*param| {
        const id = try varint.decode(&cursor);
        const len = try varint.decode(&cursor);
        const value = try cursor.readSlice(std.math.cast(usize, len) orelse return error.IntegerOverflow);
        param.* = .{ .id = id, .value = value };
    }
    return params;
}

fn encodeIntegerTransportParameter(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    id: TransportParameterId,
    value: u64,
) Error!void {
    try validateTransportInteger(id, value);
    var encoded: [8]u8 = undefined;
    const value_bytes = try varint.encodeInto(&encoded, value);
    try encodeTransportParameter(list, allocator, @intFromEnum(id), value_bytes);
}

fn encodePreferredAddressTransportParameter(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    preferred: PreferredAddress,
) Error!void {
    try validatePreferredAddress(preferred);

    const value_len = try addWireLen(41, preferred.connection_id.len);
    const id = @intFromEnum(TransportParameterId.preferred_address);
    const total_len = try addWireLen(try addWireLen(try varint.length(id), try varint.length(value_len)), value_len);
    try list.ensureUnusedCapacity(allocator, total_len);
    try appendVarintAssumeCapacity(list, id);
    try appendVarintAssumeCapacity(list, value_len);
    list.appendSliceAssumeCapacity(&preferred.ipv4_address);
    appendU16AssumeCapacity(list, preferred.ipv4_port);
    list.appendSliceAssumeCapacity(&preferred.ipv6_address);
    appendU16AssumeCapacity(list, preferred.ipv6_port);
    list.appendAssumeCapacity(@intCast(preferred.connection_id.len));
    list.appendSliceAssumeCapacity(preferred.connection_id);
    list.appendSliceAssumeCapacity(&preferred.stateless_reset_token);
}

fn encodeVersionInformationTransportParameter(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    version_information: VersionInformation,
) Error!void {
    try validateVersionInformation(version_information);
    const value_len = std.math.add(usize, 4, version_information.available_versions_wire.len) catch
        return error.InvalidTransportParameterLength;
    const id = @intFromEnum(TransportParameterId.version_information);
    const total_len = try addWireLen(try addWireLen(try varint.length(id), try varint.length(value_len)), value_len);
    try list.ensureUnusedCapacity(allocator, total_len);
    try appendVarintAssumeCapacity(list, id);
    try appendVarintAssumeCapacity(list, value_len);
    appendU32AssumeCapacity(list, version_information.chosen_version.wireValue());
    list.appendSliceAssumeCapacity(version_information.available_versions_wire);
}

fn parseVersionInformation(value: []const u8) Error!VersionInformation {
    if (value.len < 4 or (value.len % 4) != 0) return error.InvalidTransportParameterLength;
    const version_information = VersionInformation{
        .chosen_version = @enumFromInt(std.mem.readInt(u32, value[0..4], .big)),
        .available_versions_wire = value[4..],
    };
    try validateVersionInformation(version_information);
    return version_information;
}

fn validateVersionInformation(version_information: VersionInformation) Error!void {
    try validateChosenVersion(version_information.chosen_version);
    if ((version_information.available_versions_wire.len % 4) != 0) return error.InvalidTransportParameterLength;
    var i: usize = 0;
    while (i < version_information.availableVersionCount()) : (i += 1) {
        try validateAvailableVersion(version_information.availableVersionAt(i) orelse return error.InvalidTransportParameterLength);
    }
}

fn validateChosenVersion(version: Version) Error!void {
    if (version.wireValue() == Version.negotiation.wireValue() or isReservedVersionWire(version.wireValue())) {
        return error.InvalidTransportParameter;
    }
}

fn validateAvailableVersion(version: Version) Error!void {
    if (version.wireValue() == Version.negotiation.wireValue()) return error.InvalidTransportParameter;
}

pub fn isReservedVersionWire(version: u32) bool {
    return (version & 0x0f0f0f0f) == 0x0a0a0a0a;
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
        .max_idle_timeout => {
            if (value > max_idle_timeout_ms_cap) return error.InvalidTransportParameter;
        },
        .max_udp_payload_size => {
            if (value < 1200) return error.InvalidTransportParameter;
            if (value > default_max_udp_payload_size) return error.InvalidTransportParameter;
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

fn validateMinAckDelayBounds(max_ack_delay_ms: u64, min_ack_delay_us: ?u64) Error!void {
    const min_ack_delay = min_ack_delay_us orelse return;
    // ACK_FREQUENCY defines min_ack_delay in microseconds while QUIC's
    // max_ack_delay transport parameter is in milliseconds.  The extension only
    // works when the advertised minimum is no larger than the endpoint's own
    // maximum delayed-ACK timer.
    const max_ack_delay_us = std.math.mul(u64, max_ack_delay_ms, 1000) catch return error.InvalidTransportParameter;
    if (min_ack_delay > max_ack_delay_us) return error.InvalidTransportParameter;
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
    const has_ipv4 = !std.mem.eql(u8, &preferred.ipv4_address, &([_]u8{0} ** 4)) or preferred.ipv4_port != 0;
    const has_ipv6 = !std.mem.eql(u8, &preferred.ipv6_address, &([_]u8{0} ** 16)) or preferred.ipv6_port != 0;
    if (!has_ipv4 and !has_ipv6) return error.InvalidTransportParameter;
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
    immediate_ack = 0x1f,
    datagram = 0x30,
    datagram_len = 0x31,
    ack_frequency = 0xaf,
    _,

    pub fn known(value: u64) bool {
        if (FrameType.isStream(value)) return true;
        return switch (value) {
            @intFromEnum(FrameType.padding),
            @intFromEnum(FrameType.ping),
            @intFromEnum(FrameType.ack),
            @intFromEnum(FrameType.ack_ecn),
            @intFromEnum(FrameType.reset_stream),
            @intFromEnum(FrameType.stop_sending),
            @intFromEnum(FrameType.crypto),
            @intFromEnum(FrameType.new_token),
            @intFromEnum(FrameType.max_data),
            @intFromEnum(FrameType.max_stream_data),
            @intFromEnum(FrameType.max_streams_bidi),
            @intFromEnum(FrameType.max_streams_uni),
            @intFromEnum(FrameType.data_blocked),
            @intFromEnum(FrameType.stream_data_blocked),
            @intFromEnum(FrameType.streams_blocked_bidi),
            @intFromEnum(FrameType.streams_blocked_uni),
            @intFromEnum(FrameType.new_connection_id),
            @intFromEnum(FrameType.retire_connection_id),
            @intFromEnum(FrameType.path_challenge),
            @intFromEnum(FrameType.path_response),
            @intFromEnum(FrameType.connection_close),
            @intFromEnum(FrameType.connection_close_app),
            @intFromEnum(FrameType.handshake_done),
            @intFromEnum(FrameType.immediate_ack),
            @intFromEnum(FrameType.datagram),
            @intFromEnum(FrameType.datagram_len),
            @intFromEnum(FrameType.ack_frequency),
            => true,
            else => false,
        };
    }

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

pub const AckFrequencyFrame = struct {
    sequence_number: u64,
    ack_eliciting_threshold: u64,
    request_max_ack_delay: u64,
    reordering_threshold: u64,
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
    immediate_ack: void,
    datagram: DatagramFrame,
    ack_frequency: AckFrequencyFrame,

    pub fn wireLen(self: Frame) Error!usize {
        return switch (self) {
            .padding => |padding| padding.len,
            .ping => 1,
            .ack => |ack| try ackFrameWireLen(ack),
            .reset_stream => |reset| try tripleVarintFrameWireLen(@intFromEnum(FrameType.reset_stream), reset.stream_id, reset.application_error_code, reset.final_size),
            .stop_sending => |stop| try doubleVarintFrameWireLen(@intFromEnum(FrameType.stop_sending), stop.stream_id, stop.application_error_code),
            .new_token => |new_token| blk: {
                if (new_token.token.len == 0) return error.InvalidFrame;
                break :blk try singleVarintPayloadFrameWireLen(
                    @intFromEnum(FrameType.new_token),
                    new_token.token.len,
                    new_token.token.len,
                );
            },
            .crypto => |crypto| blk: {
                try validateEndOffset(crypto.offset, crypto.data.len);
                break :blk try doubleVarintPayloadFrameWireLen(
                    @intFromEnum(FrameType.crypto),
                    crypto.offset,
                    crypto.data.len,
                    crypto.data.len,
                );
            },
            .stream => |stream| blk: {
                try validateEndOffset(stream.offset, stream.data.len);
                break :blk try streamFrameWireLen(stream);
            },
            .max_data => |frame| try singleVarintFrameWireLen(@intFromEnum(FrameType.max_data), frame.maximum_data),
            .max_stream_data => |frame| try doubleVarintFrameWireLen(@intFromEnum(FrameType.max_stream_data), frame.stream_id, frame.maximum_stream_data),
            .max_streams_bidi => |frame| blk: {
                try validateStreamCount(frame.maximum_streams);
                break :blk try singleVarintFrameWireLen(@intFromEnum(FrameType.max_streams_bidi), frame.maximum_streams);
            },
            .max_streams_uni => |frame| blk: {
                try validateStreamCount(frame.maximum_streams);
                break :blk try singleVarintFrameWireLen(@intFromEnum(FrameType.max_streams_uni), frame.maximum_streams);
            },
            .data_blocked => |frame| try singleVarintFrameWireLen(@intFromEnum(FrameType.data_blocked), frame.maximum_data),
            .stream_data_blocked => |frame| try doubleVarintFrameWireLen(@intFromEnum(FrameType.stream_data_blocked), frame.stream_id, frame.maximum_stream_data),
            .streams_blocked_bidi => |frame| blk: {
                try validateStreamCount(frame.maximum_streams);
                break :blk try singleVarintFrameWireLen(@intFromEnum(FrameType.streams_blocked_bidi), frame.maximum_streams);
            },
            .streams_blocked_uni => |frame| blk: {
                try validateStreamCount(frame.maximum_streams);
                break :blk try singleVarintFrameWireLen(@intFromEnum(FrameType.streams_blocked_uni), frame.maximum_streams);
            },
            .new_connection_id => |frame| blk: {
                try validateConnectionIdLen(frame.connection_id.len);
                if (frame.retire_prior_to > frame.sequence_number) return error.InvalidFrame;
                break :blk try newConnectionIdFrameWireLen(frame);
            },
            .retire_connection_id => |frame| try singleVarintFrameWireLen(@intFromEnum(FrameType.retire_connection_id), frame.sequence_number),
            .path_challenge, .path_response => 9,
            .connection_close => |close| blk: {
                break :blk try tripleVarintPayloadFrameWireLen(
                    @intFromEnum(FrameType.connection_close),
                    close.error_code,
                    close.frame_type,
                    close.reason_phrase.len,
                    close.reason_phrase.len,
                );
            },
            .application_close => |close| blk: {
                break :blk try doubleVarintPayloadFrameWireLen(
                    @intFromEnum(FrameType.connection_close_app),
                    close.error_code,
                    close.reason_phrase.len,
                    close.reason_phrase.len,
                );
            },
            .handshake_done => 1,
            .immediate_ack => 1,
            .datagram => |datagram| blk: {
                break :blk try datagramFrameWireLen(datagram);
            },
            .ack_frequency => |frame| blk: {
                break :blk try ackFrequencyFrameWireLen(frame);
            },
        };
    }

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        switch (self) {
            .padding => |padding| try appendPadding(list, allocator, padding.len),
            .ping => try writeSingleByteFrame(list, allocator, @intFromEnum(FrameType.ping)),
            .ack => |ack| try writeAckFrame(list, allocator, ack),
            .reset_stream => |reset| {
                try writeTripleVarintFrame(list, allocator, @intFromEnum(FrameType.reset_stream), reset.stream_id, reset.application_error_code, reset.final_size);
            },
            .stop_sending => |stop| {
                try writeDoubleVarintFrame(list, allocator, @intFromEnum(FrameType.stop_sending), stop.stream_id, stop.application_error_code);
            },
            .new_token => |new_token| {
                if (new_token.token.len == 0) return error.InvalidFrame;
                try writeSingleVarintPayloadFrame(
                    list,
                    allocator,
                    @intFromEnum(FrameType.new_token),
                    new_token.token.len,
                    new_token.token,
                );
            },
            .crypto => |crypto| {
                try validateEndOffset(crypto.offset, crypto.data.len);
                try writeDoubleVarintPayloadFrame(
                    list,
                    allocator,
                    @intFromEnum(FrameType.crypto),
                    crypto.offset,
                    crypto.data.len,
                    crypto.data,
                );
            },
            .stream => |stream| {
                try validateEndOffset(stream.offset, stream.data.len);
                try writeStreamFrame(list, allocator, stream);
            },
            .max_data => |max_data| {
                try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.max_data), max_data.maximum_data);
            },
            .max_stream_data => |max_stream_data| {
                try writeDoubleVarintFrame(list, allocator, @intFromEnum(FrameType.max_stream_data), max_stream_data.stream_id, max_stream_data.maximum_stream_data);
            },
            .max_streams_bidi => |max_streams| {
                try validateStreamCount(max_streams.maximum_streams);
                try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.max_streams_bidi), max_streams.maximum_streams);
            },
            .max_streams_uni => |max_streams| {
                try validateStreamCount(max_streams.maximum_streams);
                try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.max_streams_uni), max_streams.maximum_streams);
            },
            .data_blocked => |blocked| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.data_blocked), blocked.maximum_data),
            .stream_data_blocked => |blocked| {
                try writeDoubleVarintFrame(list, allocator, @intFromEnum(FrameType.stream_data_blocked), blocked.stream_id, blocked.maximum_stream_data);
            },
            .streams_blocked_bidi => |blocked| {
                try validateStreamCount(blocked.maximum_streams);
                try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.streams_blocked_bidi), blocked.maximum_streams);
            },
            .streams_blocked_uni => |blocked| {
                try validateStreamCount(blocked.maximum_streams);
                try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.streams_blocked_uni), blocked.maximum_streams);
            },
            .new_connection_id => |new_connection_id| {
                try validateConnectionIdLen(new_connection_id.connection_id.len);
                if (new_connection_id.retire_prior_to > new_connection_id.sequence_number) return error.InvalidFrame;
                try writeNewConnectionIdFrame(list, allocator, new_connection_id);
            },
            .retire_connection_id => |retire| try writeSingleVarintFrame(list, allocator, @intFromEnum(FrameType.retire_connection_id), retire.sequence_number),
            .path_challenge => |path| {
                try writeFixedPathFrame(list, allocator, @intFromEnum(FrameType.path_challenge), path);
            },
            .path_response => |path| {
                try writeFixedPathFrame(list, allocator, @intFromEnum(FrameType.path_response), path);
            },
            .connection_close => |close| {
                try writeTripleVarintPayloadFrame(
                    list,
                    allocator,
                    @intFromEnum(FrameType.connection_close),
                    close.error_code,
                    close.frame_type,
                    close.reason_phrase.len,
                    close.reason_phrase,
                );
            },
            .application_close => |close| {
                try writeDoubleVarintPayloadFrame(
                    list,
                    allocator,
                    @intFromEnum(FrameType.connection_close_app),
                    close.error_code,
                    close.reason_phrase.len,
                    close.reason_phrase,
                );
            },
            .handshake_done => try writeSingleByteFrame(list, allocator, @intFromEnum(FrameType.handshake_done)),
            .immediate_ack => try writeSingleByteFrame(list, allocator, @intFromEnum(FrameType.immediate_ack)),
            .datagram => |datagram| {
                try writeDatagramFrame(list, allocator, datagram);
            },
            .ack_frequency => |ack_frequency| {
                try writeAckFrequencyFrame(list, allocator, ack_frequency);
            },
        }
    }
};

pub fn deinitOwnedFrame(frame: *Frame, allocator: std.mem.Allocator) void {
    switch (frame.*) {
        // `parseFrameOwned` allocates only non-empty ACK range slices because
        // the wire can carry an arbitrary number of sparse ranges.  Other frame
        // payload slices still borrow from the containing packet/datagram bytes.
        .ack => |ack| if (ack.ranges.len != 0) allocator.free(ack.ranges),
        else => {},
    }
    frame.* = undefined;
}

pub fn deinitOwnedFrameSlice(frames: []Frame, allocator: std.mem.Allocator) void {
    for (frames) |*frame| deinitOwnedFrame(frame, allocator);
}

fn addWireLen(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.InvalidFrameLength;
}

fn varintWireLen(values: []const u64) Error!usize {
    var len: usize = 0;
    for (values) |value| len = try addWireLen(len, try varint.length(value));
    return len;
}

fn singleVarintFrameWireLen(frame_type: u64, value: u64) Error!usize {
    std.debug.assert(frame_type <= 63);
    return addWireLen(1, try varint.length(value));
}

fn doubleVarintFrameWireLen(frame_type: u64, first: u64, second: u64) Error!usize {
    std.debug.assert(frame_type <= 63);
    const len = try addWireLen(1, try varint.length(first));
    return addWireLen(len, try varint.length(second));
}

fn tripleVarintFrameWireLen(frame_type: u64, first: u64, second: u64, third: u64) Error!usize {
    std.debug.assert(frame_type <= 63);
    var len = try addWireLen(1, try varint.length(first));
    len = try addWireLen(len, try varint.length(second));
    return addWireLen(len, try varint.length(third));
}

fn singleVarintPayloadFrameWireLen(frame_type: u64, value: u64, payload_len: usize) Error!usize {
    const len = try singleVarintFrameWireLen(frame_type, value);
    return addWireLen(len, payload_len);
}

fn doubleVarintPayloadFrameWireLen(frame_type: u64, first: u64, second: u64, payload_len: usize) Error!usize {
    const len = try doubleVarintFrameWireLen(frame_type, first, second);
    return addWireLen(len, payload_len);
}

fn tripleVarintPayloadFrameWireLen(frame_type: u64, first: u64, second: u64, third: u64, payload_len: usize) Error!usize {
    const len = try tripleVarintFrameWireLen(frame_type, first, second, third);
    return addWireLen(len, payload_len);
}

fn streamFrameWireLen(stream: StreamFrame) Error!usize {
    var len = try addWireLen(1, try varint.length(stream.stream_id));
    if (stream.offset != 0) len = try addWireLen(len, try varint.length(stream.offset));
    len = try addWireLen(len, try varint.length(stream.data.len));
    return addWireLen(len, stream.data.len);
}

fn datagramFrameWireLen(datagram: DatagramFrame) Error!usize {
    var len: usize = 1;
    if (datagram.length_present) len = try addWireLen(len, try varint.length(datagram.data.len));
    return addWireLen(len, datagram.data.len);
}

fn newConnectionIdFrameWireLen(frame: NewConnectionIdFrame) Error!usize {
    var len = try addWireLen(1, try varint.length(frame.sequence_number));
    len = try addWireLen(len, try varint.length(frame.retire_prior_to));
    len = try addWireLen(len, 1);
    len = try addWireLen(len, frame.connection_id.len);
    return addWireLen(len, frame.stateless_reset_token.len);
}

fn ackFrequencyFrameWireLen(frame: AckFrequencyFrame) Error!usize {
    try validateAckFrequencyFrame(frame);
    var len: usize = 2; // ACK_FREQUENCY uses a two-byte varint frame type.
    len = try addWireLen(len, try varint.length(frame.sequence_number));
    len = try addWireLen(len, try varint.length(frame.ack_eliciting_threshold));
    len = try addWireLen(len, try varint.length(frame.request_max_ack_delay));
    return addWireLen(len, try varint.length(frame.reordering_threshold));
}

pub const FramePacketType = enum {
    initial,
    handshake,
    zero_rtt,
    one_rtt,
};

pub const TransportErrorCode = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    version_negotiation_error = 0x11,
    _,
};

pub const FramePayloadCloseError = struct {
    code: TransportErrorCode,
    frame_type: u64,
    reason_phrase: []const u8,
};

pub fn frameAllowedInPacketType(frame: Frame, packet_type: FramePacketType) bool {
    return switch (packet_type) {
        .initial, .handshake => switch (frame) {
            .padding, .ping, .ack, .crypto, .connection_close => true,
            else => false,
        },
        .zero_rtt => switch (frame) {
            .padding,
            .ping,
            .reset_stream,
            .stop_sending,
            .stream,
            .max_data,
            .max_stream_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .stream_data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            .new_connection_id,
            .path_challenge,
            .connection_close,
            .application_close,
            .datagram,
            => true,
            // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, RETIRE_CONNECTION_ID,
            // PATH_RESPONSE, and the ACK_FREQUENCY draft control frames are
            // not 0-RTT frames.  NEW_CONNECTION_ID and CONNECTION_CLOSE remain
            // allowed by RFC 9000 Table 3 and mature stacks such as tquic and
            // quicz, while RETIRE_CONNECTION_ID can be treated as a 0-RTT
            // protocol violation under RFC 9000 §12.5.
            else => false,
        },
        .one_rtt => true,
    };
}

pub fn validateFrameForPacketType(frame: Frame, packet_type: FramePacketType) Error!void {
    if (!frameAllowedInPacketType(frame, packet_type)) return error.InvalidFrame;
}

pub fn classifyFramePayloadCloseError(
    allocator: std.mem.Allocator,
    payload: []const u8,
    packet_type: FramePacketType,
) Error!?FramePayloadCloseError {
    if (payload.len == 0) return .{
        .code = .protocol_violation,
        .frame_type = 0,
        .reason_phrase = "empty payload",
    };

    var pos: usize = 0;
    while (pos < payload.len) {
        const frame_type = rawFrameTypeValue(payload[pos..]);
        var parsed = parseFrameOwned(allocator, payload[pos..]) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{
                .code = frameDecodeTransportErrorCode(err) orelse return err,
                .frame_type = frame_type,
                .reason_phrase = "frame encoding",
            },
        };
        defer parsed.deinitOwned(allocator);

        if (!frameAllowedInPacketType(parsed.frame, packet_type)) return .{
            .code = .protocol_violation,
            .frame_type = frame_type,
            .reason_phrase = "packet type",
        };
        pos += parsed.consumed;
    }
    return null;
}

pub fn rawFrameTypeValue(bytes: []const u8) u64 {
    var cursor = wire.Cursor.init(bytes);
    return varint.decode(&cursor) catch 0;
}

pub fn frameDecodeTransportErrorCode(err: anyerror) ?TransportErrorCode {
    return switch (err) {
        error.UnsupportedFrameType,
        error.InvalidFrame,
        error.InvalidFrameLength,
        error.InvalidAckRange,
        error.InvalidConnectionIdLength,
        error.BufferTooShort,
        error.IntegerOverflow,
        error.VarIntTooLarge,
        error.MalformedVarInt,
        error.InvalidEncoding,
        => .frame_encoding_error,
        else => null,
    };
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
    const frame_type_len = varint.encodedLen(try cursor.peekByte());
    const frame_type = try varint.decode(&cursor);
    try validateFrameTypeEncoding(frame_type, frame_type_len);

    if (frame_type == @intFromEnum(FrameType.padding)) {
        // PADDING frequently appears in long runs (Initial datagram padding,
        // DPLPMTUD probes, and anti-deadlock probes). Use std.mem's optimized
        // non-zero search instead of advancing one byte at a time on the frame
        // parser hot path.
        cursor.pos = std.mem.indexOfNonePos(
            u8,
            cursor.buf,
            cursor.pos,
            &.{@intFromEnum(FrameType.padding)},
        ) orelse cursor.buf.len;
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

    if (frame_type == @intFromEnum(FrameType.max_streams_bidi)) return .{ .max_streams_bidi = .{ .maximum_streams = try parseStreamCount(cursor) } };
    if (frame_type == @intFromEnum(FrameType.max_streams_uni)) return .{ .max_streams_uni = .{ .maximum_streams = try parseStreamCount(cursor) } };
    if (frame_type == @intFromEnum(FrameType.data_blocked)) return .{ .data_blocked = .{ .maximum_data = try varint.decode(cursor) } };

    if (frame_type == @intFromEnum(FrameType.stream_data_blocked)) {
        return .{ .stream_data_blocked = .{
            .stream_id = try varint.decode(cursor),
            .maximum_stream_data = try varint.decode(cursor),
        } };
    }

    if (frame_type == @intFromEnum(FrameType.streams_blocked_bidi)) return .{ .streams_blocked_bidi = .{ .maximum_streams = try parseStreamCount(cursor) } };
    if (frame_type == @intFromEnum(FrameType.streams_blocked_uni)) return .{ .streams_blocked_uni = .{ .maximum_streams = try parseStreamCount(cursor) } };

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
        const stream = StreamFrame{
            .stream_id = stream_id,
            .offset = offset,
            .fin = (frame_type & 0x01) != 0,
            .data = try cursor.readSlice(len),
        };
        return .{ .stream = stream };
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
    if (frame_type == @intFromEnum(FrameType.immediate_ack)) return .{ .immediate_ack = {} };

    if (frame_type == @intFromEnum(FrameType.datagram)) {
        const payload = packet_payload[cursor.pos..];
        cursor.pos = packet_payload.len;
        return .{ .datagram = .{ .data = payload, .length_present = false } };
    }

    if (frame_type == @intFromEnum(FrameType.datagram_len)) {
        const len = try usizeFromVarint(try varint.decode(cursor));
        return .{ .datagram = .{ .data = try cursor.readSlice(len), .length_present = true } };
    }

    if (frame_type == @intFromEnum(FrameType.ack_frequency)) {
        const ack_frequency = AckFrequencyFrame{
            .sequence_number = try varint.decode(cursor),
            .ack_eliciting_threshold = try varint.decode(cursor),
            .request_max_ack_delay = try varint.decode(cursor),
            .reordering_threshold = try varint.decode(cursor),
        };
        try validateAckFrequencyFrame(ack_frequency);
        return .{ .ack_frequency = ack_frequency };
    }

    return error.UnsupportedFrameType;
}

fn parseAckFrame(allocator: ?std.mem.Allocator, cursor: *wire.Cursor, has_ecn: bool) Error!AckFrame {
    const largest_acknowledged = try varint.decode(cursor);
    const ack_delay = try varint.decode(cursor);
    const range_count = try usizeFromVarint(try varint.decode(cursor));
    const first_ack_range = try varint.decode(cursor);
    try validateAckRangePayloadFits(cursor.remaining(), range_count, has_ecn);

    const ranges: []AckRange = if (range_count == 0)
        &.{}
    else if (allocator) |gpa|
        try gpa.alloc(AckRange, range_count)
    else
        return error.InvalidAckRange;
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

    const ack = AckFrame{
        .largest_acknowledged = largest_acknowledged,
        .ack_delay = ack_delay,
        .first_ack_range = first_ack_range,
        .ranges = ranges,
        .ecn_counts = ecn_counts,
    };
    try validateAckFrame(ack);
    return ack;
}

fn validateAckFrame(ack: AckFrame) Error!void {
    try validateQuicVarint(ack.largest_acknowledged);
    try validateQuicVarint(ack.ack_delay);
    try validateQuicVarint(ack.first_ack_range);
    const range_count = std.math.cast(u64, ack.ranges.len) orelse return error.InvalidFrameLength;
    try validateQuicVarint(range_count);
    if (ack.first_ack_range > ack.largest_acknowledged) return error.InvalidAckRange;

    // ACK ranges are defined by subtracting each encoded range and gap from the
    // previous range's smallest packet number. Validate those subtractions
    // explicitly so malformed peers cannot encode a range that wraps below
    // packet number zero before connection-level ACK processing sees it.
    var smallest = ack.largest_acknowledged - ack.first_ack_range;
    for (ack.ranges) |range| {
        try validateQuicVarint(range.gap);
        try validateQuicVarint(range.ack_range_length);
        const skipped = std.math.add(u64, range.gap, 2) catch return error.InvalidAckRange;
        if (smallest < skipped) return error.InvalidAckRange;

        const range_largest = smallest - skipped;
        if (range.ack_range_length > range_largest) return error.InvalidAckRange;
        smallest = range_largest - range.ack_range_length;
    }

    if (ack.ecn_counts) |ecn| {
        try validateQuicVarint(ecn.ect0_count);
        try validateQuicVarint(ecn.ect1_count);
        try validateQuicVarint(ecn.ecn_ce_count);
    }
}

fn validateAckFrequencyFrame(ack_frequency: AckFrequencyFrame) Error!void {
    try validateQuicVarint(ack_frequency.sequence_number);
    try validateQuicVarint(ack_frequency.ack_eliciting_threshold);
    try validateQuicVarint(ack_frequency.request_max_ack_delay);
    try validateQuicVarint(ack_frequency.reordering_threshold);
    if (ack_frequency.ack_eliciting_threshold == 0) return error.InvalidFrame;
}

pub fn appendPadding(list: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) Error!void {
    if (len == 0) return;
    const start = list.items.len;
    try list.ensureUnusedCapacity(allocator, len);
    list.items.len = start + len;
    @memset(list.items[start..], @intFromEnum(FrameType.padding));
}

fn writeAckFieldsAssumeCapacity(list: *std.ArrayList(u8), ack: AckFrame) Error!void {
    try appendVarintAssumeCapacity(list, ack.largest_acknowledged);
    try appendVarintAssumeCapacity(list, ack.ack_delay);
    try appendVarintAssumeCapacity(list, ack.ranges.len);
    try appendVarintAssumeCapacity(list, ack.first_ack_range);
    for (ack.ranges) |range| {
        try appendVarintAssumeCapacity(list, range.gap);
        try appendVarintAssumeCapacity(list, range.ack_range_length);
    }
    if (ack.ecn_counts) |ecn| {
        try appendVarintAssumeCapacity(list, ecn.ect0_count);
        try appendVarintAssumeCapacity(list, ecn.ect1_count);
        try appendVarintAssumeCapacity(list, ecn.ecn_ce_count);
    }
}

fn ackFrameWireLen(ack: AckFrame) Error!usize {
    try validateAckFrame(ack);
    var len: usize = 1;
    len = try addWireLen(len, try varint.length(ack.largest_acknowledged));
    len = try addWireLen(len, try varint.length(ack.ack_delay));
    len = try addWireLen(len, try varint.length(ack.ranges.len));
    len = try addWireLen(len, try varint.length(ack.first_ack_range));
    for (ack.ranges) |range| {
        len = try addWireLen(len, try varint.length(range.gap));
        len = try addWireLen(len, try varint.length(range.ack_range_length));
    }
    if (ack.ecn_counts) |ecn| {
        len = try addWireLen(len, try varint.length(ecn.ect0_count));
        len = try addWireLen(len, try varint.length(ecn.ect1_count));
        len = try addWireLen(len, try varint.length(ecn.ecn_ce_count));
    }
    return len;
}

fn writeAckFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, ack: AckFrame) Error!void {
    const frame_len = try ackFrameWireLen(ack);
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(if (ack.ecn_counts == null)
        @intFromEnum(FrameType.ack)
    else
        @intFromEnum(FrameType.ack_ecn));
    try writeAckFieldsAssumeCapacity(list, ack);
}

fn writeSingleByteFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64) Error!void {
    std.debug.assert(frame_type <= 63);
    try list.ensureUnusedCapacity(allocator, 1);
    list.appendAssumeCapacity(@intCast(frame_type));
}

fn appendVarintAssumeCapacity(list: *std.ArrayList(u8), value: u64) Error!void {
    var buffer: [8]u8 = undefined;
    const encoded = try varint.encodeInto(&buffer, value);
    list.appendSliceAssumeCapacity(encoded);
}

fn appendU16AssumeCapacity(list: *std.ArrayList(u8), value: u16) void {
    const start = list.items.len;
    list.items.len = start + 2;
    std.mem.writeInt(u16, list.items[start..][0..2], value, .big);
}

fn appendU32AssumeCapacity(list: *std.ArrayList(u8), value: u32) void {
    const start = list.items.len;
    list.items.len = start + 4;
    std.mem.writeInt(u32, list.items[start..][0..4], value, .big);
}

fn writeSingleVarintFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64, value: u64) Error!void {
    std.debug.assert(frame_type <= 63);
    const frame_len = try singleVarintFrameWireLen(frame_type, value);
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intCast(frame_type));
    try appendVarintAssumeCapacity(list, value);
}

fn writeDoubleVarintFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    first: u64,
    second: u64,
) Error!void {
    std.debug.assert(frame_type <= 63);
    const frame_len = try doubleVarintFrameWireLen(frame_type, first, second);
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intCast(frame_type));
    try appendVarintAssumeCapacity(list, first);
    try appendVarintAssumeCapacity(list, second);
}

fn writeTripleVarintFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    first: u64,
    second: u64,
    third: u64,
) Error!void {
    std.debug.assert(frame_type <= 63);
    const frame_len = try tripleVarintFrameWireLen(frame_type, first, second, third);
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intCast(frame_type));
    try appendVarintAssumeCapacity(list, first);
    try appendVarintAssumeCapacity(list, second);
    try appendVarintAssumeCapacity(list, third);
}

fn writeSingleVarintPayloadFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    value: u64,
    payload: []const u8,
) Error!void {
    const frame_len = try singleVarintPayloadFrameWireLen(
        frame_type,
        value,
        payload.len,
    );
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intCast(frame_type));
    try appendVarintAssumeCapacity(list, value);
    list.appendSliceAssumeCapacity(payload);
}

fn writeDoubleVarintPayloadFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    first: u64,
    second: u64,
    payload: []const u8,
) Error!void {
    const frame_len = try doubleVarintPayloadFrameWireLen(
        frame_type,
        first,
        second,
        payload.len,
    );
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intCast(frame_type));
    try appendVarintAssumeCapacity(list, first);
    try appendVarintAssumeCapacity(list, second);
    list.appendSliceAssumeCapacity(payload);
}

fn writeTripleVarintPayloadFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    first: u64,
    second: u64,
    third: u64,
    payload: []const u8,
) Error!void {
    const frame_len = try tripleVarintPayloadFrameWireLen(
        frame_type,
        first,
        second,
        third,
        payload.len,
    );
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intCast(frame_type));
    try appendVarintAssumeCapacity(list, first);
    try appendVarintAssumeCapacity(list, second);
    try appendVarintAssumeCapacity(list, third);
    list.appendSliceAssumeCapacity(payload);
}

fn writeDatagramFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, datagram: DatagramFrame) Error!void {
    const frame_len = try datagramFrameWireLen(datagram);
    try list.ensureUnusedCapacity(allocator, frame_len);
    if (datagram.length_present) {
        list.appendAssumeCapacity(@intFromEnum(FrameType.datagram_len));
        try appendVarintAssumeCapacity(list, datagram.data.len);
    } else {
        list.appendAssumeCapacity(@intFromEnum(FrameType.datagram));
    }
    list.appendSliceAssumeCapacity(datagram.data);
}

fn writeNewConnectionIdFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame: NewConnectionIdFrame) Error!void {
    const frame_len = try newConnectionIdFrameWireLen(frame);
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendAssumeCapacity(@intFromEnum(FrameType.new_connection_id));
    try appendVarintAssumeCapacity(list, frame.sequence_number);
    try appendVarintAssumeCapacity(list, frame.retire_prior_to);
    list.appendAssumeCapacity(@intCast(frame.connection_id.len));
    list.appendSliceAssumeCapacity(frame.connection_id);
    list.appendSliceAssumeCapacity(&frame.stateless_reset_token);
}

fn writeFixedPathFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64, frame: PathFrame) Error!void {
    std.debug.assert(frame_type == @intFromEnum(FrameType.path_challenge) or
        frame_type == @intFromEnum(FrameType.path_response));
    try list.ensureUnusedCapacity(allocator, 9);
    list.appendAssumeCapacity(@intCast(frame_type));
    list.appendSliceAssumeCapacity(&frame.data);
}

fn writeAckFrequencyFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame: AckFrequencyFrame) Error!void {
    const frame_len = try ackFrequencyFrameWireLen(frame);
    try list.ensureUnusedCapacity(allocator, frame_len);
    list.appendSliceAssumeCapacity(&[_]u8{
        0x40,
        @intCast(@intFromEnum(FrameType.ack_frequency)),
    });
    try appendVarintAssumeCapacity(list, frame.sequence_number);
    try appendVarintAssumeCapacity(list, frame.ack_eliciting_threshold);
    try appendVarintAssumeCapacity(list, frame.request_max_ack_delay);
    try appendVarintAssumeCapacity(list, frame.reordering_threshold);
}

fn writeStreamFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream: StreamFrame) Error!void {
    const frame_len = try streamFrameWireLen(stream);
    try list.ensureUnusedCapacity(allocator, frame_len);

    var frame_type: u8 = @intCast(@intFromEnum(FrameType.stream) | 0x02); // always include Length for unambiguous composition.
    if (stream.offset != 0) frame_type |= 0x04;
    if (stream.fin) frame_type |= 0x01;
    list.appendAssumeCapacity(frame_type);
    try appendVarintAssumeCapacity(list, stream.stream_id);
    if (stream.offset != 0) try appendVarintAssumeCapacity(list, stream.offset);
    try appendVarintAssumeCapacity(list, stream.data.len);
    list.appendSliceAssumeCapacity(stream.data);
}

fn usizeFromVarint(value: u64) Error!usize {
    return std.math.cast(usize, value) orelse error.IntegerOverflow;
}

fn validateEndOffset(offset: u64, data_len: usize) Error!void {
    const data_len_u64 = std.math.cast(u64, data_len) orelse return error.InvalidFrameLength;
    const end = std.math.add(u64, offset, data_len_u64) catch return error.InvalidFrameLength;
    if (end > varint.max_value) return error.InvalidFrameLength;
}

fn validateFrameTypeEncoding(frame_type: u64, encoded_len: u8) Error!void {
    // QUIC varints can usually be encoded in a longer form, but RFC 9000
    // singles out the Frame Type field: it MUST use the shortest possible
    // encoding.  This keeps frame dispatch canonical and matches tquic's codec
    // boundary before any frame-specific parsing runs.
    const shortest = varint.length(frame_type) catch return error.UnsupportedFrameType;
    if (encoded_len != shortest) return error.InvalidFrame;
}

fn validateQuicVarint(value: u64) Error!void {
    if (value > varint.max_value) return error.InvalidFrameLength;
}

fn validateAckRangePayloadFits(remaining: usize, range_count: usize, has_ecn: bool) Error!void {
    const min_range_bytes = std.math.mul(usize, range_count, 2) catch return error.InvalidFrameLength;
    const min_ecn_bytes: usize = if (has_ecn) 3 else 0;
    const min_bytes = std.math.add(usize, min_range_bytes, min_ecn_bytes) catch return error.InvalidFrameLength;
    if (remaining < min_bytes) return error.InvalidFrameLength;
}

fn validateStreamCount(maximum_streams: u64) Error!void {
    if (maximum_streams > max_stream_count) return error.InvalidFrame;
}

fn parseStreamCount(cursor: *wire.Cursor) Error!u64 {
    const maximum_streams = try varint.decode(cursor);
    try validateStreamCount(maximum_streams);
    return maximum_streams;
}

fn validateConnectionIdLen(len: usize) Error!void {
    if (len == 0 or len > 20) return error.InvalidConnectionIdLength;
}

fn validatePacketConnectionIdLen(len: usize) Error!void {
    if (len > 20) return error.InvalidConnectionIdLength;
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
    _ = tls;
    _ = handshake;
    _ = zero_rtt;
    _ = one_rtt;
    _ = packet_space;
    _ = stream_state;
    _ = flow_control;
    _ = recovery;
    _ = connection_router;
    _ = endpoint_timers;
    _ = connection_id;
    _ = stateless_reset;
    _ = congestion;
    _ = pacing;
    _ = hystart;
    _ = path_validation;
    _ = rtt;
    _ = pmtu;
    _ = address_validation_token;
    _ = retry_flow;
    _ = version_negotiation;
    _ = qlog;
    _ = keylog;
    _ = quic_lb;
    _ = resumption;
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

    var too_short_len = try bytes.clone(allocator);
    defer too_short_len.deinit(allocator);
    // Replace the one-byte Length varint immediately before the 4-byte packet
    // number with 3.  Long-header Length covers packet number + payload, so it
    // must be at least the encoded packet-number length before any payload
    // decryption is attempted.
    too_short_len.items[too_short_len.items.len - 5] = 3;
    try std.testing.expectError(error.InvalidFrameLength, LongHeader.parse(too_short_len.items));

    var truncated = try bytes.clone(allocator);
    defer truncated.deinit(allocator);
    truncated.items[truncated.items.len - 5] = 8;
    try std.testing.expectError(error.BufferTooShort, LongHeader.parse(truncated.items));

    var coalesced = try bytes.clone(allocator);
    defer coalesced.deinit(allocator);
    try coalesced.appendSlice(allocator, &.{ 0xaa, 0xbb, 0xcc });
    const coalesced_header = try LongHeader.parse(coalesced.items);
    try std.testing.expectEqual(@as(u64, 4), coalesced_header.length.?);

    bytes.items[0] &= ~@as(u8, 0x40);
    try std.testing.expectError(error.InvalidEncoding, LongHeader.parse(bytes.items));
    const greased = try LongHeader.parseWithFixedBitPolicy(
        bytes.items,
        true,
    );
    try std.testing.expect(!greased.fixed_bit);
    try std.testing.expectEqual(PacketType.initial, greased.packet_type);

    var version_zero = try bytes.clone(allocator);
    defer version_zero.deinit(allocator);
    version_zero.items[0] |= 0x40;
    std.mem.writeInt(u32, version_zero.items[1..5], Version.negotiation.wireValue(), .big);
    try std.testing.expectError(error.InvalidVersionNegotiation, LongHeader.parse(version_zero.items));
}

test "QUIC version negotiation packet roundtrip" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const scid = [_]u8{ 0xca, 0xfe };
    const versions = [_]u32{ Version.version_1.wireValue(), Version.version_2.wireValue(), 0x0a0a0a0a };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeVersionNegotiationPacket(&encoded, allocator, .{
        .first_byte = 0xf0,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .versions = &versions,
    });

    var parsed = try parseVersionNegotiationPacket(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0xf0), parsed.first_byte);
    try std.testing.expectEqualSlices(u8, &dcid, parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, parsed.source_connection_id);
    try std.testing.expectEqualSlices(u32, &versions, parsed.versions);

    try std.testing.expectError(error.InvalidVersionNegotiation, writeVersionNegotiationPacket(&encoded, allocator, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .versions = &.{},
    }));
    try std.testing.expectError(error.InvalidVersionNegotiation, writeVersionNegotiationPacket(&encoded, allocator, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .versions = &.{Version.negotiation.wireValue()},
    }));
}

test "QUIC version negotiation packet rejects malformed inputs" {
    const allocator = std.testing.allocator;
    const short_form = [_]u8{ 0x40, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseVersionNegotiationPacket(allocator, &short_form));

    const non_zero_version = [_]u8{ 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseVersionNegotiationPacket(allocator, &non_zero_version));

    const empty_versions = [_]u8{ 0x80, 0, 0, 0, 0, 1, 0xaa, 1, 0xbb };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseVersionNegotiationPacket(allocator, &empty_versions));

    const truncated_versions = [_]u8{ 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3 };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseVersionNegotiationPacket(allocator, &truncated_versions));

    const zero_supported_version = [_]u8{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseVersionNegotiationPacket(allocator, &zero_supported_version));
}

test "QUIC Retry packet matches RFC vector and verifies integrity" {
    const allocator = std.testing.allocator;
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };
    const token = [_]u8{ 't', 'o', 'k', 'e', 'n' };
    const expected_tag = [_]u8{ 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba };
    const expected = [_]u8{
        0xff,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x08,
        0xf0,
        0x67,
        0xa5,
        0x50,
        0x2a,
        0x42,
        0x62,
        0xb5,
        't',
        'o',
        'k',
        'e',
        'n',
        0x04,
        0xa2,
        0x65,
        0xba,
        0x2e,
        0xff,
        0x4d,
        0x82,
        0x90,
        0x58,
        0xfb,
        0x3f,
        0x0f,
        0x24,
        0x96,
        0xba,
    };

    const parsed = try parseRetryPacket(&expected);
    try std.testing.expectEqual(PacketType.retry, (try LongHeader.parse(&expected)).packet_type);
    try std.testing.expectEqual(@as(u32, 1), parsed.version);
    try std.testing.expectEqualStrings("", parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, parsed.source_connection_id);
    try std.testing.expectEqualSlices(u8, &token, parsed.token);
    try std.testing.expectEqualSlices(u8, &expected_tag, &parsed.integrity_tag);
    try std.testing.expect(try verifyRetryIntegrityTag(allocator, &original_dcid, &expected));

    var tampered = expected;
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expect(!try verifyRetryIntegrityTag(allocator, &original_dcid, &tampered));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const empty_cid = [_]u8{};
    try writeRetryPacket(&encoded, allocator, .{
        .destination_connection_id = &empty_cid,
        .source_connection_id = &retry_scid,
        .token = &token,
        .original_destination_connection_id = &original_dcid,
    });
    try std.testing.expectEqualSlices(u8, &expected, encoded.items);
}

test "QUIC Retry packet supports version 2 type mapping" {
    const allocator = std.testing.allocator;
    const original_dcid = [_]u8{ 1, 2, 3, 4 };
    const retry_dcid = [_]u8{ 5, 6 };
    const retry_scid = [_]u8{ 7, 8, 9 };
    const token = [_]u8{ 10, 11, 12 };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeRetryPacket(&encoded, allocator, .{
        .version = Version.version_2.wireValue(),
        .destination_connection_id = &retry_dcid,
        .source_connection_id = &retry_scid,
        .token = &token,
        .original_destination_connection_id = &original_dcid,
        .type_specific_bits = 0,
    });

    const header = try LongHeader.parse(encoded.items);
    try std.testing.expectEqual(PacketType.retry, header.packet_type);
    try std.testing.expectEqual(@as(u4, 0), header.type_specific_bits);
    try std.testing.expectEqualSlices(u8, &retry_dcid, header.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, header.source_connection_id);
    try std.testing.expectEqualSlices(u8, &token, header.token);
    try std.testing.expect(try verifyRetryIntegrityTag(allocator, &original_dcid, encoded.items));
}

test "QUIC Retry rejects unsupported versions" {
    const allocator = std.testing.allocator;
    const cid = [_]u8{ 1, 2, 3, 4 };
    const token = [_]u8{9};

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(error.InvalidVersionNegotiation, writeRetryPacket(&encoded, allocator, .{
        .version = 0x0a0a0a0a,
        .destination_connection_id = &cid,
        .source_connection_id = &cid,
        .token = &token,
        .original_destination_connection_id = &cid,
    }));

    const retry_without_tag = [_]u8{
        0xf0,
        0x0a,
        0x0a,
        0x0a,
        0x0a,
        0x00, // dcid len
        0x00, // scid len
        0x01, // token byte
    };
    try std.testing.expectError(error.InvalidVersionNegotiation, retryIntegrityTag(allocator, &cid, &retry_without_tag));
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
    const available_versions_wire = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0x6b, 0x33, 0x43, 0xcf,
    };
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
        .version_information = .{
            .chosen_version = .version_1,
            .available_versions_wire = &available_versions_wire,
        },
        .max_datagram_frame_size = 1200,
        .grease_quic_bit = true,
        .min_ack_delay = 1000,
    };

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try encodeTransportParametersForSource(&bytes, allocator, params, .client);
    const decoded = try parseTransportParametersTyped(allocator, bytes.items, .client);

    try std.testing.expectEqual(@as(u64, 1400), decoded.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 4096), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 2048), decoded.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 10), decoded.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 50), decoded.max_ack_delay);
    try std.testing.expectEqual(@as(u64, 4), decoded.active_connection_id_limit);
    try std.testing.expectEqual(@as(?u64, 1200), decoded.max_datagram_frame_size);
    try std.testing.expect(decoded.grease_quic_bit);
    try std.testing.expectEqual(@as(?u64, 1000), decoded.min_ack_delay);
    try std.testing.expectEqualSlices(u8, &client_cid, decoded.initial_source_connection_id.?);
    try std.testing.expectEqual(Version.version_1, decoded.version_information.?.chosen_version);
    try std.testing.expect(decoded.version_information.?.containsAvailableVersion(.version_2));

    var excessive_min_ack_delay: std.ArrayList(u8) = .empty;
    defer excessive_min_ack_delay.deinit(allocator);
    try encodeIntegerTransportParameter(&excessive_min_ack_delay, allocator, .max_ack_delay, 25);
    try encodeIntegerTransportParameter(&excessive_min_ack_delay, allocator, .min_ack_delay, 25_001);
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, excessive_min_ack_delay.items, .client));

    try std.testing.expectError(error.InvalidTransportParameter, validateTransportParameters(.{
        .max_ack_delay = 10,
        .min_ack_delay = 10_001,
    }, .client));
    var encoded_excessive: std.ArrayList(u8) = .empty;
    defer encoded_excessive.deinit(allocator);
    try std.testing.expectError(error.InvalidTransportParameter, encodeTransportParameters(&encoded_excessive, allocator, .{
        .max_ack_delay = 10,
        .min_ack_delay = 10_001,
    }));

    var duplicate: std.ArrayList(u8) = .empty;
    defer duplicate.deinit(allocator);
    try encodeTransportParameter(&duplicate, allocator, @intFromEnum(TransportParameterId.max_idle_timeout), &.{1});
    try encodeTransportParameter(&duplicate, allocator, @intFromEnum(TransportParameterId.max_idle_timeout), &.{2});
    try std.testing.expectError(error.DuplicateTransportParameter, parseTransportParametersTyped(allocator, duplicate.items, .client));

    var invalid_udp: std.ArrayList(u8) = .empty;
    defer invalid_udp.deinit(allocator);
    try encodeTransportParameter(&invalid_udp, allocator, @intFromEnum(TransportParameterId.max_udp_payload_size), &.{1});
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, invalid_udp.items, .client));

    var jumbo_udp: std.ArrayList(u8) = .empty;
    defer jumbo_udp.deinit(allocator);
    var jumbo_value: std.ArrayList(u8) = .empty;
    defer jumbo_value.deinit(allocator);
    try varint.encode(&jumbo_value, allocator, default_max_udp_payload_size + 1);
    try encodeTransportParameter(&jumbo_udp, allocator, @intFromEnum(TransportParameterId.max_udp_payload_size), jumbo_value.items);
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, jumbo_udp.items, .client));
    try std.testing.expectError(error.InvalidTransportParameter, encodeTransportParameters(&encoded_excessive, allocator, .{
        .max_udp_payload_size = default_max_udp_payload_size + 1,
    }));

    var max_idle_ok: std.ArrayList(u8) = .empty;
    defer max_idle_ok.deinit(allocator);
    try encodeIntegerTransportParameter(&max_idle_ok, allocator, .max_idle_timeout, max_idle_timeout_ms_cap);
    const decoded_idle = try parseTransportParametersTyped(allocator, max_idle_ok.items, .client);
    try std.testing.expectEqual(max_idle_timeout_ms_cap, decoded_idle.max_idle_timeout);

    var max_idle_too_large: std.ArrayList(u8) = .empty;
    defer max_idle_too_large.deinit(allocator);
    try encodeTransportParameter(&max_idle_too_large, allocator, @intFromEnum(TransportParameterId.max_idle_timeout), &.{ 0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 });
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, max_idle_too_large.items, .client));
    try std.testing.expectError(error.InvalidTransportParameter, encodeIntegerTransportParameter(&max_idle_too_large, allocator, .max_idle_timeout, max_idle_timeout_ms_cap + 1));

    var bad_version_info: std.ArrayList(u8) = .empty;
    defer bad_version_info.deinit(allocator);
    try encodeTransportParameter(&bad_version_info, allocator, @intFromEnum(TransportParameterId.version_information), &.{ 0, 0, 0 });
    try std.testing.expectError(error.InvalidTransportParameterLength, parseTransportParametersTyped(allocator, bad_version_info.items, .client));
    bad_version_info.clearRetainingCapacity();
    try encodeTransportParameter(&bad_version_info, allocator, @intFromEnum(TransportParameterId.version_information), &.{ 0, 0, 0, 0 });
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, bad_version_info.items, .client));
    bad_version_info.clearRetainingCapacity();
    try encodeVersionInformationFromVersions(&bad_version_info, allocator, .version_1, &.{ .version_2, @enumFromInt(0x0a0a0a0a) });
    const decoded_reserved = try parseTransportParametersTyped(allocator, bad_version_info.items, .client);
    try std.testing.expect(decoded_reserved.version_information.?.containsAvailableVersion(@enumFromInt(0x0a0a0a0a)));

    var forbidden: std.ArrayList(u8) = .empty;
    defer forbidden.deinit(allocator);
    const token = [_]u8{0xaa} ** 16;
    try encodeTransportParameter(&forbidden, allocator, @intFromEnum(TransportParameterId.stateless_reset_token), &token);
    try std.testing.expectError(error.TransportParameterForbidden, parseTransportParametersTyped(allocator, forbidden.items, .client));

    var non_empty_grease_bit: std.ArrayList(u8) = .empty;
    defer non_empty_grease_bit.deinit(allocator);
    try encodeTransportParameter(
        &non_empty_grease_bit,
        allocator,
        @intFromEnum(TransportParameterId.grease_quic_bit),
        &.{1},
    );
    try std.testing.expectError(
        error.InvalidTransportParameterLength,
        parseTransportParametersTyped(
            allocator,
            non_empty_grease_bit.items,
            .client,
        ),
    );
}

test "QUIC reserved transport parameters grease unknown handling" {
    const allocator = std.testing.allocator;
    try std.testing.expect(isReservedTransportParameterId(27));
    try std.testing.expect(isReservedTransportParameterId(58));
    try std.testing.expect(isReservedTransportParameterId(89));
    try std.testing.expect(!isReservedTransportParameterId(@intFromEnum(TransportParameterId.version_information)));
    try std.testing.expect(!isReservedTransportParameterId(@intFromEnum(TransportParameterId.max_datagram_frame_size)));
    try std.testing.expect(!isReservedTransportParameterId(varint.max_value));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encodeReservedTransportParameter(&encoded, allocator, 27, &.{ 0xaa, 0xbb });
    try encodeIntegerTransportParameter(&encoded, allocator, .initial_max_data, 1234);

    const decoded = try parseTransportParametersTyped(allocator, encoded.items, .client);
    try std.testing.expectEqual(@as(u64, 1234), decoded.initial_max_data);

    try std.testing.expectError(error.InvalidTransportParameter, encodeReservedTransportParameter(&encoded, allocator, @intFromEnum(TransportParameterId.max_idle_timeout), &.{}));
    try std.testing.expectError(error.InvalidTransportParameter, encodeReservedTransportParameter(&encoded, allocator, varint.max_value, &.{}));

    var duplicate_reserved: std.ArrayList(u8) = .empty;
    defer duplicate_reserved.deinit(allocator);
    try encodeReservedTransportParameter(&duplicate_reserved, allocator, 27, &.{0x01});
    try encodeReservedTransportParameter(&duplicate_reserved, allocator, 27, &.{0x02});
    try std.testing.expectError(error.DuplicateTransportParameter, parseTransportParametersTyped(allocator, duplicate_reserved.items, .client));
}

test "QUIC source-aware transport parameter encoder rejects client server-only fields" {
    const allocator = std.testing.allocator;
    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const retry_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const initial_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const preferred_cid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const token = [_]u8{0xe0} ** 16;
    const params = TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .stateless_reset_token = token,
        .preferred_address = .{
            .ipv4_address = .{ 127, 0, 0, 1 },
            .ipv4_port = 4433,
            .connection_id = &preferred_cid,
            .stateless_reset_token = token,
        },
        .initial_source_connection_id = &initial_cid,
        .retry_source_connection_id = &retry_cid,
    };

    var client_bytes: std.ArrayList(u8) = .empty;
    defer client_bytes.deinit(allocator);
    try std.testing.expectError(
        error.TransportParameterForbidden,
        encodeTransportParametersForSource(&client_bytes, allocator, params, .client),
    );
    // Directionality is checked before any bytes are emitted so callers cannot
    // accidentally splice a partial, invalid TLS transport-parameter extension.
    try std.testing.expectEqual(@as(usize, 0), client_bytes.items.len);

    var server_bytes: std.ArrayList(u8) = .empty;
    defer server_bytes.deinit(allocator);
    try encodeTransportParametersForSource(&server_bytes, allocator, params, .server);
    const decoded = try parseTransportParametersTyped(allocator, server_bytes.items, .server);
    try std.testing.expectEqualSlices(u8, &original_dcid, decoded.original_destination_connection_id.?);
    try std.testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);
    try std.testing.expectEqualSlices(u8, &preferred_cid, decoded.preferred_address.?.connection_id);
    try std.testing.expectEqualSlices(u8, &initial_cid, decoded.initial_source_connection_id.?);
    try std.testing.expectEqualSlices(u8, &retry_cid, decoded.retry_source_connection_id.?);
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

    var unspecified = params;
    unspecified.preferred_address = .{
        .connection_id = &preferred_cid,
        .stateless_reset_token = token,
    };
    bytes.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidTransportParameter, encodeTransportParameters(&bytes, allocator, unspecified));

    bytes.clearRetainingCapacity();
    try encodeTransportParameter(
        &bytes,
        allocator,
        @intFromEnum(TransportParameterId.preferred_address),
        &([_]u8{0} ** 4 ++ [_]u8{0} ** 2 ++ [_]u8{0} ** 16 ++ [_]u8{0} ** 2 ++ [_]u8{4} ++ preferred_cid ++ token),
    );
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, bytes.items, .server));
}

test "QUIC stream and crypto frame codec" {
    const allocator = std.testing.allocator;

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try (Frame{ .stream = .{ .stream_id = 7, .offset = 64, .fin = true, .data = "hello" } }).write(&stream_bytes, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.stream) | 0x07), stream_bytes.items[0]);
    const parsed_stream = try parseFrame(stream_bytes.items);
    try std.testing.expectEqual(@as(usize, stream_bytes.items.len), parsed_stream.consumed);
    try std.testing.expectEqual(@as(u64, 7), parsed_stream.frame.stream.stream_id);
    try std.testing.expectEqual(@as(u64, 64), parsed_stream.frame.stream.offset);
    try std.testing.expect(parsed_stream.frame.stream.fin);
    try std.testing.expectEqualStrings("hello", parsed_stream.frame.stream.data);

    var crypto_bytes: std.ArrayList(u8) = .empty;
    defer crypto_bytes.deinit(allocator);
    try (Frame{ .crypto = .{ .offset = 0, .data = "tls" } }).write(&crypto_bytes, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.crypto)), crypto_bytes.items[0]);
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
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var owned_ack = try parseFrameOwned(no_alloc.allocator(), ack_bytes.items);
    defer owned_ack.deinitOwned(no_alloc.allocator());
    try std.testing.expectEqual(@as(usize, 0), owned_ack.frame.ack.ranges.len);

    var close_bytes: std.ArrayList(u8) = .empty;
    defer close_bytes.deinit(allocator);
    try (Frame{ .connection_close = .{ .error_code = 0, .frame_type = @intFromEnum(FrameType.stream), .reason_phrase = "done" } }).write(&close_bytes, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.connection_close)), close_bytes.items[0]);
    const close = try parseFrame(close_bytes.items);
    try std.testing.expectEqualStrings("done", close.frame.connection_close.reason_phrase);

    close_bytes.clearRetainingCapacity();
    try (Frame{ .application_close = .{ .error_code = 1, .reason_phrase = "app" } }).write(&close_bytes, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.connection_close_app)), close_bytes.items[0]);
    const app_close = try parseFrame(close_bytes.items);
    try std.testing.expectEqualStrings("app", app_close.frame.application_close.reason_phrase);

    var datagram_bytes: std.ArrayList(u8) = .empty;
    defer datagram_bytes.deinit(allocator);
    try (Frame{ .datagram = .{ .data = "dgram", .length_present = false } }).write(&datagram_bytes, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.datagram)), datagram_bytes.items[0]);
    const datagram = try parseFrame(datagram_bytes.items);
    try std.testing.expect(!datagram.frame.datagram.length_present);
    try std.testing.expectEqualStrings("dgram", datagram.frame.datagram.data);

    datagram_bytes.clearRetainingCapacity();
    try (Frame{ .datagram = .{ .data = "dgram", .length_present = true } }).write(&datagram_bytes, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.datagram_len)), datagram_bytes.items[0]);

    const padding = try parseFrame(&.{ 0, 0, 0, @intFromEnum(FrameType.ping) });
    try std.testing.expectEqual(@as(usize, 3), padding.frame.padding.len);
    try std.testing.expectEqual(@as(usize, 3), padding.consumed);

    var padding_bytes: std.ArrayList(u8) = .empty;
    defer padding_bytes.deinit(allocator);
    try appendPadding(&padding_bytes, allocator, 4);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, padding_bytes.items);
    try (Frame{ .padding = .{ .len = 2 } }).write(&padding_bytes, allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0 }, padding_bytes.items);
}

test "QUIC ACK_FREQUENCY and IMMEDIATE_ACK frames" {
    const allocator = std.testing.allocator;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Frame{ .ack_frequency = .{
        .sequence_number = 9,
        .ack_eliciting_threshold = 4,
        .request_max_ack_delay = 2500,
        .reordering_threshold = 3,
    } }).write(&encoded, allocator);
    try std.testing.expectEqualSlices(u8, &.{ 0x40, @intFromEnum(FrameType.ack_frequency) }, encoded.items[0..2]);
    const parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 9), parsed.frame.ack_frequency.sequence_number);
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.ack_frequency.ack_eliciting_threshold);
    try std.testing.expectEqual(@as(u64, 2500), parsed.frame.ack_frequency.request_max_ack_delay);
    try std.testing.expectEqual(@as(u64, 3), parsed.frame.ack_frequency.reordering_threshold);

    encoded.clearRetainingCapacity();
    try (Frame{ .immediate_ack = {} }).write(&encoded, allocator);
    const immediate = try parseFrame(encoded.items);
    try std.testing.expect(immediate.frame == .immediate_ack);

    const ack_frequency = Frame{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 1,
        .request_max_ack_delay = 0,
        .reordering_threshold = 1,
    } };
    try std.testing.expect(!frameAllowedInPacketType(ack_frequency, .zero_rtt));
    try std.testing.expect(frameAllowedInPacketType(ack_frequency, .one_rtt));
    try std.testing.expect(frameAllowedInPacketType(.{ .immediate_ack = {} }, .one_rtt));
    try std.testing.expect(!frameAllowedInPacketType(.{ .immediate_ack = {} }, .zero_rtt));

    try std.testing.expectError(error.InvalidFrame, (Frame{ .ack_frequency = .{
        .sequence_number = 10,
        .ack_eliciting_threshold = 0,
        .request_max_ack_delay = 0,
        .reordering_threshold = 0,
    } }).write(&encoded, allocator));

    encoded.clearRetainingCapacity();
    try varint.encode(&encoded, allocator, @intFromEnum(FrameType.ack_frequency));
    try varint.encode(&encoded, allocator, 10);
    try varint.encode(&encoded, allocator, 0);
    try varint.encode(&encoded, allocator, 0);
    try varint.encode(&encoded, allocator, 0);
    try std.testing.expectError(error.InvalidFrame, parseFrame(encoded.items));
}

test "QUIC frame packet context rules follow RFC 9000" {
    const stream = Frame{ .stream = .{ .stream_id = 0, .data = "data" } };
    const crypto = Frame{ .crypto = .{ .offset = 0, .data = "tls" } };
    const ack = Frame{ .ack = .{ .largest_acknowledged = 0, .ack_delay = 0, .first_ack_range = 0 } };
    const app_close = Frame{ .application_close = .{ .error_code = 0, .reason_phrase = "" } };

    try std.testing.expect(frameAllowedInPacketType(.{ .padding = .{ .len = 1 } }, .initial));
    try std.testing.expect(frameAllowedInPacketType(.{ .ping = {} }, .handshake));
    try std.testing.expect(frameAllowedInPacketType(crypto, .initial));
    try std.testing.expect(frameAllowedInPacketType(ack, .handshake));
    try std.testing.expect(!frameAllowedInPacketType(stream, .initial));
    try std.testing.expect(!frameAllowedInPacketType(stream, .handshake));
    try std.testing.expect(frameAllowedInPacketType(stream, .zero_rtt));
    try std.testing.expect(!frameAllowedInPacketType(ack, .zero_rtt));
    try std.testing.expect(!frameAllowedInPacketType(crypto, .zero_rtt));
    try std.testing.expect(!frameAllowedInPacketType(.{ .path_response = .{ .data = [_]u8{0} ** 8 } }, .zero_rtt));
    try std.testing.expect(frameAllowedInPacketType(.{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = "new-cid",
        .stateless_reset_token = [_]u8{0} ** 16,
    } }, .zero_rtt));
    try std.testing.expect(!frameAllowedInPacketType(.{ .retire_connection_id = .{ .sequence_number = 1 } }, .zero_rtt));
    try std.testing.expect(frameAllowedInPacketType(app_close, .zero_rtt));
    try validateFrameForPacketType(app_close, .zero_rtt);
    try std.testing.expect(frameAllowedInPacketType(.{ .connection_close = .{ .error_code = 0, .frame_type = 0, .reason_phrase = "" } }, .zero_rtt));
    try std.testing.expect(frameAllowedInPacketType(.{ .handshake_done = {} }, .one_rtt));
    try std.testing.expectError(error.InvalidFrame, validateFrameForPacketType(stream, .initial));
}

test "QUIC frame payload close-error classification" {
    const allocator = std.testing.allocator;

    const empty = (try classifyFramePayloadCloseError(allocator, &.{}, .one_rtt)).?;
    try std.testing.expectEqual(TransportErrorCode.protocol_violation, empty.code);
    try std.testing.expectEqual(@as(u64, 0), empty.frame_type);
    try std.testing.expectEqualStrings("empty payload", empty.reason_phrase);

    const initial_stream_payload = [_]u8{ @intFromEnum(FrameType.stream) | 0x02, 0, 1, 'x' };
    const packet_type = (try classifyFramePayloadCloseError(allocator, &initial_stream_payload, .initial)).?;
    try std.testing.expectEqual(TransportErrorCode.protocol_violation, packet_type.code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(FrameType.stream) | 0x02), packet_type.frame_type);
    try std.testing.expectEqualStrings("packet type", packet_type.reason_phrase);

    const unknown = [_]u8{0x21};
    const encoding = (try classifyFramePayloadCloseError(allocator, &unknown, .one_rtt)).?;
    try std.testing.expectEqual(TransportErrorCode.frame_encoding_error, encoding.code);
    try std.testing.expectEqual(@as(u64, 0x21), encoding.frame_type);
    try std.testing.expectEqualStrings("frame encoding", encoding.reason_phrase);

    try std.testing.expect((try classifyFramePayloadCloseError(allocator, &.{@intFromEnum(FrameType.ping)}, .one_rtt)) == null);
    try std.testing.expectEqual(@as(u64, @intFromEnum(FrameType.ack)), rawFrameTypeValue(&.{@intFromEnum(FrameType.ack)}));
    try std.testing.expectEqual(@as(u64, 0), rawFrameTypeValue(&.{0xff}));
    try std.testing.expectEqual(@as(?TransportErrorCode, TransportErrorCode.frame_encoding_error), frameDecodeTransportErrorCode(error.InvalidFrame));
    try std.testing.expectEqual(@as(?TransportErrorCode, null), frameDecodeTransportErrorCode(error.OutOfMemory));
}

test "QUIC frame type uses shortest varint encoding" {
    const overlong_ping = [_]u8{ 0x40, @intFromEnum(FrameType.ping) };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&overlong_ping));

    const overlong_padding = [_]u8{ 0x40, @intFromEnum(FrameType.padding) };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&overlong_padding));

    const ping = try parseFrame(&[_]u8{@intFromEnum(FrameType.ping)});
    try std.testing.expect(ping.frame == .ping);
}

test "QUIC STREAM frame permits empty non-FIN frames" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Frame{ .stream = .{
        .stream_id = 0,
        .data = &.{},
        .fin = false,
    } }).write(&encoded, allocator);
    var parsed = try parseFrame(encoded.items);
    try std.testing.expect(!parsed.frame.stream.fin);
    try std.testing.expectEqual(@as(usize, 0), parsed.frame.stream.data.len);

    encoded.clearRetainingCapacity();
    try varint.encode(&encoded, allocator, @intFromEnum(FrameType.stream) | 0x02);
    try varint.encode(&encoded, allocator, 0);
    try varint.encode(&encoded, allocator, 0);
    parsed = try parseFrame(encoded.items);
    try std.testing.expect(!parsed.frame.stream.fin);
    try std.testing.expectEqual(@as(usize, 0), parsed.frame.stream.data.len);

    encoded.clearRetainingCapacity();
    try (Frame{ .stream = .{ .stream_id = 0, .data = &.{}, .fin = true } }).write(&encoded, allocator);
    parsed = try parseFrame(encoded.items);
    try std.testing.expect(parsed.frame.stream.fin);
    try std.testing.expectEqual(@as(usize, 0), parsed.frame.stream.data.len);
}

test "QUIC stream-count control frames reject values above RFC limit" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try std.testing.expectError(error.InvalidFrame, (Frame{ .max_streams_bidi = .{ .maximum_streams = max_stream_count + 1 } }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidFrame, (Frame{ .streams_blocked_uni = .{ .maximum_streams = max_stream_count + 1 } }).write(&encoded, allocator));

    try varint.encode(&encoded, allocator, @intFromEnum(FrameType.max_streams_uni));
    try varint.encode(&encoded, allocator, max_stream_count + 1);
    try std.testing.expectError(error.InvalidFrame, parseFrame(encoded.items));

    encoded.clearRetainingCapacity();
    try varint.encode(&encoded, allocator, @intFromEnum(FrameType.streams_blocked_bidi));
    try varint.encode(&encoded, allocator, max_stream_count + 1);
    try std.testing.expectError(error.InvalidFrame, parseFrame(encoded.items));
}

test "QUIC MAX_DATA frame writes fixed frame type byte" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const frame = Frame{ .max_data = .{ .maximum_data = 1000 } };
    try frame.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.max_data)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try frame.wireLen());

    const parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 1000), parsed.frame.max_data.maximum_data);
}

test "QUIC stream flow-control frames write fixed frame type bytes" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const max_stream_data = Frame{ .max_stream_data = .{
        .stream_id = 4,
        .maximum_stream_data = 1000,
    } };
    try max_stream_data.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.max_stream_data)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try max_stream_data.wireLen());
    var parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 1000), parsed.frame.max_stream_data.maximum_stream_data);

    encoded.clearRetainingCapacity();
    const stream_data_blocked = Frame{ .stream_data_blocked = .{
        .stream_id = 4,
        .maximum_stream_data = 1000,
    } };
    try stream_data_blocked.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.stream_data_blocked)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try stream_data_blocked.wireLen());
    parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 1000), parsed.frame.stream_data_blocked.maximum_stream_data);
}

test "QUIC stream reset control frames write fixed frame type bytes" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const reset_stream = Frame{ .reset_stream = .{
        .stream_id = 4,
        .application_error_code = 7,
        .final_size = 99,
    } };
    try reset_stream.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.reset_stream)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try reset_stream.wireLen());
    var parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 7), parsed.frame.reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 99), parsed.frame.reset_stream.final_size);

    encoded.clearRetainingCapacity();
    const stop_sending = Frame{ .stop_sending = .{
        .stream_id = 4,
        .application_error_code = 7,
    } };
    try stop_sending.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.stop_sending)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try stop_sending.wireLen());
    parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.stop_sending.stream_id);
    try std.testing.expectEqual(@as(u64, 7), parsed.frame.stop_sending.application_error_code);
}

test "QUIC NEW_TOKEN frame writes fixed frame type byte" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const frame = Frame{ .new_token = .{ .token = "token" } };
    try frame.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.new_token)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try frame.wireLen());

    const parsed = try parseFrame(encoded.items);
    try std.testing.expectEqualStrings("token", parsed.frame.new_token.token);
}

test "QUIC NEW_CONNECTION_ID frame writes fixed frame type byte" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const token = [_]u8{0xa5} ** 16;
    const frame = Frame{ .new_connection_id = .{
        .sequence_number = 2,
        .retire_prior_to = 1,
        .connection_id = "cid",
        .stateless_reset_token = token,
    } };
    try frame.write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, @intFromEnum(FrameType.new_connection_id)), encoded.items[0]);
    try std.testing.expectEqual(encoded.items.len, try frame.wireLen());

    const parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 2), parsed.frame.new_connection_id.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), parsed.frame.new_connection_id.retire_prior_to);
    try std.testing.expectEqualStrings("cid", parsed.frame.new_connection_id.connection_id);
    try std.testing.expectEqualSlices(u8, &token, &parsed.frame.new_connection_id.stateless_reset_token);
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

test "QUIC ACK frame codec rejects invalid ranges" {
    const allocator = std.testing.allocator;

    var invalid_out: std.ArrayList(u8) = .empty;
    defer invalid_out.deinit(allocator);
    try std.testing.expectError(error.InvalidAckRange, (Frame{ .ack = .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 4,
    } }).write(&invalid_out, allocator));

    var first_too_long: std.ArrayList(u8) = .empty;
    defer first_too_long.deinit(allocator);
    try varint.encode(&first_too_long, allocator, @intFromEnum(FrameType.ack));
    try varint.encode(&first_too_long, allocator, 3);
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 4);
    try std.testing.expectError(error.InvalidAckRange, parseFrame(first_too_long.items));

    const underflow_ranges = [_]AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    };
    try std.testing.expectError(error.InvalidAckRange, (Frame{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &underflow_ranges,
    } }).write(&invalid_out, allocator));

    var range_underflow: std.ArrayList(u8) = .empty;
    defer range_underflow.deinit(allocator);
    try varint.encode(&range_underflow, allocator, @intFromEnum(FrameType.ack));
    try varint.encode(&range_underflow, allocator, 1);
    try varint.encode(&range_underflow, allocator, 0);
    try varint.encode(&range_underflow, allocator, 1);
    try varint.encode(&range_underflow, allocator, 0);
    try varint.encode(&range_underflow, allocator, 0);
    try varint.encode(&range_underflow, allocator, 0);
    try std.testing.expectError(error.InvalidAckRange, parseFrameOwned(allocator, range_underflow.items));
}

test "QUIC ACK_ECN frame codec rejects invalid ranges" {
    const allocator = std.testing.allocator;

    var first_too_long: std.ArrayList(u8) = .empty;
    defer first_too_long.deinit(allocator);
    try varint.encode(&first_too_long, allocator, @intFromEnum(FrameType.ack_ecn));
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 1);
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 0);
    try varint.encode(&first_too_long, allocator, 0);
    try std.testing.expectError(error.InvalidAckRange, parseFrame(first_too_long.items));

    var range_too_long: std.ArrayList(u8) = .empty;
    defer range_too_long.deinit(allocator);
    try varint.encode(&range_too_long, allocator, @intFromEnum(FrameType.ack_ecn));
    try varint.encode(&range_too_long, allocator, 2);
    try varint.encode(&range_too_long, allocator, 0);
    try varint.encode(&range_too_long, allocator, 1);
    try varint.encode(&range_too_long, allocator, 0);
    try varint.encode(&range_too_long, allocator, 0);
    try varint.encode(&range_too_long, allocator, 1);
    try varint.encode(&range_too_long, allocator, 1);
    try varint.encode(&range_too_long, allocator, 1);
    try varint.encode(&range_too_long, allocator, 1);
    try std.testing.expectError(error.InvalidAckRange, parseFrameOwned(allocator, range_too_long.items));
}

test "QUIC frame wire lengths match encoders for every variant" {
    const allocator = std.testing.allocator;
    const ranges = [_]AckRange{.{ .gap = 0, .ack_range_length = 1 }};
    const frames = [_]Frame{
        .{ .padding = .{ .len = 3 } },
        .{ .ping = {} },
        .{ .ack = .{ .largest_acknowledged = 5, .ack_delay = 2, .first_ack_range = 1, .ranges = &ranges } },
        .{ .ack = .{
            .largest_acknowledged = 5,
            .ack_delay = 2,
            .first_ack_range = 1,
            .ranges = &ranges,
            .ecn_counts = .{ .ect0_count = 3, .ect1_count = 2, .ecn_ce_count = 1 },
        } },
        .{ .reset_stream = .{ .stream_id = 4, .application_error_code = 7, .final_size = 99 } },
        .{ .stop_sending = .{ .stream_id = 4, .application_error_code = 7 } },
        .{ .new_token = .{ .token = "token" } },
        .{ .crypto = .{ .offset = 2, .data = "crypto" } },
        .{ .stream = .{ .stream_id = 4, .offset = 2, .fin = true, .data = "stream" } },
        .{ .max_data = .{ .maximum_data = 1000 } },
        .{ .max_stream_data = .{ .stream_id = 4, .maximum_stream_data = 1000 } },
        .{ .max_streams_bidi = .{ .maximum_streams = 4 } },
        .{ .max_streams_uni = .{ .maximum_streams = 4 } },
        .{ .data_blocked = .{ .maximum_data = 1000 } },
        .{ .stream_data_blocked = .{ .stream_id = 4, .maximum_stream_data = 1000 } },
        .{ .streams_blocked_bidi = .{ .maximum_streams = 4 } },
        .{ .streams_blocked_uni = .{ .maximum_streams = 4 } },
        .{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 1,
            .connection_id = "cid",
            .stateless_reset_token = [_]u8{0xa5} ** 16,
        } },
        .{ .retire_connection_id = .{ .sequence_number = 1 } },
        .{ .path_challenge = .{ .data = [_]u8{1} ** 8 } },
        .{ .path_response = .{ .data = [_]u8{2} ** 8 } },
        .{ .connection_close = .{ .error_code = 1, .frame_type = 8, .reason_phrase = "close" } },
        .{ .application_close = .{ .error_code = 1, .reason_phrase = "app" } },
        .{ .handshake_done = {} },
        .{ .immediate_ack = {} },
        .{ .datagram = .{ .data = "datagram", .length_present = false } },
        .{ .datagram = .{ .data = "datagram", .length_present = true } },
        .{ .ack_frequency = .{
            .sequence_number = 1,
            .ack_eliciting_threshold = 2,
            .request_max_ack_delay = 3,
            .reordering_threshold = 4,
        } },
    };

    for (frames) |frame| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try frame.write(&encoded, allocator);
        try std.testing.expectEqual(encoded.items.len, try frame.wireLen());
    }
}

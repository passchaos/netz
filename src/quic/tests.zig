const std = @import("std");
const quic_root = @import("mod.zig");

const connection_id = @import("connection_id.zig");
const handshake = @import("handshake.zig");
const one_rtt = @import("one_rtt.zig");
const tls = @import("tls/mod.zig");
const varint = @import("varint.zig");
const wire = @import("../internal/wire.zig");
const zero_rtt = @import("zero_rtt/mod.zig");

const AckRange = quic_root.AckRange;
const Frame = quic_root.Frame;
const FrameType = quic_root.FrameType;
const LongHeader = quic_root.LongHeader;
const PacketType = quic_root.PacketType;
const RetryPacketOptions = quic_root.RetryPacketOptions;
const TransportErrorCode = quic_root.TransportErrorCode;
const TransportParameterId = quic_root.TransportParameterId;
const TransportParameters = quic_root.TransportParameters;
const Version = quic_root.Version;
const VersionNegotiationPacketOptions = quic_root.VersionNegotiationPacketOptions;
const appendPadding = quic_root.appendPadding;
const classifyFramePayloadCloseError = quic_root.classifyFramePayloadCloseError;
const default_max_udp_payload_size = quic_root.default_max_udp_payload_size;
const encodeIntegerTransportParameter = quic_root.encodeIntegerTransportParameter;
const encodeReservedTransportParameter = quic_root.encodeReservedTransportParameter;
const encodeTransportParameter = quic_root.encodeTransportParameter;
const encodeTransportParameters = quic_root.encodeTransportParameters;
const encodeTransportParametersForSource = quic_root.encodeTransportParametersForSource;
const encodeVersionInformationFromVersions = quic_root.encodeVersionInformationFromVersions;
const frameAllowedInPacketType = quic_root.frameAllowedInPacketType;
const frameDecodeTransportErrorCode = quic_root.frameDecodeTransportErrorCode;
const inline_unknown_transport_parameters = quic_root.inline_unknown_transport_parameters;
const isReservedTransportParameterId = quic_root.isReservedTransportParameterId;
const max_stream_count = quic_root.max_stream_count;
const parseFrame = quic_root.parseFrame;
const parseFrameInto = quic_root.parseFrameInto;
const parseFrameOwned = quic_root.parseFrameOwned;
const parseRetryPacket = quic_root.parseRetryPacket;
const parseTransportParameters = quic_root.parseTransportParameters;
const parseTransportParametersTyped = quic_root.parseTransportParametersTyped;
const parseVersionNegotiationPacket = quic_root.parseVersionNegotiationPacket;
const rawFrameTypeValue = quic_root.rawFrameTypeValue;
const retryIntegrityTag = quic_root.retryIntegrityTag;
const retryPacketLen = quic_root.retryPacketLen;
const validateFrameForPacketType = quic_root.validateFrameForPacketType;
const validateTransportParameters = quic_root.validateTransportParameters;
const verifyRetryIntegrityTag = quic_root.verifyRetryIntegrityTag;
const versionNegotiationPacketLen = quic_root.versionNegotiationPacketLen;
const writeRetryPacket = quic_root.writeRetryPacket;
const writeRetryPacketInto = quic_root.writeRetryPacketInto;
const writeVersionNegotiationPacket = quic_root.writeVersionNegotiationPacket;
const writeVersionNegotiationPacketInto = quic_root.writeVersionNegotiationPacketInto;

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

    const options: VersionNegotiationPacketOptions = .{
        .first_byte = 0xf0,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .versions = &versions,
    };
    var direct_storage: [64]u8 = undefined;
    const direct = try writeVersionNegotiationPacketInto(
        &direct_storage,
        options,
    );
    try std.testing.expectEqual(
        encoded.items.len,
        try versionNegotiationPacketLen(options),
    );
    try std.testing.expectEqualSlices(u8, encoded.items, direct);
    try std.testing.expectError(
        error.BufferTooShort,
        writeVersionNegotiationPacketInto(
            direct_storage[0 .. direct.len - 1],
            options,
        ),
    );
    var no_alloc_list = std.ArrayList(u8).initBuffer(&direct_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeVersionNegotiationPacket(
        &no_alloc_list,
        no_alloc.allocator(),
        options,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, encoded.items, no_alloc_list.items);

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
    const options: RetryPacketOptions = .{
        .destination_connection_id = &empty_cid,
        .source_connection_id = &retry_scid,
        .token = &token,
        .original_destination_connection_id = &original_dcid,
    };
    var direct_storage: [64]u8 = undefined;
    const direct = try writeRetryPacketInto(&direct_storage, options);
    try std.testing.expectEqual(try retryPacketLen(options), direct.len);
    try std.testing.expectEqualSlices(u8, &expected, direct);
    try std.testing.expectError(
        error.BufferTooShort,
        writeRetryPacketInto(direct_storage[0 .. direct.len - 1], options),
    );
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expect(try verifyRetryIntegrityTag(
        no_alloc.allocator(),
        &original_dcid,
        direct,
    ));
    try std.testing.expect(!no_alloc.has_induced_failure);
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
        .reset_stream_at = true,
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
    try std.testing.expect(decoded.reset_stream_at);
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

    var bad_version_info: std.ArrayList(u8) = .empty;
    defer bad_version_info.deinit(allocator);
    try encodeTransportParameter(&bad_version_info, allocator, @intFromEnum(TransportParameterId.version_information), &.{ 0, 0, 0 });
    try std.testing.expectError(error.InvalidTransportParameterLength, parseTransportParametersTyped(allocator, bad_version_info.items, .client));
    bad_version_info.clearRetainingCapacity();
    try encodeTransportParameter(&bad_version_info, allocator, @intFromEnum(TransportParameterId.version_information), &.{ 0, 0, 0, 0 });
    try std.testing.expectError(error.InvalidTransportParameter, parseTransportParametersTyped(allocator, bad_version_info.items, .client));
    bad_version_info.clearRetainingCapacity();
    try encodeVersionInformationFromVersions(&bad_version_info, allocator, .version_1, &.{ .version_1, .version_2, @enumFromInt(0x0a0a0a0a) });
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

    var non_empty_reset_stream_at: std.ArrayList(u8) = .empty;
    defer non_empty_reset_stream_at.deinit(allocator);
    try encodeTransportParameter(
        &non_empty_reset_stream_at,
        allocator,
        @intFromEnum(TransportParameterId.reset_stream_at),
        &.{1},
    );
    try std.testing.expectError(
        error.InvalidTransportParameterLength,
        parseTransportParametersTyped(
            allocator,
            non_empty_reset_stream_at.items,
            .client,
        ),
    );
}

test "QUIC typed transport parameters parse known fields without allocation" {
    const client_cid = [_]u8{ 1, 2, 3, 4 };
    const versions = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0x6b, 0x33, 0x43, 0xcf,
    };
    const params = TransportParameters{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 1024,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 4,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = &client_cid,
        .version_information = .{
            .chosen_version = .version_1,
            .available_versions_wire = &versions,
        },
        .max_datagram_frame_size = 1200,
        .reset_stream_at = true,
        .grease_quic_bit = true,
        .min_ack_delay = 1000,
    };

    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encodeTransportParametersForSource(
        &encoded,
        allocator,
        params,
        .client,
    );

    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    const decoded = try parseTransportParametersTyped(
        no_alloc.allocator(),
        encoded.items,
        .client,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        params.initial_max_data,
        decoded.initial_max_data,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_cid,
        decoded.initial_source_connection_id.?,
    );
}

test "QUIC typed transport parameter parser spills only excess unknown IDs" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    for (0..inline_unknown_transport_parameters) |index| {
        try encodeTransportParameter(
            &encoded,
            allocator,
            0x100 + index,
            &.{},
        );
    }

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    _ = try parseTransportParametersTyped(
        no_alloc.allocator(),
        encoded.items,
        .client,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    try encodeTransportParameter(
        &encoded,
        allocator,
        0x100 + inline_unknown_transport_parameters,
        &.{},
    );
    var spill_fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        parseTransportParametersTyped(
            spill_fail.allocator(),
            encoded.items,
            .client,
        ),
    );

    try encodeTransportParameter(
        &encoded,
        allocator,
        0x100 + inline_unknown_transport_parameters,
        &.{ 1, 2, 3 },
    );
    try std.testing.expectError(
        error.DuplicateTransportParameter,
        parseTransportParametersTyped(allocator, encoded.items, .client),
    );
}

test "QUIC integer transport parameters accept the full RFC 9000 range" {
    const allocator = std.testing.allocator;
    const large_udp_payload_size = default_max_udp_payload_size + 1;
    const params = TransportParameters{
        .max_idle_timeout = varint.max_value,
        .max_udp_payload_size = large_udp_payload_size,
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encodeTransportParametersForSource(&encoded, allocator, params, .client);
    const decoded = try parseTransportParametersTyped(
        allocator,
        encoded.items,
        .client,
    );
    try std.testing.expectEqual(varint.max_value, decoded.max_idle_timeout);
    try std.testing.expectEqual(
        large_udp_payload_size,
        decoded.max_udp_payload_size,
    );

    try std.testing.expectError(
        error.InvalidTransportParameter,
        validateTransportParameters(.{
            .max_idle_timeout = @as(u64, varint.max_value) + 1,
        }, .client),
    );
}

test "QUIC Version Information applies sender-specific available versions" {
    const allocator = std.testing.allocator;
    const only_v2 = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    const params = TransportParameters{
        .version_information = .{
            .chosen_version = .version_1,
            .available_versions_wire = &only_v2,
        },
    };

    try std.testing.expectError(
        error.InvalidTransportParameter,
        validateTransportParameters(params, .client),
    );
    try validateTransportParameters(params, .server);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encodeTransportParametersForSource(
        &encoded,
        allocator,
        params,
        .server,
    );
    try std.testing.expectError(
        error.InvalidTransportParameter,
        parseTransportParametersTyped(allocator, encoded.items, .client),
    );
    const decoded = try parseTransportParametersTyped(
        allocator,
        encoded.items,
        .server,
    );
    try std.testing.expectEqual(
        Version.version_1,
        decoded.version_information.?.chosen_version,
    );
    try std.testing.expect(!decoded.version_information.?
        .containsAvailableVersion(.version_1));
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

    encoded.clearRetainingCapacity();
    try (Frame{ .ack_frequency = .{
        .sequence_number = 10,
        .ack_eliciting_threshold = 0,
        .request_max_ack_delay = 0,
        .reordering_threshold = 0,
    } }).write(&encoded, allocator);
    const immediate_frequency = try parseFrame(encoded.items);
    try std.testing.expectEqual(
        @as(u64, 0),
        immediate_frequency.frame.ack_frequency.ack_eliciting_threshold,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        immediate_frequency.frame.ack_frequency.reordering_threshold,
    );

    encoded.clearRetainingCapacity();
    try varint.encode(&encoded, allocator, @intFromEnum(FrameType.ack_frequency));
    try varint.encode(&encoded, allocator, 10);
    try varint.encode(&encoded, allocator, 0);
    try varint.encode(&encoded, allocator, 0);
    try varint.encode(&encoded, allocator, 0);
    const parsed_zero = try parseFrame(encoded.items);
    try std.testing.expectEqual(
        @as(u64, 0),
        parsed_zero.frame.ack_frequency.ack_eliciting_threshold,
    );
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
    const reset_stream_at = Frame{ .reset_stream_at = .{
        .stream_id = 4,
        .application_error_code = 7,
        .final_size = 99,
        .reliable_size = 63,
    } };
    try reset_stream_at.write(&encoded, allocator);
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(FrameType.reset_stream_at)),
        encoded.items[0],
    );
    try std.testing.expectEqual(encoded.items.len, try reset_stream_at.wireLen());
    parsed = try parseFrame(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.frame.reset_stream_at.stream_id);
    try std.testing.expectEqual(
        @as(u64, 7),
        parsed.frame.reset_stream_at.application_error_code,
    );
    try std.testing.expectEqual(@as(u64, 99), parsed.frame.reset_stream_at.final_size);
    try std.testing.expectEqual(@as(u64, 63), parsed.frame.reset_stream_at.reliable_size);
    try std.testing.expect(frameAllowedInPacketType(reset_stream_at, .zero_rtt));
    try std.testing.expect(frameAllowedInPacketType(reset_stream_at, .one_rtt));
    try std.testing.expect(!frameAllowedInPacketType(reset_stream_at, .handshake));

    try std.testing.expectError(
        error.InvalidFrame,
        (Frame{ .reset_stream_at = .{
            .stream_id = 4,
            .application_error_code = 7,
            .final_size = 62,
            .reliable_size = 63,
        } }).wireLen(),
    );

    encoded.clearRetainingCapacity();
    try varint.encode(&encoded, allocator, @intFromEnum(FrameType.reset_stream_at));
    try varint.encode(&encoded, allocator, 4);
    try varint.encode(&encoded, allocator, 7);
    try varint.encode(&encoded, allocator, 62);
    try varint.encode(&encoded, allocator, 63);
    try std.testing.expectError(error.InvalidFrame, parseFrame(encoded.items));

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

    // Decoding retains this semantically invalid shape so the endpoint role
    // can choose RFC 9000's FRAME_ENCODING_ERROR or PROTOCOL_VIOLATION.
    const empty_encoded = [_]u8{
        @intFromEnum(FrameType.new_token),
        0,
    };
    const parsed_empty = try parseFrame(&empty_encoded);
    try std.testing.expectEqual(
        @as(usize, 0),
        parsed_empty.frame.new_token.token.len,
    );
    try std.testing.expectError(
        error.InvalidFrame,
        (Frame{ .new_token = .{ .token = "" } }).wireLen(),
    );
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

test "QUIC ACK frame parser writes ranges into caller storage" {
    const allocator = std.testing.allocator;
    const ranges = [_]AckRange{
        .{ .gap = 0, .ack_range_length = 1 },
        .{ .gap = 2, .ack_range_length = 0 },
    };
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try (Frame{ .ack = .{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    } }).write(&bytes, allocator);

    var storage: [2]AckRange = undefined;
    const parsed = try parseFrameInto(bytes.items, &storage);
    try std.testing.expect(parsed.frame == .ack);
    try std.testing.expectEqual(
        @intFromPtr(&storage),
        @intFromPtr(parsed.frame.ack.ranges.ptr),
    );
    try std.testing.expectEqualDeep(ranges, storage);
    try std.testing.expectError(
        error.BufferTooShort,
        parseFrameInto(bytes.items, storage[0..1]),
    );
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
        .{ .reset_stream_at = .{ .stream_id = 4, .application_error_code = 7, .final_size = 99, .reliable_size = 63 } },
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
        const frame_len = try frame.wireLen();
        try std.testing.expectEqual(encoded.items.len, frame_len);

        const assume_storage = try allocator.alloc(u8, frame_len);
        defer allocator.free(assume_storage);
        var assume_encoded = std.ArrayList(u8).initBuffer(assume_storage);
        try frame.writeAssumeCapacity(&assume_encoded);
        try std.testing.expectEqualSlices(u8, encoded.items, assume_encoded.items);
    }
}

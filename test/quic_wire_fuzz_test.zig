//! Bounded QUIC wire-format fuzzing.
//!
//! This target covers packet headers, transport parameters, frame streams,
//! and the TLS handshake messages carried by QUIC CRYPTO frames. It does not
//! perform packet protection or network I/O.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes = 64 * 1024;
const max_frames = 512;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const initial_header_seed = smithSliceSeed(
    "\xc0\x00\x00\x00\x01\x04abcd\x04efgh\x00\x02\x00x",
);
const version_negotiation_seed = smithSliceSeed(
    "\x80\x00\x00\x00\x00\x04abcd\x02xy" ++
        "\x00\x00\x00\x01\x6b\x33\x43\xcf",
);
const retry_seed = smithSliceSeed(&.{
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 't',
    'o',  'k',  'e',  'n',  0x04, 0xa2, 0x65, 0xba,
    0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
    0x0f, 0x24, 0x96, 0xba,
});
const transport_parameters_seed = smithSliceSeed(&.{
    0x04, 0x02, 0x40, 0x64, // initial_max_data = 100.
    0x0e, 0x01, 0x04, // active_connection_id_limit = 4.
    0x0c, 0x00, // disable_active_migration.
    0x1d, 0x00, // reset_stream_at.
});
const frame_sequence_seed = smithSliceSeed(&.{
    0x01, // PING.
    0x02, 10, 0, 2, 0, 0, 1, 2, 0, // ACK with two ranges.
    0x0f, 0, 0, 3, 'a', 'b', 'c', // STREAM with OFF/LEN/FIN.
    0x24, 0, 1, 4, 2, // RESET_STREAM_AT with a two-byte reliable prefix.
    0x1a, 1, 2, 3, 4, 5, 6, 7, 8, // PATH_CHALLENGE.
    0x1c, 0, 8, 3, 'b', 'a', 'd', // CONNECTION_CLOSE.
});
const client_hello_seed = smithSliceSeed(
    "\x01\x00\x00\x71\x03\x03" ++ ("\x11" ** 32) ++
        "\x00\x00\x02\x13\x01\x01\x00\x00\x46" ++
        "\x00\x0a\x00\x04\x00\x02\x00\x1d" ++
        "\x00\x10\x00\x05\x00\x03\x02h3" ++
        "\x00\x2b\x00\x03\x02\x03\x04" ++
        "\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" ++
        ("\x22" ** 32) ++ "\x00\x39\x00\x00",
);
const server_hello_seed = smithSliceSeed(
    "\x02\x00\x00\x56\x03\x03" ++ ("\x33" ** 32) ++
        "\x00\x13\x01\x00\x00\x2e" ++
        "\x00\x2b\x00\x02\x03\x04" ++
        "\x00\x33\x00\x24\x00\x1d\x00\x20" ++
        ("\x44" ** 32),
);
const encrypted_extensions_seed = smithSliceSeed(
    "\x08\x00\x00\x0f\x00\x0d" ++
        "\x00\x10\x00\x05\x00\x03\x02h3" ++
        "\x00\x39\x00\x00",
);
const finished_seed = smithSliceSeed(
    "\x14\x00\x00\x20" ++ ("\x55" ** 32),
);

test "structured QUIC wire seeds reach successful parsers" {
    const allocator = std.testing.allocator;
    const initial = try netz.quic.LongHeader.parse(initial_header_seed[4..]);
    try std.testing.expectEqual(netz.quic.PacketType.initial, initial.packet_type);
    _ = try netz.quic.LongHeader.parseWithFixedBitPolicy(
        initial_header_seed[4..],
        true,
    );
    var negotiation = try netz.quic.parseVersionNegotiationPacket(
        allocator,
        version_negotiation_seed[4..],
    );
    defer negotiation.deinit(allocator);
    _ = try netz.quic.parseRetryPacket(retry_seed[4..]);
    try std.testing.expect(try netz.quic.verifyRetryIntegrityTag(
        allocator,
        &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
        retry_seed[4..],
    ));

    const untyped_parameters = try netz.quic.parseTransportParameters(
        allocator,
        transport_parameters_seed[4..],
    );
    defer allocator.free(untyped_parameters);
    try std.testing.expectEqual(@as(usize, 4), untyped_parameters.len);
    const client_parameters = try netz.quic.parseTransportParametersTyped(
        allocator,
        transport_parameters_seed[4..],
        .client,
    );
    try std.testing.expectEqual(@as(u64, 100), client_parameters.initial_max_data);
    try std.testing.expect(client_parameters.disable_active_migration);
    try std.testing.expect(client_parameters.reset_stream_at);
    _ = try netz.quic.parseTransportParametersTyped(
        allocator,
        transport_parameters_seed[4..],
        .server,
    );

    var offset: usize = 0;
    var frame_count: usize = 0;
    while (offset < frame_sequence_seed.len - 4) : (frame_count += 1) {
        var parsed = try netz.quic.parseFrameOwned(
            allocator,
            frame_sequence_seed[4 + offset ..],
        );
        defer parsed.deinitOwned(allocator);
        offset += parsed.consumed;
    }
    try std.testing.expectEqual(@as(usize, 6), frame_count);
    try std.testing.expect((try netz.quic.classifyFramePayloadCloseError(
        allocator,
        frame_sequence_seed[4..],
        .one_rtt,
    )) == null);
    var ack_ranges: [2]netz.quic.AckRange = undefined;
    const ack = try netz.quic.parseFrameInto(
        frame_sequence_seed[5..],
        &ack_ranges,
    );
    try std.testing.expectEqual(@as(usize, 2), ack.frame.ack.ranges.len);

    var client_hello = try netz.quic.tls_client_hello.parseClientHello(
        client_hello_seed[4..],
    );
    defer client_hello.deinit(allocator);
    try std.testing.expectEqualStrings("h3", client_hello.alpnProtocols()[0]);
    _ = try netz.quic.tls_client_hello.parseServerHello(
        server_hello_seed[4..],
    );
    _ = try netz.quic.tls_client_hello.parseEncryptedExtensions(
        encrypted_extensions_seed[4..],
    );
    _ = try netz.quic.tls_client_hello.parseFinished(finished_seed[4..]);
}

test "fuzz bounded QUIC wire parsers" {
    try std.testing.fuzz({}, fuzzQuicWire, .{ .corpus = &.{
        &initial_header_seed,
        &version_negotiation_seed,
        &retry_seed,
        &transport_parameters_seed,
        &frame_sequence_seed,
        &client_hello_seed,
        &server_hello_seed,
        &encrypted_extensions_seed,
        &finished_seed,
    } });
}

test "bounded deterministic QUIC wire mutation smoke" {
    const seeds = [_][]const u8{
        initial_header_seed[4..],
        version_negotiation_seed[4..],
        retry_seed[4..],
        transport_parameters_seed[4..],
        frame_sequence_seed[4..],
        client_hello_seed[4..],
        server_hello_seed[4..],
        encrypted_extensions_seed[4..],
        finished_seed[4..],
    };
    var buffer: [max_input_bytes]u8 = undefined;
    for (seeds) |seed| {
        try exerciseAll(seed);
        for (0..seed.len + 1) |length| try exerciseAll(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(buffer[0..seed.len], seed);
            buffer[index] ^= 0xff;
            try exerciseAll(buffer[0..seed.len]);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x717569635f776972);
    const random = prng.random();
    for (0..128) |_| {
        const length = random.uintLessThan(usize, 4097);
        random.bytes(buffer[0..length]);
        try exerciseAll(buffer[0..length]);
    }
}

fn fuzzQuicWire(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseAll(bytes);
}

fn exerciseAll(bytes: []const u8) !void {
    try exercisePacketHeaders(bytes);
    try exerciseTransportParameters(bytes);
    try exerciseFrames(bytes);
    try exerciseTlsHandshakeMessages(bytes);
}

fn exercisePacketHeaders(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    if (netz.quic.LongHeader.parse(bytes)) |header| {
        try std.testing.expect(header.destination_connection_id.len <= 20);
        try std.testing.expect(header.source_connection_id.len <= 20);
        try std.testing.expect(header.packet_number.len <= 4);
    } else |_| {}
    if (netz.quic.LongHeader.parseWithFixedBitPolicy(bytes, true)) |header| {
        try std.testing.expect(header.destination_connection_id.len <= 20);
        try std.testing.expect(header.source_connection_id.len <= 20);
    } else |_| {}
    if (netz.quic.parseVersionNegotiationPacket(allocator, bytes)) |value| {
        var packet = value;
        defer packet.deinit(allocator);
        try std.testing.expect(packet.destination_connection_id.len <= 20);
        try std.testing.expect(packet.source_connection_id.len <= 20);
        try std.testing.expect(packet.versions.len <= bytes.len / 4);
    } else |_| {}
    if (netz.quic.parseRetryPacket(bytes)) |packet| {
        try std.testing.expectEqual(bytes.len, packet.consumed);
        try std.testing.expect(packet.destination_connection_id.len <= 20);
        try std.testing.expect(packet.source_connection_id.len <= 20);
        try std.testing.expect(packet.token.len < bytes.len);
        _ = netz.quic.verifyRetryIntegrityTag(
            allocator,
            &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
            bytes,
        ) catch {};
    } else |_| {}
}

fn exerciseTransportParameters(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    if (netz.quic.parseTransportParameters(allocator, bytes)) |parameters| {
        defer allocator.free(parameters);
        try std.testing.expect(parameters.len <= bytes.len / 2);
        for (parameters) |parameter| {
            try std.testing.expect(parameter.value.len <= bytes.len);
        }
    } else |_| {}
    inline for (.{
        netz.quic.TransportParameterSource.client,
        netz.quic.TransportParameterSource.server,
    }) |source| {
        if (netz.quic.parseTransportParametersTyped(
            allocator,
            bytes,
            source,
        )) |parameters| {
            try netz.quic.validateTransportParameters(parameters, source);
        } else |_| {}
    }
}

fn exerciseFrames(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    var offset: usize = 0;
    var count: usize = 0;
    while (offset < bytes.len and count < max_frames) : (count += 1) {
        var parsed = netz.quic.parseFrameOwned(
            allocator,
            bytes[offset..],
        ) catch break;
        defer parsed.deinitOwned(allocator);
        try std.testing.expect(parsed.consumed != 0);
        try std.testing.expect(parsed.consumed <= bytes.len - offset);
        _ = parsed.frame.wireLen() catch {};
        inline for (.{
            netz.quic.FramePacketType.initial,
            .handshake,
            .zero_rtt,
            .one_rtt,
        }) |packet_type| {
            _ = netz.quic.validateFrameForPacketType(
                parsed.frame,
                packet_type,
            ) catch {};
        }
        offset += parsed.consumed;
    }

    var ack_ranges: [64]netz.quic.AckRange = undefined;
    if (netz.quic.parseFrameInto(bytes, &ack_ranges)) |parsed| {
        try std.testing.expect(parsed.consumed != 0);
        try std.testing.expect(parsed.consumed <= bytes.len);
    } else |_| {}
    inline for (.{
        netz.quic.FramePacketType.initial,
        .handshake,
        .zero_rtt,
        .one_rtt,
    }) |packet_type| {
        _ = netz.quic.classifyFramePayloadCloseError(
            allocator,
            bytes,
            packet_type,
        ) catch {};
    }
}

fn exerciseTlsHandshakeMessages(bytes: []const u8) !void {
    const tls = netz.quic.tls_client_hello;
    if (tls.parseClientHello(bytes)) |value| {
        var hello = value;
        defer hello.deinit(std.testing.allocator);
        try std.testing.expect(
            hello.alpnProtocols().len <=
                tls.ParsedClientHello.max_alpn_protocols,
        );
        try std.testing.expect(hello.transport_parameters.len <= bytes.len);
        try std.testing.expect(hello.cipher_suites.len <= bytes.len);
    } else |_| {}
    if (tls.parseServerHello(bytes)) |hello| {
        try std.testing.expect(hello.keyShare().len <= bytes.len);
    } else |_| {}
    if (tls.parseEncryptedExtensions(bytes)) |extensions| {
        try std.testing.expect(extensions.alpn.len <= bytes.len);
        try std.testing.expect(extensions.transport_parameters.len <= bytes.len);
    } else |_| {}
    _ = tls.parseFinished(bytes) catch {};
}

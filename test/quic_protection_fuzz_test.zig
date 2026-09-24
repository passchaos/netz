//! Bounded QUIC packet-protection fuzzing.
//!
//! The generated path seals and opens valid Initial, Handshake, 0-RTT, and
//! 1-RTT packets across QUIC v1/v2 and every supported traffic cipher. The
//! hostile path sends arbitrary protected bytes through the public open, peek,
//! header-protection, and packet-number reconstruction APIs.

const std = @import("std");
const netz = @import("netz");

const protection = netz.quic.protection;
const max_input_bytes = 4 * 1024;
const max_packet_bytes = max_input_bytes + 128;
const config_bytes = 16;
const version_1: u32 = 0x00000001;
const version_2: u32 = 0x6b3343cf;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const initial_seed = smithSliceSeed(
    "\x00\x00\x00\x03\x00\x08\x04\x05" ++
        "\x00\x00\x00\x00\x00\x00\x12\x34initial crypto",
);
const handshake_aes256_seed = smithSliceSeed(
    "\x01\x01\x01\x01\x01\x08\x04\x00" ++
        "\x00\x00\x00\x00\x00\x00\x45\x67server finished",
);
const zero_rtt_chacha_seed = smithSliceSeed(
    "\x02\x02\x00\x02\x00\x04\x04\x00" ++
        "\x00\x00\x00\x00\x00\x00\x78\x9aearly stream data",
);
const zero_rtt_sm4_seed = smithSliceSeed(
    "\x02\x03\x01\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00\x00\x01\xab\xcdsm4 early data",
);
const short_aes128_seed = smithSliceSeed(
    "\x03\x00\x00\x00\x04\x08\x00\x00" ++
        "\x00\x00\x00\x00\x00\x02\x34\x56one-rtt aes128",
);
const short_aes256_seed = smithSliceSeed(
    "\x03\x01\x01\x01\x06\x14\x00\x00" ++
        "\x00\x00\x00\x00\x00\x03\x45\x67one-rtt aes256",
);
const short_chacha_seed = smithSliceSeed(
    "\x03\x02\x00\x02\x02\x04\x00\x00" ++
        "\x00\x00\x00\x00\x00\x04\x56\x78one-rtt chacha",
);
const short_sm4_seed = smithSliceSeed(
    "\x03\x03\x01\x03\x07\x00\x00\x00" ++
        "\x00\x00\x00\x00\x00\x05\x67\x89one-rtt sm4",
);

const corpus = &.{
    &initial_seed,
    &handshake_aes256_seed,
    &zero_rtt_chacha_seed,
    &zero_rtt_sm4_seed,
    &short_aes128_seed,
    &short_aes256_seed,
    &short_chacha_seed,
    &short_sm4_seed,
};

test "structured QUIC packet-protection seeds round trip" {
    inline for (corpus) |seed| try exerciseGenerated(seed[4..]);
}

test "fuzz bounded QUIC packet protection" {
    try std.testing.fuzz({}, fuzzPacketProtection, .{ .corpus = corpus });
}

test "bounded deterministic QUIC packet-protection mutation smoke" {
    var buffer: [max_input_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        try exerciseAll(seed);
        for (0..seed.len + 1) |length| try exerciseAll(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(buffer[0..seed.len], seed);
            buffer[index] ^= 0xff;
            try exerciseAll(buffer[0..seed.len]);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x717569635f637279);
    const random = prng.random();
    for (0..128) |_| {
        const length = random.uintLessThan(usize, max_input_bytes + 1);
        random.bytes(buffer[0..length]);
        try exerciseAll(buffer[0..length]);
    }
}

fn fuzzPacketProtection(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseAll(bytes);
}

fn exerciseAll(bytes: []const u8) !void {
    try exerciseHostile(bytes);
    try exerciseGenerated(bytes);
}

fn exerciseGenerated(bytes: []const u8) !void {
    switch (byteAt(bytes, 0) & 0x03) {
        0 => try exerciseInitial(bytes),
        1 => try exerciseHandshake(bytes),
        2 => try exerciseZeroRtt(bytes),
        3 => try exerciseShort(bytes),
        else => unreachable,
    }
}

fn exerciseHostile(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const version = selectedVersion(bytes);
    const suite = selectedSuite(bytes);
    const keys = try derivedKeys(suite, version, bytes);
    var initial_dcid = connectionId(bytes, 0x11);
    const initial_keys = (try protection.deriveInitialSecretsForVersion(
        version,
        initial_dcid.slice(),
    )).client;
    const expected_packet_number = selectedPacketNumber(bytes);

    if (protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
        bytes,
        true,
    )) |_| {} else |_| {}
    if (protection.openInitialPacketWithFixedBitPolicy(
        allocator,
        initial_keys,
        bytes,
        expected_packet_number,
        true,
    )) |value| {
        var opened = value;
        opened.deinit(allocator);
    } else |_| {}
    if (protection.openHandshakePacketWithFixedBitPolicy(
        allocator,
        keys,
        bytes,
        expected_packet_number,
        true,
    )) |value| {
        var opened = value;
        opened.deinit(allocator);
    } else |_| {}
    if (protection.openZeroRttPacketWithFixedBitPolicy(
        allocator,
        keys,
        bytes,
        expected_packet_number,
        true,
    )) |value| {
        var opened = value;
        opened.deinit(allocator);
    } else |_| {}

    const destination_connection_id_len = byteAt(bytes, 5) % 21;
    if (protection.peekShortPacketKeyPhaseForKeysWithFixedBitPolicy(
        keys,
        bytes,
        destination_connection_id_len,
        true,
    )) |_| {} else |_| {}
    if (protection.openShortPacketWithFixedBitPolicy(
        allocator,
        keys,
        bytes,
        destination_connection_id_len,
        expected_packet_number,
        true,
    )) |value| {
        var opened = value;
        opened.deinit(allocator);
    } else |_| {}

    var packet: [max_input_bytes]u8 = undefined;
    @memcpy(packet[0..bytes.len], bytes);
    _ = protection.openShortPacketInPlaceWithFixedBitPolicy(
        keys,
        packet[0..bytes.len],
        destination_connection_id_len,
        expected_packet_number,
        true,
    ) catch {};
    var key_phase_state = try protection.KeyPhaseState.initForVersion(
        version,
        keys,
        false,
    );
    if (protection.openShortPacketWithKeyUpdateAndFixedBitPolicy(
        allocator,
        key_phase_state.keyUpdateKeys(),
        bytes,
        destination_connection_id_len,
        expected_packet_number,
        true,
    )) |value| {
        var opened = value;
        opened.deinit(allocator);
    } else |_| {}

    @memcpy(packet[0..bytes.len], bytes);
    const pn_offset = byteAt(bytes, 6) % (bytes.len + 1);
    _ = protection.applyHeaderProtectionForKeys(
        keys,
        if ((byteAt(bytes, 7) & 1) == 0) .long else .short,
        packet[0..bytes.len],
        pn_offset,
    ) catch {};
    @memcpy(packet[0..bytes.len], bytes);
    _ = protection.removeHeaderProtectionForKeys(
        keys,
        if ((byteAt(bytes, 7) & 1) == 0) .long else .short,
        packet[0..bytes.len],
        pn_offset,
    ) catch {};
    const packet_number_bytes = bytes[0..@min(bytes.len, 5)];
    _ = protection.reconstructPacketNumber(
        expected_packet_number,
        packet_number_bytes,
    ) catch {};
}

fn exerciseInitial(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const version = selectedVersion(bytes);
    var dcid = connectionId(bytes, 0x21);
    var scid = connectionId(bytes, 0x31);
    var token = tokenBytes(bytes);
    const payload = selectedPayload(bytes);
    const packet_number = selectedPacketNumber(bytes);
    const packet_number_len = selectedPacketNumberLen(bytes, payload.len);
    const fixed_bit = selectedFixedBit(bytes);
    const keys = (try protection.deriveInitialSecretsForVersion(
        version,
        dcid.slice(),
    )).client;
    const options: protection.InitialPacketOptions = .{
        .version = version,
        .destination_connection_id = dcid.slice(),
        .source_connection_id = scid.slice(),
        .token = token.slice(),
        .packet_number = packet_number,
        .packet_number_len = packet_number_len,
        .fixed_bit = fixed_bit,
        .payload = payload,
    };

    const allocated = try protection.sealInitialPacket(allocator, keys, options);
    defer allocator.free(allocated);
    var storage: [max_packet_bytes]u8 = undefined;
    const sealed = try protection.sealInitialPacketInto(&storage, keys, options);
    try std.testing.expectEqualSlices(u8, allocated, sealed);
    const info = try protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
        sealed,
        !fixed_bit,
    );
    try std.testing.expectEqual(protection.ProtectedLongPacketType.initial, info.packet_type);
    try std.testing.expectEqual(sealed.len, info.len);

    var opened = try protection.openInitialPacketWithFixedBitPolicy(
        allocator,
        keys,
        sealed,
        packet_number,
        !fixed_bit,
    );
    defer opened.deinit(allocator);
    try expectLongRoundTrip(
        version,
        dcid.slice(),
        scid.slice(),
        packet_number,
        fixed_bit,
        payload,
        opened.version,
        opened.destination_connection_id,
        opened.source_connection_id,
        opened.packet_number,
        opened.fixed_bit,
        opened.payload,
    );
    try std.testing.expectEqualSlices(u8, token.slice(), opened.token);

    var tampered: [max_packet_bytes]u8 = undefined;
    @memcpy(tampered[0..sealed.len], sealed);
    tampered[sealed.len - 1] ^= 1;
    if (protection.openInitialPacketWithFixedBitPolicy(
        allocator,
        keys,
        tampered[0..sealed.len],
        packet_number,
        !fixed_bit,
    )) |value| {
        var accepted = value;
        accepted.deinit(allocator);
        return error.MutatedPacketAccepted;
    } else |_| {}
}

fn exerciseHandshake(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const version = selectedVersion(bytes);
    const suite = selectedSuite(bytes);
    const keys = try derivedKeys(suite, version, bytes);
    var dcid = connectionId(bytes, 0x41);
    var scid = connectionId(bytes, 0x51);
    const payload = selectedPayload(bytes);
    const packet_number = selectedPacketNumber(bytes);
    const packet_number_len = selectedPacketNumberLen(bytes, payload.len);
    const fixed_bit = selectedFixedBit(bytes);
    const options: protection.HandshakePacketOptions = .{
        .version = version,
        .destination_connection_id = dcid.slice(),
        .source_connection_id = scid.slice(),
        .packet_number = packet_number,
        .packet_number_len = packet_number_len,
        .fixed_bit = fixed_bit,
        .payload = payload,
    };

    const allocated = try protection.sealHandshakePacket(allocator, keys, options);
    defer allocator.free(allocated);
    var storage: [max_packet_bytes]u8 = undefined;
    const sealed = try protection.sealHandshakePacketInto(&storage, keys, options);
    try std.testing.expectEqualSlices(u8, allocated, sealed);
    const info = try protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
        sealed,
        !fixed_bit,
    );
    try std.testing.expectEqual(protection.ProtectedLongPacketType.handshake, info.packet_type);

    var opened = try protection.openHandshakePacketWithFixedBitPolicy(
        allocator,
        keys,
        sealed,
        packet_number,
        !fixed_bit,
    );
    defer opened.deinit(allocator);
    try expectLongRoundTrip(
        version,
        dcid.slice(),
        scid.slice(),
        packet_number,
        fixed_bit,
        payload,
        opened.version,
        opened.destination_connection_id,
        opened.source_connection_id,
        opened.packet_number,
        opened.fixed_bit,
        opened.payload,
    );
    try expectTamperedHandshakeRejected(
        allocator,
        keys,
        sealed,
        packet_number,
        !fixed_bit,
    );
}

fn exerciseZeroRtt(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const version = selectedVersion(bytes);
    const suite = selectedSuite(bytes);
    const keys = try derivedKeys(suite, version, bytes);
    var dcid = connectionId(bytes, 0x61);
    var scid = connectionId(bytes, 0x71);
    const payload = selectedPayload(bytes);
    const packet_number = selectedPacketNumber(bytes);
    const packet_number_len = selectedPacketNumberLen(bytes, payload.len);
    const fixed_bit = selectedFixedBit(bytes);
    const options: protection.ZeroRttPacketOptions = .{
        .version = version,
        .destination_connection_id = dcid.slice(),
        .source_connection_id = scid.slice(),
        .packet_number = packet_number,
        .packet_number_len = packet_number_len,
        .fixed_bit = fixed_bit,
        .payload = payload,
    };

    const allocated = try protection.sealZeroRttPacket(allocator, keys, options);
    defer allocator.free(allocated);
    var storage: [max_packet_bytes]u8 = undefined;
    const sealed = try protection.sealZeroRttPacketInto(&storage, keys, options);
    try std.testing.expectEqualSlices(u8, allocated, sealed);
    const info = try protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
        sealed,
        !fixed_bit,
    );
    try std.testing.expectEqual(protection.ProtectedLongPacketType.zero_rtt, info.packet_type);

    var opened = try protection.openZeroRttPacketWithFixedBitPolicy(
        allocator,
        keys,
        sealed,
        packet_number,
        !fixed_bit,
    );
    defer opened.deinit(allocator);
    try expectLongRoundTrip(
        version,
        dcid.slice(),
        scid.slice(),
        packet_number,
        fixed_bit,
        payload,
        opened.version,
        opened.destination_connection_id,
        opened.source_connection_id,
        opened.packet_number,
        opened.fixed_bit,
        opened.payload,
    );
    try expectTamperedZeroRttRejected(
        allocator,
        keys,
        sealed,
        packet_number,
        !fixed_bit,
    );
}

fn exerciseShort(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const version = selectedVersion(bytes);
    const suite = selectedSuite(bytes);
    const current_keys = try derivedKeys(suite, version, bytes);
    const key_phase = (byteAt(bytes, 4) & 0x02) != 0;
    const sealing_keys = if (key_phase)
        try protection.nextPacketProtectionKeysForVersion(version, current_keys)
    else
        current_keys;
    var dcid = connectionId(bytes, 0x81);
    const payload = selectedPayload(bytes);
    const packet_number = selectedPacketNumber(bytes);
    const packet_number_len = selectedPacketNumberLen(bytes, payload.len);
    const fixed_bit = selectedFixedBit(bytes);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = dcid.slice(),
        .packet_number = packet_number,
        .packet_number_len = packet_number_len,
        .fixed_bit = fixed_bit,
        .spin_bit = (byteAt(bytes, 4) & 0x04) != 0,
        .key_phase = key_phase,
        .payload = payload,
    };

    const allocated = try protection.sealShortPacket(
        allocator,
        sealing_keys,
        options,
    );
    defer allocator.free(allocated);
    var storage: [max_packet_bytes]u8 = undefined;
    const sealed = try protection.sealShortPacketInto(
        &storage,
        sealing_keys,
        options,
    );
    try std.testing.expectEqualSlices(u8, allocated, sealed);

    var prepared = protection.PreparedPacketProtectionKeys.init(sealing_keys);
    defer prepared.deinit();
    var prepared_storage: [max_packet_bytes]u8 = undefined;
    const prepared_sealed = try protection.sealShortPacketIntoPrepared(
        &prepared_storage,
        &prepared,
        options,
    );
    try std.testing.expectEqualSlices(u8, sealed, prepared_sealed);
    try std.testing.expectEqual(
        key_phase,
        try protection.peekShortPacketKeyPhaseForKeysWithFixedBitPolicy(
            sealing_keys,
            sealed,
            dcid.len,
            !fixed_bit,
        ),
    );

    var opened = try protection.openShortPacketWithFixedBitPolicy(
        allocator,
        sealing_keys,
        sealed,
        dcid.len,
        packet_number,
        !fixed_bit,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqualSlices(u8, dcid.slice(), opened.destination_connection_id);
    try std.testing.expectEqual(packet_number, opened.packet_number);
    try std.testing.expectEqual(fixed_bit, opened.fixed_bit);
    try std.testing.expectEqual(options.spin_bit, opened.spin_bit);
    try std.testing.expectEqual(key_phase, opened.key_phase);
    try std.testing.expectEqualSlices(u8, payload, opened.payload);

    var open_storage: [max_packet_bytes]u8 = undefined;
    @memcpy(open_storage[0..sealed.len], sealed);
    const packet_number_offset = 1 + dcid.len;
    try protection.removeHeaderProtectionForKeys(
        sealing_keys,
        .short,
        open_storage[0..sealed.len],
        packet_number_offset,
    );
    try protection.applyHeaderProtectionForKeys(
        sealing_keys,
        .short,
        open_storage[0..sealed.len],
        packet_number_offset,
    );
    try std.testing.expectEqualSlices(
        u8,
        sealed,
        open_storage[0..sealed.len],
    );

    @memcpy(open_storage[0..sealed.len], sealed);
    const in_place = try protection
        .openShortPacketInPlaceForPreparedKeyPhaseWithFixedBitPolicy(
        &prepared,
        key_phase,
        open_storage[0..sealed.len],
        dcid.len,
        packet_number,
        !fixed_bit,
    );
    try std.testing.expect(in_place == .opened);
    try std.testing.expectEqualSlices(u8, payload, in_place.opened.payload);

    var receiver = try protection.KeyPhaseState.initForVersion(
        version,
        current_keys,
        false,
    );
    var updated = try protection.openShortPacketWithKeyUpdateAndFixedBitPolicy(
        allocator,
        receiver.keyUpdateKeys(),
        sealed,
        dcid.len,
        packet_number,
        !fixed_bit,
    );
    defer updated.deinit(allocator);
    try std.testing.expectEqual(key_phase, updated.peer_initiated_key_update);
    if (updated.peer_initiated_key_update) {
        try std.testing.expect(receiver.updateAfterReceiving(
            updated.packet.key_phase,
        ));
    }

    var tampered: [max_packet_bytes]u8 = undefined;
    @memcpy(tampered[0..sealed.len], sealed);
    tampered[sealed.len - 1] ^= 1;
    if (protection.openShortPacketWithFixedBitPolicy(
        allocator,
        sealing_keys,
        tampered[0..sealed.len],
        dcid.len,
        packet_number,
        !fixed_bit,
    )) |value| {
        var accepted = value;
        accepted.deinit(allocator);
        return error.MutatedPacketAccepted;
    } else |_| {}
}

fn expectLongRoundTrip(
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u64,
    fixed_bit: bool,
    payload: []const u8,
    opened_version: u32,
    opened_dcid: []const u8,
    opened_scid: []const u8,
    opened_packet_number: u64,
    opened_fixed_bit: bool,
    opened_payload: []const u8,
) !void {
    try std.testing.expectEqual(version, opened_version);
    try std.testing.expectEqualSlices(u8, dcid, opened_dcid);
    try std.testing.expectEqualSlices(u8, scid, opened_scid);
    try std.testing.expectEqual(packet_number, opened_packet_number);
    try std.testing.expectEqual(fixed_bit, opened_fixed_bit);
    try std.testing.expectEqualSlices(u8, payload, opened_payload);
}

fn expectTamperedHandshakeRejected(
    allocator: std.mem.Allocator,
    keys: protection.PacketProtectionKeys,
    sealed: []const u8,
    packet_number: u64,
    allow_zero_fixed_bit: bool,
) !void {
    var tampered: [max_packet_bytes]u8 = undefined;
    @memcpy(tampered[0..sealed.len], sealed);
    tampered[sealed.len - 1] ^= 1;
    if (protection.openHandshakePacketWithFixedBitPolicy(
        allocator,
        keys,
        tampered[0..sealed.len],
        packet_number,
        allow_zero_fixed_bit,
    )) |value| {
        var accepted = value;
        accepted.deinit(allocator);
        return error.MutatedPacketAccepted;
    } else |_| {}
}

fn expectTamperedZeroRttRejected(
    allocator: std.mem.Allocator,
    keys: protection.PacketProtectionKeys,
    sealed: []const u8,
    packet_number: u64,
    allow_zero_fixed_bit: bool,
) !void {
    var tampered: [max_packet_bytes]u8 = undefined;
    @memcpy(tampered[0..sealed.len], sealed);
    tampered[sealed.len - 1] ^= 1;
    if (protection.openZeroRttPacketWithFixedBitPolicy(
        allocator,
        keys,
        tampered[0..sealed.len],
        packet_number,
        allow_zero_fixed_bit,
    )) |value| {
        var accepted = value;
        accepted.deinit(allocator);
        return error.MutatedPacketAccepted;
    } else |_| {}
}

const BoundedBytes = struct {
    bytes: [20]u8,
    len: usize,

    fn slice(self: *const BoundedBytes) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn connectionId(bytes: []const u8, salt: u8) BoundedBytes {
    var result = BoundedBytes{
        .bytes = undefined,
        .len = byteAt(bytes, if (salt == 0x31 or salt == 0x51 or salt == 0x71) 6 else 5) % 21,
    };
    for (&result.bytes, 0..) |*byte, index| {
        byte.* = byteAt(bytes, config_bytes + index) ^ salt ^ @as(u8, @intCast(index));
    }
    return result;
}

fn tokenBytes(bytes: []const u8) BoundedBytes {
    var result = BoundedBytes{
        .bytes = undefined,
        .len = byteAt(bytes, 7) % 21,
    };
    for (&result.bytes, 0..) |*byte, index| {
        byte.* = byteAt(bytes, 8 + index) ^ 0xa5;
    }
    return result;
}

fn selectedPayload(bytes: []const u8) []const u8 {
    return bytes[@min(bytes.len, config_bytes)..];
}

fn selectedVersion(bytes: []const u8) u32 {
    return if ((byteAt(bytes, 2) & 1) == 0) version_1 else version_2;
}

fn selectedSuite(bytes: []const u8) protection.CipherSuite {
    return switch (byteAt(bytes, 1) & 0x03) {
        0 => .aes_128_gcm_sha256,
        1 => .aes_256_gcm_sha384,
        2 => .chacha20_poly1305_sha256,
        3 => .sm4_gcm_sm3,
        else => unreachable,
    };
}

fn selectedPacketNumberLen(bytes: []const u8, payload_len: usize) u8 {
    const requested: u8 = (byteAt(bytes, 3) & 0x03) + 1;
    return @max(
        requested,
        protection.minimumPacketNumberLenForHeaderProtection(payload_len),
    );
}

fn selectedFixedBit(bytes: []const u8) bool {
    return (byteAt(bytes, 4) & 1) == 0;
}

fn selectedPacketNumber(bytes: []const u8) u64 {
    var encoded = [_]u8{0} ** 8;
    const available = @min(bytes.len, config_bytes);
    if (available > 8) @memcpy(encoded[0 .. available - 8], bytes[8..available]);
    return std.mem.readInt(u64, &encoded, .big) & protection.max_packet_number;
}

fn derivedKeys(
    suite: protection.CipherSuite,
    version: u32,
    bytes: []const u8,
) !protection.PacketProtectionKeys {
    var secret_32: [32]u8 = undefined;
    var secret_48: [48]u8 = undefined;
    for (&secret_32, 0..) |*byte, index| {
        byte.* = byteAt(bytes, index) ^ @as(u8, @truncate(index *% 29));
    }
    for (&secret_48, 0..) |*byte, index| {
        byte.* = byteAt(bytes, index) ^ @as(u8, @truncate(index *% 31));
    }
    const secret = switch (suite.hash()) {
        .sha256 => netz.quic.tls.secret.Secret.fromSha256(secret_32),
        .sha384 => netz.quic.tls.secret.Secret.fromSha384(secret_48),
        .sm3 => netz.quic.tls.secret.Secret.fromSm3(secret_32),
    };
    return protection.deriveKeysForSecretForVersion(
        version,
        suite,
        secret,
    );
}

fn byteAt(bytes: []const u8, index: usize) u8 {
    return if (bytes.len == 0) 0 else bytes[index % bytes.len];
}

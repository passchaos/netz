const std = @import("std");
const vail = @import("vail");
const protection = @import("../protection.zig");
const varint = @import("../varint.zig");
const wire = @import("../../internal/wire.zig");

const version_1_wire_for_test: u32 = 0x00000001;
const version_2_wire_for_test: u32 = 0x6b3343cf;

fn longHeaderFirstByteForTest(
    version: u32,
    packet_type: protection.ProtectedLongPacketType,
    packet_number_len: u8,
) u8 {
    const type_bits: u8 = if (version == version_2_wire_for_test) switch (packet_type) {
        .retry => 0,
        .initial => 1,
        .zero_rtt => 2,
        .handshake => 3,
    } else switch (packet_type) {
        .initial => 0,
        .zero_rtt => 1,
        .handshake => 2,
        .retry => 3,
    };
    return 0xc0 | (type_bits << 4) | @as(u8, @intCast(packet_number_len - 1));
}

fn appendTruncatedPacketNumberForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    packet_number: u64,
    packet_number_len: u8,
) !void {
    if (packet_number_len == 0 or packet_number_len > 4) {
        return error.InvalidPacketNumberLength;
    }
    if (packet_number > protection.max_packet_number) {
        return error.InvalidPacketNumber;
    }
    var full: [8]u8 = undefined;
    std.mem.writeInt(u64, &full, packet_number, .big);
    try list.appendSlice(allocator, full[8 - packet_number_len ..]);
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected_buf: [128]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_buf, expected_hex);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "QUIC initial secrets match RFC 9001 Appendix A.1" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = protection.deriveInitialSecrets(&dcid);

    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial_secret);
    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", &secrets.client.secret);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &secrets.client.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &secrets.client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &secrets.client.hp);
    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", &secrets.server.secret);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", &secrets.server.key);
    try expectHex("0ac1493ca1905853b0bba03e", &secrets.server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", &secrets.server.hp);
}

test "QUIC AES header protection mask matches RFC 9001 Appendix A.2 sample" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = protection.deriveInitialSecrets(&dcid);
    var sample: [protection.header_protection_sample_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = protection.aes128HeaderProtectionMask(secrets.client.hp, sample);
    try expectHex("437b9aec36", &mask);

    var first_byte: u8 = 0xc3;
    var packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    try protection.applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc0), first_byte);
    try expectHex("7b9aec34", &packet_number);
    try protection.applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc3), first_byte);
    try expectHex("00000002", &packet_number);
}

test "QUIC AES payload protection roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = protection.deriveInitialSecrets(&dcid).client;
    const ad = "initial header pn";
    const plaintext = "crypto frame bytes";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [protection.aead_tag_len]u8 = undefined;
    try protection.protectPayload(keys, 2, ad, plaintext, &ciphertext, &tag);

    var opened: [plaintext.len]u8 = undefined;
    try protection.openPayload(keys, 2, ad, &ciphertext, tag, &opened);
    try std.testing.expectEqualStrings(plaintext, &opened);

    var bad_tag = tag;
    bad_tag[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, protection.openAes128Payload(keys, 2, ad, &ciphertext, bad_tag, &opened));
}

test "QUIC ChaCha20 short packet seal open and key update roundtrip" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveChaCha20Keys([_]u8{0x54} ** protection.secret_len);
    const packet = try protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "chacha-cid",
        .packet_number = 7,
        .packet_number_len = 4,
        .key_phase = false,
        .payload = "chacha payload",
    });
    defer allocator.free(packet);
    var opened = try protection.openShortPacket(
        allocator,
        keys,
        packet,
        "chacha-cid".len,
        7,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqualStrings("chacha payload", opened.payload);
    try std.testing.expectEqual(
        vail.quic.traffic_crypto.Suite.chacha20_poly1305_sha256,
        keys.suite,
    );

    const next = protection.nextAes128PacketProtectionKeys(keys);
    try std.testing.expectEqual(keys.suite, next.suite);
    try std.testing.expectEqualSlices(u8, &keys.suite_hp, &next.suite_hp);
    try std.testing.expect(!std.mem.eql(
        u8,
        &keys.suite_key,
        &next.suite_key,
    ));
}

test "QUIC Initial packets reject a negotiated ChaCha traffic key" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveChaCha20Keys(
        [_]u8{0x55} ** protection.secret_len,
    );
    try std.testing.expectError(
        error.InvalidCipherSuite,
        protection.sealInitialPacket(allocator, keys, .{
            .destination_connection_id = "initial-dcid",
            .source_connection_id = "scid",
            .packet_number = 0,
            .payload = "initial",
        }),
    );
    try std.testing.expectError(
        error.InvalidCipherSuite,
        protection.openInitialPacket(allocator, keys, &.{}, 0),
    );
}

test "QUIC AES key update derives next traffic keys and retains header protection" {
    const keys = protection.deriveAes128Keys([_]u8{0x44} ** protection.secret_len);
    const next_secret = protection.nextAes128TrafficSecret(keys.secret);
    const next = protection.nextAes128PacketProtectionKeys(keys);

    try std.testing.expectEqualSlices(u8, &next_secret, &next.secret);
    try std.testing.expect(!std.mem.eql(u8, &keys.secret, &next.secret));
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &next.key));
    try std.testing.expect(!std.mem.eql(u8, &keys.iv, &next.iv));
    try std.testing.expectEqualSlices(u8, &keys.hp, &next.hp);
}

test "QUIC v2 Initial secrets use v2 salt and labels" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const v1 = protection.deriveInitialSecrets(&dcid);
    const v2 = try protection.deriveInitialSecretsForVersion(version_2_wire_for_test, &dcid);

    try std.testing.expect(!std.mem.eql(u8, &v1.initial_secret, &v2.initial_secret));
    try std.testing.expect(!std.mem.eql(u8, &v1.client.key, &v2.client.key));
    try std.testing.expect(!std.mem.eql(u8, &v1.client.iv, &v2.client.iv));
    try std.testing.expect(!std.mem.eql(u8, &v1.client.hp, &v2.client.hp));

    const base = [_]u8{0x46} ** protection.secret_len;
    const v1_next = protection.nextAes128TrafficSecret(base);
    const v2_next = try protection.nextAes128TrafficSecretForVersion(version_2_wire_for_test, base);
    try std.testing.expect(!std.mem.eql(u8, &v1_next, &v2_next));
}

test "QUIC versioned key derivation rejects unsupported versions" {
    const unsupported_version: u32 = 0xface_b00c;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secret = [_]u8{0x5a} ** protection.secret_len;
    const keys = protection.deriveAes128Keys(secret);

    try std.testing.expectError(error.UnsupportedVersion, protection.deriveInitialSecretsForVersion(unsupported_version, &dcid));
    try std.testing.expectError(error.UnsupportedVersion, protection.deriveAes128KeysForVersion(unsupported_version, secret));
    try std.testing.expectError(error.UnsupportedVersion, protection.nextAes128TrafficSecretForVersion(unsupported_version, secret));
    try std.testing.expectError(error.UnsupportedVersion, protection.nextAes128PacketProtectionKeysForVersion(unsupported_version, keys));
}

test "QUIC key phase state advances and expires retained previous keys" {
    const keys = protection.deriveAes128Keys([_]u8{0x45} ** protection.secret_len);
    var state = protection.Aes128KeyPhaseState.init(keys, false);

    try std.testing.expect(!state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 0), state.keyUpdateCount());
    try std.testing.expect(state.retainsKeyGeneration(0));
    try std.testing.expect(state.retainsKeyGeneration(1));
    try std.testing.expect(!state.retainsKeyGeneration(2));

    state.initiateKeyUpdate();
    try std.testing.expect(state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), state.keyUpdateCount());
    try std.testing.expectEqual(@as(?u64, 0), state.previousKeyGeneration());
    try std.testing.expect(state.retainsKeyGeneration(0));
    try std.testing.expect(state.retainsKeyGeneration(1));
    try std.testing.expect(state.retainsKeyGeneration(2));
    try std.testing.expectEqual(@as(?bool, false), state.keyUpdateKeys().previous_key_phase);

    state.schedulePreviousDiscard(100);
    try std.testing.expectEqual(@as(?i64, 100), state.previousDiscardDeadline());
    try std.testing.expect(!state.discardExpiredPrevious(99));
    try std.testing.expect(state.discardExpiredPrevious(100));
    try std.testing.expectEqual(@as(?u64, null), state.previousKeyGeneration());
    try std.testing.expect(!state.retainsKeyGeneration(0));
}

test "QUIC packet number length follows RFC 9000 adaptive encoding" {
    try std.testing.expectEqual(@as(u8, 1), protection.packetNumberLen(0, null));
    try std.testing.expectEqual(@as(u8, 1), protection.packetNumberLen(0xabe8b3 + 1, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 2), protection.packetNumberLen(0xac5c02, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 3), protection.packetNumberLen(0xace8fe, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 4), protection.packetNumberLen(protection.max_packet_number, 0));
}

test "QUIC packet number length grows for tiny unpadded payloads" {
    try std.testing.expectEqual(@as(u8, 4), protection.minimumPacketNumberLenForHeaderProtection(0));
    try std.testing.expectEqual(@as(u8, 3), protection.packetNumberLenForPayload(1, 0, 1));
    try std.testing.expectEqual(@as(u8, 2), protection.packetNumberLenForPayload(1, 0, 2));
    try std.testing.expectEqual(@as(u8, 1), protection.packetNumberLenForPayload(1, 0, 3));
}

test "QUIC packet number reconstruction validates bounds" {
    try std.testing.expectEqual(
        @as(u64, 0xa82f9b32),
        try protection.reconstructPacketNumber(0xa82f30ea + 1, &[_]u8{ 0x9b, 0x32 }),
    );
    try std.testing.expectEqual(@as(u64, 0xff), try protection.reconstructPacketNumber(0x100, &[_]u8{0xff}));
    try std.testing.expectEqual(@as(u64, 0x200), try protection.reconstructPacketNumber(0x180, &[_]u8{0x00}));
    try std.testing.expectEqual(@as(u64, 0x1f0), try protection.reconstructPacketNumber(0x250, &[_]u8{0xf0}));
    try std.testing.expectEqual(
        protection.max_packet_number,
        try protection.reconstructPacketNumber(protection.max_packet_number + 1, &[_]u8{ 0xff, 0xff, 0xff, 0xff }),
    );

    try std.testing.expectError(error.InvalidPacketNumberLength, protection.reconstructPacketNumber(0, &[_]u8{}));
    try std.testing.expectError(error.InvalidPacketNumberLength, protection.reconstructPacketNumber(0, &[_]u8{ 0, 0, 0, 0, 0 }));
    try std.testing.expectError(error.InvalidPacketNumber, protection.reconstructPacketNumber(protection.max_packet_number + 2, &[_]u8{0}));
    try std.testing.expectError(error.InvalidPacketNumber, protection.reconstructPacketNumber(protection.max_packet_number, &[_]u8{0}));
}

test "QUIC Initial packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const keys = protection.deriveInitialSecrets(&dcid).client;
    const payload = "initial crypto payload";

    const sealed = try protection.sealInitialPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 2,
        .packet_number_len = 4,
        .payload = payload,
    });
    defer allocator.free(sealed);
    try std.testing.expect(sealed.len > payload.len + dcid.len + scid.len);
    try std.testing.expect(sealed[0] != 0xc3); // Header protection changed the first byte for this vector.

    var opened = try protection.openInitialPacket(allocator, keys, sealed, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), opened.version);
    try std.testing.expectEqual(@as(u64, 2), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);

    var tampered = try allocator.dupe(u8, sealed);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, protection.openInitialPacket(allocator, keys, tampered, 0));
}

test "QUIC v2 Initial and Handshake packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const version = version_2_wire_for_test;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const initial_keys = (try protection.deriveInitialSecretsForVersion(version, &dcid)).client;
    const initial = try protection.sealInitialPacket(allocator, initial_keys, .{
        .version = version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .packet_number_len = 2,
        .payload = "v2 initial",
    });
    defer allocator.free(initial);
    const initial_info = try protection.peekProtectedLongPacketInfo(initial);
    try std.testing.expectEqual(version, initial_info.version);
    try std.testing.expectEqual(protection.ProtectedLongPacketType.initial, initial_info.packet_type);

    var opened_initial = try protection.openInitialPacket(allocator, initial_keys, initial, 0);
    defer opened_initial.deinit(allocator);
    try std.testing.expectEqual(version, opened_initial.version);
    try std.testing.expectEqual(@as(u64, 1), opened_initial.packet_number);
    try std.testing.expectEqualStrings("v2 initial", opened_initial.payload);

    const handshake_keys = try protection.deriveAes128KeysForVersion(version, [_]u8{0x57} ** protection.secret_len);
    const handshake = try protection.sealHandshakePacket(allocator, handshake_keys, .{
        .version = version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 2,
        .packet_number_len = 2,
        .payload = "v2 handshake",
    });
    defer allocator.free(handshake);
    const handshake_info = try protection.peekProtectedLongPacketInfo(handshake);
    try std.testing.expectEqual(version, handshake_info.version);
    try std.testing.expectEqual(protection.ProtectedLongPacketType.handshake, handshake_info.packet_type);

    var opened_handshake = try protection.openHandshakePacket(allocator, handshake_keys, handshake, 0);
    defer opened_handshake.deinit(allocator);
    try std.testing.expectEqual(version, opened_handshake.version);
    try std.testing.expectEqual(@as(u64, 2), opened_handshake.packet_number);
    try std.testing.expectEqualStrings("v2 handshake", opened_handshake.payload);
}

test "QUIC 0-RTT long packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x68} ** protection.secret_len);
    const dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const scid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const zero_rtt = try protection.sealZeroRttPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 3,
        .packet_number_len = 2,
        .payload = "early stream frames",
    });
    defer allocator.free(zero_rtt);

    const info = try protection.peekProtectedLongPacketInfo(zero_rtt);
    try std.testing.expectEqual(@as(u32, 1), info.version);
    try std.testing.expectEqual(protection.ProtectedLongPacketType.zero_rtt, info.packet_type);
    try std.testing.expectEqualSlices(u8, &dcid, info.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, info.source_connection_id);

    var opened = try protection.openZeroRttPacket(allocator, keys, zero_rtt, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings("early stream frames", opened.payload);
}

test "QUIC Handshake packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x42} ** protection.secret_len);
    const dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const payload = "encrypted extensions and finished";

    const sealed = try protection.sealHandshakePacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 3,
        .packet_number_len = 2,
        .payload = payload,
    });
    defer allocator.free(sealed);

    var opened = try protection.openHandshakePacket(allocator, keys, sealed, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);
}

test "QUIC protected long packet peek splits coalesced Initial and Handshake" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const initial_keys = protection.deriveInitialSecrets(&dcid).client;
    const handshake_keys = protection.deriveAes128Keys([_]u8{0x43} ** protection.secret_len);

    const initial = try protection.sealInitialPacket(allocator, initial_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = "initial payload",
    });
    defer allocator.free(initial);
    const handshake = try protection.sealHandshakePacket(allocator, handshake_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = "handshake payload",
    });
    defer allocator.free(handshake);

    var coalesced: std.ArrayList(u8) = .empty;
    defer coalesced.deinit(allocator);
    try coalesced.appendSlice(allocator, initial);
    try coalesced.appendSlice(allocator, handshake);

    const first = try protection.peekProtectedLongPacketInfo(coalesced.items);
    try std.testing.expectEqual(@as(u32, 1), first.version);
    try std.testing.expectEqual(protection.ProtectedLongPacketType.initial, first.packet_type);
    try std.testing.expectEqualSlices(u8, &dcid, first.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, first.source_connection_id);
    try std.testing.expectEqual(initial.len, first.len);

    const second = try protection.peekProtectedLongPacketInfo(coalesced.items[first.len..]);
    try std.testing.expectEqual(@as(u32, 1), second.version);
    try std.testing.expectEqual(protection.ProtectedLongPacketType.handshake, second.packet_type);
    try std.testing.expectEqualSlices(u8, &dcid, second.destination_connection_id);
    try std.testing.expectEqual(handshake.len, second.len);
}

test "QUIC 1-RTT short packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x99} ** protection.secret_len);
    const dcid = [_]u8{ 1, 3, 3, 7 };
    const payload = "stream frame payload";
    const sealed = try protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .packet_number = 9,
        .packet_number_len = 2,
        .key_phase = false,
        .payload = payload,
    });
    defer allocator.free(sealed);

    var opened = try protection.openShortPacket(allocator, keys, sealed, dcid.len, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 9), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);
}

test "QUIC short packet in-place sealing matches allocating wrapper" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x9b} ** protection.secret_len);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = "\x01\x02\x03\x04\x05\x06\x07\x08",
        .packet_number = 0x12_3456,
        .packet_number_len = 3,
        .spin_bit = true,
        .key_phase = true,
        .payload = "allocation-free packet protection",
    };

    const allocated = try protection.sealShortPacket(allocator, keys, options);
    defer allocator.free(allocated);

    var storage: [128]u8 = undefined;
    const in_place = try protection.sealShortPacketInto(&storage, keys, options);
    try std.testing.expectEqual(try protection.shortPacketLen(options), in_place.len);
    try std.testing.expectEqualSlices(u8, allocated, in_place);
    try std.testing.expectError(error.BufferTooShort, protection.sealShortPacketInto(storage[0 .. in_place.len - 1], keys, options));
}

test "QUIC short packet in-place open matches owning open" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x9d} ** protection.secret_len);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = "in-place",
        .packet_number = 0x12_3456,
        .packet_number_len = 3,
        .spin_bit = true,
        .key_phase = false,
        .payload = "authenticated payload decrypted in caller storage",
    };
    const sealed = try protection.sealShortPacket(allocator, keys, options);
    defer allocator.free(sealed);

    var owning = try protection.openShortPacket(
        allocator,
        keys,
        sealed,
        options.destination_connection_id.len,
        options.packet_number,
    );
    defer owning.deinit(allocator);

    const in_place_storage = try allocator.dupe(u8, sealed);
    defer allocator.free(in_place_storage);
    const in_place = try protection.openShortPacketInPlace(
        keys,
        in_place_storage,
        options.destination_connection_id.len,
        options.packet_number,
    );
    try std.testing.expectEqual(owning.packet_number, in_place.packet_number);
    try std.testing.expectEqual(owning.spin_bit, in_place.spin_bit);
    try std.testing.expectEqual(owning.key_phase, in_place.key_phase);
    try std.testing.expectEqualSlices(u8, owning.destination_connection_id, in_place.destination_connection_id);
    try std.testing.expectEqualSlices(u8, owning.payload, in_place.payload);
    try std.testing.expect(
        @intFromPtr(in_place.payload.ptr) >= @intFromPtr(in_place_storage.ptr) and
            @intFromPtr(in_place.payload.ptr) < @intFromPtr(in_place_storage.ptr) + in_place_storage.len,
    );
}

test "QUIC short packet key phase peek does not mutate ciphertext" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x9e} ** protection.secret_len);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = "peek",
        .packet_number = 17,
        .packet_number_len = 2,
        .key_phase = true,
        .payload = "phase",
    };
    const sealed = try protection.sealShortPacket(allocator, keys, options);
    defer allocator.free(sealed);
    const before = try allocator.dupe(u8, sealed);
    defer allocator.free(before);

    try std.testing.expect(try protection.peekShortPacketKeyPhase(
        keys.hp,
        sealed,
        options.destination_connection_id.len,
    ));
    try std.testing.expectEqualSlices(u8, before, sealed);
}

test "QUIC short packet in-place sealing reuses caller storage" {
    const keys = protection.deriveAes128Keys([_]u8{0x9c} ** protection.secret_len);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = "destination",
        .packet_number = 77,
        .packet_number_len = 2,
        .payload = "steady-state",
    };
    var storage: [128]u8 = undefined;

    // The API has no allocator and both calls return slices into the same
    // caller-owned array, making reuse explicit rather than timing-dependent.
    const first = try protection.sealShortPacketInto(&storage, keys, options);
    const first_ptr = first.ptr;
    const second = try protection.sealShortPacketInto(&storage, keys, options);
    try std.testing.expectEqualSlices(u8, first, second);
    try std.testing.expectEqual(first_ptr, second.ptr);
}

test "QUIC allocating short packet wrapper performs one allocation" {
    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = counting.allocator();
    const keys = protection.deriveAes128Keys([_]u8{0x9d} ** protection.secret_len);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = "destination",
        .packet_number = 78,
        .packet_number_len = 2,
        .payload = "single exact allocation",
    };

    const packet = try protection.sealShortPacket(allocator, keys, options);
    defer allocator.free(packet);
    try std.testing.expectEqual(try protection.shortPacketLen(options), packet.len);
    try std.testing.expectEqual(@as(usize, 1), counting.allocations);
}

test "QUIC short packet preserves spin bit" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0x9a} ** protection.secret_len);
    const dcid = [_]u8{ 0x01, 0x23, 0x45, 0x67 };
    const packet = try protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .packet_number = 4,
        .packet_number_len = 2,
        .spin_bit = true,
        .key_phase = false,
        .payload = "spin",
    });
    defer allocator.free(packet);
    // Header protection does not mask the spin bit, so passive observers and
    // endpoint routing can read it directly from the protected datagram.
    try std.testing.expect((packet[0] & 0x20) != 0);

    var opened = try protection.openShortPacket(allocator, keys, packet, dcid.len, 0);
    defer opened.deinit(allocator);
    try std.testing.expect(opened.spin_bit);
    try std.testing.expectEqualStrings("spin", opened.payload);
}

test "QUIC packet protection rejects reserved header bits after unprotect" {
    const allocator = std.testing.allocator;

    {
        const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
        const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
        const keys = protection.deriveInitialSecrets(&dcid).client;
        const payload = "initial reserved bits";
        const packet_number: u64 = 4;
        const packet_number_len: u8 = 4;

        var packet: std.ArrayList(u8) = .empty;
        errdefer packet.deinit(allocator);
        try packet.append(allocator, longHeaderFirstByteForTest(version_1_wire_for_test, .initial, packet_number_len) | 0x04);
        try wire.appendInt(&packet, allocator, u32, version_1_wire_for_test, .big);
        try packet.append(allocator, @intCast(dcid.len));
        try packet.appendSlice(allocator, &dcid);
        try packet.append(allocator, @intCast(scid.len));
        try packet.appendSlice(allocator, &scid);
        try varint.encode(&packet, allocator, 0);
        try varint.encode(&packet, allocator, packet_number_len + payload.len + protection.aead_tag_len);
        const pn_offset = packet.items.len;
        try appendTruncatedPacketNumberForTest(&packet, allocator, packet_number, packet_number_len);
        const payload_offset = packet.items.len;
        try packet.resize(allocator, payload_offset + payload.len + protection.aead_tag_len);
        const ciphertext = packet.items[payload_offset .. payload_offset + payload.len];
        const tag = packet.items[payload_offset + payload.len ..][0..protection.aead_tag_len];
        try protection.protectPayload(keys, packet_number, packet.items[0..payload_offset], payload, ciphertext, tag);
        try protection.applyHeaderProtectionForKeys(
            keys,
            .long,
            packet.items,
            pn_offset,
        );

        const malformed = try packet.toOwnedSlice(allocator);
        defer allocator.free(malformed);
        try std.testing.expectError(error.InvalidInitialPacket, protection.openInitialPacket(allocator, keys, malformed, 0));
    }

    {
        const keys = protection.deriveAes128Keys([_]u8{0x9b} ** protection.secret_len);
        const dcid = [_]u8{ 0x01, 0x23, 0x45, 0x67 };
        const payload = "short reserved bits";
        const packet_number: u64 = 5;
        const packet_number_len: u8 = 4;

        var packet: std.ArrayList(u8) = .empty;
        errdefer packet.deinit(allocator);
        try packet.append(allocator, 0x40 | 0x08 | @as(u8, packet_number_len - 1));
        try packet.appendSlice(allocator, &dcid);
        const pn_offset = packet.items.len;
        try appendTruncatedPacketNumberForTest(&packet, allocator, packet_number, packet_number_len);
        const payload_offset = packet.items.len;
        try packet.resize(allocator, payload_offset + payload.len + protection.aead_tag_len);
        const ciphertext = packet.items[payload_offset .. payload_offset + payload.len];
        const tag = packet.items[payload_offset + payload.len ..][0..protection.aead_tag_len];
        try protection.protectPayload(keys, packet_number, packet.items[0..payload_offset], payload, ciphertext, tag);
        try protection.applyHeaderProtectionForKeys(
            keys,
            .short,
            packet.items,
            pn_offset,
        );

        const malformed = try packet.toOwnedSlice(allocator);
        defer allocator.free(malformed);
        try std.testing.expectError(error.InvalidInitialPacket, protection.openShortPacket(allocator, keys, malformed, dcid.len, 0));
    }
}

test "QUIC protected long packets reject a missing fixed bit before AEAD" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const scid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };

    const initial_keys = protection.deriveInitialSecrets(&dcid).client;
    const initial = try protection.sealInitialPacket(allocator, initial_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .packet_number_len = 4,
        .payload = "initial fixed bit",
    });
    defer allocator.free(initial);

    var malformed_initial = try allocator.dupe(u8, initial);
    defer allocator.free(malformed_initial);
    malformed_initial[0] &= ~@as(u8, 0x40);
    try std.testing.expectError(error.InvalidInitialPacket, protection.openInitialPacket(allocator, initial_keys, malformed_initial, 0));

    const handshake_keys = protection.deriveAes128Keys([_]u8{0xce} ** protection.secret_len);
    const handshake = try protection.sealHandshakePacket(allocator, handshake_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 2,
        .packet_number_len = 4,
        .payload = "handshake fixed bit",
    });
    defer allocator.free(handshake);

    var malformed_handshake = try allocator.dupe(u8, handshake);
    defer allocator.free(malformed_handshake);
    malformed_handshake[0] &= ~@as(u8, 0x40);
    try std.testing.expectError(error.InvalidInitialPacket, protection.openHandshakePacket(allocator, handshake_keys, malformed_handshake, 0));

    const zero_rtt_keys = protection.deriveAes128Keys([_]u8{0xcf} ** protection.secret_len);
    const zero_rtt = try protection.sealZeroRttPacket(allocator, zero_rtt_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 3,
        .packet_number_len = 4,
        .payload = "zero rtt fixed bit",
    });
    defer allocator.free(zero_rtt);

    var malformed_zero_rtt = try allocator.dupe(u8, zero_rtt);
    defer allocator.free(malformed_zero_rtt);
    malformed_zero_rtt[0] &= ~@as(u8, 0x40);
    try std.testing.expectError(error.InvalidInitialPacket, protection.openZeroRttPacket(allocator, zero_rtt_keys, malformed_zero_rtt, 0));
}

test "QUIC protected long packets reject oversized connection IDs before AEAD" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const keys = protection.deriveInitialSecrets(&dcid).client;

    const initial_first = longHeaderFirstByteForTest(version_1_wire_for_test, .initial, 1);
    const handshake_first = longHeaderFirstByteForTest(version_1_wire_for_test, .handshake, 1);
    const zero_rtt_first = longHeaderFirstByteForTest(version_1_wire_for_test, .zero_rtt, 1);
    const oversized_dcid_initial = [_]u8{ initial_first, 0, 0, 0, 1, 21 };
    const oversized_dcid_handshake = [_]u8{ handshake_first, 0, 0, 0, 1, 21 };
    const oversized_dcid_zero_rtt = [_]u8{ zero_rtt_first, 0, 0, 0, 1, 21 };

    try std.testing.expectError(error.InvalidInitialPacket, protection.openInitialPacket(allocator, keys, &oversized_dcid_initial, 0));
    try std.testing.expectError(error.InvalidInitialPacket, protection.openHandshakePacket(allocator, keys, &oversized_dcid_handshake, 0));
    try std.testing.expectError(error.InvalidInitialPacket, protection.openZeroRttPacket(allocator, keys, &oversized_dcid_zero_rtt, 0));

    const oversized_scid_initial = [_]u8{ initial_first, 0, 0, 0, 1, 4, 1, 2, 3, 4, 21 };
    const oversized_scid_handshake = [_]u8{ handshake_first, 0, 0, 0, 1, 4, 1, 2, 3, 4, 21 };
    const oversized_scid_zero_rtt = [_]u8{ zero_rtt_first, 0, 0, 0, 1, 4, 1, 2, 3, 4, 21 };

    try std.testing.expectError(error.InvalidInitialPacket, protection.openInitialPacket(allocator, keys, &oversized_scid_initial, 0));
    try std.testing.expectError(error.InvalidInitialPacket, protection.openHandshakePacket(allocator, keys, &oversized_scid_handshake, 0));
    try std.testing.expectError(error.InvalidInitialPacket, protection.openZeroRttPacket(allocator, keys, &oversized_scid_zero_rtt, 0));
}

test "QUIC protected long packets reject unsupported versions" {
    const allocator = std.testing.allocator;
    const unsupported_version: u32 = 0xface_b00c;
    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const scid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const keys = protection.deriveInitialSecrets(&dcid).client;

    try std.testing.expectError(error.UnsupportedVersion, protection.sealInitialPacket(allocator, keys, .{
        .version = unsupported_version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .payload = "unsupported initial",
    }));
    try std.testing.expectError(error.UnsupportedVersion, protection.sealHandshakePacket(allocator, keys, .{
        .version = unsupported_version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .payload = "unsupported handshake",
    }));
    try std.testing.expectError(error.UnsupportedVersion, protection.sealZeroRttPacket(allocator, keys, .{
        .version = unsupported_version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .payload = "unsupported zero rtt",
    }));

    const initial_first = longHeaderFirstByteForTest(version_1_wire_for_test, .initial, 1);
    const handshake_first = longHeaderFirstByteForTest(version_1_wire_for_test, .handshake, 1);
    const zero_rtt_first = longHeaderFirstByteForTest(version_1_wire_for_test, .zero_rtt, 1);
    const unsupported_initial = [_]u8{ initial_first, 0xfa, 0xce, 0xb0, 0x0c, 0, 0 };
    const unsupported_handshake = [_]u8{ handshake_first, 0xfa, 0xce, 0xb0, 0x0c, 0, 0 };
    const unsupported_zero_rtt = [_]u8{ zero_rtt_first, 0xfa, 0xce, 0xb0, 0x0c, 0, 0 };

    try std.testing.expectError(error.UnsupportedVersion, protection.openInitialPacket(allocator, keys, &unsupported_initial, 0));
    try std.testing.expectError(error.UnsupportedVersion, protection.openHandshakePacket(allocator, keys, &unsupported_handshake, 0));
    try std.testing.expectError(error.UnsupportedVersion, protection.openZeroRttPacket(allocator, keys, &unsupported_zero_rtt, 0));
    try std.testing.expectError(error.UnsupportedVersion, protection.peekProtectedLongPacketInfo(&unsupported_initial));
}

test "QUIC protected long packet samples stay inside packet length" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const keys = protection.deriveInitialSecrets(&dcid).client;

    var initial: std.ArrayList(u8) = .empty;
    defer initial.deinit(allocator);
    try initial.append(allocator, longHeaderFirstByteForTest(version_1_wire_for_test, .initial, 1));
    try wire.appendInt(&initial, allocator, u32, version_1_wire_for_test, .big);
    try initial.append(allocator, @intCast(dcid.len));
    try initial.appendSlice(allocator, &dcid);
    try initial.append(allocator, @intCast(scid.len));
    try initial.appendSlice(allocator, &scid);
    try varint.encode(&initial, allocator, 0);
    try varint.encode(&initial, allocator, 17);
    try initial.appendNTimes(allocator, 0, 17);
    try initial.appendNTimes(allocator, 0xaa, 32);
    try std.testing.expectError(error.InvalidHeaderProtectionSample, protection.openInitialPacket(allocator, keys, initial.items, 0));

    var handshake: std.ArrayList(u8) = .empty;
    defer handshake.deinit(allocator);
    try handshake.append(allocator, longHeaderFirstByteForTest(version_1_wire_for_test, .handshake, 1));
    try wire.appendInt(&handshake, allocator, u32, version_1_wire_for_test, .big);
    try handshake.append(allocator, @intCast(dcid.len));
    try handshake.appendSlice(allocator, &dcid);
    try handshake.append(allocator, @intCast(scid.len));
    try handshake.appendSlice(allocator, &scid);
    try varint.encode(&handshake, allocator, 17);
    try handshake.appendNTimes(allocator, 0, 17);
    try handshake.appendNTimes(allocator, 0xaa, 32);
    try std.testing.expectError(error.InvalidHeaderProtectionSample, protection.openHandshakePacket(allocator, keys, handshake.items, 0));

    var zero_rtt: std.ArrayList(u8) = .empty;
    defer zero_rtt.deinit(allocator);
    try zero_rtt.append(allocator, longHeaderFirstByteForTest(version_1_wire_for_test, .zero_rtt, 1));
    try wire.appendInt(&zero_rtt, allocator, u32, version_1_wire_for_test, .big);
    try zero_rtt.append(allocator, @intCast(dcid.len));
    try zero_rtt.appendSlice(allocator, &dcid);
    try zero_rtt.append(allocator, @intCast(scid.len));
    try zero_rtt.appendSlice(allocator, &scid);
    try varint.encode(&zero_rtt, allocator, 17);
    try zero_rtt.appendNTimes(allocator, 0, 17);
    try zero_rtt.appendNTimes(allocator, 0xaa, 32);
    try std.testing.expectError(error.InvalidHeaderProtectionSample, protection.openZeroRttPacket(allocator, keys, zero_rtt.items, 0));
}

test "QUIC short packet key update opens next and retained previous generations" {
    const allocator = std.testing.allocator;
    const keys = protection.deriveAes128Keys([_]u8{0xa7} ** protection.secret_len);
    const next = protection.nextAes128PacketProtectionKeys(keys);
    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };

    const old_packet = try protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .packet_number = 7,
        .packet_number_len = 4,
        .key_phase = false,
        .payload = "old-generation",
    });
    defer allocator.free(old_packet);

    const updated_packet = try protection.sealShortPacket(allocator, next, .{
        .destination_connection_id = &dcid,
        .packet_number = 8,
        .packet_number_len = 4,
        .key_phase = true,
        .payload = "next-generation",
    });
    defer allocator.free(updated_packet);

    var receiver = protection.Aes128KeyPhaseState.init(keys, false);
    var opened_next = try protection.openShortPacketWithKeyUpdate(allocator, receiver.keyUpdateKeys(), updated_packet, dcid.len, 0);
    defer opened_next.deinit(allocator);
    try std.testing.expect(opened_next.peer_initiated_key_update);
    try std.testing.expect(opened_next.packet.key_phase);
    try std.testing.expectEqualStrings("next-generation", opened_next.packet.payload);
    try std.testing.expect(receiver.updateAfterReceiving(opened_next.packet.key_phase));

    var delayed_old = try protection.openShortPacketWithKeyUpdate(allocator, receiver.keyUpdateKeys(), old_packet, dcid.len, 0);
    defer delayed_old.deinit(allocator);
    try std.testing.expect(!delayed_old.peer_initiated_key_update);
    try std.testing.expect(!delayed_old.packet.key_phase);
    try std.testing.expectEqualStrings("old-generation", delayed_old.packet.payload);

    receiver.schedulePreviousDiscard(1_000);
    try std.testing.expect(receiver.discardExpiredPrevious(1_000));
    try std.testing.expectError(
        error.KeyUpdateError,
        protection.openShortPacketWithKeyUpdate(allocator, receiver.keyUpdateKeys(), old_packet, dcid.len, 0),
    );
}

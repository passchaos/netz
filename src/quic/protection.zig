const std = @import("std");
const varint = @import("varint.zig");
const wire = @import("../internal/wire.zig");

pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const initial_salt_v2 = [_]u8{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const version_1_wire: u32 = 0x00000001;
const version_2_wire: u32 = 0x6b3343cf;

pub const secret_len = HkdfSha256.prk_length;
pub const aes_128_key_len = Aes128Gcm.key_length;
pub const iv_len = Aes128Gcm.nonce_length;
pub const hp_key_len = aes_128_key_len;
pub const aead_tag_len = Aes128Gcm.tag_length;
pub const header_protection_sample_len = 16;
pub const header_protection_mask_len = 5;
pub const max_packet_number: u64 = varint.max_value;

pub const Error = varint.Error || error{
    InvalidInitialPacket,
    InvalidHeaderProtectionSample,
    InvalidPacketNumber,
    InvalidPacketNumberLength,
    InvalidPayloadLength,
    KeyUpdateError,
} || std.crypto.errors.AuthenticationError || std.mem.Allocator.Error;

pub const HeaderForm = enum {
    long,
    short,
};

pub const PacketProtectionKeys = struct {
    secret: [secret_len]u8,
    key: [aes_128_key_len]u8,
    iv: [iv_len]u8,
    hp: [hp_key_len]u8,
};

pub const InitialSecrets = struct {
    initial_secret: [secret_len]u8,
    client: PacketProtectionKeys,
    server: PacketProtectionKeys,
};

const HkdfLabels = struct {
    key: []const u8,
    iv: []const u8,
    hp: []const u8,
    ku: []const u8,
};

const hkdf_labels_v1 = HkdfLabels{
    .key = "quic key",
    .iv = "quic iv",
    .hp = "quic hp",
    .ku = "quic ku",
};

const hkdf_labels_v2 = HkdfLabels{
    .key = "quicv2 key",
    .iv = "quicv2 iv",
    .hp = "quicv2 hp",
    .ku = "quicv2 ku",
};

const ProtectionProfile = struct {
    salt: *const [initial_salt_v1.len]u8,
    labels: HkdfLabels,
};

pub const InitialPacketOptions = struct {
    version: u32 = 0x00000001,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{},
    packet_number: u64,
    packet_number_len: u8 = 4,
    payload: []const u8,
};

pub const OpenedInitialPacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    token: []u8,
    packet_number: u64,
    payload: []u8,

    pub fn deinit(self: *OpenedInitialPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.source_connection_id);
        allocator.free(self.token);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const HandshakePacketOptions = struct {
    version: u32 = 0x00000001,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    payload: []const u8,
};

pub const OpenedHandshakePacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    packet_number: u64,
    payload: []u8,

    pub fn deinit(self: *OpenedHandshakePacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.source_connection_id);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const ZeroRttPacketOptions = struct {
    version: u32 = 0x00000001,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    payload: []const u8,
};

pub const OpenedZeroRttPacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    packet_number: u64,
    payload: []u8,

    pub fn deinit(self: *OpenedZeroRttPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.source_connection_id);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const ProtectedLongPacketType = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
};

pub const ProtectedLongPacketInfo = struct {
    version: u32,
    packet_type: ProtectedLongPacketType,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    /// Number of datagram bytes occupied by the first protected long-header
    /// packet, excluding any following coalesced packet.
    len: usize,
};

pub const ShortPacketOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    spin_bit: bool = false,
    key_phase: bool = false,
    payload: []const u8,
};

pub const OpenedShortPacket = struct {
    destination_connection_id: []u8,
    packet_number: u64,
    spin_bit: bool,
    key_phase: bool,
    payload: []u8,

    pub fn deinit(self: *OpenedShortPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.destination_connection_id);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const OpenedShortPacketWithKeyUpdate = struct {
    packet: OpenedShortPacket,
    /// True only when the packet authenticated with the pre-derived next key
    /// generation. Delayed packets opened with a retained previous generation
    /// keep this false so connection state does not advance twice.
    peer_initiated_key_update: bool = false,

    pub fn deinit(self: *OpenedShortPacketWithKeyUpdate, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const ShortPacketKeyUpdateKeys = struct {
    current: PacketProtectionKeys,
    next: PacketProtectionKeys,
    current_key_phase: bool,
    previous: ?PacketProtectionKeys = null,
    previous_key_phase: ?bool = null,
    discarded_previous_key_phase: ?bool = null,
};

/// Directional 1-RTT key-phase state.
///
/// Mature QUIC stacks keep packet-protection key update state next to the
/// connection, not in a raw packet codec.  This type captures the reusable
/// crypto portion: current/next key generations, a retained previous
/// generation for reordered packets, and the key phase bit that is visible in
/// short headers after header protection is removed.
pub const Aes128KeyPhaseState = struct {
    current: PacketProtectionKeys,
    next: PacketProtectionKeys,
    current_key_phase: bool,
    key_update_count: u64 = 0,
    previous: ?PacketProtectionKeys = null,
    previous_key_phase: ?bool = null,
    previous_discard_deadline_nanos: ?i64 = null,
    discarded_previous_key_phase: ?bool = null,

    pub fn init(current: PacketProtectionKeys, current_key_phase: bool) Aes128KeyPhaseState {
        return .{
            .current = current,
            .next = nextAes128PacketProtectionKeys(current),
            .current_key_phase = current_key_phase,
        };
    }

    pub fn currentKeys(self: Aes128KeyPhaseState) PacketProtectionKeys {
        return self.current;
    }

    pub fn currentKeyPhase(self: Aes128KeyPhaseState) bool {
        return self.current_key_phase;
    }

    pub fn keyUpdateCount(self: Aes128KeyPhaseState) u64 {
        return self.key_update_count;
    }

    pub fn previousKeyGeneration(self: Aes128KeyPhaseState) ?u64 {
        if (self.previous == null) return null;
        return self.key_update_count -% 1;
    }

    pub fn retainsKeyGeneration(self: Aes128KeyPhaseState, generation: u64) bool {
        if (generation == self.key_update_count) return true;
        if (generation == self.key_update_count +| 1) return true;
        if (self.previousKeyGeneration()) |previous_generation| {
            return generation == previous_generation;
        }
        return false;
    }

    pub fn keyUpdateKeys(self: Aes128KeyPhaseState) ShortPacketKeyUpdateKeys {
        return .{
            .current = self.current,
            .next = self.next,
            .current_key_phase = self.current_key_phase,
            .previous = self.previous,
            .previous_key_phase = self.previous_key_phase,
            .discarded_previous_key_phase = self.discarded_previous_key_phase,
        };
    }

    pub fn initiateKeyUpdate(self: *Aes128KeyPhaseState) void {
        self.advance();
    }

    pub fn updateAfterReceiving(self: *Aes128KeyPhaseState, peer_key_phase: bool) bool {
        if (peer_key_phase == self.current_key_phase) return false;
        self.advance();
        return true;
    }

    pub fn schedulePreviousDiscard(self: *Aes128KeyPhaseState, deadline_nanos: i64) void {
        if (self.previous == null) return;
        self.previous_discard_deadline_nanos = deadline_nanos;
    }

    pub fn previousDiscardDeadline(self: Aes128KeyPhaseState) ?i64 {
        return self.previous_discard_deadline_nanos;
    }

    pub fn discardExpiredPrevious(self: *Aes128KeyPhaseState, now_nanos: i64) bool {
        const deadline = self.previous_discard_deadline_nanos orelse return false;
        if (now_nanos < deadline) return false;
        self.discarded_previous_key_phase = self.previous_key_phase;
        self.previous = null;
        self.previous_key_phase = null;
        self.previous_discard_deadline_nanos = null;
        return true;
    }

    fn advance(self: *Aes128KeyPhaseState) void {
        self.previous = self.current;
        self.previous_key_phase = self.current_key_phase;
        self.previous_discard_deadline_nanos = null;
        self.current = self.next;
        self.next = nextAes128PacketProtectionKeys(self.current);
        self.current_key_phase = !self.current_key_phase;
        self.key_update_count +|= 1;
    }
};

pub fn deriveInitialSecrets(client_initial_dcid: []const u8) InitialSecrets {
    return deriveInitialSecretsForVersion(version_1_wire, client_initial_dcid);
}

pub fn deriveInitialSecretsForVersion(version: u32, client_initial_dcid: []const u8) InitialSecrets {
    const profile = protectionProfile(version);
    const initial_secret = HkdfSha256.extract(profile.salt, client_initial_dcid);
    const client_secret = hkdfExpandLabel(initial_secret, "client in", secret_len);
    const server_secret = hkdfExpandLabel(initial_secret, "server in", secret_len);
    return .{
        .initial_secret = initial_secret,
        .client = deriveAes128KeysWithLabels(client_secret, profile.labels),
        .server = deriveAes128KeysWithLabels(server_secret, profile.labels),
    };
}

pub fn deriveAes128Keys(secret: [secret_len]u8) PacketProtectionKeys {
    return deriveAes128KeysWithLabels(secret, hkdf_labels_v1);
}

pub fn deriveAes128KeysForVersion(version: u32, secret: [secret_len]u8) PacketProtectionKeys {
    return deriveAes128KeysWithLabels(secret, protectionProfile(version).labels);
}

fn deriveAes128KeysWithLabels(secret: [secret_len]u8, labels: HkdfLabels) PacketProtectionKeys {
    return .{
        .secret = secret,
        .key = hkdfExpandLabel(secret, labels.key, aes_128_key_len),
        .iv = hkdfExpandLabel(secret, labels.iv, iv_len),
        .hp = hkdfExpandLabel(secret, labels.hp, hp_key_len),
    };
}

pub fn nextAes128TrafficSecret(secret: [secret_len]u8) [secret_len]u8 {
    return nextAes128TrafficSecretForVersion(version_1_wire, secret);
}

pub fn nextAes128TrafficSecretForVersion(version: u32, secret: [secret_len]u8) [secret_len]u8 {
    return hkdfExpandLabel(secret, protectionProfile(version).labels.ku, secret_len);
}

/// Derive the next QUIC 1-RTT packet-protection generation.
///
/// RFC 9001 key updates derive a new traffic secret with the `quic ku` label.
/// The packet protection key and IV change, while the header-protection key is
/// retained for the life of the connection so the key phase bit itself remains
/// protected consistently across generations.
pub fn nextAes128PacketProtectionKeys(current: PacketProtectionKeys) PacketProtectionKeys {
    return nextAes128PacketProtectionKeysForVersion(version_1_wire, current);
}

pub fn nextAes128PacketProtectionKeysForVersion(version: u32, current: PacketProtectionKeys) PacketProtectionKeys {
    const next_secret = nextAes128TrafficSecretForVersion(version, current.secret);
    var next = deriveAes128KeysForVersion(version, next_secret);
    next.hp = current.hp;
    return next;
}

pub fn hkdfExpandLabel(secret: [secret_len]u8, label: []const u8, comptime len: usize) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, "", len);
}

pub fn packetProtectionNonce(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    var nonce = iv;
    var packet_number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &packet_number_bytes, packet_number, .big);
    for (packet_number_bytes, 0..) |byte, i| {
        nonce[iv_len - packet_number_bytes.len + i] ^= byte;
    }
    return nonce;
}

pub fn aes128HeaderProtectionMask(hp_key: [hp_key_len]u8, sample: [header_protection_sample_len]u8) [header_protection_mask_len]u8 {
    const aes = std.crypto.core.aes.Aes128.initEnc(hp_key);
    var encrypted: [header_protection_sample_len]u8 = undefined;
    aes.encrypt(&encrypted, &sample);
    return encrypted[0..header_protection_mask_len].*;
}

pub fn applyHeaderProtectionMask(
    header_form: HeaderForm,
    first_byte: *u8,
    packet_number_bytes: []u8,
    mask: [header_protection_mask_len]u8,
) Error!void {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    const first_byte_mask: u8 = switch (header_form) {
        .long => 0x0f,
        .short => 0x1f,
    };
    first_byte.* ^= mask[0] & first_byte_mask;
    for (packet_number_bytes, 0..) |*byte, i| {
        byte.* ^= mask[i + 1];
    }
}

pub fn protectAes128Payload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
) Error!void {
    try validatePacketNumber(packet_number);
    if (ciphertext.len != plaintext.len) return error.InvalidPayloadLength;
    const nonce = packetProtectionNonce(keys.iv, packet_number);
    Aes128Gcm.encrypt(ciphertext, tag, plaintext, associated_data, nonce, keys.key);
}

pub fn openAes128Payload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [aead_tag_len]u8,
    plaintext: []u8,
) Error!void {
    try validatePacketNumber(packet_number);
    if (plaintext.len != ciphertext.len) return error.InvalidPayloadLength;
    const nonce = packetProtectionNonce(keys.iv, packet_number);
    try Aes128Gcm.decrypt(plaintext, ciphertext, tag, associated_data, nonce, keys.key);
}

pub fn packetNumberLen(packet_number: u64, largest_acknowledged: ?u64) u8 {
    // RFC 9000 Section 17.1 / Appendix A.2: the truncated packet number must
    // represent more than twice the distance from the largest acknowledged
    // packet.  Implementations such as tquic and s2n-quic compute the shortest
    // valid encoding from that distance and then freely use a longer encoding
    // when packet construction needs it.
    const outstanding = if (largest_acknowledged) |largest|
        packet_number -| largest
    else
        packet_number +| 1;
    const significant_bits: u7 = if (outstanding == 0) 0 else @intCast(@bitSizeOf(u64) - @clz(outstanding));
    const required_bits = significant_bits + 1;
    const bytes = @max(@as(u7, 1), (required_bits + 7) / 8);
    return @intCast(@min(bytes, 4));
}

pub fn packetNumberLenForPayload(packet_number: u64, largest_acknowledged: ?u64, payload_len: usize) u8 {
    const adaptive = packetNumberLen(packet_number, largest_acknowledged);
    return @max(adaptive, minimumPacketNumberLenForHeaderProtection(payload_len));
}

pub fn minimumPacketNumberLenForHeaderProtection(payload_len: usize) u8 {
    // QUIC header protection samples 16 bytes starting four bytes after the
    // packet-number offset, regardless of the actual packet-number length.
    // Because the AEAD tag already contributes 16 bytes, an unpadded packet
    // needs `packet_number_len + payload_len >= 4`.  Use a longer packet
    // number for tiny payloads instead of silently producing an unprotectable
    // packet; callers that insert PADDING can still request a shorter length
    // directly through the seal*Packet options.
    if (payload_len >= 3) return 1;
    return @intCast(4 - payload_len);
}

pub fn sealInitialPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: InitialPacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = longHeaderFirstByte(options.version, .initial, options.packet_number_len);
    try out.append(allocator, first_byte);
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_bytes, options.version, .big);
    try out.appendSlice(allocator, &version_bytes);
    try out.append(allocator, @intCast(options.destination_connection_id.len));
    try out.appendSlice(allocator, options.destination_connection_id);
    try out.append(allocator, @intCast(options.source_connection_id.len));
    try out.appendSlice(allocator, options.source_connection_id);
    try varint.encode(&out, allocator, options.token.len);
    try out.appendSlice(allocator, options.token);

    const protected_payload_len = options.payload.len + aead_tag_len;
    try varint.encode(&out, allocator, pn_len + protected_payload_len);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtection(keys.hp, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openInitialPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedInitialPacket {
    const bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    const protected_first_byte = try cursor.readByte();
    try validateLongHeaderFixedBit(protected_first_byte);
    const version = try cursor.readInt(u32, .big);
    if (protectedLongPacketType(protected_first_byte, version) != .initial) return error.InvalidInitialPacket;
    const dcid_len = try cursor.readByte();
    try validateLongHeaderConnectionIdLen(dcid_len);
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    try validateLongHeaderConnectionIdLen(scid_len);
    const scid = try cursor.readSlice(scid_len);
    const token_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const token = try cursor.readSlice(token_len);
    const protected_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const pn_offset = cursor.pos;
    if (bytes.len < pn_offset + protected_len) return error.BufferTooShort;

    try removeHeaderProtection(keys.hp, .long, bytes, pn_offset);
    if ((bytes[0] & 0x80) == 0 or protectedLongPacketType(bytes[0], version) != .initial) return error.InvalidInitialPacket;
    try validateLongHeaderFixedBit(bytes[0]);
    try validateLongHeaderReservedBits(bytes[0]);
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    if (protected_len < pn_len + aead_tag_len) return error.InvalidInitialPacket;
    const payload_offset = pn_offset + pn_len;
    const packet_number = try reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const packet_end = pn_offset + protected_len;
    const ciphertext = bytes[payload_offset .. packet_end - aead_tag_len];
    const tag = bytes[packet_end - aead_tag_len .. packet_end][0..aead_tag_len].*;

    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);
    const token_owned = try allocator.dupe(u8, token);
    errdefer allocator.free(token_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .token = token_owned,
        .packet_number = packet_number,
        .payload = payload,
    };
}

pub fn sealHandshakePacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: HandshakePacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = longHeaderFirstByte(options.version, .handshake, options.packet_number_len);
    try out.append(allocator, first_byte);
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_bytes, options.version, .big);
    try out.appendSlice(allocator, &version_bytes);
    try out.append(allocator, @intCast(options.destination_connection_id.len));
    try out.appendSlice(allocator, options.destination_connection_id);
    try out.append(allocator, @intCast(options.source_connection_id.len));
    try out.appendSlice(allocator, options.source_connection_id);

    const protected_payload_len = options.payload.len + aead_tag_len;
    try varint.encode(&out, allocator, pn_len + protected_payload_len);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtection(keys.hp, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openHandshakePacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedHandshakePacket {
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    const protected_first_byte = try cursor.readByte();
    try validateLongHeaderFixedBit(protected_first_byte);
    const version = try cursor.readInt(u32, .big);
    if (protectedLongPacketType(protected_first_byte, version) != .handshake) return error.InvalidInitialPacket;
    const dcid_len = try cursor.readByte();
    try validateLongHeaderConnectionIdLen(dcid_len);
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    try validateLongHeaderConnectionIdLen(scid_len);
    const scid = try cursor.readSlice(scid_len);
    const protected_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const pn_offset = cursor.pos;
    if (bytes.len < pn_offset + protected_len) return error.BufferTooShort;

    try removeHeaderProtection(keys.hp, .long, bytes, pn_offset);
    if ((bytes[0] & 0x80) == 0 or protectedLongPacketType(bytes[0], version) != .handshake) return error.InvalidInitialPacket;
    try validateLongHeaderFixedBit(bytes[0]);
    try validateLongHeaderReservedBits(bytes[0]);
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    if (protected_len < pn_len + aead_tag_len) return error.InvalidInitialPacket;
    const payload_offset = pn_offset + pn_len;
    const packet_number = try reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const packet_end = pn_offset + protected_len;
    const ciphertext = bytes[payload_offset .. packet_end - aead_tag_len];
    const tag = bytes[packet_end - aead_tag_len .. packet_end][0..aead_tag_len].*;

    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .packet_number = packet_number,
        .payload = payload,
    };
}

pub fn sealZeroRttPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: ZeroRttPacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = longHeaderFirstByte(options.version, .zero_rtt, options.packet_number_len);
    try out.append(allocator, first_byte);
    var version_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_bytes, options.version, .big);
    try out.appendSlice(allocator, &version_bytes);
    try out.append(allocator, @intCast(options.destination_connection_id.len));
    try out.appendSlice(allocator, options.destination_connection_id);
    try out.append(allocator, @intCast(options.source_connection_id.len));
    try out.appendSlice(allocator, options.source_connection_id);

    const protected_payload_len = options.payload.len + aead_tag_len;
    try varint.encode(&out, allocator, pn_len + protected_payload_len);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtection(keys.hp, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openZeroRttPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedZeroRttPacket {
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    const protected_first_byte = try cursor.readByte();
    try validateLongHeaderFixedBit(protected_first_byte);
    const version = try cursor.readInt(u32, .big);
    if (protectedLongPacketType(protected_first_byte, version) != .zero_rtt) return error.InvalidInitialPacket;
    const dcid_len = try cursor.readByte();
    try validateLongHeaderConnectionIdLen(dcid_len);
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    try validateLongHeaderConnectionIdLen(scid_len);
    const scid = try cursor.readSlice(scid_len);
    const protected_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
    const pn_offset = cursor.pos;
    if (bytes.len < pn_offset + protected_len) return error.BufferTooShort;

    try removeHeaderProtection(keys.hp, .long, bytes, pn_offset);
    if ((bytes[0] & 0x80) == 0 or protectedLongPacketType(bytes[0], version) != .zero_rtt) return error.InvalidInitialPacket;
    try validateLongHeaderFixedBit(bytes[0]);
    try validateLongHeaderReservedBits(bytes[0]);
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    if (protected_len < pn_len + aead_tag_len) return error.InvalidInitialPacket;
    const payload_offset = pn_offset + pn_len;
    const packet_number = try reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const packet_end = pn_offset + protected_len;
    const ciphertext = bytes[payload_offset .. packet_end - aead_tag_len];
    const tag = bytes[packet_end - aead_tag_len .. packet_end][0..aead_tag_len].*;

    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .packet_number = packet_number,
        .payload = payload,
    };
}

pub fn peekProtectedLongPacketInfo(datagram: []const u8) Error!ProtectedLongPacketInfo {
    var cursor = wire.Cursor.init(datagram);
    const first = try cursor.readByte();
    if ((first & 0x80) == 0 or (first & 0x40) == 0) return error.InvalidInitialPacket;
    const version = try cursor.readInt(u32, .big);
    if (version == 0) return error.InvalidInitialPacket;

    const dcid_len = try cursor.readByte();
    if (dcid_len > 20) return error.InvalidInitialPacket;
    const dcid = try cursor.readSlice(dcid_len);
    const scid_len = try cursor.readByte();
    if (scid_len > 20) return error.InvalidInitialPacket;
    const scid = try cursor.readSlice(scid_len);

    const packet_type = protectedLongPacketType(first, version);
    if (packet_type == .retry) return error.InvalidInitialPacket;
    if (packet_type == .initial) {
        const token_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidInitialPacket;
        try cursor.skip(token_len);
    }

    const protected_len = std.math.cast(usize, try varint.decode(&cursor)) orelse return error.InvalidPayloadLength;
    if (protected_len < 1 + aead_tag_len) return error.InvalidPayloadLength;
    const packet_end = std.math.add(usize, cursor.pos, protected_len) catch return error.InvalidPayloadLength;
    if (packet_end > datagram.len) return error.InvalidPayloadLength;
    if (cursor.pos + 4 + header_protection_sample_len > packet_end) return error.InvalidHeaderProtectionSample;

    return .{
        .version = version,
        .packet_type = packet_type,
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .len = packet_end,
    };
}

pub fn sealShortPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: ShortPacketOptions,
) Error![]u8 {
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const pn_len = @as(usize, options.packet_number_len);
    const first_byte: u8 = 0x40 |
        (if (options.spin_bit) @as(u8, 0x20) else 0) |
        (if (options.key_phase) @as(u8, 0x04) else 0) |
        @as(u8, @intCast(pn_len - 1));
    try out.append(allocator, first_byte);
    try out.appendSlice(allocator, options.destination_connection_id);
    const pn_offset = out.items.len;
    try appendTruncatedPacketNumber(&out, allocator, options.packet_number, options.packet_number_len);
    const payload_offset = out.items.len;

    try out.resize(allocator, payload_offset + options.payload.len + aead_tag_len);
    const ciphertext = out.items[payload_offset .. payload_offset + options.payload.len];
    const tag = out.items[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectAes128Payload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);
    try applyHeaderProtection(keys.hp, .short, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openShortPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
) Error!OpenedShortPacket {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    const bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 1 + destination_connection_id_len + 1 + aead_tag_len or (bytes[0] & 0x80) != 0 or (bytes[0] & 0x40) == 0) {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    try removeHeaderProtection(keys.hp, .short, bytes, pn_offset);
    if ((bytes[0] & 0x80) != 0 or (bytes[0] & 0x40) == 0) return error.InvalidInitialPacket;
    try validateShortHeaderReservedBits(bytes[0]);
    const spin_bit = (bytes[0] & 0x20) != 0;
    const key_phase = (bytes[0] & 0x04) != 0;
    const pn_len = @as(usize, (bytes[0] & 0x03) + 1);
    const payload_offset = pn_offset + pn_len;
    if (bytes.len < payload_offset + aead_tag_len) return error.InvalidInitialPacket;
    const packet_number = try reconstructPacketNumber(expected_packet_number, bytes[pn_offset..payload_offset]);
    const ciphertext = bytes[payload_offset .. bytes.len - aead_tag_len];
    const tag = bytes[bytes.len - aead_tag_len ..][0..aead_tag_len].*;
    const payload = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(payload);
    try openAes128Payload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);
    const dcid = try allocator.dupe(u8, bytes[1..pn_offset]);
    errdefer allocator.free(dcid);
    return .{
        .destination_connection_id = dcid,
        .packet_number = packet_number,
        .spin_bit = spin_bit,
        .key_phase = key_phase,
        .payload = payload,
    };
}

pub fn openShortPacketWithKeyUpdate(
    allocator: std.mem.Allocator,
    keys: ShortPacketKeyUpdateKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
) Error!OpenedShortPacketWithKeyUpdate {
    const key_phase = try peekShortPacketKeyPhase(allocator, keys.current.hp, packet, destination_connection_id_len);
    if (key_phase == keys.current_key_phase) {
        return .{
            .packet = try openShortPacket(allocator, keys.current, packet, destination_connection_id_len, expected_packet_number),
            .peer_initiated_key_update = false,
        };
    }

    const next_packet = openShortPacket(allocator, keys.next, packet, destination_connection_id_len, expected_packet_number) catch |next_err| {
        if (next_err == error.OutOfMemory) return next_err;
        if (keys.previous) |previous| {
            if (keys.previous_key_phase) |previous_key_phase| {
                if (key_phase == previous_key_phase) {
                    return .{
                        .packet = try openShortPacket(allocator, previous, packet, destination_connection_id_len, expected_packet_number),
                        .peer_initiated_key_update = false,
                    };
                }
            }
        }
        if (keys.discarded_previous_key_phase) |discarded_previous_key_phase| {
            if (key_phase == discarded_previous_key_phase) return error.KeyUpdateError;
        }
        return next_err;
    };
    return .{
        .packet = next_packet,
        .peer_initiated_key_update = true,
    };
}

pub fn applyHeaderProtection(
    hp_key: [hp_key_len]u8,
    header_form: HeaderForm,
    packet: []u8,
    pn_offset: usize,
) Error!void {
    if (pn_offset + 4 + header_protection_sample_len > packet.len) return error.InvalidHeaderProtectionSample;
    const sample = packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = aes128HeaderProtectionMask(hp_key, sample);
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    try applyHeaderProtectionMask(header_form, &packet[0], packet[pn_offset .. pn_offset + pn_len], mask);
}

pub fn removeHeaderProtection(
    hp_key: [hp_key_len]u8,
    header_form: HeaderForm,
    packet: []u8,
    pn_offset: usize,
) Error!void {
    if (pn_offset + 4 + header_protection_sample_len > packet.len) return error.InvalidHeaderProtectionSample;
    const sample = packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = aes128HeaderProtectionMask(hp_key, sample);
    packet[0] ^= mask[0] & switch (header_form) {
        .long => @as(u8, 0x0f),
        .short => @as(u8, 0x1f),
    };
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    if (pn_offset + pn_len > packet.len) return error.InvalidPacketNumberLength;
    for (packet[pn_offset .. pn_offset + pn_len], 0..) |*byte, i| {
        byte.* ^= mask[i + 1];
    }
}

fn peekShortPacketKeyPhase(
    allocator: std.mem.Allocator,
    hp_key: [hp_key_len]u8,
    packet: []const u8,
    destination_connection_id_len: usize,
) Error!bool {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    const bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 1 + destination_connection_id_len + 1 + aead_tag_len or (bytes[0] & 0x80) != 0 or (bytes[0] & 0x40) == 0) {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    try removeHeaderProtection(hp_key, .short, bytes, pn_offset);
    if ((bytes[0] & 0x80) != 0 or (bytes[0] & 0x40) == 0) return error.InvalidInitialPacket;
    try validateShortHeaderReservedBits(bytes[0]);
    return (bytes[0] & 0x04) != 0;
}

fn protectionProfile(version: u32) ProtectionProfile {
    if (version == version_2_wire) {
        return .{ .salt = &initial_salt_v2, .labels = hkdf_labels_v2 };
    }
    return .{ .salt = &initial_salt_v1, .labels = hkdf_labels_v1 };
}

fn longHeaderFirstByte(version: u32, packet_type: ProtectedLongPacketType, packet_number_len: u8) u8 {
    const type_bits: u8 = if (version == version_2_wire) switch (packet_type) {
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

fn protectedLongPacketType(first_byte: u8, version: u32) ProtectedLongPacketType {
    const bits: u2 = @truncate((first_byte >> 4) & 0x03);
    if (version == version_2_wire) {
        return switch (bits) {
            0 => .retry,
            1 => .initial,
            2 => .zero_rtt,
            3 => .handshake,
        };
    }
    return switch (bits) {
        0 => .initial,
        1 => .zero_rtt,
        2 => .handshake,
        3 => .retry,
    };
}

fn validatePacketNumberLen(packet_number_len: u8) Error!void {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacketNumberLength;
}

fn validatePacketNumber(packet_number: u64) Error!void {
    if (packet_number > max_packet_number) return error.InvalidPacketNumber;
}

fn validateLongHeaderFixedBit(first_byte: u8) Error!void {
    // The QUIC fixed bit is deliberately not masked by header protection.  Drop
    // malformed encrypted long-header packets at the packet-codec boundary just
    // like the generic long-header parser and mature stacks do, instead of
    // spending AEAD work on datagrams that cannot be valid QUIC v1/v2 packets.
    if ((first_byte & 0x40) == 0) return error.InvalidInitialPacket;
}

fn validateLongHeaderConnectionIdLen(len: usize) Error!void {
    // QUIC v1/v2 long-header packets cap both connection IDs at 20 bytes.
    // The generic parser, packet peeker, and the reference implementations
    // reject this before packet-number/header protection work; keep the
    // encrypted open paths equally strict so oversized IDs cannot bypass the
    // shared parsing invariant.
    if (len > 20) return error.InvalidInitialPacket;
}

fn validateLongHeaderReservedBits(first_byte: u8) Error!void {
    // RFC 9000 §17.2: long headers have two reserved bits (0x0c) that are
    // covered by header protection.  Mature stacks such as s2n-quic and
    // quic-zig fail these packets after removing header protection and before
    // accepting payload bytes.
    if ((first_byte & 0x0c) != 0) return error.InvalidInitialPacket;
}

fn validateShortHeaderReservedBits(first_byte: u8) Error!void {
    // RFC 9000 §17.3.1: short headers have reserved bits 0x18 once header
    // protection is removed.  Treating them as a packet error here prevents
    // malformed 1-RTT packets from reaching frame parsing or key-update state.
    if ((first_byte & 0x18) != 0) return error.InvalidInitialPacket;
}

fn appendTruncatedPacketNumber(list: *std.ArrayList(u8), allocator: std.mem.Allocator, packet_number: u64, packet_number_len: u8) Error!void {
    try validatePacketNumberLen(packet_number_len);
    try validatePacketNumber(packet_number);
    var full: [8]u8 = undefined;
    std.mem.writeInt(u64, &full, packet_number, .big);
    try list.appendSlice(allocator, full[8 - packet_number_len ..]);
}

fn reconstructPacketNumber(expected_packet_number: u64, packet_number_bytes: []const u8) Error!u64 {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    if (expected_packet_number > max_packet_number + 1) return error.InvalidPacketNumber;

    var truncated: u64 = 0;
    for (packet_number_bytes) |byte| truncated = (truncated << 8) | byte;
    const pn_nbits: u6 = @intCast(packet_number_bytes.len * 8);
    const pn_win = @as(u64, 1) << pn_nbits;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    var candidate = (expected_packet_number & ~pn_mask) | truncated;
    const candidate_plus_half = std.math.add(u64, candidate, pn_hwin) catch std.math.maxInt(u64);
    if (candidate_plus_half <= expected_packet_number) {
        candidate = std.math.add(u64, candidate, pn_win) catch return error.InvalidPacketNumber;
    } else {
        const expected_plus_half = std.math.add(u64, expected_packet_number, pn_hwin) catch std.math.maxInt(u64);
        if (candidate > expected_plus_half and candidate >= pn_win) candidate -= pn_win;
    }
    if (candidate > max_packet_number) return error.InvalidPacketNumber;
    return candidate;
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected_buf: [128]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_buf, expected_hex);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "QUIC initial secrets match RFC 9001 Appendix A.1" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = deriveInitialSecrets(&dcid);

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
    const secrets = deriveInitialSecrets(&dcid);
    var sample: [header_protection_sample_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = aes128HeaderProtectionMask(secrets.client.hp, sample);
    try expectHex("437b9aec36", &mask);

    var first_byte: u8 = 0xc3;
    var packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc0), first_byte);
    try expectHex("7b9aec34", &packet_number);
    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc3), first_byte);
    try expectHex("00000002", &packet_number);
}

test "QUIC AES payload protection roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = deriveInitialSecrets(&dcid).client;
    const ad = "initial header pn";
    const plaintext = "crypto frame bytes";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(keys, 2, ad, plaintext, &ciphertext, &tag);

    var opened: [plaintext.len]u8 = undefined;
    try openAes128Payload(keys, 2, ad, &ciphertext, tag, &opened);
    try std.testing.expectEqualStrings(plaintext, &opened);

    var bad_tag = tag;
    bad_tag[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, openAes128Payload(keys, 2, ad, &ciphertext, bad_tag, &opened));
}

test "QUIC AES key update derives next traffic keys and retains header protection" {
    const keys = deriveAes128Keys([_]u8{0x44} ** secret_len);
    const next_secret = nextAes128TrafficSecret(keys.secret);
    const next = nextAes128PacketProtectionKeys(keys);

    try std.testing.expectEqualSlices(u8, &next_secret, &next.secret);
    try std.testing.expect(!std.mem.eql(u8, &keys.secret, &next.secret));
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &next.key));
    try std.testing.expect(!std.mem.eql(u8, &keys.iv, &next.iv));
    try std.testing.expectEqualSlices(u8, &keys.hp, &next.hp);
}

test "QUIC v2 Initial secrets use v2 salt and labels" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const v1 = deriveInitialSecrets(&dcid);
    const v2 = deriveInitialSecretsForVersion(version_2_wire, &dcid);

    try std.testing.expect(!std.mem.eql(u8, &v1.initial_secret, &v2.initial_secret));
    try std.testing.expect(!std.mem.eql(u8, &v1.client.key, &v2.client.key));
    try std.testing.expect(!std.mem.eql(u8, &v1.client.iv, &v2.client.iv));
    try std.testing.expect(!std.mem.eql(u8, &v1.client.hp, &v2.client.hp));

    const base = [_]u8{0x46} ** secret_len;
    const v1_next = nextAes128TrafficSecret(base);
    const v2_next = nextAes128TrafficSecretForVersion(version_2_wire, base);
    try std.testing.expect(!std.mem.eql(u8, &v1_next, &v2_next));
}

test "QUIC key phase state advances and expires retained previous keys" {
    const keys = deriveAes128Keys([_]u8{0x45} ** secret_len);
    var state = Aes128KeyPhaseState.init(keys, false);

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
    try std.testing.expectEqual(@as(u8, 1), packetNumberLen(0, null));
    try std.testing.expectEqual(@as(u8, 1), packetNumberLen(0xabe8b3 + 1, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 2), packetNumberLen(0xac5c02, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 3), packetNumberLen(0xace8fe, 0xabe8b3));
    try std.testing.expectEqual(@as(u8, 4), packetNumberLen(max_packet_number, 0));
}

test "QUIC packet number length grows for tiny unpadded payloads" {
    try std.testing.expectEqual(@as(u8, 4), minimumPacketNumberLenForHeaderProtection(0));
    try std.testing.expectEqual(@as(u8, 3), packetNumberLenForPayload(1, 0, 1));
    try std.testing.expectEqual(@as(u8, 2), packetNumberLenForPayload(1, 0, 2));
    try std.testing.expectEqual(@as(u8, 1), packetNumberLenForPayload(1, 0, 3));
}

test "QUIC packet number reconstruction validates bounds" {
    try std.testing.expectEqual(
        @as(u64, 0xa82f9b32),
        try reconstructPacketNumber(0xa82f30ea + 1, &[_]u8{ 0x9b, 0x32 }),
    );
    try std.testing.expectEqual(@as(u64, 0xff), try reconstructPacketNumber(0x100, &[_]u8{0xff}));
    try std.testing.expectEqual(@as(u64, 0x200), try reconstructPacketNumber(0x180, &[_]u8{0x00}));
    try std.testing.expectEqual(@as(u64, 0x1f0), try reconstructPacketNumber(0x250, &[_]u8{0xf0}));
    try std.testing.expectEqual(
        max_packet_number,
        try reconstructPacketNumber(max_packet_number + 1, &[_]u8{ 0xff, 0xff, 0xff, 0xff }),
    );

    try std.testing.expectError(error.InvalidPacketNumberLength, reconstructPacketNumber(0, &[_]u8{}));
    try std.testing.expectError(error.InvalidPacketNumberLength, reconstructPacketNumber(0, &[_]u8{ 0, 0, 0, 0, 0 }));
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(max_packet_number + 2, &[_]u8{0}));
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(max_packet_number, &[_]u8{0}));
}

test "QUIC Initial packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const keys = deriveInitialSecrets(&dcid).client;
    const payload = "initial crypto payload";

    const sealed = try sealInitialPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 2,
        .packet_number_len = 4,
        .payload = payload,
    });
    defer allocator.free(sealed);
    try std.testing.expect(sealed.len > payload.len + dcid.len + scid.len);
    try std.testing.expect(sealed[0] != 0xc3); // Header protection changed the first byte for this vector.

    var opened = try openInitialPacket(allocator, keys, sealed, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), opened.version);
    try std.testing.expectEqual(@as(u64, 2), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);

    var tampered = try allocator.dupe(u8, sealed);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, openInitialPacket(allocator, keys, tampered, 0));
}

test "QUIC v2 Initial and Handshake packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const version = version_2_wire;
    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const initial_keys = deriveInitialSecretsForVersion(version, &dcid).client;
    const initial = try sealInitialPacket(allocator, initial_keys, .{
        .version = version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .packet_number_len = 2,
        .payload = "v2 initial",
    });
    defer allocator.free(initial);
    const initial_info = try peekProtectedLongPacketInfo(initial);
    try std.testing.expectEqual(version, initial_info.version);
    try std.testing.expectEqual(ProtectedLongPacketType.initial, initial_info.packet_type);

    var opened_initial = try openInitialPacket(allocator, initial_keys, initial, 0);
    defer opened_initial.deinit(allocator);
    try std.testing.expectEqual(version, opened_initial.version);
    try std.testing.expectEqual(@as(u64, 1), opened_initial.packet_number);
    try std.testing.expectEqualStrings("v2 initial", opened_initial.payload);

    const handshake_keys = deriveAes128KeysForVersion(version, [_]u8{0x57} ** secret_len);
    const handshake = try sealHandshakePacket(allocator, handshake_keys, .{
        .version = version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 2,
        .packet_number_len = 2,
        .payload = "v2 handshake",
    });
    defer allocator.free(handshake);
    const handshake_info = try peekProtectedLongPacketInfo(handshake);
    try std.testing.expectEqual(version, handshake_info.version);
    try std.testing.expectEqual(ProtectedLongPacketType.handshake, handshake_info.packet_type);

    var opened_handshake = try openHandshakePacket(allocator, handshake_keys, handshake, 0);
    defer opened_handshake.deinit(allocator);
    try std.testing.expectEqual(version, opened_handshake.version);
    try std.testing.expectEqual(@as(u64, 2), opened_handshake.packet_number);
    try std.testing.expectEqualStrings("v2 handshake", opened_handshake.payload);
}

test "QUIC 0-RTT long packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0x68} ** secret_len);
    const dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const scid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const zero_rtt = try sealZeroRttPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 3,
        .packet_number_len = 2,
        .payload = "early stream frames",
    });
    defer allocator.free(zero_rtt);

    const info = try peekProtectedLongPacketInfo(zero_rtt);
    try std.testing.expectEqual(@as(u32, 1), info.version);
    try std.testing.expectEqual(ProtectedLongPacketType.zero_rtt, info.packet_type);
    try std.testing.expectEqualSlices(u8, &dcid, info.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, info.source_connection_id);

    var opened = try openZeroRttPacket(allocator, keys, zero_rtt, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, opened.source_connection_id);
    try std.testing.expectEqualStrings("early stream frames", opened.payload);
}

test "QUIC Handshake packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0x42} ** secret_len);
    const dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const payload = "encrypted extensions and finished";

    const sealed = try sealHandshakePacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 3,
        .packet_number_len = 2,
        .payload = payload,
    });
    defer allocator.free(sealed);

    var opened = try openHandshakePacket(allocator, keys, sealed, 0);
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
    const initial_keys = deriveInitialSecrets(&dcid).client;
    const handshake_keys = deriveAes128Keys([_]u8{0x43} ** secret_len);

    const initial = try sealInitialPacket(allocator, initial_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = "initial payload",
    });
    defer allocator.free(initial);
    const handshake = try sealHandshakePacket(allocator, handshake_keys, .{
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

    const first = try peekProtectedLongPacketInfo(coalesced.items);
    try std.testing.expectEqual(@as(u32, 1), first.version);
    try std.testing.expectEqual(ProtectedLongPacketType.initial, first.packet_type);
    try std.testing.expectEqualSlices(u8, &dcid, first.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, first.source_connection_id);
    try std.testing.expectEqual(initial.len, first.len);

    const second = try peekProtectedLongPacketInfo(coalesced.items[first.len..]);
    try std.testing.expectEqual(@as(u32, 1), second.version);
    try std.testing.expectEqual(ProtectedLongPacketType.handshake, second.packet_type);
    try std.testing.expectEqualSlices(u8, &dcid, second.destination_connection_id);
    try std.testing.expectEqual(handshake.len, second.len);
}

test "QUIC 1-RTT short packet seal/open roundtrip" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0x99} ** secret_len);
    const dcid = [_]u8{ 1, 3, 3, 7 };
    const payload = "stream frame payload";
    const sealed = try sealShortPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .packet_number = 9,
        .packet_number_len = 2,
        .key_phase = false,
        .payload = payload,
    });
    defer allocator.free(sealed);

    var opened = try openShortPacket(allocator, keys, sealed, dcid.len, 0);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 9), opened.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, opened.destination_connection_id);
    try std.testing.expectEqualStrings(payload, opened.payload);
}

test "QUIC short packet preserves spin bit" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0x9a} ** secret_len);
    const dcid = [_]u8{ 0x01, 0x23, 0x45, 0x67 };
    const packet = try sealShortPacket(allocator, keys, .{
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

    var opened = try openShortPacket(allocator, keys, packet, dcid.len, 0);
    defer opened.deinit(allocator);
    try std.testing.expect(opened.spin_bit);
    try std.testing.expectEqualStrings("spin", opened.payload);
}

test "QUIC packet protection rejects reserved header bits after unprotect" {
    const allocator = std.testing.allocator;

    {
        const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
        const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
        const keys = deriveInitialSecrets(&dcid).client;
        const payload = "initial reserved bits";
        const packet_number: u64 = 4;
        const packet_number_len: u8 = 4;

        var packet: std.ArrayList(u8) = .empty;
        errdefer packet.deinit(allocator);
        try packet.append(allocator, longHeaderFirstByte(version_1_wire, .initial, packet_number_len) | 0x04);
        try wire.appendInt(&packet, allocator, u32, version_1_wire, .big);
        try packet.append(allocator, @intCast(dcid.len));
        try packet.appendSlice(allocator, &dcid);
        try packet.append(allocator, @intCast(scid.len));
        try packet.appendSlice(allocator, &scid);
        try varint.encode(&packet, allocator, 0);
        try varint.encode(&packet, allocator, packet_number_len + payload.len + aead_tag_len);
        const pn_offset = packet.items.len;
        try appendTruncatedPacketNumber(&packet, allocator, packet_number, packet_number_len);
        const payload_offset = packet.items.len;
        try packet.resize(allocator, payload_offset + payload.len + aead_tag_len);
        const ciphertext = packet.items[payload_offset .. payload_offset + payload.len];
        const tag = packet.items[payload_offset + payload.len ..][0..aead_tag_len];
        try protectAes128Payload(keys, packet_number, packet.items[0..payload_offset], payload, ciphertext, tag);
        try applyHeaderProtection(keys.hp, .long, packet.items, pn_offset);

        const malformed = try packet.toOwnedSlice(allocator);
        defer allocator.free(malformed);
        try std.testing.expectError(error.InvalidInitialPacket, openInitialPacket(allocator, keys, malformed, 0));
    }

    {
        const keys = deriveAes128Keys([_]u8{0x9b} ** secret_len);
        const dcid = [_]u8{ 0x01, 0x23, 0x45, 0x67 };
        const payload = "short reserved bits";
        const packet_number: u64 = 5;
        const packet_number_len: u8 = 4;

        var packet: std.ArrayList(u8) = .empty;
        errdefer packet.deinit(allocator);
        try packet.append(allocator, 0x40 | 0x08 | @as(u8, packet_number_len - 1));
        try packet.appendSlice(allocator, &dcid);
        const pn_offset = packet.items.len;
        try appendTruncatedPacketNumber(&packet, allocator, packet_number, packet_number_len);
        const payload_offset = packet.items.len;
        try packet.resize(allocator, payload_offset + payload.len + aead_tag_len);
        const ciphertext = packet.items[payload_offset .. payload_offset + payload.len];
        const tag = packet.items[payload_offset + payload.len ..][0..aead_tag_len];
        try protectAes128Payload(keys, packet_number, packet.items[0..payload_offset], payload, ciphertext, tag);
        try applyHeaderProtection(keys.hp, .short, packet.items, pn_offset);

        const malformed = try packet.toOwnedSlice(allocator);
        defer allocator.free(malformed);
        try std.testing.expectError(error.InvalidInitialPacket, openShortPacket(allocator, keys, malformed, dcid.len, 0));
    }
}

test "QUIC protected long packets reject a missing fixed bit before AEAD" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const scid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };

    const initial_keys = deriveInitialSecrets(&dcid).client;
    const initial = try sealInitialPacket(allocator, initial_keys, .{
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
    try std.testing.expectError(error.InvalidInitialPacket, openInitialPacket(allocator, initial_keys, malformed_initial, 0));

    const handshake_keys = deriveAes128Keys([_]u8{0xce} ** secret_len);
    const handshake = try sealHandshakePacket(allocator, handshake_keys, .{
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
    try std.testing.expectError(error.InvalidInitialPacket, openHandshakePacket(allocator, handshake_keys, malformed_handshake, 0));

    const zero_rtt_keys = deriveAes128Keys([_]u8{0xcf} ** secret_len);
    const zero_rtt = try sealZeroRttPacket(allocator, zero_rtt_keys, .{
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
    try std.testing.expectError(error.InvalidInitialPacket, openZeroRttPacket(allocator, zero_rtt_keys, malformed_zero_rtt, 0));
}

test "QUIC protected long packets reject oversized connection IDs before AEAD" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const keys = deriveInitialSecrets(&dcid).client;

    const initial_first = longHeaderFirstByte(version_1_wire, .initial, 1);
    const handshake_first = longHeaderFirstByte(version_1_wire, .handshake, 1);
    const zero_rtt_first = longHeaderFirstByte(version_1_wire, .zero_rtt, 1);
    const oversized_dcid_initial = [_]u8{ initial_first, 0, 0, 0, 1, 21 };
    const oversized_dcid_handshake = [_]u8{ handshake_first, 0, 0, 0, 1, 21 };
    const oversized_dcid_zero_rtt = [_]u8{ zero_rtt_first, 0, 0, 0, 1, 21 };

    try std.testing.expectError(error.InvalidInitialPacket, openInitialPacket(allocator, keys, &oversized_dcid_initial, 0));
    try std.testing.expectError(error.InvalidInitialPacket, openHandshakePacket(allocator, keys, &oversized_dcid_handshake, 0));
    try std.testing.expectError(error.InvalidInitialPacket, openZeroRttPacket(allocator, keys, &oversized_dcid_zero_rtt, 0));

    const oversized_scid_initial = [_]u8{ initial_first, 0, 0, 0, 1, 4, 1, 2, 3, 4, 21 };
    const oversized_scid_handshake = [_]u8{ handshake_first, 0, 0, 0, 1, 4, 1, 2, 3, 4, 21 };
    const oversized_scid_zero_rtt = [_]u8{ zero_rtt_first, 0, 0, 0, 1, 4, 1, 2, 3, 4, 21 };

    try std.testing.expectError(error.InvalidInitialPacket, openInitialPacket(allocator, keys, &oversized_scid_initial, 0));
    try std.testing.expectError(error.InvalidInitialPacket, openHandshakePacket(allocator, keys, &oversized_scid_handshake, 0));
    try std.testing.expectError(error.InvalidInitialPacket, openZeroRttPacket(allocator, keys, &oversized_scid_zero_rtt, 0));
}

test "QUIC short packet key update opens next and retained previous generations" {
    const allocator = std.testing.allocator;
    const keys = deriveAes128Keys([_]u8{0xa7} ** secret_len);
    const next = nextAes128PacketProtectionKeys(keys);
    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };

    const old_packet = try sealShortPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .packet_number = 7,
        .packet_number_len = 4,
        .key_phase = false,
        .payload = "old-generation",
    });
    defer allocator.free(old_packet);

    const updated_packet = try sealShortPacket(allocator, next, .{
        .destination_connection_id = &dcid,
        .packet_number = 8,
        .packet_number_len = 4,
        .key_phase = true,
        .payload = "next-generation",
    });
    defer allocator.free(updated_packet);

    var receiver = Aes128KeyPhaseState.init(keys, false);
    var opened_next = try openShortPacketWithKeyUpdate(allocator, receiver.keyUpdateKeys(), updated_packet, dcid.len, 0);
    defer opened_next.deinit(allocator);
    try std.testing.expect(opened_next.peer_initiated_key_update);
    try std.testing.expect(opened_next.packet.key_phase);
    try std.testing.expectEqualStrings("next-generation", opened_next.packet.payload);
    try std.testing.expect(receiver.updateAfterReceiving(opened_next.packet.key_phase));

    var delayed_old = try openShortPacketWithKeyUpdate(allocator, receiver.keyUpdateKeys(), old_packet, dcid.len, 0);
    defer delayed_old.deinit(allocator);
    try std.testing.expect(!delayed_old.peer_initiated_key_update);
    try std.testing.expect(!delayed_old.packet.key_phase);
    try std.testing.expectEqualStrings("old-generation", delayed_old.packet.payload);

    receiver.schedulePreviousDiscard(1_000);
    try std.testing.expect(receiver.discardExpiredPrevious(1_000));
    try std.testing.expectError(
        error.KeyUpdateError,
        openShortPacketWithKeyUpdate(allocator, receiver.keyUpdateKeys(), old_packet, dcid.len, 0),
    );
}

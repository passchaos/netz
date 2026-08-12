const std = @import("std");
const vail = @import("vail");
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
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(
    std.crypto.auth.hmac.sha2.HmacSha384,
);
const traffic_crypto = vail.quic.traffic_crypto;
const TlsSecret = vail.tls.secret.Secret;

const version_1_wire: u32 = 0x00000001;
const version_2_wire: u32 = 0x6b3343cf;

pub const CipherSuite = traffic_crypto.Suite;
pub const secret_len = HkdfSha256.prk_length;
pub const aes_128_key_len = 16;
pub const max_key_len = traffic_crypto.max_key_len;
pub const iv_len = traffic_crypto.iv_len;
pub const hp_key_len = aes_128_key_len;
pub const aead_tag_len = traffic_crypto.tag_len;
pub const header_protection_sample_len = traffic_crypto.sample_len;
pub const header_protection_mask_len = traffic_crypto.mask_len;
pub const max_packet_number: u64 = varint.max_value;
/// RFC 9001 Section 6.6 / Appendix B.1 limits for AEAD_AES_128_GCM.
pub const aes_128_gcm_confidentiality_limit =
    CipherSuite.aes_128_gcm_sha256.confidentialityLimit();
pub const aes_128_gcm_integrity_limit =
    CipherSuite.aes_128_gcm_sha256.integrityLimit();

pub const VersionError = error{
    UnsupportedVersion,
};

pub const Error = varint.Error || VersionError || error{
    InvalidInitialPacket,
    InvalidCipherSuite,
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
    suite: CipherSuite = .aes_128_gcm_sha256,
    /// Source-compatible SHA-256 view. Suite-generic code uses
    /// `traffic_secret`, which can carry SHA-384's 48 bytes.
    secret: [secret_len]u8,
    traffic_secret: TlsSecret =
        .fromSha256([_]u8{0} ** secret_len),
    /// Source-compatible AES-128 view. New suite-generic code must use the
    /// packet helpers below, which consume `suite_key` and `suite_hp`.
    key: [aes_128_key_len]u8,
    iv: [iv_len]u8,
    hp: [hp_key_len]u8,
    /// Canonical key storage sized for the largest Vail traffic suite.
    suite_key: [max_key_len]u8 = [_]u8{0} ** max_key_len,
    suite_hp: [max_key_len]u8 = [_]u8{0} ** max_key_len,

    pub fn confidentialityLimit(self: PacketProtectionKeys) u64 {
        return self.suite.confidentialityLimit();
    }

    pub fn integrityLimit(self: PacketProtectionKeys) u64 {
        return self.suite.integrityLimit();
    }
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
    fixed_bit: bool = true,
    payload: []const u8,
};

pub const OpenedInitialPacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    token: []u8,
    packet_number: u64,
    fixed_bit: bool,
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
    fixed_bit: bool = true,
    payload: []const u8,
};

pub const OpenedHandshakePacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    packet_number: u64,
    fixed_bit: bool,
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
    fixed_bit: bool = true,
    payload: []const u8,
};

pub const OpenedZeroRttPacket = struct {
    version: u32,
    destination_connection_id: []u8,
    source_connection_id: []u8,
    packet_number: u64,
    fixed_bit: bool,
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
    /// RFC 9287 permits clearing this bit only after peer support is known.
    fixed_bit: bool = true,
    spin_bit: bool = false,
    key_phase: bool = false,
    payload: []const u8,
};

pub const OpenedShortPacket = struct {
    destination_connection_id: []u8,
    packet_number: u64,
    fixed_bit: bool,
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

pub const OpenedShortPacketView = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    fixed_bit: bool,
    spin_bit: bool,
    key_phase: bool,
    payload: []u8,
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
pub const KeyPhaseState = struct {
    current: PacketProtectionKeys,
    next: PacketProtectionKeys,
    current_key_phase: bool,
    key_update_count: u64 = 0,
    previous: ?PacketProtectionKeys = null,
    previous_key_phase: ?bool = null,
    previous_discard_deadline_nanos: ?i64 = null,
    discarded_previous_key_phase: ?bool = null,

    pub fn init(current: PacketProtectionKeys, current_key_phase: bool) KeyPhaseState {
        return .{
            .current = current,
            .next = nextPacketProtectionKeys(current),
            .current_key_phase = current_key_phase,
        };
    }

    pub fn currentKeys(self: KeyPhaseState) PacketProtectionKeys {
        return self.current;
    }

    pub fn currentKeyPhase(self: KeyPhaseState) bool {
        return self.current_key_phase;
    }

    pub fn keyUpdateCount(self: KeyPhaseState) u64 {
        return self.key_update_count;
    }

    pub fn previousKeyGeneration(self: KeyPhaseState) ?u64 {
        if (self.previous == null) return null;
        return self.key_update_count -% 1;
    }

    pub fn retainsKeyGeneration(self: KeyPhaseState, generation: u64) bool {
        if (generation == self.key_update_count) return true;
        if (generation == self.key_update_count +| 1) return true;
        if (self.previousKeyGeneration()) |previous_generation| {
            return generation == previous_generation;
        }
        return false;
    }

    pub fn keyUpdateKeys(self: KeyPhaseState) ShortPacketKeyUpdateKeys {
        return .{
            .current = self.current,
            .next = self.next,
            .current_key_phase = self.current_key_phase,
            .previous = self.previous,
            .previous_key_phase = self.previous_key_phase,
            .discarded_previous_key_phase = self.discarded_previous_key_phase,
        };
    }

    pub fn initiateKeyUpdate(self: *KeyPhaseState) void {
        self.advance();
    }

    pub fn updateAfterReceiving(self: *KeyPhaseState, peer_key_phase: bool) bool {
        if (peer_key_phase == self.current_key_phase) return false;
        self.advance();
        return true;
    }

    pub fn schedulePreviousDiscard(self: *KeyPhaseState, deadline_nanos: i64) void {
        if (self.previous == null) return;
        self.previous_discard_deadline_nanos = deadline_nanos;
    }

    pub fn previousDiscardDeadline(self: KeyPhaseState) ?i64 {
        return self.previous_discard_deadline_nanos;
    }

    pub fn discardExpiredPrevious(self: *KeyPhaseState, now_nanos: i64) bool {
        const deadline = self.previous_discard_deadline_nanos orelse return false;
        if (now_nanos < deadline) return false;
        self.discarded_previous_key_phase = self.previous_key_phase;
        self.previous = null;
        self.previous_key_phase = null;
        self.previous_discard_deadline_nanos = null;
        return true;
    }

    fn advance(self: *KeyPhaseState) void {
        self.previous = self.current;
        self.previous_key_phase = self.current_key_phase;
        self.previous_discard_deadline_nanos = null;
        self.current = self.next;
        self.next = nextPacketProtectionKeys(self.current);
        self.current_key_phase = !self.current_key_phase;
        self.key_update_count +|= 1;
    }
};

pub const Aes128KeyPhaseState = KeyPhaseState;

pub fn deriveInitialSecrets(client_initial_dcid: []const u8) InitialSecrets {
    return deriveInitialSecretsForVersion(version_1_wire, client_initial_dcid) catch unreachable;
}

pub fn deriveInitialSecretsForVersion(version: u32, client_initial_dcid: []const u8) VersionError!InitialSecrets {
    const profile = try protectionProfile(version);
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

pub fn deriveAes128KeysForVersion(version: u32, secret: [secret_len]u8) VersionError!PacketProtectionKeys {
    return deriveAes128KeysWithLabels(secret, (try protectionProfile(version)).labels);
}

pub fn deriveKeys(
    suite: CipherSuite,
    secret: [secret_len]u8,
) PacketProtectionKeys {
    return deriveKeysWithLabels(
        suite,
        .fromSha256(secret),
        hkdf_labels_v1,
    ) catch unreachable;
}

fn deriveAes128KeysWithLabels(secret: [secret_len]u8, labels: HkdfLabels) PacketProtectionKeys {
    return deriveKeysWithLabels(
        .aes_128_gcm_sha256,
        .fromSha256(secret),
        labels,
    ) catch unreachable;
}

pub fn deriveKeysForVersion(
    version: u32,
    suite: CipherSuite,
    secret: [secret_len]u8,
) VersionError!PacketProtectionKeys {
    return deriveKeysWithLabels(
        suite,
        .fromSha256(secret),
        (try protectionProfile(version)).labels,
    ) catch unreachable;
}

pub fn deriveKeysForSecretForVersion(
    version: u32,
    suite: CipherSuite,
    traffic_secret: TlsSecret,
) (VersionError || error{HashMismatch})!PacketProtectionKeys {
    return deriveKeysWithLabels(
        suite,
        traffic_secret,
        (try protectionProfile(version)).labels,
    );
}

fn deriveKeysWithLabels(
    suite: CipherSuite,
    traffic_secret: TlsSecret,
    labels: HkdfLabels,
) error{HashMismatch}!PacketProtectionKeys {
    const derived = try traffic_crypto.Keys.deriveChecked(
        suite,
        traffic_secret,
        .{
            .key = labels.key,
            .iv = labels.iv,
            .hp = labels.hp,
        },
    );
    const compatibility_secret = if (traffic_secret.hash == .sha256)
        traffic_secret.sha256() catch unreachable
    else
        [_]u8{0} ** secret_len;
    return .{
        .suite = suite,
        .secret = compatibility_secret,
        .traffic_secret = traffic_secret,
        .key = derived.key[0..aes_128_key_len].*,
        .iv = derived.iv,
        .hp = derived.hp[0..hp_key_len].*,
        .suite_key = derived.key,
        .suite_hp = derived.hp,
    };
}

pub fn deriveChaCha20Keys(
    secret: [secret_len]u8,
) PacketProtectionKeys {
    return deriveKeysWithLabels(
        .chacha20_poly1305_sha256,
        .fromSha256(secret),
        hkdf_labels_v1,
    ) catch unreachable;
}

pub fn nextAes128TrafficSecret(secret: [secret_len]u8) [secret_len]u8 {
    return nextTrafficSecret(secret);
}

pub fn nextAes128TrafficSecretForVersion(version: u32, secret: [secret_len]u8) VersionError![secret_len]u8 {
    return nextTrafficSecretForVersion(version, secret);
}

pub fn nextTrafficSecret(secret: [secret_len]u8) [secret_len]u8 {
    return nextTrafficSecretForVersion(version_1_wire, secret) catch unreachable;
}

pub fn nextTrafficSecretForVersion(version: u32, secret: [secret_len]u8) VersionError![secret_len]u8 {
    return hkdfExpandLabel(secret, (try protectionProfile(version)).labels.ku, secret_len);
}

/// Derive the next QUIC 1-RTT packet-protection generation.
///
/// RFC 9001 key updates derive a new traffic secret with the `quic ku` label.
/// The packet protection key and IV change, while the header-protection key is
/// retained for the life of the connection so the key phase bit itself remains
/// protected consistently across generations.
pub fn nextAes128PacketProtectionKeys(current: PacketProtectionKeys) PacketProtectionKeys {
    return nextPacketProtectionKeys(current);
}

pub fn nextAes128PacketProtectionKeysForVersion(version: u32, current: PacketProtectionKeys) VersionError!PacketProtectionKeys {
    return nextPacketProtectionKeysForVersion(version, current);
}

pub fn nextPacketProtectionKeys(current: PacketProtectionKeys) PacketProtectionKeys {
    return nextPacketProtectionKeysForVersion(version_1_wire, current) catch unreachable;
}

pub fn nextPacketProtectionKeysForVersion(version: u32, current: PacketProtectionKeys) VersionError!PacketProtectionKeys {
    const labels = (try protectionProfile(version)).labels;
    const next_secret = nextTrafficSecretValue(
        current.traffic_secret,
        labels.ku,
    );
    var next = deriveKeysWithLabels(
        current.suite,
        next_secret,
        labels,
    ) catch unreachable;
    next.hp = current.hp;
    next.suite_hp = current.suite_hp;
    return next;
}

pub fn hkdfExpandLabel(secret: [secret_len]u8, label: []const u8, comptime len: usize) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, "", len);
}

pub fn packetProtectionNonce(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    return traffic_crypto.packetNonce(iv, packet_number);
}

pub fn aes128HeaderProtectionMask(hp_key: [hp_key_len]u8, sample: [header_protection_sample_len]u8) [header_protection_mask_len]u8 {
    var extended = [_]u8{0} ** max_key_len;
    extended[0..hp_key_len].* = hp_key;
    return headerProtectionMask(.aes_128_gcm_sha256, extended, sample);
}

fn headerProtectionMask(
    suite: CipherSuite,
    hp_key: [max_key_len]u8,
    sample: [header_protection_sample_len]u8,
) [header_protection_mask_len]u8 {
    return (traffic_crypto.Keys{
        .suite = suite,
        .secret = [_]u8{0} ** secret_len,
        .key = [_]u8{0} ** max_key_len,
        .iv = [_]u8{0} ** iv_len,
        .hp = hp_key,
    }).headerProtectionMask(sample);
}

pub fn applyHeaderProtectionForKeys(
    keys: PacketProtectionKeys,
    header_form: HeaderForm,
    packet: []u8,
    pn_offset: usize,
) Error!void {
    if (pn_offset + 4 + header_protection_sample_len > packet.len) {
        return error.InvalidHeaderProtectionSample;
    }
    const sample =
        packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = asVailKeys(keys).headerProtectionMask(sample);
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    try applyHeaderProtectionMask(
        header_form,
        &packet[0],
        packet[pn_offset .. pn_offset + pn_len],
        mask,
    );
}

pub fn removeHeaderProtectionForKeys(
    keys: PacketProtectionKeys,
    header_form: HeaderForm,
    packet: []u8,
    pn_offset: usize,
) Error!void {
    if (pn_offset + 4 + header_protection_sample_len > packet.len) {
        return error.InvalidHeaderProtectionSample;
    }
    const sample =
        packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = asVailKeys(keys).headerProtectionMask(sample);
    packet[0] ^= mask[0] & switch (header_form) {
        .long => @as(u8, 0x0f),
        .short => @as(u8, 0x1f),
    };
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    if (pn_offset + pn_len > packet.len) {
        return error.InvalidPacketNumberLength;
    }
    for (packet[pn_offset .. pn_offset + pn_len], 0..) |*byte, index| {
        byte.* ^= mask[index + 1];
    }
}

pub fn peekShortPacketKeyPhaseForKeys(
    keys: PacketProtectionKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
) Error!bool {
    return peekShortPacketKeyPhaseForKeysWithFixedBitPolicy(
        keys,
        packet,
        destination_connection_id_len,
        false,
    );
}

pub fn peekShortPacketKeyPhaseForKeysWithFixedBitPolicy(
    keys: PacketProtectionKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    allow_zero_fixed_bit: bool,
) Error!bool {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    if (packet.len < 1 + destination_connection_id_len + 1 + aead_tag_len or
        (packet[0] & 0x80) != 0 or
        (!allow_zero_fixed_bit and (packet[0] & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    if (pn_offset + 4 + header_protection_sample_len > packet.len) {
        return error.InvalidHeaderProtectionSample;
    }
    const sample =
        packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    const mask = asVailKeys(keys).headerProtectionMask(sample);
    const first = packet[0] ^ (mask[0] & 0x1f);
    if ((first & 0x80) != 0 or
        (!allow_zero_fixed_bit and (first & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    try validateShortHeaderReservedBits(first);
    return (first & 0x04) != 0;
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

pub fn protectPayload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
) Error!void {
    try validatePacketNumber(packet_number);
    try asVailKeys(keys).protect(
        packet_number,
        associated_data,
        plaintext,
        ciphertext,
        tag,
    );
}

pub fn openPayload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [aead_tag_len]u8,
    plaintext: []u8,
) Error!void {
    try validatePacketNumber(packet_number);
    try asVailKeys(keys).open(
        packet_number,
        associated_data,
        ciphertext,
        tag,
        plaintext,
    );
}

pub fn protectAes128Payload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
) Error!void {
    if (keys.suite != .aes_128_gcm_sha256) {
        return error.InvalidPayloadLength;
    }
    try protectPayload(
        keys,
        packet_number,
        associated_data,
        plaintext,
        ciphertext,
        tag,
    );
}

pub fn openAes128Payload(
    keys: PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [aead_tag_len]u8,
    plaintext: []u8,
) Error!void {
    if (keys.suite != .aes_128_gcm_sha256) {
        return error.InvalidPayloadLength;
    }
    try openPayload(
        keys,
        packet_number,
        associated_data,
        ciphertext,
        tag,
        plaintext,
    );
}

fn asVailKeys(keys: PacketProtectionKeys) traffic_crypto.Keys {
    var suite_key = keys.suite_key;
    var suite_hp = keys.suite_hp;
    if (keys.suite == .aes_128_gcm_sha256) {
        suite_key[0..aes_128_key_len].* = keys.key;
        suite_hp[0..hp_key_len].* = keys.hp;
    }
    return .{
        .suite = keys.suite,
        .secret = keys.secret,
        .traffic_secret = keys.traffic_secret,
        .key = suite_key,
        .iv = keys.iv,
        .hp = suite_hp,
    };
}

fn nextTrafficSecretValue(
    current: TlsSecret,
    label: []const u8,
) TlsSecret {
    return switch (current.hash) {
        .sha256 => .fromSha256(std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            current.sha256() catch unreachable,
            label,
            "",
            32,
        )),
        .sha384 => .fromSha384(std.crypto.tls.hkdfExpandLabel(
            HkdfSha384,
            current.sha384() catch unreachable,
            label,
            "",
            48,
        )),
        .sm3 => unreachable,
    };
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

fn protectedLongPacketCapacity(
    destination_connection_id_len: usize,
    source_connection_id_len: usize,
    token_len: usize,
    has_token_length_field: bool,
    packet_number_len: usize,
    payload_len: usize,
) Error!usize {
    var len: usize = 1 + 4 + 1 + 1;
    len = std.math.add(usize, len, destination_connection_id_len) catch
        return error.InvalidPayloadLength;
    len = std.math.add(usize, len, source_connection_id_len) catch
        return error.InvalidPayloadLength;
    if (has_token_length_field) {
        len = std.math.add(usize, len, try varint.length(token_len)) catch
            return error.InvalidPayloadLength;
        len = std.math.add(usize, len, token_len) catch
            return error.InvalidPayloadLength;
    }
    len = std.math.add(usize, len, 8) catch return error.InvalidPayloadLength;
    len = std.math.add(usize, len, packet_number_len) catch
        return error.InvalidPayloadLength;
    len = std.math.add(usize, len, payload_len) catch
        return error.InvalidPayloadLength;
    return std.math.add(usize, len, aead_tag_len) catch
        return error.InvalidPayloadLength;
}

pub fn sealInitialPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: InitialPacketOptions,
) Error![]u8 {
    // RFC 9001 fixes Initial protection to AES-128-GCM independently of the
    // later TLS cipher-suite negotiation.
    if (keys.suite != .aes_128_gcm_sha256) {
        return error.InvalidCipherSuite;
    }
    try validateProtectedVersion(options.version);
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    try out.ensureUnusedCapacity(
        allocator,
        try protectedLongPacketCapacity(
            options.destination_connection_id.len,
            options.source_connection_id.len,
            options.token.len,
            true,
            pn_len,
            options.payload.len,
        ),
    );
    const first_byte: u8 = longHeaderFirstByte(
        options.version,
        .initial,
        options.packet_number_len,
        options.fixed_bit,
    );
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
    try protectPayload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtectionForKeys(keys, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openInitialPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedInitialPacket {
    return openInitialPacketWithFixedBitPolicy(
        allocator,
        keys,
        packet,
        expected_packet_number,
        false,
    );
}

pub fn openInitialPacketWithFixedBitPolicy(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
    allow_zero_fixed_bit: bool,
) Error!OpenedInitialPacket {
    if (keys.suite != .aes_128_gcm_sha256) {
        return error.InvalidCipherSuite;
    }
    const bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    const protected_first_byte = try cursor.readByte();
    try validateLongHeaderFixedBitPolicy(
        protected_first_byte,
        allow_zero_fixed_bit,
    );
    const version = try cursor.readInt(u32, .big);
    try validateProtectedVersion(version);
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
    try validateLongHeaderProtectionSampleBounds(protected_len);

    try removeHeaderProtectionForKeys(keys, .long, bytes, pn_offset);
    if ((bytes[0] & 0x80) == 0 or protectedLongPacketType(bytes[0], version) != .initial) return error.InvalidInitialPacket;
    try validateLongHeaderFixedBitPolicy(
        bytes[0],
        allow_zero_fixed_bit,
    );
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
    try openPayload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

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
        .fixed_bit = (bytes[0] & 0x40) != 0,
        .payload = payload,
    };
}

pub fn sealHandshakePacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: HandshakePacketOptions,
) Error![]u8 {
    try validateProtectedVersion(options.version);
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    try out.ensureUnusedCapacity(
        allocator,
        try protectedLongPacketCapacity(
            options.destination_connection_id.len,
            options.source_connection_id.len,
            0,
            false,
            pn_len,
            options.payload.len,
        ),
    );
    const first_byte: u8 = longHeaderFirstByte(
        options.version,
        .handshake,
        options.packet_number_len,
        options.fixed_bit,
    );
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
    try protectPayload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtectionForKeys(keys, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openHandshakePacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedHandshakePacket {
    return openHandshakePacketWithFixedBitPolicy(
        allocator,
        keys,
        packet,
        expected_packet_number,
        false,
    );
}

pub fn openHandshakePacketWithFixedBitPolicy(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
    allow_zero_fixed_bit: bool,
) Error!OpenedHandshakePacket {
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    const protected_first_byte = try cursor.readByte();
    try validateLongHeaderFixedBitPolicy(
        protected_first_byte,
        allow_zero_fixed_bit,
    );
    const version = try cursor.readInt(u32, .big);
    try validateProtectedVersion(version);
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
    try validateLongHeaderProtectionSampleBounds(protected_len);

    try removeHeaderProtectionForKeys(keys, .long, bytes, pn_offset);
    if ((bytes[0] & 0x80) == 0 or protectedLongPacketType(bytes[0], version) != .handshake) return error.InvalidInitialPacket;
    try validateLongHeaderFixedBitPolicy(
        bytes[0],
        allow_zero_fixed_bit,
    );
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
    try openPayload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .packet_number = packet_number,
        .fixed_bit = (bytes[0] & 0x40) != 0,
        .payload = payload,
    };
}

pub fn sealZeroRttPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    options: ZeroRttPacketOptions,
) Error![]u8 {
    try validateProtectedVersion(options.version);
    try validatePacketNumberLen(options.packet_number_len);
    if (options.destination_connection_id.len > 20 or options.source_connection_id.len > 20) return error.InvalidInitialPacket;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const pn_len = @as(usize, options.packet_number_len);
    try out.ensureUnusedCapacity(
        allocator,
        try protectedLongPacketCapacity(
            options.destination_connection_id.len,
            options.source_connection_id.len,
            0,
            false,
            pn_len,
            options.payload.len,
        ),
    );
    const first_byte: u8 = longHeaderFirstByte(
        options.version,
        .zero_rtt,
        options.packet_number_len,
        options.fixed_bit,
    );
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
    try protectPayload(keys, options.packet_number, out.items[0..payload_offset], options.payload, ciphertext, tag);

    try applyHeaderProtectionForKeys(keys, .long, out.items, pn_offset);
    return out.toOwnedSlice(allocator);
}

pub fn openZeroRttPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
) Error!OpenedZeroRttPacket {
    return openZeroRttPacketWithFixedBitPolicy(
        allocator,
        keys,
        packet,
        expected_packet_number,
        false,
    );
}

pub fn openZeroRttPacketWithFixedBitPolicy(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    expected_packet_number: u64,
    allow_zero_fixed_bit: bool,
) Error!OpenedZeroRttPacket {
    var bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 7 or (bytes[0] & 0x80) == 0) return error.InvalidInitialPacket;

    var cursor = wire.Cursor.init(bytes);
    const protected_first_byte = try cursor.readByte();
    try validateLongHeaderFixedBitPolicy(
        protected_first_byte,
        allow_zero_fixed_bit,
    );
    const version = try cursor.readInt(u32, .big);
    try validateProtectedVersion(version);
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
    try validateLongHeaderProtectionSampleBounds(protected_len);

    try removeHeaderProtectionForKeys(keys, .long, bytes, pn_offset);
    if ((bytes[0] & 0x80) == 0 or protectedLongPacketType(bytes[0], version) != .zero_rtt) return error.InvalidInitialPacket;
    try validateLongHeaderFixedBitPolicy(
        bytes[0],
        allow_zero_fixed_bit,
    );
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
    try openPayload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);

    const dcid_owned = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_owned);
    const scid_owned = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_owned);

    return .{
        .version = version,
        .destination_connection_id = dcid_owned,
        .source_connection_id = scid_owned,
        .packet_number = packet_number,
        .fixed_bit = (bytes[0] & 0x40) != 0,
        .payload = payload,
    };
}

pub fn peekProtectedLongPacketInfo(datagram: []const u8) Error!ProtectedLongPacketInfo {
    return peekProtectedLongPacketInfoWithFixedBitPolicy(datagram, false);
}

pub fn peekProtectedLongPacketInfoWithFixedBitPolicy(
    datagram: []const u8,
    allow_zero_fixed_bit: bool,
) Error!ProtectedLongPacketInfo {
    var cursor = wire.Cursor.init(datagram);
    const first = try cursor.readByte();
    if ((first & 0x80) == 0 or
        (!allow_zero_fixed_bit and (first & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    const version = try cursor.readInt(u32, .big);
    if (version == 0) return error.InvalidInitialPacket;
    try validateProtectedVersion(version);

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
    const packet_len = try shortPacketLen(options);
    const packet = try allocator.alloc(u8, packet_len);
    errdefer allocator.free(packet);
    const written = try sealShortPacketInto(packet, keys, options);
    std.debug.assert(written.len == packet.len);
    return packet;
}

/// Seal a QUIC short-header packet directly into caller-provided storage.
///
/// This is the allocation-free primitive used by long-lived 1-RTT
/// connections. Callers can provision `shortPacketLen(options)` bytes once and
/// reuse the storage for every send, while `sealShortPacket` remains the
/// ownership-friendly allocating wrapper.
pub fn sealShortPacketInto(
    out: []u8,
    keys: PacketProtectionKeys,
    options: ShortPacketOptions,
) Error![]u8 {
    const packet_len = try shortPacketLen(options);
    if (out.len < packet_len) return error.BufferTooShort;

    const packet = out[0..packet_len];
    const pn_len = @as(usize, options.packet_number_len);
    const pn_offset = 1 + options.destination_connection_id.len;
    const payload_offset = pn_offset + pn_len;
    packet[0] = shortHeaderFirstByte(options, pn_len);
    @memcpy(packet[1..pn_offset], options.destination_connection_id);
    try writeTruncatedPacketNumber(packet[pn_offset..payload_offset], options.packet_number);

    const ciphertext = packet[payload_offset .. payload_offset + options.payload.len];
    const tag = packet[payload_offset + options.payload.len ..][0..aead_tag_len];
    try protectPayload(keys, options.packet_number, packet[0..payload_offset], options.payload, ciphertext, tag);
    try applyHeaderProtectionForKeys(keys, .short, packet, pn_offset);
    return packet;
}

pub fn shortPacketLen(options: ShortPacketOptions) Error!usize {
    try validatePacketNumberLen(options.packet_number_len);
    try validatePacketNumber(options.packet_number);
    if (options.destination_connection_id.len > 20) return error.InvalidInitialPacket;

    const pn_len = @as(usize, options.packet_number_len);
    const header_len = std.math.add(usize, 1 + pn_len, options.destination_connection_id.len) catch return error.InvalidPayloadLength;
    const protected_payload_len = std.math.add(usize, options.payload.len, aead_tag_len) catch return error.InvalidPayloadLength;
    return std.math.add(usize, header_len, protected_payload_len) catch error.InvalidPayloadLength;
}

fn shortHeaderFirstByte(options: ShortPacketOptions, packet_number_len: usize) u8 {
    return (if (options.fixed_bit) @as(u8, 0x40) else 0) |
        (if (options.spin_bit) @as(u8, 0x20) else 0) |
        (if (options.key_phase) @as(u8, 0x04) else 0) |
        @as(u8, @intCast(packet_number_len - 1));
}

fn writeTruncatedPacketNumber(out: []u8, packet_number: u64) Error!void {
    if (out.len == 0 or out.len > 4) return error.InvalidPacketNumberLength;
    try validatePacketNumber(packet_number);
    writeTruncatedPacketNumberAssumeValid(out, packet_number);
}

pub fn writeTruncatedPacketNumberAssumeValid(out: []u8, packet_number: u64) void {
    std.debug.assert(out.len != 0);
    std.debug.assert(out.len <= 4);
    std.debug.assert(packet_number <= max_packet_number);
    const shift: u6 = @intCast((out.len - 1) * 8);
    for (out, 0..) |*byte, index| {
        const remaining_shift: u6 = shift - @as(u6, @intCast(index * 8));
        byte.* = @truncate(packet_number >> remaining_shift);
    }
}

pub fn openShortPacket(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
) Error!OpenedShortPacket {
    return openShortPacketWithFixedBitPolicy(
        allocator,
        keys,
        packet,
        destination_connection_id_len,
        expected_packet_number,
        false,
    );
}

/// Open a short-header packet with RFC 9287 negotiation state supplied by the
/// connection. The default wrapper above remains strict for pre-negotiation
/// and standalone callers.
pub fn openShortPacketWithFixedBitPolicy(
    allocator: std.mem.Allocator,
    keys: PacketProtectionKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    allow_zero_fixed_bit: bool,
) Error!OpenedShortPacket {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    const bytes = try allocator.dupe(u8, packet);
    defer allocator.free(bytes);
    if (bytes.len < 1 + destination_connection_id_len + 1 + aead_tag_len or
        (bytes[0] & 0x80) != 0 or
        (!allow_zero_fixed_bit and (bytes[0] & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    try removeHeaderProtectionForKeys(keys, .short, bytes, pn_offset);
    if ((bytes[0] & 0x80) != 0 or
        (!allow_zero_fixed_bit and (bytes[0] & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
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
    try openPayload(keys, packet_number, bytes[0..payload_offset], ciphertext, tag, payload);
    const dcid = try allocator.dupe(u8, bytes[1..pn_offset]);
    errdefer allocator.free(dcid);
    return .{
        .destination_connection_id = dcid,
        .packet_number = packet_number,
        .fixed_bit = (bytes[0] & 0x40) != 0,
        .spin_bit = spin_bit,
        .key_phase = key_phase,
        .payload = payload,
    };
}

/// Remove short-header protection and decrypt the payload in caller-owned
/// packet storage.
///
/// This primitive deliberately accepts one key generation. Callers that need
/// key-update fallback must determine the key phase before invoking it, because
/// AEAD authentication failure makes the plaintext output undefined and cannot
/// safely retry another key against the same in-place ciphertext.
pub fn openShortPacketInPlace(
    keys: PacketProtectionKeys,
    packet: []u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
) Error!OpenedShortPacketView {
    return openShortPacketInPlaceWithFixedBitPolicy(
        keys,
        packet,
        destination_connection_id_len,
        expected_packet_number,
        false,
    );
}

pub fn openShortPacketInPlaceWithFixedBitPolicy(
    keys: PacketProtectionKeys,
    packet: []u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    allow_zero_fixed_bit: bool,
) Error!OpenedShortPacketView {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    if (packet.len < 1 + destination_connection_id_len + 1 + aead_tag_len or
        (packet[0] & 0x80) != 0 or
        (!allow_zero_fixed_bit and (packet[0] & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    try removeHeaderProtectionForKeys(keys, .short, packet, pn_offset);
    if ((packet[0] & 0x80) != 0 or
        (!allow_zero_fixed_bit and (packet[0] & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    try validateShortHeaderReservedBits(packet[0]);
    const spin_bit = (packet[0] & 0x20) != 0;
    const key_phase = (packet[0] & 0x04) != 0;
    const pn_len = @as(usize, (packet[0] & 0x03) + 1);
    const payload_offset = pn_offset + pn_len;
    if (packet.len < payload_offset + aead_tag_len) return error.InvalidInitialPacket;
    const packet_number = try reconstructPacketNumber(expected_packet_number, packet[pn_offset..payload_offset]);
    const payload_end = packet.len - aead_tag_len;
    const ciphertext = packet[payload_offset..payload_end];
    const tag = packet[payload_end..][0..aead_tag_len].*;
    try openPayload(
        keys,
        packet_number,
        packet[0..payload_offset],
        ciphertext,
        tag,
        ciphertext,
    );
    return .{
        .destination_connection_id = packet[1..pn_offset],
        .packet_number = packet_number,
        .fixed_bit = (packet[0] & 0x40) != 0,
        .spin_bit = spin_bit,
        .key_phase = key_phase,
        .payload = ciphertext,
    };
}

pub fn peekShortPacketKeyPhaseForPolicy(
    hp_key: [hp_key_len]u8,
    packet: []const u8,
    destination_connection_id_len: usize,
    allow_zero_fixed_bit: bool,
) Error!bool {
    return peekShortPacketKeyPhaseWithFixedBitPolicy(
        hp_key,
        packet,
        destination_connection_id_len,
        allow_zero_fixed_bit,
    );
}

pub fn openShortPacketWithKeyUpdate(
    allocator: std.mem.Allocator,
    keys: ShortPacketKeyUpdateKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
) Error!OpenedShortPacketWithKeyUpdate {
    return openShortPacketWithKeyUpdateAndFixedBitPolicy(
        allocator,
        keys,
        packet,
        destination_connection_id_len,
        expected_packet_number,
        false,
    );
}

pub fn openShortPacketWithKeyUpdateAndFixedBitPolicy(
    allocator: std.mem.Allocator,
    keys: ShortPacketKeyUpdateKeys,
    packet: []const u8,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    allow_zero_fixed_bit: bool,
) Error!OpenedShortPacketWithKeyUpdate {
    const key_phase = try peekShortPacketKeyPhaseForKeysWithFixedBitPolicy(
        keys.current,
        packet,
        destination_connection_id_len,
        allow_zero_fixed_bit,
    );
    if (key_phase == keys.current_key_phase) {
        return .{
            .packet = try openShortPacketWithFixedBitPolicy(
                allocator,
                keys.current,
                packet,
                destination_connection_id_len,
                expected_packet_number,
                allow_zero_fixed_bit,
            ),
            .peer_initiated_key_update = false,
        };
    }

    const next_packet = openShortPacketWithFixedBitPolicy(
        allocator,
        keys.next,
        packet,
        destination_connection_id_len,
        expected_packet_number,
        allow_zero_fixed_bit,
    ) catch |next_err| {
        if (next_err == error.OutOfMemory) return next_err;
        if (keys.previous) |previous| {
            if (keys.previous_key_phase) |previous_key_phase| {
                if (key_phase == previous_key_phase) {
                    return .{
                        .packet = try openShortPacketWithFixedBitPolicy(
                            allocator,
                            previous,
                            packet,
                            destination_connection_id_len,
                            expected_packet_number,
                            allow_zero_fixed_bit,
                        ),
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
    var extended = [_]u8{0} ** max_key_len;
    extended[0..hp_key_len].* = hp_key;
    const mask = headerProtectionMask(
        .aes_128_gcm_sha256,
        extended,
        sample,
    );
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
    var extended = [_]u8{0} ** max_key_len;
    extended[0..hp_key_len].* = hp_key;
    const mask = headerProtectionMask(
        .aes_128_gcm_sha256,
        extended,
        sample,
    );
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

pub fn peekShortPacketKeyPhase(
    hp_key: [hp_key_len]u8,
    packet: []const u8,
    destination_connection_id_len: usize,
) Error!bool {
    return peekShortPacketKeyPhaseWithFixedBitPolicy(
        hp_key,
        packet,
        destination_connection_id_len,
        false,
    );
}

pub fn peekShortPacketKeyPhaseWithFixedBitPolicy(
    hp_key: [hp_key_len]u8,
    packet: []const u8,
    destination_connection_id_len: usize,
    allow_zero_fixed_bit: bool,
) Error!bool {
    if (destination_connection_id_len > 20) return error.InvalidInitialPacket;
    if (packet.len < 1 + destination_connection_id_len + 1 + aead_tag_len or
        (packet[0] & 0x80) != 0 or
        (!allow_zero_fixed_bit and (packet[0] & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    const pn_offset = 1 + destination_connection_id_len;
    if (pn_offset + 4 + header_protection_sample_len > packet.len) {
        return error.InvalidHeaderProtectionSample;
    }
    const sample = packet[pn_offset + 4 ..][0..header_protection_sample_len].*;
    var extended = [_]u8{0} ** max_key_len;
    extended[0..hp_key_len].* = hp_key;
    const mask = headerProtectionMask(
        .aes_128_gcm_sha256,
        extended,
        sample,
    );
    const first = packet[0] ^ (mask[0] & 0x1f);
    if ((first & 0x80) != 0 or
        (!allow_zero_fixed_bit and (first & 0x40) == 0))
    {
        return error.InvalidInitialPacket;
    }
    try validateShortHeaderReservedBits(first);
    return (first & 0x04) != 0;
}

fn protectionProfile(version: u32) VersionError!ProtectionProfile {
    if (version == version_2_wire) {
        return .{ .salt = &initial_salt_v2, .labels = hkdf_labels_v2 };
    }
    if (version == version_1_wire) {
        return .{ .salt = &initial_salt_v1, .labels = hkdf_labels_v1 };
    }
    return error.UnsupportedVersion;
}

fn longHeaderFirstByte(
    version: u32,
    packet_type: ProtectedLongPacketType,
    packet_number_len: u8,
    fixed_bit: bool,
) u8 {
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
    return 0x80 |
        (if (fixed_bit) @as(u8, 0x40) else 0) |
        (type_bits << 4) |
        @as(u8, @intCast(packet_number_len - 1));
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

fn validateProtectedVersion(version: u32) Error!void {
    // Packet-protection salts, long-header type bits, and retry integrity keys
    // are version-specific.  Do not silently treat unknown versions as v1; the
    // endpoint Version Negotiation path handles unsupported long-header packets
    // before callers attempt to derive/open protected packets.
    if (version != version_1_wire and version != version_2_wire) return error.UnsupportedVersion;
}

fn validateLongHeaderFixedBit(first_byte: u8) Error!void {
    // The QUIC fixed bit is deliberately not masked by header protection.  Drop
    // malformed encrypted long-header packets at the packet-codec boundary just
    // like the generic long-header parser and mature stacks do, instead of
    // spending AEAD work on datagrams that cannot be valid QUIC v1/v2 packets.
    if ((first_byte & 0x40) == 0) return error.InvalidInitialPacket;
}

fn validateLongHeaderFixedBitPolicy(
    first_byte: u8,
    allow_zero_fixed_bit: bool,
) Error!void {
    if (!allow_zero_fixed_bit) try validateLongHeaderFixedBit(first_byte);
}

fn validateLongHeaderConnectionIdLen(len: usize) Error!void {
    // QUIC v1/v2 long-header packets cap both connection IDs at 20 bytes.
    // The generic parser, packet peeker, and the reference implementations
    // reject this before packet-number/header protection work; keep the
    // encrypted open paths equally strict so oversized IDs cannot bypass the
    // shared parsing invariant.
    if (len > 20) return error.InvalidInitialPacket;
}

fn validateLongHeaderProtectionSampleBounds(protected_len: usize) Error!void {
    // Header protection samples 16 bytes starting four bytes after the packet
    // number offset.  Long-header packets carry an explicit Length field, so
    // the sample must be wholly inside that packet, not borrowed from a
    // following coalesced packet in the same UDP datagram.
    if (protected_len < 4 + header_protection_sample_len) return error.InvalidHeaderProtectionSample;
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
    var truncated: [4]u8 = undefined;
    const bytes = truncated[0..packet_number_len];
    writeTruncatedPacketNumberAssumeValid(bytes, packet_number);
    try list.appendSlice(allocator, bytes);
}

/// Reconstruct a full packet number from its one-to-four-byte wire encoding.
///
/// This is public because packet codecs and focused conformance tests outside
/// this module need the RFC 9000 Appendix A.3 algorithm without duplicating it.
pub fn reconstructPacketNumber(expected_packet_number: u64, packet_number_bytes: []const u8) Error!u64 {
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

test {
    _ = @import("protection/tests.zig");
}

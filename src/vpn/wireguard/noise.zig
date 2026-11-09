//! WireGuard Noise IKpsk2 handshake state machine.
//!
//! The transcript follows the WireGuard whitepaper and wireguard-go:
//! `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, HKDF based on HMAC-BLAKE2s-256,
//! and ChaCha20-Poly1305 with an all-zero 12-byte nonce for each handshake
//! encryption. No socket or clock access happens here: timestamps, indices,
//! randomness, and monotonic milliseconds are supplied by the caller.

const std = @import("std");
const vail = @import("vail");

const blake2s = vail.crypto.blake2s;
const chacha = vail.crypto.chacha20_poly1305;
const keys = @import("keys.zig");
const message = @import("message.zig");

pub const KeyPair = keys.KeyPair;
pub const PublicKey = keys.PublicKey;
pub const SecretKey = keys.SecretKey;
pub const SessionKeys = keys.SessionKeys;
pub const KeyError = keys.KeyError;

pub const construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const psk_length = 32;
pub const psk_zero = [_]u8{0} ** psk_length;

const zero_nonce = [_]u8{0} ** chacha.nonce_length;

pub const HandshakeError = KeyError || error{
    InvalidState,
    AuthenticationFailed,
    Replay,
    Flood,
    InvalidTimestamp,
};

pub const State = enum {
    zeroed,
    initiation_created,
    initiation_consumed,
    response_created,
    response_consumed,
};

/// Result of decrypting the initiator's static key. The caller looks up the
/// peer configuration before calling `acceptInitiation`.
pub const InitiationView = struct {
    hash: [32]u8,
    chain_key: [32]u8,
    peer_static: PublicKey,

    pub fn deinit(self: *InitiationView) void {
        std.crypto.secureZero(u8, &self.hash);
        std.crypto.secureZero(u8, &self.chain_key);
        self.* = undefined;
    }
};

pub const DerivedSession = struct {
    keys: SessionKeys,
    is_initiator: bool,
    local_index: u32,
    remote_index: u32,
};

pub fn hmac(key: []const u8, parts: []const []const u8) [32]u8 {
    var ctx = blake2s.Hmac.init(key);
    for (parts) |part| ctx.update(part);
    var out: [32]u8 = undefined;
    ctx.final(&out);
    return out;
}

/// WireGuard HKDF step: PRK = HMAC(key, input); output = HMAC(PRK, 0x01).
pub fn kdf1(key: []const u8, input: []const u8) [32]u8 {
    var prk = hmac(key, &.{input});
    defer std.crypto.secureZero(u8, &prk);
    return hmac(&prk, &.{&[_]u8{0x01}});
}

pub fn kdf2(key: []const u8, input: []const u8) [2][32]u8 {
    var prk = hmac(key, &.{input});
    defer std.crypto.secureZero(u8, &prk);
    const t0 = hmac(&prk, &.{&[_]u8{0x01}});
    const t1 = hmac(&prk, &.{ &t0, &[_]u8{0x02} });
    return .{ t0, t1 };
}

pub fn kdf3(key: []const u8, input: []const u8) [3][32]u8 {
    var prk = hmac(key, &.{input});
    defer std.crypto.secureZero(u8, &prk);
    const t0 = hmac(&prk, &.{&[_]u8{0x01}});
    const t1 = hmac(&prk, &.{ &t0, &[_]u8{0x02} });
    const t2 = hmac(&prk, &.{ &t1, &[_]u8{0x03} });
    return .{ t0, t1, t2 };
}

pub fn initialChainKey() [32]u8 {
    return blake2s.hash(construction);
}

pub fn initialHash() [32]u8 {
    var chain = initialChainKey();
    defer std.crypto.secureZero(u8, &chain);
    return blake2s.hash(&chain ++ identifier);
}

fn mixHash(hash: [32]u8, data: []const u8) [32]u8 {
    return blake2s.hashParts(&.{
        @as([]const u8, &hash),
        data,
    });
}

fn encryptWithKey(
    key: [32]u8,
    ciphertext: []u8,
    tag: *[16]u8,
    plaintext: []const u8,
    associated_data: []const u8,
) void {
    var ctx = chacha.Context.init(key);
    defer ctx.deinit();
    ctx.encrypt(ciphertext, tag, plaintext, associated_data, zero_nonce);
}

fn decryptWithKey(
    key: [32]u8,
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [16]u8,
    associated_data: []const u8,
) HandshakeError!void {
    var ctx = chacha.Context.init(key);
    defer ctx.deinit();
    ctx.decrypt(plaintext, ciphertext, tag, associated_data, zero_nonce) catch
        return error.AuthenticationFailed;
}

/// Compare two TAI64N timestamps in big-endian byte order.
pub fn timestampAfter(a: [12]u8, b: [12]u8) bool {
    for (a, b) |x, y| {
        if (x > y) return true;
        if (x < y) return false;
    }
    return false;
}

/// TAI64N encoding of a Unix timestamp. `nanoseconds` is truncated to a
/// 24-bit whitened value exactly like wireguard-go.
pub fn timestampFromUnix(seconds: i64, nanoseconds: u32) [12]u8 {
    const base: u64 = 0x4000_0000_0000_000a;
    const secs = base +% @as(u64, @bitCast(seconds));
    var out: [12]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], secs, .big);
    std.mem.writeInt(u32, out[8..12], nanoseconds & 0x00ff_ffff, .big);
    return out;
}

pub const Handshake = struct {
    state: State = .zeroed,
    hash: [32]u8 = [_]u8{0} ** 32,
    chain_key: [32]u8 = [_]u8{0} ** 32,
    local_ephemeral: ?KeyPair = null,
    remote_ephemeral: PublicKey = PublicKey.fromBytes(
        [_]u8{0} ** 32,
    ),
    remote_static: PublicKey = PublicKey.fromBytes([_]u8{0} ** 32),
    psk: [psk_length]u8 = psk_zero,
    local_index: u32 = 0,
    remote_index: u32 = 0,
    last_timestamp: [12]u8 = [_]u8{0} ** 12,
    last_initiation_ms: i64 = 0,
    handshake_attempts: u8 = 0,

    pub fn init() Handshake {
        return .{};
    }

    pub fn deinit(self: *Handshake) void {
        self.reset();
    }

    pub fn reset(self: *Handshake) void {
        self.clearTranscript();
        std.crypto.secureZero(u8, &self.psk);
        self.last_timestamp = [_]u8{0} ** 12;
        self.last_initiation_ms = 0;
        self.handshake_attempts = 0;
    }

    /// Erases ephemeral transcript state while preserving the configured
    /// preshared key and replay/flood history for future handshakes.
    pub fn clearTranscript(self: *Handshake) void {
        if (self.local_ephemeral) |*pair| pair.deinit();
        std.crypto.secureZero(u8, &self.hash);
        std.crypto.secureZero(u8, &self.chain_key);
        self.local_ephemeral = null;
        self.remote_ephemeral = PublicKey.fromBytes([_]u8{0} ** 32);
        self.remote_static = PublicKey.fromBytes([_]u8{0} ** 32);
        self.local_index = 0;
        self.remote_index = 0;
        self.state = .zeroed;
    }

    pub fn setPresharedKey(self: *Handshake, psk: [psk_length]u8) void {
        self.psk = psk;
    }

    /// Creates a handshake initiation as the initiator. `identity` is the
    /// initiator's long-term key pair and `remote_static` the responder's
    /// long-term public key.
    pub fn createInitiation(
        self: *Handshake,
        rng: std.Random,
        identity: *const KeyPair,
        remote_static: PublicKey,
        timestamp: [12]u8,
        local_index: u32,
    ) HandshakeError!message.Initiation {
        // A new initiation replaces any previous partial handshake, matching
        // WireGuard's retransmission behavior.
        if (self.local_ephemeral) |*pair| pair.deinit();
        self.local_ephemeral = null;

        self.hash = initialHash();
        self.chain_key = initialChainKey();
        self.local_ephemeral = KeyPair.generate(rng);
        self.remote_static = remote_static;
        self.local_index = local_index;

        self.hash = mixHash(self.hash, &remote_static.bytes);

        var msg = message.Initiation.init();
        msg.setEphemeral(self.local_ephemeral.?.public.bytes);

        self.chain_key = kdf1(&self.chain_key, msg.ephemeral());
        self.hash = mixHash(self.hash, msg.ephemeral());

        var shared = try self.local_ephemeral.?.secret.sharedSecret(
            remote_static,
        );
        defer std.crypto.secureZero(u8, &shared);
        var kdf = kdf2(&self.chain_key, &shared);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kdf));
        self.chain_key = kdf[0];

        var tag: [16]u8 = undefined;
        encryptWithKey(
            kdf[1],
            msg.raw[message.Initiation.static_offset..][0..32],
            &tag,
            &identity.public.bytes,
            &self.hash,
        );
        msg.raw[message.Initiation.static_offset + 32 ..][0..16].* = tag;
        self.hash = mixHash(self.hash, msg.encryptedStatic());

        shared = try identity.secret.sharedSecret(remote_static);
        defer std.crypto.secureZero(u8, &shared);
        kdf = kdf2(&self.chain_key, &shared);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kdf));
        self.chain_key = kdf[0];

        encryptWithKey(
            kdf[1],
            msg.raw[message.Initiation.timestamp_offset..][0..12],
            &tag,
            &timestamp,
            &self.hash,
        );
        msg.raw[message.Initiation.timestamp_offset + 12 ..][0..16].* = tag;
        self.hash = mixHash(self.hash, msg.encryptedTimestamp());

        msg.setSender(local_index);
        self.state = .initiation_created;
        return msg;
    }

    /// Decrypts the initiator's static public key and returns the transcript
    /// state needed to verify the timestamp after peer lookup.
    pub fn decryptInitiationStatic(
        self: *Handshake,
        identity: *const KeyPair,
        msg: *const message.Initiation,
    ) HandshakeError!InitiationView {
        _ = self;
        var hash = mixHash(initialHash(), &identity.public.bytes);
        var chain_key = initialChainKey();
        hash = mixHash(hash, msg.ephemeral());
        chain_key = kdf1(&chain_key, msg.ephemeral());

        const ephemeral_public = try PublicKey.fromSlice(msg.ephemeral());
        var shared = try identity.secret.sharedSecret(ephemeral_public);
        defer std.crypto.secureZero(u8, &shared);

        var kdf = kdf2(&chain_key, &shared);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kdf));
        chain_key = kdf[0];

        var peer_static: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &peer_static);
        try decryptWithKey(
            kdf[1],
            &peer_static,
            msg.encryptedStatic()[0..32],
            msg.encryptedStatic()[32..48].*,
            &hash,
        );
        hash = mixHash(hash, msg.encryptedStatic());

        const view = InitiationView{
            .hash = hash,
            .chain_key = chain_key,
            .peer_static = PublicKey.fromBytes(peer_static),
        };
        std.crypto.secureZero(u8, &hash);
        std.crypto.secureZero(u8, &chain_key);
        return view;
    }

    /// Verifies and accepts a previously decrypted initiation. Returns the
    /// authenticated TAI64N timestamp. Rejects replayed timestamps and
    /// initiations arriving faster than the protocol's 20 ms flood limit.
    pub fn acceptInitiation(
        self: *Handshake,
        identity: *const KeyPair,
        view: *const InitiationView,
        msg: *const message.Initiation,
        now_ms: i64,
    ) HandshakeError![12]u8 {
        var shared = try identity.secret.sharedSecret(view.peer_static);
        defer std.crypto.secureZero(u8, &shared);
        var kdf = kdf2(&view.chain_key, &shared);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kdf));

        var timestamp: [12]u8 = undefined;
        defer std.crypto.secureZero(u8, &timestamp);
        try decryptWithKey(
            kdf[1],
            &timestamp,
            msg.encryptedTimestamp()[0..12],
            msg.encryptedTimestamp()[12..28].*,
            &view.hash,
        );

        if (!timestampAfter(timestamp, self.last_timestamp)) {
            return error.Replay;
        }
        if (self.last_initiation_ms != 0 and
            now_ms - self.last_initiation_ms <= 20)
        {
            return error.Flood;
        }

        const final_hash = mixHash(view.hash, msg.encryptedTimestamp());
        self.hash = final_hash;
        self.chain_key = kdf[0];
        self.remote_index = msg.sender();
        self.remote_ephemeral = try PublicKey.fromSlice(msg.ephemeral());
        self.remote_static = view.peer_static;
        self.last_timestamp = timestamp;
        self.last_initiation_ms = now_ms;
        self.state = .initiation_consumed;
        return timestamp;
    }

    /// Creates a response after an initiation has been consumed.
    pub fn createResponse(
        self: *Handshake,
        rng: std.Random,
        local_index: u32,
    ) HandshakeError!message.Response {
        if (self.state != .initiation_consumed) return error.InvalidState;
        if (self.local_ephemeral) |*pair| pair.deinit();

        self.local_ephemeral = KeyPair.generate(rng);
        self.local_index = local_index;

        var msg = message.Response.init();
        msg.setSender(local_index);
        msg.setReceiver(self.remote_index);
        msg.setEphemeral(self.local_ephemeral.?.public.bytes);

        self.hash = mixHash(self.hash, msg.ephemeral());
        self.chain_key = kdf1(&self.chain_key, msg.ephemeral());

        var shared = try self.local_ephemeral.?.secret.sharedSecret(
            self.remote_ephemeral,
        );
        defer std.crypto.secureZero(u8, &shared);
        self.chain_key = kdf1(&self.chain_key, &shared);

        shared = try self.local_ephemeral.?.secret.sharedSecret(
            self.remote_static,
        );
        defer std.crypto.secureZero(u8, &shared);
        self.chain_key = kdf1(&self.chain_key, &shared);

        var kdf = kdf3(&self.chain_key, &self.psk);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kdf));
        self.chain_key = kdf[0];
        self.hash = mixHash(self.hash, &kdf[1]);

        var tag: [16]u8 = undefined;
        encryptWithKey(kdf[2], &.{}, &tag, &.{}, &self.hash);
        msg.raw[message.Response.empty_offset..][0..16].* = tag;
        self.hash = mixHash(self.hash, msg.empty());

        self.state = .response_created;
        return msg;
    }

    /// Consumes a response as the initiator and verifies the transcript.
    pub fn consumeResponse(
        self: *Handshake,
        identity: *const KeyPair,
        msg: *const message.Response,
    ) HandshakeError!void {
        if (self.state != .initiation_created) return error.InvalidState;
        const local_ephemeral = self.local_ephemeral orelse
            return error.InvalidState;

        var hash = mixHash(self.hash, msg.ephemeral());
        var chain_key = kdf1(&self.chain_key, msg.ephemeral());

        const peer_ephemeral = try PublicKey.fromSlice(msg.ephemeral());
        var shared = try local_ephemeral.secret.sharedSecret(peer_ephemeral);
        defer std.crypto.secureZero(u8, &shared);
        chain_key = kdf1(&chain_key, &shared);

        shared = try identity.secret.sharedSecret(peer_ephemeral);
        defer std.crypto.secureZero(u8, &shared);
        chain_key = kdf1(&chain_key, &shared);

        var kdf = kdf3(&chain_key, &self.psk);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kdf));
        chain_key = kdf[0];
        hash = mixHash(hash, &kdf[1]);

        try decryptWithKey(
            kdf[2],
            &.{},
            msg.empty()[0..0],
            msg.empty()[0..16].*,
            &hash,
        );
        hash = mixHash(hash, msg.empty());

        self.hash = hash;
        self.chain_key = chain_key;
        self.remote_index = msg.sender();
        self.state = .response_consumed;

        std.crypto.secureZero(u8, &hash);
        std.crypto.secureZero(u8, &chain_key);
    }

    /// Derives transport keys after a completed handshake. The handshake
    /// transcript is erased and the state returns to `zeroed`.
    pub fn deriveSession(self: *Handshake) HandshakeError!DerivedSession {
        const result: DerivedSession = switch (self.state) {
            .response_consumed => blk: {
                const kdf = kdf2(&self.chain_key, &.{});
                break :blk .{
                    .keys = .{ .send = kdf[0], .receive = kdf[1] },
                    .is_initiator = true,
                    .local_index = self.local_index,
                    .remote_index = self.remote_index,
                };
            },
            .response_created => blk: {
                const kdf = kdf2(&self.chain_key, &.{});
                break :blk .{
                    .keys = .{ .send = kdf[1], .receive = kdf[0] },
                    .is_initiator = false,
                    .local_index = self.local_index,
                    .remote_index = self.remote_index,
                };
            },
            else => return error.InvalidState,
        };

        self.clearTranscript();
        return result;
    }
};

test "KDF matches RFC 5869 expand structure" {
    const key = [_]u8{0x0b} ** 32;
    const input = "wireguard-kdf-input";
    const prk = hmac(&key, &.{input});
    const expected_t0 = hmac(&prk, &.{&[_]u8{0x01}});
    const expected_t1 = hmac(&prk, &.{ &expected_t0, &[_]u8{0x02} });
    const actual = kdf2(&key, input);
    try std.testing.expectEqual(expected_t0, actual[0]);
    try std.testing.expectEqual(expected_t1, actual[1]);
}

test "initial hash and chain key" {
    const chain = initialChainKey();
    const expected_hash = blake2s.hash(&chain ++ identifier);
    try std.testing.expectEqual(expected_hash, initialHash());
}

test "TAI64N timestamp ordering" {
    const a = timestampFromUnix(1_700_000_000, 0);
    const b = timestampFromUnix(1_700_000_001, 0);
    try std.testing.expect(timestampAfter(b, a));
    try std.testing.expect(!timestampAfter(a, b));
    try std.testing.expect(!timestampAfter(a, a));
}

fn testKeyPair(seed: u64) KeyPair {
    var prng = std.Random.DefaultPrng.init(seed);
    return KeyPair.generate(prng.random());
}

test "full handshake derives mirrored session keys" {
    var initiator_identity = testKeyPair(1);
    defer initiator_identity.deinit();
    var responder_identity = testKeyPair(2);
    defer responder_identity.deinit();

    var psk: [psk_length]u8 = undefined;
    for (&psk, 0..) |*byte, index| byte.* = @intCast(index);
    defer std.crypto.secureZero(u8, &psk);

    var initiator_rng = std.Random.DefaultPrng.init(3);
    var responder_rng = std.Random.DefaultPrng.init(4);

    var initiator = Handshake.init();
    defer initiator.deinit();
    initiator.setPresharedKey(psk);
    var responder = Handshake.init();
    defer responder.deinit();
    responder.setPresharedKey(psk);

    const timestamp = timestampFromUnix(1_700_000_000, 1234);
    const initiation = try initiator.createInitiation(
        initiator_rng.random(),
        &initiator_identity,
        responder_identity.public,
        timestamp,
        0x1111_1111,
    );
    try std.testing.expectEqual(
        @as(usize, message.initiation_size),
        initiation.bytes().len,
    );

    var view = try responder.decryptInitiationStatic(
        &responder_identity,
        &initiation,
    );
    defer view.deinit();
    try std.testing.expect(
        view.peer_static.eql(initiator_identity.public),
    );
    const accepted = try responder.acceptInitiation(
        &responder_identity,
        &view,
        &initiation,
        10_000,
    );
    try std.testing.expectEqualSlices(u8, &timestamp, &accepted);

    const response = try responder.createResponse(
        responder_rng.random(),
        0x2222_2222,
    );
    try std.testing.expectEqual(
        @as(usize, message.response_size),
        response.bytes().len,
    );
    try std.testing.expectEqual(@as(u32, 0x1111_1111), response.receiver());

    try initiator.consumeResponse(&initiator_identity, &response);

    var initiator_session = try initiator.deriveSession();
    defer initiator_session.keys.deinit();
    var responder_session = try responder.deriveSession();
    defer responder_session.keys.deinit();

    try std.testing.expect(initiator_session.is_initiator);
    try std.testing.expect(!responder_session.is_initiator);
    try std.testing.expectEqualSlices(
        u8,
        &initiator_session.keys.send,
        &responder_session.keys.receive,
    );
    try std.testing.expectEqualSlices(
        u8,
        &initiator_session.keys.receive,
        &responder_session.keys.send,
    );
    try std.testing.expectEqual(
        @as(u32, 0x2222_2222),
        initiator_session.remote_index,
    );
    try std.testing.expectEqual(
        @as(u32, 0x1111_1111),
        responder_session.remote_index,
    );
    try std.testing.expectEqual(State.zeroed, initiator.state);
    try std.testing.expectEqual(State.zeroed, responder.state);
}

test "replayed initiation is rejected" {
    var initiator_identity = testKeyPair(11);
    defer initiator_identity.deinit();
    var responder_identity = testKeyPair(12);
    defer responder_identity.deinit();
    var psk: [psk_length]u8 = [_]u8{0x55} ** psk_length;
    defer std.crypto.secureZero(u8, &psk);

    var initiator_rng = std.Random.DefaultPrng.init(13);
    var initiator = Handshake.init();
    defer initiator.deinit();
    initiator.setPresharedKey(psk);
    var responder = Handshake.init();
    defer responder.deinit();
    responder.setPresharedKey(psk);

    const timestamp = timestampFromUnix(1_700_000_000, 0);
    const initiation = try initiator.createInitiation(
        initiator_rng.random(),
        &initiator_identity,
        responder_identity.public,
        timestamp,
        1,
    );
    var view = try responder.decryptInitiationStatic(
        &responder_identity,
        &initiation,
    );
    defer view.deinit();
    _ = try responder.acceptInitiation(
        &responder_identity,
        &view,
        &initiation,
        1000,
    );
    try std.testing.expectError(
        error.Replay,
        responder.acceptInitiation(
            &responder_identity,
            &view,
            &initiation,
            2000,
        ),
    );
}

test "initiation from the wrong static key fails to decrypt" {
    var initiator_identity = testKeyPair(21);
    defer initiator_identity.deinit();
    var responder_identity = testKeyPair(22);
    defer responder_identity.deinit();
    var other_identity = testKeyPair(23);
    defer other_identity.deinit();

    var initiator_rng = std.Random.DefaultPrng.init(24);
    var initiator = Handshake.init();
    defer initiator.deinit();
    const initiation = try initiator.createInitiation(
        initiator_rng.random(),
        &initiator_identity,
        responder_identity.public,
        timestampFromUnix(1_700_000_000, 0),
        1,
    );

    var wrong_responder = Handshake.init();
    defer wrong_responder.deinit();
    try std.testing.expectError(
        error.AuthenticationFailed,
        wrong_responder.decryptInitiationStatic(
            &other_identity,
            &initiation,
        ),
    );
}

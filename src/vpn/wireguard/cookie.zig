//! WireGuard MAC1, MAC2, and cookie replies.
//!
//! The checker lives on the receiving side and may issue cookie replies when
//! under load. The generator lives on the sending side and remembers the last
//! MAC1 so a cookie reply can be authenticated before it is trusted.

const std = @import("std");
const vail = @import("vail");

const blake2s = vail.crypto.blake2s;
const xchacha = vail.crypto.xchacha20_poly1305;
const keys = @import("keys.zig");
const message = @import("message.zig");

pub const label_mac1 = "mac1----";
pub const label_cookie = "cookie--";
pub const cookie_refresh_ms: i64 = 120_000;

pub const PublicKey = keys.PublicKey;

pub const CookieError = error{
    InvalidLength,
    AuthenticationFailed,
    SecretUnavailable,
};

fn deriveKey(label: []const u8, public_key: PublicKey) [32]u8 {
    return blake2s.hashParts(&.{
        label,
        @as([]const u8, &public_key.bytes),
    });
}

pub fn mac1Key(public_key: PublicKey) [32]u8 {
    return deriveKey(label_mac1, public_key);
}

pub fn cookieEncryptionKey(public_key: PublicKey) [32]u8 {
    return deriveKey(label_cookie, public_key);
}

/// Computes MAC1 over a handshake message excluding its final 32 bytes.
pub fn computeMac1(
    public_key: PublicKey,
    msg: []const u8,
) CookieError![16]u8 {
    if (msg.len < 32) return error.InvalidLength;
    const key = mac1Key(public_key);
    var out: [16]u8 = undefined;
    var ctx = blake2s.KeyedHash128.init(&key);
    ctx.update(msg[0 .. msg.len - 32]);
    out = ctx.final();
    return out;
}

/// Computes MAC2 over a handshake message excluding its final 16 bytes, keyed
/// by a previously obtained cookie.
pub fn computeMac2(cookie: [16]u8, msg: []const u8) CookieError![16]u8 {
    if (msg.len < 16) return error.InvalidLength;
    var out: [16]u8 = undefined;
    var ctx = blake2s.KeyedHash128.init(&cookie);
    ctx.update(msg[0 .. msg.len - 16]);
    out = ctx.final();
    return out;
}

/// Derives a source cookie from a device secret and opaque source address.
pub fn computeCookie(secret: [32]u8, source: []const u8) [16]u8 {
    return blake2s.keyedHash128(&secret, source);
}

pub const CookieChecker = struct {
    mac1_key: [32]u8,
    encryption_key: [32]u8,
    secret: [32]u8 = [_]u8{0} ** 32,
    secret_set_ms: ?i64 = null,

    pub fn init(public_key: PublicKey) CookieChecker {
        return .{
            .mac1_key = mac1Key(public_key),
            .encryption_key = cookieEncryptionKey(public_key),
        };
    }

    pub fn deinit(self: *CookieChecker) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    pub fn checkMac1(self: *const CookieChecker, msg: []const u8) bool {
        const received = computeMac1Bytes(msg) orelse return false;
        const expected = mac1FromKey(&self.mac1_key, msg) orelse return false;
        return std.crypto.timing_safe.eql([16]u8, expected, received);
    }

    pub fn checkMac2(
        self: *const CookieChecker,
        msg: []const u8,
        source: []const u8,
        now_ms: i64,
    ) bool {
        if (msg.len < 32) return false;
        const set_ms = self.secret_set_ms orelse return false;
        if (now_ms - set_ms > cookie_refresh_ms) return false;
        if (now_ms < set_ms) return false;

        const received = mac2FromBytes(msg) orelse return false;
        const cookie = computeCookie(self.secret, source);
        const expected = computeMac2(cookie, msg) catch return false;
        return std.crypto.timing_safe.eql([16]u8, expected, received);
    }

    /// Creates an encrypted cookie reply. The secret is refreshed lazily so a
    /// long-running receiver never accepts stale cookies.
    pub fn createReply(
        self: *CookieChecker,
        rng: std.Random,
        msg: []const u8,
        receiver_index: u32,
        source: []const u8,
        now_ms: i64,
    ) CookieError!message.CookieReply {
        if (msg.len < 32) return error.InvalidLength;

        if (self.secret_set_ms == null or
            now_ms - self.secret_set_ms.? > cookie_refresh_ms or
            now_ms < self.secret_set_ms.?)
        {
            rng.bytes(&self.secret);
            self.secret_set_ms = now_ms;
        }

        const cookie = computeCookie(self.secret, source);

        var reply = message.CookieReply.init();
        reply.setReceiver(receiver_index);

        var nonce: [24]u8 = undefined;
        rng.bytes(&nonce);
        reply.setNonce(nonce);

        var ctx = xchacha.Context.init(self.encryption_key);
        defer ctx.deinit();
        const mac1 = msg[msg.len - 32 ..][0..16];
        ctx.encrypt(
            reply.raw[message.CookieReply.cookie_offset..][0..16],
            reply.raw[message.CookieReply.cookie_offset + 16 ..][0..16],
            &cookie,
            mac1,
            nonce,
        );
        return reply;
    }

    fn mac1FromKey(key: *const [32]u8, msg: []const u8) ?[16]u8 {
        if (msg.len < 32) return null;
        var ctx = blake2s.KeyedHash128.init(key);
        ctx.update(msg[0 .. msg.len - 32]);
        return ctx.final();
    }

    fn mac2FromBytes(msg: []const u8) ?[16]u8 {
        if (msg.len < 16) return null;
        return msg[msg.len - 16 ..][0..16].*;
    }

    fn computeMac1Bytes(msg: []const u8) ?[16]u8 {
        if (msg.len < 32) return null;
        return msg[msg.len - 32 ..][0..16].*;
    }
};

pub const CookieGenerator = struct {
    mac1_key: [32]u8,
    encryption_key: [32]u8,
    cookie: [16]u8 = [_]u8{0} ** 16,
    cookie_set_ms: ?i64 = null,
    last_mac1: [16]u8 = [_]u8{0} ** 16,
    has_last_mac1: bool = false,

    pub fn init(public_key: PublicKey) CookieGenerator {
        return .{
            .mac1_key = mac1Key(public_key),
            .encryption_key = cookieEncryptionKey(public_key),
        };
    }

    pub fn deinit(self: *CookieGenerator) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = undefined;
    }

    /// Fills in MAC1 and, when a fresh cookie exists, MAC2. The last MAC1 is
    /// retained so a cookie reply can be authenticated.
    pub fn addMacs(self: *CookieGenerator, msg: []u8, now_ms: i64) CookieError!void {
        if (msg.len < 32) return error.InvalidLength;
        const mac1_start = msg.len - 32;

        var mac1_ctx = blake2s.KeyedHash128.init(&self.mac1_key);
        mac1_ctx.update(msg[0..mac1_start]);
        const mac1 = mac1_ctx.final();
        msg[mac1_start..][0..16].* = mac1;
        self.last_mac1 = mac1;
        self.has_last_mac1 = true;

        if (self.cookie_set_ms) |set_ms| {
            if (now_ms >= set_ms and now_ms - set_ms <= cookie_refresh_ms) {
                const mac2 = computeMac2(self.cookie, msg) catch return;
                msg[msg.len - 16 ..][0..16].* = mac2;
                return;
            }
        }
        // Never leave a stale MAC2 on a reused message buffer.
        msg[msg.len - 16 ..][0..16].* = [_]u8{0} ** 16;
    }

    /// Authenticates and installs a cookie from a cookie reply.
    pub fn consumeReply(
        self: *CookieGenerator,
        reply: *const message.CookieReply,
        now_ms: i64,
    ) CookieError!void {
        if (!self.has_last_mac1) return error.AuthenticationFailed;

        var cookie: [16]u8 = undefined;
        var ctx = xchacha.Context.init(self.encryption_key);
        defer ctx.deinit();
        ctx.decrypt(
            &cookie,
            reply.encryptedCookie()[0..16],
            reply.encryptedCookie()[16..32].*,
            &self.last_mac1,
            reply.nonce(),
        ) catch return error.AuthenticationFailed;

        self.cookie = cookie;
        self.cookie_set_ms = now_ms;
    }
};

test "MAC1 is accepted and tampering is rejected" {
    var prng = std.Random.DefaultPrng.init(1);
    const pair = keys.KeyPair.generate(prng.random());
    var checker = CookieChecker.init(pair.public);
    defer checker.deinit();
    var generator = CookieGenerator.init(pair.public);
    defer generator.deinit();

    var initiation = message.Initiation.init();
    try generator.addMacs(&initiation.raw, 1000);
    try std.testing.expect(checker.checkMac1(&initiation.raw));

    initiation.raw[10] ^= 1;
    try std.testing.expect(!checker.checkMac1(&initiation.raw));
}

test "cookie reply round trip enables MAC2" {
    var prng = std.Random.DefaultPrng.init(42);
    const receiver_pair = keys.KeyPair.generate(prng.random());

    var checker = CookieChecker.init(receiver_pair.public);
    defer checker.deinit();
    // The sender derives MAC1 and cookie encryption keys from the receiver's
    // static public key.
    var generator = CookieGenerator.init(receiver_pair.public);
    defer generator.deinit();

    const source = "192.0.2.1:51820";
    var initiation = message.Initiation.init();
    try generator.addMacs(&initiation.raw, 1000);

    const reply = try checker.createReply(
        prng.random(),
        &initiation.raw,
        initiation.sender(),
        source,
        1000,
    );
    try generator.consumeReply(&reply, 1000);

    try generator.addMacs(&initiation.raw, 1000);
    try std.testing.expect(
        checker.checkMac2(&initiation.raw, source, 1000),
    );
    try std.testing.expect(
        !checker.checkMac2(&initiation.raw, "198.51.100.9:1234", 1000),
    );

    // Cookies expire and must be refreshed.
    try std.testing.expect(
        !checker.checkMac2(
            &initiation.raw,
            source,
            1000 + cookie_refresh_ms + 1,
        ),
    );
}

test "cookie reply with wrong key fails authentication" {
    var prng = std.Random.DefaultPrng.init(43);
    const receiver_pair = keys.KeyPair.generate(prng.random());
    const sender_pair = keys.KeyPair.generate(prng.random());
    const other_pair = keys.KeyPair.generate(prng.random());

    var checker = CookieChecker.init(receiver_pair.public);
    defer checker.deinit();
    var generator = CookieGenerator.init(other_pair.public);
    defer generator.deinit();

    var initiation = message.Initiation.init();
    try generator.addMacs(&initiation.raw, 1000);
    const reply = try checker.createReply(
        prng.random(),
        &initiation.raw,
        initiation.sender(),
        "192.0.2.1:1",
        1000,
    );
    try std.testing.expectError(
        error.AuthenticationFailed,
        generator.consumeReply(&reply, 1000),
    );
    _ = sender_pair;
}

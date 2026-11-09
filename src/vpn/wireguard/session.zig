//! WireGuard transport-data protection.
//!
//! A `Keypair` owns the directional ChaCha20-Poly1305 keys and the send
//! counter for one peer. Transport packets are padded to a 16-byte multiple,
//! authenticated over the 16-byte header, and protected with a nonce formed
//! from the 64-bit counter.

const std = @import("std");
const vail = @import("vail");

const chacha = vail.crypto.chacha20_poly1305;
const message = @import("message.zig");
const noise = @import("noise.zig");
const replay = @import("replay.zig");

pub const reject_after_messages: u64 = (1 << 64) - (1 << 13) - 1;
pub const reject_after_time_ms: i64 = 180_000;
pub const rekey_after_messages: u64 = 1 << 60;
pub const rekey_after_time_ms: i64 = 120_000;

pub const TransportError = error{
    BufferTooSmall,
    InvalidLength,
    InvalidReceiver,
    CounterExhausted,
    CounterReplay,
    KeyExpired,
    AuthenticationFailed,
};

pub const Keypair = struct {
    send_key: [32]u8,
    receive_key: [32]u8,
    send_counter: u64 = 0,
    replay_filter: replay.ReplayFilter = .{},
    local_index: u32,
    remote_index: u32,
    is_initiator: bool,
    created_ms: i64,

    pub fn init(derived: noise.DerivedSession, created_ms: i64) Keypair {
        return .{
            .send_key = derived.keys.send,
            .receive_key = derived.keys.receive,
            .local_index = derived.local_index,
            .remote_index = derived.remote_index,
            .is_initiator = derived.is_initiator,
            .created_ms = created_ms,
        };
    }

    pub fn deinit(self: *Keypair) void {
        std.crypto.secureZero(u8, &self.send_key);
        std.crypto.secureZero(u8, &self.receive_key);
        self.replay_filter.reset();
        self.* = undefined;
    }

    pub fn needsRekey(self: *const Keypair, now_ms: i64) bool {
        return self.send_counter >= rekey_after_messages or
            now_ms - self.created_ms >= rekey_after_time_ms;
    }

    pub fn isExpired(self: *const Keypair, now_ms: i64) bool {
        return now_ms - self.created_ms >= reject_after_time_ms;
    }

    /// Encrypts a transport packet into `out`. Returns the number of bytes to
    /// send. `out` must have room for the padded plaintext plus the 32-byte
    /// header and tag overhead.
    pub fn encrypt(
        self: *Keypair,
        out: []u8,
        plaintext: []const u8,
    ) TransportError!usize {
        if (self.send_counter >= reject_after_messages) {
            return error.CounterExhausted;
        }
        const padded_len = message.paddedLength(plaintext.len);
        const total_len = message.transport_header_size + padded_len + 16;
        if (out.len < total_len) return error.BufferTooSmall;

        std.mem.writeInt(u32, out[0..4], 4, .little);
        std.mem.writeInt(u32, out[4..8], self.remote_index, .little);
        std.mem.writeInt(u64, out[8..16], self.send_counter, .little);

        @memcpy(out[16..][0..plaintext.len], plaintext);
        @memset(out[16 + plaintext.len ..][0 .. padded_len - plaintext.len], 0);

        var ctx = chacha.Context.init(self.send_key);
        defer ctx.deinit();
        ctx.encrypt(
            out[16..][0..padded_len],
            out[16 + padded_len ..][0..16],
            out[16..][0..padded_len],
            out[0..16],
            transportNonce(self.send_counter),
        );

        self.send_counter += 1;
        return total_len;
    }

    /// Decrypts a transport packet into `out` and returns the unpadded plaintext
    /// length. The caller knows the IP header length and should trim padding.
    pub fn decrypt(
        self: *Keypair,
        out: []u8,
        packet: []const u8,
        now_ms: i64,
    ) TransportError!usize {
        const transport = message.Transport.parse(packet) catch |err| switch (err) {
            error.InvalidLength, error.TooLarge => return error.InvalidLength,
            error.InvalidType, error.ReservedNotZero => return error.InvalidLength,
        };
        if (transport.receiver() != self.local_index) {
            return error.InvalidReceiver;
        }
        if (self.isExpired(now_ms)) return error.KeyExpired;

        const content = transport.content();
        if (content.len < 16) return error.InvalidLength;
        const ciphertext_len = content.len - 16;
        if (ciphertext_len % message.padding_multiple != 0) {
            return error.InvalidLength;
        }
        if (out.len < ciphertext_len) return error.BufferTooSmall;

        const counter = transport.counter();

        var ctx = chacha.Context.init(self.receive_key);
        defer ctx.deinit();
        ctx.decrypt(
            out[0..ciphertext_len],
            content[0..ciphertext_len],
            content[ciphertext_len..][0..16].*,
            transport.header(),
            transportNonce(counter),
        ) catch return error.AuthenticationFailed;

        // Replay state is advanced only after authentication, so forged
        // packets cannot poison the window for legitimate counters.
        if (!self.replay_filter.check(counter)) return error.CounterReplay;

        return ciphertext_len;
    }
};

pub fn transportNonce(counter: u64) [12]u8 {
    var nonce = [_]u8{0} ** 12;
    std.mem.writeInt(u64, nonce[0..8], counter, .little);
    return nonce;
}

test "transport round trip and padding" {
    var derived_a: noise.DerivedSession = .{
        .keys = .{
            .send = [_]u8{0x10} ** 32,
            .receive = [_]u8{0x20} ** 32,
        },
        .is_initiator = true,
        .local_index = 7,
        .remote_index = 9,
    };
    var derived_b: noise.DerivedSession = .{
        .keys = .{
            .send = [_]u8{0x20} ** 32,
            .receive = [_]u8{0x10} ** 32,
        },
        .is_initiator = false,
        .local_index = 9,
        .remote_index = 7,
    };
    var sender = Keypair.init(derived_a, 1000);
    defer sender.deinit();
    var receiver = Keypair.init(derived_b, 1000);
    defer receiver.deinit();
    derived_a.keys.deinit();
    derived_b.keys.deinit();

    const text = "hello wireguard";
    var payload: [48]u8 = [_]u8{0} ** 48;
    @memcpy(payload[0..text.len], text);
    var packet: [16 + 64 + 16]u8 = undefined;
    const packet_len = try sender.encrypt(&packet, &payload);
    try std.testing.expectEqual(
        @as(usize, 16 + message.paddedLength(payload.len) + 16),
        packet_len,
    );

    var plaintext: [64]u8 = undefined;
    const plaintext_len = try receiver.decrypt(
        &plaintext,
        packet[0..packet_len],
        1000,
    );
    try std.testing.expectEqual(message.paddedLength(payload.len), plaintext_len);
    try std.testing.expectEqualSlices(u8, &payload, plaintext[0..payload.len]);
    for (plaintext[payload.len..plaintext_len]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "keepalive is a 32-byte transport message" {
    var sender = Keypair{
        .send_key = [_]u8{1} ** 32,
        .receive_key = [_]u8{2} ** 32,
        .local_index = 1,
        .remote_index = 2,
        .is_initiator = true,
        .created_ms = 0,
    };
    defer sender.deinit();
    var packet: [64]u8 = undefined;
    const len = try sender.encrypt(&packet, &.{});
    try std.testing.expectEqual(message.keepalive_size, len);
}

test "replay, tampering, and receiver mismatch are rejected" {
    var sender = Keypair{
        .send_key = [_]u8{0xaa} ** 32,
        .receive_key = [_]u8{0xbb} ** 32,
        .local_index = 5,
        .remote_index = 6,
        .is_initiator = true,
        .created_ms = 0,
    };
    defer sender.deinit();
    var receiver = Keypair{
        .send_key = [_]u8{0xbb} ** 32,
        .receive_key = [_]u8{0xaa} ** 32,
        .local_index = 6,
        .remote_index = 5,
        .is_initiator = false,
        .created_ms = 0,
    };
    defer receiver.deinit();

    var packet: [128]u8 = undefined;
    const len = try sender.encrypt(&packet, "payload");
    var plaintext: [64]u8 = undefined;
    _ = try receiver.decrypt(&plaintext, packet[0..len], 0);
    try std.testing.expectError(
        error.CounterReplay,
        receiver.decrypt(&plaintext, packet[0..len], 0),
    );

    // A fresh counter reaches authentication before being rejected.
    var tamper_packet: [128]u8 = undefined;
    const tamper_len = try sender.encrypt(&tamper_packet, "payload");
    tamper_packet[20] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        receiver.decrypt(&plaintext, tamper_packet[0..tamper_len], 0),
    );

    // Rebuild a packet for the wrong receiver index.
    var other: [128]u8 = undefined;
    const len2 = try sender.encrypt(&other, "payload");
    other[4] ^= 0xff;
    try std.testing.expectError(
        error.InvalidReceiver,
        receiver.decrypt(&plaintext, other[0..len2], 0),
    );
}

test "expired keypair is rejected" {
    var sender = Keypair{
        .send_key = [_]u8{1} ** 32,
        .receive_key = [_]u8{2} ** 32,
        .local_index = 1,
        .remote_index = 2,
        .is_initiator = true,
        .created_ms = 0,
    };
    defer sender.deinit();
    var receiver = Keypair{
        .send_key = [_]u8{2} ** 32,
        .receive_key = [_]u8{1} ** 32,
        .local_index = 2,
        .remote_index = 1,
        .is_initiator = false,
        .created_ms = 0,
    };
    defer receiver.deinit();
    var packet: [64]u8 = undefined;
    _ = try sender.encrypt(&packet, &.{});
    var out: [32]u8 = undefined;
    try std.testing.expectError(
        error.KeyExpired,
        receiver.decrypt(&out, packet[0..32], reject_after_time_ms),
    );
}

test "nonce layout" {
    const nonce = transportNonce(0x0102_0304_0506_0708);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0 },
        &nonce,
    );
}

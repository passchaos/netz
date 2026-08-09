//! Stateless TLS 1.3 ticket sealing with bounded key rotation.
//!
//! Wire identities carry an authenticated key identifier and nonce, so open is
//! O(1) for the current key and O(history) only across the small retained key
//! set. Origin and ALPN are AEAD associated data, preventing ticket replay
//! across application security contexts without storing every issued ticket.

const std = @import("std");
const codec = @import("vail").tls.ticket;

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
pub const key_len = Aes256Gcm.key_length;
pub const nonce_len = Aes256Gcm.nonce_length;
pub const tag_len = Aes256Gcm.tag_length;
pub const max_keys = 4;
const format_version: u8 = 1;
const header_len = 1 + @sizeOf(u32) + nonce_len;
const plaintext_len = @sizeOf(u64) + @sizeOf(u32) + @sizeOf(u32) + 32;
pub const sealed_len = header_len + plaintext_len + tag_len;

pub const Error = error{
    InvalidKeyId,
    DuplicateKeyId,
    InvalidContext,
    InvalidTicket,
    ExpiredTicket,
    UnknownKey,
    AuthenticationFailed,
    InvalidTicketLifetime,
};

pub const Key = struct {
    id: u32,
    secret: [key_len]u8,
};

pub const Opened = struct {
    secret: [32]u8,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
};

pub const Keyring = struct {
    keys: [max_keys]Key = undefined,
    len: usize = 0,

    pub fn init(current: Key) Error!Keyring {
        try validateKey(current);
        var result = Keyring{};
        result.keys[0] = current;
        result.len = 1;
        return result;
    }

    pub fn deinit(self: *Keyring) void {
        for (self.keys[0..self.len]) |*key| {
            std.crypto.secureZero(u8, &key.secret);
        }
        self.* = undefined;
    }

    pub fn rotate(self: *Keyring, next: Key) Error!void {
        try validateKey(next);
        for (self.keys[0..self.len]) |key| {
            if (key.id == next.id) return error.DuplicateKeyId;
        }
        const retained: usize = @min(self.len, @as(usize, max_keys - 1));
        if (self.len == max_keys) {
            // Wipe the evicted oldest secret before its slot is overwritten.
            std.crypto.secureZero(u8, &self.keys[max_keys - 1].secret);
        }
        std.mem.copyBackwards(
            Key,
            self.keys[1 .. retained + 1],
            self.keys[0..retained],
        );
        self.keys[0] = next;
        self.len = retained + 1;
    }

    pub fn currentId(self: *const Keyring) u32 {
        return self.keys[0].id;
    }

    pub fn seal(
        self: *const Keyring,
        nonce: [nonce_len]u8,
        server_id: []const u8,
        alpn: []const u8,
        opened: Opened,
    ) Error![sealed_len]u8 {
        try validateContext(server_id, alpn);
        try validateOpened(opened);
        const current = &self.keys[0];

        var output: [sealed_len]u8 = undefined;
        output[0] = format_version;
        std.mem.writeInt(u32, output[1..5], current.id, .big);
        @memcpy(output[5..header_len], &nonce);

        var plaintext: [plaintext_len]u8 = undefined;
        std.mem.writeInt(u64, plaintext[0..8], opened.issued_at_ms, .big);
        std.mem.writeInt(u32, plaintext[8..12], opened.lifetime_seconds, .big);
        std.mem.writeInt(u32, plaintext[12..16], opened.age_add, .big);
        @memcpy(plaintext[16..], &opened.secret);
        defer std.crypto.secureZero(u8, &plaintext);

        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        Aes256Gcm.encrypt(
            output[header_len .. header_len + plaintext_len],
            output[header_len + plaintext_len ..][0..tag_len],
            &plaintext,
            aad[0..aad_len],
            nonce,
            current.secret,
        );
        return output;
    }

    pub fn open(
        self: *const Keyring,
        identity: []const u8,
        server_id: []const u8,
        alpn: []const u8,
        now_ms: u64,
    ) Error!Opened {
        try validateContext(server_id, alpn);
        if (identity.len != sealed_len or identity[0] != format_version) {
            return error.InvalidTicket;
        }
        const key_id = std.mem.readInt(u32, identity[1..5], .big);
        const key = self.find(key_id) orelse return error.UnknownKey;
        const nonce = identity[5..header_len][0..nonce_len].*;
        const ciphertext = identity[header_len .. header_len + plaintext_len];
        const tag = identity[header_len + plaintext_len ..][0..tag_len].*;

        var aad: [512]u8 = undefined;
        const aad_len = try writeContext(&aad, server_id, alpn);
        var plaintext: [plaintext_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        Aes256Gcm.decrypt(
            &plaintext,
            ciphertext,
            tag,
            aad[0..aad_len],
            nonce,
            key.secret,
        ) catch return error.AuthenticationFailed;

        const opened = Opened{
            .issued_at_ms = std.mem.readInt(u64, plaintext[0..8], .big),
            .lifetime_seconds = std.mem.readInt(u32, plaintext[8..12], .big),
            .age_add = std.mem.readInt(u32, plaintext[12..16], .big),
            .secret = plaintext[16..][0..32].*,
        };
        try validateOpened(opened);
        if (now_ms < opened.issued_at_ms) return error.ExpiredTicket;
        const lifetime_ms = @as(u64, opened.lifetime_seconds) *
            std.time.ms_per_s;
        if (now_ms - opened.issued_at_ms > lifetime_ms) {
            return error.ExpiredTicket;
        }
        return opened;
    }

    fn find(self: *const Keyring, id: u32) ?*const Key {
        for (self.keys[0..self.len]) |*key| {
            if (key.id == id) return key;
        }
        return null;
    }
};

fn validateKey(key: Key) Error!void {
    if (key.id == 0) return error.InvalidKeyId;
}

fn validateOpened(opened: Opened) Error!void {
    if (opened.lifetime_seconds == 0 or
        opened.lifetime_seconds > codec.max_lifetime_seconds)
    {
        return error.InvalidTicketLifetime;
    }
}

fn validateContext(server_id: []const u8, alpn: []const u8) Error!void {
    if (server_id.len == 0 or alpn.len == 0 or
        server_id.len > std.math.maxInt(u16) or
        alpn.len > std.math.maxInt(u8))
    {
        return error.InvalidContext;
    }
    if (2 + server_id.len + 1 + alpn.len > 512) {
        return error.InvalidContext;
    }
}

fn writeContext(
    output: *[512]u8,
    server_id: []const u8,
    alpn: []const u8,
) Error!usize {
    try validateContext(server_id, alpn);
    std.mem.writeInt(u16, output[0..2], @intCast(server_id.len), .big);
    @memcpy(output[2 .. 2 + server_id.len], server_id);
    const alpn_len_offset = 2 + server_id.len;
    output[alpn_len_offset] = @intCast(alpn.len);
    @memcpy(output[alpn_len_offset + 1 ..][0..alpn.len], alpn);
    return alpn_len_offset + 1 + alpn.len;
}

//! QUIC-LB encrypted routing-block transform from draft-ietf-quic-load-balancers-21.
//!
//! A 16-byte routing block uses one AES-128-ECB operation. Every other
//! permitted size uses the draft's four-round Feistel construction, including
//! its nibble split for odd byte lengths.

const std = @import("std");

const Aes128 = std.crypto.core.aes.Aes128;

pub const Error = error{InvalidRoutingBlockLength};

pub fn encrypt(key: [16]u8, routing_block: []u8) Error!void {
    try validateLength(routing_block.len);
    if (routing_block.len == 16) {
        var input: [16]u8 = routing_block[0..16].*;
        Aes128.initEnc(key).encrypt(routing_block[0..16], &input);
        return;
    }

    var left: [10]u8 = undefined;
    var right: [10]u8 = undefined;
    const half_len = split(routing_block, &left, &right);
    const odd = (routing_block.len & 1) != 0;

    xorRound(key, right[0..half_len], left[0..half_len], routing_block.len, 1);
    if (odd) right[0] &= 0x0f;
    xorRound(key, left[0..half_len], right[0..half_len], routing_block.len, 2);
    if (odd) left[half_len - 1] &= 0xf0;
    xorRound(key, right[0..half_len], left[0..half_len], routing_block.len, 3);
    if (odd) right[0] &= 0x0f;
    xorRound(key, left[0..half_len], right[0..half_len], routing_block.len, 4);
    if (odd) left[half_len - 1] &= 0xf0;

    join(routing_block, left[0..half_len], right[0..half_len]);
}

pub fn decodeServerId(
    key: [16]u8,
    encrypted_routing_block: []const u8,
    server_id_len: usize,
    out: []u8,
) Error!void {
    try validateLength(encrypted_routing_block.len);
    if (server_id_len == 0 or
        server_id_len >= encrypted_routing_block.len or
        out.len < server_id_len)
    {
        return error.InvalidRoutingBlockLength;
    }
    if (encrypted_routing_block.len == 16) {
        var plaintext: [16]u8 = undefined;
        Aes128.initDec(key).decrypt(
            &plaintext,
            encrypted_routing_block[0..16],
        );
        @memcpy(out[0..server_id_len], plaintext[0..server_id_len]);
        return;
    }

    var left: [10]u8 = undefined;
    var right: [10]u8 = undefined;
    const half_len = split(encrypted_routing_block, &left, &right);
    const odd = (encrypted_routing_block.len & 1) != 0;

    xorRound(
        key,
        left[0..half_len],
        right[0..half_len],
        encrypted_routing_block.len,
        4,
    );
    if (odd) left[half_len - 1] &= 0xf0;
    xorRound(
        key,
        right[0..half_len],
        left[0..half_len],
        encrypted_routing_block.len,
        3,
    );
    if (odd) right[0] &= 0x0f;
    xorRound(
        key,
        left[0..half_len],
        right[0..half_len],
        encrypted_routing_block.len,
        2,
    );
    if (odd) left[half_len - 1] &= 0xf0;

    const nonce_len = encrypted_routing_block.len - server_id_len;
    if (nonce_len >= server_id_len) {
        // The server ID is entirely contained in left_0. Load balancers can
        // route after only three AES operations, as allowed by Section 5.5.2.
        @memcpy(out[0..server_id_len], left[0..server_id_len]);
        return;
    }

    xorRound(
        key,
        right[0..half_len],
        left[0..half_len],
        encrypted_routing_block.len,
        1,
    );
    if (odd) right[0] &= 0x0f;

    var plaintext: [19]u8 = undefined;
    join(
        plaintext[0..encrypted_routing_block.len],
        left[0..half_len],
        right[0..half_len],
    );
    @memcpy(out[0..server_id_len], plaintext[0..server_id_len]);
}

fn validateLength(len: usize) Error!void {
    // One server-ID byte plus the minimum four-byte nonce establishes the
    // lower bound; QUIC v1's 20-byte CID limit leaves 19 routing-block bytes.
    if (len < 5 or len > 19) return error.InvalidRoutingBlockLength;
}

fn split(
    input: []const u8,
    left: *[10]u8,
    right: *[10]u8,
) usize {
    const half_len = (input.len + 1) / 2;
    if ((input.len & 1) == 0) {
        @memcpy(left[0..half_len], input[0..half_len]);
        @memcpy(right[0..half_len], input[half_len..]);
        return half_len;
    }

    // The center byte is shared across the halves. The low nibble belongs to
    // the right half and the high nibble to the left half.
    @memcpy(left[0 .. half_len - 1], input[0 .. half_len - 1]);
    left[half_len - 1] = input[half_len - 1] & 0xf0;
    right[0] = input[half_len - 1] & 0x0f;
    @memcpy(right[1..half_len], input[half_len..]);
    return half_len;
}

fn join(output: []u8, left: []const u8, right: []const u8) void {
    if ((output.len & 1) == 0) {
        @memcpy(output[0..left.len], left);
        @memcpy(output[left.len..], right);
        return;
    }

    @memcpy(output[0 .. left.len - 1], left[0 .. left.len - 1]);
    output[left.len - 1] = (left[left.len - 1] & 0xf0) |
        (right[0] & 0x0f);
    @memcpy(output[left.len..], right[1..]);
}

fn xorRound(
    key: [16]u8,
    target: []u8,
    input: []const u8,
    routing_block_len: usize,
    pass: u8,
) void {
    var expanded = [_]u8{0} ** 16;
    @memcpy(expanded[0..input.len], input);
    expanded[14] = @intCast(routing_block_len);
    expanded[15] = pass;

    var encrypted: [16]u8 = undefined;
    Aes128.initEnc(key).encrypt(&encrypted, &expanded);
    for (target, encrypted[0..target.len]) |*byte, mask| byte.* ^= mask;
}

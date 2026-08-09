//! Routable QUIC Connection IDs following draft-ietf-quic-load-balancers-21.
//!
//! Generation is deterministic over caller-provided nonce/first-octet entropy.
//! Runtimes remain responsible for cryptographically random or non-repeating
//! nonce generation, while codec tests and load balancers can use exact vectors.

const std = @import("std");
const cipher = @import("cipher.zig");

pub const max_connection_id_len: usize = 20;
pub const max_server_id_len: usize = 15;
pub const min_nonce_len: usize = 4;
pub const max_routing_block_len: usize = max_connection_id_len - 1;
pub const unroutable_config_rotation: u3 = 0b111;

pub const Error = error{
    ReservedConfigRotation,
    InvalidServerIdLength,
    InvalidNonceLength,
    ConnectionIdTooLong,
    BufferTooShort,
    InvalidConnectionIdLength,
    ConfigRotationMismatch,
};

/// The algorithm is pinned so callers can audit deployed configuration
/// compatibility as the draft evolves before standardization.
pub const specification = "draft-ietf-quic-load-balancers-21";

pub const Config = struct {
    config_rotation: u3,
    server_id_len: u8,
    nonce_len: u8,
    key: ?[16]u8 = null,
    self_encoded_length: bool = true,

    pub fn validate(self: Config) Error!void {
        if (self.config_rotation == unroutable_config_rotation) {
            return error.ReservedConfigRotation;
        }
        if (self.server_id_len == 0 or
            self.server_id_len > max_server_id_len)
        {
            return error.InvalidServerIdLength;
        }
        if (self.nonce_len < min_nonce_len) return error.InvalidNonceLength;
        const routing_len = @as(usize, self.server_id_len) +
            @as(usize, self.nonce_len);
        if (routing_len > max_routing_block_len) {
            return error.ConnectionIdTooLong;
        }
    }

    pub fn connectionIdLen(self: Config) Error!usize {
        try self.validate();
        return 1 + @as(usize, self.server_id_len) +
            @as(usize, self.nonce_len);
    }
};

/// Generate one CID into caller storage and return the initialized prefix.
///
/// When length self-description is disabled, `first_octet_random_bits` fills
/// the low five bits. It must therefore come from the same unlinkable entropy
/// source as the nonce rather than a per-connection counter.
pub fn encode(
    config: Config,
    server_id: []const u8,
    nonce: []const u8,
    first_octet_random_bits: u5,
    out: []u8,
) Error![]u8 {
    return encodeWithServerUse(
        config,
        server_id,
        nonce,
        &.{},
        first_octet_random_bits,
        out,
    );
}

/// Generate a CID with optional server-use bytes appended after the routing
/// block. Draft-21 requires every server under a configuration to append the
/// same number of unlinkable bytes; enforcing that deployment-wide invariant
/// remains the configuration agent's responsibility.
pub fn encodeWithServerUse(
    config: Config,
    server_id: []const u8,
    nonce: []const u8,
    server_use: []const u8,
    first_octet_random_bits: u5,
    out: []u8,
) Error![]u8 {
    const routing_cid_len = try config.connectionIdLen();
    const cid_len = std.math.add(
        usize,
        routing_cid_len,
        server_use.len,
    ) catch return error.ConnectionIdTooLong;
    if (cid_len > max_connection_id_len) return error.ConnectionIdTooLong;
    if (server_id.len != config.server_id_len) {
        return error.InvalidServerIdLength;
    }
    if (nonce.len != config.nonce_len) return error.InvalidNonceLength;
    if (out.len < cid_len) return error.BufferTooShort;

    const low_bits: u8 = if (config.self_encoded_length)
        @intCast(cid_len - 1)
    else
        first_octet_random_bits;
    out[0] = (@as(u8, config.config_rotation) << 5) | low_bits;
    @memcpy(out[1 .. 1 + server_id.len], server_id);
    const routing_end = routing_cid_len;
    @memcpy(out[1 + server_id.len .. routing_end], nonce);
    // Config validation proves the routing block is within cipher bounds.
    if (config.key) |key| {
        cipher.encrypt(key, out[1..routing_end]) catch unreachable;
    }
    @memcpy(out[routing_end..cid_len], server_use);
    return out[0..cid_len];
}

/// Extract the server ID into caller storage. The load balancer need not retain
/// nonce bytes and this API never allocates.
pub fn decodeServerId(
    config: Config,
    connection_id: []const u8,
    out: []u8,
) Error![]u8 {
    const routing_cid_len = try config.connectionIdLen();
    if (connection_id.len < routing_cid_len) return error.BufferTooShort;
    if (connection_id.len > max_connection_id_len) {
        return error.ConnectionIdTooLong;
    }
    if (extractConfigRotation(connection_id[0]) != config.config_rotation) {
        return error.ConfigRotationMismatch;
    }
    if (config.self_encoded_length and
        encodedConnectionIdLen(connection_id[0]) != connection_id.len)
    {
        return error.InvalidConnectionIdLength;
    }
    if (out.len < config.server_id_len) return error.BufferTooShort;

    if (config.key) |key| {
        cipher.decodeServerId(
            key,
            connection_id[1..routing_cid_len],
            config.server_id_len,
            out,
        ) catch unreachable;
    } else {
        @memcpy(out[0..config.server_id_len], connection_id[1..][0..config.server_id_len]);
    }
    return out[0..config.server_id_len];
}

pub fn extractConfigRotation(first_octet: u8) u3 {
    return @intCast(first_octet >> 5);
}

/// Decode the CID length when the configuration enables self-description.
pub fn encodedConnectionIdLen(first_octet: u8) usize {
    return @as(usize, first_octet & 0x1f) + 1;
}

test {
    _ = @import("tests.zig");
}

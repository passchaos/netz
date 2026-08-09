//! Integrated server-side QUIC Retry policy.
//!
//! The policy owns no connection state. `handshake.accept` retains the first
//! Initial's ODCID while waiting for the retried Initial; this module only
//! validates configuration, supplies secure nonce entropy, and emits the Retry
//! datagram through the shared Retry/token implementation.

const std = @import("std");
const quic = @import("../mod.zig");

pub const Policy = struct {
    secret: quic.address_validation_token.Secret,
    peer_address: []const u8,
    issued_ns: i64,
    lifetime_ns: u64,
    /// Token validation time when the retried Initial returns. Defaults to
    /// `issued_ns` for synchronous callers.
    validation_now_ns: ?i64 = null,
    /// Defaults to ServerOptions.local_connection_id. A distinct value is
    /// useful when endpoint routing allocates a dedicated CID for Retry.
    source_connection_id: []const u8 = &.{},
    /// Deterministic override for tests or caller-owned entropy providers.
    /// Production callers normally leave this null.
    nonce: ?quic.address_validation_token.Nonce = null,
};

pub const Prepared = struct {
    datagram: []u8,
    source_connection_id: []const u8,
};

pub const InitialResponseFilter = struct {
    allocator: std.mem.Allocator,
    version: quic.Version,
    original_destination_connection_id: []const u8,
    initial_source_connection_id: []const u8,
    retry_already_processed: bool,

    pub fn accept(context: *anyopaque, bytes: []const u8) bool {
        const self: *const InitialResponseFilter =
            @ptrCast(@alignCast(context));
        if (isVersionNegotiationDatagram(bytes)) return true;
        if (quic.protection.peekProtectedLongPacketInfo(bytes)) |info| {
            return info.version == self.version.wireValue() and
                info.packet_type == .initial and
                std.mem.eql(
                    u8,
                    info.destination_connection_id,
                    self.initial_source_connection_id,
                );
        } else |_| {}
        if (self.retry_already_processed) return false;
        _ = quic.retry_flow.validateClientPacket(
            self.allocator,
            .{
                .version = self.version,
                .original_destination_connection_id = self.original_destination_connection_id,
                .initial_source_connection_id = self.initial_source_connection_id,
            },
            bytes,
        ) catch return false;
        return true;
    }
};

fn isVersionNegotiationDatagram(bytes: []const u8) bool {
    return bytes.len >= 5 and
        (bytes[0] & 0x80) != 0 and
        std.mem.readInt(u32, bytes[1..5], .big) ==
            quic.Version.negotiation.wireValue();
}

pub fn prepare(
    allocator: std.mem.Allocator,
    io: std.Io,
    policy: Policy,
    default_source_connection_id: []const u8,
    original_destination_connection_id: []const u8,
    client_source_connection_id: []const u8,
) (quic.retry_flow.Error || std.Io.RandomSecureError)!Prepared {
    if (policy.peer_address.len == 0 or
        policy.lifetime_ns == 0)
    {
        return error.InvalidToken;
    }
    const source_connection_id = if (policy.source_connection_id.len != 0)
        policy.source_connection_id
    else
        default_source_connection_id;
    if (source_connection_id.len == 0 or source_connection_id.len > 20) {
        return error.InvalidConnectionIdLength;
    }
    var nonce = policy.nonce orelse random: {
        var generated: quic.address_validation_token.Nonce = undefined;
        try std.Io.randomSecure(io, &generated);
        break :random generated;
    };
    defer std.crypto.secureZero(u8, &nonce);
    return .{
        .datagram = try quic.retry_flow.issue(allocator, .{
            .original_destination_connection_id = original_destination_connection_id,
            .client_source_connection_id = client_source_connection_id,
            .retry_source_connection_id = source_connection_id,
            .peer_address = policy.peer_address,
            .issued_ns = policy.issued_ns,
            .lifetime_ns = policy.lifetime_ns,
            .nonce = nonce,
            .secret = policy.secret,
        }),
        .source_connection_id = source_connection_id,
    };
}

test "integrated Retry policy defaults to the server connection ID" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    const odcid = "original";
    const client_scid = "client";
    const server_scid = "server";
    const prepared = try prepare(
        allocator,
        threaded.io(),
        .{
            .secret = [_]u8{0x31} **
                quic.address_validation_token.secret_len,
            .peer_address = "path",
            .issued_ns = 100,
            .lifetime_ns = 1_000,
            .nonce = [_]u8{0x32} **
                quic.address_validation_token.nonce_len,
        },
        server_scid,
        odcid,
        client_scid,
    );
    defer allocator.free(prepared.datagram);
    try std.testing.expectEqualStrings(
        server_scid,
        prepared.source_connection_id,
    );
    const packet = try quic.parseRetryPacket(prepared.datagram);
    try std.testing.expectEqualStrings(
        server_scid,
        packet.source_connection_id,
    );
}

//! Integrated server-side QUIC Retry policy.
//!
//! The policy owns no connection state. `handshake.accept` retains the first
//! Initial's ODCID while waiting for the retried Initial; this module only
//! validates configuration, supplies secure nonce entropy, and emits the Retry
//! datagram through the shared Retry/token implementation.

const std = @import("std");
const quic = @import("../mod.zig");

pub const Policy = struct {
    version: quic.Version = .version_1,
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

pub const PreparedInto = struct {
    datagram: []const u8,
    source_connection_id: []const u8,
};

pub const InitialResponseFilter = struct {
    allocator: std.mem.Allocator,
    version: quic.Version,
    original_destination_connection_id: []const u8,
    initial_source_connection_id: []const u8,
    initial_keys: quic.protection.PacketProtectionKeys,
    retry_already_processed: bool,
    allow_zero_fixed_bit: bool = false,

    pub fn accept(context: *anyopaque, bytes: []const u8) bool {
        const self: *const InitialResponseFilter =
            @ptrCast(@alignCast(context));
        if (isVersionNegotiationDatagram(bytes)) return true;
        if (quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
            bytes,
            self.allow_zero_fixed_bit,
        )) |info| {
            if (info.version == self.version.wireValue() and
                info.packet_type == .initial and
                std.mem.eql(
                    u8,
                    info.destination_connection_id,
                    self.initial_source_connection_id,
                ))
            {
                return self.initialContainsCryptoOffsetZero(bytes[0..info.len]);
            }
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

    /// A peer can acknowledge a later fragment of a split ClientHello without
    /// having received CRYPTO offset zero. Such an ACK-only Initial proves the
    /// path is alive but cannot advance TLS; keeping it inside the PTO loop
    /// causes the complete ClientHello flight to be retransmitted.
    fn initialContainsCryptoOffsetZero(
        self: *const InitialResponseFilter,
        bytes: []const u8,
    ) bool {
        var packet = quic.protection.openInitialPacketWithFixedBitPolicy(
            self.allocator,
            self.initial_keys,
            bytes,
            0,
            self.allow_zero_fixed_bit,
        ) catch return false;
        defer packet.deinit(self.allocator);

        var offset: usize = 0;
        while (offset < packet.payload.len) {
            var parsed = quic.parseFrameOwned(
                self.allocator,
                packet.payload[offset..],
            ) catch return false;
            defer parsed.deinitOwned(self.allocator);
            // A valid Initial close terminates the attempt even though it
            // carries no CRYPTO offset zero. Authentication failures still
            // remain inside the PTO loop above.
            if (parsed.frame == .connection_close) return true;
            if (parsed.frame == .crypto and
                parsed.frame.crypto.offset == 0 and
                parsed.frame.crypto.data.len != 0)
            {
                return true;
            }
            offset += parsed.consumed;
        }
        return false;
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
    var storage: [quic.retry_flow.max_datagram_len]u8 = undefined;
    const prepared = try prepareInto(
        &storage,
        io,
        policy,
        default_source_connection_id,
        original_destination_connection_id,
        client_source_connection_id,
    );
    return .{
        .datagram = try allocator.dupe(u8, prepared.datagram),
        .source_connection_id = prepared.source_connection_id,
    };
}

/// Prepare Retry in caller-owned storage so the integrated server can send it
/// directly without allocating a short-lived datagram.
pub fn prepareInto(
    storage: []u8,
    io: std.Io,
    policy: Policy,
    default_source_connection_id: []const u8,
    original_destination_connection_id: []const u8,
    client_source_connection_id: []const u8,
) (quic.retry_flow.Error || std.Io.RandomSecureError)!PreparedInto {
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
        .datagram = try quic.retry_flow.issueInto(storage, .{
            .version = policy.version,
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

    var direct_storage: [quic.retry_flow.max_datagram_len]u8 = undefined;
    const direct = try prepareInto(
        &direct_storage,
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
    try std.testing.expectEqualSlices(u8, prepared.datagram, direct.datagram);
    try std.testing.expectEqualStrings(server_scid, direct.source_connection_id);

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const verified = try quic.retry_flow.validate(
        no_alloc.allocator(),
        .{
            .original_destination_connection_id = odcid,
            .peer_address = "path",
            .now_ns = 100,
            .secret = [_]u8{0x31} **
                quic.address_validation_token.secret_len,
        },
        direct.datagram,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(
        server_scid,
        verified.packet.source_connection_id,
    );
}

test "integrated Retry policy preserves the negotiated QUIC version" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var storage: [quic.retry_flow.max_datagram_len]u8 = undefined;
    const prepared = try prepareInto(
        &storage,
        threaded.io(),
        .{
            .version = .version_2,
            .secret = [_]u8{0x41} **
                quic.address_validation_token.secret_len,
            .peer_address = "client-path",
            .issued_ns = 1_000,
            .lifetime_ns = 5_000,
            .nonce = [_]u8{0x42} **
                quic.address_validation_token.nonce_len,
        },
        "server",
        "original",
        "client",
    );
    const packet = try quic.parseRetryPacket(prepared.datagram);
    try std.testing.expectEqual(
        quic.Version.version_2.wireValue(),
        packet.version,
    );
    try std.testing.expect(try quic.verifyRetryIntegrityTag(
        std.testing.allocator,
        "original",
        prepared.datagram,
    ));
}

test "client Initial response filter requires CRYPTO offset zero in v1 and v2" {
    const allocator = std.testing.allocator;
    const original_dcid = "original";
    const client_scid = "client";
    const server_scid = "server";

    inline for (.{ quic.Version.version_1, quic.Version.version_2 }) |version| {
        const server_keys = (try quic.protection.deriveInitialSecretsForVersion(
            version.wireValue(),
            original_dcid,
        )).server;
        var filter = InitialResponseFilter{
            .allocator = allocator,
            .version = version,
            .original_destination_connection_id = original_dcid,
            .initial_source_connection_id = client_scid,
            .initial_keys = server_keys,
            .retry_already_processed = false,
        };

        const ack_payload = [_]u8{
            @intFromEnum(quic.FrameType.ack),
            0,
            0,
            0,
            0,
        };
        const ack_packet = try quic.protection.sealInitialPacket(
            allocator,
            server_keys,
            .{
                .version = version.wireValue(),
                .destination_connection_id = client_scid,
                .source_connection_id = server_scid,
                .packet_number = 0,
                .payload = &ack_payload,
            },
        );
        defer allocator.free(ack_packet);
        try std.testing.expect(!InitialResponseFilter.accept(
            &filter,
            ack_packet,
        ));

        var crypto_payload: std.ArrayList(u8) = .empty;
        defer crypto_payload.deinit(allocator);
        try quic.crypto_stream.writeCryptoFrames(
            &crypto_payload,
            allocator,
            1,
            "server-hello-suffix",
            1024,
        );
        const suffix_packet = try quic.protection.sealInitialPacket(
            allocator,
            server_keys,
            .{
                .version = version.wireValue(),
                .destination_connection_id = client_scid,
                .source_connection_id = server_scid,
                .packet_number = 1,
                .payload = crypto_payload.items,
            },
        );
        defer allocator.free(suffix_packet);
        try std.testing.expect(!InitialResponseFilter.accept(
            &filter,
            suffix_packet,
        ));

        crypto_payload.clearRetainingCapacity();
        try quic.crypto_stream.writeCryptoFrames(
            &crypto_payload,
            allocator,
            0,
            "server-hello",
            1024,
        );
        const prefix_packet = try quic.protection.sealInitialPacket(
            allocator,
            server_keys,
            .{
                .version = version.wireValue(),
                .destination_connection_id = client_scid,
                .source_connection_id = server_scid,
                .packet_number = 2,
                .payload = crypto_payload.items,
            },
        );
        defer allocator.free(prefix_packet);
        try std.testing.expect(InitialResponseFilter.accept(
            &filter,
            prefix_packet,
        ));
    }
}

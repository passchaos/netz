const std = @import("std");
const quic = @import("mod.zig");

pub const Error = quic.Error || quic.address_validation_token.Error || std.mem.Allocator.Error || error{
    RetryAlreadyProcessed,
    InitialAlreadyProcessed,
};

pub const IssueOptions = struct {
    version: quic.Version = .version_1,
    original_destination_connection_id: []const u8,
    client_source_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    peer_address: []const u8,
    issued_ns: i64,
    lifetime_ns: u64,
    nonce: quic.address_validation_token.Nonce,
    secret: quic.address_validation_token.Secret,
};

pub const ValidateOptions = struct {
    original_destination_connection_id: []const u8,
    peer_address: []const u8,
    now_ns: i64,
    secret: quic.address_validation_token.Secret,
};

pub const ValidateAnySecretOptions = struct {
    original_destination_connection_id: []const u8,
    peer_address: []const u8,
    now_ns: i64,
    secrets: []const quic.address_validation_token.Secret,
};

pub const ProcessOptions = struct {
    version: quic.Version = .version_1,
    original_destination_connection_id: []const u8,
    /// The Source Connection ID sent by the client in its first Initial.  A
    /// Retry packet is addressed to this CID, so checking it prevents callers
    /// from accidentally applying a Retry datagram for a different connection
    /// attempt on a shared UDP socket.
    initial_source_connection_id: []const u8,
    /// Set once this connection attempt has already accepted a Retry.  Stateful
    /// users can rely on ClientState; stateless users should set this when they
    /// keep retry state elsewhere.
    retry_already_processed: bool = false,
    /// Set once an Initial packet from the server has already been accepted.
    /// RFC 9000 requires later Retry packets to be ignored.
    server_initial_processed: bool = false,
};

pub const ValidatedRetry = struct {
    /// Parsed packet metadata.  Slices borrow from the datagram passed to
    /// validate()/validateAnySecret(); keep that datagram alive while reading
    /// these fields.
    packet: quic.RetryPacket,
    token: quic.address_validation_token.Validation,
};

pub const ProcessedRetry = struct {
    /// Parsed packet metadata.  Slices borrow from the datagram passed to
    /// processClient()/ClientState.process(); the owned token and Retry SCID are
    /// exposed separately below for long-lived state.
    packet: quic.RetryPacket,
    token: []u8,
    retry_source_connection_id: []u8,
    retry_initial_secrets: quic.protection.InitialSecrets,
    /// Client options for the retried Initial.  Its token and retry SCID slices
    /// point at this ProcessedRetry's owned fields and become invalid after
    /// deinit().
    retry_client_options: quic.handshake.ClientOptions,

    pub fn deinit(self: *ProcessedRetry, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        allocator.free(self.retry_source_connection_id);
        self.* = undefined;
    }
};

pub const ClientState = struct {
    allocator: std.mem.Allocator,
    version: quic.Version = .version_1,
    original_destination_connection_id: []u8,
    initial_source_connection_id: []u8,
    retry_token: []u8 = &.{},
    retry_source_connection_id: []u8 = &.{},
    retry_processed: bool = false,
    server_initial_processed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        version: quic.Version,
        original_destination_connection_id: []const u8,
        initial_source_connection_id: []const u8,
    ) Error!ClientState {
        if (version == .negotiation) return error.InvalidVersionNegotiation;
        try validateClientConnectionId(original_destination_connection_id, false);
        try validateClientConnectionId(initial_source_connection_id, false);

        const owned_odcid = try allocator.dupe(u8, original_destination_connection_id);
        errdefer allocator.free(owned_odcid);
        const owned_iscid = try allocator.dupe(u8, initial_source_connection_id);
        errdefer allocator.free(owned_iscid);
        return .{
            .allocator = allocator,
            .version = version,
            .original_destination_connection_id = owned_odcid,
            .initial_source_connection_id = owned_iscid,
        };
    }

    pub fn deinit(self: *ClientState) void {
        self.allocator.free(self.original_destination_connection_id);
        self.allocator.free(self.initial_source_connection_id);
        self.allocator.free(self.retry_token);
        self.allocator.free(self.retry_source_connection_id);
        self.* = undefined;
    }

    pub fn markServerInitialProcessed(self: *ClientState) void {
        self.server_initial_processed = true;
    }

    pub fn process(
        self: *ClientState,
        datagram: []const u8,
        base_options: quic.handshake.ClientOptions,
    ) Error!ProcessedRetry {
        if (self.retry_processed) return error.RetryAlreadyProcessed;
        const processed = try processClient(
            self.allocator,
            .{
                .version = self.version,
                .original_destination_connection_id = self.original_destination_connection_id,
                .initial_source_connection_id = self.initial_source_connection_id,
                .server_initial_processed = self.server_initial_processed,
            },
            datagram,
            base_options,
        );
        errdefer {
            var owned = processed;
            owned.deinit(self.allocator);
        }

        const state_token = try self.allocator.dupe(u8, processed.token);
        errdefer self.allocator.free(state_token);
        const state_rscid = try self.allocator.dupe(u8, processed.retry_source_connection_id);
        errdefer self.allocator.free(state_rscid);

        self.allocator.free(self.retry_token);
        self.allocator.free(self.retry_source_connection_id);
        self.retry_token = state_token;
        self.retry_source_connection_id = state_rscid;
        self.retry_processed = true;
        return processed;
    }
};

/// Issue a QUIC Retry datagram with an address-validation token bound to the
/// client's original DCID and the Retry SCID.
pub fn issue(allocator: std.mem.Allocator, options: IssueOptions) Error![]u8 {
    if (std.mem.eql(u8, options.retry_source_connection_id, options.original_destination_connection_id)) {
        return error.InvalidToken;
    }

    const token = try quic.address_validation_token.encodeRetry(allocator, options.secret, .{
        .kind = .retry,
        .version = options.version,
        .issued_ns = options.issued_ns,
        .lifetime_ns = options.lifetime_ns,
        .peer_address = options.peer_address,
        .nonce = options.nonce,
    }, options.original_destination_connection_id, options.retry_source_connection_id);
    defer allocator.free(token);

    var datagram: std.ArrayList(u8) = .empty;
    errdefer datagram.deinit(allocator);
    try quic.writeRetryPacket(&datagram, allocator, .{
        .version = options.version.wireValue(),
        .destination_connection_id = options.client_source_connection_id,
        .source_connection_id = options.retry_source_connection_id,
        .token = token,
        .original_destination_connection_id = options.original_destination_connection_id,
    });
    return datagram.toOwnedSlice(allocator);
}

/// Verify Retry integrity and validate the embedded Retry token binding.
pub fn validate(allocator: std.mem.Allocator, options: ValidateOptions, datagram: []const u8) Error!ValidatedRetry {
    if (!try quic.verifyRetryIntegrityTag(allocator, options.original_destination_connection_id, datagram)) return error.InvalidToken;
    const packet = try quic.parseRetryPacket(datagram);
    const validation = try quic.address_validation_token.validateRetry(
        allocator,
        options.secret,
        @enumFromInt(packet.version),
        options.now_ns,
        options.peer_address,
        options.original_destination_connection_id,
        packet.source_connection_id,
        packet.token,
    );
    return .{ .packet = packet, .token = validation };
}

pub fn validateAnySecret(allocator: std.mem.Allocator, options: ValidateAnySecretOptions, datagram: []const u8) Error!ValidatedRetry {
    if (!try quic.verifyRetryIntegrityTag(allocator, options.original_destination_connection_id, datagram)) return error.InvalidToken;
    const packet = try quic.parseRetryPacket(datagram);
    const validation = try quic.address_validation_token.validateRetryAnySecret(
        allocator,
        options.secrets,
        @enumFromInt(packet.version),
        options.now_ns,
        options.peer_address,
        options.original_destination_connection_id,
        packet.source_connection_id,
        packet.token,
    );
    return .{ .packet = packet, .token = validation };
}

/// Verify and apply a client-side Retry packet.
///
/// This is intentionally transport-only: it authenticates the Retry Integrity
/// Tag, enforces the RFC 9000 one-Retry/early-Retry rules that can be checked
/// without a full connection object, owns the Retry token/RSCID slices, derives
/// the new Initial secrets from the Retry SCID, and returns ClientOptions for
/// the second Initial.  TLS code must still resend the exact same ClientHello
/// bytes on packet number 0; callers using `handshake.connect` can feed the
/// returned options into a fresh retried connection attempt.
pub fn processClient(
    allocator: std.mem.Allocator,
    options: ProcessOptions,
    datagram: []const u8,
    base_options: quic.handshake.ClientOptions,
) Error!ProcessedRetry {
    if (options.version == .negotiation) return error.InvalidVersionNegotiation;
    try validateClientConnectionId(options.original_destination_connection_id, false);
    try validateClientConnectionId(options.initial_source_connection_id, false);
    if (options.server_initial_processed) return error.InitialAlreadyProcessed;
    if (options.retry_already_processed or base_options.retry_source_connection_id.len != 0) return error.RetryAlreadyProcessed;

    if (!try quic.verifyRetryIntegrityTag(allocator, options.original_destination_connection_id, datagram)) return error.InvalidToken;
    const packet = try quic.parseRetryPacket(datagram);
    if (packet.version != options.version.wireValue()) return error.InvalidToken;
    if (!std.mem.eql(u8, packet.destination_connection_id, options.initial_source_connection_id)) return error.InvalidToken;
    if (std.mem.eql(u8, packet.source_connection_id, options.original_destination_connection_id)) return error.InvalidToken;
    try validateClientConnectionId(packet.source_connection_id, true);

    const owned_token = try allocator.dupe(u8, packet.token);
    errdefer allocator.free(owned_token);
    const owned_rscid = try allocator.dupe(u8, packet.source_connection_id);
    errdefer allocator.free(owned_rscid);

    // Retry changes the destination CID used for Initial key derivation.  The
    // first Initial's ODCID remains available separately for later server
    // transport-parameter validation.
    const retry_initial_secrets = quic.protection.deriveInitialSecretsForVersion(packet.version, owned_rscid);
    var retry_options = base_options;
    retry_options.version = options.version;
    retry_options.retry_source_connection_id = owned_rscid;
    retry_options.address_validation_token = owned_token;
    retry_options.client_initial_packet_number = 0;

    return .{
        .packet = packet,
        .token = owned_token,
        .retry_source_connection_id = owned_rscid,
        .retry_initial_secrets = retry_initial_secrets,
        .retry_client_options = retry_options,
    };
}

fn validateClientConnectionId(cid: []const u8, require_non_empty: bool) Error!void {
    if (cid.len > 20 or (require_non_empty and cid.len == 0)) return error.InvalidConnectionIdLength;
}

test "QUIC Retry flow issues and validates address-bound Retry datagram" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const client_scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const retry_scid = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const secret: quic.address_validation_token.Secret = [_]u8{0x44} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0x55} ** quic.address_validation_token.nonce_len;

    const datagram = try issue(allocator, .{
        .version = .version_2,
        .original_destination_connection_id = &odcid,
        .client_source_connection_id = &client_scid,
        .retry_source_connection_id = &retry_scid,
        .peer_address = "client-path",
        .issued_ns = 100,
        .lifetime_ns = 500,
        .nonce = nonce,
        .secret = secret,
    });
    defer allocator.free(datagram);

    const result = try validate(allocator, .{
        .original_destination_connection_id = &odcid,
        .peer_address = "client-path",
        .now_ns = 120,
        .secret = secret,
    }, datagram);
    try std.testing.expectEqual(quic.Version.version_2.wireValue(), result.packet.version);
    try std.testing.expectEqualSlices(u8, &client_scid, result.packet.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, result.packet.source_connection_id);
    try std.testing.expectEqual(quic.address_validation_token.Kind.retry, result.token.kind);
}

test "QUIC Retry flow rejects wrong integrity ODCID or token binding" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 1, 2, 3, 4 };
    const wrong_odcid = [_]u8{ 1, 2, 3, 9 };
    const client_scid = [_]u8{ 5, 6, 7, 8 };
    const retry_scid = [_]u8{ 9, 10, 11, 12 };
    const secret: quic.address_validation_token.Secret = [_]u8{0x66} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0x77} ** quic.address_validation_token.nonce_len;

    const datagram = try issue(allocator, .{
        .original_destination_connection_id = &odcid,
        .client_source_connection_id = &client_scid,
        .retry_source_connection_id = &retry_scid,
        .peer_address = "client-path",
        .issued_ns = 100,
        .lifetime_ns = 500,
        .nonce = nonce,
        .secret = secret,
    });
    defer allocator.free(datagram);

    try std.testing.expectError(error.InvalidToken, validate(allocator, .{
        .original_destination_connection_id = &wrong_odcid,
        .peer_address = "client-path",
        .now_ns = 120,
        .secret = secret,
    }, datagram));
    try std.testing.expectError(error.InvalidToken, validate(allocator, .{
        .original_destination_connection_id = &odcid,
        .peer_address = "other-path",
        .now_ns = 120,
        .secret = secret,
    }, datagram));
}

test "QUIC client Retry processing builds retried Initial inputs" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const retry_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4 };
    const secret: quic.address_validation_token.Secret = [_]u8{0x88} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0x99} ** quic.address_validation_token.nonce_len;

    const datagram = try issue(allocator, .{
        .version = .version_2,
        .original_destination_connection_id = &odcid,
        .client_source_connection_id = &client_scid,
        .retry_source_connection_id = &retry_scid,
        .peer_address = "client-path",
        .issued_ns = 1_000,
        .lifetime_ns = 10_000,
        .nonce = nonce,
        .secret = secret,
    });
    defer allocator.free(datagram);

    var state = try ClientState.init(allocator, .version_2, &odcid, &client_scid);
    defer state.deinit();

    var processed = try state.process(datagram, .{
        .version = .version_2,
        .original_destination_connection_id = &odcid,
        .local_connection_id = &client_scid,
        .address_validation_token = "cached-new-token",
        .client_initial_packet_number = 42,
    });
    defer processed.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &client_scid, processed.packet.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, processed.packet.source_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, processed.retry_source_connection_id);
    try std.testing.expectEqualSlices(u8, processed.token, processed.retry_client_options.address_validation_token);
    try std.testing.expectEqualSlices(u8, &odcid, processed.retry_client_options.original_destination_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, processed.retry_client_options.retry_source_connection_id);
    try std.testing.expectEqual(quic.Version.version_2, processed.retry_client_options.version);
    try std.testing.expectEqual(@as(u64, 0), processed.retry_client_options.client_initial_packet_number);
    try std.testing.expectEqualSlices(u8, processed.token, state.retry_token);
    try std.testing.expectEqualSlices(u8, &retry_scid, state.retry_source_connection_id);
    try std.testing.expectEqualSlices(
        u8,
        &quic.protection.deriveInitialSecretsForVersion(quic.Version.version_2.wireValue(), &retry_scid).client.key,
        &processed.retry_initial_secrets.client.key,
    );

    const validation = try validateAnySecret(allocator, .{
        .original_destination_connection_id = &odcid,
        .peer_address = "client-path",
        .now_ns = 1_100,
        .secrets = &[_]quic.address_validation_token.Secret{secret},
    }, datagram);
    try std.testing.expectEqual(quic.address_validation_token.Kind.retry, validation.token.kind);
    try std.testing.expectError(error.RetryAlreadyProcessed, state.process(datagram, .{
        .original_destination_connection_id = &odcid,
        .local_connection_id = &client_scid,
    }));
}

test "QUIC client Retry processing rejects stale or misrouted Retry packets" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const retry_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const secret: quic.address_validation_token.Secret = [_]u8{0xaa} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0xbb} ** quic.address_validation_token.nonce_len;

    const datagram = try issue(allocator, .{
        .original_destination_connection_id = &odcid,
        .client_source_connection_id = &client_scid,
        .retry_source_connection_id = &retry_scid,
        .peer_address = "client-path",
        .issued_ns = 5,
        .lifetime_ns = 100,
        .nonce = nonce,
        .secret = secret,
    });
    defer allocator.free(datagram);

    const base_options = quic.handshake.ClientOptions{
        .original_destination_connection_id = &odcid,
        .local_connection_id = &client_scid,
    };
    try std.testing.expectError(error.InitialAlreadyProcessed, processClient(allocator, .{
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &client_scid,
        .server_initial_processed = true,
    }, datagram, base_options));
    try std.testing.expectError(error.RetryAlreadyProcessed, processClient(allocator, .{
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &client_scid,
        .retry_already_processed = true,
    }, datagram, base_options));
    try std.testing.expectError(error.RetryAlreadyProcessed, processClient(allocator, .{
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &client_scid,
    }, datagram, .{
        .original_destination_connection_id = &odcid,
        .local_connection_id = &client_scid,
        .retry_source_connection_id = &retry_scid,
        .address_validation_token = "retry-token",
    }));

    try std.testing.expectError(error.InvalidToken, processClient(allocator, .{
        .original_destination_connection_id = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 },
        .initial_source_connection_id = &client_scid,
    }, datagram, base_options));
    try std.testing.expectError(error.InvalidToken, processClient(allocator, .{
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &[_]u8{ 0x31, 0x32, 0x33, 0x34 },
    }, datagram, base_options));

    try std.testing.expectError(error.InvalidToken, issue(allocator, .{
        .original_destination_connection_id = &odcid,
        .client_source_connection_id = &client_scid,
        .retry_source_connection_id = &odcid,
        .peer_address = "client-path",
        .issued_ns = 5,
        .lifetime_ns = 100,
        .nonce = nonce,
        .secret = secret,
    }));

    const bad_scid_token = try quic.address_validation_token.encodeRetry(allocator, secret, .{
        .kind = .retry,
        .issued_ns = 5,
        .lifetime_ns = 100,
        .peer_address = "client-path",
        .nonce = nonce,
    }, &odcid, &odcid);
    defer allocator.free(bad_scid_token);
    var bad_scid_datagram: std.ArrayList(u8) = .empty;
    defer bad_scid_datagram.deinit(allocator);
    try quic.writeRetryPacket(&bad_scid_datagram, allocator, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &odcid,
        .token = bad_scid_token,
        .original_destination_connection_id = &odcid,
    });
    try std.testing.expectError(error.InvalidToken, processClient(allocator, .{
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &client_scid,
    }, bad_scid_datagram.items, base_options));
}

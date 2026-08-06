const std = @import("std");
const quic = @import("mod.zig");

pub const Error = quic.Error || quic.address_validation_token.Error || std.mem.Allocator.Error;

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

pub const ValidatedRetry = struct {
    packet: quic.RetryPacket,
    token: quic.address_validation_token.Validation,
};

/// Issue a QUIC Retry datagram with an address-validation token bound to the
/// client's original DCID and the Retry SCID.
pub fn issue(allocator: std.mem.Allocator, options: IssueOptions) Error![]u8 {
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

test "QUIC Retry flow issues and validates address-bound Retry datagram" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const client_scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const retry_scid = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const secret: quic.address_validation_token.Secret = [_]u8{0x44} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0x55} ** quic.address_validation_token.nonce_len;

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

    const result = try validate(allocator, .{
        .original_destination_connection_id = &odcid,
        .peer_address = "client-path",
        .now_ns = 120,
        .secret = secret,
    }, datagram);
    try std.testing.expectEqual(quic.Version.version_1.wireValue(), result.packet.version);
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

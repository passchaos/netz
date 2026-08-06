const std = @import("std");
const quic = @import("mod.zig");

pub const Error = quic.Error || std.mem.Allocator.Error;

pub const ProcessOptions = struct {
    chosen_version: quic.Version = .version_1,
    /// Client preference order.  The first version that also appears in the
    /// server's Version Negotiation packet is selected.
    available_versions: []const quic.Version = &.{ .version_1, .version_2 },
    original_destination_connection_id: []const u8,
    initial_source_connection_id: []const u8,
    /// A Version Negotiation packet is only valid as a response to the first
    /// Initial.  Socket loops should set this to false until the Initial is
    /// actually written to the network.
    initial_sent: bool = true,
    /// RFC 9000 requires clients to ignore Version Negotiation once any Retry
    /// or server packet has been accepted for the same connection attempt.
    retry_processed: bool = false,
    server_packet_processed: bool = false,
    version_negotiation_processed: bool = false,
};

pub const Processed = struct {
    packet: quic.VersionNegotiationPacket,
    selected_version: quic.Version,
    /// Initial secrets for the restarted first flight.  Version Negotiation does
    /// not replace the original Destination Connection ID; it only changes the
    /// QUIC version and therefore the Initial salt/labels.
    selected_initial_secrets: quic.protection.InitialSecrets,

    pub fn deinit(self: *Processed, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        self.* = undefined;
    }

    /// Build the caller's next client-handshake options after Version
    /// Negotiation.  Retry state and address tokens are cleared because a
    /// Version Negotiation packet is only processed before Retry or server
    /// packets, and netz address-validation tokens are version-bound.
    pub fn clientOptions(self: Processed, base: quic.handshake.ClientOptions) quic.handshake.ClientOptions {
        var next = base;
        next.version = self.selected_version;
        next.retry_source_connection_id = &.{};
        next.address_validation_token = &.{};
        next.client_initial_packet_number = 0;
        next.client_handshake_packet_number = 0;
        return next;
    }
};

pub const ClientState = struct {
    allocator: std.mem.Allocator,
    chosen_version: quic.Version,
    available_versions: []quic.Version,
    original_destination_connection_id: []u8,
    initial_source_connection_id: []u8,
    initial_sent: bool = false,
    retry_processed: bool = false,
    server_packet_processed: bool = false,
    selected_version: ?quic.Version = null,

    pub fn init(
        allocator: std.mem.Allocator,
        chosen_version: quic.Version,
        available_versions: []const quic.Version,
        original_destination_connection_id: []const u8,
        initial_source_connection_id: []const u8,
    ) Error!ClientState {
        try validateVersionList(chosen_version, available_versions);
        try validateConnectionId(original_destination_connection_id);
        try validateConnectionId(initial_source_connection_id);

        const owned_versions = try allocator.dupe(quic.Version, available_versions);
        errdefer allocator.free(owned_versions);
        const owned_odcid = try allocator.dupe(u8, original_destination_connection_id);
        errdefer allocator.free(owned_odcid);
        const owned_scid = try allocator.dupe(u8, initial_source_connection_id);
        errdefer allocator.free(owned_scid);
        return .{
            .allocator = allocator,
            .chosen_version = chosen_version,
            .available_versions = owned_versions,
            .original_destination_connection_id = owned_odcid,
            .initial_source_connection_id = owned_scid,
        };
    }

    pub fn deinit(self: *ClientState) void {
        self.allocator.free(self.available_versions);
        self.allocator.free(self.original_destination_connection_id);
        self.allocator.free(self.initial_source_connection_id);
        self.* = undefined;
    }

    pub fn markInitialSent(self: *ClientState) void {
        self.initial_sent = true;
    }

    pub fn markRetryProcessed(self: *ClientState) void {
        self.retry_processed = true;
    }

    pub fn markServerPacketProcessed(self: *ClientState) void {
        self.server_packet_processed = true;
    }

    pub fn process(self: *ClientState, datagram: []const u8) Error!?Processed {
        const processed = try processClient(self.allocator, .{
            .chosen_version = self.chosen_version,
            .available_versions = self.available_versions,
            .original_destination_connection_id = self.original_destination_connection_id,
            .initial_source_connection_id = self.initial_source_connection_id,
            .initial_sent = self.initial_sent,
            .retry_processed = self.retry_processed,
            .server_packet_processed = self.server_packet_processed,
            .version_negotiation_processed = self.selected_version != null,
        }, datagram);
        if (processed) |result| self.selected_version = result.selected_version;
        return processed;
    }
};

/// Validate and process a client-side Version Negotiation packet.
///
/// The packet is ignored (`null`) for RFC-mandated discard cases: no Initial was
/// sent yet, a Retry/server packet has already been processed, CIDs are not the
/// exact swap of the first Initial, the packet lists the client's original
/// version, or a previous Version Negotiation packet already selected a version.
/// A syntactically valid but unusable negotiation (no mutually supported version)
/// is returned as `error.InvalidVersionNegotiation`, matching mature stacks that
/// fail the connection attempt rather than silently continuing with an
/// unsupported version.
pub fn processClient(allocator: std.mem.Allocator, options: ProcessOptions, datagram: []const u8) Error!?Processed {
    try validateVersionList(options.chosen_version, options.available_versions);
    try validateConnectionId(options.original_destination_connection_id);
    try validateConnectionId(options.initial_source_connection_id);
    if (!options.initial_sent or
        options.retry_processed or
        options.server_packet_processed or
        options.version_negotiation_processed)
    {
        return null;
    }

    var packet = try quic.parseVersionNegotiationPacket(allocator, datagram);
    errdefer packet.deinit(allocator);

    if (!std.mem.eql(u8, packet.destination_connection_id, options.initial_source_connection_id)) {
        packet.deinit(allocator);
        return null;
    }
    if (!std.mem.eql(u8, packet.source_connection_id, options.original_destination_connection_id)) {
        packet.deinit(allocator);
        return null;
    }
    if (containsWireVersion(packet.versions, options.chosen_version.wireValue())) {
        packet.deinit(allocator);
        return null;
    }

    const selected = selectMutualVersion(options.available_versions, packet.versions) orelse return error.InvalidVersionNegotiation;
    return .{
        .packet = packet,
        .selected_version = selected,
        .selected_initial_secrets = quic.protection.deriveInitialSecretsForVersion(
            selected.wireValue(),
            options.original_destination_connection_id,
        ),
    };
}

pub fn selectMutualVersion(available_versions: []const quic.Version, server_versions: []const u32) ?quic.Version {
    for (available_versions) |version| {
        if (version == .negotiation) continue;
        if (containsWireVersion(server_versions, version.wireValue())) return version;
    }
    return null;
}

fn containsWireVersion(versions: []const u32, value: u32) bool {
    for (versions) |version| {
        if (version == value) return true;
    }
    return false;
}

fn validateVersionList(chosen_version: quic.Version, available_versions: []const quic.Version) Error!void {
    if (chosen_version == .negotiation) return error.InvalidVersionNegotiation;
    if (available_versions.len == 0) return error.InvalidVersionNegotiation;
    var has_chosen = false;
    for (available_versions) |version| {
        if (version == .negotiation) return error.InvalidVersionNegotiation;
        if (version.wireValue() == chosen_version.wireValue()) has_chosen = true;
    }
    if (!has_chosen) return error.InvalidVersionNegotiation;
}

fn validateConnectionId(cid: []const u8) Error!void {
    if (cid.len > 20) return error.InvalidConnectionIdLength;
}

fn writeNegotiation(
    allocator: std.mem.Allocator,
    dcid: []const u8,
    scid: []const u8,
    versions: []const u32,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try quic.writeVersionNegotiationPacket(&out, allocator, .{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .versions = versions,
    });
    return out.toOwnedSlice(allocator);
}

test "QUIC client Version Negotiation selects mutual version once" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_versions = [_]u32{ quic.Version.version_2.wireValue(), 0x0a0a0a0a };
    const datagram = try writeNegotiation(allocator, &client_scid, &odcid, &server_versions);
    defer allocator.free(datagram);

    var state = try ClientState.init(allocator, .version_1, &.{ .version_1, .version_2 }, &odcid, &client_scid);
    defer state.deinit();
    try std.testing.expect((try state.process(datagram)) == null);
    state.markInitialSent();

    var processed = (try state.process(datagram)) orelse return error.TestUnexpectedResult;
    defer processed.deinit(allocator);
    try std.testing.expectEqual(quic.Version.version_2, processed.selected_version);
    try std.testing.expectEqual(quic.Version.version_2, state.selected_version.?);
    try std.testing.expectEqualSlices(u8, &client_scid, processed.packet.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &odcid, processed.packet.source_connection_id);

    try std.testing.expectEqualSlices(
        u8,
        &quic.protection.deriveInitialSecretsForVersion(quic.Version.version_2.wireValue(), &odcid).client.key,
        &processed.selected_initial_secrets.client.key,
    );

    const followup = processed.clientOptions(.{
        .version = .version_1,
        .original_destination_connection_id = &odcid,
        .local_connection_id = &client_scid,
        .address_validation_token = "old-version-token",
        .client_initial_packet_number = 7,
        .client_handshake_packet_number = 9,
    });
    try std.testing.expectEqual(quic.Version.version_2, followup.version);
    try std.testing.expectEqual(@as(u64, 0), followup.client_initial_packet_number);
    try std.testing.expectEqual(@as(u64, 0), followup.client_handshake_packet_number);
    try std.testing.expectEqual(@as(usize, 0), followup.address_validation_token.len);

    try std.testing.expect((try state.process(datagram)) == null);
}

test "QUIC client Version Negotiation ignores unsafe or mismatched packets" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 9, 10, 11, 12 };
    const other_cid = [_]u8{ 0xaa, 0xbb, 0xcc };
    const v1_and_v2 = [_]u32{ quic.Version.version_2.wireValue(), quic.Version.version_1.wireValue() };
    const v2_only = [_]u32{quic.Version.version_2.wireValue()};

    const contains_original = try writeNegotiation(allocator, &client_scid, &odcid, &v1_and_v2);
    defer allocator.free(contains_original);
    const wrong_dcid = try writeNegotiation(allocator, &other_cid, &odcid, &v2_only);
    defer allocator.free(wrong_dcid);
    const wrong_scid = try writeNegotiation(allocator, &client_scid, &other_cid, &v2_only);
    defer allocator.free(wrong_scid);

    const options = ProcessOptions{
        .chosen_version = .version_1,
        .available_versions = &.{ .version_1, .version_2 },
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &client_scid,
    };
    try std.testing.expect((try processClient(allocator, options, contains_original)) == null);
    try std.testing.expect((try processClient(allocator, options, wrong_dcid)) == null);
    try std.testing.expect((try processClient(allocator, options, wrong_scid)) == null);
    try std.testing.expect((try processClient(allocator, .{ .original_destination_connection_id = &odcid, .initial_source_connection_id = &client_scid, .retry_processed = true }, wrong_scid)) == null);
    try std.testing.expect((try processClient(allocator, .{ .original_destination_connection_id = &odcid, .initial_source_connection_id = &client_scid, .server_packet_processed = true }, wrong_scid)) == null);
    try std.testing.expect((try processClient(allocator, .{ .original_destination_connection_id = &odcid, .initial_source_connection_id = &client_scid, .version_negotiation_processed = true }, wrong_scid)) == null);
}

test "QUIC client Version Negotiation rejects no mutual version" {
    const allocator = std.testing.allocator;
    const odcid = [_]u8{ 1, 3, 3, 7, 9, 2, 4, 6 };
    const client_scid = [_]u8{ 4, 2 };
    const reserved_versions = [_]u32{0x0a0a0a0a};
    const datagram = try writeNegotiation(allocator, &client_scid, &odcid, &reserved_versions);
    defer allocator.free(datagram);

    try std.testing.expectError(error.InvalidVersionNegotiation, processClient(allocator, .{
        .chosen_version = .version_1,
        .available_versions = &.{ .version_1, .version_2 },
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &client_scid,
    }, datagram));
    try std.testing.expectError(error.InvalidVersionNegotiation, ClientState.init(allocator, .negotiation, &.{.version_1}, &odcid, &client_scid));
    try std.testing.expectError(error.InvalidVersionNegotiation, ClientState.init(allocator, .version_1, &.{.version_2}, &odcid, &client_scid));

    var greased = try ClientState.init(allocator, .version_1, &.{ .version_1, @enumFromInt(0x0a0a0a0a) }, &odcid, &client_scid);
    defer greased.deinit();
    try std.testing.expectEqual(@as(usize, 2), greased.available_versions.len);
}

const std = @import("std");
const quic = @import("../mod.zig");
const trust = @import("../client_trust.zig");

test "QUIC effective trust inherits TCP verifier despite an inactive CA bundle" {
    const verifier: quic.tls.auth.ClientVerifier = .{ .pinned_ecdsa_p256_public_key = @splat(7) };
    inline for (.{ false, true }) |bounded| {
        var options: quic.handshake.ClientOptions = .{ .original_destination_connection_id = "effective-origin", .local_connection_id = "effective-client" };
        var owned: ?trust.SystemStore = null;
        defer if (owned) |*store| store.deinit();
        try apply(bounded, &options, .{ .server_verifier = verifier, .ca_bundle_configured = true }, &owned);
        try std.testing.expectEqualDeep(verifier, options.server_auth.?);
        try std.testing.expect(owned == null);
    }
}

test "QUIC effective trust still rejects an active TCP CA bundle" {
    var external = trust.SystemStore.initEmpty(std.testing.allocator);
    defer external.deinit();
    inline for (.{ false, true }) |bounded| {
        var options: quic.handshake.ClientOptions = .{ .original_destination_connection_id = "effective-origin", .local_connection_id = "effective-client" };
        const expected = options;
        var owned: ?trust.SystemStore = null;
        defer if (owned) |*store| store.deinit();
        try std.testing.expectError(error.UnsupportedH3TrustConfiguration, apply(bounded, &options, .{ .system_store = &external, .root_source = .bundled, .ca_bundle_configured = true }, &owned));
        try std.testing.expectEqualDeep(expected, options);
        try std.testing.expect(owned == null);
    }
}

fn apply(comptime bounded: bool, options: *quic.handshake.ClientOptions, tls: trust.ClientTlsTrust, owned: *?trust.SystemStore) !void {
    if (bounded) {
        try trust.applyClientTrustBefore(std.testing.allocator, std.testing.io, options, tls, owned, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    } else {
        try trust.applyClientTrust(std.testing.allocator, std.testing.io, options, tls, owned);
    }
}

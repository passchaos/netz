//! Explicit H3 peer-authentication policy is independent of TCP trust defaults.
const std = @import("std");
const quic = @import("../mod.zig");
const trust = @import("../client_trust.zig");
const tls_testing = @import("../../tls/testing.zig");

const Source = enum { verifier, store, environment, bundled, platform };

fn exercise(comptime source: Source) !void {
    var h3_store = trust.SystemStore.initEmpty(std.testing.allocator);
    defer h3_store.deinit();
    var tcp_store = trust.SystemStore.initEmpty(std.testing.allocator);
    defer tcp_store.deinit();
    inline for (.{ false, true }) |bounded| {
        var options: quic.handshake.ClientOptions = .{
            .original_destination_connection_id = "precedence-origin",
            .local_connection_id = "precedence-client",
        };
        switch (source) {
            .verifier => options.server_auth = .{ .pinned_ecdsa_p256_public_key = @splat(7) },
            .store => options.system_store = &h3_store,
            .environment => options.system_environ = .empty,
            .bundled => options.root_source = .bundled,
            .platform => options.root_source = .platform,
        }
        const expected = options;
        var owned: ?trust.SystemStore = null;
        defer if (owned) |*store| store.deinit();
        const tcp: trust.ClientTlsTrust = .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = @splat(9) },
            .system_store = &tcp_store,
            .environ = .empty,
            .root_source = .bundled,
            .ca_bundle_configured = true,
        };
        if (bounded) {
            try trust.applyClientTrustBefore(std.testing.allocator, std.testing.io, &options, tcp, &owned, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        } else {
            try trust.applyClientTrust(std.testing.allocator, std.testing.io, &options, tcp, &owned);
        }
        try std.testing.expectEqualDeep(expected.server_auth, options.server_auth);
        try std.testing.expectEqual(expected.system_store, options.system_store);
        try std.testing.expectEqual(expected.system_environ != null, options.system_environ != null);
        try std.testing.expectEqual(expected.root_source, options.root_source);
        try std.testing.expect(owned == null);
    }
}

test "QUIC trust precedence explicit verifier isolates TCP trust defaults" {
    try exercise(.verifier);
}
test "QUIC trust precedence explicit store isolates TCP trust defaults" {
    try exercise(.store);
}
test "QUIC trust precedence explicit environment isolates TCP trust defaults" {
    try exercise(.environment);
}
test "QUIC trust precedence bundled roots isolate TCP trust defaults" {
    try exercise(.bundled);
}
test "QUIC trust precedence platform roots isolate TCP trust defaults" {
    try exercise(.platform);
}

test "QUIC trust precedence client identity inherits independently of explicit peer trust" {
    const key_pair = try tls_testing.serverKeyPair();
    const tcp_identity: quic.tls.client_auth.ClientIdentity = .{
        .certificate_chain = &.{"tcp-client-identity"},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    const h3_identity: quic.tls.client_auth.ClientIdentity = .{
        .certificate_chain = &.{"h3-client-identity"},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    inline for (.{ false, true }) |configured| {
        var options: quic.handshake.ClientOptions = .{
            .original_destination_connection_id = "identity-origin",
            .local_connection_id = "identity-client",
            .root_source = .bundled,
            .client_identity = if (configured) h3_identity else null,
        };
        var owned: ?trust.SystemStore = null;
        defer if (owned) |*store| store.deinit();
        try trust.applyClientTrust(std.testing.allocator, std.testing.io, &options, .{
            .client_identity = tcp_identity,
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = @splat(9) },
        }, &owned);
        try std.testing.expectEqualDeep(if (configured) h3_identity else tcp_identity, options.client_identity.?);
        try std.testing.expect(options.server_auth == null);
        try std.testing.expect(owned == null);
    }
}

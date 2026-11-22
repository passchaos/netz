//! Cross-transport TLS trust policy for QUIC clients.
//!
//! H1/H2 verify TCP TLS peers through `client.Options.tls`. QUIC/H3 has its
//! own low-level handshake options, and a null `server_auth` with no store or
//! environment leaves certificate verification disabled. This module maps a
//! unified TLS policy onto the QUIC handshake so one client configuration
//! authenticates the same peer identity over both transports.
//!
//! Precedence matches `src/trust.zig`: an explicit QUIC verifier or store
//! wins; otherwise the handshake inherits the TCP verifier, client identity,
//! native store, environment, and root source. A TCP CA bundle has no QUIC
//! equivalent, so QUIC refuses to run unverified when only a bundle is set.

const std = @import("std");
const quic = @import("mod.zig");
const root_trust = @import("../trust.zig");

pub const SystemStore = quic.tls.trust.SystemStore;

pub const ClientTlsTrust = struct {
    server_verifier: ?quic.tls.auth.ClientVerifier = null,
    client_identity: ?quic.tls.client_auth.ClientIdentity = null,
    environ: ?std.process.Environ = null,
    system_store: ?*const quic.tls.trust.SystemStore = null,
    root_source: root_trust.RootSource = .system,
    /// `client.Options.tls.ca_bundle != null`. The bundle itself is not copied
    /// because QUIC cannot consume the TCP bundle representation.
    ca_bundle_configured: bool = false,
};

pub const Error = error{
    OutOfMemory,
    NativeTrustStoreUnavailable,
    UnsupportedH3TrustConfiguration,
};

pub const DefaultRootError = error{
    OutOfMemory,
    NativeTrustStoreUnavailable,
};

/// True when the caller configured H3-specific trust material. The default
/// `.system` root source is not explicit: it is the QUIC low-level "unset"
/// value, which would otherwise disable verification.
pub fn hasExplicitTrust(options: *const quic.handshake.ClientOptions) bool {
    return options.server_auth != null or
        options.system_store != null or
        options.system_environ != null or
        options.root_source != .system;
}

/// Apply the unified client's TCP TLS trust policy to a QUIC handshake.
///
/// `store_out` receives a platform-root store when the resolved policy is
/// `.system` and no explicit material exists. The caller must keep both the
/// returned store and this option value alive for every handshake that uses
/// them; the low-level handshake borrows the store pointer.
pub fn applyClientTrust(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: *quic.handshake.ClientOptions,
    tls: ClientTlsTrust,
    store_out: *?quic.tls.trust.SystemStore,
) Error!void {
    if (!hasExplicitTrust(options) and tls.ca_bundle_configured) {
        return error.UnsupportedH3TrustConfiguration;
    }
    if (options.server_auth == null) options.server_auth = tls.server_verifier;
    if (options.client_identity == null) options.client_identity = tls.client_identity;
    if (options.system_environ == null) options.system_environ = tls.environ;
    if (options.system_store == null) options.system_store = tls.system_store;
    if (options.root_source == .system) options.root_source = tls.root_source;
    try applyPlatformRootDefault(allocator, io, options, store_out);
}

/// Install a platform-root store when the QUIC handshake still has no trust
/// material. Facades without a TCP TLS policy (WebSocket over H3, WebTransport
/// URI connects) use this directly. The caller owns `store_out` and must keep
/// it alive for the synchronous handshake.
pub fn applyPlatformRootDefault(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: *quic.handshake.ClientOptions,
    store_out: *?quic.tls.trust.SystemStore,
) DefaultRootError!void {
    if (hasExplicitTrust(options)) return;
    // `.system` is the QUIC low-level "no verifier" default. Load the native
    // root files once, matching the TCP TLS default, instead of silently
    // accepting any certificate.
    store_out.* = quic.tls.trust.SystemStore.init(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NativeTrustStoreUnavailable,
    };
    options.system_store = &store_out.*.?;
}

const testing = std.testing;

fn baseOptions() quic.handshake.ClientOptions {
    return .{
        .original_destination_connection_id = &.{},
        .local_connection_id = &.{},
    };
}

test "explicit H3 trust wins over the TCP policy" {
    var options = baseOptions();
    options.server_auth = .{ .pinned_ecdsa_p256_public_key = [_]u8{7} ** 65 };
    const pinned = options.server_auth;
    var store: ?quic.tls.trust.SystemStore = null;
    defer if (store) |*value| value.deinit();

    try applyClientTrust(
        testing.allocator,
        testing.io,
        &options,
        .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = [_]u8{9} ** 65 },
            .root_source = .bundled,
        },
        &store,
    );

    try testing.expectEqual(pinned.?, options.server_auth.?);
    try testing.expect(store == null);
    try testing.expectEqual(root_trust.RootSource.bundled, options.root_source);
}

test "TCP trust material is inherited when H3 leaves it unset" {
    var options = baseOptions();
    var external_store: quic.tls.trust.SystemStore = undefined;
    var store: ?quic.tls.trust.SystemStore = null;
    defer if (store) |*value| value.deinit();

    try applyClientTrust(
        testing.allocator,
        testing.io,
        &options,
        .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = [_]u8{5} ** 65 },
            .system_store = &external_store,
            .root_source = .bundled,
        },
        &store,
    );

    try testing.expect(options.server_auth != null);
    try testing.expect(options.system_store == &external_store);
    try testing.expectEqual(root_trust.RootSource.bundled, options.root_source);
    try testing.expect(store == null);
}

test "TCP CA bundle without explicit H3 trust fails closed" {
    var options = baseOptions();
    var store: ?quic.tls.trust.SystemStore = null;
    defer if (store) |*value| value.deinit();

    try testing.expectError(
        error.UnsupportedH3TrustConfiguration,
        applyClientTrust(
            testing.allocator,
            testing.io,
            &options,
            .{ .ca_bundle_configured = true },
            &store,
        ),
    );
    try testing.expect(store == null);
}

test "explicit H3 root source overrides a TCP CA bundle" {
    var options = baseOptions();
    options.root_source = .bundled;
    var store: ?quic.tls.trust.SystemStore = null;
    defer if (store) |*value| value.deinit();

    try applyClientTrust(
        testing.allocator,
        testing.io,
        &options,
        .{ .ca_bundle_configured = true },
        &store,
    );

    try testing.expectEqual(root_trust.RootSource.bundled, options.root_source);
    try testing.expect(store == null);
}

test "default policy loads platform roots instead of skipping verification" {
    var options = baseOptions();
    var store: ?quic.tls.trust.SystemStore = null;
    defer if (store) |*value| value.deinit();

    try applyClientTrust(testing.allocator, testing.io, &options, .{}, &store);

    try testing.expect(store != null);
    try testing.expect(options.system_store == &store.?);
    try testing.expect(options.server_auth == null);
}

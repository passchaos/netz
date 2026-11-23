//! Protocol feasibility is decided before any application request is sent.
const std = @import("std");
const types = @import("types.zig");
const Owner = @import("http3_connection.zig").Owner;
const deadlines = @import("../../internal/deadline.zig");
const client_trust = @import("../../quic/client_trust.zig");

pub fn selectHttp3(allocator: std.mem.Allocator, io: std.Io, uri: std.Uri, options: types.Options, deadline: ?std.Io.Clock.Timestamp) !?*Owner {
    if (!options.protocol_policy.attemptsHttp3()) return null;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        if (options.protocol_policy == .http3_only) return error.UnsupportedScheme;
        return null;
    }
    if (options.protocol_policy == .http3_only) return try Owner.connect(allocator, io, uri, options, deadline);
    // A TCP CA bundle has no QUIC representation. `http3_only` rejects this
    // configuration at init; opportunistic H3 stays on TCP rather than running
    // an unauthenticated QUIC handshake.
    if (options.tls.ca_bundle != null and
        !client_trust.hasExplicitTrust(&options.http3.handshake.handshake))
    {
        return null;
    }
    // Preserve the configured route and TLS version constraints. A cleartext
    // HTTP/1.1 CONNECT proxy cannot carry QUIC; SOCKS5 can, using UDP
    // ASSOCIATE with proxy-side domain resolution.
    if (options.http_proxy != null or !options.tls.protocol_policy.offersTls13()) return null;
    var budget = options.http3.preference_timeout;
    if (deadline) |until| {
        _ = try deadlines.usableAwake(io, until);
        budget.nanoseconds = @min(budget.nanoseconds, @max(1, @divTrunc(until.durationFromNow(io).raw.nanoseconds, 2)));
    }
    const probe = (try deadlines.fromTimeout(io, budget)).?;
    var effective = options;
    switch (effective.http3.address_connect_policy) {
        .happy_eyeballs => |*race| {
            // Let an alternate address family participate before the bounded
            // feasibility window ends, including short caller deadlines.
            race.attempt_delay.nanoseconds = @min(race.attempt_delay.nanoseconds, @max(1, @divTrunc(budget.nanoseconds, 4)));
        },
        .ordered => {},
    }
    return Owner.connect(allocator, io, uri, effective, deadlines.earlier(deadline, probe)) catch |err| {
        if (!unavailable(err)) return err;
        if (deadline) |until| _ = try deadlines.usableAwake(io, until);
        return null;
    };
}

/// Authentication, configuration, resource and caller-cancellation failures
/// remain errors. Only connection/protocol unavailability advances selection.
/// Proxy-reported UDP path failures advance too because the same proxy can
/// still carry the TCP fallback.
pub fn unavailable(err: anyerror) bool {
    return switch (err) {
        error.Timeout,
        error.HandshakeTimeout,
        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.PortUnreachable,
        error.AddressFamilyUnsupported,
        error.ConnectionResetByPeer,
        error.NetworkDown,
        error.HandshakeSendFailed,
        error.HandshakeReceiveFailed,
        error.ConnectionClosed,
        error.UnsupportedVersion,
        error.MissingAlpn,
        error.InvalidAlpn,
        error.ProxyCommandUnsupported,
        error.ProxyConnectionNotAllowed,
        error.ProxyAddressTypeUnsupported,
        error.ProxyInvalidRelayAddress,
        error.ProxyProtocolViolation,
        error.ProxyConnectionClosed,
        error.ProxyGeneralFailure,
        error.ProxyNetworkUnreachable,
        error.ProxyHostUnreachable,
        error.ProxyConnectionRefused,
        error.ProxyTtlExpired,
        => true,
        else => false,
    };
}

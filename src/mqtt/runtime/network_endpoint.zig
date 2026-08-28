//! MQTT TCP endpoint connection helpers shared by cleartext and TLS clients.
//!
//! URI parsing owns MQTT-specific policy in `redirect.zig`; this module turns
//! an already-validated target into a socket while preserving one DNS/TCP
//! deadline across every resolved address. Keeping that conversion here lets
//! ordinary URI connects and redirect hops share exactly the same behavior.

const std = @import("std");
const redirect = @import("../redirect.zig");
const tcp_connect = @import("../../internal/tcp_connect.zig");

const net = std.Io.net;

pub const Error = net.HostName.ValidateError ||
    net.HostName.ConnectError || net.IpAddress.ConnectError || error{
    InvalidServerReference,
    UnsupportedRedirectScheme,
};

pub fn connectHost(
    io: std.Io,
    host: []const u8,
    port: u16,
    timeout: ?std.Io.Duration,
) Error!net.Stream {
    const host_name = try net.HostName.init(host);
    return tcp_connect.host(io, host_name, port, timeout);
}

pub fn connectTarget(
    io: std.Io,
    target: *const redirect.Target,
    expected_transport: redirect.Transport,
    timeout: ?std.Io.Duration,
) Error!net.Stream {
    if (target.transport != expected_transport) {
        return error.UnsupportedRedirectScheme;
    }
    if (target.port == 0 or target.host.len == 0) {
        return error.InvalidServerReference;
    }

    // `redirect.parse` retains RFC 3986 brackets in an IPv6 URI host. Socket
    // addresses require only the literal itself, unlike URI authorities.
    if (target.host[0] == '[') {
        if (target.host.len < 3 or
            target.host[target.host.len - 1] != ']')
        {
            return error.InvalidServerReference;
        }
        const address = net.IpAddress.parseIp6(
            target.host[1 .. target.host.len - 1],
            target.port,
        ) catch return error.InvalidServerReference;
        return tcp_connect.ip(io, address, timeout);
    }
    if (net.IpAddress.parseIp4(target.host, target.port)) |address| {
        return tcp_connect.ip(io, address, timeout);
    } else |_| {}

    // Target construction is public, so validate again rather than relying on
    // callers to have obtained it from `redirect.parse`.
    const host_name = net.HostName.init(target.host) catch
        return error.InvalidServerReference;
    return tcp_connect.host(io, host_name, target.port, timeout);
}

/// Return host text suitable for TLS SNI and certificate verification. URI
/// brackets delimit an IPv6 literal but are not part of its TLS identity.
pub fn tlsHost(target: *const redirect.Target) Error![]const u8 {
    if (target.host.len == 0) return error.InvalidServerReference;
    if (target.host[0] != '[') return target.host;
    if (target.host.len < 3 or target.host[target.host.len - 1] != ']') {
        return error.InvalidServerReference;
    }
    return target.host[1 .. target.host.len - 1];
}

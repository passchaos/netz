//! MQTT TCP endpoint connection helpers shared by cleartext and TLS clients.
//!
//! URI parsing owns MQTT-specific policy in `redirect.zig`; this module turns
//! an already-validated target into a socket while preserving one DNS/TCP
//! deadline across every resolved address. Keeping that conversion here lets
//! ordinary URI connects and redirect hops share exactly the same behavior.

const std = @import("std");
const redirect = @import("../redirect.zig");
const tcp_connect = @import("../../internal/tcp_connect.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const address_resolver = @import("../../internal/address_resolver.zig");

const net = std.Io.net;

pub const Error = net.HostName.ValidateError ||
    net.HostName.ConnectError || net.IpAddress.ConnectError ||
    address_resolver.Error || error{
    InvalidAddressConnectPolicy,
    InvalidServerReference,
    UnsupportedRedirectScheme,
};

pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = tcp_connect.AddressConnectPolicy;
pub const HappyEyeballsOptions = tcp_connect.HappyEyeballsOptions;

pub fn connectHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    timeout: ?std.Io.Duration,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(policy);
    if (net.IpAddress.parse(host, port)) |address| {
        return tcp_connect.ip(io, address, timeout);
    } else |_| {}
    const host_name = try net.HostName.init(host);
    if (resolver == null and policy == .ordered) {
        return tcp_connect.host(io, host_name, port, timeout);
    }
    const deadline = try deadline_policy.fromTimeout(io, timeout);
    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            host,
            port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    defer allocator.free(addresses);
    return if (deadline) |absolute|
        tcp_connect.resolvedWithPolicyAndDeadline(
            allocator,
            io,
            addresses,
            absolute,
            policy,
        )
    else
        tcp_connect.resolvedWithPolicy(
            allocator,
            io,
            addresses,
            null,
            policy,
        );
}

pub fn connectHostWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    deadline: std.Io.Clock.Timestamp,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(policy);
    if (net.IpAddress.parse(host, port)) |address| {
        return tcp_connect.ipWithDeadline(io, address, deadline);
    } else |_| {}
    const host_name = try net.HostName.init(host);
    if (resolver == null and policy == .ordered) {
        return tcp_connect.hostWithDeadline(io, host_name, port, deadline);
    }
    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            host,
            port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    defer allocator.free(addresses);
    return tcp_connect.resolvedWithPolicyAndDeadline(
        allocator,
        io,
        addresses,
        deadline,
        policy,
    );
}

pub fn connectHostBound(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(policy);
    if (net.IpAddress.parse(host, port)) |address| {
        return tcp_connect.ipBound(
            io,
            address,
            local_address,
            timeout,
        );
    } else |_| {}
    const host_name = try net.HostName.init(host);
    if (resolver == null and policy == .ordered) {
        return tcp_connect.hostBound(
            io,
            host_name,
            port,
            local_address,
            timeout,
        );
    }
    const deadline = try deadline_policy.fromTimeout(io, timeout);
    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            host,
            port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    defer allocator.free(addresses);
    return if (deadline) |absolute|
        tcp_connect.resolvedBoundWithPolicyAndDeadline(
            allocator,
            io,
            addresses,
            local_address,
            absolute,
            policy,
        )
    else
        tcp_connect.resolvedBoundWithPolicy(
            allocator,
            io,
            addresses,
            local_address,
            null,
            policy,
        );
}

pub fn connectHostBoundWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(policy);
    if (net.IpAddress.parse(host, port)) |address| {
        return tcp_connect.ipBoundWithDeadline(
            io,
            address,
            local_address,
            deadline,
        );
    } else |_| {}
    const host_name = try net.HostName.init(host);
    if (resolver == null and policy == .ordered) {
        return tcp_connect.hostBoundWithDeadline(
            io,
            host_name,
            port,
            local_address,
            deadline,
        );
    }
    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            host,
            port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    defer allocator.free(addresses);
    return tcp_connect.resolvedBoundWithPolicyAndDeadline(
        allocator,
        io,
        addresses,
        local_address,
        deadline,
        policy,
    );
}

pub fn connectTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: *const redirect.Target,
    expected_transport: redirect.Transport,
    timeout: ?std.Io.Duration,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(policy);
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
    if (resolver == null and policy == .ordered) {
        return tcp_connect.host(io, host_name, target.port, timeout);
    }
    const deadline = try deadline_policy.fromTimeout(io, timeout);
    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            target.host,
            target.port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            target.host,
            target.port,
            deadline,
        );
    defer allocator.free(addresses);
    return if (deadline) |absolute|
        tcp_connect.resolvedWithPolicyAndDeadline(
            allocator,
            io,
            addresses,
            absolute,
            policy,
        )
    else
        tcp_connect.resolvedWithPolicy(
            allocator,
            io,
            addresses,
            null,
            policy,
        );
}

pub fn connectTargetWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: *const redirect.Target,
    expected_transport: redirect.Transport,
    deadline: std.Io.Clock.Timestamp,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(policy);
    if (target.transport != expected_transport) {
        return error.UnsupportedRedirectScheme;
    }
    if (target.port == 0 or target.host.len == 0) {
        return error.InvalidServerReference;
    }
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
        return tcp_connect.ipWithDeadline(io, address, deadline);
    }
    if (net.IpAddress.parseIp4(target.host, target.port)) |address| {
        return tcp_connect.ipWithDeadline(io, address, deadline);
    } else |_| {}
    const host_name = net.HostName.init(target.host) catch
        return error.InvalidServerReference;
    if (resolver == null and policy == .ordered) {
        return tcp_connect.hostWithDeadline(io, host_name, target.port, deadline);
    }
    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            target.host,
            target.port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            target.host,
            target.port,
            deadline,
        );
    defer allocator.free(addresses);
    return tcp_connect.resolvedWithPolicyAndDeadline(
        allocator,
        io,
        addresses,
        deadline,
        policy,
    );
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

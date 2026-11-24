//! Deadline-bounded TCP connection establishment for Zig 0.16 `std.Io`.
//!
//! The threaded backend currently rejects `IpAddress.ConnectOptions.timeout`.
//! Racing the normal cancelable connect task against one absolute awake-clock
//! deadline also gives hostname lookup and all address attempts one shared
//! budget. If timeout wins concurrently with a successful connect, deferred
//! select draining closes that unselected socket.
//! Explicit local-address binds use zio's native socket API because Zig 0.16's
//! generic `std.Io` connect operation cannot accept a pre-bound socket.

const std = @import("std");
const zio = @import("zio");
const deadline_policy = @import("deadline.zig");
const happy_eyeballs = @import("tcp_connect/happy_eyeballs.zig");
const binding = @import("tcp_connect/binding.zig");
const socket_binding = @import("socket_binding.zig");
const hostname_connect = @import("tcp_connect/hostname.zig");

pub const NetworkInterface = socket_binding.NetworkInterface;
pub const Binding = socket_binding.Binding;
pub const BindingConnectError = binding.ConnectError;
pub const BindingHostConnectError = binding.HostConnectError;
pub const BindingResolvedConnectError = binding.ResolvedConnectError;
pub const ipWithOptions = binding.ip;
pub const ipWithDeadlineAndOptions = binding.ipWithDeadline;
pub const hostWithOptions = binding.host;
pub const hostWithDeadlineAndOptions = binding.hostWithDeadline;
pub const resolvedWithOptions = binding.resolved;
pub const endpointWithOptions = @import("tcp_connect/endpoint.zig").open;

pub fn validateUnixOptions(options: anytype) error{OptionUnsupported}!void {
    if (Binding.fromOptions(options).isRequested()) return error.OptionUnsupported;
}

const net = std.Io.net;

pub const BoundConnectError = net.IpAddress.ConnectError || error{AddressInUse};

pub const BoundHostConnectError = net.HostName.LookupError ||
    BoundConnectError;
pub const ResolvedConnectError = net.HostName.LookupError ||
    net.IpAddress.ConnectError;
pub const ResolvedBoundConnectError = net.HostName.LookupError ||
    BoundConnectError;
pub const AddressConnectPolicy = happy_eyeballs.Policy;
pub const HappyEyeballsOptions = happy_eyeballs.Options;
pub const ResolvedPolicyConnectError = ResolvedConnectError ||
    happy_eyeballs.Error;
pub const ResolvedBoundPolicyConnectError = ResolvedBoundConnectError ||
    happy_eyeballs.Error;

pub fn validateAddressConnectPolicy(
    policy: AddressConnectPolicy,
) error{InvalidAddressConnectPolicy}!void {
    switch (policy) {
        .ordered => {},
        .happy_eyeballs => |options| try happy_eyeballs.validate(options),
    }
}

pub fn ip(
    io: std.Io,
    address: net.IpAddress,
    timeout: ?std.Io.Duration,
) net.IpAddress.ConnectError!net.Stream {
    const duration = timeout orelse
        return address.connect(io, .{ .mode = .stream });
    const deadline = (try deadline_policy.fromTimeout(io, duration)).?;
    return race(io, deadline, connectIp, .{ io, address });
}

pub fn ipWithDeadline(
    io: std.Io,
    address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) net.IpAddress.ConnectError!net.Stream {
    return race(
        io,
        try deadline_policy.usableAwake(io, deadline),
        connectIp,
        .{ io, address },
    );
}

/// Establish a TCP stream after binding its socket to `local_address`.
///
/// Zig 0.16's generic `std.Io` connect operation cannot bind an existing
/// socket. Netz's production zio backend exposes that operation directly; a
/// foreign backend is rejected rather than silently ignoring the requested
/// source address.
pub fn ipBound(
    io: std.Io,
    address: net.IpAddress,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
) BoundConnectError!net.Stream {
    return connectBoundZio(
        io,
        address,
        local_address,
        if (timeout) |duration| zio.Timeout.fromNanoseconds(
            durationNanoseconds(duration),
        ) else .none,
    );
}

pub fn ipBoundWithDeadline(
    io: std.Io,
    address: net.IpAddress,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) BoundConnectError!net.Stream {
    const usable = try deadline_policy.usableAwake(io, deadline);
    return connectBoundZio(
        io,
        address,
        local_address,
        zio.Timeout.fromNanoseconds(durationNanoseconds(
            usable.durationFromNow(io).raw,
        )),
    );
}

pub fn host(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    timeout: ?std.Io.Duration,
) net.HostName.ConnectError!net.Stream {
    const duration = timeout orelse
        return connectHost(io, host_name, port);
    const deadline = (try deadline_policy.fromTimeout(io, duration)).?;
    return race(io, deadline, connectHost, .{ io, host_name, port });
}

pub fn hostWithDeadline(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    deadline: std.Io.Clock.Timestamp,
) net.HostName.ConnectError!net.Stream {
    return race(
        io,
        try deadline_policy.usableAwake(io, deadline),
        connectHost,
        .{ io, host_name, port },
    );
}

/// Try caller-resolved addresses in order under one optional timeout.
pub fn resolved(
    io: std.Io,
    addresses: []const net.IpAddress,
    timeout: ?std.Io.Duration,
) ResolvedConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedBefore(io, addresses, deadline);
}

pub fn resolvedWithDeadline(
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) ResolvedConnectError!net.Stream {
    return resolvedBefore(
        io,
        addresses,
        try deadline_policy.usableAwake(io, deadline),
    );
}

pub fn resolvedWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    timeout: ?std.Io.Duration,
    policy: AddressConnectPolicy,
) ResolvedPolicyConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedWithPolicyBefore(
        allocator,
        io,
        addresses,
        deadline,
        policy,
    );
}

pub fn resolvedWithPolicyAndDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedPolicyConnectError!net.Stream {
    return resolvedWithPolicyBefore(
        allocator,
        io,
        addresses,
        try deadline_policy.usableAwake(io, deadline),
        policy,
    );
}

fn resolvedWithPolicyBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedPolicyConnectError!net.Stream {
    return switch (policy) {
        .ordered => resolvedBefore(io, addresses, deadline),
        .happy_eyeballs => |options| happy_eyeballs.connect(
            net.IpAddress.ConnectError,
            allocator,
            io,
            addresses,
            options,
            deadline,
            {},
            connectResolvedIp,
            shouldTryNextResolvedAddress,
        ),
    };
}

fn resolvedBefore(
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) ResolvedConnectError!net.Stream {
    var last_error: ?net.IpAddress.ConnectError = null;
    for (addresses) |address| {
        const stream = if (deadline) |absolute|
            ipWithDeadline(io, address, absolute)
        else
            ip(io, address, null);
        return stream catch |err| {
            if (!shouldTryNextResolvedAddress(err)) return err;
            last_error = err;
            continue;
        };
    }
    return last_error orelse error.NoAddressReturned;
}

/// Try caller-resolved addresses in order after binding each candidate socket
/// to `local_address`. All candidates share one optional absolute deadline.
pub fn resolvedBound(
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
) ResolvedBoundConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedBoundBefore(io, addresses, local_address, deadline);
}

pub fn resolvedBoundWithDeadline(
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) ResolvedBoundConnectError!net.Stream {
    return resolvedBoundBefore(
        io,
        addresses,
        local_address,
        try deadline_policy.usableAwake(io, deadline),
    );
}

pub fn resolvedBoundWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
    policy: AddressConnectPolicy,
) ResolvedBoundPolicyConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedBoundWithPolicyBefore(
        allocator,
        io,
        addresses,
        local_address,
        deadline,
        policy,
    );
}

pub fn resolvedBoundWithPolicyAndDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedBoundPolicyConnectError!net.Stream {
    return resolvedBoundWithPolicyBefore(
        allocator,
        io,
        addresses,
        local_address,
        try deadline_policy.usableAwake(io, deadline),
        policy,
    );
}

fn resolvedBoundWithPolicyBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedBoundPolicyConnectError!net.Stream {
    return switch (policy) {
        .ordered => resolvedBoundBefore(
            io,
            addresses,
            local_address,
            deadline,
        ),
        .happy_eyeballs => |options| happy_eyeballs.connect(
            BoundConnectError,
            allocator,
            io,
            addresses,
            options,
            deadline,
            local_address,
            connectResolvedBoundIp,
            shouldTryNextResolvedAddress,
        ),
    };
}

fn resolvedBoundBefore(
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) ResolvedBoundConnectError!net.Stream {
    var last_error: ?BoundConnectError = null;
    for (addresses) |address| {
        const stream = if (deadline) |absolute|
            ipBoundWithDeadline(io, address, local_address, absolute)
        else
            ipBound(io, address, local_address, null);
        return stream catch |err| {
            if (!shouldTryNextResolvedAddress(err)) return err;
            last_error = err;
            continue;
        };
    }
    return last_error orelse error.NoAddressReturned;
}

pub fn shouldTryNextResolvedAddress(err: anyerror) bool {
    return switch (err) {
        error.AddressFamilyUnsupported,
        error.AddressUnavailable,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.ProtocolUnsupportedByAddressFamily,
        error.ProtocolUnsupportedBySystem,
        error.SocketUnconnected,
        => true,
        else => false,
    };
}

pub fn hostBound(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
) BoundHostConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return connectHostBoundBefore(
        io,
        host_name,
        port,
        local_address,
        deadline,
    );
}

pub fn hostBoundWithDeadline(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) BoundHostConnectError!net.Stream {
    return connectHostBoundBefore(
        io,
        host_name,
        port,
        local_address,
        try deadline_policy.usableAwake(io, deadline),
    );
}

fn connectHostBoundBefore(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    local_address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) BoundHostConnectError!net.Stream {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    return if (deadline) |absolute|
        race(io, absolute, connectHostBound, .{ io, host_name, port, local_address })
    else
        connectHostBound(io, host_name, port, local_address);
}

fn connectHostBound(io: std.Io, host_name: net.HostName, port: u16, local_address: net.IpAddress) BoundHostConnectError!net.Stream {
    return hostname_connect.connect(
        BoundConnectError,
        io,
        host_name,
        .{ .port = port, .family = std.meta.activeTag(local_address) },
        local_address,
        connectHostBoundCandidate,
        shouldTryNextResolvedAddress,
    );
}

fn connectHostBoundCandidate(local_address: net.IpAddress, io: std.Io, address: net.IpAddress) BoundConnectError!net.Stream {
    return ipBound(io, address, local_address, null);
}

fn connectBoundZio(io: std.Io, address: net.IpAddress, local_address: net.IpAddress, timeout: zio.Timeout) BoundConnectError!net.Stream {
    return socket_binding.connect(io, address, .{ .local_address = local_address }, timeout) catch |err| switch (err) {
        // This compatibility API never requests an interface option.
        error.InterfaceNotFound, error.NameTooLong, error.InvalidNetworkInterface, error.SocketOptionFailed => unreachable,
        else => |other| return other,
    };
}

fn durationNanoseconds(duration: std.Io.Duration) u64 {
    if (duration.nanoseconds <= 0) return 0;
    return @intCast(@min(duration.nanoseconds, std.math.maxInt(u64)));
}

pub fn unix(
    io: std.Io,
    address: net.UnixAddress,
    timeout: ?std.Io.Duration,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    const duration = timeout orelse return address.connect(io);
    const deadline = (try deadline_policy.fromTimeout(io, duration)).?;
    return race(io, deadline, connectUnix, .{ io, address });
}

pub fn unixWithDeadline(
    io: std.Io,
    address: net.UnixAddress,
    deadline: std.Io.Clock.Timestamp,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    return race(
        io,
        try deadline_policy.usableAwake(io, deadline),
        connectUnix,
        .{ io, address },
    );
}

pub fn race(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    comptime connect_fn: anytype,
    args: std.meta.ArgsTuple(@TypeOf(connect_fn)),
) @typeInfo(@TypeOf(connect_fn)).@"fn".return_type.? {
    const ConnectResult = @typeInfo(@TypeOf(connect_fn)).@"fn".return_type.?;
    const Wake = union(enum) {
        connected: ConnectResult,
        timeout: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .connected => |result| if (result) |stream| {
            stream.close(io);
        } else |_| {},
        .timeout => {},
    };
    // Reserve real concurrency for both halves. An inline async fallback can
    // block the connector or wait out the entire deadline after a connection
    // has already completed. Socket connect APIs report resource admission
    // failure through their standard SystemResources error.
    select.concurrent(.timeout, waitUntil, .{ io, deadline }) catch return error.SystemResources;
    select.concurrent(.connected, connect_fn, args) catch return error.SystemResources;
    return switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .connected => |result| result,
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    };
}

fn connectIp(
    io: std.Io,
    address: net.IpAddress,
) net.IpAddress.ConnectError!net.Stream {
    return address.connect(io, .{ .mode = .stream });
}

fn connectResolvedIp(
    _: void,
    io: std.Io,
    address: net.IpAddress,
    _: ?std.Io.Clock.Timestamp,
) net.IpAddress.ConnectError!net.Stream {
    return connectIp(io, address);
}

fn connectResolvedBoundIp(
    local_address: net.IpAddress,
    io: std.Io,
    address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) BoundConnectError!net.Stream {
    return if (deadline) |absolute|
        ipBoundWithDeadline(io, address, local_address, absolute)
    else
        ipBound(io, address, local_address, null);
}

fn connectHost(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
) net.HostName.ConnectError!net.Stream {
    return hostname_connect.connect(
        net.IpAddress.ConnectError,
        io,
        host_name,
        .{ .port = port },
        {},
        connectHostCandidate,
        shouldTryNextResolvedAddress,
    );
}

fn connectHostCandidate(_: void, io: std.Io, address: net.IpAddress) net.IpAddress.ConnectError!net.Stream {
    return connectIp(io, address);
}

fn connectUnix(
    io: std.Io,
    address: net.UnixAddress,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    return address.connect(io);
}

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

test {
    _ = @import("tcp_connect/tests.zig");
    _ = @import("tcp_connect/binding_tests.zig");
    _ = @import("tcp_connect/hostname_tests.zig");
    _ = @import("tcp_connect/hostname_binding_tests.zig");
}

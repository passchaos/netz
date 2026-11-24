//! TCP binding policy shared by protocol-specific connection owners.
const std = @import("std");
const zio = @import("zio");
const tcp = @import("../tcp_connect.zig");
const sockets = @import("../socket_binding.zig");
const deadlines = @import("../deadline.zig");
const happy_eyeballs = @import("happy_eyeballs.zig");
const net = std.Io.net;

pub const Binding = sockets.Binding;
pub const ConnectError = sockets.ConnectError;
pub const HostConnectError = ConnectError || net.HostName.LookupError;
pub const ResolvedConnectError = HostConnectError || happy_eyeballs.Error;

pub fn ip(io: std.Io, address: net.IpAddress, timeout: ?std.Io.Duration, options: anytype) ConnectError!net.Stream {
    const binding = Binding.fromOptions(options);
    if (!binding.isRequested()) return tcp.ip(io, address, timeout);
    if (try deadlines.fromTimeout(io, timeout)) |deadline| return tcp.race(io, deadline, connect, .{ io, address, binding });
    return connect(io, address, binding);
}

pub fn ipWithDeadline(io: std.Io, address: net.IpAddress, deadline: std.Io.Clock.Timestamp, options: anytype) ConnectError!net.Stream {
    const binding = Binding.fromOptions(options);
    if (!binding.isRequested()) return tcp.ipWithDeadline(io, address, deadline);
    return tcp.race(io, try deadlines.usableAwake(io, deadline), connect, .{ io, address, binding });
}

pub fn host(io: std.Io, hostname: net.HostName, port: u16, timeout: ?std.Io.Duration, options: anytype) HostConnectError!net.Stream {
    const binding = Binding.fromOptions(options);
    if (!binding.isRequested()) return tcp.host(io, hostname, port, timeout);
    if (try deadlines.fromTimeout(io, timeout)) |deadline| return tcp.race(io, deadline, connectHost, .{ io, hostname, port, binding });
    return connectHost(io, hostname, port, binding);
}

pub fn hostWithDeadline(io: std.Io, hostname: net.HostName, port: u16, deadline: std.Io.Clock.Timestamp, options: anytype) HostConnectError!net.Stream {
    const binding = Binding.fromOptions(options);
    if (!binding.isRequested()) return tcp.hostWithDeadline(io, hostname, port, deadline);
    return tcp.race(io, try deadlines.usableAwake(io, deadline), connectHost, .{ io, hostname, port, binding });
}

pub fn resolved(allocator: std.mem.Allocator, io: std.Io, addresses: []const net.IpAddress, deadline: ?std.Io.Clock.Timestamp, policy: tcp.AddressConnectPolicy, options: anytype) ResolvedConnectError!net.Stream {
    const binding = Binding.fromOptions(options);
    if (!binding.isRequested()) return if (deadline) |until|
        tcp.resolvedWithPolicyAndDeadline(allocator, io, addresses, until, policy)
    else
        tcp.resolvedWithPolicy(allocator, io, addresses, null, policy);
    try tcp.validateAddressConnectPolicy(policy);
    if (deadline) |until| _ = try deadlines.usableAwake(io, until);
    return switch (policy) {
        .ordered => ordered(io, addresses, binding, deadline),
        .happy_eyeballs => |race| happy_eyeballs.connect(ConnectError, allocator, io, addresses, race, deadline, binding, candidate, tcp.shouldTryNextResolvedAddress),
    };
}

fn ordered(io: std.Io, addresses: []const net.IpAddress, binding: Binding, deadline: ?std.Io.Clock.Timestamp) HostConnectError!net.Stream {
    var last_error: ?ConnectError = null;
    for (addresses) |address| {
        return candidate(binding, io, address, deadline) catch |err| {
            if (!tcp.shouldTryNextResolvedAddress(err)) return err;
            last_error = err;
            continue;
        };
    }
    return last_error orelse error.NoAddressReturned;
}

fn candidate(binding: Binding, io: std.Io, address: net.IpAddress, deadline: ?std.Io.Clock.Timestamp) ConnectError!net.Stream {
    return if (deadline) |until| ipWithDeadline(io, address, until, binding) else connect(io, address, binding);
}

fn connect(io: std.Io, address: net.IpAddress, binding: Binding) ConnectError!net.Stream {
    return sockets.connect(io, address, binding, .none);
}

fn connectHost(io: std.Io, hostname: net.HostName, port: u16, binding: Binding) HostConnectError!net.Stream {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    var buffer: [32]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&buffer);
    var lookup = io.async(net.HostName.lookup, .{ hostname, io, &queue, .{
        .port = port,
        .family = if (binding.local_address) |address| std.meta.activeTag(address) else null,
    } });
    defer {
        lookup.cancel(io) catch {};
        while (queue.getOneUncancelable(io)) |_| {} else |err| switch (err) {
            error.Closed => {},
        }
    }
    var last_error: ?ConnectError = null;
    while (queue.getOne(io)) |result| switch (result) {
        .canonical_name => {},
        .address => |address| return connect(io, address, binding) catch |err| {
            if (!tcp.shouldTryNextResolvedAddress(err)) return err;
            last_error = err;
            continue;
        },
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {
            try lookup.await(io);
            return last_error orelse error.UnknownHostName;
        },
    }
}

//! Resolver/connection policy boundary shared by HTTP, WS and SOCKS routes.
const std = @import("std");
const tcp = @import("../tcp_connect.zig");
const addresses = @import("../address_resolver.zig");
const deadlines = @import("../deadline.zig");

pub const Error = tcp.BindingResolvedConnectError || addresses.Error || std.Io.net.HostName.ValidateError;

pub fn open(allocator: std.mem.Allocator, io: std.Io, literal: ?std.Io.net.IpAddress, hostname: []const u8, port: u16, resolver: ?addresses.Resolver, policy: tcp.AddressConnectPolicy, deadline: ?std.Io.Clock.Timestamp, binding: tcp.Binding) Error!std.Io.net.Stream {
    try tcp.validateAddressConnectPolicy(policy);
    if (deadline) |absolute| _ = try deadlines.usableAwake(io, absolute);
    if (literal) |address| return if (deadline) |until|
        tcp.ipWithDeadlineAndOptions(io, address, until, binding)
    else
        tcp.ipWithOptions(io, address, null, binding);
    if (resolver == null and policy == .ordered) {
        const host = try std.Io.net.HostName.init(hostname);
        return if (deadline) |until|
            tcp.hostWithDeadlineAndOptions(io, host, port, until, binding)
        else
            tcp.hostWithOptions(io, host, port, null, binding);
    }
    const resolved = if (resolver) |configured|
        try configured.resolve(configured.context, allocator, io, hostname, port, deadline)
    else
        try addresses.resolveSystem(allocator, io, hostname, port, deadline);
    defer allocator.free(resolved);
    return tcp.resolvedWithOptions(allocator, io, resolved, deadline, policy, binding);
}

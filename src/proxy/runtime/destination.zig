//! ACL-checked destination resolution and TCP connection establishment.
//!
//! Both SOCKS and HTTP CONNECT share this policy path so a domain rule can
//! never bypass a deny rule on a resolved address. Domain resolution returns
//! every unique address; candidates are filtered before any connection is
//! attempted.

const std = @import("std");

const net = std.Io.net;
const acl = @import("acl.zig");
const reload = @import("reload.zig");
const resolve = @import("../internal/resolve.zig");
const connect = @import("../internal/connect.zig");
const io_helpers = @import("../internal/io.zig");

pub const Domain = struct {
    host: []const u8,
    port: u16,
};

pub const Target = union(enum) {
    ip: net.IpAddress,
    domain: Domain,
};

pub const Error = error{
    DestinationDenied,
    NoAllowedAddress,
    UnknownHostName,
} || resolve.Error || connect.Error;

/// Connect to a target after applying the ACL to both the textual authority
/// and every resolved address.
pub fn connectTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    policy: acl.Policy,
    target: Target,
    command: acl.Command,
    timeout: std.Io.Duration,
) !net.Stream {
    const deadline = try io_helpers.deadlineFromTimeout(io, timeout);
    return switch (target) {
        .ip => |ip| {
            if (policy.decideIp(ip, ip.getPort(), command) != .allow) {
                return error.DestinationDenied;
            }
            return connect.ipWithDeadline(io, ip, deadline);
        },
        .domain => |domain| {
            const allowed = try allowedAddresses(
                allocator,
                io,
                policy,
                domain,
                command,
                deadline,
            );
            defer allocator.free(allowed);
            if (allowed.len == 0) return error.DestinationDenied;
            return connect.resolvedWithDeadline(io, allowed, deadline);
        },
    };
}

/// Snapshot a reloadable policy and connect with the resulting rule set.
pub fn connectTargetReloadable(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *reload.Reloadable,
    target: Target,
    command: acl.Command,
    timeout: std.Io.Duration,
) !net.Stream {
    const snapshot = store.snapshot();
    return connectTarget(
        allocator,
        io,
        snapshot.policy,
        target,
        command,
        timeout,
    );
}

/// Resolve one UDP destination after applying the ACL. Domain rules are
/// evaluated first; explicit IP deny rules still win for resolved addresses.
pub fn resolveTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    policy: acl.Policy,
    target: Target,
    command: acl.Command,
    timeout: std.Io.Duration,
) !net.IpAddress {
    const deadline = try io_helpers.deadlineFromTimeout(io, timeout);
    return switch (target) {
        .ip => |ip| {
            if (policy.decideIp(ip, ip.getPort(), command) != .allow) {
                return error.DestinationDenied;
            }
            return ip;
        },
        .domain => |domain| {
            const allowed = try allowedAddresses(
                allocator,
                io,
                policy,
                domain,
                command,
                deadline,
            );
            defer allocator.free(allowed);
            if (allowed.len == 0) return error.DestinationDenied;
            return allowed[0];
        },
    };
}

fn allowedAddresses(
    allocator: std.mem.Allocator,
    io: std.Io,
    policy: acl.Policy,
    domain: Domain,
    command: acl.Command,
    deadline: ?std.Io.Clock.Timestamp,
) ![]net.IpAddress {
    const domain_decision = policy.evaluateDomain(
        domain.host,
        domain.port,
        command,
    );
    if (domain_decision == .deny) return error.DestinationDenied;

    const addresses = resolve.resolveHost(
        allocator,
        io,
        domain.host,
        domain.port,
        deadline,
    ) catch |err| switch (err) {
        error.NoAddressReturned => return error.UnknownHostName,
        else => return err,
    };
    defer allocator.free(addresses);

    const allowed = try allocator.alloc(net.IpAddress, addresses.len);
    errdefer allocator.free(allowed);
    var count: usize = 0;
    for (addresses) |ip| {
        const decision = policy.evaluateIp(
            ip,
            ip.getPort(),
            command,
        ) orelse domain_decision orelse policy.default_action;
        if (decision == .allow) {
            allowed[count] = ip;
            count += 1;
        }
    }
    return allocator.realloc(allowed, count);
}

test "destination ACL denies an IPv4 target by default" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.DestinationDenied,
        connectTarget(
            allocator,
            io,
            .{},
            .{ .ip = .{ .ip4 = .loopback(1) } },
            .connect,
            .fromSeconds(1),
        ),
    );
}

test "destination ACL rejects an explicitly denied domain before resolving" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const rules = [_]acl.Rule{.{
        .action = .deny,
        .matcher = .{ .domain = try acl.DomainMatch.parse("*.example.com") },
    }};
    try std.testing.expectError(
        error.DestinationDenied,
        connectTarget(
            allocator,
            io,
            .{ .rules = &rules },
            .{ .domain = .{ .host = "api.example.com", .port = 443 } },
            .connect,
            .fromSeconds(1),
        ),
    );
}

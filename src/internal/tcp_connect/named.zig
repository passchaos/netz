//! DNS/IP connection identity, default authority and one shared connect budget.
const std = @import("std");
const endpoint_host = @import("../endpoint_host.zig");
const tcp = @import("../tcp_connect.zig");
const deadline_policy = @import("../deadline.zig");

pub const Opened = struct {
    stream: std.Io.net.Stream,
    authority: []u8,
    identity: []const u8,
};

pub const Error = tcp.EndpointConnectError;

/// The caller owns stream and authority on success. Parse/budget/OOM rejection
/// happens before network admission; a failed connect releases the authority.
pub fn open(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, options: anytype, deadline: ?std.Io.Clock.Timestamp) Error!Opened {
    const parsed = try endpoint_host.parse(host, port);
    const resolver = if (@hasField(@TypeOf(options), "address_resolver")) options.address_resolver else null;
    const configured_policy: ?tcp.AddressConnectPolicy = if (@hasField(@TypeOf(options), "address_connect_policy")) options.address_connect_policy else null;
    const policy = configured_policy orelse .ordered;
    try tcp.validateAddressConnectPolicy(policy);
    const until = if (deadline) |value| try deadline_policy.capTimeout(io, value, options.connect_timeout) else try deadline_policy.fromTimeout(io, options.connect_timeout);
    const authority = try parsed.authorityAlloc(allocator, port);
    errdefer allocator.free(authority);
    const stream = try tcp.endpointWithOptions(allocator, io, parsed.literal, parsed.host, port, resolver, policy, until, .fromOptions(options));
    return .{ .stream = stream, .authority = authority, .identity = parsed.host };
}

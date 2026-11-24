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

pub const Error = std.mem.Allocator.Error || tcp.BindingHostConnectError || std.Io.net.HostName.ValidateError;

/// The caller owns stream and authority on success. Parse/budget/OOM rejection
/// happens before network admission; a failed connect releases the authority.
pub fn open(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, options: anytype, deadline: ?std.Io.Clock.Timestamp) Error!Opened {
    const parsed = try endpoint_host.parse(host, port);
    const until = if (deadline) |value| try deadline_policy.capTimeout(io, value, options.connect_timeout) else try deadline_policy.fromTimeout(io, options.connect_timeout);
    const authority = try parsed.authorityAlloc(allocator, port);
    errdefer allocator.free(authority);
    const stream = if (parsed.literal) |address|
        if (until) |value| try tcp.ipWithDeadlineAndOptions(io, address, value, options) else try tcp.ipWithOptions(io, address, null, options)
    else if (until) |value|
        try tcp.hostWithDeadlineAndOptions(io, try std.Io.net.HostName.init(parsed.host), port, value, options)
    else
        try tcp.hostWithOptions(io, try std.Io.net.HostName.init(parsed.host), port, null, options);
    return .{ .stream = stream, .authority = authority, .identity = parsed.host };
}

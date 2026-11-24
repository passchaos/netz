//! Validate and open one DNS/IP route while retaining its logical identity.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const endpoint_host = @import("../../../internal/endpoint_host.zig");
const tcp = @import("../../../internal/tcp_connect.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Opened = struct {
    stream: std.Io.net.Stream,
    authority: []u8,
    identity: []const u8,
};

/// The caller takes both resources on success. Parse/budget/OOM rejection
/// happens before network admission; a failed connect releases the authority.
pub fn open(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, limits: runtime.Limits, deadline: ?std.Io.Clock.Timestamp) runtime.Error!Opened {
    const parsed = try endpoint_host.parse(host, port);
    const until = if (deadline) |value| try deadline_policy.capTimeout(io, value, limits.connect_timeout) else try deadline_policy.fromTimeout(io, limits.connect_timeout);
    const authority = try parsed.authorityAlloc(allocator, port);
    errdefer allocator.free(authority);
    const stream = if (parsed.literal) |address|
        if (until) |value| try tcp.ipWithDeadlineAndOptions(io, address, value, limits) else try tcp.ipWithOptions(io, address, null, limits)
    else if (until) |value|
        try tcp.hostWithDeadlineAndOptions(io, try std.Io.net.HostName.init(parsed.host), port, value, limits)
    else
        try tcp.hostWithOptions(io, try std.Io.net.HostName.init(parsed.host), port, null, limits);
    return .{ .stream = stream, .authority = authority, .identity = parsed.host };
}

test "HTTP/2 host connection validates literal budgets and OOM before network admission" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const allocator = failing.allocator();
    try std.testing.expectError(error.InvalidHostName, open(allocator, undefined, "[::1]:443", 443, .{}, null));
    try std.testing.expectError(error.Timeout, open(allocator, undefined, "::1", 443, .{ .connect_timeout = .zero }, null));
    try std.testing.expectError(error.Timeout, open(allocator, undefined, "::1", 443, .{}, .{ .clock = .real, .raw = .zero }));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectError(error.OutOfMemory, open(allocator, undefined, "::1", 443, .{}, null));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

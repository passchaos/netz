//! Validate and open one DNS/IP route while retaining its logical identity.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const named = @import("../../../internal/tcp_connect/named.zig");

pub const Opened = named.Opened;

/// Retain the public H2 limits/error shape over the shared DNS/IP boundary.
pub fn open(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, limits: runtime.Limits, deadline: ?std.Io.Clock.Timestamp) runtime.Error!Opened {
    return named.open(allocator, io, host, port, limits, deadline);
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

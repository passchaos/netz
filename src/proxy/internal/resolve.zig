//! Bounded hostname resolution with an optional absolute deadline.
//!
//! Proxy servers must apply ACLs to the actual destination addresses rather
//! than only to the untrusted textual hostname. This helper returns every
//! unique address so the caller can filter candidates before connecting.

const std = @import("std");

const address_resolver = @import("../../internal/address_resolver.zig");

pub const Error = address_resolver.Error;

/// Resolve all unique system addresses into caller-owned storage. Shared DNS
/// scheduling and cancellation keep the proxy's ACL candidate list complete.
pub const resolveHost = address_resolver.resolveSystem;

test "resolve localhost returns bounded allocator-owned addresses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const addresses = try resolveHost(allocator, io, "localhost", 80, null);
    defer allocator.free(addresses);
    try std.testing.expect(addresses.len > 0);
    for (addresses) |address| {
        try std.testing.expectEqual(@as(u16, 80), address.getPort());
    }
}

test "resolve rejects an expired deadline before lookup" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        resolveHost(
            allocator,
            io,
            "localhost",
            80,
            .{ .raw = .zero, .clock = .awake },
        ),
    );
}

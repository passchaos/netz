//! Bounded hostname resolution with an optional absolute deadline.
//!
//! Proxy servers must apply ACLs to the actual destination addresses rather
//! than only to the untrusted textual hostname. This helper returns every
//! unique address so the caller can filter candidates before connecting.

const std = @import("std");

const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || net.HostName.ValidateError ||
    net.HostName.LookupError || std.Io.Timeout.Error || error{
    NoAddressReturned,
};

/// Resolve `host` into allocator-owned addresses. The caller owns the
/// returned slice and must free it with `allocator`.
pub fn resolveHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    const host_name = try net.HostName.init(host);
    const absolute = deadline orelse
        return resolveAll(allocator, io, host_name, port);
    if (absolute.durationFromNow(io).raw.nanoseconds <= 0) {
        return error.Timeout;
    }

    const ResolveResult = Error![]net.IpAddress;
    const Wake = union(enum) {
        resolved: ResolveResult,
        timeout: std.Io.Cancelable!void,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_storage);
    defer while (select.cancel()) |wake| switch (wake) {
        .resolved => |result| if (result) |addresses| {
            allocator.free(addresses);
        } else |_| {},
        .timeout => {},
    };
    select.async(
        .resolved,
        resolveAll,
        .{ allocator, io, host_name, port },
    );
    select.async(.timeout, waitUntil, .{ io, absolute });
    return switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .resolved => |result| try result,
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    };
}

fn resolveAll(
    allocator: std.mem.Allocator,
    io: std.Io,
    host_name: net.HostName,
    port: u16,
) Error![]net.IpAddress {
    var lookup_storage: [16]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) =
        .init(&lookup_storage);
    var lookup = io.async(
        net.HostName.lookup,
        .{ host_name, io, &lookup_queue, .{ .port = port } },
    );
    defer {
        lookup.cancel(io) catch {};
        while (lookup_queue.getOneUncancelable(io)) |_| {} else |err| switch (err) {
            error.Closed => {},
        }
    }

    var addresses: std.ArrayList(net.IpAddress) = .empty;
    errdefer addresses.deinit(allocator);
    while (lookup_queue.getOne(io)) |result| switch (result) {
        .canonical_name => {},
        .address => |address| {
            for (addresses.items) |*existing| {
                if (existing.eql(&address)) break;
            } else try addresses.append(allocator, address);
        },
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => try lookup.await(io),
    }
    if (addresses.items.len == 0) return error.NoAddressReturned;
    return addresses.toOwnedSlice(allocator);
}

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

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

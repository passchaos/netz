//! Protocol-independent asynchronous address resolution contract.

const std = @import("std");

const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || net.HostName.ValidateError ||
    net.HostName.LookupError || std.Io.Timeout.Error;

pub const Resolver = struct {
    pub const ResolveError = Error;

    context: *anyopaque,
    /// Calls may overlap for independent routes. Implementations must be
    /// thread-safe, honor cancellation and the optional absolute deadline via
    /// `io`, and return a slice owned by `allocator`.
    resolve: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![]net.IpAddress,
};

/// Resolve every unique system address into allocator-owned storage. The
/// optional deadline bounds the complete lookup rather than each queue read.
pub fn resolveSystem(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    const host_name = try net.HostName.init(host);
    const absolute = deadline orelse
        return resolveHostAddresses(allocator, io, host_name, port);
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
        resolveHostAddresses,
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

fn resolveHostAddresses(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: net.HostName,
    port: u16,
) Error![]net.IpAddress {
    var lookup_storage: [16]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) =
        .init(&lookup_storage);
    var lookup = io.async(
        net.HostName.lookup,
        .{ host, io, &lookup_queue, .{ .port = port } },
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

test "system address resolver returns allocator-owned unique addresses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const addresses = try resolveSystem(
        std.testing.allocator,
        threaded.io(),
        "localhost",
        443,
        null,
    );
    defer std.testing.allocator.free(addresses);
    try std.testing.expect(addresses.len != 0);
    for (addresses, 0..) |*address, index| {
        try std.testing.expectEqual(@as(u16, 443), address.getPort());
        for (addresses[0..index]) |*previous| {
            try std.testing.expect(!address.eql(previous));
        }
    }
}

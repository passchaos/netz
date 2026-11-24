//! Protocol-independent asynchronous address resolution contract.

const std = @import("std");
const deadline_policy = @import("deadline.zig");
const lookup = @import("address_resolver/lookup.zig");

const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || net.HostName.ValidateError ||
    net.HostName.LookupError || std.Io.Timeout.Error || std.Io.ConcurrentError;

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
/// Requires concurrency so a bounded DNS queue can always be consumed while
/// the producer runs; unsupported admission fails before falling back inline.
pub fn resolveSystem(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    return resolveHostBefore(allocator, io, try net.HostName.init(host), port, deadline);
}

pub fn resolveHostBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    const absolute = deadline orelse
        return lookup.all(allocator, io, host_name, port);
    _ = try deadline_policy.usableAwake(io, absolute);
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
    try select.concurrent(
        .resolved,
        lookup.all,
        .{ allocator, io, host_name, port },
    );
    try select.concurrent(.timeout, waitUntil, .{ io, absolute });
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

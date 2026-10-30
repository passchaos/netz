//! Shared RFC 8305 address planning for connection-oriented transports.
//!
//! Transport modules retain ownership of their attempt state and cleanup, but
//! use one public policy and one stable family interleaving rule so TCP and
//! QUIC do not drift into subtly different resolver semantics.

const std = @import("std");

const net = std.Io.net;
const connection_race = @import("connection_race.zig");
const stack_address_capacity: usize = 8;

pub const Error = connection_race.Error;

pub const Options = struct {
    /// Delay between overlapping connection attempts. RFC 8305 recommends
    /// 250 ms; applications may tune this from measured network data.
    attempt_delay: std.Io.Duration = .fromMilliseconds(250),
    /// Bound on concurrent connection attempts. Two covers the common
    /// IPv6/IPv4 race without allowing a large DNS answer to exhaust sockets.
    max_in_flight: usize = 2,
};

pub const Policy = union(enum) {
    /// Preserve the resolver's exact order and try one address at a time.
    ordered,
    /// Stable-interleave address families and start attempts with a delay.
    happy_eyeballs: Options,
};

pub fn validate(options: Options) error{InvalidAddressConnectPolicy}!void {
    if (options.attempt_delay.nanoseconds <= 0 or
        options.max_in_flight == 0)
    {
        return error.InvalidAddressConnectPolicy;
    }
}

pub fn interleaveAddressFamilies(
    out: []net.IpAddress,
    addresses: []const net.IpAddress,
) void {
    std.debug.assert(out.len == addresses.len);
    if (addresses.len == 0) return;
    const preferred = std.meta.activeTag(addresses[0]);
    const alternate: std.meta.Tag(net.IpAddress) = switch (preferred) {
        .ip4 => .ip6,
        .ip6 => .ip4,
    };
    var preferred_cursor: usize = 0;
    var alternate_cursor: usize = 0;
    var want_preferred = true;
    for (out) |*output| {
        if (want_preferred) {
            if (nextFamily(addresses, preferred, &preferred_cursor)) |value| {
                output.* = value;
                want_preferred = false;
                continue;
            }
        } else if (nextFamily(addresses, alternate, &alternate_cursor)) |value| {
            output.* = value;
            want_preferred = true;
            continue;
        }
        output.* = nextFamily(
            addresses,
            if (want_preferred) alternate else preferred,
            if (want_preferred) &alternate_cursor else &preferred_cursor,
        ).?;
    }
}

/// Race already-resolved addresses while leaving transport-specific attempt
/// construction and successful-loser cleanup with the caller. Every worker
/// publishes its owned result into a stable slot before waking the selector,
/// so cancellation cannot lose a connection that completed concurrently.
pub fn race(
    comptime ConnectError: type,
    comptime Connected: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    options: Options,
    deadline: ?std.Io.Clock.Timestamp,
    deadline_error: ?ConnectError,
    context: anytype,
    comptime connect_one: anytype,
    comptime deinit_connected: anytype,
    comptime should_try_next: anytype,
) (ConnectError || Error)!Connected {
    if (addresses.len == 0) return error.NoAddressReturned;
    try validate(options);
    std.debug.assert((deadline == null) == (deadline_error == null));

    var ordered_stack: [stack_address_capacity]net.IpAddress = undefined;
    const ordered_heap = if (addresses.len > ordered_stack.len)
        try allocator.alloc(net.IpAddress, addresses.len)
    else
        null;
    defer if (ordered_heap) |storage| allocator.free(storage);
    const ordered = ordered_heap orelse ordered_stack[0..addresses.len];
    interleaveAddressFamilies(ordered, addresses);

    return connection_race.race(
        ConnectError,
        Connected,
        allocator,
        io,
        ordered,
        .{ .attempt_delay = options.attempt_delay, .max_in_flight = options.max_in_flight },
        deadline,
        deadline_error,
        context,
        connect_one,
        deinit_connected,
        should_try_next,
    );
}

fn nextFamily(
    addresses: []const net.IpAddress,
    family: std.meta.Tag(net.IpAddress),
    cursor: *usize,
) ?net.IpAddress {
    while (cursor.* < addresses.len) : (cursor.* += 1) {
        const address = addresses[cursor.*];
        if (std.meta.activeTag(address) != family) continue;
        cursor.* += 1;
        return address;
    }
    return null;
}

test "Happy Eyeballs stable-interleaves address families" {
    const addresses = [_]net.IpAddress{
        .{ .ip6 = .loopback(1) },
        .{ .ip6 = .loopback(2) },
        .{ .ip4 = .loopback(3) },
        .{ .ip4 = .loopback(4) },
        .{ .ip6 = .loopback(5) },
    };
    var ordered: [addresses.len]net.IpAddress = undefined;
    interleaveAddressFamilies(&ordered, &addresses);
    try std.testing.expectEqual([addresses.len]net.IpAddress{
        .{ .ip6 = .loopback(1) },
        .{ .ip4 = .loopback(3) },
        .{ .ip6 = .loopback(2) },
        .{ .ip4 = .loopback(4) },
        .{ .ip6 = .loopback(5) },
    }, ordered);
}

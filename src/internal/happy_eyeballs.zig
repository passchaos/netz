//! Shared RFC 8305 address planning for connection-oriented transports.
//!
//! Transport modules retain ownership of their attempt state and cleanup, but
//! use one public policy and one stable family interleaving rule so TCP and
//! QUIC do not drift into subtly different resolver semantics.

const std = @import("std");

const net = std.Io.net;
const stack_address_capacity: usize = 8;

pub const Error = std.mem.Allocator.Error || error{
    InvalidAddressConnectPolicy,
    NoAddressReturned,
};

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

    const Result = ConnectError!Connected;
    const Context = @TypeOf(context);
    const Slot = struct {
        io: std.Io,
        address: net.IpAddress,
        context: Context,
        index: usize,
        result: ?Result = null,

        fn run(self: *@This()) usize {
            self.result = connect_one(
                self.context,
                self.io,
                self.address,
                self.index,
            );
            return self.index;
        }

        fn take(self: *@This()) Result {
            const result = self.result orelse unreachable;
            self.result = null;
            return result;
        }

        fn deinit(self: *@This()) void {
            const result = self.result orelse return;
            self.result = null;
            if (result) |value| {
                var owned = value;
                deinit_connected(self.context, &owned);
            } else |_| {}
        }
    };
    const Wake = union(enum) {
        attempt: usize,
        launch: std.Io.Cancelable!void,
        deadline: std.Io.Cancelable!void,
    };

    var slot_stack: [stack_address_capacity]Slot = undefined;
    const slot_heap = if (ordered.len > slot_stack.len)
        try allocator.alloc(Slot, ordered.len)
    else
        null;
    defer if (slot_heap) |storage| allocator.free(storage);
    const slots = slot_heap orelse slot_stack[0..ordered.len];
    for (slots, ordered, 0..) |*slot, address, index| {
        slot.* = .{
            .io = io,
            .address = address,
            .context = context,
            .index = index,
        };
    }
    defer for (slots) |*slot| slot.deinit();

    const wake_capacity = std.math.add(usize, addresses.len, 2) catch
        return error.OutOfMemory;
    var wake_stack: [stack_address_capacity + 2]Wake = undefined;
    const wake_heap = if (wake_capacity > wake_stack.len)
        try allocator.alloc(Wake, wake_capacity)
    else
        null;
    defer if (wake_heap) |storage| allocator.free(storage);
    const wake_storage = wake_heap orelse wake_stack[0..wake_capacity];
    var select: std.Io.Select(Wake) = .init(io, wake_storage);
    defer while (select.cancel()) |_| {};
    if (deadline) |absolute| {
        select.async(.deadline, waitUntil, .{ io, absolute });
    }

    var next_index: usize = 1;
    var active: usize = 1;
    var timer_pending = false;
    var next_launch_at = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = options.attempt_delay,
        .clock = .awake,
    });
    var last_error: ?ConnectError = null;
    select.async(.attempt, Slot.run, .{&slots[0]});
    if (next_index < slots.len and active < options.max_in_flight) {
        select.async(.launch, waitUntil, .{ io, next_launch_at });
        timer_pending = true;
    }

    while (true) {
        const wake = select.await() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
        switch (wake) {
            .attempt => |index| {
                std.debug.assert(active != 0);
                active -= 1;
                const connected = slots[index].take() catch |err| {
                    if (!should_try_next(err)) return err;
                    last_error = err;
                    if (active == 0 and next_index < slots.len) {
                        select.async(
                            .attempt,
                            Slot.run,
                            .{&slots[next_index]},
                        );
                        next_index += 1;
                        active += 1;
                        next_launch_at = .fromNow(io, .{
                            .raw = options.attempt_delay,
                            .clock = .awake,
                        });
                    }
                    if (next_index == slots.len and active == 0) {
                        return last_error.?;
                    }
                    if (next_index < slots.len and
                        active < options.max_in_flight and
                        !timer_pending)
                    {
                        if (active == 0 or
                            next_launch_at.durationFromNow(io)
                                .raw.nanoseconds <= 0)
                        {
                            select.async(
                                .attempt,
                                Slot.run,
                                .{&slots[next_index]},
                            );
                            next_index += 1;
                            active += 1;
                            next_launch_at = .fromNow(io, .{
                                .raw = options.attempt_delay,
                                .clock = .awake,
                            });
                        }
                        if (next_index < slots.len and
                            active < options.max_in_flight)
                        {
                            select.async(
                                .launch,
                                waitUntil,
                                .{ io, next_launch_at },
                            );
                            timer_pending = true;
                        }
                    }
                    continue;
                };
                return connected;
            },
            .launch => |result| {
                result catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                timer_pending = false;
                if (next_index >= slots.len or
                    active >= options.max_in_flight)
                {
                    continue;
                }
                if (active != 0 and
                    next_launch_at.durationFromNow(io).raw.nanoseconds > 0)
                {
                    select.async(
                        .launch,
                        waitUntil,
                        .{ io, next_launch_at },
                    );
                    timer_pending = true;
                    continue;
                }
                select.async(.attempt, Slot.run, .{&slots[next_index]});
                next_index += 1;
                active += 1;
                next_launch_at = .fromNow(io, .{
                    .raw = options.attempt_delay,
                    .clock = .awake,
                });
                if (next_index < slots.len and
                    active < options.max_in_flight)
                {
                    select.async(
                        .launch,
                        waitUntil,
                        .{ io, next_launch_at },
                    );
                    timer_pending = true;
                }
            },
            .deadline => |result| {
                result catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                return deadline_error.?;
            },
        }
    }
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

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
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

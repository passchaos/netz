//! Deadline-bounded TCP connection establishment for Zig 0.16 `std.Io`.
//!
//! The threaded backend currently rejects `IpAddress.ConnectOptions.timeout`.
//! Racing the normal cancelable connect task against one absolute awake-clock
//! deadline also gives hostname lookup and all address attempts one shared
//! budget. If timeout wins concurrently with a successful connect, deferred
//! select draining closes that unselected socket.
//! Explicit local-address binds use zio's native socket API because Zig 0.16's
//! generic `std.Io` connect operation cannot accept a pre-bound socket.

const std = @import("std");
const zio = @import("zio");
const deadline_policy = @import("deadline.zig");
const happy_eyeballs = @import("tcp_connect/happy_eyeballs.zig");

const net = std.Io.net;

pub const BoundConnectError = net.IpAddress.ConnectError || error{
    AddressInUse,
};

pub const BoundHostConnectError = net.HostName.LookupError ||
    BoundConnectError;
pub const ResolvedConnectError = net.HostName.LookupError ||
    net.IpAddress.ConnectError;
pub const ResolvedBoundConnectError = net.HostName.LookupError ||
    BoundConnectError;
pub const AddressConnectPolicy = happy_eyeballs.Policy;
pub const HappyEyeballsOptions = happy_eyeballs.Options;
pub const ResolvedPolicyConnectError = ResolvedConnectError ||
    happy_eyeballs.Error;
pub const ResolvedBoundPolicyConnectError = ResolvedBoundConnectError ||
    happy_eyeballs.Error;

pub fn validateAddressConnectPolicy(
    policy: AddressConnectPolicy,
) error{InvalidAddressConnectPolicy}!void {
    switch (policy) {
        .ordered => {},
        .happy_eyeballs => |options| try happy_eyeballs.validate(options),
    }
}

pub fn ip(
    io: std.Io,
    address: net.IpAddress,
    timeout: ?std.Io.Duration,
) net.IpAddress.ConnectError!net.Stream {
    const duration = timeout orelse
        return address.connect(io, .{ .mode = .stream });
    const deadline = (try deadline_policy.fromTimeout(io, duration)).?;
    return race(io, deadline, connectIp, .{ io, address });
}

pub fn ipWithDeadline(
    io: std.Io,
    address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) net.IpAddress.ConnectError!net.Stream {
    return race(
        io,
        try deadline_policy.usableAwake(io, deadline),
        connectIp,
        .{ io, address },
    );
}

/// Establish a TCP stream after binding its socket to `local_address`.
///
/// Zig 0.16's generic `std.Io` connect operation cannot bind an existing
/// socket. Netz's production zio backend exposes that operation directly; a
/// foreign backend is rejected rather than silently ignoring the requested
/// source address.
pub fn ipBound(
    io: std.Io,
    address: net.IpAddress,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
) BoundConnectError!net.Stream {
    return connectBoundZio(
        io,
        address,
        local_address,
        if (timeout) |duration| zio.Timeout.fromNanoseconds(
            durationNanoseconds(duration),
        ) else .none,
    );
}

pub fn ipBoundWithDeadline(
    io: std.Io,
    address: net.IpAddress,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) BoundConnectError!net.Stream {
    const usable = try deadline_policy.usableAwake(io, deadline);
    return connectBoundZio(
        io,
        address,
        local_address,
        zio.Timeout.fromNanoseconds(durationNanoseconds(
            usable.durationFromNow(io).raw,
        )),
    );
}

pub fn host(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    timeout: ?std.Io.Duration,
) net.HostName.ConnectError!net.Stream {
    const duration = timeout orelse
        return host_name.connect(io, port, .{ .mode = .stream });
    const deadline = (try deadline_policy.fromTimeout(io, duration)).?;
    return race(io, deadline, connectHost, .{ io, host_name, port });
}

pub fn hostWithDeadline(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    deadline: std.Io.Clock.Timestamp,
) net.HostName.ConnectError!net.Stream {
    return race(
        io,
        try deadline_policy.usableAwake(io, deadline),
        connectHost,
        .{ io, host_name, port },
    );
}

/// Try caller-resolved addresses in order under one optional timeout.
pub fn resolved(
    io: std.Io,
    addresses: []const net.IpAddress,
    timeout: ?std.Io.Duration,
) ResolvedConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedBefore(io, addresses, deadline);
}

pub fn resolvedWithDeadline(
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) ResolvedConnectError!net.Stream {
    return resolvedBefore(
        io,
        addresses,
        try deadline_policy.usableAwake(io, deadline),
    );
}

pub fn resolvedWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    timeout: ?std.Io.Duration,
    policy: AddressConnectPolicy,
) ResolvedPolicyConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedWithPolicyBefore(
        allocator,
        io,
        addresses,
        deadline,
        policy,
    );
}

pub fn resolvedWithPolicyAndDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedPolicyConnectError!net.Stream {
    return resolvedWithPolicyBefore(
        allocator,
        io,
        addresses,
        try deadline_policy.usableAwake(io, deadline),
        policy,
    );
}

fn resolvedWithPolicyBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedPolicyConnectError!net.Stream {
    return switch (policy) {
        .ordered => resolvedBefore(io, addresses, deadline),
        .happy_eyeballs => |options| happy_eyeballs.connect(
            net.IpAddress.ConnectError,
            allocator,
            io,
            addresses,
            options,
            deadline,
            {},
            connectResolvedIp,
            shouldTryNextResolvedAddress,
        ),
    };
}

fn resolvedBefore(
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) ResolvedConnectError!net.Stream {
    var last_error: ?net.IpAddress.ConnectError = null;
    for (addresses) |address| {
        const stream = if (deadline) |absolute|
            ipWithDeadline(io, address, absolute)
        else
            ip(io, address, null);
        return stream catch |err| {
            if (!shouldTryNextResolvedAddress(err)) return err;
            last_error = err;
            continue;
        };
    }
    return last_error orelse error.NoAddressReturned;
}

/// Try caller-resolved addresses in order after binding each candidate socket
/// to `local_address`. All candidates share one optional absolute deadline.
pub fn resolvedBound(
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
) ResolvedBoundConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedBoundBefore(io, addresses, local_address, deadline);
}

pub fn resolvedBoundWithDeadline(
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) ResolvedBoundConnectError!net.Stream {
    return resolvedBoundBefore(
        io,
        addresses,
        local_address,
        try deadline_policy.usableAwake(io, deadline),
    );
}

pub fn resolvedBoundWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
    policy: AddressConnectPolicy,
) ResolvedBoundPolicyConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return resolvedBoundWithPolicyBefore(
        allocator,
        io,
        addresses,
        local_address,
        deadline,
        policy,
    );
}

pub fn resolvedBoundWithPolicyAndDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedBoundPolicyConnectError!net.Stream {
    return resolvedBoundWithPolicyBefore(
        allocator,
        io,
        addresses,
        local_address,
        try deadline_policy.usableAwake(io, deadline),
        policy,
    );
}

fn resolvedBoundWithPolicyBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
    policy: AddressConnectPolicy,
) ResolvedBoundPolicyConnectError!net.Stream {
    return switch (policy) {
        .ordered => resolvedBoundBefore(
            io,
            addresses,
            local_address,
            deadline,
        ),
        .happy_eyeballs => |options| happy_eyeballs.connect(
            BoundConnectError,
            allocator,
            io,
            addresses,
            options,
            deadline,
            local_address,
            connectResolvedBoundIp,
            shouldTryNextResolvedAddress,
        ),
    };
}

fn resolvedBoundBefore(
    io: std.Io,
    addresses: []const net.IpAddress,
    local_address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) ResolvedBoundConnectError!net.Stream {
    var last_error: ?BoundConnectError = null;
    for (addresses) |address| {
        const stream = if (deadline) |absolute|
            ipBoundWithDeadline(io, address, local_address, absolute)
        else
            ipBound(io, address, local_address, null);
        return stream catch |err| {
            if (!shouldTryNextResolvedAddress(err)) return err;
            last_error = err;
            continue;
        };
    }
    return last_error orelse error.NoAddressReturned;
}

fn shouldTryNextResolvedAddress(err: anyerror) bool {
    return switch (err) {
        error.AddressFamilyUnsupported,
        error.AddressUnavailable,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.ProtocolUnsupportedByAddressFamily,
        error.ProtocolUnsupportedBySystem,
        error.SocketUnconnected,
        => true,
        else => false,
    };
}

pub fn hostBound(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    local_address: net.IpAddress,
    timeout: ?std.Io.Duration,
) BoundHostConnectError!net.Stream {
    const deadline = if (timeout) |duration|
        (try deadline_policy.fromTimeout(io, duration)).?
    else
        null;
    return connectHostBoundBefore(
        io,
        host_name,
        port,
        local_address,
        deadline,
    );
}

pub fn hostBoundWithDeadline(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    local_address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) BoundHostConnectError!net.Stream {
    return connectHostBoundBefore(
        io,
        host_name,
        port,
        local_address,
        try deadline_policy.usableAwake(io, deadline),
    );
}

fn connectHostBoundBefore(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    local_address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) BoundHostConnectError!net.Stream {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    var lookup_buffer: [32]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) =
        .init(&lookup_buffer);
    var lookup = io.async(net.HostName.lookup, .{
        host_name,
        io,
        &lookup_queue,
        .{
            .port = port,
            .family = std.meta.activeTag(local_address),
        },
    });
    defer {
        lookup.cancel(io) catch {};
        while (lookup_queue.getOneUncancelable(io)) |_| {} else |err| switch (err) {
            error.Closed => {},
        }
    }

    var last_error: ?BoundConnectError = null;
    while (lookup_queue.getOne(io)) |result| switch (result) {
        .canonical_name => {},
        .address => |address| {
            const stream = if (deadline) |absolute|
                ipBoundWithDeadline(
                    io,
                    address,
                    local_address,
                    absolute,
                )
            else
                ipBound(io, address, local_address, null);
            return stream catch |err| switch (err) {
                error.Canceled,
                error.OptionUnsupported,
                error.SystemResources,
                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                error.AddressInUse,
                => |fatal| return fatal,
                else => |connect_error| {
                    last_error = connect_error;
                    continue;
                },
            };
        },
    } else |err| switch (err) {
        error.Canceled => |cancelled| return cancelled,
        error.Closed => {
            try lookup.await(io);
            return last_error orelse error.UnknownHostName;
        },
    }
}

fn connectBoundZio(
    io: std.Io,
    address: net.IpAddress,
    local_address: net.IpAddress,
    timeout: zio.Timeout,
) BoundConnectError!net.Stream {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    if (std.meta.activeTag(address) != std.meta.activeTag(local_address)) {
        return error.AddressFamilyUnsupported;
    }
    const domain: zio.os.net.Domain = switch (local_address) {
        .ip4 => .ipv4,
        .ip6 => .ipv6,
    };
    var socket = zio.net.Socket.open(.stream, domain, .tcp) catch |err|
        return mapBoundConnectError(err);
    errdefer socket.close();
    socket.bind(.{ .ip = zioIpAddress(local_address) }) catch |err|
        return mapBoundConnectError(err);
    const bound_address = stdIpAddress(socket.address.ip);
    socket.connect(.{ .ip = zioIpAddress(address) }, .{
        .timeout = timeout,
    }) catch |err| return mapBoundConnectError(err);
    return .{ .socket = .{
        .handle = stdIoSocketHandle(socket.handle),
        .address = bound_address,
    } };
}

fn zioIpAddress(address: net.IpAddress) zio.net.IpAddress {
    return switch (address) {
        .ip4 => |ip4| .initIp4(ip4.bytes, ip4.port),
        .ip6 => |ip6| .initIp6(
            ip6.bytes,
            ip6.port,
            ip6.flow,
            ip6.interface.index,
        ),
    };
}

fn stdIpAddress(address: zio.net.IpAddress) net.IpAddress {
    return switch (address.getFamily()) {
        .ipv4 => .{ .ip4 = .{
            .bytes = @bitCast(address.in.addr),
            .port = std.mem.bigToNative(u16, address.in.port),
        } },
        .ipv6 => .{ .ip6 = .{
            .bytes = address.in6.addr,
            .port = std.mem.bigToNative(u16, address.in6.port),
            .flow = address.in6.flowinfo,
            .interface = .{ .index = address.in6.scope_id },
        } },
    };
}

fn stdIoSocketHandle(
    handle: @FieldType(zio.net.Socket, "handle"),
) net.Socket.Handle {
    return if (@typeInfo(net.Socket.Handle) == .pointer)
        @ptrCast(handle)
    else
        @intCast(handle);
}

fn durationNanoseconds(duration: std.Io.Duration) u64 {
    if (duration.nanoseconds <= 0) return 0;
    return @intCast(@min(duration.nanoseconds, std.math.maxInt(u64)));
}

fn mapBoundConnectError(err: anyerror) BoundConnectError {
    return switch (err) {
        error.AccessDenied => error.AccessDenied,
        error.AddressInUse => error.AddressInUse,
        error.AddressUnavailable => error.AddressUnavailable,
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.Canceled => error.Canceled,
        error.ConnectionPending => error.ConnectionPending,
        error.ConnectionRefused => error.ConnectionRefused,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.HostUnreachable => error.HostUnreachable,
        error.NetworkDown => error.NetworkDown,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.ProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        error.ProtocolUnsupportedByAddressFamily => error.ProtocolUnsupportedByAddressFamily,
        error.ProtocolUnsupportedBySystem => error.ProtocolUnsupportedBySystem,
        error.SocketModeUnsupported => error.SocketModeUnsupported,
        error.SystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        error.SystemResources => error.SystemResources,
        error.Timeout => error.Timeout,
        error.WouldBlock => error.WouldBlock,
        else => error.Unexpected,
    };
}

pub fn unix(
    io: std.Io,
    address: net.UnixAddress,
    timeout: ?std.Io.Duration,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    const duration = timeout orelse return address.connect(io);
    const deadline = (try deadline_policy.fromTimeout(io, duration)).?;
    return race(io, deadline, connectUnix, .{ io, address });
}

pub fn unixWithDeadline(
    io: std.Io,
    address: net.UnixAddress,
    deadline: std.Io.Clock.Timestamp,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    return race(
        io,
        try deadline_policy.usableAwake(io, deadline),
        connectUnix,
        .{ io, address },
    );
}

fn race(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    comptime connect_fn: anytype,
    args: std.meta.ArgsTuple(@TypeOf(connect_fn)),
) @typeInfo(@TypeOf(connect_fn)).@"fn".return_type.? {
    const ConnectResult = @typeInfo(@TypeOf(connect_fn)).@"fn".return_type.?;
    const Wake = union(enum) {
        connected: ConnectResult,
        timeout: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .connected => |result| if (result) |stream| {
            stream.close(io);
        } else |_| {},
        .timeout => {},
    };
    select.async(.connected, connect_fn, args);
    select.async(.timeout, waitUntil, .{ io, deadline });
    return switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .connected => |result| result,
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    };
}

fn connectIp(
    io: std.Io,
    address: net.IpAddress,
) net.IpAddress.ConnectError!net.Stream {
    return address.connect(io, .{ .mode = .stream });
}

fn connectResolvedIp(
    _: void,
    io: std.Io,
    address: net.IpAddress,
    _: ?std.Io.Clock.Timestamp,
) net.IpAddress.ConnectError!net.Stream {
    return connectIp(io, address);
}

fn connectResolvedBoundIp(
    local_address: net.IpAddress,
    io: std.Io,
    address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) BoundConnectError!net.Stream {
    return if (deadline) |absolute|
        ipBoundWithDeadline(io, address, local_address, absolute)
    else
        ipBound(io, address, local_address, null);
}

fn connectHost(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
) net.HostName.ConnectError!net.Stream {
    return host_name.connect(io, port, .{ .mode = .stream });
}

fn connectUnix(
    io: std.Io,
    address: net.UnixAddress,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    return address.connect(io);
}

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

test "TCP connect deadline accepts a ready endpoint" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    var stream = try ip(io, listener.socket.address, .fromSeconds(1));
    defer stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
}

test "TCP Happy Eyeballs rejects an invalid attempt policy" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidAddressConnectPolicy,
        resolvedWithPolicy(
            std.testing.allocator,
            threaded.io(),
            &.{.{ .ip4 = .loopback(1) }},
            null,
            .{ .happy_eyeballs = .{ .attempt_delay = .zero } },
        ),
    );
    try std.testing.expectError(
        error.InvalidAddressConnectPolicy,
        resolvedWithPolicy(
            std.testing.allocator,
            threaded.io(),
            &.{.{ .ip4 = .loopback(1) }},
            null,
            .{ .happy_eyeballs = .{ .max_in_flight = 0 } },
        ),
    );
}

test "TCP ordered address policy remains allocation free" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var stream = try resolvedWithPolicy(
        failing.allocator(),
        io,
        &.{listener.socket.address},
        .fromSeconds(1),
        .ordered,
    );
    defer stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
}

test "TCP Happy Eyeballs allocates only beyond stack capacity" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var addresses: [9]net.IpAddress = undefined;
    for (&addresses, 0..) |*address, index| {
        address.* = .{ .ip4 = .loopback(@intCast(index + 1)) };
    }
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        resolvedWithPolicy(
            failing.allocator(),
            threaded.io(),
            &addresses,
            .fromSeconds(1),
            .{ .happy_eyeballs = .{} },
        ),
    );
}

test "TCP Happy Eyeballs advances immediately after path failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    var unavailable = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    const unavailable_address = unavailable.socket.address;
    unavailable.deinit(io);
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );

    const started = std.Io.Clock.awake.now(io);
    var stream = try resolvedWithPolicy(
        failing.allocator(),
        io,
        &.{ unavailable_address, listener.socket.address },
        .fromSeconds(1),
        .{ .happy_eyeballs = .{
            .attempt_delay = .fromSeconds(5),
        } },
    );
    defer stream.close(io);
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
    const accepted = try listener.accept(io);
    accepted.close(io);
}

test "TCP Happy Eyeballs returns the last retryable path error" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const MockIo = struct {
        var calls: std.atomic.Value(u8) = .init(0);

        fn netConnectIp(
            _: ?*anyopaque,
            address: *const net.IpAddress,
            _: net.IpAddress.ConnectOptions,
        ) net.IpAddress.ConnectError!net.Socket {
            _ = calls.fetchAdd(1, .acq_rel);
            return if (address.getPort() == 1)
                error.ConnectionRefused
            else
                error.NetworkUnreachable;
        }
    };
    MockIo.calls.store(0, .release);
    var vtable = io.vtable.*;
    vtable.netConnectIp = MockIo.netConnectIp;
    const racing_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    try std.testing.expectError(
        error.NetworkUnreachable,
        resolvedWithPolicy(
            std.testing.allocator,
            racing_io,
            &.{
                .{ .ip6 = .loopback(1) },
                .{ .ip4 = .loopback(2) },
            },
            .fromSeconds(1),
            .{ .happy_eyeballs = .{
                .attempt_delay = .fromSeconds(5),
            } },
        ),
    );
    try std.testing.expectEqual(@as(u8, 2), MockIo.calls.load(.acquire));
}

test "TCP Happy Eyeballs fails fast on resource errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const MockIo = struct {
        var calls: std.atomic.Value(u8) = .init(0);

        fn netConnectIp(
            _: ?*anyopaque,
            _: *const net.IpAddress,
            _: net.IpAddress.ConnectOptions,
        ) net.IpAddress.ConnectError!net.Socket {
            _ = calls.fetchAdd(1, .acq_rel);
            return error.SystemResources;
        }
    };
    MockIo.calls.store(0, .release);
    var vtable = io.vtable.*;
    vtable.netConnectIp = MockIo.netConnectIp;
    const racing_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    try std.testing.expectError(
        error.SystemResources,
        resolvedWithPolicy(
            std.testing.allocator,
            racing_io,
            &.{
                .{ .ip6 = .loopback(1) },
                .{ .ip4 = .loopback(2) },
            },
            .fromSeconds(1),
            .{ .happy_eyeballs = .{
                .attempt_delay = .fromSeconds(5),
            } },
        ),
    );
    try std.testing.expectEqual(@as(u8, 1), MockIo.calls.load(.acquire));
}

test "TCP Happy Eyeballs staggers attempts and closes a successful loser" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var slow_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer slow_listener.deinit(io);
    var winner_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer winner_listener.deinit(io);

    const MockIo = struct {
        var active: ?*@This() = null;

        delegate: std.Io,
        slow_port: u16,
        never: std.Io.Event = .unset,
        calls: std.atomic.Value(u8) = .init(0),
        close_calls: std.atomic.Value(u8) = .init(0),
        first_started_ns: std.atomic.Value(i64) = .init(0),
        second_started_ns: std.atomic.Value(i64) = .init(0),

        fn netConnectIp(
            _: ?*anyopaque,
            address: *const net.IpAddress,
            options: net.IpAddress.ConnectOptions,
        ) net.IpAddress.ConnectError!net.Socket {
            const self = active.?;
            const call = self.calls.fetchAdd(1, .acq_rel);
            const now: i64 = @intCast(std.Io.Clock.awake.now(
                self.delegate,
            ).nanoseconds);
            if (call == 0) {
                self.first_started_ns.store(now, .release);
            } else {
                self.second_started_ns.store(now, .release);
            }
            if (address.getPort() == self.slow_port) {
                self.never.wait(self.delegate) catch |err| switch (err) {
                    error.Canceled => {},
                };
                const old = std.Io.swapCancelProtection(
                    self.delegate,
                    .blocked,
                );
                defer _ = std.Io.swapCancelProtection(self.delegate, old);
                return self.delegate.vtable.netConnectIp(
                    self.delegate.userdata,
                    address,
                    options,
                );
            }
            return self.delegate.vtable.netConnectIp(
                self.delegate.userdata,
                address,
                options,
            );
        }

        fn netClose(
            _: ?*anyopaque,
            handles: []const net.Socket.Handle,
        ) void {
            const self = active.?;
            _ = self.close_calls.fetchAdd(@intCast(handles.len), .acq_rel);
            self.delegate.vtable.netClose(self.delegate.userdata, handles);
        }
    };
    var mock = MockIo{
        .delegate = io,
        .slow_port = slow_listener.socket.address.getPort(),
    };
    MockIo.active = &mock;
    defer MockIo.active = null;
    var vtable = io.vtable.*;
    vtable.netConnectIp = MockIo.netConnectIp;
    vtable.netClose = MockIo.netClose;
    const racing_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };

    const delay = std.Io.Duration.fromMilliseconds(30);
    var winner = try resolvedWithPolicy(
        std.testing.allocator,
        racing_io,
        &.{ slow_listener.socket.address, winner_listener.socket.address },
        .fromSeconds(2),
        .{ .happy_eyeballs = .{
            .attempt_delay = delay,
            .max_in_flight = 2,
        } },
    );
    defer winner.close(io);
    try std.testing.expectEqual(@as(u8, 2), mock.calls.load(.acquire));
    try std.testing.expectEqual(@as(u8, 1), mock.close_calls.load(.acquire));
    try std.testing.expect(
        mock.second_started_ns.load(.acquire) -
            mock.first_started_ns.load(.acquire) +
            5 * std.time.ns_per_ms >=
            delay.nanoseconds,
    );

    const accepted_winner = try winner_listener.accept(io);
    accepted_winner.close(io);
    const accepted_loser = try slow_listener.accept(io);
    accepted_loser.close(io);
}

test "TCP Happy Eyeballs applies one deadline to all attempts" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const MockIo = struct {
        var active: ?*@This() = null;

        delegate: std.Io,
        never: std.Io.Event = .unset,
        calls: std.atomic.Value(u8) = .init(0),

        fn netConnectIp(
            _: ?*anyopaque,
            _: *const net.IpAddress,
            _: net.IpAddress.ConnectOptions,
        ) net.IpAddress.ConnectError!net.Socket {
            const self = active.?;
            _ = self.calls.fetchAdd(1, .acq_rel);
            self.never.wait(self.delegate) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Unexpected;
        }
    };
    var mock = MockIo{ .delegate = io };
    MockIo.active = &mock;
    defer MockIo.active = null;
    var vtable = io.vtable.*;
    vtable.netConnectIp = MockIo.netConnectIp;
    const racing_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        resolvedWithPolicy(
            std.testing.allocator,
            racing_io,
            &.{
                .{ .ip6 = .loopback(1) },
                .{ .ip4 = .loopback(2) },
                .{ .ip6 = .loopback(3) },
            },
            .fromMilliseconds(50),
            .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(10),
                .max_in_flight = 2,
            } },
        ),
    );
    try std.testing.expectEqual(@as(u8, 2), mock.calls.load(.acquire));
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
}

test "TCP Happy Eyeballs propagates external cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const MockIo = struct {
        var active: ?*@This() = null;

        delegate: std.Io,
        started: std.Io.Event = .unset,
        never: std.Io.Event = .unset,

        fn netConnectIp(
            _: ?*anyopaque,
            _: *const net.IpAddress,
            _: net.IpAddress.ConnectOptions,
        ) net.IpAddress.ConnectError!net.Socket {
            const self = active.?;
            self.started.set(self.delegate);
            self.never.wait(self.delegate) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Unexpected;
        }
    };
    var mock = MockIo{ .delegate = io };
    MockIo.active = &mock;
    defer MockIo.active = null;
    var vtable = io.vtable.*;
    vtable.netConnectIp = MockIo.netConnectIp;
    const racing_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };

    var future = try io.concurrent(resolvedWithPolicy, .{
        std.testing.allocator,
        racing_io,
        &.{
            net.IpAddress{ .ip6 = .loopback(1) },
            net.IpAddress{ .ip4 = .loopback(2) },
        },
        null,
        AddressConnectPolicy{ .happy_eyeballs = .{
            .attempt_delay = .fromSeconds(1),
        } },
    });
    try mock.started.wait(io);
    try std.testing.expectError(error.Canceled, future.cancel(io));
}

test "TCP bound connect uses the requested IPv4 source" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const local = net.IpAddress{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 2 },
        .port = 0,
    } };
    var stream = try ipBound(
        io,
        listener.socket.address,
        local,
        .fromSeconds(1),
    );
    defer stream.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    try std.testing.expectEqualSlices(
        u8,
        &local.ip4.bytes,
        &accepted.socket.address.ip4.bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        &local.ip4.bytes,
        &stream.socket.address.ip4.bytes,
    );
    try std.testing.expect(stream.socket.address.ip4.port != 0);
}

test "TCP resolved bound connect falls back under one deadline" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    var unavailable = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    const unavailable_address = unavailable.socket.address;
    unavailable.deinit(io);

    const local = net.IpAddress{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 2 },
        .port = 0,
    } };
    var stream = try resolvedBoundWithPolicyAndDeadline(
        std.testing.allocator,
        io,
        &.{ unavailable_address, listener.socket.address },
        local,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        .{ .happy_eyeballs = .{
            .attempt_delay = .fromSeconds(5),
        } },
    );
    defer stream.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    try std.testing.expectEqualSlices(
        u8,
        &local.ip4.bytes,
        &accepted.socket.address.ip4.bytes,
    );
}

test "TCP bound connect uses the requested IPv6 source" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = (net.IpAddress{ .ip6 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |other| return other,
    };
    defer listener.deinit(io);

    const local = net.IpAddress{ .ip6 = .loopback(0) };
    var stream = try ipBoundWithDeadline(
        io,
        listener.socket.address,
        local,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer stream.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    try std.testing.expectEqualSlices(
        u8,
        &local.ip6.bytes,
        &accepted.socket.address.ip6.bytes,
    );
    try std.testing.expectEqualSlices(
        u8,
        &local.ip6.bytes,
        &stream.socket.address.ip6.bytes,
    );
    try std.testing.expect(stream.socket.address.ip6.port != 0);
}

test "TCP bound connect rejects foreign backends and address families" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const threaded_io = threaded.io();
    try std.testing.expectError(
        error.OptionUnsupported,
        ipBound(
            threaded_io,
            .{ .ip4 = .loopback(1) },
            .{ .ip4 = .loopback(0) },
            null,
        ),
    );

    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    try std.testing.expectError(
        error.AddressFamilyUnsupported,
        ipBound(
            backend.io(),
            .{ .ip4 = .loopback(1) },
            .{ .ip6 = .loopback(0) },
            null,
        ),
    );
}

test "TCP connect deadline includes hostname resolution" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const host_name = try net.HostName.init("localhost");
    var stream = try host(
        io,
        host_name,
        listener.socket.address.ip4.port,
        .fromSeconds(1),
    );
    defer stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
}

test "TCP connect deadline cancels a slow connect task" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Slow = struct {
        fn connect(
            io_value: std.Io,
        ) net.IpAddress.ConnectError!net.Stream {
            std.Io.sleep(
                io_value,
                .fromSeconds(1),
                .awake,
            ) catch |err| return err;
            return error.ConnectionRefused;
        }
    };
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{
        .raw = .fromMilliseconds(5),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.Timeout,
        race(io, deadline, Slow.connect, .{io}),
    );
}

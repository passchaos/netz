const std = @import("std");
const tcp_connect_root = @import("../tcp_connect.zig");

const happy_eyeballs = @import("happy_eyeballs.zig");
const net = std.Io.net;
const zio = @import("zio");

const AddressConnectPolicy = tcp_connect_root.AddressConnectPolicy;
const host = tcp_connect_root.host;
const ip = tcp_connect_root.ip;
const ipBound = tcp_connect_root.ipBound;
const ipBoundWithDeadline = tcp_connect_root.ipBoundWithDeadline;
const race = tcp_connect_root.race;
const resolved = tcp_connect_root.resolved;
const resolvedBoundWithPolicyAndDeadline = tcp_connect_root.resolvedBoundWithPolicyAndDeadline;
const resolvedWithPolicy = tcp_connect_root.resolvedWithPolicy;

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
        slow_socket: ?net.Socket,
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
                const socket = self.slow_socket.?;
                self.slow_socket = null;
                return socket;
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
    // Open the successful slow socket before the cancelable task starts.
    // Retrying a real Threaded connect after cancellation can hit Zig 0.16's
    // EINTR -> ISCONN assertion; the race needs a delayed result, not another
    // syscall under an already canceled worker.
    const slow_socket = try io.vtable.netConnectIp(io.userdata, &slow_listener.socket.address, .{ .mode = .stream });
    var mock = MockIo{
        .delegate = io,
        .slow_port = slow_listener.socket.address.getPort(),
        .slow_socket = slow_socket,
    };
    defer if (mock.slow_socket) |socket| socket.close(io);
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
    var stream = ipBound(
        io,
        listener.socket.address,
        local,
        .fromSeconds(1),
    ) catch |err| switch (err) {
        // macOS and some CI hosts do not configure the 127.0.0.0/8 alias.
        error.AddressUnavailable => return error.SkipZigTest,
        else => |other| return other,
    };
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
    var stream = resolvedBoundWithPolicyAndDeadline(
        std.testing.allocator,
        io,
        &.{ unavailable_address, listener.socket.address },
        local,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        .{ .happy_eyeballs = .{
            .attempt_delay = .fromSeconds(5),
        } },
    ) catch |err| switch (err) {
        // macOS and some CI hosts do not configure the 127.0.0.0/8 alias.
        error.AddressUnavailable => return error.SkipZigTest,
        else => |other| return other,
    };
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

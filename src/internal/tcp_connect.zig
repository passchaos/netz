//! Deadline-bounded TCP connection establishment for Zig 0.16 `std.Io`.
//!
//! The threaded backend currently rejects `IpAddress.ConnectOptions.timeout`.
//! Racing the normal cancelable connect task against one absolute awake-clock
//! deadline also gives hostname lookup and all address attempts one shared
//! budget. If timeout wins concurrently with a successful connect, deferred
//! select draining closes that unselected socket.

const std = @import("std");

const net = std.Io.net;

pub fn ip(
    io: std.Io,
    address: net.IpAddress,
    timeout: ?std.Io.Duration,
) net.IpAddress.ConnectError!net.Stream {
    const duration = timeout orelse
        return address.connect(io, .{ .mode = .stream });
    const deadline = try deadlineFromTimeout(io, duration);
    return race(io, deadline, connectIp, .{ io, address });
}

pub fn host(
    io: std.Io,
    host_name: net.HostName,
    port: u16,
    timeout: ?std.Io.Duration,
) net.HostName.ConnectError!net.Stream {
    const duration = timeout orelse
        return host_name.connect(io, port, .{ .mode = .stream });
    const deadline = try deadlineFromTimeout(io, duration);
    return race(io, deadline, connectHost, .{ io, host_name, port });
}

pub fn unix(
    io: std.Io,
    address: net.UnixAddress,
    timeout: ?std.Io.Duration,
) (net.UnixAddress.ConnectError || std.Io.Timeout.Error)!net.Stream {
    const duration = timeout orelse return address.connect(io);
    const deadline = try deadlineFromTimeout(io, duration);
    return race(io, deadline, connectUnix, .{ io, address });
}

fn deadlineFromTimeout(
    io: std.Io,
    timeout: std.Io.Duration,
) std.Io.Timeout.Error!std.Io.Clock.Timestamp {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return .fromNow(io, .{ .raw = timeout, .clock = .awake });
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

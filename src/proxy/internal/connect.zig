//! Deadline-bounded TCP connection establishment.
//!
//! `std.Io.net.IpAddress.connect` has no timeout parameter. Racing the
//! cancelable connect operation against one absolute awake-clock deadline
//! gives every candidate address a single shared budget.

const std = @import("std");

const net = std.Io.net;

pub const Error = net.IpAddress.ConnectError || std.Io.Timeout.Error ||
    error{ SystemResources, NoAddressReturned };

pub fn ipWithDeadline(
    io: std.Io,
    address: net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    const absolute = deadline orelse
        return address.connect(io, .{ .mode = .stream });
    if (absolute.durationFromNow(io).raw.nanoseconds <= 0) {
        return error.Timeout;
    }
    return race(io, address, absolute);
}

fn race(
    io: std.Io,
    address: net.IpAddress,
    deadline: std.Io.Clock.Timestamp,
) Error!net.Stream {
    const Wake = union(enum) {
        connected: net.IpAddress.ConnectError!net.Stream,
        timeout: std.Io.Cancelable!void,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_storage);
    defer while (select.cancel()) |wake| switch (wake) {
        .connected => |result| if (result) |stream| {
            stream.close(io);
        } else |_| {},
        .timeout => {},
    };
    select.concurrent(.timeout, waitUntil, .{ io, deadline }) catch
        return error.SystemResources;
    select.concurrent(.connected, connectIp, .{ io, address }) catch
        return error.SystemResources;
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

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

/// Try each resolved address in order under one shared deadline.
pub fn resolvedWithDeadline(
    io: std.Io,
    addresses: []const net.IpAddress,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    var last_error: ?Error = null;
    for (addresses) |address| {
        const stream = ipWithDeadline(io, address, deadline) catch |err| {
            switch (err) {
                error.AddressFamilyUnsupported,
                error.AddressUnavailable,
                error.ConnectionRefused,
                error.ConnectionResetByPeer,
                error.HostUnreachable,
                error.NetworkDown,
                error.NetworkUnreachable,
                error.ProtocolUnsupportedByAddressFamily,
                error.ProtocolUnsupportedBySystem,
                => {
                    last_error = err;
                    continue;
                },
                else => return err,
            }
        };
        return stream;
    }
    return last_error orelse error.NoAddressReturned;
}

test "expired deadline is rejected before connect" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        ipWithDeadline(
            io,
            .{ .ip4 = .loopback(1) },
            .{ .raw = .zero, .clock = .awake },
        ),
    );
}

test "resolved connect falls back across refused addresses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const address = net.IpAddress{
        .ip4 = .loopback(listener.socket.address.ip4.port),
    };

    const Accept = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            var buffer: [4]u8 = undefined;
            const count = ioRead(self.io, stream, &buffer);
            if (count) |value| {
                _ = self.io.vtable.netWrite(
                    self.io.userdata,
                    stream.socket.handle,
                    buffer[0..value],
                    &.{""},
                    0,
                ) catch {};
            } else |_| {}
        }

        fn ioRead(task_io: std.Io, stream: net.Stream, buffer: []u8) !usize {
            var parts = [_][]u8{buffer};
            return task_io.vtable.netRead(
                task_io.userdata,
                stream.socket.handle,
                &parts,
            );
        }
    };

    var accept = Accept{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Accept.run, .{&accept});

    const refused = net.IpAddress{ .ip4 = .loopback(1) };
    const addresses = [_]net.IpAddress{ refused, address };
    const stream = try resolvedWithDeadline(io, &addresses, null);
    defer stream.close(io);
    // The accept thread echoes four bytes. Use the data path rather than the
    // local socket address, which std reports as the ephemeral client port.
    const probe = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    _ = try io.vtable.netWrite(
        io.userdata,
        stream.socket.handle,
        &probe,
        &.{""},
        0,
    );
    var echoed: [4]u8 = undefined;
    var read_parts = [_][]u8{&echoed};
    const count = try io.vtable.netRead(
        io.userdata,
        stream.socket.handle,
        &read_parts,
    );
    try std.testing.expectEqualSlices(u8, &probe, echoed[0..count]);
    thread.join();
    if (accept.err) |err| return err;
}

//! Bidirectional UDP relay between a proxy byte stream and a UDP target.
//!
//! VLESS and VMess carry UDP payloads as raw stream chunks. Each chunk read
//! from the client is sent as one datagram; each received datagram is written
//! back as one stream chunk. Polled mode keeps all QUIC/H2/gRPC operations on
//! the caller's thread; threaded mode is used by TLS/WebSocket streams that do
//! not expose a timed read.

const std = @import("std");

const stats_mod = @import("../runtime/stats.zig");

const net = std.Io.net;

pub fn relayPolled(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    socket: net.Socket,
    target: net.IpAddress,
    buffer_size: usize,
    stats: ?*stats_mod.Stats,
) !void {
    const buffer = try allocator.alloc(u8, buffer_size);
    defer allocator.free(buffer);

    const poll = std.Io.Duration.fromMilliseconds(10);
    while (true) {
        const count = connection.readTimeout(buffer, poll) catch |err| switch (err) {
            error.Timeout => 0,
            error.ConnectionClosed => return,
            else => return err,
        };
        if (count == 0) return;
        try socket.send(io, &target, buffer[0..count]);
        if (stats) |value| value.addBytesIn(@intCast(count));

        const message = socket.receiveTimeout(io, buffer, .{
            .duration = .{ .raw = poll, .clock = .awake },
        }) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        if (message.flags.trunc) continue;
        try connection.writeAll(message.data);
        if (stats) |value| value.addBytesOut(@intCast(message.data.len));
    }
}

pub fn relayThreaded(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    socket: net.Socket,
    target: net.IpAddress,
    idle_timeout: std.Io.Duration,
    buffer_size: usize,
    stats: ?*stats_mod.Stats,
) !void {
    _ = idle_timeout;
    const buffer = try allocator.alloc(u8, buffer_size);
    defer allocator.free(buffer);

    const Shared = struct {
        io: std.Io,
        connection: @TypeOf(connection),
        socket: net.Socket,
        buffer: []u8,
        stats: ?*stats_mod.Stats,
        closed: std.atomic.Value(bool) = .init(false),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.pump() catch |err| {
                self.err = err;
                self.closed.store(true, .release);
            };
        }

        fn pump(self: *@This()) !void {
            while (!self.closed.load(.acquire)) {
                const message = self.socket.receiveTimeout(
                    self.io,
                    self.buffer,
                    .{ .duration = .{
                        .raw = .fromMilliseconds(100),
                        .clock = .awake,
                    } },
                ) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return err,
                };
                if (message.flags.trunc) continue;
                try self.connection.writeAll(message.data);
                if (self.stats) |value| value.addBytesOut(@intCast(message.data.len));
            }
        }
    };

    var shared = Shared{
        .io = io,
        .connection = connection,
        .socket = socket,
        .buffer = buffer,
        .stats = stats,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.closed.store(true, .release);
        thread.join();
    };

    while (true) {
        const count = connection.read(buffer) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (count == 0) break;
        try socket.send(io, &target, buffer[0..count]);
        if (stats) |value| value.addBytesIn(@intCast(count));
    }

    shared.closed.store(true, .release);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

//! Single-threaded relay between a QUIC byte stream and a TCP upstream.
//!
//! QUIC connections are not safe to mutate from multiple threads. This relay
//! polls both directions on the caller's thread instead of spawning a second
//! pump, which also keeps the connection's receive path moving while the
//! upstream is idle.

const std = @import("std");

const io_helpers = @import("io.zig");

const net = std.Io.net;

pub fn relay(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    upstream: net.Stream,
    idle_timeout: std.Io.Duration,
    buffer_size: usize,
) !void {
    const buffer = try allocator.alloc(u8, buffer_size);
    defer allocator.free(buffer);

    const poll_timeout = std.Io.Duration.fromMilliseconds(10);
    var quic_done = false;
    var tcp_done = false;
    while (true) {
        if (!quic_done) {
            const count = connection.readTimeout(buffer, poll_timeout) catch |err| switch (err) {
                error.Timeout => 0,
                else => blk: {
                    quic_done = true;
                    break :blk 0;
                },
            };
            if (count == 0) {
                quic_done = true;
                upstream.shutdown(io, .send) catch {};
            } else {
                try io_helpers.writeAll(
                    io,
                    upstream,
                    buffer[0..count],
                    currentDeadline(io, idle_timeout),
                );
            }
        }

        if (!tcp_done) {
            const count = io_helpers.readSome(
                io,
                upstream,
                buffer,
                pollDeadline(io, poll_timeout),
            ) catch |err| switch (err) {
                error.Timeout => 0,
                else => return err,
            };
            if (count == 0) {
                tcp_done = true;
                connection.finish();
            } else {
                try connection.writeAll(buffer[0..count]);
            }
        }

        if ((quic_done and tcp_done) or tcp_done) break;
    }
}

fn pollDeadline(
    io: std.Io,
    timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, timeout) catch null;
}

fn currentDeadline(
    io: std.Io,
    idle_timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, idle_timeout) catch null;
}

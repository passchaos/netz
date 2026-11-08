//! Bidirectional relay between a TLS byte stream and a plain TCP upstream.

const std = @import("std");

const io_helpers = @import("io.zig");
const stats_mod = @import("../runtime/stats.zig");

const net = std.Io.net;

pub fn relay(
    allocator: std.mem.Allocator,
    io: std.Io,
    tls: anytype,
    upstream: net.Stream,
    initial_payload: []const u8,
    idle_timeout: std.Io.Duration,
    buffer_size: usize,
    stats: ?*stats_mod.Stats,
) !void {
    if (initial_payload.len > 0) {
        try io_helpers.writeAll(
            io,
            upstream,
            initial_payload,
            currentDeadline(io, idle_timeout),
        );
    }

    const buffer = try allocator.alloc(u8, buffer_size);
    defer allocator.free(buffer);

    const Shared = struct {
        io: std.Io,
        tls: @TypeOf(tls),
        upstream: net.Stream,
        idle_timeout: std.Io.Duration,
        buffer: []u8,
        stats: ?*stats_mod.Stats,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.pump() catch |err| {
                self.err = err;
                self.upstream.shutdown(self.io, .both) catch {};
            };
        }

        fn pump(self: *@This()) !void {
            while (true) {
                const count = io_helpers.readSome(
                    self.io,
                    self.upstream,
                    self.buffer,
                    currentDeadline(self.io, self.idle_timeout),
                ) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                if (count == 0) break;
                try self.tls.writeAll(self.buffer[0..count]);
                if (self.stats) |value| {
                    value.addBytesOut(@intCast(count));
                }
            }
        }
    };

    var shared = Shared{
        .io = io,
        .tls = tls,
        .upstream = upstream,
        .idle_timeout = idle_timeout,
        .buffer = buffer,
        .stats = stats,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        upstream.shutdown(io, .both) catch {};
        thread.join();
    };

    while (true) {
        const count = try tls.read(buffer);
        if (count == 0) break;
        try io_helpers.writeAll(
            io,
            upstream,
            buffer[0..count],
            currentDeadline(io, idle_timeout),
        );
        if (stats) |value| {
            value.addBytesIn(@intCast(count));
        }
    }
    upstream.shutdown(io, .send) catch {};
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn currentDeadline(
    io: std.Io,
    idle_timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, idle_timeout) catch null;
}

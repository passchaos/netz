//! Bidirectional TCP tunnel with bounded buffers and half-close semantics.

const std = @import("std");

const io_helpers = @import("../internal/io.zig");
const stats_mod = @import("../runtime/stats.zig");

const net = std.Io.net;

pub const Options = struct {
    buffer_size: usize = 16 * 1024,
    /// Applied independently to each read and write. Null means the caller
    /// already bounded the connection lifetime.
    idle_timeout: ?std.Io.Duration = null,
    /// Optional counters. The first relay argument is treated as the client
    /// side: `a -> b` counts as inbound and `b -> a` as outbound.
    stats: ?*stats_mod.Stats = null,
};

pub const Error = std.Thread.SpawnError ||
    io_helpers.ReadError || io_helpers.WriteError ||
    net.Stream.ShutdownError || error{
    InvalidBufferSize,
};

const Pump = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    src: net.Stream,
    dst: net.Stream,
    initial: []const u8,
    options: Options,
    /// True when bytes flow from the client to the upstream target.
    counts_in: bool,
    err: ?anyerror = null,

    fn run(self: *Pump) void {
        self.pump() catch |err| {
            self.err = err;
            shutdownBoth(self.io, self.src, self.dst);
        };
    }

    fn pump(self: *Pump) !void {
        if (self.initial.len > 0) {
            try io_helpers.writeAll(
                self.io,
                self.dst,
                self.initial,
                currentDeadline(self.io, self.options.idle_timeout),
            );
            self.record(self.initial.len);
        }

        const buffer = try self.allocator.alloc(u8, self.options.buffer_size);
        defer self.allocator.free(buffer);

        while (true) {
            const deadline = currentDeadline(
                self.io,
                self.options.idle_timeout,
            );
            const count = io_helpers.readSome(
                self.io,
                self.src,
                buffer,
                deadline,
            ) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (count == 0) break;
            try io_helpers.writeAll(
                self.io,
                self.dst,
                buffer[0..count],
                currentDeadline(self.io, self.options.idle_timeout),
            );
            self.record(count);
        }

        // Propagate a clean half-close so the peer can finish its response.
        self.dst.shutdown(self.io, .send) catch {};
    }

    fn record(self: *Pump, count: usize) void {
        const stats = self.options.stats orelse return;
        const bytes: u64 = @intCast(count);
        if (self.counts_in) {
            stats.addBytesIn(bytes);
        } else {
            stats.addBytesOut(bytes);
        }
    }
};

/// Relay bytes in both directions until both peers finish or one side errors.
/// The caller retains ownership of both streams.
pub fn relay(
    allocator: std.mem.Allocator,
    io: std.Io,
    a: net.Stream,
    b: net.Stream,
    a_initial: []const u8,
    b_initial: []const u8,
    options: Options,
) !void {
    if (options.buffer_size == 0) return error.InvalidBufferSize;

    var a_to_b = Pump{
        .allocator = allocator,
        .io = io,
        .src = a,
        .dst = b,
        .initial = a_initial,
        .options = options,
        .counts_in = true,
    };
    const thread = try std.Thread.spawn(.{}, Pump.run, .{&a_to_b});
    var joined = false;
    defer if (!joined) thread.join();

    var b_to_a = Pump{
        .allocator = allocator,
        .io = io,
        .src = b,
        .dst = a,
        .initial = b_initial,
        .options = options,
        .counts_in = false,
    };
    b_to_a.run();

    thread.join();
    joined = true;

    if (a_to_b.err) |err| return err;
    if (b_to_a.err) |err| return err;
}

fn currentDeadline(
    io: std.Io,
    idle_timeout: ?std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    const duration = idle_timeout orelse return null;
    return .fromNow(io, .{ .raw = duration, .clock = .awake });
}

fn shutdownBoth(io: std.Io, a: net.Stream, b: net.Stream) void {
    a.shutdown(io, .both) catch {};
    b.shutdown(io, .both) catch {};
}

test "relay forwards initial bytes and both directions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const pair = try makeTcpPair(io);
    const left = pair[0];
    const right = pair[1];

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        left: net.Stream,
        right: net.Stream,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            relay(
                self.allocator,
                self.io,
                self.left,
                self.right,
                "hello",
                "world",
                .{ .buffer_size = 1024 },
            ) catch |err| {
                self.err = err;
            };
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .left = left,
        .right = right,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    // On a failed assertion, close both streams before joining so the pumps
    // cannot remain blocked on a read that no longer has a producer.
    defer if (!joined) {
        left.close(io);
        right.close(io);
        thread.join();
    };

    var buffer: [16]u8 = undefined;
    try readExact(io, left, buffer[0..5]);
    try std.testing.expectEqualStrings("hello", buffer[0..5]);
    try readExact(io, right, buffer[0..5]);
    try std.testing.expectEqualStrings("world", buffer[0..5]);

    try io_helpers.writeAll(io, right, "ping", null);
    try readExact(io, left, buffer[0..4]);
    try std.testing.expectEqualStrings("ping", buffer[0..4]);

    try io_helpers.writeAll(io, left, "pong", null);
    try readExact(io, right, buffer[0..4]);
    try std.testing.expectEqualStrings("pong", buffer[0..4]);

    try left.shutdown(io, .send);
    try right.shutdown(io, .send);
    thread.join();
    joined = true;
    left.close(io);
    right.close(io);
    if (shared.err) |err| return err;
}

test "relay counts bytes in both directions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    // Two independent pairs: client <-> relay-left and relay-right <-> server.
    const client_pair = try makeTcpPair(io);
    const server_pair = try makeTcpPair(io);
    const client = client_pair[0];
    const relay_left = client_pair[1];
    const relay_right = server_pair[0];
    const server = server_pair[1];

    var stats = stats_mod.Stats{};
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        left: net.Stream,
        right: net.Stream,
        stats: *stats_mod.Stats,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            relay(
                self.allocator,
                self.io,
                self.left,
                self.right,
                "",
                "",
                .{ .buffer_size = 1024, .stats = self.stats },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .left = relay_left,
        .right = relay_right,
        .stats = &stats,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        client.close(io);
        relay_left.close(io);
        relay_right.close(io);
        server.close(io);
        thread.join();
    };

    try io_helpers.writeAll(io, client, "ping", null);
    var buffer: [8]u8 = undefined;
    try readExact(io, server, buffer[0..4]);
    try std.testing.expectEqualStrings("ping", buffer[0..4]);

    try io_helpers.writeAll(io, server, "pong", null);
    try readExact(io, client, buffer[0..4]);
    try std.testing.expectEqualStrings("pong", buffer[0..4]);

    try client.shutdown(io, .send);
    try server.shutdown(io, .send);
    thread.join();
    joined = true;
    client.close(io);
    relay_left.close(io);
    relay_right.close(io);
    server.close(io);
    if (shared.err) |err| return err;

    const snapshot = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 4), snapshot.bytes_in);
    try std.testing.expectEqual(@as(u64, 4), snapshot.bytes_out);
}

test "relay rejects a zero buffer" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const pair = try makeTcpPair(io);
    const left = pair[0];
    const right = pair[1];
    defer left.close(io);
    defer right.close(io);

    try std.testing.expectError(
        error.InvalidBufferSize,
        relay(allocator, io, left, right, "", "", .{ .buffer_size = 0 }),
    );
}

fn makeTcpPair(io: std.Io) ![2]net.Stream {
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try (net.IpAddress{
        .ip4 = .loopback(listener.socket.address.ip4.port),
    }).connect(io, .{ .mode = .stream });
    errdefer client.close(io);
    const server = try listener.accept(io);
    return .{ client, server };
}

fn readExact(io: std.Io, stream: net.Stream, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try io_helpers.readSome(
            io,
            stream,
            output[offset..],
            null,
        );
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

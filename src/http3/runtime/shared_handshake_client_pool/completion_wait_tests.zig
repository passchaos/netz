const std = @import("std");
const runtime = @import("../../runtime.zig");
const zio = @import("zio");

test "HTTP/3 shared synchronous acquire wakes on resolver completion" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const Resolver = struct {
        started: std.Io.Event = .unset,
        calls: usize = 0,

        fn resolve(context: *anyopaque, _: std.mem.Allocator, resolve_io: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) runtime.SharedHandshakeClientPoolAddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.started.set(resolve_io);
            try std.Io.sleep(resolve_io, .fromMilliseconds(20), .awake);
            return error.UnknownHostName;
        }
    };
    var resolver: Resolver = .{};
    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .handshake_poll_interval = .fromSeconds(10),
        .client = .{
            .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} },
            .connect_timeout = .fromMilliseconds(600),
            .address_connect_policy = .{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(20), .max_in_flight = 2 } },
            .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
        },
    });
    defer pool.deinit();
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.UnknownHostName, pool.acquireUri("https://completion.example:443/"));
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(resolver.started.isSet());
    try std.testing.expectEqual(@as(usize, 1), resolver.calls);
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());
    try std.testing.expect(elapsed.nanoseconds < 250 * std.time.ns_per_ms);
}

test "HTTP/3 shared synchronous acquire cancels its resolver and endpoint wait" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const Resolver = struct {
        started: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,
        release: std.Io.Event = .unset,

        fn resolve(context: *anyopaque, _: std.mem.Allocator, resolve_io: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) runtime.SharedHandshakeClientPoolAddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            defer self.finished.set(resolve_io);
            self.started.set(resolve_io);
            try self.release.wait(resolve_io);
            return error.UnknownHostName;
        }
    };
    var resolver: Resolver = .{};
    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .handshake_poll_interval = .fromSeconds(10),
        .client = .{
            .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} },
            .connect_timeout = null,
            .address_connect_policy = .{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(20), .max_in_flight = 2 } },
            .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
        },
    });
    defer pool.deinit();
    var acquire = try std.Io.concurrent(io, runtime.SharedHandshakeClientPool.acquireUri, .{ &pool, "https://cancel.example:443/" });
    var acquire_active = true;
    defer if (acquire_active) {
        resolver.release.set(io);
        if (acquire.cancel(io)) |value| {
            var lease = value;
            lease.release();
        } else |_| {}
    };
    try resolver.started.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const result = acquire.cancel(io);
    acquire_active = false;
    if (result) |value| {
        var lease = value;
        lease.release();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.Canceled), err);
    try std.testing.expect(resolver.finished.isSet());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());
    // The canceled receive must be gone before a later acquisition reuses
    // this endpoint and the pool's connection reservation.
    resolver.release.set(io);
    try std.testing.expectError(error.UnknownHostName, pool.acquireUri("https://cancel.example:443/"));
}

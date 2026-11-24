//! The acquisition owner enforces its connection phase budget independently
//! of a cancellable resolver's completion and the request's overall deadline.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const connection_budget = @import("../../../internal/connection_budget.zig");
const zio = @import("zio");

const SlowResolver = struct {
    finished: std.Io.Event = .unset,
    calls: usize = 0,

    fn resolve(context: *anyopaque, _: std.mem.Allocator, io: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.calls += 1;
        defer self.finished.set(io);
        // A finite wait keeps a regression failure bounded. The resolver
        // honors cancellation but deliberately leaves expiry to its owner.
        try std.Io.sleep(io, .fromMilliseconds(600), .awake);
        return error.UnknownHostName;
    }
};

fn initPool(io: std.Io, resolver: *SlowResolver, budget: *connection_budget.Budget) !runtime.SharedHandshakeClientPool {
    return runtime.SharedHandshakeClientPool.init(std.testing.allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 1,
        .shared_connection_budget = budget,
        .handshake_poll_interval = .fromSeconds(10),
        .client = .{
            .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} },
            .connect_timeout = .fromMilliseconds(80),
            .address_connect_policy = .{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(20), .max_in_flight = 2 } },
            .address_resolver = .{ .context = resolver, .resolve = SlowResolver.resolve },
        },
    });
}

fn expectReclaimed(pool: *runtime.SharedHandshakeClientPool, resolver: *SlowResolver, budget: *connection_budget.Budget) !void {
    try std.testing.expect(resolver.finished.isSet());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.connections);
}

test "HTTP/3 shared acquisition deadline cancels a slow synchronous resolver" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const budget = try connection_budget.Budget.create(allocator, io, 1);
    defer budget.deinit();
    var resolver: SlowResolver = .{};
    var pool = try initPool(io, &resolver, budget);
    defer pool.deinit();

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(error.HandshakeTimeout, pool.acquireUri("https://slow.acquire.test/"));
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 250 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), resolver.calls);
    try expectReclaimed(&pool, &resolver, budget);
}

test "HTTP/3 shared acquisition deadline wakes a request driver before its request budget" {
    const allocator = std.testing.allocator;
    var backend = try zio.Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const budget = try connection_budget.Budget.create(allocator, io, 1);
    defer budget.deinit();
    var resolver: SlowResolver = .{};
    var pool = try initPool(io, &resolver, budget);
    defer pool.deinit();
    var dispatcher = try runtime.SharedHandshakeClientPoolRequestDispatcher.init(allocator, io, &pool, .{ .max_active_connections = 1 });
    defer dispatcher.deinit();
    var driver = try std.Io.concurrent(io, runtime.SharedHandshakeClientPoolRequestDispatcher.run, .{&dispatcher});
    var driver_active = true;
    defer if (driver_active) {
        dispatcher.close();
        driver.cancel(io) catch {};
    };
    const sender = dispatcher.sender();

    // An absent request timeout and a longer request timeout must both retain
    // the connection phase's deadline. A shorter request timeout stays Timeout.
    inline for ([_]?std.Io.Duration{ null, .fromSeconds(1), .fromMilliseconds(40) }, 0..) |timeout, index| {
        resolver.finished.reset();
        const started = std.Io.Clock.awake.now(io);
        const response = if (timeout) |duration|
            sender.requestWithTimeout("https://slow.acquire.test/", .{}, duration)
        else
            sender.request("https://slow.acquire.test/", .{});
        if (response) |value| {
            var owned = value;
            owned.deinit();
            return error.TestExpectedError;
        } else |err| try std.testing.expectEqual(@as(anyerror, if (index == 2) error.Timeout else error.HandshakeTimeout), err);
        try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 250 * std.time.ns_per_ms);
        try std.testing.expectEqual(index + 1, resolver.calls);
        try expectReclaimed(&pool, &resolver, budget);
        const stats = dispatcher.stats();
        try std.testing.expectEqual(@as(usize, 0), stats.active_connections);
        try std.testing.expectEqual(@as(usize, 0), stats.active_requests);
    }
    dispatcher.close();
    try driver.await(io);
    driver_active = false;
}

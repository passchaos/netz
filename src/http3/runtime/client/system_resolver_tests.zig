//! Shared DNS scheduling through common, proxy and HTTP/3 entry points.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const common = @import("../../../internal/address_resolver.zig");
const proxy = @import("../../../proxy/internal/resolve.zig");
const net = std.Io.net;

const Route = enum { common, proxy, h3 };

fn resolve(comptime route: Route, io: std.Io, deadline: ?std.Io.Clock.Timestamp) anyerror![]net.IpAddress {
    return switch (route) {
        .common => common.resolveSystem(std.testing.allocator, io, "system.resolve.test", 443, deadline),
        .proxy => proxy.resolveHost(std.testing.allocator, io, "system.resolve.test", 443, deadline),
        .h3 => runtime.resolveHostPortAddressesBefore(std.testing.allocator, io, "system.resolve.test", 443, deadline),
    };
}

const Probe = struct {
    threaded: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    mode: enum { slow, many } = .slow,
    calls: std.atomic.Value(usize) = .init(0),
    finished: std.atomic.Value(bool) = .init(false),

    fn init(concurrent_limit: std.Io.Limit) Probe {
        return .{ .threaded = .init(std.testing.allocator, .{
            .async_limit = .nothing,
            .concurrent_limit = concurrent_limit,
        }) };
    }

    fn io(self: *Probe) std.Io {
        const base = self.threaded.io();
        self.table = base.vtable.*;
        self.table.netLookup = lookup;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn lookup(userdata: ?*anyopaque, _: net.HostName, output: *std.Io.Queue(net.HostName.LookupResult), options: net.HostName.LookupOptions) net.HostName.LookupError!void {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata));
        const self: *Probe = @fieldParentPtr("threaded", backend);
        const io_value = backend.io();
        _ = self.calls.fetchAdd(1, .acq_rel);
        defer self.finished.store(true, .release);
        defer output.close(io_value);
        if (self.mode == .slow) {
            try std.Io.sleep(io_value, .fromMilliseconds(600), .awake);
            return error.UnknownHostName;
        }
        for (0..41) |index| {
            const result: net.HostName.LookupResult = .{ .address = .{ .ip4 = .{
                .bytes = .{ 192, 0, 2, @intCast(index % 40 + 1) },
                .port = options.port,
            } } };
            output.putOne(io_value, result) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => unreachable,
            };
        }
    }
};

fn deadlineWithNoAsync(comptime route: Route) !void {
    var probe = Probe.init(.unlimited);
    defer probe.threaded.deinit();
    const io = probe.io();
    const started = std.Io.Clock.awake.now(io);
    const expected: anyerror = if (route == .h3) error.HandshakeTimeout else error.Timeout;
    try std.testing.expectError(expected, resolve(route, io, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(80) })));
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 250 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), probe.calls.load(.acquire));
    try std.testing.expect(probe.finished.load(.acquire));
}

fn queueWithNoAsync(comptime route: Route) !void {
    var probe = Probe.init(.unlimited);
    defer probe.threaded.deinit();
    probe.mode = .many;
    const io = probe.io();
    const Task = struct {
        fn run(io_value: std.Io, done: *std.Io.Event) anyerror![]net.IpAddress {
            defer done.set(io_value);
            return resolve(route, io_value, null);
        }
    };
    var done: std.Io.Event = .unset;
    var future = try std.Io.concurrent(io, Task.run, .{ io, &done });
    var active = true;
    defer if (active) {
        if (future.cancel(io)) |addresses| std.testing.allocator.free(addresses) else |_| {}
    };
    // The watchdog cancels the baseline's blocked queue writer, so a failed
    // regression never leaves a DNS task running or hangs the test process.
    try done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(250) } });
    const result = future.await(io);
    active = false;
    const addresses = try result;
    defer std.testing.allocator.free(addresses);
    try std.testing.expectEqual(@as(usize, 40), addresses.len);
    for (addresses, 0..) |address, index| {
        try std.testing.expectEqual(net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, @intCast(index + 1) }, .port = 443 } }, address);
    }
    try std.testing.expect(probe.finished.load(.acquire));
}

fn unavailable(comptime route: Route) !void {
    var probe = Probe.init(.nothing);
    defer probe.threaded.deinit();
    const io = probe.io();
    try std.testing.expectError(error.ConcurrencyUnavailable, resolve(route, io, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(80) })));
    try std.testing.expectEqual(@as(usize, 0), probe.calls.load(.acquire));
    const timeout: anyerror = if (route == .h3) error.HandshakeTimeout else error.Timeout;
    try std.testing.expectError(timeout, resolve(route, io, .fromNow(io, .{ .clock = .real, .raw = .fromSeconds(1) })));
    try std.testing.expectEqual(@as(usize, 0), probe.calls.load(.acquire));
    if (route == .h3) {
        const literal = try runtime.resolveHostPortAddressesBefore(std.testing.allocator, io, "127.0.0.1", 443, null);
        defer std.testing.allocator.free(literal);
        try std.testing.expectEqual(@as(usize, 1), literal.len);
        try std.testing.expectEqual(net.IpAddress{ .ip4 = .loopback(443) }, literal[0]);
    }
}

test "HTTP3 system resolver common deadline survives zero async budget" {
    try deadlineWithNoAsync(.common);
}
test "HTTP3 system resolver proxy deadline survives zero async budget" {
    try deadlineWithNoAsync(.proxy);
}
test "HTTP3 system resolver H3 deadline survives zero async budget" {
    try deadlineWithNoAsync(.h3);
}
test "HTTP3 system resolver common drains more addresses than its queue with zero async budget" {
    try queueWithNoAsync(.common);
}
test "HTTP3 system resolver proxy drains more addresses than its queue with zero async budget" {
    try queueWithNoAsync(.proxy);
}
test "HTTP3 system resolver H3 drains more addresses than its queue with zero async budget" {
    try queueWithNoAsync(.h3);
}
test "HTTP3 system resolver common refuses unavailable concurrency before DNS" {
    try unavailable(.common);
}
test "HTTP3 system resolver proxy refuses unavailable concurrency before DNS" {
    try unavailable(.proxy);
}
test "HTTP3 system resolver H3 refuses unavailable concurrency before DNS" {
    try unavailable(.h3);
}

test "HTTP3 system resolver application callback delegates DNS admission and timeout" {
    const Delegate = struct {
        fn run(_: *anyopaque, allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, deadline: ?std.Io.Clock.Timestamp) runtime.AddressResolver.ResolveError![]net.IpAddress {
            return common.resolveSystem(allocator, io, host, port, deadline);
        }
    };
    inline for (.{ std.Io.Limit.nothing, std.Io.Limit.unlimited }) |limit| {
        var probe = Probe.init(limit);
        defer probe.threaded.deinit();
        const io = probe.io();
        const expected: anyerror = if (limit == .nothing) error.ConcurrencyUnavailable else error.HandshakeTimeout;
        const started = std.Io.Clock.awake.now(io);
        try std.testing.expectError(expected, runtime.resolveHostPortWithResolverBefore(
            std.testing.allocator,
            io,
            "system.resolve.test",
            443,
            .{ .context = &probe, .resolve = Delegate.run },
            .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(80) }),
        ));
        try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 250 * std.time.ns_per_ms);
        try std.testing.expectEqual(@as(usize, if (limit == .nothing) 0 else 1), probe.calls.load(.acquire));
        if (limit != .nothing) try std.testing.expect(probe.finished.load(.acquire));
    }
}

//! Ordered hostname connections consume DNS incrementally with one TCP attempt.
const std = @import("std");
const tcp = @import("../tcp_connect.zig");
const net = std.Io.net;

const Probe = struct {
    threaded: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    peer: net.IpAddress = .{ .ip4 = .loopback(0) },
    mode: enum { ordered, streaming, many, fatal } = .ordered,
    lookup_calls: std.atomic.Value(usize) = .init(0),
    connect_calls: std.atomic.Value(usize) = .init(0),
    first_finished: std.atomic.Value(bool) = .init(false),
    lookup_finished: std.atomic.Value(bool) = .init(false),
    overlapped: std.atomic.Value(bool) = .init(false),
    connected_before_lookup_finished: std.atomic.Value(bool) = .init(false),
    seen: [64]u8 = @splat(0),

    fn init(async_limit: std.Io.Limit, concurrent_limit: std.Io.Limit) Probe {
        return .{ .threaded = .init(std.testing.allocator, .{ .async_limit = async_limit, .concurrent_limit = concurrent_limit }) };
    }

    fn io(self: *Probe) std.Io {
        const base = self.threaded.io();
        self.table = base.vtable.*;
        self.table.netLookup = lookup;
        self.table.netConnectIp = connect;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn owner(userdata: ?*anyopaque) *Probe {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata));
        return @fieldParentPtr("threaded", backend);
    }

    fn emit(io_value: std.Io, output: *std.Io.Queue(net.HostName.LookupResult), address: net.IpAddress) net.HostName.LookupError!void {
        output.putOne(io_value, .{ .address = address }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => unreachable,
        };
    }

    fn lookup(userdata: ?*anyopaque, _: net.HostName, output: *std.Io.Queue(net.HostName.LookupResult), options: net.HostName.LookupOptions) net.HostName.LookupError!void {
        const self = owner(userdata);
        const base = self.threaded.io();
        _ = self.lookup_calls.fetchAdd(1, .acq_rel);
        defer self.lookup_finished.store(true, .release);
        defer output.close(base);
        if (self.mode == .streaming) {
            try emit(base, output, self.peer);
            // A successful first candidate must not wait for this finite tail.
            try std.Io.sleep(base, .fromMilliseconds(600), .awake);
            return;
        }
        const count: usize = if (self.mode == .many) 39 else 1;
        for (0..count) |index| {
            try emit(base, output, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, @intCast(index + 2) }, .port = options.port } });
        }
        try emit(base, output, self.peer);
    }

    fn connect(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
        const self = owner(userdata);
        const index = self.connect_calls.fetchAdd(1, .acq_rel);
        std.debug.assert(index < self.seen.len);
        self.seen[index] = address.ip4.bytes[3];
        const base = self.threaded.io();
        if (address.ip4.bytes[3] != 1) {
            if (self.mode == .fatal) return error.AccessDenied;
            if (self.mode == .ordered) {
                defer self.first_finished.store(true, .release);
                try std.Io.sleep(base, .fromMilliseconds(150), .awake);
            }
            return error.ConnectionRefused;
        }
        if (self.mode == .ordered and !self.first_finished.load(.acquire)) self.overlapped.store(true, .release);
        if (!self.lookup_finished.load(.acquire)) self.connected_before_lookup_finished.store(true, .release);
        return base.vtable.netConnectIp(base.userdata, address, options);
    }
};

fn ordered(comptime route: enum { host, deadline, endpoint }) !void {
    var probe = Probe.init(.unlimited, .unlimited);
    defer probe.threaded.deinit();
    const io = probe.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    probe.peer = listener.socket.address;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const name = try net.HostName.init("ordered.hostname.test");
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    const stream = try switch (route) {
        .host => tcp.host(io, name, probe.peer.getPort(), null),
        .deadline => tcp.hostWithDeadline(io, name, probe.peer.getPort(), deadline),
        .endpoint => tcp.endpointWithOptions(failing.allocator(), io, null, name.bytes, probe.peer.getPort(), null, .ordered, deadline, .{}),
    };
    defer stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
    try std.testing.expect(!probe.overlapped.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), probe.connect_calls.load(.acquire));
    try std.testing.expectEqualSlices(u8, &.{ 2, 1 }, probe.seen[0..2]);
    try std.testing.expect(probe.lookup_finished.load(.acquire));
    try std.testing.expect(!failing.has_induced_failure);
}

test "TCP ordered hostname unbounded connect preserves address order" {
    try ordered(.host);
}
test "TCP ordered hostname deadline connect preserves address order" {
    try ordered(.deadline);
}
test "TCP ordered hostname endpoint policy preserves order without address allocation" {
    try ordered(.endpoint);
}

test "TCP ordered hostname starts a ready candidate before DNS completion" {
    var probe = Probe.init(.unlimited, .unlimited);
    defer probe.threaded.deinit();
    probe.mode = .streaming;
    const io = probe.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    probe.peer = listener.socket.address;
    const started = std.Io.Clock.awake.now(io);
    const stream = try tcp.host(io, try net.HostName.init("stream.hostname.test"), probe.peer.getPort(), null);
    defer stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
    try std.testing.expect(probe.connected_before_lookup_finished.load(.acquire));
    try std.testing.expect(probe.lookup_finished.load(.acquire));
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 250 * std.time.ns_per_ms);
}

test "TCP ordered hostname drains large DNS answers without async budget" {
    var probe = Probe.init(.nothing, .unlimited);
    defer probe.threaded.deinit();
    probe.mode = .many;
    const io = probe.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    probe.peer = listener.socket.address;
    const Task = struct {
        fn run(io_value: std.Io, port: u16, done: *std.Io.Event) net.HostName.ConnectError!net.Stream {
            defer done.set(io_value);
            return tcp.host(io_value, net.HostName.init("many.hostname.test") catch unreachable, port, null);
        }
    };
    var done: std.Io.Event = .unset;
    var future = try std.Io.concurrent(io, Task.run, .{ io, probe.peer.getPort(), &done });
    var active = true;
    defer if (active) {
        if (future.cancel(io)) |stream| stream.close(io) else |_| {}
    };
    // Cancel and join the old inline producer when it fills the 32-entry queue.
    try done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(500) } });
    const result = future.await(io);
    active = false;
    const stream = try result;
    defer stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
    try std.testing.expectEqual(@as(usize, 40), probe.connect_calls.load(.acquire));
    try std.testing.expect(probe.lookup_finished.load(.acquire));
}

test "TCP ordered hostname refuses missing concurrency before DNS" {
    var probe = Probe.init(.unlimited, .nothing);
    defer probe.threaded.deinit();
    const io = probe.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    probe.peer = listener.socket.address;
    if (tcp.host(io, try net.HostName.init("unavailable.hostname.test"), probe.peer.getPort(), null)) |stream| {
        stream.close(io);
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.SystemResources), err);
    try std.testing.expectEqual(@as(usize, 0), probe.lookup_calls.load(.acquire));
}

test "TCP ordered hostname stops on a fatal first candidate" {
    var probe = Probe.init(.unlimited, .unlimited);
    defer probe.threaded.deinit();
    probe.mode = .fatal;
    const io = probe.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    probe.peer = listener.socket.address;
    if (tcp.host(io, try net.HostName.init("fatal.hostname.test"), probe.peer.getPort(), null)) |stream| {
        stream.close(io);
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.AccessDenied), err);
    try std.testing.expectEqual(@as(usize, 1), probe.connect_calls.load(.acquire));
    try std.testing.expect(probe.lookup_finished.load(.acquire));
}

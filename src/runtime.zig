const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");

pub const NetworkInterface = @import("internal/network_interface.zig").NetworkInterface;
pub const NetworkInterfaceError = @import("internal/network_interface.zig").Error;

const ip_listener = @import("runtime/ip_listener.zig");

pub const TcpListenerOptions = ip_listener.Options;
pub const listenTcp = ip_listener.listen;
pub const InterfaceAddresses = ip_listener.InterfaceAddresses;
pub const InterfaceAddressError = ip_listener.InterfaceAddressError;
pub const resolveInterfaceAddresses = ip_listener.resolveInterfaceAddresses;

/// Runtime backend for netz examples and applications.
///
/// zio owns scheduling and platform I/O while protocol modules consume only
/// its standard `std.Io` interface. No zio or operating-system-specific type
/// crosses into HTTP, WebSocket, QUIC, or the other protocol APIs.
pub const BackendKind = enum { zio };

/// Coroutine-stack capacity and high-water data reported by the runtime.
/// Reserved virtual bytes are address space, not resident memory.
pub const StackMetrics = struct {
    configured_maximum_bytes: usize,
    configured_initial_committed_bytes: usize,
    active_stacks: usize,
    retained_stacks: usize,
    peak_active_stacks: usize,
    peak_committed_bytes_per_stack: usize,
    reserved_virtual_bytes: usize,
};

/// Return the zio event-loop's awake-clock snapshot when `io` belongs to the
/// task currently running on that loop. Foreign `std.Io` implementations and
/// calls outside a matching runtime retain their ordinary clock semantics.
pub fn cachedAwakeNow(io: std.Io) std.Io.Timestamp {
    return zio.cachedAwakeNow(io);
}

/// Clock-tagged form for composing an awake-clock deadline.
pub fn cachedAwakeTimestamp(io: std.Io) std.Io.Clock.Timestamp {
    return .{
        .raw = cachedAwakeNow(io),
        .clock = .awake,
    };
}

/// Placement preference for tasks spawned through `.auto` by the calling
/// task. Only the zio backend implements the hint; foreign `std.Io`
/// implementations ignore it, so protocol code can set it unconditionally.
pub const SpawnLocality = enum {
    /// Spread new tasks round-robin across executors.
    spread,
    /// Keep new tasks on the calling executor (still stealable), so a
    /// connection pump and its select arms share one executor's caches.
    local,
};

pub fn setSpawnLocality(locality: SpawnLocality) void {
    zio.setSpawnLocality(switch (locality) {
        .spread => .spread,
        .local => .local,
    });
}

pub fn getSpawnLocality() SpawnLocality {
    return switch (zio.getSpawnLocality()) {
        .spread => .spread,
        .local => .local,
    };
}

pub const Backend = struct {
    allocator: std.mem.Allocator,
    backing_allocator: std.mem.Allocator,
    cache: ?*@import("alloc.zig").BlockCache = null,
    kind: BackendKind = .zio,
    runtime: *anyopaque,

    /// Initialize the supported asynchronous backend. Protocol callers receive
    /// a `std.Io`; zio remains an implementation detail of this owner.
    pub fn init(allocator: std.mem.Allocator) !Backend {
        return initZio(allocator);
    }

    /// Initialize with a bounded message-sized block cache in front of
    /// `allocator`. The cache is heap-owned so its `std.mem.Allocator`
    /// remains stable when the returned `Backend` moves.
    pub fn initCached(
        allocator: std.mem.Allocator,
        options: @import("alloc.zig").BlockCache.Options,
    ) !Backend {
        const cache = try allocator.create(@import("alloc.zig").BlockCache);
        errdefer allocator.destroy(cache);
        cache.* = .init(allocator, options);
        const runtime = try zio.Runtime.init(cache.allocator(), .{});
        return .{
            .allocator = cache.allocator(),
            .backing_allocator = allocator,
            .cache = cache,
            .runtime = @ptrCast(runtime),
        };
    }

    /// Initialize with an explicit executor count. One executor runs every
    /// connection on the calling thread; larger values place independent
    /// connection tasks on separate threads.
    pub fn initWithExecutors(allocator: std.mem.Allocator, executors: u8) !Backend {
        if (executors == 0) return error.InvalidExecutorCount;
        const runtime = try zio.Runtime.init(allocator, .{
            .executors = @enumFromInt(executors),
        });
        return .{
            .allocator = allocator,
            .backing_allocator = allocator,
            .runtime = @ptrCast(runtime),
        };
    }

    /// Explicit spelling for applications that want to document the backend.
    pub fn initZio(allocator: std.mem.Allocator) !Backend {
        const runtime = try zio.Runtime.init(allocator, .{});
        return .{
            .allocator = allocator,
            .backing_allocator = allocator,
            .runtime = @ptrCast(runtime),
        };
    }

    pub fn io(self: *Backend) std.Io {
        return zioRuntime(self.runtime).io();
    }

    /// Snapshot coroutine stack capacity without exposing a zio-specific type
    /// through Netz's runtime facade.
    pub fn stackMetrics(self: *Backend) StackMetrics {
        const metrics = zioRuntime(self.runtime).stackMetrics();
        return .{
            .configured_maximum_bytes = metrics.configured_maximum_bytes,
            .configured_initial_committed_bytes = metrics.configured_initial_committed_bytes,
            .active_stacks = metrics.active_stacks,
            .retained_stacks = metrics.retained_stacks,
            .peak_active_stacks = metrics.peak_active_stacks,
            .peak_committed_bytes_per_stack = metrics.peak_committed_bytes_per_stack,
            .reserved_virtual_bytes = metrics.reserved_virtual_bytes,
        };
    }

    pub fn deinit(self: *Backend) void {
        zioRuntime(self.runtime).deinit();
        if (self.cache) |cache| {
            cache.deinit();
            self.backing_allocator.destroy(cache);
        }
        self.* = undefined;
    }

    fn zioRuntime(runtime: *anyopaque) *zio.Runtime {
        return @ptrCast(@alignCast(runtime));
    }
};

test "runtime backend initializes zio behind std.Io" {
    var backend = try Backend.init(std.testing.allocator);
    defer backend.deinit();

    try std.testing.expectEqual(BackendKind.zio, backend.kind);
    const io = backend.io();
    try std.testing.expect(io.userdata != null);

    const metrics = backend.stackMetrics();
    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024), metrics.configured_maximum_bytes);
    try std.testing.expectEqual(@as(usize, 256 * 1024), metrics.configured_initial_committed_bytes);
    try std.testing.expectEqual(@as(usize, 0), metrics.active_stacks);
    try std.testing.expectEqual(@as(usize, 0), metrics.retained_stacks);
    try std.testing.expectEqual(@as(usize, 0), metrics.reserved_virtual_bytes);
}

test "runtime backend cached allocator reuses message blocks" {
    var backend = try Backend.initCached(std.testing.allocator, .{});
    defer backend.deinit();
    const allocator = backend.allocator;
    const first = try allocator.alloc(u8, 256 * 1024);
    allocator.free(first);
    const second = try allocator.alloc(u8, 256 * 1024);
    try std.testing.expectEqual(first.ptr, second.ptr);
    allocator.free(second);
}

test "runtime cached awake timestamp follows zio event-loop scans" {
    var backend = try Backend.init(std.testing.allocator);
    defer backend.deinit();
    const io = backend.io();

    const before = cachedAwakeNow(io);
    zio.os.time.sleep(.fromMilliseconds(2));
    try std.testing.expectEqual(before.nanoseconds, cachedAwakeNow(io).nanoseconds);
    const tagged = cachedAwakeTimestamp(io);
    try std.testing.expectEqual(std.Io.Clock.awake, tagged.clock);
    try std.testing.expectEqual(before.nanoseconds, tagged.raw.nanoseconds);

    try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    try std.testing.expect(cachedAwakeNow(io).nanoseconds > before.nanoseconds);
}

test "runtime backend zio std.Io TCP round trip" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try std.Io.net.IpAddress.listen(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .reuse_address = true },
    );
    defer server.deinit(io);

    const Echo = struct {
        fn run(
            echo_io: std.Io,
            listener: *std.Io.net.Server,
            result: *anyerror!void,
        ) void {
            result.* = runFallible(echo_io, listener);
        }

        fn runFallible(
            echo_io: std.Io,
            listener: *std.Io.net.Server,
        ) !void {
            const peer = try listener.accept(echo_io);
            defer peer.close(echo_io);

            var read_buffer: [16]u8 = undefined;
            var reader = peer.reader(echo_io, &read_buffer);
            var payload: [4]u8 = undefined;
            const received = try reader.interface.readSliceShort(&payload);

            var write_buffer: [16]u8 = undefined;
            var writer = peer.writer(echo_io, &write_buffer);
            try writer.interface.writeAll(payload[0..received]);
            try writer.interface.flush();
            try peer.shutdown(echo_io, .send);
        }
    };

    var echo_result: anyerror!void = {};
    var echo = io.async(Echo.run, .{ io, &server, &echo_result });
    defer echo.cancel(io);

    const client = try std.Io.net.IpAddress.connect(
        &server.socket.address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    var write_buffer: [16]u8 = undefined;
    var writer = client.writer(io, &write_buffer);
    try writer.interface.writeAll("ping");
    try writer.interface.flush();
    try client.shutdown(io, .send);

    var read_buffer: [16]u8 = undefined;
    var reader = client.reader(io, &read_buffer);
    var payload: [4]u8 = undefined;
    const received = try reader.interface.readSliceShort(&payload);
    try std.testing.expectEqualStrings("ping", payload[0..received]);

    echo.await(io);
    try echo_result;
}

test "runtime backend zio std.Io drains queued UDP datagrams in one batch" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const io = backend.io();

    var sender = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer sender.close(io);
    var receiver = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer receiver.close(io);

    const expected = [_][]const u8{ "one", "two", "three", "four" };
    for (expected) |payload| {
        try sender.send(io, &receiver.address, payload);
    }

    var messages: [expected.len]std.Io.net.IncomingMessage =
        @splat(.init);
    var storage: [expected.len * 16]u8 = undefined;
    const receive_error, const count = receiver.receiveManyTimeout(
        io,
        &messages,
        &storage,
        .{},
        .{ .duration = .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        } },
    );
    try std.testing.expectEqual(null, receive_error);
    try std.testing.expectEqual(expected.len, count);
    for (messages[0..count], expected) |message, payload| {
        try std.testing.expectEqualStrings(payload, message.data);
        try std.testing.expect(message.from.eql(&sender.address));
    }
}

test "runtime backend accepts an explicit executor count" {
    var backend = try Backend.initWithExecutors(std.testing.allocator, 2);
    defer backend.deinit();
    const io = backend.io();
    try std.testing.expect(io.userdata != null);
    var task = try io.concurrent(struct {
        fn run(value: std.Io) !void {
            try std.Io.sleep(value, .fromMilliseconds(10), .awake);
        }
    }.run, .{io});
    try task.await(io);
    try std.testing.expectError(error.InvalidExecutorCount, Backend.initWithExecutors(std.testing.allocator, 0));
}

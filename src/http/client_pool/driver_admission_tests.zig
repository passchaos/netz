//! Pool owners must progress independently even when async may execute inline.
const std = @import("std");
const http = @import("../client_pool.zig");

fn options(shared_endpoint: bool) http.Options {
    return .{ .http3 = .{
        .shared_endpoint = shared_endpoint,
        .handshake = .{ .handshake = .{
            .server_auth = .{ .pinned_ecdsa_p256_public_key = @splat(7) },
            .original_destination_connection_id = &.{1},
            .local_connection_id = &.{2},
        } },
    } };
}

test "HTTP H3 pool driver admission starts independently with zero async capacity" {
    var backend = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .nothing });
    defer backend.deinit();
    const io = backend.io();
    const Worker = struct {
        io: std.Io,
        shared_endpoint: bool,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.io);
            var pool = http.Pool.init(std.testing.allocator, self.io, options(self.shared_endpoint)) catch |err| {
                self.err = err;
                return;
            };
            pool.deinit();
        }
    };
    inline for (.{ true, false }) |shared_endpoint| {
        var worker: Worker = .{ .io = io, .shared_endpoint = shared_endpoint };
        var future = try std.Io.concurrent(io, Worker.run, .{&worker});
        defer future.cancel(io);
        try worker.done.waitTimeout(io, .{ .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }) });
        future.await(io);
        if (worker.err) |err| return err;
    }
}

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    future_calls: std.atomic.Value(usize) = .init(0),
    group_calls: std.atomic.Value(usize) = .init(0),
    reject_future: usize = 0,
    reject_group: usize = 0,

    fn io(self: *@This()) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.concurrent = concurrent;
        self.table.groupConcurrent = groupConcurrent;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn context(userdata: ?*anyopaque) *@This() {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }

    fn concurrent(userdata: ?*anyopaque, result_len: usize, result_alignment: std.mem.Alignment, args: []const u8, args_alignment: std.mem.Alignment, start: *const fn (*const anyopaque, *anyopaque) void) std.Io.ConcurrentError!*std.Io.AnyFuture {
        const self = context(userdata);
        const call = self.future_calls.fetchAdd(1, .monotonic) + 1;
        if (call == self.reject_future) return error.ConcurrencyUnavailable;
        const base = self.backend.io();
        return base.vtable.concurrent(userdata, result_len, result_alignment, args, args_alignment, start);
    }

    fn groupConcurrent(userdata: ?*anyopaque, group: *std.Io.Group, args: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        const self = context(userdata);
        const call = self.group_calls.fetchAdd(1, .monotonic) + 1;
        if (call == self.reject_group) return error.ConcurrencyUnavailable;
        const base = self.backend.io();
        return base.vtable.groupConcurrent(userdata, group, args, alignment, start);
    }
};

test "HTTP H3 pool driver admission rejects missing owners and joins an admitted owner" {
    for (1..3) |reject| {
        var probe: Probe = .{
            .backend = .init(std.testing.allocator, .{ .async_limit = .nothing }),
            .reject_future = reject,
        };
        defer probe.backend.deinit();
        var allocations = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        try std.testing.expectError(error.ConcurrencyUnavailable, http.Pool.init(allocations.allocator(), probe.io(), options(true)));
        try std.testing.expectEqual(reject, probe.future_calls.load(.monotonic));
        try std.testing.expectEqual(allocations.allocated_bytes, allocations.freed_bytes);
        // Disabling the optional backend needs no independently running owner.
        var tcp_only = try http.Pool.init(std.testing.allocator, probe.io(), .{});
        tcp_only.deinit();
        try std.testing.expectEqual(reject, probe.future_calls.load(.monotonic));
    }
}

test "HTTP H3 pool driver admission retries a rejected lazy SOCKS5 owner" {
    const socks = @import("../../proxy/socks/server.zig");
    const cache = @import("../alt_svc_cache.zig");
    var probe: Probe = .{
        .backend = .init(std.testing.allocator, .{ .async_limit = .unlimited }),
        .reject_future = 2,
    };
    defer probe.backend.deinit();
    const base = probe.backend.io();
    var proxy = try socks.Server.init(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{
        .auth = .{ .allow_anonymous = true },
        .acl = .{ .default_action = .allow },
        .allow_udp = true,
    });
    defer proxy.deinit();
    const Peer = struct {
        fn run(server: *socks.Server) !void {
            try server.serve();
        }
    };
    var peer = try std.Io.concurrent(base, Peer.run, .{&proxy});
    defer peer.cancel(base) catch {};
    const io = probe.io();
    var configuration = options(true);
    configuration.client.socks5_proxy = .{ .host = "127.0.0.1", .port = proxy.listener.socket.address.ip4.port };
    var pool = try http.Pool.init(std.testing.allocator, io, configuration);
    defer pool.deinit();
    var host = "localhost".*;
    var alpn = "h3".*;
    const alternative: cache.Alternative = .{
        .allocator = std.testing.allocator,
        .storage = &.{},
        .alpn = &alpn,
        .connect_host = &host,
        .origin_host = &host,
        .port = 443,
        .expires_at_ms = std.math.maxInt(u64),
        .failure_count = 0,
    };
    const Reclaim = struct {
        fn run(_: *anyopaque) bool {
            return false;
        }
    };
    const state = pool.http3.?;
    inline for (.{ false, true }) |retry| {
        if (retry) probe.reject_future = 0;
        // The invalid URI ends the retry after endpoint/driver admission,
        // without needing a QUIC peer or changing trust expectations.
        try std.testing.expectError(if (retry) error.InvalidUri else error.ConcurrencyUnavailable, state.request(
            .{ .scheme = "https", .host = &host, .port = 443 },
            "invalid",
            &alternative,
            .{},
            false,
            .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }),
            false,
            false,
            .{ .context = &pool, .reclaim = Reclaim.run },
        ));
        try std.testing.expectEqual(retry, state.shared_pool != null);
        try std.testing.expectEqual(retry, state.shared_dispatcher != null);
        try std.testing.expectEqual(retry, state.shared_driver != null);
        try std.testing.expect(!state.closed.load(.acquire));
    }
}

test "HTTP H3 pool driver admission joins a partially admitted route group" {
    const runtime = @import("../../http3/runtime.zig");
    for (1..3) |reject| {
        var probe: Probe = .{
            .backend = .init(std.testing.allocator, .{ .async_limit = .nothing }),
            .reject_group = reject,
        };
        defer probe.backend.deinit();
        const io = probe.io();
        var allocations = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        {
            var connector: runtime.HandshakeClientPoolDefaultConnector = .{ .options = options(false).http3.?.handshake };
            var pool = try runtime.HandshakeClientPool.init(allocations.allocator(), io, .{
                .local_address = .{ .ip4 = .loopback(0) },
                .connector = connector.connector(),
            });
            defer pool.deinit();
            var dispatcher = try runtime.HandshakeClientPoolSharedDispatcher.init(allocations.allocator(), io, &pool, .{ .max_connection_drivers = 2 });
            defer dispatcher.deinit();
            try std.testing.expectError(error.ConcurrencyUnavailable, dispatcher.run());
            try std.testing.expectEqual(reject, probe.group_calls.load(.monotonic));
            try std.testing.expect(!dispatcher.state.running.load(.acquire));
            try std.testing.expect(dispatcher.state.closed);
        }
        try std.testing.expectEqual(allocations.allocated_bytes, allocations.freed_bytes);
    }
}

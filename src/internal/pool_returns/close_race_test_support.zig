//! A completed close must reject publication by an older connection attempt.
const std = @import("std");
const http = @import("../../http/client_pool.zig");
const h1 = @import("../../http1/runtime.zig");
const h2 = @import("../../http2/runtime.zig");

pub fn exercise(comptime Pool: type, comptime h2_protocol: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const Protocol = if (h2_protocol) h2 else h1;
    var server = try Protocol.Server.listen(std.testing.allocator, base, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        server: *Protocol.Server,
        finish: std.Io.Event = .unset,
        error_result: ?anyerror = null,
        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.error_result = err;
                return;
            };
            defer connection.close();
            self.finish.waitUncancelable(self.server.io);
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    defer {
        worker.finish.set(base);
        thread.join();
    }
    var pool = if (Pool == http.Pool)
        try Pool.init(std.testing.allocator, base, .{ .client = .{ .cleartext_protocol = if (h2_protocol) .http2_prior_knowledge else .http1 } })
    else
        try Pool.init(std.testing.allocator, base, .{});
    defer pool.deinit();
    const Gate = struct {
        base: std.Io,
        pool: *Pool,
        connections: usize = 0,
        var active: ?*@This() = null;
        fn connect(userdata: ?*anyopaque, address: *const std.Io.net.IpAddress, options: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
            const self = active.?;
            const socket = try self.base.vtable.netConnectIp(userdata, address, options);
            self.connections += 1;
            self.pool.close();
            return socket;
        }
    };
    var gate = Gate{ .base = base, .pool = &pool };
    var table = base.vtable.*;
    table.netConnectIp = Gate.connect;
    Gate.active = &gate;
    pool.io = .{ .userdata = base.userdata, .vtable = &table };
    defer {
        Gate.active = null;
        pool.io = base;
    }
    const uri = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/", .{server.address().ip4.port});
    defer std.testing.allocator.free(uri);
    if (pool.acquireUriWithTimeout(uri, .fromSeconds(1))) |value| {
        var lease = value;
        lease.discard();
        return error.UnexpectedLeaseAfterPoolClose;
    } else |err| try std.testing.expectEqual(error.PoolClosed, err);
    try std.testing.expectEqual(@as(usize, 1), gate.connections);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    if (Pool == http.Pool) try std.testing.expectEqual(@as(usize, 0), pool.shared_budget.connectionCount());
}

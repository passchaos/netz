//! A retirement during node allocation must not become a missed retry hint.
const std = @import("std");
const Node = @import("../owned_fifo_admission/node.zig").Node;

pub fn exercise(comptime Pool: type, base: std.Io) !void {
    const Scenario = struct {
        backing: std.mem.Allocator,
        pool: *Pool,
        fired: bool = false,
        network_calls: usize = 0,
        var active: ?*@This() = null;

        fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            if (!self.fired and len == @sizeOf(Node) and self.pool.mutex.state.load(.acquire) != .unlocked) {
                self.fired = true;
                // Model the leased socket being destroyed after admission's
                // capacity check, before its new node captures the epoch.
                self.pool.retired_connections.release(&self.pool.connections, &self.pool.capacity_waiters, &self.pool.mutex, self.pool.io, 1);
                if (comptime @hasField(Pool, "shared_budget")) self.pool.shared_budget.release(1);
            }
            return self.backing.rawAlloc(len, alignment, ret);
        }
        fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.backing.rawFree(bytes, alignment, ret);
        }
        fn connect(_: ?*anyopaque, _: *const std.Io.net.IpAddress, _: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
            active.?.network_calls += 1;
            return error.NetworkUnreachable;
        }
        const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free };
    };
    var pool = try Pool.init(std.testing.allocator, base, .{});
    defer pool.deinit();
    pool.options.max_connections = 1;
    pool.connections = 1;
    if (comptime @hasField(Pool, "shared_budget")) try pool.shared_budget.tryReserve(null);
    var scenario = Scenario{ .backing = std.testing.allocator, .pool = &pool };
    Scenario.active = &scenario;
    var table = base.vtable.*;
    table.netConnectIp = Scenario.connect;
    pool.io = .{ .userdata = base.userdata, .vtable = &table };
    pool.allocator = .{ .ptr = &scenario, .vtable = &Scenario.vtable };
    defer {
        pool.io = base;
        pool.allocator = std.testing.allocator;
        Scenario.active = null;
    }
    try std.testing.expectError(error.NetworkUnreachable, pool.acquireUriWithTimeout("http://127.0.0.1:1/", .fromSeconds(1)));
    try std.testing.expect(scenario.fired);
    // A missed hint would time out without reaching a replacement connect.
    try std.testing.expectEqual(@as(usize, 1), scenario.network_calls);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
    if (comptime @hasField(Pool, "shared_budget")) try std.testing.expectEqual(@as(usize, 0), pool.shared_budget.connectionCount());
}

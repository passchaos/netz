const std = @import("std");
const h1 = @import("../../http1/client_pool.zig");
const h2 = @import("../../http2/client_pool.zig");
const http = @import("../../http/client_pool.zig");

fn exercise(comptime Pool: type, io: std.Io) !void {
    const ReturnNode = @FieldType(Pool, "returns").Node;
    const Allocator = struct {
        backing: std.mem.Allocator,
        rejected: bool = false,
        calls: usize = 0,
        var active: ?*@This() = null;
        fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            if (len == @sizeOf(ReturnNode)) {
                self.rejected = true;
                return null;
            }
            return self.backing.rawAlloc(len, alignment, ret);
        }
        fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.backing.rawFree(bytes, alignment, ret);
        }
        fn connect(_: ?*anyopaque, _: *const std.Io.net.IpAddress, _: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
            active.?.calls += 1;
            return error.NetworkUnreachable;
        }
        const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free };
    };
    var allocator = Allocator{ .backing = std.testing.allocator };
    var table = io.vtable.*;
    table.netConnectIp = Allocator.connect;
    Allocator.active = &allocator;
    defer Allocator.active = null;
    var pool = try Pool.init(.{ .ptr = &allocator, .vtable = &Allocator.vtable }, .{ .userdata = io.userdata, .vtable = &table }, .{});
    defer pool.deinit();
    try std.testing.expectError(error.OutOfMemory, pool.acquireUriWithTimeout("http://127.0.0.1:1/", .fromSeconds(1)));
    try std.testing.expect(allocator.rejected);
    try std.testing.expectEqual(@as(usize, 0), allocator.calls);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
    if (comptime Pool == http.Pool) try std.testing.expectEqual(@as(usize, 0), pool.shared_budget.connectionCount());
}

test "connection return node allocation failure releases reserved capacity before connecting" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ h1.Pool, h2.Pool, http.Pool }) |Pool| try exercise(Pool, threaded.io());
}

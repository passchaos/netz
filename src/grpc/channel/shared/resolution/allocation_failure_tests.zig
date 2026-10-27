//! Rejecting a resolver replacement must leave the last valid transport usable.
const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

const FailNext = struct {
    fail: std.atomic.Value(bool) = .init(false),
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.fail.swap(false, .acq_rel)) return null;
        return std.testing.allocator.rawAlloc(len, alignment, ra);
    }
    fn resize(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        return std.testing.allocator.rawResize(bytes, alignment, len, ra);
    }
    fn remap(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
    }
    fn free(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        std.testing.allocator.rawFree(bytes, alignment, ra);
    }
};

test "gRPC shared hostname replacement allocation failure preserves a ready connection" {
    const Resolver = struct {
        address: support.Address,
        fail_next: *FailNext,
        calls: std.atomic.Value(usize) = .init(0),
        fn resolve(context: *anyopaque, gpa: std.mem.Allocator, _: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) grpc.ChannelAddressResolver.ResolveError![]support.Address {
            const self: *@This() = @ptrCast(@alignCast(context));
            const addresses = try gpa.dupe(support.Address, &.{self.address});
            // Publication itself does not allocate. Arm after the owned DNS
            // result exists, so the subsequent membership replacement fails.
            if (self.calls.fetchAdd(1, .monotonic) == 1) self.fail_next.fail.store(true, .release);
            return addresses;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{server.address().getPort()});
    defer allocator.free(authority);
    var peer = support.Peer{ .server = &server, .authority = authority, .reply = "preserved", .requests = 2 };
    var task = io.async(support.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var failing: FailNext = .{};
    var resolver = Resolver{ .address = server.address(), .fail_next = &failing };
    var client = try shared.SharedChannel.init(failing.allocator(), io, .{ .cleartext_host = .{ .host = "resolve.test", .port = server.address().getPort() } }, .{ .channel = .{ .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve }, .resolver_min_refresh_interval = .zero } });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var first = try support.unary(sender, "first");
    defer first.deinit();
    try std.testing.expectError(error.OutOfMemory, client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    try std.testing.expectEqual(@as(usize, 1), client.endpointCount());
    try std.testing.expectEqual(grpc.ChannelConnectivityState.ready, client.connectivityState());
    var second = try support.unary(sender, "after-rejection");
    defer second.deinit();
    try std.testing.expectEqualStrings("preserved", second.message.?.payload);
    client.deinit();
    live = false;
    try task.await(io);
}

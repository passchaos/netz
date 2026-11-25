const std = @import("std");
const runtime = @import("../../runtime.zig");
const shared = @import("../../../internal/testing/connection_race_admission.zig");

test "HTTP3 connection race admission preserves handshake timeout before allocation" {
    try shared.rejected(false, error.HandshakeTimeout);
    try shared.rejected(true, error.HandshakeTimeout);
}

test "HTTP3 connection race admission rejects a resolver result at the expired deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const Resolver = struct {
        allocator: *std.testing.FailingAllocator,
        calls: usize = 0,
        fn resolve(context: *anyopaque, allocator: std.mem.Allocator, active_io: std.Io, _: []const u8, _: u16, deadline: ?std.Io.Clock.Timestamp) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            const addresses = try allocator.alloc(std.Io.net.IpAddress, 9);
            errdefer allocator.free(addresses);
            @memset(addresses, .{ .ip4 = .loopback(1) });
            try @import("../../../internal/deadline.zig").waitUntil(active_io, deadline.?);
            // Any allocation after the late result obscures the phase timeout.
            self.allocator.fail_index = self.allocator.alloc_index;
            return addresses;
        }
    };
    var resolver: Resolver = .{ .allocator = &failing };
    const uri = try std.Uri.parse("https://late.race.test/");
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(50) });
    try std.testing.expectError(error.HandshakeTimeout, runtime.HandshakeClient.connectUriWithDeadline(failing.allocator(), io, .{ .ip4 = .loopback(0) }, uri, .{}, .{
        .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} },
        .address_resolver = .{ .context = &resolver, .resolve = Resolver.resolve },
        .address_connect_policy = .{ .happy_eyeballs = .{} },
    }, deadline));
    try std.testing.expectEqual(@as(usize, 1), resolver.calls);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

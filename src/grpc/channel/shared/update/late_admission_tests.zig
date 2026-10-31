const std = @import("std");
const shared = @import("../../shared.zig");
const allocator = std.testing.allocator;

test "gRPC shared update checks the deadline after candidate task admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var client = try shared.SharedChannel.init(allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer client.deinit();
    const original = client.state.sources[0];
    const Probe = struct {
        io: std.Io,
        calls: usize = 0,
        var active: ?*@This() = null;

        fn concurrent(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            const self = active.?;
            try self.io.vtable.groupConcurrent(userdata, group, context, alignment, start);
            self.calls += 1;
            // Admission succeeds but consumes more than the caller's budget.
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var probe = Probe{ .io = base };
    var table = base.vtable.*;
    table.groupConcurrent = Probe.concurrent;
    Probe.active = &probe;
    client.state.io = .{ .userdata = base.userdata, .vtable = &table };
    defer {
        client.state.io = base;
        Probe.active = null;
    }
    try std.testing.expectError(error.Timeout, client.updateWithTimeout(.{ .target = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) } } } }, .fromMilliseconds(200)));
    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    try std.testing.expect(client.state.sources[0] == original);
    try std.testing.expect(!original.retired);
    try std.testing.expect(!client.state.demand);
}

const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = std.testing.allocator;

test "gRPC retained child cancels staged manager when admission exhausts update budget" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(.{ .ip4 = .loopback(1) }, &support.path_a), support.endpoint(.{ .ip4 = .loopback(2) }, &support.path_b) };
    var client = try shared.SharedChannel.init(allocator, base, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = support.cfg_a });
    defer client.deinit();
    const Probe = struct {
        io: std.Io,
        calls: usize = 0,
        var active: ?*@This() = null;
        fn start(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, function: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            const self = active.?;
            try self.io.vtable.groupConcurrent(userdata, group, context, alignment, function);
            self.calls += 1;
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var probe = Probe{ .io = base };
    var table = base.vtable.*;
    table.groupConcurrent = Probe.start;
    Probe.active = &probe;
    client.state.io = .{ .userdata = base.userdata, .vtable = &table };
    defer {
        client.state.io = base;
        Probe.active = null;
    }
    try std.testing.expectError(error.Timeout, client.updateWithTimeout(.{ .service_config = .{ .replace = support.cfg_b } }, .fromMilliseconds(200)));
    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expectEqual(@as(u64, 1), client.configurationRevision());
    try std.testing.expectEqual(@as(usize, 0), client.retainedChildCount());
    try std.testing.expect(!client.state.retention.manager_started);
    try std.testing.expect(!client.state.sources[0].suspended);
}

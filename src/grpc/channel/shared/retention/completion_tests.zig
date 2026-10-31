const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test "gRPC retained child records an active failure while disabled and restores its bucket" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var entered: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(server: *grpc.runtime.Server, admitted: *std.Io.Event, finish: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            admitted.set(connection.connection.io);
            try finish.wait(connection.connection.io);
            try connection.writeUnary(request.request.stream_id, .{ .status = .unavailable });
            try @import("../resolution/test_support.zig").closed(&connection);
        }
    };
    var a_task = io.async(Peer.run, .{ &a, &entered, &release });
    defer _ = a_task.cancel(io) catch {};
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 1 };
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(a.address(), &support.path_a), support.endpoint(b.address(), &support.path_b) };
    const cfg = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"outlier_detection_experimental\":{\"interval\":\"60s\",\"failurePercentageEjection\":{},\"childPolicy\":[{\"round_robin\":{}}]}}]}}}}]}";
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = cfg });
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(support.unary, .{sender});
    defer _ = pending.cancel(io) catch {};
    try entered.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } });
    const source = client.state.sources[0];
    _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = endpoints[1..] } }, .service_config = .{ .replace = support.cfg_b } });
    var current = try support.unary(sender);
    defer current.deinit();
    try std.testing.expectEqualStrings("B", current.message.?.payload);
    release.set(io);
    var old = try pending.await(io);
    defer old.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, old.status);
    _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } }, .service_config = .{ .replace = cfg } });
    {
        client.state.lock();
        defer client.state.unlock();
        try std.testing.expect(client.state.sources[0] == source);
        try std.testing.expectEqual(@as(u64, 1), source.current[0].weighted_outliers[0].failures.load(.acquire));
    }
}

//! Admitted calls retain their transport when the cluster config is removed.
const std = @import("std");
const grpc = @import("../mod.zig");
const shared = @import("shared.zig");
const config = @import("cluster_manager_tests.zig").json;
const allocator = std.testing.allocator;
const Peer = @import("shared/weighted_target/test_support.zig").Peer;

fn invoke(sender: shared.Sender, cluster: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Cluster/Unary", .message = "request", .xds_cluster = cluster, .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}

test "gRPC cluster manager removes only new admission while an active RPC completes" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Held = struct {
        fn run(server: *grpc.runtime.Server, entered: *std.Io.Event, finish: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            entered.set(connection.connection.io);
            try finish.waitTimeout(connection.connection.io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
            try connection.writeUnary(request.request.stream_id, .{ .message = "a" });
            var extra = connection.readUnaryWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.UnexpectedEof, error.SocketUnconnected => return,
                else => return err,
            };
            defer extra.deinit();
            return error.UnexpectedExtraRequest;
        }
    };
    var stop: std.Io.Event = .unset;
    var a_task = io.async(Held.run, .{ &a, &admitted, &release });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Peer.run, .{ &b, &stop, "b", null });
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a.address(), .hierarchical_path = &.{"a"} } },
        .{ .cleartext_ip = .{ .address = b.address(), .hierarchical_path = &.{"b"} } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = config });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var active = try io.concurrent(invoke, .{ sender, "a" });
    defer _ = active.cancel(io) catch {};
    try admitted.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    const change = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"b\":{\"childPolicy\":[{\"pick_first\":{}}]}}}}]}";
    _ = try client.updateWithTimeout(.{ .service_config = .{ .replace = change } }, .fromSeconds(3));
    try std.testing.expectError(error.UnknownCluster, invoke(sender, "a"));
    var next = try invoke(sender, "b");
    defer next.deinit();
    try std.testing.expectEqualStrings("b", next.message.?.payload);
    release.set(io);
    var retained = try active.await(io);
    defer retained.deinit();
    try std.testing.expectEqualStrings("a", retained.message.?.payload);
    client.deinit();
    live = false;
    stop.set(io);
    try a_task.await(io);
    try b_task.await(io);
}

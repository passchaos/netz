const std = @import("std");
const grpc = @import("../../mod.zig");
const service = @import("../../service_config.zig");
const gpa = std.testing.allocator;
pub const limited = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{\"childPolicy\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"impl-a\",\"edsServiceName\":\"eds-a\",\"maxConcurrentRequests\":1,\"childPolicy\":[{\"round_robin\":{}}]}}]},\"b\":{\"childPolicy\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"impl-b\",\"edsServiceName\":\"eds-b\",\"maxConcurrentRequests\":2,\"childPolicy\":[{\"round_robin\":{}}]}}]}}}}]}";
pub const dropped = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{\"childPolicy\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"impl-drop-a\",\"dropCategories\":[{\"category\":\"full\",\"requestsPerMillion\":1000000}],\"childPolicy\":[{\"round_robin\":{}}]}}]},\"b\":{\"childPolicy\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"impl-drop-b\",\"childPolicy\":[{\"round_robin\":{}}]}}]}}}}]}";
test "gRPC cluster impl parses bounded identity circuit drops and child policies" {
    var config = try service.ServiceConfig.parse(gpa, limited);
    defer config.deinit();
    const root = config.loadBalancingConfig().root.?;
    try std.testing.expect(root.* == .cluster_manager);
    const child = root.cluster_manager.targets[0].child.cluster_impl;
    try std.testing.expectEqualStrings("impl-a", child.admission.cluster);
    try std.testing.expectEqual(@as(u32, 1), child.admission.max_concurrent_requests);
    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var parsed = try service.ServiceConfig.parse(allocator, dropped);
            defer parsed.deinit();
            const Runtime = @import("../shared/state.zig").State.WeightedTarget;
            var runtime = try Runtime.init(allocator, parsed.loadBalancingConfig().root.?);
            defer runtime.deinit();
            const policy = (try @import("../cluster_impl.zig").forCluster(runtime.root, "a")).?;
            try std.testing.expect(policy.drops.dropsAll());
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{});
    for ([_][]const u8{
        "{\"loadBalancingConfig\":[{\"xds_cluster_impl_experimental\":{\"childPolicy\":[{\"round_robin\":{}}]}}]}",
        "{\"loadBalancingConfig\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"a\",\"maxConcurrentRequests\":-1,\"childPolicy\":[{\"round_robin\":{}}]}}]}",
        "{\"loadBalancingConfig\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"a\",\"dropCategories\":[{\"category\":\"bad\",\"requestsPerMillion\":1000001}],\"childPolicy\":[{\"round_robin\":{}}]}}]}",
    }) |json| try std.testing.expectError(error.InvalidServiceConfig, service.ServiceConfig.parse(gpa, json));
}
test "gRPC cluster impl drops one selected cluster without affecting another ordinary and shared" {
    for ([_]bool{ false, true }) |is_shared| {
        var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
        defer server.deinit();
        var stop: std.Io.Event = .unset;
        var peer = io.async(@import("../shared/weighted_target/test_support.zig").Peer.run, .{ &server, &stop, "b", null });
        defer _ = peer.cancel(io) catch {};
        const endpoints = [_]grpc.ChannelEndpoint{.{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &.{"b"} } }};
        var parsed = try grpc.ServiceConfig.parse(gpa, dropped);
        defer parsed.deinit();
        var ordinary = if (!is_shared) try grpc.Channel.initWithServiceConfig(gpa, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{}, &parsed) else null;
        defer if (ordinary) |*value| value.deinit();
        var shared = if (is_shared) try grpc.SharedChannel.init(gpa, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = dropped }) else null;
        var live = is_shared;
        defer if (live) shared.?.deinit();
        var sender = if (is_shared) shared.?.sender() else null;
        defer if (sender) |*value| value.deinit();
        const failed: grpc.UnaryCallOptions = .{ .path = "/demo.Impl/Unary", .message = "request", .xds_cluster = "a" };
        var response = if (sender) |value| try value.unary(failed) else try ordinary.?.unary(failed);
        defer response.deinit();
        try std.testing.expect(response.was_dropped and response.status == .unavailable and response.transport == null);
        const good: grpc.UnaryCallOptions = .{ .path = "/demo.Impl/Unary", .message = "request", .xds_cluster = "b", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } };
        var allowed = if (sender) |value| try value.unary(good) else try ordinary.?.unary(good);
        defer allowed.deinit();
        try std.testing.expectEqualStrings("b", allowed.message.?.payload);
        if (shared) |value| {
            try std.testing.expectEqual(@as(u64, 1), (try value.clusterDropStats("a")).dropped);
            try std.testing.expectEqual(@as(u64, 1), (try value.clusterCircuitStats("b")).admitted);
            shared.?.deinit();
            live = false;
        }
        stop.set(io);
        try peer.await(io);
    }
}

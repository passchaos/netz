const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const allocator = std.testing.allocator;

test "gRPC shared update rebuilds ring and round robin from canonical endpoints" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .ring_hash_key = "a", .ring_hash_weight = 1 } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .ring_hash_key = "a", .ring_hash_weight = 2 } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) }, .ring_hash_key = "b" } },
    };
    const ring = "{\"loadBalancingConfig\":[{\"ring_hash_experimental\":{\"minRingSize\":16,\"maxRingSize\":16}}]}";
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = ring });
    defer client.deinit();
    const a = client.state.sources[0];
    const b = client.state.sources[1];
    try std.testing.expectEqual(@as(usize, 2), client.endpointCount());
    try std.testing.expectEqual(@as(u64, 2), try client.update(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"round_robin\":{}}]}" } }));
    try std.testing.expectEqual(grpc.ChannelSelectionPolicy.round_robin, client.selectionPolicy());
    try std.testing.expectEqual(@as(usize, 3), client.endpointCount());
    try std.testing.expectEqual(@as(usize, 3), client.configuredEndpointCount());
    try std.testing.expect(client.state.sources[0] == a and client.state.sources[2] == b);
    try std.testing.expectEqual(@as(u64, 3), try client.update(.{ .service_config = .{ .replace = ring } }));
    try std.testing.expectEqual(grpc.ChannelSelectionPolicy.ring_hash, client.selectionPolicy());
    try std.testing.expectEqual(@as(usize, 2), client.endpointCount());
    try std.testing.expect(client.state.sources[0] == a and client.state.sources[1] == b);
    try std.testing.expectEqual(@as(u32, 3), a.ring_hash_weight);
    try std.testing.expect(!client.state.demand);
}

test "gRPC shared update composes weighted ring WRR and outlier replacements" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const path = [_][]const u8{"a"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .ring_hash_key = "a", .ring_hash_weight = 1, .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .ring_hash_key = "a", .ring_hash_weight = 2, .hierarchical_path = &path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{});
    defer client.deinit();
    _ = try client.update(.{ .service_config = .{ .replace =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{
        \\ "a":{"weight":1,"childPolicy":[{"ring_hash_experimental":{"minRingSize":16,"maxRingSize":16}}]}
        \\}}}]}
    } });
    try std.testing.expectEqual(@as(usize, 1), client.endpointCount());
    _ = try client.update(.{ .service_config = .{ .replace =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{
        \\ "a":{"weight":1,"childPolicy":[{"outlier_detection_experimental":{"childPolicy":[
        \\ {"weighted_round_robin":{"enableOobLoadReport":false}}
        \\ ]}}]}
        \\}}}]}
    } });
    try std.testing.expectEqual(grpc.ChannelSelectionPolicy.weighted_target, client.selectionPolicy());
    try std.testing.expectEqual(@as(usize, 2), client.endpointCount());
    client.state.lock();
    defer client.state.unlock();
    try std.testing.expectEqual(@as(usize, 1), client.state.weighted_target.?.outlierCount());
    for (client.state.workers.items) |worker| {
        if (!worker.retired) try std.testing.expectEqual(@as(usize, 1), worker.weighted_outliers.len);
    }
}

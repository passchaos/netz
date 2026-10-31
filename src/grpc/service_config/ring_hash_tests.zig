const std = @import("std");
const service_config = @import("../service_config.zig");

test "gRPC ring hash service config validates sizes and hash header" {
    var defaults = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{}}]}
    );
    defer defaults.deinit();
    const default_lb = defaults.loadBalancingConfig();
    try std.testing.expectEqual(
        service_config.LoadBalancingPolicy.ring_hash,
        default_lb.policy,
    );
    try std.testing.expectEqual(@as(usize, 1024), default_lb.ring_hash.min_ring_size);
    try std.testing.expectEqual(@as(usize, 4096), default_lb.ring_hash.max_ring_size);
    try std.testing.expectEqual(@as(?[]const u8, null), default_lb.ring_hash.request_hash_header);

    var configured = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{
        \\ "minRingSize":"16","maxRingSize":64,
        \\ "requestHashHeader":"x-shard"}}]}
    );
    defer configured.deinit();
    const ring = configured.loadBalancingConfig().ring_hash;
    try std.testing.expectEqual(@as(usize, 16), ring.min_ring_size);
    try std.testing.expectEqual(@as(usize, 64), ring.max_ring_size);
    try std.testing.expectEqualStrings("x-shard", ring.request_hash_header.?);

    for ([_][]const u8{
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"minRingSize":0}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"maxRingSize":8388609}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"minRingSize":8,"maxRingSize":4}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"minRingSize":1.5}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"requestHashHeader":"X-Shard"}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"requestHashHeader":"grpc-timeout"}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"requestHashHeader":"token-bin"}}]}
        ,
        \\{"loadBalancingConfig":[{"ring_hash_experimental":{"unknown":1}}]}
        ,
    }) |json| {
        try std.testing.expectError(
            error.InvalidServiceConfig,
            service_config.ServiceConfig.parse(std.testing.allocator, json),
        );
    }
}

test "gRPC outlier detection composes ring hash child policy" {
    var config = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "childPolicy":[{"ring_hash_experimental":{
        \\  "minRingSize":32,"maxRingSize":128}}]
        \\ }}]}
    );
    defer config.deinit();
    const balancing = config.loadBalancingConfig();
    try std.testing.expectEqual(
        service_config.LoadBalancingPolicy.ring_hash,
        balancing.policy,
    );
    try std.testing.expectEqual(@as(usize, 32), balancing.ring_hash.min_ring_size);
    try std.testing.expectEqual(@as(usize, 128), balancing.ring_hash.max_ring_size);
    try std.testing.expect(balancing.outlier_detection != null);
}

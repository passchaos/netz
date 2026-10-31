const std = @import("std");
const service_config = @import("../service_config.zig");

test "gRPC least request service config validates and bounds choiceCount" {
    var defaults = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"unknown":{}},
        \\ {"least_request_experimental":{}}]}
    );
    defer defaults.deinit();
    const default_lb = defaults.loadBalancingConfig();
    try std.testing.expectEqual(
        service_config.LoadBalancingPolicy.least_request,
        default_lb.policy,
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        default_lb.least_request.choice_count,
    );

    var configured = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"least_request_experimental":
        \\ {"choiceCount":7}}]}
    );
    defer configured.deinit();
    try std.testing.expectEqual(
        @as(u8, 7),
        configured.loadBalancingConfig().least_request.choice_count,
    );

    var bounded = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"least_request_experimental":
        \\ {"choiceCount":4294967295}}]}
    );
    defer bounded.deinit();
    try std.testing.expectEqual(
        @as(u8, 10),
        bounded.loadBalancingConfig().least_request.choice_count,
    );

    for ([_][]const u8{
        \\{"loadBalancingConfig":[{"least_request_experimental":{"choiceCount":1}}]}
        ,
        \\{"loadBalancingConfig":[{"least_request_experimental":{"choiceCount":-1}}]}
        ,
        \\{"loadBalancingConfig":[{"least_request_experimental":{"choiceCount":2.5}}]}
        ,
        \\{"loadBalancingConfig":[{"least_request_experimental":{"choiceCount":"2"}}]}
        ,
        \\{"loadBalancingConfig":[{"least_request_experimental":{"choiceCount":4294967296}}]}
        ,
        \\{"loadBalancingConfig":[{"least_request_experimental":{"unknown":2}}]}
        ,
    }) |json| {
        try std.testing.expectError(
            error.InvalidServiceConfig,
            service_config.ServiceConfig.parse(std.testing.allocator, json),
        );
    }
}

test "gRPC outlier detection composes least request child policy" {
    var config = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "childPolicy":[{"least_request_experimental":{"choiceCount":4}}]
        \\ }}]}
    );
    defer config.deinit();
    const balancing = config.loadBalancingConfig();
    try std.testing.expectEqual(
        service_config.LoadBalancingPolicy.least_request,
        balancing.policy,
    );
    try std.testing.expectEqual(
        @as(u8, 4),
        balancing.least_request.choice_count,
    );
    try std.testing.expect(balancing.outlier_detection != null);
}

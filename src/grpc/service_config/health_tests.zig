const std = @import("std");
const service_config = @import("../service_config.zig");
const allocator = std.testing.allocator;

test "gRPC service config health service distinguishes absent null and empty names" {
    for ([_][]const u8{
        "{}",
        "{\"healthCheckConfig\": null}",
        "{\"healthCheckConfig\": {}}",
        "{\"healthCheckConfig\": {\"serviceName\": null}}",
        "{\"healthCheckConfig\": {\"unknown\": true}}",
    }) |json| {
        var config = try service_config.ServiceConfig.parse(allocator, json);
        defer config.deinit();
        try std.testing.expect(config.healthCheckServiceName() == null);
    }
    var overall = try service_config.ServiceConfig.parse(allocator, "{\"healthCheckConfig\": {\"serviceName\": \"\"}}");
    defer overall.deinit();
    try std.testing.expectEqualStrings("", overall.healthCheckServiceName().?);
    var named = try service_config.ServiceConfig.parse(allocator, "{\"healthCheckConfig\": {\"serviceName\": \"demo.Echo\", \"future\": [1,2]}}");
    defer named.deinit();
    try std.testing.expectEqualStrings("demo.Echo", named.healthCheckServiceName().?);
}

test "gRPC service config rejects malformed health configuration and duplicate fields" {
    for ([_][]const u8{
        "{\"healthCheckConfig\": false}",
        "{\"healthCheckConfig\": 1}",
        "{\"healthCheckConfig\": []}",
        "{\"healthCheckConfig\": \"service\"}",
        "{\"healthCheckConfig\": {\"serviceName\": false}}",
        "{\"healthCheckConfig\": {\"serviceName\": 1}}",
        "{\"healthCheckConfig\": {\"serviceName\": []}}",
        "{\"healthCheckConfig\": {\"serviceName\": [65,66]}}",
        "{\"healthCheckConfig\": {\"serviceName\": {}}}",
        "{\"healthCheckConfig\": {}, \"healthCheckConfig\": {}}",
        "{\"healthCheckConfig\": {\"serviceName\": \"a\", \"serviceName\": \"b\"}}",
        "{\"healthCheckConfig\": {\"serviceName\": \"\xff\"}}",
    }) |json| {
        if (service_config.ServiceConfig.parse(allocator, json)) |value| {
            var unexpected = value;
            defer unexpected.deinit();
            return error.TestExpectedError;
        } else |err| try std.testing.expectEqual(error.InvalidServiceConfig, err);
    }
}

test "gRPC service config owns health names and accepts protobuf string content" {
    const json = try allocator.dupe(u8, "{\"healthCheckConfig\": {\"serviceName\": \"demo.Echo\"}}");
    defer allocator.free(json);
    var config = try service_config.ServiceConfig.parse(allocator, json);
    defer config.deinit();
    @memset(json, 'x');
    try std.testing.expectEqualStrings("demo.Echo", config.healthCheckServiceName().?);
    var unicode = try service_config.ServiceConfig.parse(allocator, "{\"healthCheckConfig\": {\"serviceName\": \"服务\\u0000名称\"}}");
    defer unicode.deinit();
    try std.testing.expectEqualStrings("服务\x00名称", unicode.healthCheckServiceName().?);
}

test "gRPC service config health parsing remains transactional on allocation failure" {
    const Harness = struct {
        fn run(gpa: std.mem.Allocator) !void {
            var config = try service_config.ServiceConfig.parse(gpa,
                \\{"healthCheckConfig":{"serviceName":"demo.Echo"},
                \\ "loadBalancingConfig":[{"round_robin":{}}]}
            );
            defer config.deinit();
            try std.testing.expectEqualStrings("demo.Echo", config.healthCheckServiceName().?);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{});
}

const std = @import("std");
const service_config = @import("../service_config.zig");

test "gRPC service config owns and validates hedging policy" {
    var config = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"retryThrottling":{"maxTokens":4,"tokenRatio":1},
        \\ "methodConfig":[{"name":[{"service":"demo.Hedge",
        \\  "method":"Call"}],"hedgingPolicy":{"maxAttempts":9,
        \\  "hedgingDelay":"0.25s","nonFatalStatusCodes":
        \\  ["UNAVAILABLE","ABORTED"]}}]}
    );
    defer config.deinit();
    const policy = config.methodPolicy("/demo.Hedge/Call").?.hedging_policy.?;
    try std.testing.expectEqual(@as(u8, 5), policy.max_attempts);
    try std.testing.expectEqual(
        @as(i96, 250 * std.time.ns_per_ms),
        policy.hedging_delay.nanoseconds,
    );
    try std.testing.expectEqualSlices(
        @import("../wire.zig").Status,
        &.{ .unavailable, .aborted },
        policy.non_fatal_status_codes,
    );
    try std.testing.expect(policy.throttler != null);

    var defaults = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":
        \\ {"maxAttempts":2}}]}
    );
    defer defaults.deinit();
    const default_policy = defaults.methodPolicy("/demo.Any/Call").?
        .hedging_policy.?;
    try std.testing.expectEqual(@as(i96, 0), default_policy.hedging_delay.nanoseconds);
    try std.testing.expectEqual(@as(usize, 0), default_policy.non_fatal_status_codes.len);
}

test "gRPC service config rejects invalid or ambiguous hedging policy" {
    for ([_][]const u8{
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":{}}]}
        ,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":{"maxAttempts":1}}]}
        ,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":{"maxAttempts":2,"hedgingDelay":"invalid"}}]}
        ,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":{"maxAttempts":2,"nonFatalStatusCodes":["OK"]}}]}
        ,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":{"maxAttempts":2,"nonFatalStatusCodes":["ABORTED","ABORTED"]}}]}
        ,
        \\{"methodConfig":[{"name":[{}],"hedgingPolicy":{"maxAttempts":2,"nonFatalStatusCodes":["NOT_A_STATUS"]}}]}
        ,
        \\{"methodConfig":[{"name":[{}],
        \\ "retryPolicy":{"maxAttempts":2,"initialBackoff":"0.1s",
        \\ "maxBackoff":"1s","backoffMultiplier":2,
        \\ "retryableStatusCodes":["UNAVAILABLE"]},
        \\ "hedgingPolicy":{"maxAttempts":2}}]}
        ,
    }) |json| {
        try std.testing.expectError(
            error.InvalidServiceConfig,
            service_config.ServiceConfig.parse(std.testing.allocator, json),
        );
    }
}

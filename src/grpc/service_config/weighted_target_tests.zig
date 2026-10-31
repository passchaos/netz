const std = @import("std");
const service_config = @import("../service_config.zig");
const channel = @import("../channel.zig");
const shared = @import("../channel/shared.zig");

test "gRPC weighted target service config owns recursive child policies" {
    var config = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{
        \\  "z":{"weight":3,"childPolicy":[{"unknown":{}},{"round_robin":{}}]},
        \\  "a":{"weight":1,"childPolicy":[{"outlier_detection_experimental":{
        \\   "maxEjectionPercent":7,"childPolicy":[
        \\    {"least_request_experimental":{"choiceCount":4}}]}}]},
        \\  "nested":{"weight":2,"childPolicy":[
        \\   {"weighted_target_experimental":{"targets":{
        \\    "inner":{"weight":5,"childPolicy":[{"pick_first":{}}]}
        \\   }}}]}
        \\ }}}]}
    );
    defer config.deinit();
    const balancing = config.loadBalancingConfig();
    try std.testing.expectEqual(
        service_config.LoadBalancingPolicy.weighted_target,
        balancing.policy,
    );
    const targets = balancing.weighted_target.targets;
    try std.testing.expectEqual(@as(usize, 3), targets.len);
    try std.testing.expectEqualStrings("a", targets[0].name);
    try std.testing.expectEqual(@as(u32, 1), targets[0].weight);
    switch (targets[0].child.*) {
        .outlier_detection => |wrapper| {
            try std.testing.expectEqual(
                @as(u32, 7),
                wrapper.config.max_ejection_percent,
            );
            switch (wrapper.child.*) {
                .least_request => |least| try std.testing.expectEqual(
                    @as(u8, 4),
                    least.choice_count,
                ),
                else => return error.TestUnexpectedResult,
            }
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("nested", targets[1].name);
    switch (targets[1].child.*) {
        .weighted_target => |nested| {
            try std.testing.expectEqual(@as(usize, 1), nested.targets.len);
            try std.testing.expectEqualStrings(
                "inner",
                nested.targets[0].name,
            );
            try std.testing.expect(
                nested.targets[0].child.* == .pick_first,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("z", targets[2].name);
    try std.testing.expect(targets[2].child.* == .round_robin);
    try std.testing.expect(balancing.root.?.* == .weighted_target);
}

test "gRPC weighted target parser validates targets and recursion depth" {
    var empty = try service_config.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{}}}]}
    );
    defer empty.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        empty.loadBalancingConfig().weighted_target.targets.len,
    );

    for ([_][]const u8{
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":[]}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{"":{"weight":1,"childPolicy":[{"round_robin":{}}]}}}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{"a":{"weight":0,"childPolicy":[{"round_robin":{}}]}}}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{"a":{"weight":4294967296,"childPolicy":[{"round_robin":{}}]}}}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{"a":{"weight":1}}}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{"a":{"weight":1,"childPolicy":[{"unknown":{}}]}}}}]}
        ,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{"targets":{"a":{"weight":1,"childPolicy":[{"round_robin":{}}],"extra":true}}}}]}
        ,
    }) |json| try std.testing.expectError(
        error.InvalidServiceConfig,
        service_config.ServiceConfig.parse(std.testing.allocator, json),
    );

    const allocator = std.testing.allocator;
    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(allocator);
    try json.appendSlice(allocator, "{\"loadBalancingConfig\":[");
    for (0..service_config.max_load_balancing_depth + 1) |_| {
        try json.appendSlice(
            allocator,
            "{\"weighted_target_experimental\":{\"targets\":{\"child\":{\"weight\":1,\"childPolicy\":[",
        );
    }
    try json.appendSlice(allocator, "{\"round_robin\":{}}");
    for (0..service_config.max_load_balancing_depth + 1) |_| {
        try json.appendSlice(allocator, "]}}}}");
    }
    try json.appendSlice(allocator, "]}");
    try std.testing.expectError(
        error.InvalidServiceConfig,
        service_config.ServiceConfig.parse(allocator, json.items),
    );
}

test "gRPC weighted target parser is allocation transactional" {
    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var config = try service_config.ServiceConfig.parse(allocator,
                \\{"loadBalancingConfig":[{"weighted_target_experimental":{
                \\ "targets":{
                \\  "a":{"weight":3,"childPolicy":[{"round_robin":{}}]},
                \\  "b":{"weight":7,"childPolicy":[
                \\   {"least_request_experimental":{"choiceCount":3}}]}
                \\ }}}]}
            );
            defer config.deinit();
            try std.testing.expectEqual(
                @as(usize, 2),
                config.loadBalancingConfig().weighted_target.targets.len,
            );
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{},
    );
}

test "gRPC weighted target runtime is selected by both channel owners" {
    const json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"a":{"weight":1,
        \\  "childPolicy":[{"ring_hash_experimental":{
        \\   "minRingSize":16,"maxRingSize":16,
        \\   "requestHashHeader":"x-shard"}}]}}}}]}
    ;
    var config = try service_config.ServiceConfig.parse(
        std.testing.allocator,
        json,
    );
    defer config.deinit();
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const target: channel.Target = .{ .cleartext_ip = .{
        .address = .{ .ip4 = .loopback(9) },
        .hierarchical_path = &.{"a"},
    } };
    var ordinary = try channel.Channel.initWithServiceConfig(
        std.testing.allocator,
        io,
        target,
        .{},
        &config,
    );
    defer ordinary.deinit();
    try std.testing.expectEqual(
        channel.SelectionPolicy.weighted_target,
        ordinary.selectionPolicy(),
    );
    var manager = try shared.SharedChannel.init(
        std.testing.allocator,
        io,
        target,
        .{ .service_config_json = json },
    );
    defer manager.deinit();
    try std.testing.expectEqual(
        channel.SelectionPolicy.weighted_target,
        manager.selectionPolicy(),
    );
}

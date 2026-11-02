const std = @import("std");
const service = @import("../service_config.zig");
const locality = @import("locality.zig");
const channel = @import("../channel.zig");
const allocator = std.testing.allocator;

pub const json = "{\"loadBalancingConfig\":[{\"xds_wrr_locality_experimental\":{\"childPolicy\":[{\"unknown\":{}},{\"round_robin\":{}}]}}]}";

fn endpoint(path: []const []const u8, weight: u32) channel.Endpoint {
    return .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = path, .locality_weight = weight } };
}

test "gRPC xDS locality config selects a child and rejects malformed recursion" {
    var config = try service.ServiceConfig.parse(allocator, json);
    defer config.deinit();
    const balancing = config.loadBalancingConfig();
    try std.testing.expectEqual(service.LoadBalancingPolicy.weighted_target, balancing.policy);
    try std.testing.expect(balancing.root.?.* == .xds_wrr_locality);
    try std.testing.expect(balancing.root.?.xds_wrr_locality.* == .round_robin);
    for ([_][]const u8{
        "{\"loadBalancingConfig\":[{\"xds_wrr_locality_experimental\":{}}]}",
        "{\"loadBalancingConfig\":[{\"xds_wrr_locality_experimental\":{\"childPolicy\":[]}}]}",
        "{\"loadBalancingConfig\":[{\"xds_wrr_locality_experimental\":{\"childPolicy\":[{\"unknown\":{}}]}}]}",
        "{\"loadBalancingConfig\":[{\"xds_wrr_locality_experimental\":{\"childPolicy\":{}}}]}",
    }) |invalid| try std.testing.expectError(error.InvalidServiceConfig, service.ServiceConfig.parse(allocator, invalid));
    var too_deep: std.ArrayList(u8) = .empty;
    defer too_deep.deinit(allocator);
    try too_deep.appendSlice(allocator, "{\"loadBalancingConfig\":");
    for (0..service.max_load_balancing_depth + 2) |_| try too_deep.appendSlice(allocator, "[{\"xds_wrr_locality_experimental\":{\"childPolicy\":");
    try too_deep.appendSlice(allocator, "[{\"round_robin\":{}}]");
    for (0..service.max_load_balancing_depth + 2) |_| try too_deep.appendSlice(allocator, "}}]");
    try too_deep.appendSlice(allocator, "}");
    try std.testing.expectError(error.InvalidServiceConfig, service.ServiceConfig.parse(allocator, too_deep.items));
}

test "gRPC xDS locality expansion uses first positive weights sorted by name and retains missing locality behavior" {
    var config = try service.ServiceConfig.parse(allocator, json);
    defer config.deinit();
    const endpoints = [_]channel.Endpoint{
        endpoint(&.{"b"}, 3), endpoint(&.{"a"}, 0), endpoint(&.{"a"}, 1),
        endpoint(&.{"a"}, 9), endpoint(&.{}, 5),    endpoint(&.{"omitted"}, 0),
    };
    var expanded = try locality.Resolved.init(allocator, config.loadBalancingConfig().root.?, &endpoints);
    defer expanded.deinit();
    const children = expanded.root.weighted_target.targets;
    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqualStrings("a", children[0].name);
    try std.testing.expectEqual(@as(u32, 1), children[0].weight);
    try std.testing.expectEqualStrings("b", children[1].name);
    try std.testing.expectEqual(@as(u32, 3), children[1].weight);
    try std.testing.expect(children[0].child.* == .round_robin);
    var empty = try locality.Resolved.init(allocator, config.loadBalancingConfig().root.?, &[_]channel.Endpoint{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.root.weighted_target.targets.len);
}

test "gRPC xDS locality expansion isolates nested priority and weighted address paths" {
    var config = try service.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"p":{"config":[{"weighted_target_experimental":{"targets":{
        \\ "outer":{"weight":1,"childPolicy":[{"xds_wrr_locality_experimental":{"childPolicy":[{"pick_first":{}}]}}]}
        \\ }}}]}},"priorities":["p"]}}]}
    );
    defer config.deinit();
    const endpoints = [_]channel.Endpoint{
        endpoint(&.{ "p", "outer", "b" }, 3),     endpoint(&.{ "p", "outer", "a" }, 1),
        endpoint(&.{ "other", "outer", "c" }, 9), endpoint(&.{ "p", "different", "d" }, 9),
    };
    var expanded = try locality.Resolved.init(allocator, config.loadBalancingConfig().root.?, &endpoints);
    defer expanded.deinit();
    const children = expanded.root.priority.children[0].child.weighted_target.targets[0].child.weighted_target.targets;
    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqualStrings("a", children[0].name);
    try std.testing.expectEqualStrings("b", children[1].name);
}

test "gRPC xDS locality parsing and expansion roll back allocation failures" {
    const Harness = struct {
        fn run(gpa: std.mem.Allocator) !void {
            var config = try service.ServiceConfig.parse(gpa, json);
            defer config.deinit();
            const endpoints = [_]channel.Endpoint{ endpoint(&.{"a"}, 1), endpoint(&.{"b"}, 3) };
            var expanded = try locality.Resolved.init(gpa, config.loadBalancingConfig().root.?, &endpoints);
            defer expanded.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{});
}

test "gRPC xDS locality target regeneration preserves unchanged priority activation and failover clocks" {
    var config = try service.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"priority_experimental":{
        \\ "children":{"p":{"config":[{"xds_wrr_locality_experimental":{"childPolicy":[{"round_robin":{}}]}}]}},"priorities":["p"]}}]}
    );
    defer config.deinit();
    const Runtime = @import("shared/state.zig").State.WeightedTarget;
    const first = [_]channel.Endpoint{ endpoint(&.{ "p", "a" }, 1), endpoint(&.{ "p", "b" }, 3) };
    const second = [_]channel.Endpoint{ endpoint(&.{ "p", "a" }, 3), endpoint(&.{ "p", "b" }, 1) };
    var old = try Runtime.initResolvedWithPriorityTimeouts(allocator, config.loadBalancingConfig().root.?, &first, 1000, 2000);
    defer old.deinit();
    var next = try Runtime.initResolvedWithPriorityTimeouts(allocator, config.loadBalancingConfig().root.?, &second, 1000, 2000);
    defer next.deinit();
    old.root.kind.priority.failover_started_ns = 17;
    old.root.kind.priority.failover_can_start = false;
    old.root.kind.priority.children[0].activated = true;
    old.root.kind.priority.children[0].deactivate_at = 200;
    old.root.kind.priority.children[0].deactivated = true;
    try std.testing.expect(!locality.sameTargets(old.root, next.root));
    locality.retainPriorityState(old.root, next.root);
    try std.testing.expectEqual(@as(?i96, 17), next.root.kind.priority.failover_started_ns);
    try std.testing.expect(!next.root.kind.priority.failover_can_start);
    try std.testing.expect(next.root.kind.priority.children[0].activated);
    try std.testing.expect(next.root.kind.priority.children[0].deactivated);
    try std.testing.expectEqual(@as(?i96, 200), next.root.kind.priority.children[0].deactivate_at);
    const targets = next.root.kind.priority.children[0].node.kind.weighted.children;
    try std.testing.expectEqual(@as(u32, 3), targets[0].weight);
    try std.testing.expectEqual(@as(u32, 1), targets[1].weight);
}

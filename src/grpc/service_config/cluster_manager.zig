//! xds_cluster_manager child-policy map validation.
const std = @import("std");
const config = @import("../service_config.zig");
const locality = @import("locality.zig");

pub fn parse(allocator: std.mem.Allocator, value: std.json.Value, depth: usize, comptime parseChild: anytype) config.Error!config.WeightedTargetConfig {
    const object = switch (value) {
        .object => |v| v,
        else => return error.InvalidServiceConfig,
    };
    const children = object.get("children") orelse return error.InvalidServiceConfig;
    const map = switch (children) {
        .object => |v| v,
        else => return error.InvalidServiceConfig,
    };
    const targets = try allocator.alloc(config.WeightedTargetConfig.Target, map.count());
    var iterator = map.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        const policies = try locality.childPolicies(entry.value_ptr.*);
        const child = try parseChild(allocator, .{ .loadBalancingConfig = policies }, depth + 1);
        targets[index] = .{ .name = entry.key_ptr.*, .weight = 1, .child = child.root orelse return error.InvalidServiceConfig };
    }
    std.mem.sort(config.WeightedTargetConfig.Target, targets, {}, struct {
        fn less(_: void, a: config.WeightedTargetConfig.Target, b: config.WeightedTargetConfig.Target) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.less);
    return .{ .targets = targets };
}

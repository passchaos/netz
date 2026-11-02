//! xds_cluster_impl policy config and child topology validation.
const std = @import("std");
const service = @import("../service_config.zig");
const admission = @import("../channel/cluster_impl.zig");
const Node = service.LoadBalancingNode;
fn text(value: ?std.json.Value, required: bool) service.Error![]const u8 {
    const raw = value orelse return if (required) error.InvalidServiceConfig else "";
    if (raw != .string or raw.string.len > 4096 or (required and raw.string.len == 0) or !std.unicode.utf8ValidateSlice(raw.string)) return error.InvalidServiceConfig;
    return raw.string;
}
fn integer(value: std.json.Value) service.Error!u32 {
    const raw: i64 = switch (value) {
        .integer => value.integer,
        .number_string => std.fmt.parseInt(i64, value.number_string, 10) catch return error.InvalidServiceConfig,
        else => return error.InvalidServiceConfig,
    };
    if (raw < 0 or raw > std.math.maxInt(u32)) return error.InvalidServiceConfig;
    return @intCast(raw);
}
fn nested(node: *const Node) bool {
    return switch (node.*) {
        .cluster_impl, .cluster_manager => true,
        .outlier_detection => |wrapper| nested(wrapper.child),
        .xds_wrr_locality => |child| nested(child),
        .weighted_target => |value| for (value.targets) |child| {
            if (nested(child.child)) break true;
        } else false,
        .priority => |value| for (value.children) |child| {
            if (nested(child.child)) break true;
        } else false,
        else => false,
    };
}
pub fn parse(gpa: std.mem.Allocator, value: std.json.Value, depth: usize, comptime parseChild: anytype) service.Error!service.ClusterImplConfig {
    if (value != .object) return error.InvalidServiceConfig;
    const object = value.object;
    const name = try text(object.get("clusterName"), true);
    const eds = try text(object.get("edsServiceName"), false);
    const maximum = if (object.get("maxConcurrentRequests")) |raw| try integer(raw) else 1024;
    const pending = if (object.get("discoveryPending")) |raw| blk: {
        if (raw != .bool) return error.InvalidServiceConfig;
        break :blk raw.bool;
    } else false;
    var drops: std.ArrayList(@import("../channel/drop_policy.zig").Category) = .empty;
    defer drops.deinit(gpa);
    if (object.get("dropCategories")) |raw| {
        if (raw != .array or raw.array.items.len > 256) return error.InvalidServiceConfig;
        for (raw.array.items) |entry| {
            if (entry != .object) return error.InvalidServiceConfig;
            const category = try text(entry.object.get("category"), true);
            const fraction = try integer(entry.object.get("requestsPerMillion") orelse return error.InvalidServiceConfig);
            if (fraction > 1000000) return error.InvalidServiceConfig;
            try drops.append(gpa, .{ .category = category, .requests_per_million = fraction });
        }
    }
    const policies = try @import("locality.zig").childPolicies(value);
    const child = try parseChild(gpa, .{ .loadBalancingConfig = policies }, depth + 1);
    const node = child.root orelse return error.InvalidServiceConfig;
    if (nested(node)) return error.InvalidServiceConfig;
    const options = admission.Options{ .cluster = name, .eds_service_name = eds, .max_concurrent_requests = maximum, .drop_categories = try drops.toOwnedSlice(gpa), .discovery_pending = pending };
    return .{ .admission = options, .child = node };
}

//! Expand resolver locality weights into a weighted_target policy snapshot.
const std = @import("std");
const config = @import("../service_config.zig");
const Node = config.LoadBalancingNode;

pub const Resolved = struct {
    arena: std.heap.ArenaAllocator,
    root: *const Node,

    pub fn init(allocator: std.mem.Allocator, root: *const Node, endpoints: anytype) std.mem.Allocator.Error!Resolved {
        var self = Resolved{ .arena = .init(allocator), .root = root };
        errdefer self.deinit();
        if (contains(root)) self.root = try expand(self.arena.allocator(), root, endpoints, &.{});
        return self;
    }
    pub fn deinit(self: *Resolved) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn contains(node: *const Node) bool {
    return switch (node.*) {
        .xds_wrr_locality => true,
        .weighted_target => |v| for (v.targets) |child| {
            if (contains(child.child)) break true;
        } else false,
        .priority => |v| for (v.children) |child| {
            if (contains(child.child)) break true;
        } else false,
        .outlier_detection => |v| contains(v.child),
        else => false,
    };
}

/// Runtime target weights can change without a service-config JSON change.
/// Preserve the existing tree only while the generated target structure agrees.
pub fn sameTargets(left: anytype, right: @TypeOf(left)) bool {
    if (std.meta.activeTag(left.kind) != std.meta.activeTag(right.kind)) return false;
    return switch (left.kind) {
        .leaf => true,
        .weighted => |a| blk: {
            const b = right.kind.weighted;
            if (a.children.len != b.children.len) break :blk false;
            for (a.children, b.children) |x, y| {
                if (x.weight != y.weight or !sameTargets(x.node, y.node)) break :blk false;
                if (x.node.path.len != y.node.path.len) break :blk false;
                for (x.node.path, y.node.path) |xp, yp| if (!std.mem.eql(u8, xp, yp)) break :blk false;
            }
            break :blk true;
        },
        .priority => |a| blk: {
            const b = right.kind.priority;
            if (a.children.len != b.children.len) break :blk false;
            for (a.children, b.children) |x, y| if (!sameTargets(x.node, y.node)) break :blk false;
            break :blk true;
        },
        .outlier => |a| sameTargets(a.child, right.kind.outlier.child),
    };
}

/// Resolver-only target changes keep the unchanged priority policy's timers
/// and child activation, while leaf picker buffers move through StateTransfer.
pub fn retainPriorityState(old: anytype, next: @TypeOf(old)) void {
    if (std.meta.activeTag(old.kind) != std.meta.activeTag(next.kind)) return;
    switch (next.kind) {
        .leaf => {},
        .outlier => |value| retainPriorityState(old.kind.outlier.child, value.child),
        .weighted => |value| for (value.children) |child| {
            for (old.kind.weighted.children) |prior| {
                if (samePath(prior.node.path, child.node.path)) {
                    retainPriorityState(prior.node, child.node);
                    break;
                }
            }
        },
        .priority => |*value| {
            const prior = old.kind.priority;
            value.failover_started_ns = prior.failover_started_ns;
            value.failover_can_start = prior.failover_can_start;
            for (value.children) |*child| {
                for (prior.children) |previous| {
                    if (!samePath(previous.node.path, child.node.path)) continue;
                    child.activated = previous.activated;
                    child.deactivate_at = previous.deactivate_at;
                    child.deactivated = previous.deactivated;
                    retainPriorityState(previous.node, child.node);
                    break;
                }
            }
        },
    }
}

fn samePath(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

fn childPath(allocator: std.mem.Allocator, path: []const []const u8, name: []const u8) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, path.len + 1);
    @memcpy(result[0..path.len], path);
    result[path.len] = name;
    return result;
}

fn expand(allocator: std.mem.Allocator, node: *const Node, endpoints: anytype, path: []const []const u8) std.mem.Allocator.Error!*const Node {
    if (!contains(node)) return node;
    const result = try allocator.create(Node);
    result.* = switch (node.*) {
        .xds_wrr_locality => |child| .{ .weighted_target = .{ .targets = try targets(allocator, child, endpoints, path) } },
        .weighted_target => |value| blk: {
            const children = try allocator.dupe(config.WeightedTargetConfig.Target, value.targets);
            for (children) |*child| child.child = try expand(allocator, child.child, endpoints, try childPath(allocator, path, child.name));
            break :blk .{ .weighted_target = .{ .targets = children } };
        },
        .priority => |value| blk: {
            const children = try allocator.dupe(config.PriorityConfig.Child, value.children);
            for (children) |*child| child.child = try expand(allocator, child.child, endpoints, try childPath(allocator, path, child.name));
            break :blk .{ .priority = .{ .children = children, .priorities = value.priorities } };
        },
        .outlier_detection => |value| .{ .outlier_detection = .{ .config = value.config, .child = try expand(allocator, value.child, endpoints, path) } },
        else => unreachable,
    };
    return result;
}

fn targets(allocator: std.mem.Allocator, child: *const Node, endpoints: anytype, path: []const []const u8) std.mem.Allocator.Error![]const config.WeightedTargetConfig.Target {
    var values: std.ArrayList(config.WeightedTargetConfig.Target) = .empty;
    for (endpoints) |item| {
        const endpoint = if (@hasField(@TypeOf(item), "endpoint")) item.endpoint else item;
        const route = endpoint.hierarchicalPath();
        if (route.len <= path.len or endpoint.localityWeight() == 0) continue;
        var matches = true;
        for (path, route[0..path.len]) |expected, actual| if (!std.mem.eql(u8, expected, actual)) {
            matches = false;
            break;
        };
        if (!matches) continue;
        const name = route[path.len];
        // grpc-core keeps the first positive weight if endpoints disagree.
        var exists = false;
        for (values.items) |value| if (std.mem.eql(u8, value.name, name)) {
            exists = true;
            break;
        };
        if (exists) continue;
        try values.append(allocator, .{ .name = name, .weight = endpoint.localityWeight(), .child = child });
    }
    // grpc-core generates targets in locality-name order, independent of
    // address order. This also keeps updates stable when only DNS order changes.
    std.mem.sort(config.WeightedTargetConfig.Target, values.items, {}, struct {
        fn less(_: void, a: config.WeightedTargetConfig.Target, b: config.WeightedTargetConfig.Target) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.less);
    for (values.items) |*value| value.child = try expand(allocator, child, endpoints, try childPath(allocator, path, value.name));
    return values.toOwnedSlice(allocator);
}

test {
    _ = @import("locality_tests.zig");
}

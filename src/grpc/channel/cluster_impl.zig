//! Per-cluster xDS drop/circuit admission, independent of endpoint LB state.
const std = @import("std");
const drop = @import("drop_policy.zig");
const circuit = @import("circuit_breaker.zig");
pub const Options = struct {
    cluster: []const u8,
    eds_service_name: []const u8 = "",
    max_concurrent_requests: u32 = 1024,
    drop_categories: []const drop.Category = &.{},
    discovery_pending: bool = false,
};
var next_revision: std.atomic.Value(u64) = .init(1);
pub const Policy = struct {
    drops: drop.Policy,
    circuit: circuit.Policy,
    revision: u64,
    counters: drop.Counters = .{},
    discovery_pending: bool,
    /// EDS service name from the xDS cluster implementation config, used by
    /// LRS cluster reports. Borrows the service-config arena.
    eds_service_name: []const u8 = "",
    pub fn init(gpa: std.mem.Allocator, options: Options) (drop.Error || circuit.Error)!Policy {
        var drops = try drop.Policy.init(gpa, options.drop_categories);
        errdefer drops.deinit();
        const budget = try circuit.Policy.init(.{ .cluster = options.cluster, .eds_service_name = options.eds_service_name, .max_concurrent_requests = options.max_concurrent_requests });
        return .{ .drops = drops, .circuit = budget, .revision = next_revision.fetchAdd(1, .monotonic), .discovery_pending = options.discovery_pending, .eds_service_name = options.eds_service_name };
    }
    pub fn deinit(self: *Policy) void {
        self.drops.deinit();
        self.circuit.deinit();
        self.* = undefined;
    }
    pub fn transfer(self: *Policy, previous: *const Policy) void {
        // A queued call keeps its draw while category contents are unchanged.
        // Circuit-only updates do not introduce another probability trial.
        if (self.drops.equivalent(previous.drops)) self.revision = previous.revision;
        const stats = previous.counters.snapshot();
        self.counters.evaluated.store(stats.evaluated, .release);
        self.counters.dropped.store(stats.dropped, .release);
    }
};
pub fn forCluster(node: anytype, cluster: ?[]const u8) error{UnknownCluster}!?*Policy {
    if (node.cluster_manager) return forCluster(try @import("cluster_route.zig").select(node, cluster), cluster);
    if (node.admission != null) return &node.admission.?;
    return switch (node.kind) {
        .outlier => |wrapper| forCluster(wrapper.child, cluster),
        else => null,
    };
}
pub fn contains(node: anytype) bool {
    if (node.admission != null) return true;
    return switch (node.kind) {
        .leaf => false,
        .outlier => |wrapper| contains(wrapper.child),
        .weighted => |weighted| for (@import("tree_query.zig").weightedChildren(weighted)) |child| {
            if (contains(child.node)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (contains(child.node)) break true;
        } else false,
    };
}
/// Admission roots are standalone or direct manager children, optionally
/// enclosed by transparent outlier wrappers. Unsupported ambiguous placement
/// fails construction rather than applying one child's budget to its siblings.
pub fn validLayout(node: anytype, eligible: bool) bool {
    if (node.admission != null and !eligible) return false;
    const allowed = eligible and node.admission == null;
    return switch (node.kind) {
        .leaf => true,
        .outlier => |wrapper| validLayout(wrapper.child, allowed),
        .weighted => |weighted| for (@import("tree_query.zig").weightedChildren(weighted)) |child| {
            if (!validLayout(child.node, allowed and node.cluster_manager)) break false;
        } else true,
        .priority => |priority| for (priority.children) |child| {
            if (!validLayout(child.node, false)) break false;
        } else true,
    };
}
test {
    _ = @import("cluster_impl/tests.zig");
    _ = @import("cluster_impl/stream_tests.zig");
    _ = @import("cluster_impl/update_tests.zig");
}

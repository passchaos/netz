//! RPC-local xDS cluster selection; selectors never enter wire metadata.
const std = @import("std");
const query = @import("tree_query.zig");
pub const Error = error{UnknownCluster};

pub fn contains(node: anytype) bool {
    if (node.cluster_manager) return true;
    return switch (node.kind) {
        .leaf => false,
        .weighted => |weighted| for (query.weightedChildren(weighted)) |child| {
            if (contains(child.node)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (contains(child.node)) break true;
        } else false,
        .outlier => |wrapper| contains(wrapper.child),
    };
}

pub fn select(node: anytype, name: ?[]const u8) Error!@TypeOf(node) {
    const cluster = name orelse "";
    for (query.weightedChildren(node.kind.weighted)) |child| {
        if (std.mem.eql(u8, child.node.path[node.path.len], cluster)) return child.node;
    }
    return error.UnknownCluster;
}

pub fn validate(node: anytype, name: ?[]const u8) Error!void {
    if (node.cluster_manager) return validate(try select(node, name), name);
    switch (node.kind) {
        .leaf => {},
        .outlier => |wrapper| try validate(wrapper.child, name),
        .weighted => |weighted| for (query.weightedChildren(weighted)) |child| try validate(child.node, name),
        .priority => |priority| for (priority.children) |child| try validate(child.node, name),
    }
}

pub fn jobCluster(job: anytype) ?[]const u8 {
    return if (job.stream) |stream| stream.options.xds_cluster else job.options.xds_cluster;
}

/// Aggregate the selected cluster's state while keeping the channel's ordinary
/// aggregate available for observers. Below that cluster, its configured
/// priority/weighted/outlier policy keeps the existing state machine.
pub fn aggregate(node: anytype, context: anytype, cluster: ?[]const u8, comptime stateFn: anytype) @TypeOf(stateFn(context, node)) {
    if (node.cluster_manager) return aggregate(select(node, cluster) catch return .transient_failure, context, cluster, stateFn);
    return switch (node.kind) {
        .leaf, .priority => stateFn(context, node),
        .outlier => |wrapper| aggregate(wrapper.child, context, cluster, stateFn),
        .weighted => |weighted| blk: {
            var connecting = false;
            var idle = false;
            for (query.weightedChildren(weighted)) |child| {
                const state = aggregate(child.node, context, cluster, stateFn);
                if (state == .ready) break :blk .ready;
                connecting = connecting or state == .connecting;
                idle = idle or state == .idle;
            }
            break :blk if (connecting) .connecting else if (idle) .idle else .transient_failure;
        },
    };
}

/// Connection attempts for an ordinary RPC are scoped to the selected cluster;
/// shared endpoint owners retain their independent background connection tasks.
pub fn accepts(node: anytype, cluster: ?[]const u8, path: []const []const u8) bool {
    if (!query.matches(path, node.path)) return false;
    if (node.cluster_manager) return accepts(select(node, cluster) catch return false, cluster, path);
    return switch (node.kind) {
        .leaf => true,
        .outlier => |wrapper| accepts(wrapper.child, cluster, path),
        .weighted => |weighted| for (query.weightedChildren(weighted)) |child| {
            if (accepts(child.node, cluster, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (accepts(child.node, cluster, path)) break true;
        } else false,
    };
}

//! Child-local static-stride scheduling and ORCA configuration lookup.
const std = @import("std");
const service_config = @import("../../../service_config.zig");
const orca_config = @import("../orca/config.zig");

pub fn pick(
    allocator: std.mem.Allocator,
    runtime: anytype,
    node: anytype,
    leaf: anytype,
    state: anytype,
) std.mem.Allocator.Error!?@TypeOf(state.workers.items[0]) {
    const ContextType = Context(
        @TypeOf(runtime),
        @TypeOf(node),
        @TypeOf(state),
    );
    var context = ContextType{
        .runtime = runtime,
        .node = node,
        .state = state,
    };
    const now = std.Io.Clock.awake.now(state.io).nanoseconds;
    if (now >= leaf.wrr_scheduler.next_update_ns) {
        try leaf.wrr_scheduler.rebuildFiltered(
            allocator,
            state.workers.items,
            now,
            leaf.wrr_config,
            &context,
            ContextType.ready,
        );
    }
    return leaf.wrr_scheduler.pickFiltered(
        @typeInfo(@TypeOf(state.workers.items[0])).pointer.child,
        &leaf.wrr_sequence,
        &context,
        ContextType.available,
    );
}

pub fn config(
    node: anytype,
    state: anytype,
    worker: anytype,
) ?service_config.WeightedRoundRobinConfig {
    if (!workerMatches(state, worker, node.path)) return null;
    return switch (node.kind) {
        .leaf => |leaf| if (leaf.policy == .weighted_round_robin)
            leaf.wrr_config
        else
            null,
        .weighted => |weighted| for (weighted.children) |child| {
            if (config(child.node, state, worker)) |value| return value;
        } else null,
        .outlier => |wrapper| config(wrapper.child, state, worker),
    };
}

pub fn disconnect(node: anytype, state: anytype, worker: anytype) void {
    if (!workerMatches(state, worker, node.path)) return;
    switch (node.kind) {
        .leaf => |*leaf| if (leaf.policy == .weighted_round_robin) {
            leaf.wrr_scheduler.remove(worker);
        },
        .weighted => |weighted| for (weighted.children) |child| {
            disconnect(child.node, state, worker);
        },
        .outlier => |wrapper| disconnect(wrapper.child, state, worker),
    }
}

pub fn orcaConfig(
    node: anytype,
    state: anytype,
    worker: anytype,
) ?*orca_config.Config {
    _ = state;
    return orcaForPath(node, worker.source.endpoint.hierarchicalPath());
}
pub fn orcaForPath(node: anytype, path: []const []const u8) ?*orca_config.Config {
    if (!pathMatches(path, node.path)) return null;
    return switch (node.kind) {
        .leaf => |*leaf| if (leaf.wrr_oob) |*value| value else null,
        .weighted => |weighted| for (weighted.children) |child| {
            if (orcaForPath(child.node, path)) |value| return value;
        } else null,
        .outlier => |wrapper| orcaForPath(wrapper.child, path),
    };
}

pub fn hasOob(node: anytype) bool {
    return switch (node.kind) {
        .leaf => |leaf| leaf.wrr_oob != null,
        .weighted => |weighted| for (weighted.children) |child| {
            if (hasOob(child.node)) break true;
        } else false,
        .outlier => |wrapper| hasOob(wrapper.child),
    };
}

fn Context(
    comptime RuntimePointer: type,
    comptime NodePointer: type,
    comptime StatePointer: type,
) type {
    return struct {
        runtime: RuntimePointer,
        node: NodePointer,
        state: StatePointer,

        fn ready(self: *@This(), worker: anytype) bool {
            return workerMatches(self.state, worker, self.node.path) and
                worker.eligible and !worker.retired and
                worker.published == .ready and
                !self.runtime.workerEjected(self.state, worker);
        }

        fn available(self: *@This(), worker: anytype) bool {
            return self.ready(worker) and worker.capacity != 0;
        }
    };
}

fn workerMatches(state: anytype, worker: anytype, path: []const []const u8) bool {
    _ = state;
    return pathMatches(
        worker.source.endpoint.hierarchicalPath(),
        path,
    );
}

fn pathMatches(
    endpoint_path: []const []const u8,
    node_path: []const []const u8,
) bool {
    if (endpoint_path.len < node_path.len) return false;
    for (node_path, endpoint_path[0..node_path.len]) |expected, actual| {
        if (!std.mem.eql(u8, expected, actual)) return false;
    }
    return true;
}

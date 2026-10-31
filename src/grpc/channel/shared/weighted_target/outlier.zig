//! Wrapper-local outlier evaluation and nested ejection state.
const std = @import("std");
const outlier_detection = @import("../../outlier_detection.zig");

pub fn evaluate(runtime: anytype, node: anytype, state: anytype, now_ns: i96) bool {
    return switch (node.kind) {
        .leaf => false,
        .weighted => |weighted| blk: {
            var changed = false;
            for (weighted.children) |child| {
                changed = evaluate(runtime, child.node, state, now_ns) or changed;
            }
            break :blk changed;
        },
        .outlier => |*wrapper| blk: {
            var changed = false;
            if (wrapper.config.countingEnabled() and
                now_ns >= wrapper.next_evaluation_ns)
            {
                const ContextType = Context(@TypeOf(node), @TypeOf(state));
                var context = ContextType{ .node = node, .state = state };
                changed = outlier_detection.evaluate(
                    state.io,
                    wrapper.config,
                    &context,
                    state.workers.items.len,
                    now_ns,
                    ContextType.endpoint,
                    ContextType.eligible,
                );
                wrapper.next_evaluation_ns = now_ns +| @max(
                    wrapper.config.interval.nanoseconds,
                    1,
                );
            }
            break :blk evaluate(runtime, wrapper.child, state, now_ns) or
                changed;
        },
    };
}

pub fn nextDeadline(node: anytype) ?i96 {
    return switch (node.kind) {
        .leaf => null,
        .weighted => |weighted| blk: {
            var result: ?i96 = null;
            for (weighted.children) |child| {
                if (nextDeadline(child.node)) |value| {
                    result = if (result) |prior| @min(prior, value) else value;
                }
            }
            break :blk result;
        },
        .outlier => |wrapper| blk: {
            var result: ?i96 = if (wrapper.config.countingEnabled())
                wrapper.next_evaluation_ns
            else
                null;
            if (nextDeadline(wrapper.child)) |value| {
                result = if (result) |prior| @min(prior, value) else value;
            }
            break :blk result;
        },
    };
}

pub fn record(node: anytype, state: anytype, worker: anytype, success: bool) void {
    if (!workerMatches(state, worker, node.path)) return;
    switch (node.kind) {
        .leaf => {},
        .weighted => |weighted| for (weighted.children) |child| {
            record(child.node, state, worker, success);
        },
        .outlier => |wrapper| {
            if (wrapper.config.countingEnabled()) worker.weighted_outliers[wrapper.index].record(success);
            record(wrapper.child, state, worker, success);
        },
    }
}

pub fn ejected(node: anytype, state: anytype, worker: anytype) bool {
    if (!workerMatches(state, worker, node.path)) return false;
    return switch (node.kind) {
        .leaf => false,
        .weighted => |weighted| for (weighted.children) |child| {
            if (ejected(child.node, state, worker)) break true;
        } else false,
        .outlier => |wrapper| worker.weighted_outliers[wrapper.index]
            .isEjected() or ejected(wrapper.child, state, worker),
    };
}

fn Context(comptime NodePointer: type, comptime StatePointer: type) type {
    return struct {
        node: NodePointer,
        state: StatePointer,

        fn endpoint(self: *@This(), index: usize) *outlier_detection.Endpoint {
            const worker = self.state.workers.items[index];
            return &worker.weighted_outliers[self.node.kind.outlier.index];
        }

        fn eligible(self: *@This(), index: usize) bool {
            const worker = self.state.workers.items[index];
            return !worker.retired and worker.eligible and
                workerMatches(self.state, worker, self.node.path);
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

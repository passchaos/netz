//! Wrapper-local outlier evaluation for ordinary weighted_target slots.
const std = @import("std");
const outlier_detection = @import("../outlier_detection.zig");

pub fn start(node: anytype, now_ns: i96) void {
    switch (node.kind) {
        .leaf => {},
        .weighted => |children| for (children) |child| {
            start(child.node, now_ns);
        },
        .priority => |priority| for (priority.children) |child| {
            start(child.node, now_ns);
        },
        .outlier => |*wrapper| {
            if (wrapper.config.countingEnabled() and
                wrapper.next_evaluation_ns == 0)
            {
                wrapper.next_evaluation_ns = now_ns +| @max(
                    wrapper.config.interval.nanoseconds,
                    1,
                );
            }
            start(wrapper.child, now_ns);
        },
    }
}

pub fn evaluate(
    node: anytype,
    slots: anytype,
    io: std.Io,
    now_ns: i96,
) bool {
    return switch (node.kind) {
        .leaf => false,
        .weighted => |children| blk: {
            var changed = false;
            for (children) |child| {
                changed = evaluate(child.node, slots, io, now_ns) or changed;
            }
            break :blk changed;
        },
        .priority => |priority| blk: {
            var changed = false;
            for (priority.children) |child| {
                changed = evaluate(child.node, slots, io, now_ns) or changed;
            }
            break :blk changed;
        },
        .outlier => |*wrapper| blk: {
            var changed = false;
            if (wrapper.config.countingEnabled() and
                now_ns >= wrapper.next_evaluation_ns)
            {
                const ContextType = Context(@TypeOf(node), @TypeOf(slots));
                var context = ContextType{ .node = node, .slots = slots };
                changed = outlier_detection.evaluate(
                    io,
                    wrapper.config,
                    &context,
                    slots.len,
                    now_ns,
                    ContextType.endpoint,
                    ContextType.eligible,
                );
                wrapper.next_evaluation_ns = now_ns +| @max(
                    wrapper.config.interval.nanoseconds,
                    1,
                );
            }
            break :blk evaluate(wrapper.child, slots, io, now_ns) or changed;
        },
    };
}

pub fn nextDeadline(node: anytype) ?i96 {
    return switch (node.kind) {
        .leaf => null,
        .weighted => |children| blk: {
            var result: ?i96 = null;
            for (children) |child| {
                if (nextDeadline(child.node)) |value| {
                    result = if (result) |prior| @min(prior, value) else value;
                }
            }
            break :blk result;
        },
        .priority => |priority| blk: {
            var result: ?i96 = null;
            for (priority.children) |child| {
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

pub fn ejected(node: anytype, slot: anytype) bool {
    if (!pathMatches(slot.endpoint.hierarchicalPath(), node.path)) return false;
    return switch (node.kind) {
        .leaf => false,
        .weighted => |children| for (children) |child| {
            if (ejected(child.node, slot)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (ejected(child.node, slot)) break true;
        } else false,
        .outlier => |wrapper| slot.weighted_outliers[wrapper.index]
            .endpoint.isEjected() or ejected(wrapper.child, slot),
    };
}

fn Context(comptime NodePointer: type, comptime Slots: type) type {
    return struct {
        node: NodePointer,
        slots: Slots,

        fn endpoint(
            self: *@This(),
            index: usize,
        ) *outlier_detection.Endpoint {
            return &self.slots[index].weighted_outliers[
                self.node.kind.outlier.index
            ].endpoint;
        }

        fn eligible(self: *@This(), index: usize) bool {
            return pathMatches(
                self.slots[index].endpoint.hierarchicalPath(),
                self.node.path,
            );
        }
    };
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

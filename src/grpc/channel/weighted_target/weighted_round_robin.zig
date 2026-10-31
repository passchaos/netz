//! Child-local static-stride scheduling and ORCA configuration lookup for the
//! single-owner weighted_target runtime.
const std = @import("std");
const service_config = @import("../../service_config.zig");

pub fn pick(
    allocator: std.mem.Allocator,
    node: anytype,
    leaf: anytype,
    slots: anytype,
    io: std.Io,
) std.mem.Allocator.Error!?usize {
    const ContextType = Context(@TypeOf(node));
    var context = ContextType{ .node = node };
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now >= leaf.wrr_scheduler.next_update_ns) {
        try leaf.wrr_scheduler.rebuildFiltered(
            allocator,
            slots,
            now,
            leaf.wrr_config,
            &context,
            ContextType.ready,
        );
    }
    const Slot = @typeInfo(@TypeOf(slots)).pointer.child;
    const selected = leaf.wrr_scheduler.pickFiltered(
        Slot,
        &leaf.wrr_sequence,
        &context,
        ContextType.ready,
    ) orelse return null;
    for (slots, 0..) |*slot, index| {
        if (slot == selected) return index;
    }
    unreachable;
}

pub fn config(
    node: anytype,
    slot: anytype,
) ?service_config.WeightedRoundRobinConfig {
    if (!pathMatches(slot.endpoint.hierarchicalPath(), node.path)) return null;
    return switch (node.kind) {
        .leaf => |leaf| if (leaf.policy == .weighted_round_robin)
            leaf.wrr_config
        else
            null,
        .weighted => |children| for (children) |child| {
            if (config(child.node, slot)) |value| return value;
        } else null,
        .outlier => |wrapper| config(wrapper.child, slot),
    };
}

fn Context(comptime NodePointer: type) type {
    return struct {
        node: NodePointer,

        fn ready(self: *@This(), slot: anytype) bool {
            if (!pathMatches(
                slot.endpoint.hierarchicalPath(),
                self.node.path,
            ) or slot.disabled or slot.weighted_target_ejected) return false;
            const connection = if (slot.connection) |*value|
                value
            else
                return false;
            return connection.isReusable();
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

//! Match policy instances by hierarchical name and migrate their mutable state.
const std = @import("std");
const Outlier = @import("../../outlier_detection.zig").Endpoint;

pub fn Plan(comptime Runtime: type) type {
    return struct {
        allocator: std.mem.Allocator,
        pairs: std.ArrayList(Pair) = .empty,

        const Self = @This();
        const Node = @typeInfo(@FieldType(Runtime, "root")).pointer.child;
        const Pair = struct { old: *Node, next: *Node, retained: bool = false };

        pub fn init(allocator: std.mem.Allocator, old: ?*Runtime, next: ?*Runtime) std.mem.Allocator.Error!Self {
            var self = Self{ .allocator = allocator };
            errdefer self.deinit();
            if (old != null and next != null) try self.collect(old.?.root, next.?.root);
            return self;
        }
        pub fn deinit(self: *Self) void {
            self.pairs.deinit(self.allocator);
        }

        pub fn collect(self: *Self, old: *Node, next: *Node) std.mem.Allocator.Error!void {
            if (!samePath(old.path, next.path) or old.cluster_manager != next.cluster_manager) return;
            if (old.kind == .outlier and next.kind != .outlier) {
                return self.collect(old.kind.outlier.child, next);
            }
            if (next.kind == .outlier and old.kind != .outlier) {
                return self.collect(old, next.kind.outlier.child);
            }
            if (std.meta.activeTag(old.kind) != std.meta.activeTag(next.kind)) return;
            switch (next.kind) {
                .leaf => |leaf| {
                    if (old.kind.leaf.policy == leaf.policy) try self.pairs.append(self.allocator, .{ .old = old, .next = next });
                },
                .priority => |priority| {
                    for (priority.children) |child| {
                        for (old.kind.priority.children) |prior| {
                            if (!samePath(prior.node.path, child.node.path)) continue;
                            try self.collect(prior.node, child.node);
                            break;
                        }
                    }
                },
                .outlier => |wrapper| {
                    try self.pairs.append(self.allocator, .{ .old = old, .next = next });
                    try self.collect(old.kind.outlier.child, wrapper.child);
                },
                .weighted => |weighted| {
                    for (weighted.children) |child| {
                        for (old.kind.weighted.children) |prior| {
                            if (!samePath(prior.node.path, child.node.path)) continue;
                            try self.collect(prior.node, child.node);
                            break;
                        }
                    }
                },
            }
        }
        pub fn collectRetained(self: *Self, old: *Node, next: *Node) std.mem.Allocator.Error!void {
            const start = self.pairs.items.len;
            try self.collect(old, next);
            for (self.pairs.items[start..]) |*pair| pair.retained = true;
        }

        pub fn copyOutliers(self: *const Self, path: []const []const u8, old: []const Outlier, next: []Outlier) void {
            self.copyOutliersFrom(path, old, next, false);
        }
        pub fn copyOutliersFrom(self: *const Self, path: []const []const u8, old: []const Outlier, next: []Outlier, retained: bool) void {
            for (self.pairs.items) |pair| {
                if (pair.retained != retained) continue;
                if (pair.next.kind != .outlier or !matches(path, pair.next.path)) continue;
                const source_index = pair.old.kind.outlier.index;
                const destination_index = pair.next.kind.outlier.index;
                std.debug.assert(source_index < old.len and destination_index < next.len);
                next[destination_index] = old[source_index];
                if (!pair.next.kind.outlier.config.countingEnabled()) {
                    next[destination_index].ejected_at_ns = null;
                    next[destination_index].multiplier = 0;
                }
            }
        }

        pub fn keepsWrr(self: *const Self, path: []const []const u8) bool {
            for (self.pairs.items) |pair| {
                if (pair.next.kind == .leaf and pair.next.kind.leaf.policy == .weighted_round_robin and matches(path, pair.next.path)) return true;
            }
            return false;
        }

        /// Called only after all allocation/task admission succeeds. The old
        /// runtime loses each moved buffer so its later destruction is safe.
        pub fn commit(self: *Self) void {
            for (self.pairs.items) |pair| switch (pair.next.kind) {
                .leaf => |*leaf| {
                    const prior = &pair.old.kind.leaf;
                    leaf.selected = prior.selected;
                    leaf.next_pick = prior.next_pick;
                    leaf.wrr_sequence = prior.wrr_sequence;
                    leaf.ring.deinit(self.allocator);
                    leaf.ring = prior.ring;
                    prior.ring = .{};
                    leaf.ring_dirty = true;
                    leaf.wrr_scheduler.deinit(self.allocator);
                    leaf.wrr_scheduler = prior.wrr_scheduler;
                    prior.wrr_scheduler = .{};
                    leaf.wrr_scheduler.next_update_ns = 0;
                },
                .outlier => |*wrapper| {
                    if (wrapper.config.interval.nanoseconds == pair.old.kind.outlier.config.interval.nanoseconds) {
                        wrapper.next_evaluation_ns = pair.old.kind.outlier.next_evaluation_ns;
                    }
                },
                .priority => unreachable,
                .weighted => unreachable,
            };
        }

        fn samePath(a: []const []const u8, b: []const []const u8) bool {
            return a.len == b.len and matches(a, b);
        }
        fn matches(path: []const []const u8, prefix: []const []const u8) bool {
            if (path.len < prefix.len) return false;
            for (path[0..prefix.len], prefix) |a, b| if (!std.mem.eql(u8, a, b)) return false;
            return true;
        }
    };
}

//! Recursive weighted_target runtime for the single-owner Channel.
//!
//! The initial executable subset supports nested weighted targets with
//! pick-first and round-robin leaves. Configuration strings are deep-copied so
//! the caller may destroy ServiceConfig immediately after Channel init.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const service_config = @import("../service_config.zig");

pub fn Runtime(comptime Slot: type) type {
    return struct {
        allocator: std.mem.Allocator,
        root: *Node,

        const Self = @This();
        const AggregateState = enum {
            idle,
            connecting,
            ready,
            transient_failure,
        };
        const BuildError = std.mem.Allocator.Error || error{
            InvalidChannelOptions,
        };

        const Leaf = struct {
            policy: enum { pick_first, round_robin },
            selected: ?usize = null,
            next_pick: usize = 0,
        };

        const Child = struct {
            weight: u32,
            node: *Node,
        };

        const Node = struct {
            path: []const []const u8,
            kind: union(enum) {
                leaf: Leaf,
                weighted: []Child,
            },
        };

        pub fn init(
            allocator: std.mem.Allocator,
            config: *const service_config.LoadBalancingNode,
        ) BuildError!Self {
            var self = Self{ .allocator = allocator, .root = undefined };
            self.root = try self.build(config, &.{});
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.destroy(self.root);
            self.* = undefined;
        }

        pub fn pick(self: *Self, slots: []Slot, io: std.Io) ?usize {
            return self.pickNode(self.root, slots, io);
        }

        pub fn hasReady(self: *Self, slots: []Slot) bool {
            return self.aggregate(self.root, slots) == .ready;
        }

        fn build(
            self: *Self,
            config: *const service_config.LoadBalancingNode,
            path: []const []const u8,
        ) BuildError!*Node {
            return switch (config.*) {
                .pick_first => self.buildLeaf(path, .pick_first),
                .round_robin => self.buildLeaf(path, .round_robin),
                .weighted_target => |weighted| self.buildWeighted(
                    weighted,
                    path,
                ),
                else => error.InvalidChannelOptions,
            };
        }

        fn buildLeaf(
            self: *Self,
            path: []const []const u8,
            policy: @FieldType(Leaf, "policy"),
        ) BuildError!*Node {
            const owned_path = try dupePath(self.allocator, path);
            errdefer freePath(self.allocator, owned_path);
            const node = try self.allocator.create(Node);
            node.* = .{
                .path = owned_path,
                .kind = .{ .leaf = .{ .policy = policy } },
            };
            return node;
        }

        fn buildWeighted(
            self: *Self,
            config: service_config.WeightedTargetConfig,
            path: []const []const u8,
        ) BuildError!*Node {
            const owned_path = try dupePath(self.allocator, path);
            errdefer freePath(self.allocator, owned_path);
            const children = try self.allocator.alloc(Child, config.targets.len);
            var initialized: usize = 0;
            errdefer {
                for (children[0..initialized]) |child| self.destroy(child.node);
                self.allocator.free(children);
            }
            for (config.targets, children) |target, *child| {
                const child_path = try self.allocator.alloc(
                    []const u8,
                    path.len + 1,
                );
                defer self.allocator.free(child_path);
                @memcpy(child_path[0..path.len], path);
                child_path[path.len] = target.name;
                child.* = .{
                    .weight = target.weight,
                    .node = try self.build(target.child, child_path),
                };
                initialized += 1;
            }
            const node = try self.allocator.create(Node);
            node.* = .{
                .path = owned_path,
                .kind = .{ .weighted = children },
            };
            return node;
        }

        fn destroy(self: *Self, node: *Node) void {
            switch (node.kind) {
                .leaf => {},
                .weighted => |children| {
                    for (children) |child| self.destroy(child.node);
                    self.allocator.free(children);
                },
            }
            freePath(self.allocator, node.path);
            self.allocator.destroy(node);
        }

        fn pickNode(
            self: *Self,
            node: *Node,
            slots: []Slot,
            io: std.Io,
        ) ?usize {
            return switch (node.kind) {
                .leaf => |*leaf| pickLeaf(node.path, leaf, slots),
                .weighted => |children| blk: {
                    var total: u64 = 0;
                    for (children) |child| {
                        if (self.aggregate(child.node, slots) == .ready) {
                            total += child.weight;
                        }
                    }
                    if (total == 0) break :blk null;
                    var seed: u64 = undefined;
                    io.random(std.mem.asBytes(&seed));
                    var prng = std.Random.DefaultPrng.init(seed);
                    var sample = prng.random().uintLessThan(u64, total);
                    for (children) |child| {
                        if (self.aggregate(child.node, slots) != .ready) {
                            continue;
                        }
                        if (sample < child.weight) {
                            break :blk self.pickNode(child.node, slots, io);
                        }
                        sample -= child.weight;
                    }
                    unreachable;
                },
            };
        }

        fn aggregate(
            self: *Self,
            node: *Node,
            slots: []Slot,
        ) AggregateState {
            return switch (node.kind) {
                .leaf => aggregateLeaf(node.path, slots),
                .weighted => |children| blk: {
                    var connecting = false;
                    var idle = false;
                    for (children) |child| switch (self.aggregate(
                        child.node,
                        slots,
                    )) {
                        .ready => break :blk .ready,
                        .connecting => connecting = true,
                        .idle => idle = true,
                        .transient_failure => {},
                    };
                    break :blk if (connecting)
                        .connecting
                    else if (idle)
                        .idle
                    else
                        .transient_failure;
                },
            };
        }

        fn aggregateLeaf(
            path: []const []const u8,
            slots: []Slot,
        ) AggregateState {
            var connecting = false;
            var idle = false;
            for (slots) |*slot| {
                if (!pathMatches(slot.endpoint.hierarchicalPath(), path)) {
                    continue;
                }
                if (slot.connection) |*connection| {
                    if (connection.isReusable()) return .ready;
                }
                if (slot.disabled) continue;
                if (slot.next_attempt_at_ns != null) connecting = true else idle = true;
            }
            return if (connecting)
                .connecting
            else if (idle)
                .idle
            else
                .transient_failure;
        }

        fn pickLeaf(
            path: []const []const u8,
            leaf: *Leaf,
            slots: []Slot,
        ) ?usize {
            if (leaf.policy == .pick_first) {
                if (leaf.selected) |selected| {
                    if (slotReady(&slots[selected]) and
                        pathMatches(
                            slots[selected].endpoint.hierarchicalPath(),
                            path,
                        )) return selected;
                    leaf.selected = null;
                }
            }
            var count: usize = 0;
            for (slots) |slot| {
                if (pathMatches(
                    slot.endpoint.hierarchicalPath(),
                    path,
                )) count += 1;
            }
            for (0..count) |offset| {
                const wanted = if (leaf.policy == .round_robin)
                    (leaf.next_pick + offset) % count
                else
                    offset;
                var ordinal: usize = 0;
                for (slots, 0..) |*slot, index| {
                    if (!pathMatches(slot.endpoint.hierarchicalPath(), path)) {
                        continue;
                    }
                    if (ordinal == wanted) {
                        if (!slotReady(slot)) break;
                        if (leaf.policy == .pick_first) {
                            leaf.selected = index;
                        } else {
                            leaf.next_pick = (wanted + 1) % count;
                        }
                        return index;
                    }
                    ordinal += 1;
                }
            }
            return null;
        }

        fn slotReady(slot: *Slot) bool {
            if (slot.disabled) return false;
            const connection = if (slot.connection) |*value| value else return false;
            return connection.isReusable();
        }
    };
}

fn dupePath(
    allocator: std.mem.Allocator,
    path: []const []const u8,
) std.mem.Allocator.Error![][]const u8 {
    const result = try allocator.alloc([]const u8, path.len);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |element| allocator.free(element);
        allocator.free(result);
    }
    for (path, result) |element, *owned| {
        owned.* = try allocator.dupe(u8, element);
        initialized += 1;
    }
    return result;
}

fn freePath(allocator: std.mem.Allocator, path: []const []const u8) void {
    for (path) |element| allocator.free(element);
    allocator.free(path);
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

test "ordinary weighted target runtime deep copy is allocation transactional" {
    const FakeSlot = struct {};
    const leaf = service_config.LoadBalancingNode.round_robin;
    const nested_targets = [_]service_config.WeightedTargetConfig.Target{.{
        .name = "inner",
        .weight = 1,
        .child = &leaf,
    }};
    const nested = service_config.LoadBalancingNode{ .weighted_target = .{
        .targets = &nested_targets,
    } };
    const targets = [_]service_config.WeightedTargetConfig.Target{
        .{ .name = "a", .weight = 1, .child = &leaf },
        .{ .name = "b", .weight = 3, .child = &nested },
    };
    const root = service_config.LoadBalancingNode{ .weighted_target = .{
        .targets = &targets,
    } };
    const Harness = struct {
        fn run(
            allocator: std.mem.Allocator,
            config: *const service_config.LoadBalancingNode,
        ) !void {
            var runtime = try Runtime(FakeSlot).init(allocator, config);
            runtime.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{&root},
    );
}

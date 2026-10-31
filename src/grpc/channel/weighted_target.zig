//! Recursive weighted_target runtime for the single-owner Channel.
//!
//! The executable subset supports nested weighted targets with pick-first,
//! round-robin, and least-request leaves. Configuration strings are
//! deep-copied so the caller may destroy ServiceConfig immediately after
//! Channel init.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const least_request = @import("least_request.zig");
const ring_hash = @import("ring_hash.zig");
const ring_support = @import("weighted_target/ring_hash.zig");
const weighted_round_robin = @import("weighted_round_robin.zig");
const wrr_support = @import("weighted_target/weighted_round_robin.zig");
const service_config = @import("../service_config.zig");

pub const RequestInput = struct {
    request_hash: ?u64 = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    random_if_missing: bool = false,

    pub fn resolveHash(
        self: RequestInput,
        io: std.Io,
        config: ring_hash.Config,
    ) error{MissingRequestHash}!ring_hash.RequestHash {
        if (self.random_if_missing and config.request_hash_header == null and
            self.request_hash == null)
        {
            var random: u64 = undefined;
            io.random(std.mem.asBytes(&random));
            return .{ .value = random, .random = true };
        }
        return ring_hash.requestHash(io, config, self);
    }
};

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
        const PickError = std.mem.Allocator.Error || error{
            MissingRequestHash,
        };

        const Leaf = struct {
            policy: enum { pick_first, round_robin, least_request, ring_hash, weighted_round_robin },
            least_request_config: least_request.Config = .{},
            ring_hash_config: ring_hash.Config = .{},
            ring_hash_header: ?[]u8 = null,
            ring: ring_hash.Ring = .{},
            wrr_config: service_config.WeightedRoundRobinConfig = .{},
            wrr_metric_names: ?[][]u8 = null,
            wrr_scheduler: weighted_round_robin.Scheduler = .{},
            wrr_sequence: u32 = 0,
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

        pub fn pick(
            self: *Self,
            slots: []Slot,
            io: std.Io,
            input: RequestInput,
        ) PickError!?usize {
            return self.pickNode(self.root, slots, io, input);
        }

        pub fn hasReady(self: *Self, slots: []Slot) bool {
            return self.aggregate(self.root, slots) == .ready;
        }

        pub fn wrrConfig(
            self: *Self,
            slots: []Slot,
            index: usize,
        ) ?service_config.WeightedRoundRobinConfig {
            return wrr_support.config(self.root, &slots[index]);
        }

        pub fn configureSlots(self: *Self, slots: []Slot) BuildError!void {
            for (slots) |*slot| {
                slot.least_request_enabled = self.pathUsesLeastRequest(
                    self.root,
                    slot.endpoint.hierarchicalPath(),
                );
            }
            self.invalidateWrr(self.root);
            try self.rebuildRings(self.root, slots);
        }

        fn build(
            self: *Self,
            config: *const service_config.LoadBalancingNode,
            path: []const []const u8,
        ) BuildError!*Node {
            return switch (config.*) {
                .pick_first => self.buildLeaf(path, .pick_first),
                .round_robin => self.buildLeaf(path, .round_robin),
                .least_request => |config_value| self.buildLeastRequest(
                    path,
                    config_value,
                ),
                .ring_hash => |config_value| self.buildRingHash(
                    path,
                    config_value,
                ),
                .weighted_round_robin => |config_value| self.buildWrr(
                    path,
                    config_value,
                ),
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

        fn buildLeastRequest(
            self: *Self,
            path: []const []const u8,
            config: least_request.Config,
        ) BuildError!*Node {
            const node = try self.buildLeaf(path, .least_request);
            node.kind.leaf.least_request_config = config;
            return node;
        }

        fn buildRingHash(
            self: *Self,
            path: []const []const u8,
            config: ring_hash.Config,
        ) BuildError!*Node {
            const node = try self.buildLeaf(path, .ring_hash);
            errdefer self.destroy(node);
            var retained = config;
            if (config.request_hash_header) |header| {
                const owned = try self.allocator.dupe(u8, header);
                node.kind.leaf.ring_hash_header = owned;
                retained.request_hash_header = owned;
            }
            node.kind.leaf.ring_hash_config = retained;
            return node;
        }

        fn buildWrr(
            self: *Self,
            path: []const []const u8,
            config: service_config.WeightedRoundRobinConfig,
        ) BuildError!*Node {
            const node = try self.buildLeaf(path, .weighted_round_robin);
            errdefer self.destroy(node);
            if (config.metric_names.len == 0) {
                node.kind.leaf.wrr_config = config;
                return node;
            }
            const names = try self.allocator.alloc(
                []u8,
                config.metric_names.len,
            );
            var initialized: usize = 0;
            errdefer {
                for (names[0..initialized]) |name| self.allocator.free(name);
                self.allocator.free(names);
            }
            for (config.metric_names, names) |name, *owned| {
                owned.* = try self.allocator.dupe(u8, name);
                initialized += 1;
            }
            var retained = config;
            retained.metric_names = names;
            node.kind.leaf.wrr_metric_names = names;
            node.kind.leaf.wrr_config = retained;
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
                .leaf => |*leaf| {
                    leaf.ring.deinit(self.allocator);
                    leaf.wrr_scheduler.deinit(self.allocator);
                    if (leaf.ring_hash_header) |header| {
                        self.allocator.free(header);
                    }
                    if (leaf.wrr_metric_names) |names| {
                        for (names) |name| self.allocator.free(name);
                        self.allocator.free(names);
                    }
                },
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
            input: RequestInput,
        ) PickError!?usize {
            return switch (node.kind) {
                .leaf => |*leaf| try self.pickLeaf(
                    node,
                    leaf,
                    slots,
                    io,
                    input,
                ),
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
                            break :blk try self.pickNode(
                                child.node,
                                slots,
                                io,
                                input,
                            );
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
            self: *Self,
            node: *Node,
            leaf: *Leaf,
            slots: []Slot,
            io: std.Io,
            input: RequestInput,
        ) PickError!?usize {
            const path = node.path;
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
            if (leaf.policy == .least_request) {
                return pickLeastRequest(
                    path,
                    leaf.least_request_config,
                    slots,
                    io,
                );
            }
            if (leaf.policy == .ring_hash) {
                return try ring_support.pick(
                    self,
                    node,
                    leaf,
                    slots,
                    io,
                    input,
                );
            }
            if (leaf.policy == .weighted_round_robin) {
                if (try wrr_support.pick(
                    self.allocator,
                    node,
                    leaf,
                    slots,
                    io,
                )) |index| return index;
            }
            var count: usize = 0;
            for (slots) |slot| {
                if (pathMatches(
                    slot.endpoint.hierarchicalPath(),
                    path,
                )) count += 1;
            }
            for (0..count) |offset| {
                const wanted = if (leaf.policy == .round_robin or
                    leaf.policy == .weighted_round_robin)
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
                        } else if (leaf.policy == .round_robin or
                            leaf.policy == .weighted_round_robin)
                        {
                            leaf.next_pick = (wanted + 1) % count;
                        }
                        return index;
                    }
                    ordinal += 1;
                }
            }
            return null;
        }

        fn pickLeastRequest(
            path: []const []const u8,
            config: least_request.Config,
            slots: []Slot,
            io: std.Io,
        ) ?usize {
            const Context = struct {
                slots: []Slot,
                path: []const []const u8,

                fn available(context: *@This(), index: usize) bool {
                    const slot = &context.slots[index];
                    return pathMatches(
                        slot.endpoint.hierarchicalPath(),
                        context.path,
                    ) and slotReady(slot);
                }

                fn outstanding(context: *@This(), index: usize) usize {
                    return context.slots[index].outstanding_requests;
                }
            };
            var seed: u64 = undefined;
            io.random(std.mem.asBytes(&seed));
            var context = Context{ .slots = slots, .path = path };
            return least_request.pickIndex(
                &context,
                slots.len,
                config,
                seed,
                Context.available,
                Context.outstanding,
            );
        }

        fn pathUsesLeastRequest(
            self: *Self,
            node: *Node,
            path: []const []const u8,
        ) bool {
            if (!pathMatches(path, node.path)) return false;
            return switch (node.kind) {
                .leaf => |leaf| leaf.policy == .least_request,
                .weighted => |children| for (children) |child| {
                    if (pathMatches(path, child.node.path)) {
                        return self.pathUsesLeastRequest(child.node, path);
                    }
                } else false,
            };
        }

        fn rebuildRings(
            self: *Self,
            node: *Node,
            slots: []Slot,
        ) BuildError!void {
            switch (node.kind) {
                .leaf => |*leaf| if (leaf.policy == .ring_hash) {
                    ring_support.rebuild(
                        self.allocator,
                        self,
                        node,
                        leaf,
                        slots,
                    ) catch |err| return switch (err) {
                        error.OutOfMemory => error.OutOfMemory,
                        else => error.InvalidChannelOptions,
                    };
                },
                .weighted => |children| for (children) |child| {
                    try self.rebuildRings(child.node, slots);
                },
            }
        }

        fn invalidateWrr(self: *Self, node: *Node) void {
            switch (node.kind) {
                .leaf => |*leaf| if (leaf.policy == .weighted_round_robin) {
                    leaf.wrr_scheduler.invalidate();
                },
                .weighted => |children| for (children) |child| {
                    self.invalidateWrr(child.node);
                },
            }
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
    const least_leaf = service_config.LoadBalancingNode{ .least_request = .{
        .choice_count = 4,
    } };
    const ring_leaf = service_config.LoadBalancingNode{ .ring_hash = .{
        .min_ring_size = 16,
        .max_ring_size = 16,
        .request_hash_header = "x-shard",
    } };
    const wrr_leaf = service_config.LoadBalancingNode{
        .weighted_round_robin = .{
            .metric_names = &.{"named_metrics.queue"},
        },
    };
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
        .{ .name = "least", .weight = 2, .child = &least_leaf },
        .{ .name = "ring", .weight = 4, .child = &ring_leaf },
        .{ .name = "wrr", .weight = 5, .child = &wrr_leaf },
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

test "ordinary weighted target least request is child local" {
    const FakeConnection = struct {
        ready: bool = true,

        fn isReusable(self: *@This()) bool {
            return self.ready;
        }
    };
    const FakeEndpoint = struct {
        path: []const []const u8,

        fn hierarchicalPath(self: *const @This()) []const []const u8 {
            return self.path;
        }
    };
    const FakeSlot = struct {
        endpoint: FakeEndpoint,
        connection: ?FakeConnection = .{},
        disabled: bool = false,
        next_attempt_at_ns: ?i96 = null,
        outstanding_requests: usize = 0,
        least_request_enabled: bool = false,
    };
    const least_leaf = service_config.LoadBalancingNode{ .least_request = .{
        .choice_count = 10,
    } };
    const targets = [_]service_config.WeightedTargetConfig.Target{.{
        .name = "least",
        .weight = 1,
        .child = &least_leaf,
    }};
    const root = service_config.LoadBalancingNode{ .weighted_target = .{
        .targets = &targets,
    } };
    const least_path = [_][]const u8{"least"};
    const sibling_path = [_][]const u8{"sibling"};
    var slots = [_]FakeSlot{
        .{
            .endpoint = .{ .path = &least_path },
            .outstanding_requests = 100,
        },
        .{ .endpoint = .{ .path = &least_path } },
        .{ .endpoint = .{ .path = &sibling_path } },
    };
    var runtime = try Runtime(FakeSlot).init(std.testing.allocator, &root);
    defer runtime.deinit();
    try runtime.configureSlots(&slots);
    try std.testing.expect(slots[0].least_request_enabled);
    try std.testing.expect(slots[1].least_request_enabled);
    try std.testing.expect(!slots[2].least_request_enabled);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var low_load_picks: usize = 0;
    for (0..4096) |_| {
        const picked = (try runtime.pick(
            &slots,
            threaded.io(),
            .{},
        )).?;
        try std.testing.expect(picked != 2);
        low_load_picks += @intFromBool(picked == 1);
    }
    try std.testing.expect(low_load_picks > 4000);
}

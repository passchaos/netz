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
const outlier_detection = @import("outlier_detection.zig");
const outlier_support = @import("weighted_target/outlier.zig");
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
        outlier_count: usize = 0,
        priority_failover_timeout_ns: i96 = 10 * std.time.ns_per_s,

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

        const Outlier = struct {
            config: service_config.OutlierDetectionConfig,
            index: usize,
            next_evaluation_ns: i96 = 0,
            child: *Node,
        };

        const PriorityChild = struct {
            ignore_reresolution_requests: bool,
            node: *Node,
        };

        const Priority = struct {
            children: []PriorityChild,
            order: []usize,
            failover_started_ns: ?i96 = null,
            /// grpc-core only restarts the failover timer after the first
            /// priority has been READY or IDLE since the previous attempt.
            failover_can_start: bool = true,
        };

        const Node = struct {
            path: []const []const u8,
            kind: union(enum) {
                leaf: Leaf,
                weighted: []Child,
                priority: Priority,
                outlier: Outlier,
            },
        };

        pub fn init(
            allocator: std.mem.Allocator,
            config: *const service_config.LoadBalancingNode,
        ) BuildError!Self {
            return initWithPriorityFailoverTimeout(
                allocator,
                config,
                10 * std.time.ns_per_s,
            );
        }

        pub fn initWithPriorityFailoverTimeout(
            allocator: std.mem.Allocator,
            config: *const service_config.LoadBalancingNode,
            priority_failover_timeout_ns: i96,
        ) BuildError!Self {
            var self = Self{
                .allocator = allocator,
                .root = undefined,
                .priority_failover_timeout_ns = priority_failover_timeout_ns,
            };
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

        pub fn evaluateOutliers(self: *Self, slots: []Slot, io: std.Io) bool {
            const changed = outlier_support.evaluate(
                self.root,
                slots,
                io,
                std.Io.Clock.awake.now(io).nanoseconds,
            );
            self.updateEjectedSlots(slots);
            if (changed) self.invalidateWrr(self.root);
            return changed;
        }

        pub fn startOutliers(self: *Self, io: std.Io) void {
            outlier_support.start(
                self.root,
                std.Io.Clock.awake.now(io).nanoseconds,
            );
        }

        pub fn nextOutlierDeadline(self: *const Self) ?i96 {
            return outlier_support.nextDeadline(self.root);
        }

        pub fn ignoresReresolution(self: *const Self, path: []const []const u8) bool {
            return @import("tree_query.zig").ignoresReresolution(self.root, path);
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
            try self.configureOutliers(slots);
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
                .priority => |priority| self.buildPriority(
                    priority,
                    path,
                ),
                .outlier_detection => |wrapper| self.buildOutlier(
                    wrapper,
                    path,
                ),
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

        fn buildPriority(
            self: *Self,
            config: service_config.PriorityConfig,
            path: []const []const u8,
        ) BuildError!*Node {
            const owned_path = try dupePath(self.allocator, path);
            errdefer freePath(self.allocator, owned_path);
            const children = try self.allocator.alloc(
                PriorityChild,
                config.children.len,
            );
            var initialized: usize = 0;
            errdefer {
                for (children[0..initialized]) |child| self.destroy(child.node);
                self.allocator.free(children);
            }
            for (config.children, children) |child_config, *child| {
                const child_path = try self.allocator.alloc(
                    []const u8,
                    path.len + 1,
                );
                defer self.allocator.free(child_path);
                @memcpy(child_path[0..path.len], path);
                child_path[path.len] = child_config.name;
                child.* = .{
                    .ignore_reresolution_requests = child_config.ignore_reresolution_requests,
                    .node = try self.build(child_config.child, child_path),
                };
                initialized += 1;
            }
            const order = try self.allocator.alloc(
                usize,
                config.priorities.len,
            );
            errdefer self.allocator.free(order);
            for (config.priorities, order) |name, *slot| {
                var found: ?usize = null;
                for (config.children, 0..) |child_config, index| {
                    if (std.mem.eql(u8, child_config.name, name)) {
                        found = index;
                        break;
                    }
                }
                slot.* = found orelse return error.InvalidChannelOptions;
            }
            const node = try self.allocator.create(Node);
            node.* = .{
                .path = owned_path,
                .kind = .{ .priority = .{
                    .children = children,
                    .order = order,
                } },
            };
            return node;
        }

        fn buildOutlier(
            self: *Self,
            wrapper: @FieldType(
                service_config.LoadBalancingNode,
                "outlier_detection",
            ),
            path: []const []const u8,
        ) BuildError!*Node {
            const index = self.outlier_count;
            self.outlier_count += 1;
            const owned_path = try dupePath(self.allocator, path);
            errdefer freePath(self.allocator, owned_path);
            const child = try self.build(wrapper.child, path);
            errdefer self.destroy(child);
            const node = try self.allocator.create(Node);
            node.* = .{
                .path = owned_path,
                .kind = .{ .outlier = .{
                    .config = wrapper.config,
                    .index = index,
                    .child = child,
                } },
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
                .priority => |priority| {
                    for (priority.children) |child| self.destroy(child.node);
                    self.allocator.free(priority.children);
                    self.allocator.free(priority.order);
                },
                .outlier => |wrapper| self.destroy(wrapper.child),
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
                .priority => |*priority| blk: {
                    if (priority.order.len == 0) break :blk null;
                    const now = std.Io.Clock.awake.now(io).nanoseconds;
                    const first = priority.children[priority.order[0]];
                    const first_state = self.aggregate(first.node, slots);
                    switch (first_state) {
                        .ready, .idle => {
                            priority.failover_started_ns = null;
                            priority.failover_can_start = true;
                        },
                        .connecting => {
                            if (priority.failover_started_ns == null and
                                priority.failover_can_start)
                            {
                                priority.failover_started_ns = now;
                            }
                            priority.failover_can_start = false;
                        },
                        .transient_failure => {
                            priority.failover_started_ns = null;
                            priority.failover_can_start = false;
                        },
                    }
                    const failover_open = self.priority_failover_timeout_ns <= 0 or switch (first_state) {
                        .ready, .idle => false,
                        .transient_failure => true,
                        .connecting => timer: {
                            const started = priority.failover_started_ns orelse
                                break :timer true;
                            break :timer now >= started +|
                                self.priority_failover_timeout_ns;
                        },
                    };
                    if (!failover_open) {
                        if (first_state == .ready) {
                            break :blk try self.pickNode(
                                first.node,
                                slots,
                                io,
                                input,
                            );
                        }
                        break :blk null;
                    }
                    for (priority.order) |child_index| {
                        const child = priority.children[child_index];
                        if (self.aggregate(child.node, slots) == .ready) {
                            break :blk try self.pickNode(
                                child.node,
                                slots,
                                io,
                                input,
                            );
                        }
                    }
                    break :blk null;
                },
                .outlier => |wrapper| try self.pickNode(
                    wrapper.child,
                    slots,
                    io,
                    input,
                ),
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
                .priority => |priority| blk: {
                    var connecting = false;
                    var idle = false;
                    for (priority.children) |child| switch (self.aggregate(
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
                .outlier => |wrapper| self.aggregate(
                    wrapper.child,
                    slots,
                ),
            };
        }

        fn aggregateLeaf(
            path: []const []const u8,
            slots: []Slot,
        ) AggregateState {
            var idle = false;
            for (slots) |*slot| {
                if (!pathMatches(slot.endpoint.hierarchicalPath(), path)) {
                    continue;
                }
                if (slot.weighted_target_ejected) continue;
                if (slotReady(slot)) return .ready;
                if (slot.disabled) continue;
                // A slot waiting for retry backoff is grpc-core's
                // TRANSIENT_FAILURE, not CONNECTING. Only a never-attempted
                // slot is IDLE.
                if (slot.next_attempt_at_ns == null) idle = true;
            }
            return if (idle) .idle else .transient_failure;
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
                .priority => |priority| for (priority.children) |child| {
                    if (pathMatches(path, child.node.path)) {
                        return self.pathUsesLeastRequest(child.node, path);
                    }
                } else false,
                .outlier => |wrapper| self.pathUsesLeastRequest(
                    wrapper.child,
                    path,
                ),
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
                .priority => |priority| for (priority.children) |child| {
                    try self.rebuildRings(child.node, slots);
                },
                .outlier => |wrapper| try self.rebuildRings(
                    wrapper.child,
                    slots,
                ),
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
                .priority => |priority| for (priority.children) |child| {
                    self.invalidateWrr(child.node);
                },
                .outlier => |wrapper| self.invalidateWrr(wrapper.child),
            }
        }

        fn configureOutliers(self: *Self, slots: []Slot) BuildError!void {
            if (self.outlier_count == 0) return;
            const State = @typeInfo(
                @FieldType(Slot, "weighted_outliers"),
            ).pointer.child;
            const pending = try self.allocator.alloc(?[]State, slots.len);
            defer self.allocator.free(pending);
            @memset(pending, null);
            errdefer for (pending) |states| if (states) |owned| {
                self.allocator.free(owned);
            };
            for (slots, pending) |slot, *replacement| {
                if (slot.weighted_outliers.len == self.outlier_count) continue;
                if (slot.weighted_outliers.len != 0) {
                    return error.InvalidChannelOptions;
                }
                const states = try self.allocator.alloc(
                    State,
                    self.outlier_count,
                );
                @memset(states, .{});
                replacement.* = states;
            }
            for (slots, pending) |*slot, replacement| {
                if (replacement) |states| slot.weighted_outliers = states;
                for (slot.weighted_outliers) |*state| state.enabled = false;
                self.markOutlierMembership(self.root, slot);
            }
            self.updateEjectedSlots(slots);
        }

        fn markOutlierMembership(
            self: *Self,
            node: *Node,
            slot: *Slot,
        ) void {
            if (!pathMatches(
                slot.endpoint.hierarchicalPath(),
                node.path,
            )) return;
            switch (node.kind) {
                .leaf => {},
                .weighted => |children| for (children) |child| {
                    self.markOutlierMembership(child.node, slot);
                },
                .priority => |priority| for (priority.children) |child| {
                    self.markOutlierMembership(child.node, slot);
                },
                .outlier => |wrapper| {
                    slot.weighted_outliers[wrapper.index].enabled = true;
                    self.markOutlierMembership(wrapper.child, slot);
                },
            }
        }

        fn updateEjectedSlots(self: *Self, slots: []Slot) void {
            for (slots) |*slot| {
                slot.weighted_target_ejected = outlier_support.ejected(
                    self.root,
                    slot,
                );
            }
        }

        fn slotReady(slot: *Slot) bool {
            if (slot.disabled or slot.weighted_target_ejected) return false;
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
    const leaf = service_config.LoadBalancingNode{ .round_robin = {} };
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
    const outlier_leaf = service_config.LoadBalancingNode{
        .outlier_detection = .{
            .config = .{},
            .child = &leaf,
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
        .{ .name = "outlier", .weight = 6, .child = &outlier_leaf },
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

        pub fn isReusable(self: *@This()) bool {
            return self.ready;
        }
    };
    const FakeTarget = struct {
        address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1) },
        host: []const u8 = "localhost",
        port: u16 = 1,
        ring_hash_key: ?[]const u8 = null,
        ring_hash_weight: u32 = 1,
        hierarchical_path: []const []const u8 = &.{},
    };
    const FakeEndpoint = union(enum) {
        cleartext_ip: FakeTarget,
        cleartext_host: FakeTarget,
        tls_host: FakeTarget,
        tls_address: FakeTarget,
        custom: FakeTarget,

        pub fn hierarchicalPath(self: *const @This()) []const []const u8 {
            return switch (self.*) {
                inline else => |target| target.hierarchical_path,
            };
        }
    };
    const FakeWeightedOutlier = struct {
        endpoint: outlier_detection.Endpoint = .{},
        enabled: bool = false,
    };
    const FakeSlot = struct {
        endpoint: FakeEndpoint,
        connection: ?FakeConnection = .{},
        disabled: bool = false,
        next_attempt_at_ns: ?i96 = null,
        outstanding_requests: usize = 0,
        least_request_enabled: bool = false,
        weighted_target_ejected: bool = false,
        weighted_outliers: []FakeWeightedOutlier = &.{},
        wrr_weight: weighted_round_robin.Weight = .{},
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
            .endpoint = .{ .custom = .{ .hierarchical_path = &least_path } },
            .outstanding_requests = 100,
        },
        .{ .endpoint = .{ .custom = .{ .hierarchical_path = &least_path } } },
        .{ .endpoint = .{ .custom = .{ .hierarchical_path = &sibling_path } } },
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

test "ordinary weighted target outlier membership is allocation transactional" {
    const FakeTarget = struct {
        address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1) },
        host: []const u8 = "localhost",
        port: u16 = 1,
        ring_hash_key: ?[]const u8 = null,
        ring_hash_weight: u32 = 1,
        hierarchical_path: []const []const u8 = &.{},
    };
    const FakeEndpoint = union(enum) {
        cleartext_ip: FakeTarget,
        cleartext_host: FakeTarget,
        tls_host: FakeTarget,
        tls_address: FakeTarget,
        custom: FakeTarget,

        pub fn hierarchicalPath(self: *const @This()) []const []const u8 {
            return switch (self.*) {
                inline else => |target| target.hierarchical_path,
            };
        }
    };
    const FakeState = struct {
        endpoint: outlier_detection.Endpoint = .{},
        enabled: bool = false,
    };
    const FakeSlot = struct {
        endpoint: FakeEndpoint,
        least_request_enabled: bool = false,
        weighted_target_ejected: bool = false,
        weighted_outliers: []FakeState = &.{},
        wrr_weight: weighted_round_robin.Weight = .{},
    };
    const leaf = service_config.LoadBalancingNode{ .round_robin = {} };
    const nested_wrapper = service_config.LoadBalancingNode{
        .outlier_detection = .{ .config = .{}, .child = &leaf },
    };
    const a_wrapper = service_config.LoadBalancingNode{
        .outlier_detection = .{
            .config = .{},
            .child = &nested_wrapper,
        },
    };
    const b_wrapper = service_config.LoadBalancingNode{
        .outlier_detection = .{ .config = .{}, .child = &leaf },
    };
    const targets = [_]service_config.WeightedTargetConfig.Target{
        .{ .name = "a", .weight = 1, .child = &a_wrapper },
        .{ .name = "b", .weight = 1, .child = &b_wrapper },
    };
    const root = service_config.LoadBalancingNode{ .weighted_target = .{
        .targets = &targets,
    } };
    const a_path = [_][]const u8{"a"};
    const b_path = [_][]const u8{"b"};
    const Harness = struct {
        fn run(
            allocator: std.mem.Allocator,
            config: *const service_config.LoadBalancingNode,
            first_path: []const []const u8,
            second_path: []const []const u8,
        ) !void {
            var slots = [_]FakeSlot{
                .{ .endpoint = .{ .custom = .{ .hierarchical_path = first_path } } },
                .{ .endpoint = .{ .custom = .{ .hierarchical_path = second_path } } },
            };
            defer for (&slots) |*slot| if (slot.weighted_outliers.len != 0) {
                allocator.free(slot.weighted_outliers);
            };
            var runtime = try Runtime(FakeSlot).init(allocator, config);
            defer runtime.deinit();
            try runtime.configureSlots(&slots);
            try std.testing.expectEqual(@as(usize, 3), slots[0].weighted_outliers.len);
            try std.testing.expectEqual(@as(usize, 3), slots[1].weighted_outliers.len);
            try std.testing.expect(slots[0].weighted_outliers[0].enabled);
            try std.testing.expect(slots[0].weighted_outliers[1].enabled);
            try std.testing.expect(!slots[0].weighted_outliers[2].enabled);
            try std.testing.expect(!slots[1].weighted_outliers[0].enabled);
            try std.testing.expect(!slots[1].weighted_outliers[1].enabled);
            try std.testing.expect(slots[1].weighted_outliers[2].enabled);
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{ &root, &a_path, &b_path },
    );
}

test "ordinary priority honors ignoreReresolutionRequests" {
    const FakeSlot = struct {};
    const leaf = service_config.LoadBalancingNode{ .round_robin = {} };
    const inner_children = [_]service_config.PriorityConfig.Child{
        .{ .name = "a", .child = &leaf, .ignore_reresolution_requests = true },
        .{ .name = "b", .child = &leaf },
    };
    const inner_priorities = [_][]const u8{ "a", "b" };
    const inner = service_config.LoadBalancingNode{ .priority = .{
        .children = &inner_children,
        .priorities = &inner_priorities,
    } };
    const outer_children = [_]service_config.PriorityConfig.Child{
        .{ .name = "high", .child = &inner, .ignore_reresolution_requests = true },
        .{ .name = "low", .child = &leaf },
    };
    const outer_priorities = [_][]const u8{ "high", "low" };
    const outer = service_config.LoadBalancingNode{ .priority = .{
        .children = &outer_children,
        .priorities = &outer_priorities,
    } };
    var runtime = try Runtime(FakeSlot).init(std.testing.allocator, &outer);
    defer runtime.deinit();
    try std.testing.expect(runtime.ignoresReresolution(&.{"high"}));
    try std.testing.expect(runtime.ignoresReresolution(&.{ "high", "b" }));
    try std.testing.expect(!runtime.ignoresReresolution(&.{"low"}));
    var inner_runtime = try Runtime(FakeSlot).init(std.testing.allocator, &inner);
    defer inner_runtime.deinit();
    try std.testing.expect(inner_runtime.ignoresReresolution(&.{"a"}));
    try std.testing.expect(!inner_runtime.ignoresReresolution(&.{"b"}));
}

//! Recursive grpc-core weighted_target runtime for SharedChannel.
//!
//! The first runtime slice supports nested weighted targets with pick-first and
//! round-robin leaves. Unsupported parsed leaves fail initialization instead
//! of flattening into a different policy.
const std = @import("std");
const service_config = @import("../../service_config.zig");
const connectivity = @import("../connectivity.zig");
const least_request = @import("../least_request.zig");
const ring_hash = @import("../ring_hash.zig");
const ring_support = @import("weighted_target/ring_hash.zig");
const weighted_round_robin = @import("../weighted_round_robin.zig");
const wrr_support = @import("weighted_target/weighted_round_robin.zig");
const orca_config = @import("orca/config.zig");

pub fn Runtime(comptime State: type) type {
    return struct {
        allocator: std.mem.Allocator,
        root: *Node,

        const Self = @This();
        const Worker = State.Worker;
        const BuildError = std.mem.Allocator.Error || error{
            InvalidSharedOptions,
        };
        const PickError = BuildError || error{MissingRequestHash};

        const Leaf = struct {
            policy: enum { pick_first, round_robin, least_request, ring_hash, weighted_round_robin },
            least_request_config: least_request.Config = .{},
            ring_hash_config: ring_hash.Config = .{},
            ring: ring_hash.Ring = .{},
            ring_dirty: bool = true,
            wrr_config: service_config.WeightedRoundRobinConfig = .{},
            wrr_scheduler: weighted_round_robin.Scheduler = .{},
            wrr_sequence: u32 = 0,
            wrr_oob: ?orca_config.Config = null,
            selected: ?*Worker = null,
            next_pick: usize = 0,
        };

        const Child = struct {
            weight: u32,
            node: *Node,
        };

        const Weighted = struct {
            children: []Child,
        };

        const Node = struct {
            path: []const []const u8,
            kind: union(enum) {
                leaf: Leaf,
                weighted: Weighted,
            },
        };

        pub fn init(
            allocator: std.mem.Allocator,
            root_config: *const service_config.LoadBalancingNode,
        ) BuildError!Self {
            var self = Self{
                .allocator = allocator,
                .root = undefined,
            };
            self.root = try self.build(root_config, &.{});
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.destroy(self.root);
            self.* = undefined;
        }

        pub fn aggregate(self: *Self, state: *State) connectivity.State {
            return self.aggregateNode(self.root, state);
        }

        pub fn pick(self: *Self, state: *State, job: anytype) PickError!?*Worker {
            return self.pickNode(self.root, state, job);
        }

        pub fn commit(self: *Self, state: *State, worker: *Worker) void {
            self.commitNode(self.root, state, worker);
        }

        pub fn finishOutstanding(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) void {
            self.finishOutstandingNode(self.root, state, worker);
        }

        pub fn remove(self: *Self, worker: *Worker) void {
            self.removeNode(self.root, worker);
        }

        pub fn invalidateRings(self: *Self) void {
            self.invalidateNodeRings(self.root);
        }

        pub fn usesRing(self: *Self, path: []const []const u8) bool {
            return self.pathUsesRing(self.root, path);
        }

        pub fn wrrConfig(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) ?service_config.WeightedRoundRobinConfig {
            return wrr_support.config(self.root, state, worker);
        }

        pub fn disconnectWrr(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) void {
            wrr_support.disconnect(self.root, state, worker);
        }

        pub fn orcaConfig(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) ?*orca_config.Config {
            return wrr_support.orcaConfig(self.root, state, worker);
        }

        pub fn hasOob(self: *Self) bool {
            return wrr_support.hasOob(self.root);
        }

        pub fn available(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) bool {
            _ = self;
            return workerAvailable(state, worker);
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
                else => error.InvalidSharedOptions,
            };
        }

        fn buildLeaf(
            self: *Self,
            path: []const []const u8,
            policy: @FieldType(Leaf, "policy"),
        ) BuildError!*Node {
            const owned_path = try self.allocator.dupe([]const u8, path);
            errdefer self.allocator.free(owned_path);
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
            node.kind.leaf.ring_hash_config = config;
            return node;
        }

        fn buildWrr(
            self: *Self,
            path: []const []const u8,
            config: service_config.WeightedRoundRobinConfig,
        ) BuildError!*Node {
            const node = try self.buildLeaf(path, .weighted_round_robin);
            errdefer self.destroy(node);
            node.kind.leaf.wrr_config = config;
            if (config.enable_oob_load_report) {
                node.kind.leaf.wrr_oob = orca_config.Config.init(
                    self.allocator,
                    .{ .report_interval = config.oob_reporting_period },
                ) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.InvalidSharedOptions,
                };
            }
            return node;
        }

        fn buildWeighted(
            self: *Self,
            config: service_config.WeightedTargetConfig,
            path: []const []const u8,
        ) BuildError!*Node {
            const owned_path = try self.allocator.dupe([]const u8, path);
            errdefer self.allocator.free(owned_path);
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
                .kind = .{ .weighted = .{ .children = children } },
            };
            return node;
        }

        fn destroy(self: *Self, node: *Node) void {
            switch (node.kind) {
                .leaf => |*leaf| {
                    leaf.ring.deinit(self.allocator);
                    leaf.wrr_scheduler.deinit(self.allocator);
                    if (leaf.wrr_oob) |*config| config.deinit();
                },
                .weighted => |weighted| {
                    for (weighted.children) |child| self.destroy(child.node);
                    self.allocator.free(weighted.children);
                },
            }
            self.allocator.free(node.path);
            self.allocator.destroy(node);
        }

        fn aggregateNode(
            self: *Self,
            node: *Node,
            state: *State,
        ) connectivity.State {
            return switch (node.kind) {
                .leaf => self.aggregateLeaf(node, state),
                .weighted => |weighted| blk: {
                    var connecting = false;
                    var idle = false;
                    for (weighted.children) |child| {
                        switch (self.aggregateNode(child.node, state)) {
                            .ready => break :blk .ready,
                            .connecting => connecting = true,
                            .idle => idle = true,
                            .transient_failure, .shutdown => {},
                        }
                    }
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
            self: *Self,
            node: *Node,
            state: *State,
        ) connectivity.State {
            _ = self;
            var connecting = false;
            var idle = false;
            for (state.workers.items) |worker| {
                if (!workerMatches(state, worker, node.path) or
                    worker.retired or !worker.eligible)
                {
                    continue;
                }
                switch (worker.published) {
                    .ready => return .ready,
                    .connecting => connecting = true,
                    .idle => idle = true,
                    .transient_failure, .shutdown => {},
                }
            }
            for (state.sources) |source| {
                if (!pathMatches(source.endpoint.hierarchicalPath(), node.path)) {
                    continue;
                }
                if (source.resolver != null and source.generation == 0) {
                    connecting = true;
                }
            }
            return if (connecting)
                .connecting
            else if (idle)
                .idle
            else
                .transient_failure;
        }

        fn pickNode(
            self: *Self,
            node: *Node,
            state: *State,
            job: anytype,
        ) PickError!?*Worker {
            return switch (node.kind) {
                .leaf => |*leaf| self.pickLeaf(node, leaf, state, job),
                .weighted => |weighted| blk: {
                    var total: u64 = 0;
                    for (weighted.children) |child| {
                        if (self.aggregateNode(child.node, state) != .ready) {
                            continue;
                        }
                        total += child.weight;
                    }
                    if (total == 0) break :blk null;
                    var seed: u64 = undefined;
                    state.io.random(std.mem.asBytes(&seed));
                    var random = std.Random.DefaultPrng.init(seed);
                    var selected = random.random().uintLessThan(u64, total);
                    for (weighted.children) |child| {
                        if (self.aggregateNode(child.node, state) != .ready) {
                            continue;
                        }
                        if (selected < child.weight) {
                            break :blk try self.pickNode(
                                child.node,
                                state,
                                job,
                            );
                        }
                        selected -= child.weight;
                    }
                    unreachable;
                },
            };
        }

        fn pickLeaf(
            self: *Self,
            node: *Node,
            leaf: *Leaf,
            state: *State,
            job: anytype,
        ) PickError!?*Worker {
            if (leaf.policy == .pick_first) {
                if (leaf.selected) |selected| {
                    if (workerMatches(state, selected, node.path) and
                        workerAvailable(state, selected)) return selected;
                    leaf.selected = null;
                }
            }
            if (leaf.policy == .least_request) {
                return pickLeastRequest(node, leaf, state);
            }
            if (leaf.policy == .ring_hash) {
                return try self.pickRingHash(node, leaf, state, job);
            }
            if (leaf.policy == .weighted_round_robin) {
                if (try self.pickWrr(node, leaf, state)) |worker| {
                    return worker;
                }
            }
            var count: usize = 0;
            for (state.workers.items) |worker| {
                if (workerMatches(state, worker, node.path)) count += 1;
            }
            if (count == 0) return null;
            for (0..count) |offset| {
                const wanted = if (leaf.policy == .round_robin or
                    leaf.policy == .weighted_round_robin)
                    (leaf.next_pick + offset) % count
                else
                    offset;
                var ordinal: usize = 0;
                for (state.workers.items) |worker| {
                    if (!workerMatches(state, worker, node.path)) continue;
                    if (ordinal == wanted) {
                        if (!workerAvailable(state, worker)) break;
                        if (leaf.policy == .pick_first) leaf.selected = worker;
                        return worker;
                    }
                    ordinal += 1;
                }
            }
            return null;
        }

        fn commitNode(
            self: *Self,
            node: *Node,
            state: *State,
            worker: *Worker,
        ) void {
            switch (node.kind) {
                .leaf => |*leaf| {
                    if (leaf.policy == .least_request) {
                        worker.outstanding_requests += 1;
                        return;
                    }
                    if (leaf.policy != .round_robin and
                        leaf.policy != .weighted_round_robin) return;
                    var ordinal: usize = 0;
                    var count: usize = 0;
                    for (state.workers.items) |member| {
                        if (!workerMatches(state, member, node.path)) continue;
                        if (member == worker) ordinal = count;
                        count += 1;
                    }
                    if (count != 0) leaf.next_pick = (ordinal + 1) % count;
                },
                .weighted => |weighted| {
                    for (weighted.children) |child| {
                        if (!pathMatches(
                            state.sources[worker.source_index]
                                .endpoint.hierarchicalPath(),
                            child.node.path,
                        )) continue;
                        self.commitNode(child.node, state, worker);
                        return;
                    }
                },
            }
        }

        fn finishOutstandingNode(
            self: *Self,
            node: *Node,
            state: *State,
            worker: *Worker,
        ) void {
            switch (node.kind) {
                .leaf => |leaf| {
                    if (leaf.policy != .least_request) return;
                    std.debug.assert(worker.outstanding_requests != 0);
                    worker.outstanding_requests -= 1;
                },
                .weighted => |weighted| {
                    for (weighted.children) |child| {
                        if (!pathMatches(
                            state.sources[worker.source_index]
                                .endpoint.hierarchicalPath(),
                            child.node.path,
                        )) continue;
                        self.finishOutstandingNode(
                            child.node,
                            state,
                            worker,
                        );
                        return;
                    }
                },
            }
        }

        fn removeNode(self: *Self, node: *Node, worker: *Worker) void {
            switch (node.kind) {
                .leaf => |*leaf| {
                    if (leaf.selected == worker) leaf.selected = null;
                    leaf.wrr_scheduler.remove(worker);
                },
                .weighted => |weighted| {
                    for (weighted.children) |child| {
                        self.removeNode(child.node, worker);
                    }
                },
            }
        }

        fn pickLeastRequest(
            node: *Node,
            leaf: *const Leaf,
            state: *State,
        ) ?*Worker {
            var available_count: usize = 0;
            for (state.workers.items) |worker| {
                if (workerMatches(state, worker, node.path) and
                    workerAvailable(state, worker))
                {
                    available_count += 1;
                }
            }
            if (available_count == 0) return null;
            var seed: u64 = undefined;
            state.io.random(std.mem.asBytes(&seed));
            var prng = std.Random.DefaultPrng.init(seed);
            const random = prng.random();
            var selected: ?*Worker = null;
            for (0..leaf.least_request_config.choice_count) |_| {
                var ordinal = random.uintLessThan(usize, available_count);
                const sampled = for (state.workers.items) |worker| {
                    if (!workerMatches(state, worker, node.path) or
                        !workerAvailable(state, worker))
                    {
                        continue;
                    }
                    if (ordinal == 0) break worker;
                    ordinal -= 1;
                } else unreachable;
                if (selected == null or
                    sampled.outstanding_requests <
                        selected.?.outstanding_requests)
                {
                    selected = sampled;
                }
            }
            return selected;
        }

        fn pickRingHash(
            self: *Self,
            node: *Node,
            leaf: *Leaf,
            state: *State,
            job: anytype,
        ) PickError!?*Worker {
            return ring_support.pick(
                self.allocator,
                self,
                node,
                leaf,
                state,
                job,
            );
        }

        fn pickWrr(
            self: *Self,
            node: *Node,
            leaf: *Leaf,
            state: *State,
        ) std.mem.Allocator.Error!?*Worker {
            return wrr_support.pick(self.allocator, node, leaf, state);
        }

        fn invalidateNodeRings(self: *Self, node: *Node) void {
            switch (node.kind) {
                .leaf => |*leaf| if (leaf.policy == .ring_hash) {
                    leaf.ring_dirty = true;
                },
                .weighted => |weighted| for (weighted.children) |child| {
                    self.invalidateNodeRings(child.node);
                },
            }
        }

        fn pathUsesRing(
            self: *Self,
            node: *Node,
            path: []const []const u8,
        ) bool {
            if (!pathMatches(path, node.path)) return false;
            return switch (node.kind) {
                .leaf => |leaf| leaf.policy == .ring_hash,
                .weighted => |weighted| for (weighted.children) |child| {
                    if (pathMatches(path, child.node.path)) {
                        return self.pathUsesRing(child.node, path);
                    }
                } else false,
            };
        }

        fn workerMatches(
            state: *State,
            worker: *Worker,
            path: []const []const u8,
        ) bool {
            return pathMatches(
                state.sources[worker.source_index]
                    .endpoint.hierarchicalPath(),
                path,
            );
        }

        fn workerAvailable(state: *State, worker: *Worker) bool {
            _ = state;
            return worker.eligible and !worker.retired and
                worker.published == .ready and worker.capacity != 0;
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
    };
}

test "SharedChannel weighted target runtime construction is transactional" {
    const FakeState = struct {
        const Worker = struct {};
    };
    const leaf = service_config.LoadBalancingNode.round_robin;
    const nested_targets = [_]service_config.WeightedTargetConfig.Target{.{
        .name = "inner",
        .weight = 2,
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
        fn run(allocator: std.mem.Allocator, config: *const service_config.LoadBalancingNode) !void {
            var runtime = try Runtime(FakeState).init(allocator, config);
            runtime.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{&root},
    );
}

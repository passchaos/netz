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
const outlier_support = @import("weighted_target/outlier.zig");

pub fn Runtime(comptime State: type) type {
    return struct {
        allocator: std.mem.Allocator,
        root: *Node,
        outlier_count: usize = 0,
        priority_failover_timeout_ns: i96 = 10 * std.time.ns_per_s,

        const Self = @This();
        const Worker = State.Worker;
        const BuildError = std.mem.Allocator.Error || error{
            InvalidSharedOptions,
        };
        const PickError = BuildError || error{MissingRequestHash};

        const Leaf = struct {
            policy: enum { pick_first, round_robin, least_request, ring_hash, weighted_round_robin },
            shuffle_address_list: bool = false,
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

        const Outlier = struct {
            config: service_config.OutlierDetectionConfig,
            index: usize,
            next_evaluation_ns: i96 = 0,
            child: *Node,
        };

        const PriorityChild = struct {
            ignore_reresolution_requests: bool,
            node: *Node,
            /// Once grpc-core reaches a priority it keeps that child alive and
            /// retrying even when a lower priority becomes current.
            activated: bool = false,
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
            refs: std.atomic.Value(usize) = .init(1),
            path: []const []const u8,
            kind: union(enum) {
                leaf: Leaf,
                weighted: Weighted,
                priority: Priority,
                outlier: Outlier,
            },
        };

        pub fn init(
            allocator: std.mem.Allocator,
            root_config: *const service_config.LoadBalancingNode,
        ) BuildError!Self {
            return initWithPriorityFailoverTimeout(
                allocator,
                root_config,
                10 * std.time.ns_per_s,
            );
        }

        pub fn initWithPriorityFailoverTimeout(
            allocator: std.mem.Allocator,
            root_config: *const service_config.LoadBalancingNode,
            priority_failover_timeout_ns: i96,
        ) BuildError!Self {
            var self = Self{
                .allocator = allocator,
                .root = undefined,
                .priority_failover_timeout_ns = priority_failover_timeout_ns,
            };
            self.root = try self.build(root_config, &.{});
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.destroy(self.root);
            self.* = undefined;
        }
        pub fn retainNode(node: *Node) void {
            _ = node.refs.fetchAdd(1, .monotonic);
        }
        pub fn releaseNode(allocator: std.mem.Allocator, node: *Node) void {
            var owner = Self{ .allocator = allocator, .root = node };
            owner.destroy(node);
        }
        pub fn acceptsPath(self: *const Self, path: []const []const u8) bool {
            return @import("../tree_query.zig").accepts(self.root, path);
        }

        pub fn ignoresReresolution(self: *const Self, path: []const []const u8) bool {
            return @import("../tree_query.zig").ignoresReresolution(self.root, path);
        }

        pub fn shufflesAddressList(self: *const Self, path: []const []const u8) bool {
            return @import("../tree_query.zig").shufflesAddressList(self.root, path);
        }

        /// Whether the endpoint path belongs to the priority slice that should
        /// currently be connected. `wake_at` receives the failover deadline
        /// when the path is waiting for a higher priority's timer.
        pub fn pathActive(
            self: *Self,
            state: *State,
            path: []const []const u8,
            wake_at: *?i96,
        ) bool {
            return self.pathActiveNode(self.root, state, path, wake_at);
        }

        const PriorityState = struct {
            active_index: ?usize,
            wake_at: ?i96,
            failover_open: bool,
        };

        fn evaluatePriority(
            self: *Self,
            priority: *Priority,
            state: *State,
        ) PriorityState {
            if (priority.order.len == 0) {
                return .{ .active_index = null, .wake_at = null, .failover_open = true };
            }
            const now = std.Io.Clock.awake.now(state.io).nanoseconds;
            const first = priority.children[priority.order[0]];
            const first_state = self.aggregateNode(first.node, state);
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
                .transient_failure, .shutdown => {
                    priority.failover_started_ns = null;
                    priority.failover_can_start = false;
                },
            }
            if (first_state == .ready or first_state == .idle) {
                activatePriority(priority, 0);
                return .{ .active_index = 0, .wake_at = null, .failover_open = false };
            }
            if (first_state == .connecting) {
                if (priority.failover_started_ns) |started| {
                    const deadline = started +| self.priority_failover_timeout_ns;
                    if (self.priority_failover_timeout_ns > 0 and now < deadline) {
                        activatePriority(priority, 0);
                        return .{
                            .active_index = 0,
                            .wake_at = deadline,
                            .failover_open = false,
                        };
                    }
                }
            }
            // The first priority failed or its timer expired. Select the next
            // priority that is not in TRANSIENT_FAILURE; otherwise delegate to
            // the last priority so it can retry.
            var index = priority.order.len - 1;
            for (priority.order[1..], 1..) |child_index, ordinal| {
                const child = priority.children[child_index];
                if (self.aggregateNode(child.node, state) != .transient_failure) {
                    index = ordinal;
                    break;
                }
            }
            activatePriority(priority, index);
            return .{ .active_index = index, .wake_at = null, .failover_open = true };
        }

        fn activatePriority(priority: *Priority, index: usize) void {
            for (priority.order[0 .. index + 1]) |child_index| {
                priority.children[child_index].activated = true;
            }
        }

        fn pathActiveNode(
            self: *Self,
            node: *Node,
            state: *State,
            path: []const []const u8,
            wake_at: *?i96,
        ) bool {
            if (!pathMatches(path, node.path)) return false;
            return switch (node.kind) {
                .leaf => true,
                .outlier => |wrapper| self.pathActiveNode(wrapper.child, state, path, wake_at),
                .weighted => |weighted| for (weighted.children) |child| {
                    if (self.pathActiveNode(child.node, state, path, wake_at)) break true;
                } else false,
                .priority => |*priority| blk: {
                    const info = self.evaluatePriority(priority, state);
                    for (priority.order) |child_index| {
                        const child = priority.children[child_index];
                        if (!pathMatches(path, child.node.path)) continue;
                        if (child.activated) {
                            break :blk self.pathActiveNode(child.node, state, path, wake_at);
                        }
                        if (info.wake_at) |deadline| {
                            wake_at.* = if (wake_at.*) |current|
                                @min(current, deadline)
                            else
                                deadline;
                        }
                        break :blk false;
                    }
                    break :blk false;
                },
            };
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
        pub fn removeFromNode(node: *Node, worker: *Worker) void {
            var owner = Self{ .allocator = undefined, .root = node };
            owner.removeNode(node, worker);
        }

        pub fn invalidatePickers(self: *Self) void {
            self.invalidateNodePickers(self.root);
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
        pub fn orcaForPath(self: *Self, path: []const []const u8) ?*orca_config.Config {
            return wrr_support.orcaForPath(self.root, path);
        }

        pub fn hasOob(self: *Self) bool {
            return wrr_support.hasOob(self.root);
        }

        pub fn outlierCount(self: *const Self) usize {
            return self.outlier_count;
        }

        pub fn available(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) bool {
            return self.workerAvailable(state, worker);
        }

        pub fn evaluateOutliers(self: *Self, state: *State) bool {
            return outlier_support.evaluate(
                self,
                self.root,
                state,
                std.Io.Clock.awake.now(state.io).nanoseconds,
            );
        }

        pub fn nextOutlierDeadline(self: *Self) ?i96 {
            return outlier_support.nextDeadline(self.root);
        }

        pub fn recordOutlier(
            self: *Self,
            state: *State,
            worker: *Worker,
            success: bool,
        ) void {
            outlier_support.record(self.root, state, worker, success);
        }

        pub fn workerEjected(
            self: *Self,
            state: *State,
            worker: *Worker,
        ) bool {
            return outlier_support.ejected(self.root, state, worker);
        }

        fn build(
            self: *Self,
            config: *const service_config.LoadBalancingNode,
            path: []const []const u8,
        ) BuildError!*Node {
            return switch (config.*) {
                .pick_first => |config_value| blk: {
                    const node = try self.buildLeaf(path, .pick_first);
                    node.kind.leaf.shuffle_address_list =
                        config_value.shuffle_address_list;
                    break :blk node;
                },
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

        fn buildPriority(
            self: *Self,
            config: service_config.PriorityConfig,
            path: []const []const u8,
        ) BuildError!*Node {
            const owned_path = try self.allocator.dupe([]const u8, path);
            errdefer self.allocator.free(owned_path);
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
                slot.* = found orelse return error.InvalidSharedOptions;
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
            wrapper: @FieldType(service_config.LoadBalancingNode, "outlier_detection"),
            path: []const []const u8,
        ) BuildError!*Node {
            const index = self.outlier_count;
            self.outlier_count += 1;
            const owned_path = try self.allocator.dupe([]const u8, path);
            errdefer self.allocator.free(owned_path);
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
            if (node.refs.fetchSub(1, .acq_rel) != 1) return;
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
                .priority => |priority| {
                    for (priority.children) |child| self.destroy(child.node);
                    self.allocator.free(priority.children);
                    self.allocator.free(priority.order);
                },
                .outlier => |wrapper| self.destroy(wrapper.child),
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
                .priority => |priority| blk: {
                    var connecting = false;
                    var idle = false;
                    for (priority.children) |child| {
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
                .outlier => |wrapper| self.aggregateNode(
                    wrapper.child,
                    state,
                ),
            };
        }

        fn aggregateLeaf(
            self: *Self,
            node: *Node,
            state: *State,
        ) connectivity.State {
            var connecting = false;
            var idle = false;
            for (state.workers.items) |worker| {
                if (!workerMatches(state, worker, node.path) or
                    worker.retired or worker.source.suspended or !worker.eligible)
                {
                    continue;
                }
                switch (worker.published) {
                    .ready => if (!self.workerEjected(state, worker)) {
                        return .ready;
                    },
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
                .priority => |*priority| blk: {
                    const info = self.evaluatePriority(priority, state);
                    const active_index = info.active_index orelse break :blk null;
                    if (!info.failover_open) {
                        const first = priority.children[priority.order[active_index]];
                        if (self.aggregateNode(first.node, state) == .ready) {
                            break :blk try self.pickNode(
                                first.node,
                                state,
                                job,
                            );
                        }
                        break :blk null;
                    }
                    for (priority.order) |child_index| {
                        const child = priority.children[child_index];
                        if (self.aggregateNode(child.node, state) == .ready) {
                            break :blk try self.pickNode(
                                child.node,
                                state,
                                job,
                            );
                        }
                    }
                    break :blk null;
                },
                .outlier => |wrapper| try self.pickNode(
                    wrapper.child,
                    state,
                    job,
                ),
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
                        self.workerAvailable(state, selected)) return selected;
                    leaf.selected = null;
                }
            }
            if (leaf.policy == .least_request) {
                return self.pickLeastRequest(node, leaf, state);
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
                        if (!self.workerAvailable(state, worker)) break;
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
                            worker.source
                                .endpoint.hierarchicalPath(),
                            child.node.path,
                        )) continue;
                        self.commitNode(child.node, state, worker);
                        return;
                    }
                },
                .priority => |priority| {
                    for (priority.children) |child| {
                        if (!pathMatches(
                            worker.source
                                .endpoint.hierarchicalPath(),
                            child.node.path,
                        )) continue;
                        self.commitNode(child.node, state, worker);
                        return;
                    }
                },
                .outlier => |wrapper| self.commitNode(
                    wrapper.child,
                    state,
                    worker,
                ),
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
                            worker.source
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
                .outlier => |wrapper| self.finishOutstandingNode(
                    wrapper.child,
                    state,
                    worker,
                ),
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
                .priority => |priority| {
                    for (priority.children) |child| {
                        self.removeNode(child.node, worker);
                    }
                },
                .outlier => |wrapper| self.removeNode(wrapper.child, worker),
            }
        }

        fn pickLeastRequest(
            self: *Self,
            node: *Node,
            leaf: *const Leaf,
            state: *State,
        ) ?*Worker {
            var available_count: usize = 0;
            for (state.workers.items) |worker| {
                if (workerMatches(state, worker, node.path) and
                    self.workerAvailable(state, worker))
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
                        !self.workerAvailable(state, worker))
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
            return wrr_support.pick(
                self.allocator,
                self,
                node,
                leaf,
                state,
            );
        }

        fn invalidateNodePickers(self: *Self, node: *Node) void {
            switch (node.kind) {
                .leaf => |*leaf| if (leaf.policy == .ring_hash) {
                    leaf.ring_dirty = true;
                } else if (leaf.policy == .weighted_round_robin) {
                    leaf.wrr_scheduler.next_update_ns = 0;
                },
                .weighted => |weighted| for (weighted.children) |child| {
                    self.invalidateNodePickers(child.node);
                },
                .priority => |priority| for (priority.children) |child| {
                    self.invalidateNodePickers(child.node);
                },
                .outlier => |wrapper| self.invalidateNodePickers(wrapper.child),
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
                .priority => |priority| for (priority.children) |child| {
                    if (pathMatches(path, child.node.path)) {
                        return self.pathUsesRing(child.node, path);
                    }
                } else false,
                .outlier => |wrapper| self.pathUsesRing(wrapper.child, path),
            };
        }

        fn workerMatches(
            state: *State,
            worker: *Worker,
            path: []const []const u8,
        ) bool {
            _ = state;
            return pathMatches(
                worker.source
                    .endpoint.hierarchicalPath(),
                path,
            );
        }

        fn workerAvailable(self: *Self, state: *State, worker: *Worker) bool {
            return worker.eligible and !worker.retired and !worker.source.suspended and
                worker.published == .ready and worker.capacity != 0 and
                !self.workerEjected(state, worker);
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
    const leaf = service_config.LoadBalancingNode{ .round_robin = {} };
    const nested_targets = [_]service_config.WeightedTargetConfig.Target{.{
        .name = "inner",
        .weight = 2,
        .child = &leaf,
    }};
    const nested = service_config.LoadBalancingNode{ .weighted_target = .{
        .targets = &nested_targets,
    } };
    const wrapped = service_config.LoadBalancingNode{ .outlier_detection = .{
        .config = .{ .failure_percentage_ejection = .{} },
        .child = &nested,
    } };
    const targets = [_]service_config.WeightedTargetConfig.Target{
        .{ .name = "a", .weight = 1, .child = &leaf },
        .{ .name = "b", .weight = 3, .child = &wrapped },
    };
    const root = service_config.LoadBalancingNode{ .weighted_target = .{
        .targets = &targets,
    } };
    const Harness = struct {
        fn run(allocator: std.mem.Allocator, config: *const service_config.LoadBalancingNode) !void {
            var runtime = try Runtime(FakeState).init(allocator, config);
            try std.testing.expectEqual(@as(usize, 1), runtime.outlierCount());
            runtime.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{&root},
    );
}

test "SharedChannel priority honors ignoreReresolutionRequests" {
    const FakeState = struct {
        const Worker = struct {};
    };
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
    var runtime = try Runtime(FakeState).init(std.testing.allocator, &outer);
    defer runtime.deinit();
    try std.testing.expect(runtime.ignoresReresolution(&.{"high"}));
    try std.testing.expect(runtime.ignoresReresolution(&.{ "high", "b" }));
    try std.testing.expect(!runtime.ignoresReresolution(&.{"low"}));
    var inner_runtime = try Runtime(FakeState).init(std.testing.allocator, &inner);
    defer inner_runtime.deinit();
    try std.testing.expect(inner_runtime.ignoresReresolution(&.{"a"}));
    try std.testing.expect(!inner_runtime.ignoresReresolution(&.{"b"}));
}

test "SharedChannel priority propagates nested pick_first shuffleAddressList" {
    const FakeState = struct {
        const Worker = struct {};
    };
    const shuffled_leaf = service_config.LoadBalancingNode{ .pick_first = .{
        .shuffle_address_list = true,
    } };
    const plain_leaf = service_config.LoadBalancingNode{ .pick_first = .{} };
    const inner_children = [_]service_config.PriorityConfig.Child{
        .{ .name = "a", .child = &shuffled_leaf },
        .{ .name = "b", .child = &plain_leaf },
    };
    const inner_priorities = [_][]const u8{ "a", "b" };
    const inner = service_config.LoadBalancingNode{ .priority = .{
        .children = &inner_children,
        .priorities = &inner_priorities,
    } };
    const outer_children = [_]service_config.PriorityConfig.Child{
        .{ .name = "high", .child = &inner },
        .{ .name = "low", .child = &plain_leaf },
    };
    const outer_priorities = [_][]const u8{ "high", "low" };
    const outer = service_config.LoadBalancingNode{ .priority = .{
        .children = &outer_children,
        .priorities = &outer_priorities,
    } };
    var runtime = try Runtime(FakeState).init(std.testing.allocator, &outer);
    defer runtime.deinit();
    try std.testing.expect(runtime.shufflesAddressList(&.{ "high", "a" }));
    try std.testing.expect(!runtime.shufflesAddressList(&.{ "high", "b" }));
    try std.testing.expect(!runtime.shufflesAddressList(&.{"low"}));
}

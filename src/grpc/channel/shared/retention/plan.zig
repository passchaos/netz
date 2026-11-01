//! Stage removed nodes and reactivation before publishing any cache mutation.
const std = @import("std");
const State = @import("../state.zig").State;
const Generation = @import("../config_generation.zig").Generation;
const Transfer = @import("../weighted_target/state_transfer.zig").Plan(State.WeightedTarget);
const query = @import("../../tree_query.zig");
const Manager = @import("manager.zig").Manager;
const Prepared = @import("../update/prepare.zig").Prepared;

pub const Plan = struct {
    state: *State,
    now: i96,
    added: ?*State.Retention.Entry = null,
    added_count: usize = 0,
    used: std.ArrayList(*State.Retention.Entry) = .empty,
    manager: ?*Manager = null,
    committed: bool = false,

    const Node = @typeInfo(@FieldType(State.WeightedTarget, "root")).pointer.child;

    pub fn init(state: *State, next: ?*State.WeightedTarget, transfer: *Transfer) State.Failure!Plan {
        var self = Plan{ .state = state, .now = std.Io.Clock.awake.now(state.io).nanoseconds };
        errdefer self.deinit();
        if (state.weighted_target != null and next != null) {
            try self.collect(state.weighted_target.?.root, next.?.root, state.config.load(.acquire).?, transfer);
        }
        var entry = state.retention.head;
        while (entry) |cached| : (entry = cached.next) {
            if (next == null or state.options.removed_child_retention.nanoseconds == 0 or
                !query.compositeParent(next.?.root, cached.node.path[0 .. cached.node.path.len - 1])) try self.use(cached);
        }
        var reused: usize = 0;
        for (self.used.items) |cached| if (cached.expires_ns > self.now) {
            reused += 1;
        };
        if (state.retention.liveCount(self.now) - reused + self.added_count > state.options.max_retained_children) return error.SharedRetentionFull;
        return self;
    }
    fn use(self: *Plan, entry: *State.Retention.Entry) !void {
        for (self.used.items) |prior| if (prior == entry) return;
        try self.used.append(self.state.allocator, entry);
    }
    fn collect(self: *Plan, old: *Node, next: *Node, generation: *Generation, transfer: *Transfer) State.Failure!void {
        if (!query.equal(old.path, next.path)) return;
        if (old.kind == .outlier) return self.collect(old.kind.outlier.child, if (next.kind == .outlier) next.kind.outlier.child else next, generation, transfer);
        if (next.kind == .outlier) return self.collect(old, next.kind.outlier.child, generation, transfer);
        if (std.meta.activeTag(old.kind) != std.meta.activeTag(next.kind)) return;
        switch (next.kind) {
            .leaf => {},
            .outlier => unreachable,
            .weighted => |weighted| {
                try self.retainRemoved(old.kind.weighted.children, weighted.children, generation);
                try self.reusePresent(old.kind.weighted.children, weighted.children, generation, transfer);
            },
            .priority => |priority| {
                try self.retainRemoved(old.kind.priority.children, priority.children, generation);
                try self.reusePresent(old.kind.priority.children, priority.children, generation, transfer);
            },
        }
    }
    fn retainRemoved(self: *Plan, old_children: anytype, next_children: anytype, generation: *Generation) State.Failure!void {
        for (old_children) |child| {
            const present = for (next_children) |candidate| {
                if (query.equal(child.node.path, candidate.node.path)) break true;
            } else false;
            if (present or self.state.options.removed_child_retention.nanoseconds == 0) continue;
            const entry = try State.Retention.Entry.create(self.state, child.node, generation, self.now);
            entry.next = self.added;
            self.added = entry;
            self.added_count += 1;
        }
    }
    fn reusePresent(self: *Plan, old_children: anytype, next_children: anytype, generation: *Generation, transfer: *Transfer) State.Failure!void {
        for (next_children) |child| {
            const prior = for (old_children) |candidate| {
                if (query.equal(child.node.path, candidate.node.path)) break candidate.node;
            } else null;
            if (prior) |node| {
                try self.collect(node, child.node, generation, transfer);
            } else if (self.state.retention.lookup(child.node.path, self.now)) |cached| {
                try self.use(cached);
                try transfer.collectRetained(cached.node, child.node);
                try self.collect(cached.node, child.node, cached.generation, transfer);
            }
        }
    }
    pub fn deinit(self: *Plan) void {
        if (!self.committed) {
            State.Retention.destroyList(self.added);
            if (self.manager) |manager| {
                manager.aborted.store(true, .release);
                manager.activation.set(self.state.io);
            }
        }
        self.used.deinit(self.state.allocator);
    }
    pub fn holds(self: *Plan, source: *State.Source) bool {
        var entry = self.added;
        while (entry) |cached| : (entry = cached.next) for (cached.sources) |member| {
            if (member == source) return true;
        };
        entry = self.state.retention.head;
        while (entry) |cached| : (entry = cached.next) {
            if (cached.expires_ns <= self.now) continue;
            var consumed = false;
            for (self.used.items) |used| consumed = consumed or used == cached;
            if (consumed) continue;
            for (cached.sources) |member| if (member == source) return true;
        }
        return false;
    }
    pub fn startManager(self: *Plan) State.Failure!void {
        if (self.added == null or self.state.retention.manager_started) return;
        const manager = try self.state.allocator.create(Manager);
        errdefer self.state.allocator.destroy(manager);
        manager.* = .{ .state = self.state };
        try self.state.group.concurrent(self.state.io, Manager.run, .{manager});
        self.manager = manager;
    }
    fn appendGarbage(prepared: *Prepared, head: ?*State.Retention.Entry) void {
        var pending = head;
        while (pending) |entry| {
            pending = entry.next;
            entry.next = prepared.retired_children;
            prepared.retired_children = entry;
        }
    }
    pub fn commit(self: *Plan, prepared: *Prepared) void {
        for (self.used.items) |entry| {
            var link = &self.state.retention.head;
            while (link.*) |cached| {
                if (cached == entry) {
                    link.* = cached.next;
                    self.state.retention.count -= 1;
                    cached.next = null;
                    appendGarbage(prepared, cached);
                    break;
                }
                link = &cached.next;
            }
        }
        while (self.added) |entry| {
            self.added = entry.next;
            entry.next = self.state.retention.head;
            self.state.retention.head = entry;
            self.state.retention.count += 1;
        }
        appendGarbage(prepared, self.state.retention.poll(self.state, self.now));
        if (self.manager) |manager| {
            self.state.retention.manager_started = true;
            manager.activation.set(self.state.io);
            self.manager = null;
        }
        self.state.retention.wake.set(self.state.io);
        self.committed = true;
    }
};

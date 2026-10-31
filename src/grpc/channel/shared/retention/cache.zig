//! Deactivated named children own their old tree, config arena and endpoints.
const std = @import("std");
const Generation = @import("../config_generation.zig").Generation;
const query = @import("../weighted_target/tree_query.zig");
const outliers = @import("../weighted_target/outlier.zig");
const wrr = @import("../weighted_target/weighted_round_robin.zig");
const Config = @import("../../../service_config.zig").WeightedRoundRobinConfig;

pub fn Cache(comptime State: type) type {
    return struct {
        head: ?*Entry = null,
        count: usize = 0,
        manager_started: bool = false,
        wake: std.Io.Event = .unset,

        const Self = @This();
        const Runtime = State.WeightedTarget;
        const Node = @typeInfo(@FieldType(Runtime, "root")).pointer.child;
        pub const Entry = struct {
            allocator: std.mem.Allocator,
            node: *Node,
            generation: *Generation,
            sources: []*State.Source,
            expires_ns: i96,
            next: ?*Entry = null,

            pub fn create(state: *State, node: *Node, generation: *Generation, now: i96) State.Failure!*Entry {
                const allocator = state.allocator;
                var sources: std.ArrayList(*State.Source) = .empty;
                errdefer {
                    for (sources.items) |source| source.release();
                    sources.deinit(allocator);
                }
                for (state.sources) |source| try appendSource(allocator, &sources, source, node.path);
                var cached = state.retention.head;
                while (cached) |entry| : (cached = entry.next) {
                    for (entry.sources) |source| try appendSource(allocator, &sources, source, node.path);
                }
                const entry = try allocator.create(Entry);
                errdefer allocator.destroy(entry);
                const owned = try sources.toOwnedSlice(allocator);
                Runtime.retainNode(node);
                _ = generation.retain();
                entry.* = .{ .allocator = allocator, .node = node, .generation = generation, .sources = owned, .expires_ns = now +| state.options.removed_child_retention.nanoseconds };
                return entry;
            }
            fn appendSource(allocator: std.mem.Allocator, sources: *std.ArrayList(*State.Source), source: *State.Source, path: []const []const u8) !void {
                if (source.retired or !query.matches(source.endpoint.hierarchicalPath(), path)) return;
                for (sources.items) |prior| if (prior == source) return;
                try sources.append(allocator, source);
                source.retain();
            }
            pub fn destroy(self: *Entry) void {
                const allocator = self.allocator;
                Runtime.releaseNode(allocator, self.node);
                self.generation.release();
                for (self.sources) |source| source.release();
                allocator.free(self.sources);
                allocator.destroy(self);
            }
        };

        pub fn destroyList(head: ?*Entry) void {
            var pending = head;
            while (pending) |entry| {
                pending = entry.next;
                entry.destroy();
            }
        }
        pub fn deinit(self: *Self) void {
            destroyList(self.head);
            self.head = null;
            self.count = 0;
        }
        pub fn lookup(self: *Self, path: []const []const u8, now: i96) ?*Entry {
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) {
                if (entry.expires_ns > now and query.equal(entry.node.path, path)) return entry;
            }
            return null;
        }
        pub fn liveCount(self: *Self, now: i96) usize {
            var count: usize = 0;
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) if (entry.expires_ns > now) {
                count += 1;
            };
            return count;
        }
        pub fn entryFor(self: *Self, source: *State.Source, now: i96) ?*Entry {
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) {
                if (entry.expires_ns <= now) continue;
                for (entry.sources) |member| if (member == source) return entry;
            }
            return null;
        }
        pub fn cachedSource(self: *Self, endpoint: anytype, now: i96, excluded: []const *State.Source) ?*State.Source {
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) {
                if (entry.expires_ns <= now) continue;
                for (entry.sources) |source| {
                    var used = false;
                    for (excluded) |candidate| used = used or candidate == source;
                    if (used) continue;
                    if (!source.retired and @import("../../ring_hash.zig").sameEndpointIdentity(source.endpoint, endpoint)) return source;
                }
            }
            return null;
        }
        pub fn record(self: *Self, state: *State, worker: *State.Worker, success: bool) void {
            if (self.entryFor(worker.source, std.Io.Clock.awake.now(state.io).nanoseconds)) |entry| outliers.record(entry.node, state, worker, success);
        }
        pub fn wrrConfig(self: *Self, state: *State, worker: *State.Worker) ?Config {
            const entry = self.entryFor(worker.source, std.Io.Clock.awake.now(state.io).nanoseconds) orelse return null;
            return wrr.config(entry.node, state, worker);
        }
        pub fn removeWorker(self: *Self, worker: *State.Worker) void {
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) Runtime.removeFromNode(entry.node, worker);
        }
        pub fn stopResolution(self: *Self) void {
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) for (entry.sources) |source| {
                if (source.resolver) |resolver| {
                    source.resolver = null;
                    resolver.deinit();
                }
            };
        }
        pub fn retireSource(state: *State, source: *State.Source) void {
            source.retired = true;
            source.suspended = true;
            for (state.workers.items) |worker| if (worker.source == source and !worker.retired) State.Membership.retireLocked(state, worker);
            state.allocator.free(source.current);
            source.current = &.{};
            if (source.pending) |pending| state.allocator.free(pending);
            source.pending = null;
            source.wake.set(state.io);
        }
        /// Detach expired entries under State ownership; free them after unlock.
        pub fn poll(self: *Self, state: *State, now: i96) ?*Entry {
            var garbage: ?*Entry = null;
            var link = &self.head;
            while (link.*) |entry| {
                if (entry.expires_ns > now) {
                    const view = RetainedView{ .io = state.io, .workers = state.workers };
                    _ = outliers.evaluate({}, entry.node, &view, now);
                    link = &entry.next;
                    continue;
                }
                link.* = entry.next;
                self.count -= 1;
                entry.next = garbage;
                garbage = entry;
            }
            var pending = garbage;
            while (pending) |entry| : (pending = entry.next) for (entry.sources) |source| {
                if (source.suspended and !source.retired and self.entryFor(source, now) == null) retireSource(state, source);
            };
            if (garbage != null) {
                state.resolution_changed.set(state.io);
                state.recomputeLocked();
                state.wakeAllLocked();
            }
            return garbage;
        }
        const RetainedView = struct {
            io: std.Io,
            workers: std.ArrayList(*State.Worker),
            retained_mode: bool = true,
        };
        pub fn nextDeadline(self: *Self) ?i96 {
            var result: ?i96 = null;
            var pending = self.head;
            while (pending) |entry| : (pending = entry.next) {
                const deadline = if (outliers.nextDeadline(entry.node)) |value| @min(value, entry.expires_ns) else entry.expires_ns;
                result = if (result) |value| @min(value, deadline) else deadline;
            }
            return result;
        }
    };
}

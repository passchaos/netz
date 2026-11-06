//! Immutable CDS reporting registrations, copied before channel publication.
const std = @import("std");

pub const Propagation = struct {
    cpu_utilization: bool = false,
    memory_utilization: bool = false,
    application_utilization: bool = false,
    named_metrics_all: bool = false,
    named_metrics: []const []const u8 = &.{},
};

pub const Identity = struct {
    cluster: []const u8,
    service_name: []const u8 = "",
    propagation: Propagation = .{},
};

pub const Selection = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize) = .init(1),
    identities: []const Identity,
    index: []const usize = &.{},

    pub fn create(allocator: std.mem.Allocator, identities: []const Identity) std.mem.Allocator.Error!*Selection {
        const self = try allocator.create(Selection);
        self.* = .{ .allocator = allocator, .arena = .init(allocator), .identities = &.{} };
        errdefer self.release();
        const arena = self.arena.allocator();
        const copies = try arena.alloc(Identity, identities.len);
        for (identities, copies) |source, *copy| {
            copy.* = source;
            copy.cluster = try arena.dupe(u8, source.cluster);
            copy.service_name = try arena.dupe(u8, source.service_name);
            const names = try arena.alloc([]const u8, source.propagation.named_metrics.len);
            for (source.propagation.named_metrics, names) |name, *owned| owned.* = try arena.dupe(u8, name);
            copy.propagation.named_metrics = names;
        }
        self.identities = copies;
        const index = try arena.alloc(usize, copies.len);
        for (index, 0..) |*slot, position| slot.* = position;
        std.mem.sort(usize, index, self.identities, lessThan);
        self.index = index;
        return self;
    }

    pub fn retain(self: *Selection) *Selection {
        const previous = self.refs.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
        return self;
    }

    pub fn release(self: *Selection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.arena.deinit();
        self.allocator.destroy(self);
    }

    pub fn find(self: *const Selection, cluster: []const u8, service_name: []const u8) ?*const Identity {
        var first: usize = 0;
        var last = self.index.len;
        while (first < last) {
            const middle = first + (last - first) / 2;
            const identity = &self.identities[self.index[middle]];
            switch (order(identity.*, cluster, service_name)) {
                .lt => first = middle + 1,
                .gt => last = middle,
                .eq => return identity,
            }
        }
        return null;
    }

    fn order(identity: Identity, cluster: []const u8, service_name: []const u8) std.math.Order {
        const cluster_order = std.mem.order(u8, identity.cluster, cluster);
        return if (cluster_order == .eq) std.mem.order(u8, identity.service_name, service_name) else cluster_order;
    }

    fn lessThan(identities: []const Identity, a: usize, b: usize) bool {
        return order(identities[a], identities[b].cluster, identities[b].service_name) == .lt;
    }
};

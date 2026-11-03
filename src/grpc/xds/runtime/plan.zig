//! Stage immutable cache references and name sets before target publication.
const std = @import("std");
const identity = @import("entry.zig");
const Controller = @import("controller.zig").Controller;
const Error = @import("errors.zig").PublishError;
const Projection = @import("../lds/projection.zig").Projection;
pub const Plan = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(identity.Entry) = .empty,
    route_storage: usize = 0,
    pub fn deinit(self: *Plan) void {
        for (self.entries.items) |*item| item.deinit();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn create(controller: *Controller, projection: ?*Projection) Error!Plan {
        var self = Plan{ .allocator = controller.allocator };
        errdefer self.deinit();
        var keys: std.ArrayList([]const u8) = .empty;
        defer keys.deinit(controller.allocator);
        var sources: std.ArrayList(*@import("../rds.zig").Snapshot) = .empty;
        defer sources.deinit(controller.allocator);
        for (controller.projections.items) |view| {
            if (view.refs.load(.acquire) == 1) continue;
            try keys.appendSlice(controller.allocator, view.source.required_clusters);
            try sources.append(controller.allocator, view.source);
        }
        if (projection) |view| {
            try keys.appendSlice(controller.allocator, view.source.required_clusters);
            try sources.append(controller.allocator, view.source);
        }
        std.mem.sort(*@import("../rds.zig").Snapshot, sources.items, {}, struct {
            fn less(_: void, a: *@import("../rds.zig").Snapshot, b: *@import("../rds.zig").Snapshot) bool {
                return @intFromPtr(a) < @intFromPtr(b);
            }
        }.less);
        for (sources.items, 0..) |source, i| {
            if (i != 0 and source == sources.items[i - 1]) continue;
            self.route_storage = std.math.add(usize, self.route_storage, source.resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
            if (self.route_storage > controller.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        }
        std.mem.sort([]const u8, keys.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        var count: usize = 0;
        for (keys.items) |key| {
            if (count != 0 and std.mem.eql(u8, keys.items[count - 1], key)) continue;
            if (count >= controller.options.limits.max_clusters) return error.XdsLimitExceeded;
            keys.items[count] = key;
            count += 1;
        }
        try self.entries.ensureUnusedCapacity(controller.allocator, count);
        for (keys.items[0..count]) |key| {
            if (!std.mem.startsWith(u8, key, "cluster:") or key.len == 8) return error.InvalidSharedOptions;
            if (find(controller.entries.items, key)) |old| self.entries.appendAssumeCapacity(old.clone()) else {
                self.entries.appendAssumeCapacity(.{ .identity = try identity.Identity.create(controller.allocator, key[8..]) });
            }
        }
        return self;
    }
    pub fn find(entries: []const identity.Entry, key: []const u8) ?identity.Entry {
        var first: usize = 0;
        var last = entries.len;
        while (first < last) {
            const middle = first + (last - first) / 2;
            const item = entries[middle];
            switch (std.mem.order(u8, key, item.identity.key)) {
                .lt => last = middle,
                .gt => first = middle + 1,
                .eq => return item,
            }
        }
        return null;
    }
    pub fn cdsNames(self: *Plan) std.mem.Allocator.Error![]const []const u8 {
        const names = try self.allocator.alloc([]const u8, self.entries.items.len);
        for (self.entries.items, names) |item, *name| name.* = item.identity.name;
        return names;
    }
    pub fn edsNames(self: *Plan) std.mem.Allocator.Error![]const []const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        for (self.entries.items) |item| if (item.cluster) |cluster| {
            if (!cluster.resource.value.isEds()) continue;
            try names.append(self.allocator, cluster.resource.value.edsName());
        };
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        var count: usize = 0;
        for (names.items) |name| {
            if (count != 0 and std.mem.eql(u8, names.items[count - 1], name)) continue;
            names.items[count] = name;
            count += 1;
        }
        names.shrinkRetainingCapacity(count);
        return names.toOwnedSlice(self.allocator);
    }
};

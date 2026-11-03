//! Delta EDS resources applied to each referenced cluster's endpoint plan.
const std = @import("std");
const ctl = @import("controller.zig");
const eds = @import("../eds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;

fn removedName(names: []const []const u8, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}

fn heartbeatName(resources: []const delta.codec.Resource, name: []const u8) bool {
    for (resources) |resource| {
        if (resource.resource == null and std.mem.eql(u8, resource.name, name)) return true;
    }
    return false;
}

pub fn apply(self: *ctl.Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    const response = update.response.value;
    var resources: std.ArrayList(eds.resource.Owned) = .empty;
    defer {
        for (resources.items) |*resource| resource.deinit();
        resources.deinit(self.allocator);
    }
    var storage: usize = 0;
    for (response.resources) |raw| {
        const any = raw.resource orelse continue;
        var resource = try eds.decode(self.allocator, any.value, self.options.limits.eds);
        errdefer resource.deinit();
        if (!std.mem.eql(u8, resource.value.cluster_name, raw.name)) return error.InvalidDiscoveryMessage;
        storage = std.math.add(usize, storage, resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        try resources.append(self.allocator, resource);
    }
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        const name = cluster.resource.value.edsName();
        const selected = for (resources.items) |resource| {
            if (std.mem.eql(u8, resource.value.cluster_name, name)) break resource.wire;
        } else null;
        if (selected) |wire| {
            if (item.snapshot) |old| if (std.mem.eql(u8, old.resource.wire, wire)) {
                changed = changed or !item.eds_seen;
                item.eds_seen = true;
                continue;
            };
            const snapshot = try self.project(cluster, wire);
            changed = true;
            if (item.snapshot) |old| old.release();
            item.snapshot = snapshot;
            item.eds_seen = true;
        } else if (removedName(response.removed, name)) {
            // An explicit removal resolves the assignment to an empty one;
            // it is not the same as an initial omission.
            const empty = try self.emptyEds(cluster);
            if (item.snapshot) |old| if (std.mem.eql(u8, old.resource.wire, empty.resource.wire) and item.eds_seen) {
                empty.release();
                continue;
            };
            changed = true;
            if (item.snapshot) |old| old.release();
            item.snapshot = empty;
            item.eds_seen = true;
        } else if (heartbeatName(response.resources, name)) {
            if (item.snapshot == null or !item.eds_seen) return error.InvalidDiscoveryMessage;
        }
    }
    if (!changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    return self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
}

//! Whole CDS response staging, EDS-name handoff and cached endpoint reprojection.
const std = @import("std");
const ctl = @import("controller.zig");
const entry = @import("entry.zig");
const cds = @import("../cds.zig");
const ads = @import("../ads.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    var resources: std.ArrayList(*entry.Cluster) = .empty;
    defer {
        for (resources.items) |resource| resource.release();
        resources.deinit(self.allocator);
    }
    var storage: usize = 0;
    for (update.response.value.resources) |raw| {
        var owned = try cds.decode(self.allocator, raw.value, self.options.limits.cds);
        const resource = entry.Cluster.create(self.allocator, owned) catch |err| {
            owned.deinit();
            return err;
        };
        errdefer resource.release();
        storage = std.math.add(usize, storage, owned.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        try resources.append(self.allocator, resource);
    }
    std.mem.sort(*entry.Cluster, resources.items, {}, struct {
        fn less(_: void, a: *entry.Cluster, b: *entry.Cluster) bool {
            return std.mem.order(u8, a.resource.value.name, b.resource.value.name) == .lt;
        }
    }.less);
    if (resources.items.len > 1) for (resources.items[1..], 0..) |resource, i| if (std.mem.eql(u8, resource.resource.value.name, resources.items[i].resource.value.name)) return error.DuplicateCdsResource;
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const selected = for (resources.items) |resource| {
            if (std.mem.eql(u8, resource.resource.value.name, item.identity.name)) break resource;
        } else null;
        if (selected) |resource| {
            changed = true;
            const after = resource.resource.value;
            const same = if (item.cluster) |old| blk: {
                const before = old.resource.value;
                break :blk before.discovery == after.discovery and std.mem.eql(u8, before.edsName(), after.edsName()) and std.mem.eql(u8, before.static_assignment, after.static_assignment);
            } else false;
            const snapshot = if (same and item.snapshot != null) blk: {
                const before = item.cluster.?.resource.value;
                if (before.max_concurrent_requests == after.max_concurrent_requests and before.policy.locality_weighted == after.policy.locality_weighted and std.mem.eql(u8, before.policy.child_json, after.policy.child_json)) {
                    item.snapshot.?.retain();
                    break :blk item.snapshot.?;
                }
                break :blk try self.project(resource, if (after.isEds()) item.snapshot.?.resource.wire else after.static_assignment);
            } else if (after.isEds()) try self.emptyEds(resource) else try self.project(resource, after.static_assignment);
            resource.retain();
            if (item.cluster) |old| old.release();
            if (item.snapshot) |old| old.release();
            item.cluster = resource;
            item.snapshot = snapshot;
            item.eds_seen = !after.isEds() or (same and item.eds_seen);
        } else {
            // Missing newly requested CDS is not a resource-not-found answer.
            // Delete only a previously received cluster, preserving pending
            // siblings when a full-type response predates their subscription.
            if (item.cluster == null) continue;
            changed = true;
            if (item.cluster) |old| old.release();
            if (item.snapshot) |old| old.release();
            item.cluster = null;
            item.snapshot = null;
            item.eds_seen = false;
        }
        item.cds_seen = true;
    }
    if (!changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    return self.publish(client, &plan, self.latest.?, false, destination, deadline);
}

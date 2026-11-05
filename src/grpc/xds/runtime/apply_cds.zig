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
    var limits = self.options.limits.cds;
    limits.allow_sds = true;
    for (update.response.value.resources) |raw| {
        var owned = try cds.decode(self.allocator, raw.value, limits);
        const resource = entry.Cluster.create(self.allocator, owned) catch |err| {
            owned.deinit();
            return err;
        };
        errdefer resource.release();
        try self.resolveClusterTls(resource);
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
    var plan = try Plan.createWithClusters(self, null, resources.items);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const selected = for (resources.items) |resource| {
            if (std.mem.eql(u8, resource.resource.value.name, item.identity.name)) break resource;
        } else null;
        if (selected) |resource| {
            changed = true;
            const after = resource.resource.value;
            const before: ?cds.resource.Cluster = if (item.cluster) |old| old.resource.value else null;
            const same_identity = if (before) |old| old.discovery == after.discovery and std.mem.eql(u8, old.edsName(), after.edsName()) and std.mem.eql(u8, old.inline_assignment, after.inline_assignment) else false;
            // TLS material can change independently of discovery identity
            // (inline rotation or SDS references), so always reproject it.
            const has_tls = after.tls != null or after.tls_sds != null or
                (before != null and (before.?.tls != null or before.?.tls_sds != null));
            const same_config = same_identity and !has_tls and if (before) |old|
                old.max_concurrent_requests == after.max_concurrent_requests and
                    old.policy.locality_weighted == after.policy.locality_weighted and
                    std.mem.eql(u8, old.policy.child_json, after.policy.child_json)
            else
                false;
            const snapshot: ?*@import("../eds.zig").Snapshot = if (same_config and item.snapshot != null) blk: {
                item.snapshot.?.retain();
                break :blk item.snapshot.?;
            } else if (same_identity and item.snapshot != null)
                try self.project(client.sender.state.io, resource, if (after.isEds()) item.snapshot.?.resource.wire else after.inline_assignment)
            else if (after.isEds())
                try self.emptyEds(client.sender.state.io, resource)
            else if (after.isDns() or after.isAggregate())
                null
            else if (resource.sdsPending())
                null
            else
                try self.project(client.sender.state.io, resource, after.inline_assignment);
            resource.retain();
            if (item.cluster) |old| old.release();
            if (item.snapshot) |old| old.release();
            item.cluster = resource;
            item.snapshot = snapshot;
            item.eds_seen = !after.isEds() or (same_identity and item.eds_seen);
        } else {
            // Missing newly requested CDS is not a resource-not-found answer.
            // Delete only a previously received cluster, preserving pending
            // siblings when a full-type response predates their subscription.
            if (item.cluster == null) continue;
            if (self.options.ignore_resource_deletion) {
                item.cds_seen = true;
                continue;
            }
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

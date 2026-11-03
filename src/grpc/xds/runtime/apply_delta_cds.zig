//! Delta CDS resources applied to the automatic cluster plan.
const std = @import("std");
const ctl = @import("controller.zig");
const entry = @import("entry.zig");
const cds = @import("../cds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;

const Candidate = struct { name: []const u8, resource: *entry.Cluster };

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
    var candidates: std.ArrayList(Candidate) = .empty;
    defer {
        for (candidates.items) |candidate| candidate.resource.release();
        candidates.deinit(self.allocator);
    }
    var storage: usize = 0;
    for (response.resources) |raw| {
        const any = raw.resource orelse continue;
        var owned = try cds.decode(self.allocator, any.value, self.options.limits.cds);
        const resource = entry.Cluster.create(self.allocator, owned) catch |err| {
            owned.deinit();
            return err;
        };
        errdefer resource.release();
        if (!std.mem.eql(u8, resource.resource.value.name, raw.name)) return error.InvalidDiscoveryMessage;
        storage = std.math.add(usize, storage, owned.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        try candidates.append(self.allocator, .{ .name = raw.name, .resource = resource });
    }
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const selected = for (candidates.items) |candidate| {
            if (std.mem.eql(u8, candidate.name, item.identity.name)) break candidate.resource;
        } else null;
        if (selected) |resource| {
            changed = true;
            const same = if (item.cluster) |old| std.mem.eql(u8, old.resource.value.edsName(), resource.resource.value.edsName()) else false;
            const snapshot = if (same and item.snapshot != null) blk: {
                const before = item.cluster.?.resource.value;
                const after = resource.resource.value;
                if (before.max_concurrent_requests == after.max_concurrent_requests and before.policy.locality_weighted == after.policy.locality_weighted and std.mem.eql(u8, before.policy.child_json, after.policy.child_json)) {
                    item.snapshot.?.retain();
                    break :blk item.snapshot.?;
                }
                break :blk try self.project(resource, item.snapshot.?.resource.wire);
            } else try self.emptyEds(resource);
            resource.retain();
            if (item.cluster) |old| old.release();
            if (item.snapshot) |old| old.release();
            item.cluster = resource;
            item.snapshot = snapshot;
            if (!same) item.eds_seen = false;
            item.cds_seen = true;
        } else if (removedName(response.removed, item.identity.name)) {
            // Explicit removal of a resource the client never accepted is a
            // no-op; removal of an accepted cluster resolves it as not found.
            if (item.cluster == null) continue;
            changed = true;
            if (item.cluster) |old| old.release();
            if (item.snapshot) |old| old.release();
            item.cluster = null;
            item.snapshot = null;
            item.cds_seen = true;
            item.eds_seen = false;
        } else if (heartbeatName(response.resources, item.identity.name)) {
            if (item.cluster == null) return error.InvalidDiscoveryMessage;
            item.cds_seen = true;
        }
    }
    if (!changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    return self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
}

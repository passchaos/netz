//! Delta CDS resources applied to the automatic cluster plan.
const std = @import("std");
const ctl = @import("controller.zig");
const entry = @import("entry.zig");
const cds = @import("../cds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;

const Candidate = struct { name: []const u8, resource: *entry.Cluster, ttl: ?delta.codec.Duration };

fn removedName(names: []const []const u8, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
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
    var limits = self.options.limits.cds;
    limits.allow_sds = true;
    for (response.resources) |raw| {
        const any = raw.resource orelse continue;
        var owned = try cds.decode(self.allocator, any.value, limits);
        const resource = entry.Cluster.create(self.allocator, owned) catch |err| {
            owned.deinit();
            return err;
        };
        errdefer resource.release();
        if (!std.mem.eql(u8, resource.resource.value.name, raw.name)) return error.InvalidDiscoveryMessage;
        try self.resolveClusterTls(resource);
        storage = std.math.add(usize, storage, owned.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        try candidates.append(self.allocator, .{ .name = raw.name, .resource = resource, .ttl = raw.ttl });
    }
    // A payload-free heartbeat only refreshes the timer. It does not require a
    // target publication and must not invent a new payload.
    for (response.resources) |raw| {
        if (raw.resource != null) continue;
        for (self.entries.items) |*item| {
            if (!std.mem.eql(u8, item.identity.name, raw.name)) continue;
            if (item.cluster == null) return error.InvalidDiscoveryMessage;
            item.cds_deadline = try delta.codec.ttlDeadline(client.sender.state.io, raw.ttl);
        }
    }
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const selected = for (candidates.items) |candidate| {
            if (std.mem.eql(u8, candidate.name, item.identity.name)) break candidate;
        } else null;
        if (selected) |candidate| {
            const resource = candidate.resource;
            const cds_deadline = try delta.codec.ttlDeadline(client.sender.state.io, candidate.ttl);
            const after = resource.resource.value;
            const same_identity = if (item.cluster) |old| blk: {
                const before = old.resource.value;
                break :blk before.discovery == after.discovery and std.mem.eql(u8, before.edsName(), after.edsName()) and std.mem.eql(u8, before.inline_assignment, after.inline_assignment);
            } else false;
            const same_config = if (item.cluster) |old| blk: {
                const before = old.resource.value;
                if (after.tls != null or after.tls_sds != null or before.tls != null or before.tls_sds != null) break :blk false;
                break :blk same_identity and before.max_concurrent_requests == after.max_concurrent_requests and before.policy.locality_weighted == after.policy.locality_weighted and std.mem.eql(u8, before.policy.child_json, after.policy.child_json);
            } else false;
            if (same_config and item.snapshot != null and item.cds_seen and entry.sameDeadline(item.cds_deadline, cds_deadline)) {
                item.cds_deadline = cds_deadline;
                continue;
            }
            changed = true;
            const snapshot: ?*@import("../eds.zig").Snapshot = if (same_config) blk: {
                item.snapshot.?.retain();
                break :blk item.snapshot.?;
            } else if (same_identity and item.snapshot != null)
                try self.project(client.sender.state.io, resource, if (after.isEds()) item.snapshot.?.resource.wire else after.inline_assignment)
            else if (after.isEds())
                try self.emptyEds(client.sender.state.io, resource)
            else if (after.isDns())
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
            item.cds_seen = true;
            item.cds_deadline = cds_deadline;
        } else if (removedName(response.removed, item.identity.name)) {
            // Explicit removal of a resource the client never accepted is a
            // no-op; removal of an accepted cluster resolves it as not found.
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
            item.cds_seen = true;
            item.eds_seen = false;
            item.cds_deadline = null;
        }
    }
    if (!changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    return self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
}

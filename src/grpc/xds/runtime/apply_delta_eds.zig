//! Delta EDS resources applied to each referenced cluster's endpoint plan.
const std = @import("std");
const ctl = @import("controller.zig");
const entry = @import("entry.zig");
const eds = @import("../eds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;

const Candidate = struct { resource: eds.resource.Owned, ttl: ?delta.codec.Duration };

fn removedName(names: []const []const u8, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}

pub fn apply(self: *ctl.Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    const response = update.response.value;
    var resources: std.ArrayList(Candidate) = .empty;
    defer {
        for (resources.items) |*candidate| candidate.resource.deinit();
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
        try resources.append(self.allocator, .{ .resource = resource, .ttl = raw.ttl });
    }
    // Payload-free heartbeats refresh the timer without republishing endpoints.
    for (response.resources) |raw| {
        if (raw.resource != null) continue;
        for (self.entries.items) |*item| {
            const cluster = item.cluster orelse continue;
            if (!std.mem.eql(u8, cluster.resource.value.edsName(), raw.name)) continue;
            if (item.snapshot == null or !item.eds_seen) return error.InvalidDiscoveryMessage;
            item.eds_deadline = try delta.codec.ttlDeadline(client.sender.state.io, raw.ttl);
        }
    }
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        const name = cluster.resource.value.edsName();
        const selected = for (resources.items) |*candidate| {
            if (std.mem.eql(u8, candidate.resource.value.cluster_name, name)) break candidate;
        } else null;
        if (selected) |candidate| {
            const wire = candidate.resource.wire;
            const eds_deadline = try delta.codec.ttlDeadline(client.sender.state.io, candidate.ttl);
            if (item.snapshot) |old| if (std.mem.eql(u8, old.resource.wire, wire)) {
                const seen_changed = !item.eds_seen;
                const deadline_changed = !entry.sameDeadline(item.eds_deadline, eds_deadline);
                item.eds_seen = true;
                item.eds_deadline = eds_deadline;
                changed = changed or seen_changed or deadline_changed;
                continue;
            };
            const snapshot = try self.project(cluster, wire);
            changed = true;
            if (item.snapshot) |old| old.release();
            item.snapshot = snapshot;
            item.eds_seen = true;
            item.eds_deadline = eds_deadline;
        } else if (removedName(response.removed, name)) {
            // An explicit removal resolves the assignment to an empty one;
            // it is not the same as an initial omission.
            const empty = try self.emptyEds(cluster);
            item.eds_deadline = null;
            if (item.snapshot) |old| if (std.mem.eql(u8, old.resource.wire, empty.resource.wire) and item.eds_seen) {
                empty.release();
                continue;
            };
            changed = true;
            if (item.snapshot) |old| old.release();
            item.snapshot = empty;
            item.eds_seen = true;
        }
    }
    if (!changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    return self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
}

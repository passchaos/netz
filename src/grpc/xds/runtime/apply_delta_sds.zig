//! Delta SDS resources applied to the controller's secret cache.
const std = @import("std");
const ctl = @import("controller.zig");
const sds = @import("../sds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;

pub fn apply(self: *ctl.Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    if (self.latest == null) return error.XdsNotStarted;
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    const io = client.sender.state.io;
    const response = update.response.value;
    const decoded = try self.allocator.alloc(*ctl.CachedSecret, response.resources.len);
    defer self.allocator.free(decoded);
    const owned = try self.allocator.alloc(bool, response.resources.len);
    defer self.allocator.free(owned);
    var count: usize = 0;
    var storage: usize = 0;
    defer for (decoded[0..count], owned[0..count]) |value, keep| {
        if (!keep) continue;
        value.owned.deinit();
        self.allocator.destroy(value);
    };
    for (response.resources) |raw| {
        const any = raw.resource orelse continue;
        var value = try sds.decode(self.allocator, any.value, self.options.limits.sds);
        const pointer = self.allocator.create(ctl.CachedSecret) catch |err| {
            value.deinit();
            return err;
        };
        pointer.* = .{
            .owned = value,
            .deadline = try delta.codec.ttlDeadline(io, raw.ttl),
        };
        decoded[count] = pointer;
        owned[count] = true;
        count += 1;
        storage = std.math.add(usize, storage, value.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
    }
    std.mem.sort(*ctl.CachedSecret, decoded[0..count], {}, struct {
        fn less(_: void, a: *ctl.CachedSecret, b: *ctl.CachedSecret) bool {
            return std.mem.order(u8, a.owned.value.name, b.owned.value.name) == .lt;
        }
    }.less);
    if (count > 1) for (decoded[1..count], 0..) |value, i| {
        if (std.mem.eql(u8, value.owned.value.name, decoded[i].owned.value.name)) return error.DuplicateSdsResource;
    };
    try self.sds_secrets.ensureUnusedCapacity(self.allocator, @intCast(count));
    var changed = false;
    for (decoded[0..count], owned[0..count]) |value, *keep| {
        if (self.sds_secrets.get(value.owned.value.name)) |old| {
            if (std.mem.eql(u8, old.owned.wire, value.owned.wire)) {
                // Same payload: only the delta timer may have moved.
                old.deadline = value.deadline;
                keep.* = false;
                value.owned.deinit();
                self.allocator.destroy(value);
                continue;
            }
            const removed = self.sds_secrets.fetchRemove(value.owned.value.name).?;
            removed.value.owned.deinit();
            self.allocator.destroy(removed.value);
        }
        self.sds_secrets.putAssumeCapacity(value.owned.value.name, value);
        keep.* = false;
        changed = true;
    }
    // Payload-free heartbeats refresh the timer without republishing secrets.
    for (response.resources) |raw| {
        if (raw.resource != null) continue;
        const cached = self.sds_secrets.get(raw.name) orelse continue;
        cached.deadline = try delta.codec.ttlDeadline(io, raw.ttl);
    }
    for (response.removed) |name| {
        if (self.sds_secrets.fetchRemove(name)) |removed| {
            removed.value.owned.deinit();
            self.allocator.destroy(removed.value);
            changed = true;
        }
    }
    if (!changed) {
        // Still validate and resolve referenced clusters so a wrong-kind
        // reference keeps failing instead of being accepted on retry.
        for (self.entries.items) |*item| {
            const cluster = item.cluster orelse continue;
            if (cluster.resource.value.tls_sds == null) continue;
            try self.resolveClusterTls(cluster);
        }
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }
    for (self.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        if (cluster.resource.value.tls_sds == null) continue;
        try self.resolveClusterTls(cluster);
    }

    var plan = try Plan.create(self, null);
    defer plan.deinit();
    for (plan.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        if (cluster.resource.value.tls_sds == null) continue;
        try self.reproject(io, item);
    }
    return self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
}

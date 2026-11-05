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
    const response = update.response.value;
    const decoded = try self.allocator.alloc(*sds.Owned, response.resources.len);
    defer self.allocator.free(decoded);
    const owned = try self.allocator.alloc(bool, response.resources.len);
    defer self.allocator.free(owned);
    var count: usize = 0;
    var storage: usize = 0;
    defer for (decoded[0..count], owned[0..count]) |value, keep| {
        if (!keep) continue;
        value.deinit();
        self.allocator.destroy(value);
    };
    for (response.resources) |raw| {
        const any = raw.resource orelse continue;
        var value = try sds.decode(self.allocator, any.value, self.options.limits.sds);
        const pointer = self.allocator.create(sds.Owned) catch |err| {
            value.deinit();
            return err;
        };
        pointer.* = value;
        decoded[count] = pointer;
        owned[count] = true;
        count += 1;
        storage = std.math.add(usize, storage, value.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
    }
    std.mem.sort(*sds.Owned, decoded[0..count], {}, struct {
        fn less(_: void, a: *sds.Owned, b: *sds.Owned) bool {
            return std.mem.order(u8, a.value.name, b.value.name) == .lt;
        }
    }.less);
    if (count > 1) for (decoded[1..count], 0..) |value, i| {
        if (std.mem.eql(u8, value.value.name, decoded[i].value.name)) return error.DuplicateSdsResource;
    };
    try self.sds_secrets.ensureUnusedCapacity(self.allocator, @intCast(count));
    var changed = false;
    for (decoded[0..count], owned[0..count]) |value, *keep| {
        if (self.sds_secrets.get(value.value.name)) |old| {
            if (std.mem.eql(u8, old.wire, value.wire)) {
                keep.* = false;
                value.deinit();
                self.allocator.destroy(value);
                continue;
            }
            const removed = self.sds_secrets.fetchRemove(value.value.name).?;
            removed.value.deinit();
            self.allocator.destroy(removed.value);
        }
        self.sds_secrets.putAssumeCapacity(value.value.name, value);
        keep.* = false;
        changed = true;
    }
    for (response.removed) |name| {
        if (self.sds_secrets.fetchRemove(name)) |removed| {
            removed.value.deinit();
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
        try self.reproject(client.sender.state.io, item);
    }
    return self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
}

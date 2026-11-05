//! Whole SDS response staging and cluster TLS reprojection.
const std = @import("std");
const ctl = @import("controller.zig");
const sds = @import("../sds.zig");
const ads = @import("../ads.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    if (self.latest == null) return error.XdsNotStarted;
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    const resources = update.response.value.resources;
    const decoded = try self.allocator.alloc(*sds.Owned, resources.len);
    defer self.allocator.free(decoded);
    var initialized: usize = 0;
    var committed = false;
    defer if (!committed) {
        for (decoded[0..initialized]) |value| {
            value.deinit();
            self.allocator.destroy(value);
        }
    };
    var storage: usize = 0;
    for (resources, 0..) |raw, index| {
        var owned = try sds.decode(self.allocator, raw.value, self.options.limits.sds);
        const pointer = self.allocator.create(sds.Owned) catch |err| {
            owned.deinit();
            return err;
        };
        pointer.* = owned;
        decoded[index] = pointer;
        initialized += 1;
        storage = std.math.add(usize, storage, owned.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
    }
    std.mem.sort(*sds.Owned, decoded, {}, struct {
        fn less(_: void, a: *sds.Owned, b: *sds.Owned) bool {
            return std.mem.order(u8, a.value.name, b.value.name) == .lt;
        }
    }.less);
    if (decoded.len > 1) for (decoded[1..], 0..) |value, i| {
        if (std.mem.eql(u8, value.value.name, decoded[i].value.name)) return error.DuplicateSdsResource;
    };
    const cache_changed = try self.updateSecrets(decoded);
    committed = cache_changed;
    // Resolve even when the wire bytes are unchanged: a previously rejected
    // wrong-kind reference must keep failing until the control plane fixes it.
    var state_changed = cache_changed;
    for (self.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        if (cluster.resource.value.tls_sds == null) continue;
        const before = cluster.sdsPending();
        try self.resolveClusterTls(cluster);
        if (before != cluster.sdsPending()) state_changed = true;
    }
    if (!state_changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);

    var plan = try Plan.create(self, null);
    defer plan.deinit();
    for (plan.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        if (cluster.resource.value.tls_sds == null) continue;
        try self.reproject(client.sender.state.io, item);
    }
    return self.publish(client, &plan, self.latest.?, false, destination, deadline);
}

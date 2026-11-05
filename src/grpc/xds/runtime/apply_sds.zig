//! Whole SDS response staging and cluster TLS reprojection.
const std = @import("std");
const ctl = @import("controller.zig");
const sds = @import("../sds.zig");
const ads = @import("../ads.zig");
const shared = @import("../../channel/shared.zig");
const raw_name = @import("../raw_name.zig");
const Plan = @import("plan.zig").Plan;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    if (self.latest == null) return error.XdsNotStarted;
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    const resources = update.response.value.resources;
    const decoded = try self.allocator.alloc(*ctl.CachedSecret, resources.len);
    defer self.allocator.free(decoded);
    var initialized: usize = 0;
    var committed = false;
    defer if (!committed) {
        for (decoded[0..initialized]) |value| {
            value.owned.deinit();
            self.allocator.destroy(value);
        }
    };
    var storage: usize = 0;
    var count: usize = 0;
    var first_error: ?sds.Error = null;
    for (resources) |raw| {
        var owned = sds.decode(self.allocator, raw.value, self.options.limits.sds) catch |err| {
            if (!self.options.fail_on_data_errors) return err;
            if (raw_name.first(raw.value, 1) == null) return err;
            if (first_error == null) first_error = err;
            continue;
        };
        const pointer = self.allocator.create(ctl.CachedSecret) catch |err| {
            owned.deinit();
            return err;
        };
        pointer.* = .{ .owned = owned };
        decoded[count] = pointer;
        count += 1;
        initialized += 1;
        storage = std.math.add(usize, storage, owned.arena.queryCapacity()) catch return error.XdsLimitExceeded;
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
    const cache_changed = try self.updateSecrets(decoded[0..count]);
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
    if (!state_changed) {
        if (first_error) |err| return err;
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }

    var plan = try Plan.create(self, null);
    defer plan.deinit();
    for (plan.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        if (cluster.resource.value.tls_sds == null) continue;
        try self.reproject(client.sender.state.io, item);
    }
    _ = try self.publish(client, &plan, self.latest.?, false, destination, deadline);
    if (first_error) |err| return err;
    return @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
}

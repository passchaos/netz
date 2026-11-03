//! Typed EDS validation and one staged projection for each referenced cluster.
const std = @import("std");
const ctl = @import("controller.zig");
const eds = @import("../eds.zig");
const ads = @import("../ads.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    var resources: std.ArrayList(eds.resource.Owned) = .empty;
    defer {
        for (resources.items) |*resource| resource.deinit();
        resources.deinit(self.allocator);
    }
    var storage: usize = 0;
    for (update.response.value.resources) |raw| {
        var resource = try eds.decode(self.allocator, raw.value, self.options.limits.eds);
        errdefer resource.deinit();
        storage = std.math.add(usize, storage, resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        try resources.append(self.allocator, resource);
    }
    const names = try self.allocator.alloc([]const u8, resources.items.len);
    defer self.allocator.free(names);
    for (resources.items, names) |resource, *name| name.* = resource.value.cluster_name;
    std.mem.sort([]const u8, names, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    if (names.len > 1) for (names[1..], 0..) |name, i| if (std.mem.eql(u8, name, names[i])) return error.DuplicateEdsResource;
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        const cluster = item.cluster orelse continue;
        const selected = for (resources.items) |resource| {
            if (std.mem.eql(u8, resource.value.cluster_name, cluster.resource.value.edsName())) break resource.wire;
        } else continue;
        // EDS SotW can carry a subset. Missing children retain their exact
        // snapshot and discovery state; a new assignment stays pending.
        if (item.snapshot) |old| if (std.mem.eql(u8, old.resource.wire, selected)) {
            changed = changed or !item.eds_seen;
            item.eds_seen = true;
            continue;
        };
        const snapshot = try self.project(cluster, selected);
        changed = true;
        if (item.snapshot) |old| old.release();
        item.snapshot = snapshot;
        item.eds_seen = true;
    }
    if (!changed) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    return self.publish(client, &plan, self.latest.?, false, destination, deadline);
}

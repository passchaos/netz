//! Late RDS cannot restore inline/deleted listeners; cached data is immutable.
const std = @import("std");
const ctl = @import("controller.zig");
const ads = @import("../ads.zig");
const rds = @import("../rds.zig");
const shared = @import("../../channel/shared.zig");
const Projection = @import("projection.zig").Projection;
pub fn apply(self: *ctl.Controller, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    var candidates: std.ArrayList(*rds.Snapshot) = .empty;
    defer {
        for (candidates.items) |snapshot| snapshot.release();
        candidates.deinit(self.allocator);
    }
    var storage: usize = 0;
    for (update.response.value.resources) |raw| {
        const snapshot = try rds.Snapshot.create(self.allocator, raw.value, self.options.limits.rds, self.routeOptions());
        errdefer snapshot.release();
        storage = std.math.add(usize, storage, snapshot.resource.arena.queryCapacity()) catch return error.LdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.LdsLimitExceeded;
        try candidates.append(self.allocator, snapshot);
    }
    const names = try self.allocator.dupe(*rds.Snapshot, candidates.items);
    defer self.allocator.free(names);
    std.mem.sort(*rds.Snapshot, names, {}, struct {
        fn less(_: void, a: *rds.Snapshot, b: *rds.Snapshot) bool {
            return std.mem.order(u8, a.resource.value.name, b.resource.value.name) == .lt;
        }
    }.less);
    if (names.len > 1) for (names[1..], 0..) |value, i| if (std.mem.eql(u8, value.resource.value.name, names[i].resource.value.name)) return error.DuplicateRdsResource;
    const listener = self.listener orelse return destination.configurationRevision();
    if (listener.value.hcm.route_source != .rds) return destination.configurationRevision();
    const name = listener.value.hcm.route_source.rds;
    var selected: ?*rds.Snapshot = null;
    for (candidates.items) |snapshot| if (std.mem.eql(u8, name, snapshot.resource.value.name)) {
        selected = snapshot;
    };
    if (selected == null) {
        const empty = try self.empty(name);
        errdefer empty.release();
        storage = std.math.add(usize, storage, empty.resource.arena.queryCapacity()) catch return error.LdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.LdsLimitExceeded;
        try candidates.append(self.allocator, empty);
        selected = empty;
    }
    const projection = try Projection.create(self.allocator, selected.?, listener.value.hcm.max_stream_duration);
    defer projection.release();
    const revision = try projection.publishWithDeadline(destination, deadline);
    selected.?.retain();
    if (self.routes) |previous| previous.release();
    self.routes = selected.?;
    return revision;
}

//! Prepare names and route projection before committing listener state.
const std = @import("std");
const ctl = @import("controller.zig");
const model = @import("model.zig");
const ads = @import("../ads.zig");
const rds = @import("../rds.zig");
const shared = @import("../../channel/shared.zig");
const Projection = @import("projection.zig").Projection;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    var candidates: std.ArrayList(?model.Owned) = .empty;
    defer {
        for (candidates.items) |*candidate| if (candidate.*) |*resource| resource.deinit();
        candidates.deinit(self.allocator);
    }
    var selected: ?usize = null;
    var storage: usize = 0;
    for (update.response.value.resources) |raw| {
        var candidate = try @import("decode.zig").decode(self.allocator, raw.value, self.options.limits);
        errdefer candidate.deinit();
        storage = std.math.add(usize, storage, candidate.storageBytes()) catch return error.LdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.LdsLimitExceeded;
        if (std.mem.eql(u8, candidate.value.name, self.options.listener_name)) selected = candidates.items.len;
        try candidates.append(self.allocator, candidate);
    }
    const indices = try self.allocator.alloc(usize, candidates.items.len);
    defer self.allocator.free(indices);
    for (indices, 0..) |*index, i| index.* = i;
    std.mem.sort(usize, indices, candidates.items, struct {
        fn less(values: []?model.Owned, a: usize, b: usize) bool {
            return std.mem.order(u8, values[a].?.value.name, values[b].?.value.name) == .lt;
        }
    }.less);
    if (indices.len > 1) for (indices[1..], 0..) |index, i| if (std.mem.eql(u8, candidates.items[index].?.value.name, candidates.items[indices[i]].?.value.name)) return error.DuplicateLdsResource;
    if (selected) |index| {
        const candidate = &candidates.items[index].?;
        const hcm = candidate.value.hcm;
        var subscription: ?ads.subscriptions.Prepared = if (hcm.route_source == .rds) try client.subscriptions.prepare(rds.type_url, &.{hcm.route_source.rds}) else null;
        defer if (subscription) |*prepared| prepared.deinit();
        const same = if (self.listener) |previous| previous.value.hcm.route_source == .rds and hcm.route_source == .rds and std.mem.eql(u8, previous.value.hcm.route_source.rds, hcm.route_source.rds) else false;
        const source = if (hcm.route_source == .inline_rds)
            try self.takeInline(candidate)
        else if (same and self.routes != null) blk: {
            self.routes.?.retain();
            break :blk self.routes.?;
        } else try self.empty(hcm.route_source.rds);
        var source_owned = true;
        defer if (source_owned) source.release();
        const projection = try Projection.create(self.allocator, source, hcm.max_stream_duration);
        defer projection.release();
        const revision = try self.publish(client, projection, destination, deadline);
        if (subscription) |*prepared| prepared.commit();
        if (self.listener) |*previous| previous.deinit();
        self.listener = candidates.items[index];
        candidates.items[index] = null;
        if (self.routes) |previous| previous.release();
        self.routes = source;
        source_owned = false;
        return revision;
    }
    const empty = try self.empty("_");
    defer empty.release();
    const projection = try Projection.create(self.allocator, empty, null);
    defer projection.release();
    const revision = try self.publish(client, projection, destination, deadline);
    if (self.listener) |*previous| previous.deinit();
    self.listener = null;
    if (self.routes) |previous| previous.release();
    self.routes = null;
    // Keep the last named RDS subscription; empty names would be wildcard.
    return revision;
}

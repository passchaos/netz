//! Prepare names and route projection before committing listener state.
const std = @import("std");
const ctl = @import("controller.zig");
const model = @import("model.zig");
const ads = @import("../ads.zig");
const rds = @import("../rds.zig");
const shared = @import("../../channel/shared.zig");
const raw_name = @import("../raw_name.zig");
const Projection = @import("projection.zig").Projection;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    var candidates: std.ArrayList(?model.Owned) = .empty;
    defer {
        for (candidates.items) |*candidate| if (candidate.*) |*resource| resource.deinit();
        candidates.deinit(self.allocator);
    }
    var selected: ?usize = null;
    var storage: usize = 0;
    var first_error: ?model.Error = null;
    var failed_listener = false;
    for (update.response.value.resources) |raw| {
        var candidate = @import("decode.zig").decode(self.allocator, raw.value, self.options.limits) catch |err| {
            if (!self.options.fail_on_data_errors) return err;
            const name = raw_name.first(raw.value, 1) orelse return err;
            if (std.mem.eql(u8, name, self.options.listener_name)) failed_listener = true;
            if (first_error == null) first_error = err;
            continue;
        };
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
        const projection = try Projection.create(self.allocator, source, hcm.max_stream_duration, hcm.rbac_config, hcm.fault_config, hcm.rbac_name, hcm.fault_name);
        defer projection.release();
        const revision = try self.publish(client, projection, destination, deadline);
        if (subscription) |*prepared| prepared.commit();
        if (self.listener) |*previous| previous.deinit();
        self.listener = candidates.items[index];
        candidates.items[index] = null;
        self.rbac_config = hcm.rbac_config;
        self.rbac_name = hcm.rbac_name;
        self.fault_config = hcm.fault_config;
        self.fault_name = hcm.fault_name;
        if (self.routes) |previous| previous.release();
        self.routes = source;
        source_owned = false;
        if (first_error) |err| return err;
        return revision;
    }
    // A response may precede a newly added subscription. Only a previously
    // accepted LDS resource can be deleted by omission.
    if (self.listener == null) {
        if (first_error) |err| return err;
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }
    if (self.options.ignore_resource_deletion and !failed_listener) {
        if (first_error) |err| return err;
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }
    const empty = try self.empty("_");
    defer empty.release();
    const projection = try Projection.create(self.allocator, empty, null, null, null, null, null);
    defer projection.release();
    const revision = try self.publish(client, projection, destination, deadline);
    if (self.listener) |*previous| previous.deinit();
    self.listener = null;
    self.rbac_config = null;
    self.rbac_name = null;
    self.fault_config = null;
    self.fault_name = null;
    if (self.routes) |previous| previous.release();
    self.routes = null;
    // Keep the last named RDS subscription; empty names would be wildcard.
    if (first_error) |err| return err;
    return revision;
}

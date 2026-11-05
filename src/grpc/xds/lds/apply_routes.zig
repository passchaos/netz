//! Late RDS cannot restore inline/deleted listeners; cached data is immutable.
const std = @import("std");
const ctl = @import("controller.zig");
const ads = @import("../ads.zig");
const rds = @import("../rds.zig");
const shared = @import("../../channel/shared.zig");
const raw_name = @import("../raw_name.zig");
const Projection = @import("projection.zig").Projection;
pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    var candidates: std.ArrayList(*rds.Snapshot) = .empty;
    defer {
        for (candidates.items) |snapshot| snapshot.release();
        candidates.deinit(self.allocator);
    }
    var storage: usize = 0;
    var first_error: ?rds.Error = null;
    var failed_name: ?[]const u8 = null;
    for (update.response.value.resources) |raw| {
        const snapshot = rds.Snapshot.create(self.allocator, raw.value, self.options.limits.rds, self.routeOptions()) catch |err| {
            if (!self.options.fail_on_data_errors) return err;
            const name = raw_name.first(raw.value, 1) orelse return err;
            if (first_error == null) first_error = err;
            failed_name = name;
            continue;
        };
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
    const listener = self.listener orelse {
        if (first_error) |err| return err;
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    };
    if (listener.value.hcm.route_source != .rds) {
        // Inline listeners do not consume RDS, but malformed resources must
        // still be rejected before the update is acknowledged.
        if (first_error) |err| return err;
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }
    const name = listener.value.hcm.route_source.rds;
    if (failed_name) |invalid| if (std.mem.eql(u8, invalid, name)) {
        const empty = try self.empty(name);
        defer empty.release();
        const projection = try Projection.create(self.allocator, empty, listener.value.hcm.max_stream_duration);
        defer projection.release();
        _ = try self.publish(client, projection, destination, deadline);
        empty.retain();
        if (self.routes) |previous| previous.release();
        self.routes = empty;
        self.routes_accepted = false;
        return first_error.?;
    };
    var selected: ?*rds.Snapshot = null;
    for (candidates.items) |snapshot| if (std.mem.eql(u8, name, snapshot.resource.value.name)) {
        selected = snapshot;
    };
    // RDS omission is not deletion. Keep the immutable cached projection and
    // do not turn an unanswered new subscription into an empty accepted image.
    const snapshot = selected orelse {
        if (first_error) |err| return err;
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    };
    const projection = try Projection.create(self.allocator, snapshot, listener.value.hcm.max_stream_duration);
    defer projection.release();
    const revision = try self.publish(client, projection, destination, deadline);
    snapshot.retain();
    if (self.routes) |previous| previous.release();
    self.routes = snapshot;
    self.routes_accepted = true;
    if (first_error) |err| return err;
    return revision;
}

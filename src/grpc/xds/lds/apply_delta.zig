//! Delta listener and route-config publication. Payload-free heartbeats reuse
//! the accepted image; explicit removal publishes a rejecting configuration.
const std = @import("std");
const ctl = @import("controller.zig");
const model = @import("model.zig");
const decode = @import("decode.zig");
const rds = @import("../rds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Projection = @import("projection.zig").Projection;

fn hasName(names: []const []const u8, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}

pub fn applyListener(self: *ctl.Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    const response = update.response.value;
    var candidates: std.ArrayList(?model.Owned) = .empty;
    defer {
        for (candidates.items) |*candidate| if (candidate.*) |*resource| resource.deinit();
        candidates.deinit(self.allocator);
    }
    var selected: ?usize = null;
    var selected_ttl: ?delta.codec.Duration = null;
    var heartbeat = false;
    var heartbeat_ttl: ?delta.codec.Duration = null;
    var storage: usize = 0;
    for (response.resources) |raw| {
        if (std.mem.eql(u8, raw.name, self.options.listener_name)) {
            if (raw.resource == null) {
                heartbeat = true;
                heartbeat_ttl = raw.ttl;
                continue;
            }
        }
        const any = raw.resource orelse continue;
        var candidate = try decode.decode(self.allocator, any.value, self.options.limits);
        errdefer candidate.deinit();
        if (!std.mem.eql(u8, candidate.value.name, raw.name)) return error.InvalidDiscoveryMessage;
        storage = std.math.add(usize, storage, candidate.storageBytes()) catch return error.LdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.LdsLimitExceeded;
        if (std.mem.eql(u8, candidate.value.name, self.options.listener_name)) {
            selected = candidates.items.len;
            selected_ttl = raw.ttl;
        }
        try candidates.append(self.allocator, candidate);
    }
    if (hasName(response.removed, self.options.listener_name)) {
        if (self.listener == null) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        if (self.options.ignore_resource_deletion) {
            return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        }
        var subscription = try client.subscriptions.prepare(rds.type_url, &.{});
        defer subscription.deinit();
        const empty = try self.empty("_");
        defer empty.release();
        const projection = try Projection.create(self.allocator, empty, null);
        defer projection.release();
        const revision = try self.publishDelta(client, projection, destination, deadline);
        subscription.commit();
        if (self.listener) |*previous| previous.deinit();
        self.listener = null;
        if (self.routes) |previous| previous.release();
        self.routes = null;
        self.routes_accepted = false;
        self.listener_deadline = null;
        self.routes_deadline = null;
        return revision;
    }
    if (selected) |index| {
        const candidate = &candidates.items[index].?;
        const hcm = candidate.value.hcm;
        const listener_deadline = try delta.codec.ttlDeadline(client.sender.state.io, selected_ttl);
        var subscription = try client.subscriptions.prepare(rds.type_url, if (hcm.route_source == .rds) &.{hcm.route_source.rds} else &.{});
        defer subscription.deinit();
        const same = if (self.listener) |previous| self.routes_accepted and previous.value.hcm.route_source == .rds and hcm.route_source == .rds and std.mem.eql(u8, previous.value.hcm.route_source.rds, hcm.route_source.rds) else false;
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
        const revision = try self.publishDelta(client, projection, destination, deadline);
        subscription.commit();
        if (self.listener) |*previous| previous.deinit();
        self.listener = candidates.items[index];
        candidates.items[index] = null;
        if (self.routes) |previous| previous.release();
        self.routes = source;
        self.routes_accepted = hcm.route_source == .inline_rds or same;
        self.listener_deadline = listener_deadline;
        if (hcm.route_source == .inline_rds or !same) self.routes_deadline = null;
        source_owned = false;
        return revision;
    }
    // A heartbeat for a listener we have never accepted is not a valid
    // unchanged-resource notification. A heartbeat without a TTL clears the
    // resource timer, as the Envoy Resource contract requires.
    if (heartbeat) {
        if (self.listener == null) return error.InvalidDiscoveryMessage;
        self.listener_deadline = try delta.codec.ttlDeadline(client.sender.state.io, heartbeat_ttl);
    }
    return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
}

pub fn applyRoutes(self: *ctl.Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    const response = update.response.value;
    var candidates: std.ArrayList(*rds.Snapshot) = .empty;
    defer {
        for (candidates.items) |snapshot| snapshot.release();
        candidates.deinit(self.allocator);
    }
    const listener = self.listener orelse return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    if (listener.value.hcm.route_source != .rds) {
        // Inline listeners do not consume RDS, but malformed resources must
        // still be rejected before the update is acknowledged.
        for (response.resources) |raw| {
            const any = raw.resource orelse continue;
            const snapshot = try rds.Snapshot.create(self.allocator, any.value, self.options.limits.rds, self.routeOptions());
            if (!std.mem.eql(u8, snapshot.resource.value.name, raw.name)) {
                snapshot.release();
                return error.InvalidDiscoveryMessage;
            }
            snapshot.release();
        }
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }
    const name = listener.value.hcm.route_source.rds;
    var selected: ?*rds.Snapshot = null;
    var selected_ttl: ?delta.codec.Duration = null;
    var heartbeat = false;
    var heartbeat_ttl: ?delta.codec.Duration = null;
    var storage: usize = 0;
    for (response.resources) |raw| {
        if (std.mem.eql(u8, raw.name, name)) {
            if (raw.resource == null) {
                heartbeat = true;
                heartbeat_ttl = raw.ttl;
                continue;
            }
        }
        const any = raw.resource orelse continue;
        const snapshot = try rds.Snapshot.create(self.allocator, any.value, self.options.limits.rds, self.routeOptions());
        errdefer snapshot.release();
        if (!std.mem.eql(u8, snapshot.resource.value.name, raw.name)) return error.InvalidDiscoveryMessage;
        storage = std.math.add(usize, storage, snapshot.resource.arena.queryCapacity()) catch return error.LdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.LdsLimitExceeded;
        try candidates.append(self.allocator, snapshot);
        if (std.mem.eql(u8, name, snapshot.resource.value.name)) {
            selected = snapshot;
            selected_ttl = raw.ttl;
        }
    }
    if (hasName(response.removed, name)) {
        if (!self.routes_accepted or self.routes == null) return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        if (self.options.ignore_resource_deletion) {
            return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        }
        const empty = try self.empty(name);
        defer empty.release();
        const projection = try Projection.create(self.allocator, empty, listener.value.hcm.max_stream_duration);
        defer projection.release();
        const revision = try self.publishDelta(client, projection, destination, deadline);
        empty.retain();
        if (self.routes) |previous| previous.release();
        self.routes = empty;
        self.routes_accepted = false;
        self.routes_deadline = null;
        return revision;
    }
    if (selected) |snapshot| {
        const routes_deadline = try delta.codec.ttlDeadline(client.sender.state.io, selected_ttl);
        if (self.routes_accepted and self.routes != null and std.mem.eql(u8, self.routes.?.resource.wire, snapshot.resource.wire)) {
            self.routes_deadline = routes_deadline;
            return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        }
        const projection = try Projection.create(self.allocator, snapshot, listener.value.hcm.max_stream_duration);
        defer projection.release();
        const revision = try self.publishDelta(client, projection, destination, deadline);
        snapshot.retain();
        if (self.routes) |previous| previous.release();
        self.routes = snapshot;
        self.routes_accepted = true;
        self.routes_deadline = routes_deadline;
        return revision;
    }
    if (heartbeat) {
        if (!self.routes_accepted or self.routes == null) return error.InvalidDiscoveryMessage;
        self.routes_deadline = try delta.codec.ttlDeadline(client.sender.state.io, heartbeat_ttl);
        return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    }
    return try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
}

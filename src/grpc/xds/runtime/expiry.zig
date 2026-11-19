//! Authority-scoped delta TTL withdrawal with cache and version staging.
const std = @import("std");
const ctl = @import("controller.zig");
const Plan = @import("plan.zig").Plan;
const SecretPlan = @import("apply_sds.zig").SecretPlan;
const cloneCluster = @import("apply_sds.zig").cloneCluster;
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const sds = @import("../sds.zig");
const rds = @import("../rds.zig");
const Projection = @import("../lds/projection.zig").Projection;
const discovery = @import("discovery.zig");
const shared = @import("../../channel/shared.zig");
const Removed = struct { type_url: []const u8, name: []const u8 };

fn due(value: ?std.Io.Clock.Timestamp, now: std.Io.Clock.Timestamp) bool {
    return if (value) |deadline| deadline.raw.nanoseconds <= now.raw.nanoseconds else false;
}
fn removed(values: []const Removed, url: []const u8, name: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value.type_url, url) and std.mem.eql(u8, value.name, name)) return true;
    }
    return false;
}
fn desired(names: []const []const u8, name: []const u8) bool {
    for (names) |value| if (std.mem.eql(u8, value, name)) return true;
    return false;
}

/// Allocate version maps before publication, then transfer without a fallible
/// `forget` after caches have committed. Desired CDS/EDS/SDS names are derived
/// from the same plan that publication uses, so pruning is staged too.
const Versions = struct {
    const Change = struct { type_url: []const u8, versions: []delta.subscriptions.Version, storage: []u8 };
    client: *delta.Client,
    changes: std.ArrayList(Change) = .empty,

    fn prepare(client: *delta.Client, removals: []const Removed, plan: *Plan, clear_rds: bool) ctl.Error!Versions {
        var self = Versions{ .client = client };
        errdefer self.deinit();
        const allocator = client.subscriptions.allocator;
        const cds_names = try plan.cdsNames();
        defer plan.allocator.free(cds_names);
        const eds_names = try plan.edsNames();
        defer plan.allocator.free(eds_names);
        const sds_names = try plan.sdsNames();
        defer plan.allocator.free(sds_names);
        for ([_][]const u8{ lds.type_url, rds.type_url, cds.type_url, eds.type_url, sds.type_url }, 0..) |url, type_index| {
            const current = client.subscriptions.find(url) orelse continue;
            const names: []const []const u8 = switch (type_index) {
                2 => cds_names,
                3 => eds_names,
                4 => sds_names,
                1 => if (clear_rds) &.{} else current.names,
                else => current.names,
            };
            var changed = false;
            var count: usize = 0;
            var bytes: usize = 0;
            for (current.versions) |version| {
                if (removed(removals, url, version.name) or !desired(names, version.name)) {
                    changed = true;
                    continue;
                }
                count += 1;
                bytes = std.math.add(usize, bytes, version.name.len + version.version.len) catch return error.DiscoveryLimitExceeded;
            }
            if (!changed) continue;
            const versions = try allocator.alloc(delta.subscriptions.Version, count);
            errdefer allocator.free(versions);
            const storage = try allocator.alloc(u8, bytes);
            errdefer allocator.free(storage);
            var used: usize = 0;
            var index: usize = 0;
            for (current.versions) |version| {
                if (removed(removals, url, version.name) or !desired(names, version.name)) continue;
                const name = storage[used..][0..version.name.len];
                used += version.name.len;
                @memcpy(name, version.name);
                const value = storage[used..][0..version.version.len];
                used += version.version.len;
                @memcpy(value, version.version);
                versions[index] = .{ .name = name, .version = value, .accepted_ns = version.accepted_ns };
                index += 1;
            }
            try self.changes.append(allocator, .{ .type_url = url, .versions = versions, .storage = storage });
        }
        return self;
    }
    fn deinit(self: *Versions) void {
        const allocator = self.client.subscriptions.allocator;
        for (self.changes.items) |value| {
            allocator.free(value.versions);
            allocator.free(value.storage);
        }
        self.changes.deinit(allocator);
    }
    fn commit(self: *Versions) void {
        const allocator = self.client.subscriptions.allocator;
        for (self.changes.items) |*value| {
            const current = self.client.subscriptions.find(value.type_url) orelse continue;
            allocator.free(current.versions);
            allocator.free(current.versions_storage);
            current.versions = value.versions;
            current.versions_storage = value.storage;
            value.versions = &.{};
            value.storage = &.{};
        }
    }
};

pub fn expireDelta(self: *ctl.Controller, client: *delta.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    if (self.latest == null) return error.XdsNotStarted;
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    const io = client.sender.state.io;
    const now = std.Io.Clock.Timestamp.now(io, .awake);
    var removals: std.ArrayList(Removed) = .empty;
    defer removals.deinit(self.allocator);
    var secrets = try SecretPlan.init(self);
    defer secrets.deinit();
    var projection: ?*Projection = null;
    defer if (projection) |value| value.release();
    var rejecting: ?*rds.Snapshot = null;
    defer if (rejecting) |value| value.release();
    var subscription: ?discovery.Prepared = null;
    defer if (subscription) |*value| value.deinit();
    var drop_listener = false;
    var drop_routes = false;
    var clear_listener_timer = false;
    var clear_route_timer = false;
    if (self.listener) |*listener| {
        if (self.inResponseScope(listener.options.listener_name) and due(listener.listener_deadline, now)) {
            clear_listener_timer = true;
            if (listener.listener) |current| {
                drop_listener = true;
                try removals.append(self.allocator, .{ .type_url = lds.type_url, .name = listener.options.listener_name });
                if (current.value.hcm.route_source == .rds) {
                    const name = current.value.hcm.route_source.rds;
                    try removals.append(self.allocator, .{ .type_url = rds.type_url, .name = name });
                    if (listener.options.discovery_router != null or client.subscriptions.find(rds.type_url) != null) {
                        subscription = try discovery.prepare(client, listener.options.discovery_router, rds.type_url, &.{}, deadline);
                    }
                }
                rejecting = try listener.empty("_");
                projection = try Projection.create(self.allocator, rejecting.?, null, null, null, null, null, null, null);
            }
        }
        if (!drop_listener and due(listener.routes_deadline, now)) {
            const name: ?[]const u8 = if (listener.listener) |current| if (current.value.hcm.route_source == .rds) current.value.hcm.route_source.rds else null else null;
            if (name) |resource_name| {
                if (self.inResponseScope(resource_name)) {
                    clear_route_timer = true;
                    if (listener.routes_accepted and listener.routes != null) {
                        drop_routes = true;
                        try removals.append(self.allocator, .{ .type_url = rds.type_url, .name = resource_name });
                        rejecting = try listener.empty(resource_name);
                        const hcm = listener.listener.?.value.hcm;
                        projection = try Projection.create(self.allocator, rejecting.?, hcm.max_stream_duration, listener.rbac_config, listener.fault_config, listener.rbac_name, listener.fault_name, listener.header_mutation_config, listener.header_mutation_name);
                    }
                }
            } else if (self.inResponseScope(listener.options.listener_name)) clear_route_timer = true;
        }
    }
    var plan = try Plan.create(self, projection);
    defer plan.deinit();
    var changed = false;
    for (plan.entries.items) |*item| {
        if (self.inResponseScope(item.identity.name) and due(item.cds_deadline, now)) {
            item.cds_deadline = null;
            if (item.cluster != null) {
                try removals.append(self.allocator, .{ .type_url = cds.type_url, .name = item.identity.name });
                if (item.cluster) |old| old.release();
                if (item.snapshot) |old| old.release();
                item.cluster = null;
                item.snapshot = null;
                item.cds_seen = true;
                item.eds_seen = false;
                changed = true;
            }
        }
        const cluster = item.cluster orelse {
            if (self.inResponseScope(item.identity.name)) item.eds_deadline = null;
            continue;
        };
        const name = cluster.resource.value.edsName();
        if (!self.inResponseScope(name) or !due(item.eds_deadline, now)) continue;
        try removals.append(self.allocator, .{ .type_url = eds.type_url, .name = name });
        // TLS projection observes the accepted CDS source policy. TTL expiry
        // itself remains effective with ignore_resource_deletion, matching the
        // existing runtime contract for an explicit resource lifetime.
        const saved_options = self.options;
        const saved_listener_options = if (self.listener) |listener| listener.options else null;
        defer {
            self.options = saved_options;
            if (self.listener) |*listener| if (saved_listener_options) |options| {
                listener.options = options;
            };
        }
        if (cluster.discovery_source) |source| self.applyServerFeatures(source.server);
        if (cluster.pending_eds != null) {
            const staged = try cloneCluster(self, cluster);
            errdefer staged.release();
            try self.resolveClusterTls(staged);
            staged.clearPendingEds();
            cluster.release();
            item.cluster = staged;
        }
        const empty = try self.emptyEds(io, item.cluster.?);
        if (item.snapshot) |old| old.release();
        item.snapshot = empty;
        item.eds_seen = true;
        item.eds_deadline = null;
        changed = true;
    }
    var iterator = self.sds_secrets.iterator();
    while (iterator.next()) |cached| {
        if (!self.inResponseScope(cached.key_ptr.*) or !due(cached.value_ptr.*.deadline, now)) continue;
        try removals.append(self.allocator, .{ .type_url = sds.type_url, .name = cached.key_ptr.* });
        secrets.remove(cached.key_ptr.*);
    }
    if (secrets.changed) changed = (try secrets.stageClusters(&plan, io)) or changed;
    var versions = try Versions.prepare(client, removals.items, &plan, subscription != null);
    defer versions.deinit();
    const revision = if (projection) |next|
        try self.publishDelta(client, &plan, next, true, destination, deadline)
    else if (changed)
        try self.publishDelta(client, &plan, self.latest.?, false, destination, deadline)
    else
        try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    if (projection == null and !changed) {
        const old = self.entries;
        self.entries = plan.entries;
        plan.entries = old;
    }
    if (subscription) |*value| value.commit();
    if (self.listener) |*listener| {
        if (drop_listener) {
            if (listener.listener) |*old| old.deinit();
            listener.listener = null;
            listener.rbac_config = null;
            listener.rbac_name = null;
            listener.fault_config = null;
            listener.fault_name = null;
            listener.header_mutation_config = null;
            listener.header_mutation_name = null;
            if (listener.routes) |old| old.release();
            listener.routes = null;
            listener.routes_accepted = false;
            listener.listener_deadline = null;
            listener.routes_deadline = null;
        } else {
            if (drop_routes) {
                rejecting.?.retain();
                if (listener.routes) |old| old.release();
                listener.routes = rejecting;
                listener.routes_accepted = false;
            }
            if (clear_listener_timer) listener.listener_deadline = null;
            if (clear_route_timer) listener.routes_deadline = null;
        }
    }
    secrets.commit();
    versions.commit();
    _ = try client.flushWithDeadline(deadline);
    return revision;
}

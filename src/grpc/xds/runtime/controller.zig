//! Automatic listener/router/cluster/endpoint dependency staging for one caller.
const std = @import("std");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const bootstrap = @import("../bootstrap.zig");
const rds = @import("../rds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const shared = @import("../../channel/shared.zig");
const tls_material = @import("../tls_material.zig");
const lrs = @import("../lrs.zig");
const sds = @import("../sds.zig");
const entries = @import("entry.zig");
const Plan = @import("plan.zig").Plan;
const Target = @import("target.zig").Target;
pub const Options = @import("options.zig").Options;
pub const Error = @import("errors.zig").PublishError || lds.Error || cds.Error || eds.Error || tls_material.Error || lrs.RunnerError || sds.Error || error{ InvalidXdsOptions, XdsNotStarted, DuplicateSdsResource, InvalidXdsResourceName };
pub const CachedSecret = struct {
    owned: sds.Owned,
    /// Delta `Resource.ttl` deadline; null means no timer.
    deadline: ?std.Io.Clock.Timestamp = null,
};
/// State of a resource from the controller's point of view. A resource that
/// has not been delivered yet is `requested`; its initial-fetch timer moves it
/// to `does_not_exist` or, with `resource_timer_is_transient_error`, to
/// `timeout`. Delivery replaces the timer with `acked`.
pub const ResourceStatus = enum { requested, acked, does_not_exist, timeout };
const ResourceTimer = struct {
    type_url: []u8,
    name: []u8,
    deadline: std.Io.Clock.Timestamp,
    status: ResourceStatus = .requested,
    /// EDS wire published by the does-not-exist path. It distinguishes that
    /// placeholder from a real delivery when the status is re-evaluated.
    timeout_wire: ?[]u8 = null,
    fn deinit(self: *ResourceTimer, allocator: std.mem.Allocator) void {
        allocator.free(self.type_url);
        allocator.free(self.name);
        if (self.timeout_wire) |wire| allocator.free(wire);
        self.* = undefined;
    }
};
pub const Controller = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    options: Options,
    listener: ?lds.Controller = null,
    entries: std.ArrayList(entries.Entry) = .empty,
    projections: std.ArrayList(*@import("../lds/projection.zig").Projection) = .empty,
    latest: ?*@import("../lds/projection.zig").Projection = null,
    local_json: ?[]const u8 = null,
    local_captured: bool = false,
    lrs_runner: ?*lrs.Runner = null,
    /// Accepted xdstp authorities; empty accepts only old-style names.
    authorities: []const []const u8 = &.{},
    /// SotW/delta SDS cache keyed by secret name. Secrets are copied into each
    /// referencing cluster, so cache entries can be replaced independently.
    sds_secrets: std.StringHashMapUnmanaged(*CachedSecret) = .empty,
    /// Owned initial-fetch timers, refreshed from the client's desired names.
    resource_timers: std.ArrayList(ResourceTimer) = .empty,
    pub fn create(gpa: std.mem.Allocator, options: Options) Error!*Controller {
        if (options.limits.max_clusters == 0 or options.limits.max_projections == 0 or options.limits.max_storage_bytes == 0 or options.target.authority.len == 0 or options.target.attempt_delay.nanoseconds <= 0) return error.InvalidXdsOptions;
        if (options.lrs) |value| {
            if (value.poll_interval.nanoseconds <= 0 or value.connect_timeout.nanoseconds <= 0) return error.InvalidXdsOptions;
        }
        if (options.resource_timer_timeout) |value| {
            if (value.nanoseconds <= 0) return error.InvalidXdsOptions;
        }
        const self = try gpa.create(Controller);
        self.* = .{ .allocator = gpa, .arena = .init(gpa), .options = options };
        errdefer self.deinit();
        self.options.target.authority = try self.arena.allocator().dupe(u8, options.target.authority);
        {
            var count: usize = if (options.authority != null) 1 else 0;
            count += options.additional_authorities.len;
            const authorities = try self.arena.allocator().alloc([]const u8, count);
            var index: usize = 0;
            if (options.authority) |authority| {
                if (authority.len == 0 or !std.unicode.utf8ValidateSlice(authority)) return error.InvalidXdsOptions;
                authorities[index] = try self.arena.allocator().dupe(u8, authority);
                index += 1;
            }
            for (options.additional_authorities) |authority| {
                if (authority.len == 0 or !std.unicode.utf8ValidateSlice(authority)) return error.InvalidXdsOptions;
                authorities[index] = try self.arena.allocator().dupe(u8, authority);
                index += 1;
            }
            self.authorities = authorities;
        }
        if (!@import("../resource_name.zig").matchesAuthorities(options.listener_name, self.authorities, lds.type_url)) {
            return error.InvalidXdsResourceName;
        }
        if (self.options.target.tls) |*tls| tls.host = try self.arena.allocator().dupe(u8, tls.host);
        if (options.local_service_config_json) |json| {
            if (json.len > options.limits.max_storage_bytes) return error.XdsLimitExceeded;
            self.local_json = try self.arena.allocator().dupe(u8, json);
            self.local_captured = true;
        }
        self.listener = try lds.Controller.init(gpa, .{ .listener_name = options.listener_name, .authority = self.options.target.authority, .max_header_bytes = options.max_header_bytes, .limits = options.limits.lds, .ignore_resource_deletion = options.ignore_resource_deletion, .fail_on_data_errors = options.fail_on_data_errors, .trusted_xds_server = options.trusted_xds_server, .publisher = .{ .context = self, .publish_fn = publishHook }, .delta_publisher = .{ .context = self, .publish_fn = publishDeltaHook } });
        return self;
    }
    /// Apply the current bootstrap server's feature set to this live
    /// controller. Call it after creation and after a failover that selects a
    /// server with different `server_features`; the listener policy is updated
    /// alongside the controller options.
    pub fn applyServerFeatures(self: *Controller, server: bootstrap.Server) void {
        self.options.applyServerFeatures(server);
        if (self.listener) |*listener| {
            listener.options.ignore_resource_deletion = server.ignore_resource_deletion;
            listener.options.fail_on_data_errors = server.fail_on_data_errors;
            listener.options.trusted_xds_server = server.trusted_xds_server;
        }
    }
    pub fn deinit(self: *Controller) void {
        if (self.lrs_runner) |runner| runner.deinit();
        var secrets = self.sds_secrets.iterator();
        while (secrets.next()) |item| {
            item.value_ptr.*.owned.deinit();
            self.allocator.destroy(item.value_ptr.*);
        }
        self.sds_secrets.deinit(self.allocator);
        if (self.listener) |*value| value.deinit();
        for (self.projections.items) |value| value.release();
        self.projections.deinit(self.allocator);
        for (self.entries.items) |*value| value.deinit();
        self.entries.deinit(self.allocator);
        for (self.resource_timers.items) |*timer| timer.deinit(self.allocator);
        self.resource_timers.deinit(self.allocator);
        self.arena.deinit();
        self.allocator.destroy(self);
    }
    fn ensureLrsRunner(
        self: *Controller,
        destination: shared.SharedChannel,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.lrs_runner != null) return;
        const options = self.options.lrs orelse return;
        const remaining = deadline.durationFromNow(
            destination.state.io,
        ).raw.nanoseconds;
        if (remaining <= 0) return error.Timeout;
        const connect_ns = @min(
            options.connect_timeout.nanoseconds,
            remaining,
        );
        const runner = try lrs.Runner.create(
            self.allocator,
            destination.state.io,
            options.sender,
            options.control_plane,
            destination,
            .{
                .client = options.client,
                .reporter = options.reporter,
                .poll_interval = options.poll_interval,
                .connect_timeout = .fromNanoseconds(connect_ns),
            },
        );
        errdefer runner.deinit();
        try runner.start();
        self.lrs_runner = runner;
    }
    /// Validate an old-style or xdstp resource name against the configured
    /// authority and resource type.
    pub fn validateResourceName(self: *const Controller, name: []const u8, type_url: []const u8) @import("errors.zig").PublishError!void {
        if (!@import("../resource_name.zig").matchesAuthorities(name, self.authorities, type_url)) {
            return error.InvalidXdsResourceName;
        }
    }
    /// Resolve a cluster's SDS references from the current secret cache.
    /// Missing secrets leave the cluster pending instead of publishing it
    /// without transport security.
    pub fn resolveClusterTls(self: *Controller, cluster: *entries.Cluster) Error!void {
        const refs = cluster.resource.value.tls_sds orelse return;
        const certificate = if (refs.certificate) |name| self.sds_secrets.get(name) else null;
        const validation = if (refs.validation) |name| self.sds_secrets.get(name) else null;
        if ((refs.certificate != null and certificate == null) or
            (refs.validation != null and validation == null))
        {
            _ = cluster.tls_arena.reset(.retain_capacity);
            cluster.tls_override = null;
            return;
        }
        try cluster.applySds(
            if (certificate) |value| value.owned.value else null,
            if (validation) |value| value.owned.value else null,
        );
    }
    /// Replace the cached SotW secret set and resolve every referencing
    /// cluster. Returns true when any cached secret changed.
    pub fn updateSecrets(
        self: *Controller,
        decoded: []const *CachedSecret,
    ) Error!bool {
        var changed = decoded.len != self.sds_secrets.count();
        for (decoded) |value| {
            const name = value.owned.value.name;
            if (self.sds_secrets.get(name)) |old| {
                if (!std.mem.eql(u8, old.owned.wire, value.owned.wire)) changed = true;
            } else changed = true;
        }
        // SotW SDS is complete for the subscribed type: omitted names expire.
        var iterator = self.sds_secrets.iterator();
        while (iterator.next()) |item| {
            var present = false;
            for (decoded) |value| {
                if (std.mem.eql(u8, item.key_ptr.*, value.owned.value.name)) {
                    present = true;
                    break;
                }
            }
            if (!present) changed = true;
        }
        if (!changed) return false;

        try self.sds_secrets.ensureUnusedCapacity(self.allocator, @intCast(decoded.len));
        var names: std.ArrayList([]const u8) = .empty;
        defer names.deinit(self.allocator);
        try names.ensureTotalCapacity(self.allocator, self.sds_secrets.count());
        var all = self.sds_secrets.iterator();
        while (all.next()) |item| names.appendAssumeCapacity(item.key_ptr.*);
        for (names.items) |name| {
            const removed = self.sds_secrets.fetchRemove(name).?;
            removed.value.owned.deinit();
            self.allocator.destroy(removed.value);
        }
        for (decoded) |value| {
            self.sds_secrets.putAssumeCapacity(value.owned.value.name, value);
        }
        return true;
    }
    /// Rebuild the projected snapshot of one entry after a TLS change.
    pub fn reproject(self: *Controller, io: std.Io, item: *entries.Entry) Error!void {
        const cluster = item.cluster orelse return;
        if (cluster.sdsPending()) {
            if (cluster.resource.value.isEds()) {
                if (item.eds_seen) if (item.snapshot) |old| try cluster.setPendingEds(old.resource.wire);
                if (item.snapshot) |old| old.release();
                item.snapshot = try self.emptyEds(io, cluster);
                item.eds_seen = false;
            } else {
                if (item.snapshot) |old| old.release();
                item.snapshot = null;
            }
            return;
        }
        if (cluster.resource.value.isEds()) {
            if (!item.eds_seen) {
                if (cluster.pending_eds) |wire| {
                    const snapshot = try self.project(io, cluster, wire);
                    if (item.snapshot) |old| old.release();
                    item.snapshot = snapshot;
                    item.eds_seen = true;
                } else if (item.snapshot == null) item.snapshot = try self.emptyEds(io, cluster);
                return;
            }
            const wire = item.snapshot.?.resource.wire;
            const snapshot = try self.project(io, cluster, wire);
            if (item.snapshot) |old| old.release();
            item.snapshot = snapshot;
        } else if (cluster.resource.value.isDns() or cluster.resource.value.isAggregate()) {
            if (item.snapshot) |old| old.release();
            item.snapshot = null;
        } else {
            const snapshot = try self.project(io, cluster, cluster.resource.value.inline_assignment);
            if (item.snapshot) |old| old.release();
            item.snapshot = snapshot;
        }
    }
    fn cleanProjections(self: *Controller) void {
        var i: usize = 0;
        while (i < self.projections.items.len) {
            const value = self.projections.items[i];
            if (value != self.latest and value.refs.load(.acquire) == 1) {
                _ = self.projections.orderedRemove(i);
                value.release();
            } else i += 1;
        }
    }
    fn publishPlan(self: *Controller, plan: *Plan, projection: *@import("../lds/projection.zig").Projection, new_projection: bool, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        self.cleanProjections();
        if (new_projection) {
            if (self.projections.items.len >= self.options.limits.max_projections) return error.XdsLimitExceeded;
            try self.projections.ensureUnusedCapacity(self.allocator, 1);
        }
        const target = try Target.create(self.allocator, destination.state.io, plan.entries.items, self.local_json);
        defer target.release();
        var storage = std.math.add(usize, plan.route_storage, target.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        for (plan.entries.items) |entry| {
            if (entry.cluster) |cluster| storage = std.math.add(usize, storage, cluster.resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
            if (entry.snapshot) |snapshot| storage = std.math.add(usize, storage, snapshot.resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        }
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        const revision = try target.publish(destination, projection.descriptor(), deadline);
        // Clusters that leave the inventory must not keep a stale ORCA
        // propagation selection; new/kept selections were applied above.
        for (self.entries.items) |old_entry| {
            var kept = false;
            for (plan.entries.items) |new_entry| {
                if (std.mem.eql(u8, old_entry.identity.name, new_entry.identity.name)) {
                    kept = true;
                    break;
                }
            }
            if (!kept) destination.setLrsPropagation(old_entry.identity.name, .{});
        }
        const old = self.entries;
        self.entries = plan.entries;
        plan.entries = old;
        if (new_projection) {
            projection.retain();
            self.projections.appendAssumeCapacity(projection);
            self.latest = projection;
        }
        self.cleanProjections();
        return revision;
    }
    fn planNames(plan: *Plan) @import("errors.zig").PublishError![3]?[]const []const u8 {
        const cds_names = try plan.cdsNames();
        const eds_names = plan.edsNames() catch |err| {
            plan.allocator.free(cds_names);
            return err;
        };
        const sds_names = plan.sdsNames() catch |err| {
            plan.allocator.free(cds_names);
            plan.allocator.free(eds_names);
            return err;
        };
        return .{ cds_names, eds_names, sds_names };
    }
    pub fn publish(self: *Controller, client: *ads.Client, plan: *Plan, projection: *@import("../lds/projection.zig").Projection, new_projection: bool, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        const names = try planNames(plan);
        defer {
            if (names[0]) |value| self.allocator.free(value);
            if (names[1]) |value| self.allocator.free(value);
            if (names[2]) |value| self.allocator.free(value);
        }
        var requested: [3]ads.subscriptions.Subscription = undefined;
        var count: usize = 0;
        if (names[0]) |value| {
            if (value.len != 0) {
                requested[count] = .{ .type_url = cds.type_url, .names = value };
                count += 1;
            }
        }
        if (names[1]) |value| {
            if (value.len != 0) {
                requested[count] = .{ .type_url = eds.type_url, .names = value };
                count += 1;
            }
        }
        if (names[2]) |value| {
            if (value.len != 0) {
                requested[count] = .{ .type_url = sds.type_url, .names = value };
                count += 1;
            }
        }
        var subscriptions = try client.subscriptions.prepareMany(requested[0..count]);
        defer subscriptions.deinit();
        const revision = try self.publishPlan(plan, projection, new_projection, destination, deadline);
        subscriptions.commit();
        return revision;
    }
    pub fn publishDelta(self: *Controller, client: *delta.Client, plan: *Plan, projection: *@import("../lds/projection.zig").Projection, new_projection: bool, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        const names = try planNames(plan);
        defer {
            if (names[0]) |value| self.allocator.free(value);
            if (names[1]) |value| self.allocator.free(value);
            if (names[2]) |value| self.allocator.free(value);
        }
        var requested: [3]delta.subscriptions.Subscription = undefined;
        var count: usize = 0;
        if (names[0]) |value| {
            // Delta has no wildcard: an empty desired set is a real unsubscribe
            // and must be sent for a type that still has an active subscription.
            if (value.len != 0 or client.subscriptions.find(cds.type_url) != null) {
                requested[count] = .{ .type_url = cds.type_url, .names = value };
                count += 1;
            }
        }
        if (names[1]) |value| {
            if (value.len != 0 or client.subscriptions.find(eds.type_url) != null) {
                requested[count] = .{ .type_url = eds.type_url, .names = value };
                count += 1;
            }
        }
        if (names[2]) |value| {
            if (value.len != 0 or client.subscriptions.find(sds.type_url) != null) {
                requested[count] = .{ .type_url = sds.type_url, .names = value };
                count += 1;
            }
        }
        var subscriptions = try client.subscriptions.prepareMany(requested[0..count]);
        defer subscriptions.deinit();
        const revision = try self.publishPlan(plan, projection, new_projection, destination, deadline);
        subscriptions.commit();
        return revision;
    }
    fn publishHook(pointer: *anyopaque, client: *ads.Client, projection: *@import("../lds/projection.zig").Projection, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        const self: *Controller = @ptrCast(@alignCast(pointer));
        var plan = try Plan.create(self, projection);
        defer plan.deinit();
        return self.publish(client, &plan, projection, true, destination, deadline);
    }
    fn publishDeltaHook(pointer: *anyopaque, client: *delta.Client, projection: *@import("../lds/projection.zig").Projection, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        const self: *Controller = @ptrCast(@alignCast(pointer));
        var plan = try Plan.create(self, projection);
        defer plan.deinit();
        return self.publishDelta(client, &plan, projection, true, destination, deadline);
    }
    pub fn startWithDeadline(self: *Controller, client: *ads.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        if (self.latest != null) return self.synchronizeWithDeadline(client, destination, deadline);
        if (!self.local_captured) {
            const config = destination.state.retainConfig();
            defer if (config) |value| value.release();
            if (config) |value| if (value.json) |json| {
                if (json.len > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
                self.local_json = try self.arena.allocator().dupe(u8, json);
            };
            self.local_captured = true;
        }
        var subscription = try client.subscriptions.prepare(lds.type_url, &.{self.listener.?.options.listener_name});
        defer subscription.deinit();
        const empty = try self.listener.?.empty("_");
        defer empty.release();
        const projection = try @import("../lds/projection.zig").Projection.create(self.allocator, empty, null);
        defer projection.release();
        var plan = try Plan.create(self, projection);
        defer plan.deinit();
        const revision = try self.publish(client, &plan, projection, true, destination, deadline);
        subscription.commit();
        try self.ensureLrsRunner(destination, deadline);
        return revision;
    }
    pub fn synchronizeWithDeadline(self: *Controller, client: *ads.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        const projection = self.latest orelse return error.XdsNotStarted;
        self.cleanProjections();
        var plan = try Plan.create(self, null);
        defer plan.deinit();
        var same = plan.entries.items.len == self.entries.items.len;
        if (same) for (plan.entries.items, self.entries.items) |a, b| {
            if (a.identity != b.identity or a.cluster != b.cluster or a.snapshot != b.snapshot or a.cds_seen != b.cds_seen or a.eds_seen != b.eds_seen) same = false;
        };
        const revision = if (same) try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline) else try self.publish(client, &plan, projection, false, destination, deadline);
        _ = try client.flushWithDeadline(deadline);
        try self.ensureLrsRunner(destination, deadline);
        return revision;
    }
    pub fn applyWithDeadline(self: *Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.latest == null) return error.XdsNotStarted;
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try client.validateUpdate(update);
        const url = update.response.value.type_url;
        if (std.mem.eql(u8, url, lds.type_url) or std.mem.eql(u8, url, rds.type_url)) return self.listener.?.applyWithDeadline(client, update, destination, deadline);
        const revision = if (std.mem.eql(u8, url, cds.type_url))
            try @import("apply_cds.zig").apply(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, eds.type_url))
            try @import("apply_eds.zig").apply(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, sds.type_url))
            try @import("apply_sds.zig").apply(self, client, update, destination, deadline)
        else
            return error.InvalidDiscoveryMessage;
        try client.acceptAppliedUpdate(update);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    pub fn startDeltaWithDeadline(self: *Controller, client: *delta.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        if (self.latest != null) return self.synchronizeDeltaWithDeadline(client, destination, deadline);
        if (!self.local_captured) {
            const config = destination.state.retainConfig();
            defer if (config) |value| value.release();
            if (config) |value| if (value.json) |json| {
                if (json.len > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
                self.local_json = try self.arena.allocator().dupe(u8, json);
            };
            self.local_captured = true;
        }
        var subscription = try client.subscriptions.prepare(lds.type_url, &.{self.listener.?.options.listener_name});
        defer subscription.deinit();
        const empty = try self.listener.?.empty("_");
        defer empty.release();
        const projection = try @import("../lds/projection.zig").Projection.create(self.allocator, empty, null);
        defer projection.release();
        var plan = try Plan.create(self, projection);
        defer plan.deinit();
        const revision = try self.publishDelta(client, &plan, projection, true, destination, deadline);
        subscription.commit();
        try self.ensureLrsRunner(destination, deadline);
        return revision;
    }
    pub fn synchronizeDeltaWithDeadline(self: *Controller, client: *delta.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        const projection = self.latest orelse return error.XdsNotStarted;
        self.cleanProjections();
        var plan = try Plan.create(self, null);
        defer plan.deinit();
        var same = plan.entries.items.len == self.entries.items.len;
        if (same) for (plan.entries.items, self.entries.items) |a, b| {
            if (a.identity != b.identity or a.cluster != b.cluster or a.snapshot != b.snapshot or a.cds_seen != b.cds_seen or a.eds_seen != b.eds_seen) same = false;
        };
        const revision = if (same) try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline) else try self.publishDelta(client, &plan, projection, false, destination, deadline);
        _ = try client.flushWithDeadline(deadline);
        try self.ensureLrsRunner(destination, deadline);
        return revision;
    }
    pub fn applyDeltaWithDeadline(self: *Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.latest == null) return error.XdsNotStarted;
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try client.validateUpdate(update);
        const url = update.response.value.type_url;
        if (std.mem.eql(u8, url, lds.type_url) or std.mem.eql(u8, url, rds.type_url)) return self.listener.?.applyDeltaWithDeadline(client, update, destination, deadline);
        const revision = if (std.mem.eql(u8, url, cds.type_url))
            try @import("apply_delta_cds.zig").apply(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, eds.type_url))
            try @import("apply_delta_eds.zig").apply(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, sds.type_url))
            try @import("apply_delta_sds.zig").apply(self, client, update, destination, deadline)
        else
            return error.InvalidDiscoveryMessage;
        try client.acceptAppliedUpdate(update);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    pub fn nextDeltaExpiry(self: *Controller) ?std.Io.Clock.Timestamp {
        var earliest: ?std.Io.Clock.Timestamp = null;
        if (self.listener) |*listener| {
            if (listener.nextDeadline()) |value| earliest = value;
        }
        for (self.entries.items) |entry| {
            if (entry.cds_deadline) |value| {
                if (earliest == null or value.raw.nanoseconds < earliest.?.raw.nanoseconds) earliest = value;
            }
            if (entry.eds_deadline) |value| {
                if (earliest == null or value.raw.nanoseconds < earliest.?.raw.nanoseconds) earliest = value;
            }
        }
        var secrets = self.sds_secrets.iterator();
        while (secrets.next()) |item| {
            if (item.value_ptr.*.deadline) |value| {
                if (earliest == null or value.raw.nanoseconds < earliest.?.raw.nanoseconds) earliest = value;
            }
        }
        return earliest;
    }
    fn resourceTimerBudget(self: *const Controller) std.Io.Duration {
        if (self.options.resource_timer_timeout) |value| return value;
        return if (self.options.resource_timer_is_transient_error) .fromSeconds(30) else .fromSeconds(15);
    }
    fn cachedResource(self: *const Controller, type_url: []const u8, name: []const u8) bool {
        if (std.mem.eql(u8, type_url, lds.type_url)) {
            const listener = self.listener orelse return false;
            return listener.listener != null and std.mem.eql(u8, listener.options.listener_name, name);
        }
        if (std.mem.eql(u8, type_url, rds.type_url)) {
            const listener = self.listener orelse return false;
            if (!listener.routes_accepted) return false;
            const routes = listener.routes orelse return false;
            return std.mem.eql(u8, routes.resource.value.name, name);
        }
        if (std.mem.eql(u8, type_url, cds.type_url)) {
            for (self.entries.items) |entry| {
                if (std.mem.eql(u8, entry.identity.name, name)) return entry.cds_seen and entry.cluster != null;
            }
            return false;
        }
        if (std.mem.eql(u8, type_url, eds.type_url)) {
            for (self.entries.items) |entry| {
                const cluster = entry.cluster orelse continue;
                if (std.mem.eql(u8, cluster.resource.value.edsName(), name)) return entry.eds_seen and entry.snapshot != null;
            }
            return false;
        }
        if (std.mem.eql(u8, type_url, sds.type_url)) return self.sds_secrets.contains(name);
        return false;
    }
    fn findResourceTimer(self: *Controller, type_url: []const u8, name: []const u8) ?usize {
        for (self.resource_timers.items, 0..) |timer, index| {
            if (std.mem.eql(u8, timer.type_url, type_url) and std.mem.eql(u8, timer.name, name)) return index;
        }
        return null;
    }
    fn resourceTimerDesired(client: anytype, type_url: []const u8, name: []const u8) bool {
        const entry = client.subscriptions.find(type_url) orelse return false;
        for (entry.names) |candidate| if (std.mem.eql(u8, candidate, name)) return true;
        return false;
    }
    /// Reconcile the initial-fetch timers with the client's current desired
    /// names and the controller's accepted state. Callers should invoke the
    /// public timer methods after every discovery step.
    fn refreshResourceTimers(self: *Controller, client: anytype) std.mem.Allocator.Error!void {
        var index: usize = 0;
        while (index < self.resource_timers.items.len) {
            const timer = self.resource_timers.items[index];
            const cached = self.cachedResource(timer.type_url, timer.name);
            if (!resourceTimerDesired(client, timer.type_url, timer.name) or
                (cached and !self.edsTimeoutPlaceholder(timer)))
            {
                self.resource_timers.items[index].deinit(self.allocator);
                _ = self.resource_timers.swapRemove(index);
                continue;
            }
            index += 1;
        }
        const io = client.sender.state.io;
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        const budget = self.resourceTimerBudget();
        const types = [_][]const u8{ lds.type_url, rds.type_url, cds.type_url, eds.type_url, sds.type_url };
        for (types) |type_url| {
            const entry = client.subscriptions.find(type_url) orelse continue;
            for (entry.names) |name| {
                if (self.cachedResource(type_url, name)) continue;
                if (self.findResourceTimer(type_url, name) != null) continue;
                const owned_type = try self.allocator.dupe(u8, type_url);
                errdefer self.allocator.free(owned_type);
                const owned_name = try self.allocator.dupe(u8, name);
                errdefer self.allocator.free(owned_name);
                try self.resource_timers.append(self.allocator, .{
                    .type_url = owned_type,
                    .name = owned_name,
                    .deadline = .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(now.raw.nanoseconds + budget.nanoseconds),
                    },
                });
            }
        }
    }
    /// Expire due initial-fetch timers. The resource remains subscribed; the
    /// status surface reports the grpc-core outcome without changing cached
    /// configuration, because a timed-out resource has never been cached.
    pub fn pollResourceTimers(self: *Controller, client: anytype) Error!void {
        try self.refreshResourceTimers(client);
        const now = std.Io.Clock.Timestamp.now(client.sender.state.io, .awake);
        const expired: ResourceStatus = if (self.options.resource_timer_is_transient_error) .timeout else .does_not_exist;
        for (self.resource_timers.items) |*timer| {
            if (timer.status != .requested) continue;
            if (timer.deadline.raw.nanoseconds > now.raw.nanoseconds) continue;
            timer.status = expired;
        }
    }
    /// Earliest armed initial-fetch timer, or null when none is pending.
    pub fn nextResourceTimerExpiry(self: *Controller, client: anytype) Error!?std.Io.Clock.Timestamp {
        try self.refreshResourceTimers(client);
        var earliest: ?std.Io.Clock.Timestamp = null;
        for (self.resource_timers.items) |timer| {
            if (timer.status != .requested) continue;
            if (earliest == null or timer.deadline.raw.nanoseconds < earliest.?.raw.nanoseconds) earliest = timer.deadline;
        }
        return earliest;
    }
    /// Current resource status, or null when the controller has never observed
    /// this resource and no timer is pending. Call a timer method first so
    /// newly desired names are registered.
    pub fn resourceStatus(self: *Controller, type_url: []const u8, name: []const u8) ?ResourceStatus {
        if (self.findResourceTimer(type_url, name)) |index| {
            const status = self.resource_timers.items[index].status;
            if (status != .requested) return status;
        }
        if (self.cachedResource(type_url, name)) return .acked;
        if (self.findResourceTimer(type_url, name)) |index| return self.resource_timers.items[index].status;
        return null;
    }
    fn resourceVersion(client: anytype, type_url: []const u8, name: []const u8) []const u8 {
        const entry = client.subscriptions.find(type_url) orelse return "";
        if (@TypeOf(client) == *delta.Client) {
            for (entry.versions) |version| {
                if (std.mem.eql(u8, version.name, name)) return version.version;
            }
            return "";
        }
        return entry.version;
    }
    /// Encode one `ClientStatusDiscoveryService` `ClientStatusResponse` for
    /// this controller. Accepted LDS/RDS/CDS/EDS/SDS resources carry their raw
    /// wire bytes and the version the client accepted. SotW reports the type's
    /// accepted version for every resource; delta reports the per-resource
    /// accepted version.
    pub fn encodeClientStatus(
        self: *Controller,
        client: anytype,
        allocator: std.mem.Allocator,
        options: @import("../csds.zig").Options,
    ) Error![]u8 {
        const csds = @import("../csds.zig");
        try self.refreshResourceTimers(client);
        var resources: std.ArrayList(csds.Resource) = .empty;
        defer resources.deinit(allocator);
        if (self.listener) |*listener| {
            if (listener.listener) |*owned| {
                try resources.append(allocator, .{
                    .type_url = lds.type_url,
                    .name = owned.value.name,
                    .wire = owned.wire,
                    .version = resourceVersion(client, lds.type_url, owned.value.name),
                    .status = self.csdsResourceStatus(lds.type_url, owned.value.name),
                });
            }
            if (listener.routes_accepted) {
                if (listener.routes) |routes| {
                    try resources.append(allocator, .{
                        .type_url = rds.type_url,
                        .name = routes.resource.value.name,
                        .wire = routes.resource.wire,
                        .version = resourceVersion(client, rds.type_url, routes.resource.value.name),
                        .status = self.csdsResourceStatus(rds.type_url, routes.resource.value.name),
                    });
                }
            }
        }
        for (self.entries.items) |entry| {
            if (entry.cds_seen) {
                if (entry.cluster) |cluster| {
                    try resources.append(allocator, .{
                        .type_url = cds.type_url,
                        .name = entry.identity.name,
                        .wire = cluster.resource.wire,
                        .version = resourceVersion(client, cds.type_url, entry.identity.name),
                        .status = self.csdsResourceStatus(cds.type_url, entry.identity.name),
                    });
                }
            }
            if (entry.eds_seen) {
                if (entry.snapshot) |snapshot| {
                    const cluster = entry.cluster orelse continue;
                    const name = cluster.resource.value.edsName();
                    try resources.append(allocator, .{
                        .type_url = eds.type_url,
                        .name = name,
                        .wire = snapshot.resource.wire,
                        .version = resourceVersion(client, eds.type_url, name),
                        .status = self.csdsResourceStatus(eds.type_url, name),
                    });
                }
            }
        }
        var secrets = self.sds_secrets.iterator();
        while (secrets.next()) |item| {
            try resources.append(allocator, .{
                .type_url = sds.type_url,
                .name = item.key_ptr.*,
                .wire = item.value_ptr.*.owned.wire,
                .version = resourceVersion(client, sds.type_url, item.key_ptr.*),
                .status = self.csdsResourceStatus(sds.type_url, item.key_ptr.*),
            });
        }
        for (self.resource_timers.items) |timer| {
            if (self.cachedResource(timer.type_url, timer.name)) continue;
            try resources.append(allocator, .{
                .type_url = timer.type_url,
                .name = timer.name,
                .status = self.csdsResourceStatus(timer.type_url, timer.name),
            });
        }
        return csds.encodeResponse(allocator, resources.items, options);
    }
    fn csdsResourceStatus(self: *Controller, type_url: []const u8, name: []const u8) @import("../csds.zig").ClientStatus {
        const status = self.resourceStatus(type_url, name) orelse return .acked;
        return switch (status) {
            .requested => .requested,
            .does_not_exist => .does_not_exist,
            .timeout => .requested,
            .acked => .acked,
        };
    }
    /// True when an expired EDS timer still matches the empty assignment that
    /// its own does-not-exist publication installed. A different wire means a
    /// real delivery replaced the placeholder, so the timer can be dropped.
    fn edsTimeoutPlaceholder(self: *const Controller, timer: ResourceTimer) bool {
        if (timer.status == .requested) return false;
        const wire = timer.timeout_wire orelse return false;
        if (!std.mem.eql(u8, timer.type_url, eds.type_url)) return false;
        for (self.entries.items) |entry| {
            const cluster = entry.cluster orelse continue;
            if (!std.mem.eql(u8, cluster.resource.value.edsName(), timer.name)) continue;
            const snapshot = entry.snapshot orelse return false;
            return std.mem.eql(u8, snapshot.resource.wire, wire);
        }
        return false;
    }
    fn resourceTimerDue(timer: ResourceTimer, now: std.Io.Clock.Timestamp) bool {
        return timer.status == .requested and timer.deadline.raw.nanoseconds <= now.raw.nanoseconds;
    }
    /// Expire due initial-fetch timers and publish the does-not-exist effect.
    /// grpc-core treats a timed-out EDS resource as absent, which netz models
    /// as an empty assignment; LDS/RDS/CDS/SDS resources were never cached, so
    /// their absent configuration already matches. With
    /// `resource_timer_is_transient_error` the timer only reports `timeout`
    /// and publishes nothing. Statuses change only after publication succeeds,
    /// so a failed call can be retried.
    pub fn expireResourceTimersWithDeadline(self: *Controller, client: anytype, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.latest == null) return error.XdsNotStarted;
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try self.refreshResourceTimers(client);
        const io = client.sender.state.io;
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        const expired: ResourceStatus = if (self.options.resource_timer_is_transient_error) .timeout else .does_not_exist;
        var plan = try Plan.create(self, null);
        defer plan.deinit();
        var changed = false;
        if (expired == .does_not_exist) for (self.resource_timers.items) |*timer| {
            if (!resourceTimerDue(timer.*, now)) continue;
            if (!std.mem.eql(u8, timer.type_url, eds.type_url)) continue;
            for (plan.entries.items) |*item| {
                const cluster = item.cluster orelse continue;
                if (!std.mem.eql(u8, cluster.resource.value.edsName(), timer.name)) continue;
                const empty = try self.emptyEds(io, cluster);
                const timeout_wire = try self.allocator.dupe(u8, empty.resource.wire);
                if (timer.timeout_wire) |old| self.allocator.free(old);
                timer.timeout_wire = timeout_wire;
                if (item.snapshot) |old| old.release();
                item.snapshot = empty;
                item.eds_seen = true;
                changed = true;
            }
        };
        const revision = if (changed)
            (if (@TypeOf(client) == *delta.Client)
                try self.publishDelta(client, &plan, self.latest.?, false, destination, deadline)
            else
                try self.publish(client, &plan, self.latest.?, false, destination, deadline))
        else
            try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        for (self.resource_timers.items) |*timer| {
            if (!resourceTimerDue(timer.*, now)) continue;
            timer.status = expired;
        }
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    /// Remove cached secrets whose delta TTL has expired and forget their
    /// accepted versions. Returns true when at least one secret expired.
    fn expireSecrets(
        self: *Controller,
        now: std.Io.Clock.Timestamp,
        client: *delta.Client,
    ) Error!bool {
        var names: std.ArrayList([]const u8) = .empty;
        defer names.deinit(self.allocator);
        var iterator = self.sds_secrets.iterator();
        while (iterator.next()) |item| {
            if (item.value_ptr.*.deadline) |value| {
                if (value.raw.nanoseconds <= now.raw.nanoseconds) {
                    try names.append(self.allocator, item.key_ptr.*);
                }
            }
        }
        if (names.items.len == 0) return false;
        for (names.items) |name| {
            if (client.subscriptions.find(sds.type_url) != null) {
                try client.subscriptions.forget(sds.type_url, name);
            }
            const removed = self.sds_secrets.fetchRemove(name).?;
            removed.value.owned.deinit();
            self.allocator.destroy(removed.value);
        }
        return true;
    }
    /// Expire due TTL resources, republish their removal, and forget their
    /// accepted versions. The caller drives this between delta updates.
    pub fn expireDeltaWithDeadline(self: *Controller, client: *delta.Client, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        if (self.latest == null) return error.XdsNotStarted;
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        const now = std.Io.Clock.Timestamp.now(client.sender.state.io, .awake);
        var revision = try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
        if (self.listener) |*listener| {
            const listener_expired = if (listener.listener_deadline) |value| value.raw.nanoseconds <= now.raw.nanoseconds else false;
            if (listener_expired) {
                revision = try listener.expireListenerWithDeadline(client, destination, deadline);
            } else if (listener.routes_deadline) |value| {
                if (value.raw.nanoseconds <= now.raw.nanoseconds) {
                    revision = try listener.expireRoutesWithDeadline(client, destination, deadline);
                }
            }
        }
        var plan = try Plan.create(self, null);
        defer plan.deinit();
        var changed = false;
        for (plan.entries.items) |*item| {
            if (item.cds_deadline) |value| {
                if (value.raw.nanoseconds <= now.raw.nanoseconds) {
                    if (item.cluster == null) {
                        item.cds_deadline = null;
                    } else {
                        if (client.subscriptions.find(cds.type_url) != null) try client.subscriptions.forget(cds.type_url, item.identity.name);
                        if (item.cluster) |old| old.release();
                        if (item.snapshot) |old| old.release();
                        item.cluster = null;
                        item.snapshot = null;
                        item.cds_seen = true;
                        item.eds_seen = false;
                        item.cds_deadline = null;
                        changed = true;
                    }
                }
            }
            if (item.eds_deadline) |value| {
                if (value.raw.nanoseconds <= now.raw.nanoseconds) {
                    const cluster = item.cluster orelse {
                        item.eds_deadline = null;
                        continue;
                    };
                    if (client.subscriptions.find(eds.type_url) != null) try client.subscriptions.forget(eds.type_url, cluster.resource.value.edsName());
                    const empty = try self.emptyEds(client.sender.state.io, cluster);
                    if (item.snapshot) |old| old.release();
                    item.snapshot = empty;
                    item.eds_seen = true;
                    item.eds_deadline = null;
                    changed = true;
                }
            }
        }
        if (try self.expireSecrets(now, client)) {
            for (plan.entries.items) |*item| {
                const cluster = item.cluster orelse continue;
                if (cluster.resource.value.tls_sds == null) continue;
                try self.resolveClusterTls(cluster);
                try self.reproject(client.sender.state.io, item);
            }
            changed = true;
        }
        if (changed) revision = try self.publishDelta(client, &plan, self.latest.?, false, destination, deadline);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
    pub fn project(self: *Controller, io: std.Io, cluster: *entries.Cluster, bytes: []const u8) Error!*eds.Snapshot {
        const config = cluster.resource.value;
        var options = self.options.target;
        options.cluster = config.name;
        options.max_concurrent_requests = config.max_concurrent_requests;
        options.child_policy_json = config.policy.child_json;
        options.locality_weighted = config.policy.locality_weighted;
        if (config.http2_limits) |overrides| {
            if (overrides.header_table_size) |value| {
                options.limits.header_table_size = value;
            }
            if (overrides.max_concurrent_streams) |value| {
                options.limits.max_concurrent_streams = value;
            }
            if (overrides.initial_window_size) |value| {
                options.limits.initial_window_size = value;
            }
            if (overrides.initial_connection_window_size) |value| {
                options.limits.initial_connection_window_size = value;
            }
        }
        if (cluster.resolvedTls()) |tls_config| {
            const material = try tls_material.Material.create(self.allocator, io, tls_config);
            const host = material.serverName(config.name);
            options.tls = .{ .host = host, .options = material.options() };
            options.tls_material = material;
        }
        return eds.Snapshot.create(self.allocator, bytes, self.options.limits.eds, options);
    }
    pub fn emptyEds(self: *Controller, io: std.Io, cluster: *entries.Cluster) Error!*eds.Snapshot {
        const name = cluster.resource.value.edsName();
        var writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var length = name.len;
        while (length >= 128) : (length >>= 7) writer.writer.writeByte(@as(u8, @truncate(length)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(length)) catch return error.OutOfMemory;
        writer.writer.writeAll(name) catch return error.OutOfMemory;
        return self.project(io, cluster, writer.written());
    }
};

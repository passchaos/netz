//! Automatic listener/router/cluster/endpoint dependency staging for one caller.
const std = @import("std");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const rds = @import("../rds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const shared = @import("../../channel/shared.zig");
const tls_material = @import("../tls_material.zig");
const entries = @import("entry.zig");
const Plan = @import("plan.zig").Plan;
const Target = @import("target.zig").Target;
pub const Options = @import("options.zig").Options;
pub const Error = @import("errors.zig").PublishError || lds.Error || cds.Error || eds.Error || tls_material.Error || error{ InvalidXdsOptions, XdsNotStarted };
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
    pub fn create(gpa: std.mem.Allocator, options: Options) Error!*Controller {
        if (options.limits.max_clusters == 0 or options.limits.max_projections == 0 or options.limits.max_storage_bytes == 0 or options.target.authority.len == 0 or options.target.attempt_delay.nanoseconds <= 0) return error.InvalidXdsOptions;
        const self = try gpa.create(Controller);
        self.* = .{ .allocator = gpa, .arena = .init(gpa), .options = options };
        errdefer self.deinit();
        self.options.target.authority = try self.arena.allocator().dupe(u8, options.target.authority);
        if (self.options.target.tls) |*tls| tls.host = try self.arena.allocator().dupe(u8, tls.host);
        if (options.local_service_config_json) |json| {
            if (json.len > options.limits.max_storage_bytes) return error.XdsLimitExceeded;
            self.local_json = try self.arena.allocator().dupe(u8, json);
            self.local_captured = true;
        }
        self.listener = try lds.Controller.init(gpa, .{ .listener_name = options.listener_name, .authority = self.options.target.authority, .max_header_bytes = options.max_header_bytes, .limits = options.limits.lds, .publisher = .{ .context = self, .publish_fn = publishHook }, .delta_publisher = .{ .context = self, .publish_fn = publishDeltaHook } });
        return self;
    }
    pub fn deinit(self: *Controller) void {
        if (self.listener) |*value| value.deinit();
        for (self.projections.items) |value| value.release();
        self.projections.deinit(self.allocator);
        for (self.entries.items) |*value| value.deinit();
        self.entries.deinit(self.allocator);
        self.arena.deinit();
        self.allocator.destroy(self);
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
    fn planNames(plan: *Plan) @import("errors.zig").PublishError![2]?[]const []const u8 {
        const cds_names = try plan.cdsNames();
        const eds_names = plan.edsNames() catch |err| {
            plan.allocator.free(cds_names);
            return err;
        };
        return .{ cds_names, eds_names };
    }
    pub fn publish(self: *Controller, client: *ads.Client, plan: *Plan, projection: *@import("../lds/projection.zig").Projection, new_projection: bool, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        const names = try planNames(plan);
        defer {
            if (names[0]) |value| self.allocator.free(value);
            if (names[1]) |value| self.allocator.free(value);
        }
        var requested: [2]ads.subscriptions.Subscription = undefined;
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
        }
        var requested: [2]delta.subscriptions.Subscription = undefined;
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
        return earliest;
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
        if (config.tls) |tls_config| {
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

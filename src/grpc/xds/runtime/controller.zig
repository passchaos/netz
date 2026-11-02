//! Automatic listener/router/cluster/endpoint dependency staging for one caller.
const std = @import("std");
const ads = @import("../ads.zig");
const lds = @import("../lds.zig");
const rds = @import("../rds.zig");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const shared = @import("../../channel/shared.zig");
const entries = @import("entry.zig");
const Plan = @import("plan.zig").Plan;
const Target = @import("target.zig").Target;
pub const Options = @import("options.zig").Options;
pub const Error = @import("errors.zig").PublishError || lds.Error || cds.Error || eds.Error || error{ InvalidXdsOptions, XdsNotStarted };
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
        self.listener = try lds.Controller.init(gpa, .{ .listener_name = options.listener_name, .authority = self.options.target.authority, .max_header_bytes = options.max_header_bytes, .limits = options.limits.lds, .publisher = .{ .context = self, .publish_fn = publishHook } });
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
    pub fn publish(self: *Controller, client: *ads.Client, plan: *Plan, projection: *@import("../lds/projection.zig").Projection, new_projection: bool, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        self.cleanProjections();
        if (new_projection) {
            if (self.projections.items.len >= self.options.limits.max_projections) return error.XdsLimitExceeded;
            try self.projections.ensureUnusedCapacity(self.allocator, 1);
        }
        const cds_names = try plan.cdsNames();
        defer self.allocator.free(cds_names);
        const eds_names = try plan.edsNames();
        defer self.allocator.free(eds_names);
        var requested: [2]ads.subscriptions.Subscription = undefined;
        var count: usize = 0;
        if (cds_names.len != 0) {
            requested[count] = .{ .type_url = cds.type_url, .names = cds_names };
            count += 1;
        }
        if (eds_names.len != 0) {
            requested[count] = .{ .type_url = eds.type_url, .names = eds_names };
            count += 1;
        }
        var subscriptions = try client.subscriptions.prepareMany(requested[0..count]);
        defer subscriptions.deinit();
        const target = try Target.create(self.allocator, plan.entries.items, self.local_json);
        defer target.release();
        var storage = std.math.add(usize, plan.route_storage, target.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        for (plan.entries.items) |entry| {
            if (entry.cluster) |cluster| storage = std.math.add(usize, storage, cluster.resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
            if (entry.snapshot) |snapshot| storage = std.math.add(usize, storage, snapshot.resource.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        }
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
        const revision = try target.publish(destination, projection.descriptor(), deadline);
        subscriptions.commit();
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
    fn publishHook(pointer: *anyopaque, client: *ads.Client, projection: *@import("../lds/projection.zig").Projection, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) @import("errors.zig").PublishError!u64 {
        const self: *Controller = @ptrCast(@alignCast(pointer));
        var plan = try Plan.create(self, projection);
        defer plan.deinit();
        return self.publish(client, &plan, projection, true, destination, deadline);
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
        const revision = if (same) destination.configurationRevision() else try self.publish(client, &plan, projection, false, destination, deadline);
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
    pub fn project(self: *Controller, cluster: *entries.Cluster, bytes: []const u8) Error!*eds.Snapshot {
        const config = cluster.resource.value;
        var options = self.options.target;
        options.cluster = config.name;
        options.max_concurrent_requests = config.max_concurrent_requests;
        options.child_policy_json = config.policy.child_json;
        options.locality_weighted = config.policy.locality_weighted;
        return eds.Snapshot.create(self.allocator, bytes, self.options.limits.eds, options);
    }
    pub fn emptyEds(self: *Controller, cluster: *entries.Cluster) Error!*eds.Snapshot {
        const name = cluster.resource.value.edsName();
        var writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var length = name.len;
        while (length >= 128) : (length >>= 7) writer.writer.writeByte(@as(u8, @truncate(length)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(length)) catch return error.OutOfMemory;
        writer.writer.writeAll(name) catch return error.OutOfMemory;
        return self.project(cluster, writer.written());
    }
};

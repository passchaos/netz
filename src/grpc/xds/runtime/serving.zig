//! Keep the last valid route view while replacement dependencies are requested.
const std = @import("std");
const Controller = @import("controller.zig").Controller;
const Plan = @import("plan.zig").Plan;
const Entry = @import("entry.zig").Entry;
const Projection = @import("../lds/projection.zig").Projection;
const discovery = @import("discovery.zig");
const rds = @import("../rds.zig");
const Error = @import("errors.zig").PublishError;

pub const PublishedEntry = struct {
    entry: Entry,
    pending: bool,
    source: ?*@import("../discovery_source.zig").Source,
    tls_fingerprint: [32]u8,

    pub fn create(item: Entry) PublishedEntry {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        const tls = if (item.cluster) |cluster| cluster.resolvedTls() else null;
        std.hash.autoHashStrat(&hasher, tls, .Deep);
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return .{ .entry = item.clone(), .pending = item.pending(), .source = if (item.cluster) |cluster| cluster.discovery_source else null, .tls_fingerprint = digest };
    }

    pub fn deinit(self: *PublishedEntry) void {
        self.entry.deinit();
    }
};

fn sameCluster(a: anytype, b: @TypeOf(a)) bool {
    if (a == b) return true;
    const current = a orelse return false;
    const previous = b orelse return false;
    // A complete SotW CDS response can repeat an unchanged serving cluster
    // alongside the pending replacement. Its immutable wire/source identity
    // remains equal even though the accepted resource owner is newly decoded.
    // TLS owners stay conservative because SDS material can change separately.
    if (current.resource.value.tls != null or current.resource.value.tls_sds != null or
        previous.resource.value.tls != null or previous.resource.value.tls_sds != null) return false;
    if (!std.mem.eql(u8, current.resource.wire, previous.resource.wire)) return false;
    const current_source = current.discovery_source orelse return previous.discovery_source == null;
    const previous_source = previous.discovery_source orelse return false;
    return std.mem.eql(u8, current_source.key, previous_source.key);
}

pub const View = struct {
    allocator: std.mem.Allocator,
    deferred: bool,
    projection: *Projection,
    next: std.ArrayList(Entry) = .empty,
    published_next: std.ArrayList(PublishedEntry) = .empty,

    pub fn prepare(controller: *Controller, plan: *Plan, projection: *Projection) std.mem.Allocator.Error!View {
        const deferred = controller.retain_valid_routes and controller.served_projection != null and projection != controller.served_projection.? and !plan.ready(projection);
        var self: View = .{ .allocator = controller.allocator, .deferred = deferred, .projection = if (deferred) controller.served_projection.? else projection };
        errdefer self.deinit();
        // Retain the selector, never old entry contents: withdrawals and TLS
        // changes for a serving child must still reach the data plane.
        if (controller.retain_valid_routes) for (plan.entries.items) |item| {
            if (!plan.required(self.projection, item.identity.name)) continue;
            try self.next.ensureUnusedCapacity(self.allocator, 1);
            self.next.appendAssumeCapacity(item.clone());
        };
        if (controller.retain_valid_routes) for (self.targetEntries(plan)) |item| {
            try self.published_next.ensureUnusedCapacity(self.allocator, 1);
            self.published_next.appendAssumeCapacity(PublishedEntry.create(item));
        };
        return self;
    }

    pub fn targetEntries(self: *const View, plan: *const Plan) []const Entry {
        // The pending graph drives watches and cache acceptance. Only current
        // entries required by the retained selector enter its target inventory.
        return if (self.deferred) self.next.items else plan.entries.items;
    }

    pub fn storageBytes(self: *const View, controller: *const Controller) error{XdsLimitExceeded}!usize {
        const inventories = [_]struct { capacity: usize, size: usize }{
            .{ .capacity = self.next.capacity, .size = @sizeOf(Entry) },
            .{ .capacity = self.published_next.capacity, .size = @sizeOf(PublishedEntry) },
            .{ .capacity = controller.served_entries.capacity, .size = @sizeOf(Entry) },
            .{ .capacity = controller.published_entries.capacity, .size = @sizeOf(PublishedEntry) },
        };
        var storage: usize = 0;
        for (inventories) |inventory| {
            const bytes = std.math.mul(usize, inventory.capacity, inventory.size) catch return error.XdsLimitExceeded;
            storage = std.math.add(usize, storage, bytes) catch return error.XdsLimitExceeded;
        }
        return storage;
    }

    pub fn unchanged(self: *const View, controller: *const Controller) bool {
        if (!self.deferred or self.published_next.items.len != controller.published_entries.items.len) return false;
        for (self.published_next.items, controller.published_entries.items) |current, previous| {
            if (current.pending != previous.pending or current.source != previous.source or
                !std.mem.eql(u8, &current.tls_fingerprint, &previous.tls_fingerprint)) return false;
            if (current.entry.identity != previous.entry.identity or !sameCluster(current.entry.cluster, previous.entry.cluster) or current.entry.snapshot != previous.entry.snapshot or
                current.entry.cds_seen != previous.entry.cds_seen or current.entry.eds_seen != previous.entry.eds_seen) return false;
        }
        return true;
    }

    pub fn deinit(self: *View) void {
        for (self.next.items) |*item| item.deinit();
        self.next.deinit(self.allocator);
        for (self.published_next.items) |*item| item.deinit();
        self.published_next.deinit(self.allocator);
    }

    pub fn commit(self: *View, controller: *Controller, projection: *Projection) void {
        if (!controller.retain_valid_routes) return;
        if (!self.deferred) {
            projection.retain();
            if (controller.served_projection) |previous| previous.release();
            controller.served_projection = projection;
        }
        const previous = controller.served_entries;
        controller.served_entries = self.next;
        self.next = previous;
        const published_previous = controller.published_entries;
        controller.published_entries = self.published_next;
        self.published_next = published_previous;
    }
};

pub fn subscriptions(context: *anyopaque, watches: []const discovery.Watch, deadline: std.Io.Clock.Timestamp) Error!discovery.Transaction {
    const self: *Controller = @ptrCast(@alignCast(context));
    const remote = if (self.served_projection) |served| served.remote_rds else null;
    if (!self.retain_valid_routes or remote == null) return self.upstream_router.?.prepare(watches, deadline);
    const adapted = try self.allocator.dupe(discovery.Watch, watches);
    defer self.allocator.free(adapted);
    var retained: ?[]const []const u8 = null;
    defer if (retained) |names| self.allocator.free(names);
    for (adapted, 0..) |*watch, index| {
        for (adapted[0..index]) |previous| if (std.mem.eql(u8, previous.type_url, watch.type_url)) return error.InvalidDiscoveryMessage;
        if (!std.mem.eql(u8, watch.type_url, rds.type_url)) continue;
        const already = for (watch.names) |name| {
            if (std.mem.eql(u8, name, remote.?)) break true;
        } else false;
        if (already) continue;
        const names = try self.allocator.alloc([]const u8, watch.names.len + 1);
        @memcpy(names[0..watch.names.len], watch.names);
        names[watch.names.len] = remote.?;
        retained = names;
        watch.names = names;
    }
    return self.upstream_router.?.prepare(adapted, deadline);
}

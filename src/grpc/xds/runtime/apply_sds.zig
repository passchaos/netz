//! Authority-scoped secret cache staging and transactional TLS reprojection.
const std = @import("std");
const ctl = @import("controller.zig");
const sds = @import("../sds.zig");
const cds = @import("../cds.zig");
const entry = @import("entry.zig");
const ads = @import("../ads.zig");
const shared = @import("../../channel/shared.zig");
const raw_name = @import("../raw_name.zig");
const Plan = @import("plan.zig").Plan;
const SecretMap = std.StringHashMapUnmanaged(*ctl.CachedSecret);

/// The map borrows accepted secrets until commit. Decoded replacements and TLS
/// copies remain private until the target and subscription plan both publish.
pub const SecretPlan = struct {
    controller: *ctl.Controller,
    secrets: SecretMap = .empty,
    decoded: std.ArrayList(*ctl.CachedSecret) = .empty,
    deadlines: std.ArrayList(struct { secret: *ctl.CachedSecret, deadline: ?std.Io.Clock.Timestamp }) = .empty,
    changed: bool = false,
    committed: bool = false,

    pub fn init(controller: *ctl.Controller) std.mem.Allocator.Error!SecretPlan {
        var self = SecretPlan{ .controller = controller };
        errdefer self.deinit();
        try self.secrets.ensureTotalCapacity(controller.allocator, controller.sds_secrets.count());
        var iterator = controller.sds_secrets.iterator();
        while (iterator.next()) |value| self.secrets.putAssumeCapacity(value.key_ptr.*, value.value_ptr.*);
        return self;
    }

    pub fn deinit(self: *SecretPlan) void {
        for (self.decoded.items) |value| {
            if (self.committed and self.controller.sds_secrets.get(value.owned.value.name) == value) continue;
            value.owned.deinit();
            self.controller.allocator.destroy(value);
        }
        self.decoded.deinit(self.controller.allocator);
        self.deadlines.deinit(self.controller.allocator);
        self.secrets.deinit(self.controller.allocator);
    }

    /// Take ownership before any fallible map or timer work.
    pub fn put(self: *SecretPlan, value: *ctl.CachedSecret) std.mem.Allocator.Error!void {
        self.decoded.append(self.controller.allocator, value) catch |err| {
            value.owned.deinit();
            self.controller.allocator.destroy(value);
            return err;
        };
        const name = value.owned.value.name;
        if (self.secrets.get(name)) |old| {
            if (std.mem.eql(u8, old.owned.wire, value.owned.wire)) {
                try self.refresh(old, value.deadline);
                return;
            }
        }
        const slot = try self.secrets.getOrPut(self.controller.allocator, name);
        slot.key_ptr.* = name;
        slot.value_ptr.* = value;
        self.changed = true;
    }

    pub fn refresh(self: *SecretPlan, secret: *ctl.CachedSecret, deadline: ?std.Io.Clock.Timestamp) std.mem.Allocator.Error!void {
        try self.deadlines.append(self.controller.allocator, .{ .secret = secret, .deadline = deadline });
    }

    pub fn remove(self: *SecretPlan, name: []const u8) void {
        if (self.secrets.remove(name)) self.changed = true;
    }

    pub fn omit(self: *SecretPlan) void {
        var iterator = self.controller.sds_secrets.iterator();
        while (iterator.next()) |old| {
            if (!self.controller.inResponseScope(old.key_ptr.*)) continue;
            const present = for (self.decoded.items) |value| {
                if (std.mem.eql(u8, old.key_ptr.*, value.owned.value.name)) break true;
            } else false;
            if (!present) self.remove(old.key_ptr.*);
        }
    }

    pub fn commit(self: *SecretPlan) void {
        var iterator = self.controller.sds_secrets.iterator();
        while (iterator.next()) |old| {
            if (self.secrets.get(old.key_ptr.*) == old.value_ptr.*) continue;
            old.value_ptr.*.owned.deinit();
            self.controller.allocator.destroy(old.value_ptr.*);
        }
        self.controller.sds_secrets.deinit(self.controller.allocator);
        self.controller.sds_secrets = self.secrets;
        self.secrets = .empty;
        // A removal or replacement may retire a heartbeat's borrowed pointer.
        // Match pointers against the committed map without dereferencing it.
        for (self.deadlines.items) |timer| {
            var current = self.controller.sds_secrets.valueIterator();
            while (current.next()) |value| {
                if (value.* == timer.secret) {
                    value.*.deadline = timer.deadline;
                    break;
                }
            }
        }
        self.committed = true;
        self.controller.resource_commit_generation +%= 1;
    }

    pub fn stageClusters(self: *SecretPlan, plan: *Plan, io: std.Io) ctl.Error!bool {
        var changed = self.changed;
        for (plan.entries.items) |*item| {
            const old = item.cluster orelse continue;
            const refs = old.resource.value.tls_sds orelse continue;
            const affected = (if (refs.certificate) |name| self.controller.inResponseScope(name) else false) or
                (if (refs.validation) |name| self.controller.inResponseScope(name) else false);
            if (!affected) continue;
            const cluster = try cloneCluster(self.controller, old);
            var retained = false;
            defer if (!retained) cluster.release();
            const certificate = if (refs.certificate) |name| self.secrets.get(name) else null;
            const validation = if (refs.validation) |name| self.secrets.get(name) else null;
            if ((refs.certificate == null or certificate != null) and
                (refs.validation == null or validation != null))
            {
                try cluster.applySds(
                    if (certificate) |value| value.owned.value else null,
                    if (validation) |value| value.owned.value else null,
                );
            }
            if (!self.changed and old.sdsPending() == cluster.sdsPending()) continue;
            old.release();
            item.cluster = cluster;
            retained = true;
            // Allocate the empty replacement before releasing the retained
            // snapshot, keeping plan cleanup valid if projection fails.
            if (cluster.sdsPending() and cluster.resource.value.isEds()) {
                if (item.eds_seen) if (item.snapshot) |snapshot| try cluster.setPendingEds(snapshot.resource.wire);
                const empty = try self.controller.emptyEds(io, cluster);
                if (item.snapshot) |snapshot| snapshot.release();
                item.snapshot = empty;
                item.eds_seen = false;
            } else try self.controller.reproject(io, item);
            changed = true;
        }
        return changed;
    }
};

/// Deep copy mutable TLS and pending-EDS state without touching the accepted
/// cluster. The caller resolves TLS from its intended cache before projection.
pub fn cloneCluster(self: *ctl.Controller, old: *entry.Cluster) ctl.Error!*entry.Cluster {
    var limits = self.options.limits.cds;
    limits.allow_sds = true;
    var owned = try cds.decode(self.allocator, old.resource.wire, limits);
    const cluster = entry.Cluster.create(self.allocator, owned) catch |err| {
        owned.deinit();
        return err;
    };
    errdefer cluster.release();
    cluster.discovery_source = if (old.discovery_source) |source| source.retain() else null;
    if (old.pending_eds) |wire| try cluster.setPendingEds(wire);
    return cluster;
}

pub fn apply(self: *ctl.Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    if (self.latest == null) return error.XdsNotStarted;
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    var secrets = try SecretPlan.init(self);
    defer secrets.deinit();
    var storage: usize = 0;
    var first_error: ?sds.Error = null;
    for (update.response.value.resources) |raw| {
        var owned = sds.decode(self.allocator, raw.value, self.options.limits.sds) catch |err| {
            if (!self.options.fail_on_data_errors) return err;
            const name = raw_name.first(raw.value, 1) orelse return err;
            if (!self.inResponseScope(name)) continue;
            if (first_error == null) first_error = err;
            continue;
        };
        if (!self.inResponseScope(owned.value.name)) {
            owned.deinit();
            continue;
        }
        const pointer = self.allocator.create(ctl.CachedSecret) catch |err| {
            owned.deinit();
            return err;
        };
        pointer.* = .{ .owned = owned };
        try secrets.put(pointer);
        storage = std.math.add(usize, storage, owned.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
    }
    std.mem.sort(*ctl.CachedSecret, secrets.decoded.items, {}, struct {
        fn less(_: void, a: *ctl.CachedSecret, b: *ctl.CachedSecret) bool {
            return std.mem.order(u8, a.owned.value.name, b.owned.value.name) == .lt;
        }
    }.less);
    if (secrets.decoded.items.len > 1) for (secrets.decoded.items[1..], 0..) |value, i| {
        if (std.mem.eql(u8, value.owned.value.name, secrets.decoded.items[i].owned.value.name)) return error.DuplicateSdsResource;
    };
    secrets.omit();
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    const changed = try secrets.stageClusters(&plan, client.sender.state.io);
    const revision = if (changed)
        try self.publish(client, &plan, self.latest.?, false, destination, deadline)
    else
        try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    secrets.commit();
    if (first_error) |err| return err;
    return revision;
}

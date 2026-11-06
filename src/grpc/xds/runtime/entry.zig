//! Shared immutable identity/CDS state and projected EDS references for staging.
const std = @import("std");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
const sds = @import("../sds.zig");
const tls_material = @import("../tls_material.zig");
pub const Identity = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    name: []u8,
    key: []u8,
    pub fn create(gpa: std.mem.Allocator, name: []const u8) std.mem.Allocator.Error!*Identity {
        const raw = try gpa.dupe(u8, name);
        errdefer gpa.free(raw);
        const key = try std.fmt.allocPrint(gpa, "cluster:{s}", .{name});
        errdefer gpa.free(key);
        const self = try gpa.create(Identity);
        self.* = .{ .allocator = gpa, .name = raw, .key = key };
        return self;
    }
    pub fn retain(self: *Identity) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Identity) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.allocator.free(self.name);
        self.allocator.free(self.key);
        self.allocator.destroy(self);
    }
};
pub const Cluster = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    resource: cds.resource.Owned,
    /// SDS material copied into this cluster's own arena. Kept separate from
    /// the immutable CDS resource so a secret rotation can replace it without
    /// rebuilding the cluster identity.
    tls_arena: std.heap.ArenaAllocator,
    tls_override: ?tls_material.Config = null,
    /// Last EDS payload received while SDS was unresolved. It is projected
    /// once every referenced secret arrives.
    pending_eds: ?[]u8 = null,
    pub fn create(gpa: std.mem.Allocator, resource: cds.resource.Owned) std.mem.Allocator.Error!*Cluster {
        const self = try gpa.create(Cluster);
        self.* = .{
            .allocator = gpa,
            .resource = resource,
            .tls_arena = .init(gpa),
        };
        return self;
    }
    /// Effective TLS configuration: resolved SDS material when present,
    /// otherwise the inline CDS configuration.
    pub fn resolvedTls(self: *const Cluster) ?tls_material.Config {
        return self.tls_override orelse self.resource.value.tls;
    }
    /// A cluster that references SDS material is not publishable until every
    /// referenced secret has been resolved.
    pub fn sdsPending(self: *const Cluster) bool {
        return self.resource.value.tls_sds != null and self.tls_override == null;
    }
    pub fn setPendingEds(self: *Cluster, wire: []const u8) std.mem.Allocator.Error!void {
        const copy = try self.allocator.dupe(u8, wire);
        if (self.pending_eds) |old| self.allocator.free(old);
        self.pending_eds = copy;
    }
    pub fn clearPendingEds(self: *Cluster) void {
        if (self.pending_eds) |value| self.allocator.free(value);
        self.pending_eds = null;
    }
    /// Copy the referenced secrets into this cluster's TLS arena. Callers must
    /// supply a secret for every reference; a missing or mismatched secret is
    /// rejected so the cluster stays pending rather than publishing without
    /// transport security.
    pub fn applySds(
        self: *Cluster,
        certificate: ?sds.Secret,
        validation: ?sds.Secret,
    ) (std.mem.Allocator.Error || error{InvalidSdsResource})!void {
        const refs = self.resource.value.tls_sds orelse return;
        _ = self.tls_arena.reset(.retain_capacity);
        self.tls_override = null;
        var config = self.resource.value.tls orelse tls_material.Config{};
        const arena = self.tls_arena.allocator();
        if (refs.certificate != null) {
            const secret = certificate orelse return error.InvalidSdsResource;
            switch (secret.kind) {
                .tls_certificate => |value| {
                    config.certificate_chain = try arena.dupe(u8, value.certificate_chain);
                    config.private_key = try arena.dupe(u8, value.private_key);
                },
                .validation_context => return error.InvalidSdsResource,
            }
        }
        if (refs.validation != null) {
            const secret = validation orelse return error.InvalidSdsResource;
            switch (secret.kind) {
                .validation_context => |value| {
                    config.trusted_ca = try arena.dupe(u8, value.trusted_ca);
                    config.system_root_certs = value.system_root_certs;
                    if (value.san_matchers.len != 0) {
                        const matchers = try arena.alloc(tls_material.SanMatcher, value.san_matchers.len);
                        for (value.san_matchers, matchers) |source, *target| {
                            target.* = .{
                                .kind = source.kind,
                                .value = try arena.dupe(u8, source.value),
                                .ignore_case = source.ignore_case,
                                .san_type = source.san_type,
                            };
                        }
                        config.san_matchers = matchers;
                    }
                    if (value.verify_certificate_hashes.len != 0) {
                        config.verify_certificate_hashes = try arena.dupe([32]u8, value.verify_certificate_hashes);
                    }
                    if (value.verify_certificate_spkis.len != 0) {
                        config.verify_certificate_spkis = try arena.dupe([32]u8, value.verify_certificate_spkis);
                    }
                },
                .tls_certificate => return error.InvalidSdsResource,
            }
        }
        self.tls_override = config;
    }
    pub fn retain(self: *Cluster) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Cluster) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.pending_eds) |value| self.allocator.free(value);
        self.tls_arena.deinit();
        self.resource.deinit();
        self.allocator.destroy(self);
    }
};
pub const Entry = struct {
    identity: *Identity,
    cluster: ?*Cluster = null,
    snapshot: ?*eds.Snapshot = null,
    cds_seen: bool = false,
    eds_seen: bool = false,
    /// Delta TTL deadlines; null means no timer.
    cds_deadline: ?std.Io.Clock.Timestamp = null,
    eds_deadline: ?std.Io.Clock.Timestamp = null,
    pub fn clone(self: Entry) Entry {
        self.identity.retain();
        if (self.cluster) |value| value.retain();
        if (self.snapshot) |value| value.retain();
        return self;
    }
    pub fn deinit(self: *Entry) void {
        self.identity.release();
        if (self.cluster) |value| value.release();
        if (self.snapshot) |value| value.release();
        self.* = undefined;
    }
    pub fn pending(self: Entry) bool {
        return !self.cds_seen or (self.cluster != null and
            (!self.eds_seen or self.cluster.?.sdsPending()));
    }
};

pub fn sameDeadline(a: ?std.Io.Clock.Timestamp, b: ?std.Io.Clock.Timestamp) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return a.?.raw.nanoseconds == b.?.raw.nanoseconds;
}

/// Reporting-only CDS changes still replace the accepted registration image.
pub fn sameReporting(a: cds.resource.Cluster, b: cds.resource.Cluster) bool {
    if (a.lrs_self != b.lrs_self) return false;
    const before = a.lrs_propagation;
    const after = b.lrs_propagation;
    if (before.cpu_utilization != after.cpu_utilization or before.memory_utilization != after.memory_utilization or
        before.application_utilization != after.application_utilization or before.named_metrics_all != after.named_metrics_all or
        before.named_metrics.len != after.named_metrics.len) return false;
    for (before.named_metrics, after.named_metrics) |left, right| if (!std.mem.eql(u8, left, right)) return false;
    return true;
}

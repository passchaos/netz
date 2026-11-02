//! Shared immutable identity/CDS state and projected EDS references for staging.
const std = @import("std");
const cds = @import("../cds.zig");
const eds = @import("../eds.zig");
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
    pub fn create(gpa: std.mem.Allocator, resource: cds.resource.Owned) std.mem.Allocator.Error!*Cluster {
        const self = try gpa.create(Cluster);
        self.* = .{ .allocator = gpa, .resource = resource };
        return self;
    }
    pub fn retain(self: *Cluster) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Cluster) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
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
        return !self.cds_seen or (self.cluster != null and !self.eds_seen);
    }
};

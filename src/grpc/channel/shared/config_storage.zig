//! Shared parsed configuration storage, independent of per-RPC selector epochs.
const std = @import("std");
const service = @import("../../service_config.zig");
pub const Storage = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    config: service.ServiceConfig,
    json: ?[]u8,
    /// Consumes the caller's config only on successful construction.
    pub fn create(gpa: std.mem.Allocator, config: service.ServiceConfig, json: ?[]const u8) std.mem.Allocator.Error!*Storage {
        const self = try gpa.create(Storage);
        errdefer gpa.destroy(self);
        const text = if (json) |bytes| try gpa.dupe(u8, bytes) else null;
        self.* = .{ .allocator = gpa, .config = config, .json = text };
        return self;
    }
    pub fn retain(self: *Storage) *Storage {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }
    pub fn release(self: *Storage) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const gpa = self.allocator;
        self.config.deinit();
        if (self.json) |json| gpa.free(json);
        gpa.destroy(self);
    }
};

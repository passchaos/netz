//! Per-cluster call counters for xDS Load Reporting Service.
const std = @import("std");
pub const max_clusters: usize = 4096;
pub const max_categories: usize = 256;

pub const CategoryCount = struct { category: []const u8, count: u64 = 0 };

pub const Entry = struct {
    cluster: []const u8,
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    dropped: u64 = 0,
    categories: []CategoryCount = &.{},
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    entries: []Entry,
    categories: []CategoryCount,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.categories);
        self.allocator.free(self.entries);
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

pub fn stripCluster(name: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, name, "cluster:") and name.len > "cluster:".len) name["cluster:".len..] else name;
}

pub fn clusterName(endpoint: anytype) ?[]const u8 {
    for (endpoint.hierarchicalPath()) |part| {
        if (std.mem.startsWith(u8, part, "cluster:") and part.len > "cluster:".len) return part["cluster:".len..];
    }
    return null;
}

const Counter = struct {
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    dropped: u64 = 0,
    dropped_categories: std.StringHashMapUnmanaged(u64) = .empty,

    fn deinit(self: *Counter, gpa: std.mem.Allocator) void {
        var iterator = self.dropped_categories.iterator();
        while (iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.dropped_categories.deinit(gpa);
    }
};

pub const Stats = struct {
    /// Null in test-only State literals; real channels set it during init.
    allocator: ?std.mem.Allocator = null,
    mutex: std.Io.Mutex = .init,
    map: std.StringHashMapUnmanaged(Counter) = .empty,

    const Update = enum { issued_success, issued_error, issued, success, error_request, dropped };

    fn entryLocked(self: *Stats, cluster: []const u8) ?*Counter {
        const gpa = self.allocator orelse return null;
        if (cluster.len == 0) return null;
        if (self.map.count() >= max_clusters) {
            if (self.map.get(cluster) == null) return null;
        }
        const gop = self.map.getOrPut(gpa, cluster) catch return null;
        if (!gop.found_existing) {
            const owned = gpa.dupe(u8, cluster) catch {
                _ = self.map.remove(cluster);
                return null;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = .{};
        }
        return gop.value_ptr;
    }

    fn update(self: *Stats, io: std.Io, cluster: []const u8, kind: Update) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster) orelse return;
        switch (kind) {
            .issued_success => {
                value.issued +%= 1;
                value.successful +%= 1;
            },
            .issued_error => {
                value.issued +%= 1;
                value.error_requests +%= 1;
            },
            .issued => value.issued +%= 1,
            .success => value.successful +%= 1,
            .error_request => value.error_requests +%= 1,
            .dropped => value.dropped +%= 1,
        }
    }

    pub fn record(self: *Stats, io: std.Io, cluster: []const u8, success: bool) void {
        self.update(io, cluster, if (success) .issued_success else .issued_error);
    }
    pub fn recordIssued(self: *Stats, io: std.Io, cluster: []const u8) void {
        self.update(io, cluster, .issued);
    }
    pub fn recordCompletion(self: *Stats, io: std.Io, cluster: []const u8, success: bool) void {
        self.update(io, cluster, if (success) .success else .error_request);
    }
    pub fn recordDropped(self: *Stats, io: std.Io, cluster: []const u8, category: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const value = self.entryLocked(cluster) orelse return;
        value.dropped +%= 1;
        if (category.len == 0) return;
        const gpa = self.allocator orelse return;
        if (value.dropped_categories.count() >= max_categories) {
            if (value.dropped_categories.get(category) == null) return;
        }
        const gop = value.dropped_categories.getOrPut(gpa, category) catch return;
        if (!gop.found_existing) {
            const owned = gpa.dupe(u8, category) catch {
                _ = value.dropped_categories.remove(category);
                return;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = 0;
        }
        gop.value_ptr.* +%= 1;
    }

    pub fn snapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var storage_bytes: usize = 0;
        var category_count: usize = 0;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            storage_bytes += entry.key_ptr.*.len;
            category_count += entry.value_ptr.dropped_categories.count();
            var categories = entry.value_ptr.dropped_categories.iterator();
            while (categories.next()) |category| storage_bytes += category.key_ptr.*.len;
        }
        const entries = try gpa.alloc(Entry, self.map.count());
        errdefer gpa.free(entries);
        const categories = try gpa.alloc(CategoryCount, category_count);
        errdefer gpa.free(categories);
        const storage = try gpa.alloc(u8, storage_bytes);
        errdefer gpa.free(storage);
        var offset: usize = 0;
        var index: usize = 0;
        var category_index: usize = 0;
        iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            const name = entry.key_ptr.*;
            const copy = storage[offset..][0..name.len];
            @memcpy(copy, name);
            offset += name.len;
            const category_start = category_index;
            var category_iterator = entry.value_ptr.dropped_categories.iterator();
            while (category_iterator.next()) |category| {
                const category_name = category.key_ptr.*;
                const category_copy = storage[offset..][0..category_name.len];
                @memcpy(category_copy, category_name);
                offset += category_name.len;
                categories[category_index] = .{ .category = category_copy, .count = category.value_ptr.* };
                category_index += 1;
            }
            entries[index] = .{
                .cluster = copy,
                .issued = entry.value_ptr.issued,
                .successful = entry.value_ptr.successful,
                .error_requests = entry.value_ptr.error_requests,
                .dropped = entry.value_ptr.dropped,
                .categories = categories[category_start..][0 .. category_index - category_start],
            };
            index += 1;
        }
        return .{ .allocator = gpa, .storage = storage, .entries = entries, .categories = categories };
    }

    pub fn deinit(self: *Stats) void {
        const gpa = self.allocator orelse return;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            entry.value_ptr.deinit(gpa);
        }
        self.map.deinit(gpa);
        self.* = undefined;
    }
};

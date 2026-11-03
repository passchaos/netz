//! Per-cluster unary call counters for xDS Load Reporting Service.
const std = @import("std");
pub const max_clusters: usize = 4096;

pub const Entry = struct {
    cluster: []const u8,
    issued: u64 = 0,
    successful: u64 = 0,
    error_requests: u64 = 0,
    dropped: u64 = 0,
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

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    entries: []Entry,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

const Counter = struct { issued: u64 = 0, successful: u64 = 0, error_requests: u64 = 0, dropped: u64 = 0 };

pub const Stats = struct {
    /// Null in test-only State literals; real channels set it during init.
    allocator: ?std.mem.Allocator = null,
    mutex: std.Io.Mutex = .init,
    map: std.StringHashMapUnmanaged(Counter) = .empty,

    const Update = enum { issued_success, issued_error, issued, success, error_request, dropped };
    fn update(self: *Stats, io: std.Io, cluster: []const u8, kind: Update) void {
        const gpa = self.allocator orelse return;
        if (cluster.len == 0) return;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.map.count() >= max_clusters) {
            if (self.map.get(cluster) == null) return;
        }
        const gop = self.map.getOrPut(gpa, cluster) catch return;
        if (!gop.found_existing) {
            const owned = gpa.dupe(u8, cluster) catch {
                _ = self.map.remove(cluster);
                return;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = .{};
        }
        switch (kind) {
            .issued_success => {
                gop.value_ptr.issued +%= 1;
                gop.value_ptr.successful +%= 1;
            },
            .issued_error => {
                gop.value_ptr.issued +%= 1;
                gop.value_ptr.error_requests +%= 1;
            },
            .issued => gop.value_ptr.issued +%= 1,
            .success => gop.value_ptr.successful +%= 1,
            .error_request => gop.value_ptr.error_requests +%= 1,
            .dropped => gop.value_ptr.dropped +%= 1,
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
    pub fn recordDropped(self: *Stats, io: std.Io, cluster: []const u8) void {
        self.update(io, cluster, .dropped);
    }

    pub fn snapshot(self: *Stats, gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var storage_bytes: usize = 0;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| storage_bytes += entry.key_ptr.*.len;
        const entries = try gpa.alloc(Entry, self.map.count());
        errdefer gpa.free(entries);
        const storage = try gpa.alloc(u8, storage_bytes);
        errdefer gpa.free(storage);
        var offset: usize = 0;
        var index: usize = 0;
        iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            const name = entry.key_ptr.*;
            const copy = storage[offset..][0..name.len];
            @memcpy(copy, name);
            offset += name.len;
            entries[index] = .{
                .cluster = copy,
                .issued = entry.value_ptr.issued,
                .successful = entry.value_ptr.successful,
                .error_requests = entry.value_ptr.error_requests,
                .dropped = entry.value_ptr.dropped,
            };
            index += 1;
        }
        return .{ .allocator = gpa, .storage = storage, .entries = entries };
    }

    pub fn deinit(self: *Stats) void {
        const gpa = self.allocator orelse return;
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| gpa.free(entry.key_ptr.*);
        self.map.deinit(gpa);
        self.* = undefined;
    }
};

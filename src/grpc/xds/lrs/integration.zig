//! Convert SharedChannel per-cluster counters into LRS cluster reports.
const std = @import("std");
const channel = @import("../../channel/shared.zig");
const lrs_stats = @import("../../channel/shared/lrs_stats.zig");
const codec = @import("codec.zig");

pub const Reports = struct {
    allocator: std.mem.Allocator,
    clusters: []codec.ClusterStats,
    localities: []codec.LocalityStats,
    dropped: []codec.Dropped,
    pub fn deinit(self: *Reports) void {
        self.allocator.free(self.dropped);
        self.allocator.free(self.localities);
        self.allocator.free(self.clusters);
        self.* = undefined;
    }
};

fn selected(entry: lrs_stats.Entry, filter: ?[]const []const u8) bool {
    const names = filter orelse return true;
    for (names) |name| if (std.mem.eql(u8, name, entry.cluster)) return true;
    return false;
}

/// Cluster and category names borrow the snapshot's storage; keep it alive
/// until the report has been encoded.
pub fn build(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
) std.mem.Allocator.Error!Reports {
    return buildWithFilter(allocator, snapshot, locality, interval_ns, null);
}

pub fn buildWithFilter(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
    filter: ?[]const []const u8,
) std.mem.Allocator.Error!Reports {
    var cluster_count: usize = 0;
    var dropped_count: usize = 0;
    for (snapshot.entries) |entry| {
        if (!selected(entry, filter)) continue;
        cluster_count += 1;
        dropped_count += entry.categories.len;
    }
    const clusters = try allocator.alloc(codec.ClusterStats, cluster_count);
    errdefer allocator.free(clusters);
    const localities = try allocator.alloc(codec.LocalityStats, cluster_count);
    errdefer allocator.free(localities);
    const dropped = try allocator.alloc(codec.Dropped, dropped_count);
    errdefer allocator.free(dropped);
    var cluster_index: usize = 0;
    var dropped_index: usize = 0;
    for (snapshot.entries) |entry| {
        if (!selected(entry, filter)) continue;
        localities[cluster_index] = .{
            .locality = locality,
            .successful = entry.successful,
            .error_requests = entry.error_requests,
            .in_progress = entry.in_progress,
            .issued = entry.issued,
        };
        const start = dropped_index;
        for (entry.categories) |category| {
            dropped[dropped_index] = .{ .category = category.category, .count = category.count };
            dropped_index += 1;
        }
        clusters[cluster_index] = .{
            .name = entry.cluster,
            .localities = localities[cluster_index..][0..1],
            .total_dropped = entry.dropped,
            .dropped = dropped[start..][0 .. dropped_index - start],
            .interval_ns = interval_ns,
        };
        cluster_index += 1;
    }
    return .{ .allocator = allocator, .clusters = clusters, .localities = localities, .dropped = dropped };
}

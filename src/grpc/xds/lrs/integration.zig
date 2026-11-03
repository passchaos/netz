//! Convert SharedChannel per-cluster counters into LRS cluster reports.
const std = @import("std");
const channel = @import("../../channel/shared.zig");
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

/// Cluster and category names borrow the snapshot's storage; keep it alive
/// until the report has been encoded.
pub fn build(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
) std.mem.Allocator.Error!Reports {
    var dropped_count: usize = 0;
    for (snapshot.entries) |entry| dropped_count += entry.categories.len;
    const clusters = try allocator.alloc(codec.ClusterStats, snapshot.entries.len);
    errdefer allocator.free(clusters);
    const localities = try allocator.alloc(codec.LocalityStats, snapshot.entries.len);
    errdefer allocator.free(localities);
    const dropped = try allocator.alloc(codec.Dropped, dropped_count);
    errdefer allocator.free(dropped);
    var dropped_index: usize = 0;
    for (snapshot.entries, clusters, localities, 0..) |entry, *cluster, *stats, index| {
        stats.* = .{
            .locality = locality,
            .successful = entry.successful,
            .error_requests = entry.error_requests,
            .issued = entry.issued,
        };
        const start = dropped_index;
        for (entry.categories) |category| {
            dropped[dropped_index] = .{ .category = category.category, .count = category.count };
            dropped_index += 1;
        }
        cluster.* = .{
            .name = entry.cluster,
            .localities = localities[index..][0..1],
            .total_dropped = entry.dropped,
            .dropped = dropped[start..][0 .. dropped_index - start],
            .interval_ns = interval_ns,
        };
    }
    return .{ .allocator = allocator, .clusters = clusters, .localities = localities, .dropped = dropped };
}

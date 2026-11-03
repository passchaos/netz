//! Convert SharedChannel per-cluster counters into LRS cluster reports.
const std = @import("std");
const channel = @import("../../channel/shared.zig");
const codec = @import("codec.zig");

pub const Reports = struct {
    allocator: std.mem.Allocator,
    clusters: []codec.ClusterStats,
    localities: []codec.LocalityStats,
    pub fn deinit(self: *Reports) void {
        self.allocator.free(self.localities);
        self.allocator.free(self.clusters);
        self.* = undefined;
    }
};

/// Cluster names borrow the snapshot's storage; keep it alive until the report
/// has been encoded.
pub fn build(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
) std.mem.Allocator.Error!Reports {
    const clusters = try allocator.alloc(codec.ClusterStats, snapshot.entries.len);
    errdefer allocator.free(clusters);
    const localities = try allocator.alloc(codec.LocalityStats, snapshot.entries.len);
    errdefer allocator.free(localities);
    for (snapshot.entries, clusters, localities, 0..) |entry, *cluster, *stats, index| {
        stats.* = .{
            .locality = locality,
            .successful = entry.successful,
            .error_requests = entry.error_requests,
            .issued = entry.issued,
        };
        cluster.* = .{
            .name = entry.cluster,
            .localities = localities[index..][0..1],
            .total_dropped = entry.dropped,
            .interval_ns = interval_ns,
        };
    }
    return .{ .allocator = allocator, .clusters = clusters, .localities = localities };
}

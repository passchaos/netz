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
    endpoints: []codec.EndpointStats,
    pub fn deinit(self: *Reports) void {
        self.allocator.free(self.endpoints);
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

/// Cluster, category and endpoint names borrow the snapshot's storage; keep
/// it alive until the report has been encoded.
pub fn build(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
) std.mem.Allocator.Error!Reports {
    return buildWithOptions(allocator, snapshot, locality, interval_ns, null, false);
}

pub fn buildWithFilter(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
    filter: ?[]const []const u8,
) std.mem.Allocator.Error!Reports {
    return buildWithOptions(allocator, snapshot, locality, interval_ns, filter, false);
}

pub fn buildWithOptions(
    allocator: std.mem.Allocator,
    snapshot: *const channel.LrsStatsSnapshot,
    locality: codec.Locality,
    interval_ns: u64,
    filter: ?[]const []const u8,
    endpoint_granularity: bool,
) std.mem.Allocator.Error!Reports {
    var cluster_count: usize = 0;
    var dropped_count: usize = 0;
    var endpoint_count: usize = 0;
    for (snapshot.entries) |entry| {
        if (!selected(entry, filter)) continue;
        cluster_count += 1;
        dropped_count += entry.categories.len;
        if (endpoint_granularity) endpoint_count += entry.endpoints.len;
    }
    const clusters = try allocator.alloc(codec.ClusterStats, cluster_count);
    errdefer allocator.free(clusters);
    const localities = try allocator.alloc(codec.LocalityStats, cluster_count);
    errdefer allocator.free(localities);
    const dropped = try allocator.alloc(codec.Dropped, dropped_count);
    errdefer allocator.free(dropped);
    const endpoints = try allocator.alloc(codec.EndpointStats, endpoint_count);
    errdefer allocator.free(endpoints);
    var cluster_index: usize = 0;
    var dropped_index: usize = 0;
    var endpoint_index: usize = 0;
    for (snapshot.entries) |entry| {
        if (!selected(entry, filter)) continue;
        const endpoint_start = endpoint_index;
        if (endpoint_granularity) for (entry.endpoints) |endpoint| {
            endpoints[endpoint_index] = .{
                .host = endpoint.host,
                .port = endpoint.port,
                .ipv6 = endpoint.ipv6,
                .successful = endpoint.successful,
                .in_progress = endpoint.in_progress,
                .error_requests = endpoint.error_requests,
                .issued = endpoint.issued,
            };
            endpoint_index += 1;
        };
        localities[cluster_index] = .{
            .locality = locality,
            .successful = entry.successful,
            .error_requests = entry.error_requests,
            .in_progress = entry.in_progress,
            .issued = entry.issued,
            .endpoints = endpoints[endpoint_start..][0 .. endpoint_index - endpoint_start],
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
    return .{ .allocator = allocator, .clusters = clusters, .localities = localities, .dropped = dropped, .endpoints = endpoints };
}

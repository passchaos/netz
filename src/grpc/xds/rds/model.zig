//! Owned typed route configuration; all strings/sets borrow the resource arena.
const std = @import("std");
const routing = @import("../routing/mod.zig");
pub const type_url = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub const Error = @import("../../protobuf.zig").Error || std.mem.Allocator.Error || routing.regex.Error || error{ InvalidRdsResource, RdsLimitExceeded, UnsupportedRdsFeature };
pub const Limits = struct {
    max_bytes: usize = 8 * 1024 * 1024,
    max_text_bytes: usize = 4096,
    max_virtual_hosts: usize = 1024,
    max_domains: usize = 4096,
    max_routes: usize = 4096,
    max_headers_per_route: usize = 128,
    max_clusters_per_route: usize = 256,
    max_cluster_entries: usize = 16384,
    max_referenced_clusters: usize = 4096,
    max_hash_policies: usize = 64,
    max_total_regex_instructions: usize = 65536,
    max_storage_bytes: usize = 64 * 1024 * 1024,
    regex: routing.regex.Limits = .{},
};
pub const Weighted = struct { name: []const u8, key: []const u8, weight: u32 };
pub const HashPolicy = struct { kind: union(enum) { header: []const u8, channel_id }, terminal: bool };
pub const Forward = struct {
    clusters: []const Weighted,
    total_weight: u32,
    hash_policies: []const HashPolicy,
    max_stream_duration: ?std.Io.Duration,
    retry_policy: ?@import("../../call.zig").RetryPolicy,
    retry_present: bool,
};
pub const Route = struct {
    path: routing.string.Match,
    headers: []const routing.header.Match,
    fraction_per_million: ?u32,
    action: union(enum) { forward: Forward, inappropriate },
};
pub const VirtualHost = struct { domains: []const []const u8, routes: []const Route };
pub const Config = struct { name: []const u8, virtual_hosts: []const VirtualHost };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    value: Config,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

//! One retained target inventory and cluster-manager policy assembled from caches.
const std = @import("std");
const entry = @import("entry.zig");
const channel = @import("../../channel.zig");
const eds = @import("../eds.zig");
const cds = @import("../cds.zig");
const tls_material = @import("../tls_material.zig");
const shared = @import("../../channel/shared.zig");
const lrs_stats = @import("../../channel/shared/lrs_stats.zig");
const Json = std.json.Value;
fn object() Json {
    return .{ .object = .{} };
}
fn string(bytes: []const u8) Json {
    return .{ .string = bytes };
}
fn field(gpa: std.mem.Allocator, value: *Json, key: []const u8, child: Json) !void {
    try value.object.put(gpa, key, child);
}
fn policy(gpa: std.mem.Allocator, name: []const u8, value: Json) !Json {
    var wrapper = object();
    try field(gpa, &wrapper, name, value);
    var array = Json{ .array = std.array_list.Managed(Json).init(gpa) };
    try array.array.append(wrapper);
    return array;
}

fn dnsChildPolicy(
    arena: std.mem.Allocator,
    logical_only: bool,
    hosts: []const cds.resource.HostEndpoint,
    base_policy: Json,
    locality_weighted: bool,
    key: []const u8,
    material: ?*tls_material.Material,
    endpoints: *std.ArrayList(channel.Endpoint),
) !Json {
    var children = object();
    var order: Json = .{ .array = std.array_list.Managed(Json).init(arena) };
    var priorities: usize = 0;
    for (hosts) |host| priorities = @max(priorities, @as(usize, host.priority) + 1);
    for (0..priorities) |priority| {
        const priority_name = try std.fmt.allocPrint(arena, "priority-{d}", .{priority});
        try order.array.append(string(priority_name));
        var child = object();
        if (locality_weighted) {
            var locality_policy = object();
            try field(arena, &locality_policy, "childPolicy", base_policy);
            try field(arena, &child, "config", try policy(arena, "xds_wrr_locality_experimental", locality_policy));
        } else try field(arena, &child, "config", base_policy);
        // LOGICAL_DNS resolves once when the cluster is applied. STRICT_DNS
        // keeps re-resolution requests enabled so a connection failure can
        // refresh the address list, matching gRFC A27.
        try field(arena, &child, "ignoreReresolutionRequests", .{ .bool = logical_only });
        try field(arena, &children, priority_name, child);
        for (hosts) |host| {
            if (host.priority != priority) continue;
            const locality_name = try std.fmt.allocPrint(arena, "{d}:{s}{d}:{s}{d}:{s}", .{ host.region.len, host.region, host.zone.len, host.zone, host.sub_zone.len, host.sub_zone });
            const path = try arena.alloc([]const u8, 3);
            path[0] = key;
            path[1] = priority_name;
            path[2] = locality_name;
            const weight = if (locality_weighted) host.endpoint_weight else std.math.mul(u32, host.locality_weight, host.endpoint_weight) catch return error.InvalidServiceConfig;
            const endpoint_key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ host.host, host.port });
            if (material) |tls| {
                try endpoints.append(arena, .{ .tls_host = .{
                    .host = host.host,
                    .port = host.port,
                    .tls = tls.options(),
                    .ring_hash_key = endpoint_key,
                    .ring_hash_weight = weight,
                    .hierarchical_path = path,
                    .locality_weight = host.locality_weight,
                } });
            } else try endpoints.append(arena, .{ .cleartext_host = .{
                .host = host.host,
                .port = host.port,
                .ring_hash_key = endpoint_key,
                .ring_hash_weight = weight,
                .hierarchical_path = path,
                .locality_weight = host.locality_weight,
            } });
        }
    }
    var priority_config = object();
    try field(arena, &priority_config, "children", children);
    try field(arena, &priority_config, "priorities", order);
    return policy(arena, "priority_experimental", priority_config);
}
pub const Target = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize) = .init(1),
    snapshots: std.ArrayList(*eds.Snapshot) = .empty,
    tls_materials: std.ArrayList(*tls_material.Material) = .empty,
    endpoints: []const channel.Endpoint = &.{},
    /// Per-cluster ORCA propagation selections derived from CDS field 57.
    /// Entries are applied on publish; an empty selection clears any stale
    /// propagation for a cluster that remains in the inventory.
    propagations: []const PropagationEntry = &.{},
    lrs_selection: ?*lrs_stats.Selection = null,
    json: []const u8 = "",
    const PropagationEntry = struct {
        cluster: []const u8,
        propagation: lrs_stats.Propagation,
    };
    pub fn create(gpa: std.mem.Allocator, io: std.Io, entries: []const entry.Entry, local_json: ?[]const u8) (std.mem.Allocator.Error || @import("../../service_config.zig").Error || tls_material.Error)!*Target {
        return createWithReporting(gpa, io, entries, local_json, true);
    }

    pub fn createWithReporting(gpa: std.mem.Allocator, io: std.Io, entries: []const entry.Entry, local_json: ?[]const u8, source_scoped: bool) (std.mem.Allocator.Error || @import("../../service_config.zig").Error || tls_material.Error)!*Target {
        const self = try gpa.create(Target);
        self.* = .{ .allocator = gpa, .arena = .init(gpa) };
        errdefer self.release();
        const arena = self.arena.allocator();
        var child_keys: std.ArrayList([]const u8) = .empty;
        var child_values: std.ArrayList(Json) = .empty;
        var child_policies: std.StringHashMapUnmanaged(Json) = .empty;
        var aggregates: std.ArrayList(struct {
            index: usize,
            leaves: []const []const u8,
        }) = .empty;
        var endpoints: std.ArrayList(channel.Endpoint) = .empty;
        var propagations: std.ArrayList(PropagationEntry) = .empty;
        var registrations: std.ArrayList(lrs_stats.Identity) = .empty;
        for (entries) |value| {
            var implementation = object();
            try field(arena, &implementation, "clusterName", string(value.identity.name));
            const cluster = if (value.cluster) |resource| resource.resource.value else null;
            const discovery_source = if (value.cluster) |resource| resource.discovery_source else null;
            // Publish a selection for every retained identity so a cluster
            // whose CDS resource disappeared also loses any stale propagation.
            try propagations.append(arena, .{
                .cluster = value.identity.name,
                .propagation = if (cluster) |resource| .{
                    .cpu_utilization = resource.lrs_propagation.cpu_utilization,
                    .memory_utilization = resource.lrs_propagation.memory_utilization,
                    .application_utilization = resource.lrs_propagation.application_utilization,
                    .named_metrics_all = resource.lrs_propagation.named_metrics_all,
                    .named_metrics = resource.lrs_propagation.named_metrics,
                    .prefix_named_metrics = true,
                } else .{},
            });
            if (cluster) |resource| if (resource.lrs_self) {
                // An explicit transport override has one logical reporting
                // destination, so discovery failover keeps its shared bucket.
                try registrations.append(arena, .{ .cluster = value.identity.name, .service_name = resource.edsName(), .source = discovery_source, .source_key = if (source_scoped and discovery_source != null) discovery_source.?.key else "", .propagation = .{
                    .cpu_utilization = resource.lrs_propagation.cpu_utilization,
                    .memory_utilization = resource.lrs_propagation.memory_utilization,
                    .application_utilization = resource.lrs_propagation.application_utilization,
                    .named_metrics_all = resource.lrs_propagation.named_metrics_all,
                    .named_metrics = resource.lrs_propagation.named_metrics,
                    .prefix_named_metrics = true,
                } });
            };
            try field(arena, &implementation, "edsServiceName", string(if (cluster) |resource| resource.edsName() else ""));
            try field(arena, &implementation, "maxConcurrentRequests", .{ .integer = if (cluster) |resource| resource.max_concurrent_requests else 1024 });
            try field(arena, &implementation, "discoveryPending", .{ .bool = value.pending() });
            var drops = Json{ .array = std.array_list.Managed(Json).init(arena) };
            var child_policy: Json = undefined;
            if (value.snapshot) |snapshot| {
                snapshot.retain();
                self.snapshots.append(gpa, snapshot) catch |err| {
                    snapshot.release();
                    return err;
                };
                const decoded = std.json.parseFromSliceLeaky(Json, arena, snapshot.service_config_json, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else unreachable;
                child_policy = decoded.object.get("loadBalancingConfig").?;
                for (snapshot.resource.value.drops) |drop| {
                    var category = object();
                    try field(arena, &category, "category", string(drop.category));
                    try field(arena, &category, "requestsPerMillion", .{ .integer = drop.requests_per_million });
                    try drops.array.append(category);
                }
                const key = try arena.dupe(u8, value.identity.key);
                for (snapshot.endpoints) |endpoint| {
                    const original = endpoint.hierarchicalPath();
                    const path = try arena.alloc([]const u8, original.len + 1);
                    path[0] = key;
                    @memcpy(path[1..], original);
                    const projected = switch (endpoint) {
                        inline else => |item, tag| blk: {
                            var copy = item;
                            copy.hierarchical_path = path;
                            break :blk @unionInit(channel.Endpoint, @tagName(tag), copy);
                        },
                    };
                    try endpoints.append(arena, projected);
                }
            } else if (cluster) |resource| {
                const source = value.cluster.?;
                if (!source.sdsPending() and resource.isDns() and resource.host_endpoints.len != 0) {
                    const decoded = std.json.parseFromSliceLeaky(Json, arena, resource.policy.child_json, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidServiceConfig;
                    if (decoded != .array) return error.InvalidServiceConfig;
                    const key = try arena.dupe(u8, value.identity.key);
                    const material: ?*tls_material.Material = if (source.resolvedTls()) |config| blk: {
                        const created = try tls_material.Material.create(gpa, io, config);
                        self.tls_materials.append(gpa, created) catch |err| {
                            created.deinit();
                            return err;
                        };
                        break :blk created;
                    } else null;
                    child_policy = try dnsChildPolicy(arena, resource.isLogicalDns(), resource.host_endpoints, decoded, resource.policy.locality_weighted, key, material, &endpoints);
                } else child_policy = try policy(arena, "round_robin", object());
            } else child_policy = try policy(arena, "round_robin", object());
            try field(arena, &implementation, "dropCategories", drops);
            try field(arena, &implementation, "childPolicy", child_policy);
            var child = object();
            try field(arena, &child, "childPolicy", try policy(arena, "xds_cluster_impl_experimental", implementation));
            try child_keys.append(arena, value.identity.key);
            try child_values.append(arena, child);
            try child_policies.put(arena, value.identity.name, child_policy);
            if (cluster) |resource| if (resource.isAggregate()) {
                try aggregates.append(arena, .{
                    .index = child_values.items.len - 1,
                    .leaves = resource.aggregate_clusters,
                });
            };
        }
        // Aggregate clusters expand into an ordered priority policy over their
        // leaf clusters. Leaf child policies are already built above, so this
        // works regardless of entry order and reuses live leaf transports.
        for (aggregates.items) |aggregate| {
            var priority_children = object();
            var priorities = Json{ .array = std.array_list.Managed(Json).init(arena) };
            for (aggregate.leaves) |leaf| {
                const leaf_policy = child_policies.get(leaf) orelse
                    try policy(arena, "round_robin", object());
                const leaf_key = try std.fmt.allocPrint(arena, "cluster:{s}", .{leaf});
                var child = object();
                try field(arena, &child, "config", leaf_policy);
                try field(arena, &priority_children, leaf_key, child);
                try priorities.array.append(string(leaf_key));
            }
            var priority = object();
            try field(arena, &priority, "children", priority_children);
            try field(arena, &priority, "priorities", priorities);
            var child = child_values.items[aggregate.index];
            try field(arena, &child, "childPolicy", try policy(arena, "priority_experimental", priority));
            child_values.items[aggregate.index] = child;
        }
        var children = object();
        for (child_keys.items, child_values.items) |key, child| {
            try field(arena, &children, key, child);
        }
        var manager = object();
        try field(arena, &manager, "children", children);
        var config = if (local_json) |json| std.json.parseFromSliceLeaky(Json, arena, json, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidServiceConfig else object();
        if (config != .object) return error.InvalidServiceConfig;
        try field(arena, &config, "loadBalancingConfig", try policy(arena, "xds_cluster_manager_experimental", manager));
        self.json = try std.json.Stringify.valueAlloc(arena, config, .{});
        self.endpoints = try endpoints.toOwnedSlice(arena);
        self.propagations = try propagations.toOwnedSlice(arena);
        self.lrs_selection = try lrs_stats.Selection.create(gpa, registrations.items);
        return self;
    }
    pub fn retain(self: *Target) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Target) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        for (self.snapshots.items) |snapshot| snapshot.release();
        self.snapshots.deinit(self.allocator);
        for (self.tls_materials.items) |material| material.deinit();
        self.tls_materials.deinit(self.allocator);
        if (self.lrs_selection) |value| value.release();
        self.arena.deinit();
        self.allocator.destroy(self);
    }
    fn retainContext(context: *anyopaque) void {
        const self: *Target = @ptrCast(@alignCast(context));
        self.retain();
    }
    fn releaseContext(context: *anyopaque) void {
        const self: *Target = @ptrCast(@alignCast(context));
        self.release();
    }
    pub fn lifetime(self: *Target) @import("../../channel/shared/target_lifetime.zig").Lifetime {
        return .{ .context = self, .retain_fn = retainContext, .release_fn = releaseContext };
    }
    pub fn publish(self: *Target, destination: shared.SharedChannel, selector: @import("../../channel/call_selector.zig").Selector, deadline: std.Io.Clock.Timestamp, enable_lrs_stats: bool) shared.Error!u64 {
        const revision = try destination.updateWithDeadline(.{ .target = .{ .resolved = .{ .endpoints = self.endpoints } }, .target_lifetime = self.lifetime(), .service_config = .{ .replace = self.json }, .call_selector = .{ .replace = selector }, .lrs_selection = .{ .replace = self.lrs_selection }, .enable_lrs_stats = enable_lrs_stats }, deadline);
        for (self.propagations) |value| destination.setLrsPropagation(value.cluster, value.propagation);
        return revision;
    }
};

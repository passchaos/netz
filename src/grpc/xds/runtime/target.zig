//! One retained target inventory and cluster-manager policy assembled from caches.
const std = @import("std");
const entry = @import("entry.zig");
const channel = @import("../../channel.zig");
const eds = @import("../eds.zig");
const shared = @import("../../channel/shared.zig");
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
pub const Target = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize) = .init(1),
    snapshots: std.ArrayList(*eds.Snapshot) = .empty,
    endpoints: []const channel.Endpoint = &.{},
    json: []const u8 = "",
    pub fn create(gpa: std.mem.Allocator, entries: []const entry.Entry, local_json: ?[]const u8) (std.mem.Allocator.Error || @import("../../service_config.zig").Error)!*Target {
        const self = try gpa.create(Target);
        self.* = .{ .allocator = gpa, .arena = .init(gpa) };
        errdefer self.release();
        const arena = self.arena.allocator();
        var children = object();
        var endpoints: std.ArrayList(channel.Endpoint) = .empty;
        for (entries) |value| {
            var implementation = object();
            try field(arena, &implementation, "clusterName", string(value.identity.name));
            const cluster = if (value.cluster) |resource| resource.resource.value else null;
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
            } else child_policy = try policy(arena, "round_robin", object());
            try field(arena, &implementation, "dropCategories", drops);
            try field(arena, &implementation, "childPolicy", child_policy);
            var child = object();
            try field(arena, &child, "childPolicy", try policy(arena, "xds_cluster_impl_experimental", implementation));
            try field(arena, &children, value.identity.key, child);
        }
        var manager = object();
        try field(arena, &manager, "children", children);
        var config = if (local_json) |json| std.json.parseFromSliceLeaky(Json, arena, json, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidServiceConfig else object();
        if (config != .object) return error.InvalidServiceConfig;
        try field(arena, &config, "loadBalancingConfig", try policy(arena, "xds_cluster_manager_experimental", manager));
        self.json = try std.json.Stringify.valueAlloc(arena, config, .{});
        self.endpoints = try endpoints.toOwnedSlice(arena);
        return self;
    }
    pub fn retain(self: *Target) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Target) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        for (self.snapshots.items) |snapshot| snapshot.release();
        self.snapshots.deinit(self.allocator);
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
    pub fn publish(self: *Target, destination: shared.SharedChannel, selector: @import("../../channel/call_selector.zig").Selector, deadline: std.Io.Clock.Timestamp) shared.Error!u64 {
        return destination.updateWithDeadline(.{ .target = .{ .resolved = .{ .endpoints = self.endpoints } }, .target_lifetime = self.lifetime(), .service_config = .{ .replace = self.json }, .call_selector = .{ .replace = selector } }, deadline);
    }
};

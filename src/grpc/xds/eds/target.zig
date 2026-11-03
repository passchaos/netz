//! Reference-owned EDS projection into existing priority/locality channel policies.
const std = @import("std");
const decode = @import("decode.zig");
const channel = @import("../../channel.zig");
const shared = @import("../../channel/shared.zig");
const http2 = @import("../../../http2/mod.zig");
const tls_material = @import("../tls_material.zig");
pub const Error = decode.Error || shared.Error || tls_material.Error || error{ UnsupportedEdsPolicy, InvalidEdsTarget };
pub const Options = struct {
    authority: []const u8,
    /// CDS circuit limit and logical cluster identity; EDS service is resource name.
    max_concurrent_requests: u32 = 1024,
    cluster: ?[]const u8 = null,
    limits: http2.runtime.Limits = .{},
    tls: ?struct { host: []const u8, options: http2.runtime.TlsConnectOptions = .{} } = null,
    /// Owned inline TLS material for this projection, when the cluster declares it.
    tls_material: ?*tls_material.Material = null,
    /// Endpoint-level child policy shared by every locality.
    child_policy_json: []const u8 = "[{\"round_robin\":{}}]",
    /// Wrap each priority in locality weighting; direct CDS policies flatten it.
    locality_weighted: bool = true,
    attempt_delay: std.Io.Duration = .fromMilliseconds(250),
};
const Json = std.json.Value;
fn object(_: std.mem.Allocator) Json {
    return .{ .object = .{} };
}
fn field(gpa: std.mem.Allocator, value: *Json, key: []const u8, child: Json) !void {
    try value.object.put(gpa, key, child);
}
fn text(bytes: []const u8) Json {
    return .{ .string = bytes };
}
fn array(gpa: std.mem.Allocator, value: Json) !Json {
    var result: Json = .{ .array = std.array_list.Managed(Json).init(gpa) };
    try result.array.append(value);
    return result;
}
fn policy(gpa: std.mem.Allocator, name: []const u8, config: Json) !Json {
    var result = object(gpa);
    try field(gpa, &result, name, config);
    return array(gpa, result);
}

const Connector = struct {
    addresses: []const std.Io.net.IpAddress,
    options: Options,
    fn connect(context: ?*anyopaque, gpa: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        const Race = struct {
            connector: *Connector,
            allocator: std.mem.Allocator,
            deadline: std.Io.Clock.Timestamp,
            fn one(ctx: @This(), active_io: std.Io, address: std.Io.net.IpAddress, _: usize) http2.runtime.Error!http2.runtime.Connection {
                return if (ctx.connector.options.tls) |tls| http2.runtime.Client.connectTlsAddressWithDeadline(ctx.allocator, active_io, address, tls.host, ctx.connector.options.authority, ctx.connector.options.limits, tls.options, ctx.deadline) else http2.runtime.Client.connectWithDeadline(ctx.allocator, active_io, address, ctx.connector.options.limits, ctx.deadline);
            }
            fn close(_: @This(), connection: *http2.runtime.Connection) void {
                connection.closeWithoutCloseNotify();
            }
            fn next(err: http2.runtime.Error) bool {
                return err != error.Canceled and err != error.OutOfMemory and err != error.ConcurrencyUnavailable;
            }
        };
        return @import("../../../internal/connection_race.zig").race(http2.runtime.Error, http2.runtime.Connection, gpa, io, self.addresses, .{ .attempt_delay = self.options.attempt_delay, .max_in_flight = 2 }, deadline, error.Timeout, Race{ .connector = self, .allocator = gpa, .deadline = deadline }, Race.one, Race.close, Race.next) catch |err| switch (err) {
            error.NoAddressReturned => error.InvalidAddressConnectPolicy,
            else => @errorCast(err),
        };
    }
};
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    resource: decode.Owned,
    endpoints: []const channel.Endpoint,
    service_config_json: []const u8,
    circuit: channel.circuit_breaker.Options,
    tls_material: ?*tls_material.Material = null,
    pub fn create(gpa: std.mem.Allocator, bytes: []const u8, bounds: decode.Limits, options: Options) Error!*Snapshot {
        if (options.authority.len == 0 or options.attempt_delay.nanoseconds <= 0) return error.InvalidEdsTarget;
        const material = options.tls_material;
        errdefer if (material) |value| value.deinit();
        var resource = try decode.decode(gpa, bytes, bounds);
        errdefer resource.deinit();
        const arena = resource.arena.allocator();
        const authority = try arena.dupe(u8, options.authority);
        var retained_options = options;
        retained_options.authority = authority;
        if (retained_options.tls) |*tls| tls.host = try arena.dupe(u8, tls.host);
        const parsed_child = std.json.parseFromSlice(Json, arena, options.child_policy_json, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidEdsTarget;
        if (parsed_child.value != .array or parsed_child.value.array.items.len == 0) return error.InvalidEdsTarget;
        var children = object(arena);
        var order: Json = .{ .array = std.array_list.Managed(Json).init(arena) };
        var endpoints: std.ArrayList(channel.Endpoint) = .empty;
        for (0..resource.value.priority_count) |priority| {
            const priority_name = try std.fmt.allocPrint(arena, "priority-{d}", .{priority});
            try order.array.append(text(priority_name));
            var child = object(arena);
            var locality_policy = object(arena);
            try field(arena, &locality_policy, "childPolicy", parsed_child.value);
            try field(arena, &child, "config", if (options.locality_weighted) try policy(arena, "xds_wrr_locality_experimental", locality_policy) else parsed_child.value);
            try field(arena, &child, "ignoreReresolutionRequests", .{ .bool = true });
            try field(arena, &children, priority_name, child);
            for (resource.value.localities) |locality| {
                if (locality.priority != priority) continue;
                // Length prefixes preserve exact protobuf identity even for
                // locality components that contain punctuation or separators.
                const name = try std.fmt.allocPrint(arena, "{d}:{s}{d}:{s}{d}:{s}", .{ locality.region.len, locality.region, locality.zone.len, locality.zone, locality.sub_zone.len, locality.sub_zone });
                // Leaf selection matches its priority prefix. Retain locality
                // suffixes across direct/wrapped policy changes so otherwise
                // identical transports keep their connection identity.
                const path = try arena.alloc([]const u8, 2);
                path[0] = priority_name;
                path[1] = name;
                for (locality.endpoints) |endpoint| {
                    // Standard serving picks use UNKNOWN/HEALTHY. DRAINING is
                    // retained in the resource model for override-host routing.
                    if (endpoint.health == .draining) continue;
                    const weight = if (options.locality_weighted) endpoint.weight else std.math.mul(u32, locality.weight, endpoint.weight) catch return error.InvalidEdsTarget;
                    const key = try std.fmt.allocPrint(arena, "{f}", .{endpoint.addresses[0]});
                    const value: channel.Endpoint = if (endpoint.addresses.len > 1) blk: {
                        const connector = try arena.create(Connector);
                        connector.* = .{ .addresses = endpoint.addresses, .options = retained_options };
                        break :blk .{ .custom = .{ .context = connector, .connect_fn = Connector.connect, .ring_hash_key = key, .ring_hash_weight = weight, .hierarchical_path = path, .locality_weight = locality.weight } };
                    } else if (options.tls) |tls| .{ .tls_address = .{ .address = endpoint.addresses[0], .tls_host = retained_options.tls.?.host, .authority = authority, .tls = tls.options, .limits = options.limits, .ring_hash_key = key, .ring_hash_weight = weight, .hierarchical_path = path, .locality_weight = locality.weight } } else .{ .cleartext_ip = .{ .address = endpoint.addresses[0], .authority = authority, .limits = options.limits, .ring_hash_key = key, .ring_hash_weight = weight, .hierarchical_path = path, .locality_weight = locality.weight } };
                    try endpoints.append(arena, value);
                }
            }
        }
        var config = object(arena);
        var priority_config = object(arena);
        try field(arena, &priority_config, "children", children);
        try field(arena, &priority_config, "priorities", order);
        try field(arena, &config, "loadBalancingConfig", try policy(arena, "priority_experimental", priority_config));
        const json = try std.json.Stringify.valueAlloc(arena, config, .{});
        var checked = @import("../../service_config.zig").ServiceConfig.parse(arena, json) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidEdsTarget;
        checked.deinit();
        const values = try endpoints.toOwnedSlice(arena);
        const cluster = try arena.dupe(u8, options.cluster orelse resource.value.cluster_name);
        const self = try gpa.create(Snapshot);
        self.* = .{ .allocator = gpa, .resource = resource, .endpoints = values, .service_config_json = json, .circuit = .{ .cluster = cluster, .eds_service_name = resource.value.cluster_name, .max_concurrent_requests = options.max_concurrent_requests }, .tls_material = material };
        return self;
    }
    pub fn retain(self: *Snapshot) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Snapshot) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.tls_material) |value| value.deinit();
        self.resource.deinit();
        self.allocator.destroy(self);
    }
    fn retainContext(context: *anyopaque) void {
        const self: *Snapshot = @ptrCast(@alignCast(context));
        self.retain();
    }
    fn releaseContext(context: *anyopaque) void {
        const self: *Snapshot = @ptrCast(@alignCast(context));
        self.release();
    }
    pub fn lifetime(self: *Snapshot) @import("../../channel/shared/target_lifetime.zig").Lifetime {
        return .{ .context = self, .retain_fn = retainContext, .release_fn = releaseContext };
    }
    pub fn publishWithDeadline(self: *Snapshot, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        return destination.updateWithDeadline(.{ .target = .{ .resolved = .{ .endpoints = self.endpoints } }, .target_lifetime = self.lifetime(), .drop_categories = .{ .replace = self.resource.value.drops }, .circuit_breaker = .{ .replace = self.circuit }, .service_config = .{ .replace = self.service_config_json } }, deadline);
    }
};

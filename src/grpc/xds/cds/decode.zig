//! Owned EDS-backed Envoy v3 Cluster data used by the application resolver.
const std = @import("std");
const pb = @import("protobuf.zig");
const policy = @import("policy.zig");
pub const type_url = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const Error = pb.Error;
pub const Limits = struct { max_bytes: usize = 8 * 1024 * 1024, max_text_bytes: usize = 4096, max_thresholds: usize = 256, max_policies: usize = 32, max_endpoints: usize = 65536 };
pub const Discovery = enum(u32) { static = 0, strict_dns = 1, logical_dns = 2, eds = 3, _ };
pub const HostEndpoint = struct {
    host: []const u8,
    port: u16,
    priority: u32 = 0,
    endpoint_weight: u32 = 1,
    locality_weight: u32 = 1,
    region: []const u8 = "",
    zone: []const u8 = "",
    sub_zone: []const u8 = "",
};
pub const Cluster = struct {
    name: []const u8,
    eds_service_name: []const u8,
    discovery: Discovery = .eds,
    /// Raw inline `ClusterLoadAssignment` for STATIC/DNS clusters.
    inline_assignment: []const u8 = "",
    /// Flattened DNS endpoints, retaining priority/locality identity.
    host_endpoints: []const HostEndpoint = &.{},
    max_concurrent_requests: u32 = 1024,
    policy: policy.Result,
    pub fn isEds(self: Cluster) bool {
        return self.discovery == .eds;
    }
    pub fn isDns(self: Cluster) bool {
        return self.discovery == .strict_dns or self.discovery == .logical_dns;
    }
    pub fn edsName(self: Cluster) []const u8 {
        if (!self.isEds()) return "";
        return if (self.eds_service_name.len != 0) self.eds_service_name else self.name;
    }
};
pub const Owned = struct {
    wire: []const u8 = "",
    arena: std.heap.ArenaAllocator,
    value: Cluster,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn eds(bytes: []const u8, text_limit: usize) Error![]const u8 {
    var reader: pb.Reader = .{ .bytes = bytes };
    var source: ?[]const u8 = null;
    var service: []const u8 = "";
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) source = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) service = try pb.text(&reader, text_limit) else try reader.skip(field);
    }
    _ = @import("../config_source.zig").decode(source orelse return error.InvalidCdsResource) catch |err| return switch (err) {
        error.InvalidConfigSource => error.InvalidCdsResource,
        error.UnsupportedConfigSource => error.UnsupportedCdsFeature,
        else => @errorCast(err),
    };
    return service;
}
const Socket = struct { host: []const u8, port: u16 };

const DnsParser = struct {
    arena: std.mem.Allocator,
    limits: Limits,
    count: usize = 0,

    fn text(self: DnsParser, reader: *pb.Reader) Error![]const u8 {
        const value = try reader.string();
        if (value.len > self.limits.max_text_bytes) return error.CdsLimitExceeded;
        return value;
    }
    fn u32Value(_: DnsParser, reader: *pb.Reader) Error!u32 {
        const value = try reader.varint();
        if (value > std.math.maxInt(u32)) return error.InvalidCdsResource;
        return @intCast(value);
    }
    fn wrapper(self: DnsParser, bytes: []const u8) Error!u32 {
        var value: u32 = 0;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 0) value = try self.u32Value(&reader) else try reader.skip(field);
        }
        return value;
    }
    fn socket(self: DnsParser, bytes: []const u8) Error!Socket {
        var host: []const u8 = "";
        var port: ?u32 = null;
        var protocol: u32 = 0;
        var resolver: []const u8 = "";
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 0) protocol = try self.u32Value(&reader) else if (field.number == 2 and field.wire_type == 2) host = try self.text(&reader) else if (field.number == 3 and field.wire_type == 0) port = try self.u32Value(&reader) else if (field.number == 4 and field.wire_type == 2) resolver = try self.text(&reader) else try reader.skip(field);
        }
        if (protocol != 0 or resolver.len != 0) return error.UnsupportedCdsFeature;
        const value = port orelse return error.InvalidCdsResource;
        if (value == 0 or value > 65535 or host.len == 0) return error.InvalidCdsResource;
        return .{ .host = host, .port = @intCast(value) };
    }
    fn address(self: DnsParser, bytes: []const u8) Error!Socket {
        var socket_bytes: ?[]const u8 = null;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) socket_bytes = try reader.bytesValue() else if ((field.number == 2 or field.number == 3) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
        }
        return self.socket(socket_bytes orelse return error.InvalidCdsResource);
    }
    fn endpoint(self: DnsParser, bytes: []const u8) Error!Socket {
        var address_bytes: ?[]const u8 = null;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) address_bytes = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 2) {
                _ = try self.text(&reader);
            } else if (field.number == 4 and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
        }
        return self.address(address_bytes orelse return error.InvalidCdsResource);
    }
    fn lbEndpoint(self: *DnsParser, bytes: []const u8) Error!?HostEndpoint {
        var endpoint_bytes: ?[]const u8 = null;
        var weight_bytes: ?[]const u8 = null;
        var health: u32 = 0;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) endpoint_bytes = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 0) health = try self.u32Value(&reader) else if (field.number == 4 and field.wire_type == 2) weight_bytes = try reader.bytesValue() else try reader.skip(field);
        }
        if (health != 0 and health != 1 and health != 3) return null;
        const weight = if (weight_bytes) |raw| try self.wrapper(raw) else 1;
        if (weight == 0) return error.InvalidCdsResource;
        if (self.count >= self.limits.max_endpoints) return error.CdsLimitExceeded;
        self.count += 1;
        const socket_value = try self.endpoint(endpoint_bytes orelse return error.InvalidCdsResource);
        return .{ .host = socket_value.host, .port = socket_value.port, .endpoint_weight = weight };
    }
    fn locality(self: *DnsParser, bytes: []const u8, out: *std.ArrayList(HostEndpoint)) Error!void {
        var locality_bytes: ?[]const u8 = null;
        var weight: u32 = 1;
        var priority: u32 = 0;
        var endpoint_bytes: std.ArrayList([]const u8) = .empty;
        defer endpoint_bytes.deinit(self.arena);
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) locality_bytes = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 2) weight = try self.wrapper(try reader.bytesValue()) else if (field.number == 5 and field.wire_type == 0) priority = try self.u32Value(&reader) else if (field.number == 2 and field.wire_type == 2) {
                try endpoint_bytes.append(self.arena, try reader.bytesValue());
            } else if ((field.number == 7 or field.number == 8) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
        }
        if (weight == 0) return error.InvalidCdsResource;
        var region: []const u8 = "";
        var zone: []const u8 = "";
        var sub_zone: []const u8 = "";
        if (locality_bytes) |raw| {
            var location: pb.Reader = .{ .bytes = raw };
            while (try location.next()) |field| {
                if (field.number == 1 and field.wire_type == 2) region = try self.text(&location) else if (field.number == 2 and field.wire_type == 2) zone = try self.text(&location) else if (field.number == 3 and field.wire_type == 2) sub_zone = try self.text(&location) else try location.skip(field);
            }
        }
        for (endpoint_bytes.items) |raw| {
            const value = (try self.lbEndpoint(raw)) orelse continue;
            try out.append(self.arena, .{ .host = value.host, .port = value.port, .priority = priority, .endpoint_weight = value.endpoint_weight, .locality_weight = weight, .region = region, .zone = zone, .sub_zone = sub_zone });
        }
    }
};

fn onePerLocality(arena: std.mem.Allocator, hosts: []const HostEndpoint) Error![]const HostEndpoint {
    var selected: std.ArrayList(HostEndpoint) = .empty;
    for (hosts) |host| {
        var duplicate = false;
        for (selected.items) |existing| {
            if (existing.priority == host.priority and std.mem.eql(u8, existing.region, host.region) and std.mem.eql(u8, existing.zone, host.zone) and std.mem.eql(u8, existing.sub_zone, host.sub_zone)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) try selected.append(arena, host);
    }
    return selected.toOwnedSlice(arena);
}

fn dnsAssignment(arena: std.mem.Allocator, bytes: []const u8, name: []const u8, limits: Limits) Error![]const HostEndpoint {
    var parser = DnsParser{ .arena = arena, .limits = limits };
    var endpoints: std.ArrayList(HostEndpoint) = .empty;
    var cluster_name: []const u8 = "";
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) cluster_name = try parser.text(&reader) else if (field.number == 2 and field.wire_type == 2) {
            try parser.locality(try reader.bytesValue(), &endpoints);
        } else try reader.skip(field);
    }
    if (!std.mem.eql(u8, cluster_name, name)) return error.InvalidCdsResource;
    return endpoints.toOwnedSlice(arena);
}

fn circuit(bytes: []const u8, limit: usize) Error!u32 {
    var reader: pb.Reader = .{ .bytes = bytes };
    var count: usize = 0;
    var selected: ?u32 = null;
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        if (count >= limit) return error.CdsLimitExceeded;
        count += 1;
        var threshold: pb.Reader = .{ .bytes = try reader.bytesValue() };
        var priority: u32 = 0;
        var maximum: ?[]const u8 = null;
        while (try threshold.next()) |value| {
            if (value.number == 1 and value.wire_type == 0) priority = try pb.u32Value(&threshold) else if (value.number == 4 and value.wire_type == 2) maximum = try threshold.bytesValue() else try threshold.skip(value);
        }
        const raw = if (maximum) |value| try pb.wrapper(value) else 1024;
        if (raw > std.math.maxInt(u32)) return error.InvalidCdsResource;
        // DEFAULT selection does not excuse malformed nested wire data in a
        // HIGH or later threshold: the whole resource must decode first.
        if (priority != 0 or selected != null) continue;
        selected = @intCast(raw);
    }
    return selected orelse 1024;
}
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Owned {
    if (bytes.len > limits.max_bytes) return error.CdsLimitExceeded;
    var result = Owned{ .arena = .init(gpa), .value = undefined };
    errdefer result.deinit();
    const arena = result.arena.allocator();
    const image = try arena.dupe(u8, bytes);
    result.wire = image;
    var reader: pb.Reader = .{ .bytes = image };
    var name: []const u8 = "";
    var kind: u32 = 0;
    var config: ?[]const u8 = null;
    var assignment: ?[]const u8 = null;
    var lb: u32 = 0;
    var ring_config: ?[]const u8 = null;
    var typed_policy: ?[]const u8 = null;
    var breaker: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limits.max_text_bytes) else if (field.number == 2 and field.wire_type == 0) kind = try pb.u32Value(&reader) else if (field.number == 38 and field.wire_type == 2) {
            _ = try reader.bytesValue();
            kind = std.math.maxInt(u32);
        } else if (field.number == 3 and field.wire_type == 2) config = try reader.bytesValue() else if (field.number == 33 and field.wire_type == 2) assignment = try reader.bytesValue() else if (field.number == 6 and field.wire_type == 0) lb = try pb.u32Value(&reader) else if (field.number == 23 and field.wire_type == 2) ring_config = try reader.bytesValue() else if (field.number == 41 and field.wire_type == 2) typed_policy = try reader.bytesValue() else if (field.number == 10 and field.wire_type == 2) breaker = try reader.bytesValue() else if ((field.number == 24 or field.number == 43 or field.number == 19 or field.number == 42 or field.number == 48) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidCdsResource;
    const discovery: Discovery = @enumFromInt(kind);
    var service: []const u8 = "";
    var inline_assignment: []const u8 = "";
    var host_endpoints: []const HostEndpoint = &.{};
    switch (discovery) {
        .eds => {
            service = try eds(config orelse return error.InvalidCdsResource, limits.max_text_bytes);
            if (std.mem.startsWith(u8, name, "xdstp:") and service.len == 0) return error.InvalidCdsResource;
        },
        .static => {
            const raw = assignment orelse return error.InvalidCdsResource;
            var checked = @import("../eds/decode.zig").decode(arena, raw, .{ .max_bytes = limits.max_bytes }) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidCdsResource,
            };
            defer checked.deinit();
            if (!std.mem.eql(u8, checked.value.cluster_name, name)) return error.InvalidCdsResource;
            inline_assignment = raw;
        },
        .strict_dns, .logical_dns => {
            const raw = assignment orelse return error.InvalidCdsResource;
            host_endpoints = try dnsAssignment(arena, raw, name, limits);
            if (discovery == .logical_dns) host_endpoints = try onePerLocality(arena, host_endpoints);
            inline_assignment = raw;
        },
        else => return error.UnsupportedCdsFeature,
    }
    result.value = .{ .name = name, .eds_service_name = service, .discovery = discovery, .inline_assignment = inline_assignment, .host_endpoints = host_endpoints, .max_concurrent_requests = if (breaker) |raw| try circuit(raw, limits.max_thresholds) else 1024, .policy = if (typed_policy) |raw| try policy.typed(arena, raw, limits.max_policies, limits.max_text_bytes, 0) else try policy.legacy(arena, lb, ring_config) };
    // Converted policies must satisfy the same configuration parser/runtime
    // contract as direct callers, including complete range validation.
    const json = try std.fmt.allocPrint(arena, "{{\"loadBalancingConfig\":{s}}}", .{result.value.policy.child_json});
    var checked = @import("../../service_config.zig").ServiceConfig.parse(arena, json) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidCdsResource;
    checked.deinit();
    return result;
}

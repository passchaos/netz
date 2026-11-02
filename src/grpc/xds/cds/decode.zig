//! Owned EDS-backed Envoy v3 Cluster data used by the application resolver.
const std = @import("std");
const pb = @import("protobuf.zig");
const policy = @import("policy.zig");
pub const type_url = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const Error = pb.Error;
pub const Limits = struct { max_bytes: usize = 8 * 1024 * 1024, max_text_bytes: usize = 4096, max_thresholds: usize = 256, max_policies: usize = 32 };
pub const Cluster = struct {
    name: []const u8,
    eds_service_name: []const u8,
    max_concurrent_requests: u32 = 1024,
    policy: policy.Result,
    pub fn edsName(self: Cluster) []const u8 {
        return if (self.eds_service_name.len != 0) self.eds_service_name else self.name;
    }
};
pub const Owned = struct {
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
    var source_reader: pb.Reader = .{ .bytes = source orelse return error.InvalidCdsResource };
    var supported = false;
    while (try source_reader.next()) |field| {
        if ((field.number == 3 or field.number == 5) and field.wire_type == 2) {
            try pb.validate(try source_reader.bytesValue());
            supported = true;
        } else if ((field.number == 1 or field.number == 2 or field.number == 8) and field.wire_type == 2) {
            _ = try source_reader.bytesValue();
            supported = false;
        } else if (field.number == 6 and field.wire_type == 0) {
            if (try source_reader.varint() != 2) return error.UnsupportedCdsFeature;
        } else try source_reader.skip(field);
    }
    if (!supported) return error.InvalidCdsResource;
    return service;
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
    var reader: pb.Reader = .{ .bytes = image };
    var name: []const u8 = "";
    var kind: u32 = 0;
    var config: ?[]const u8 = null;
    var lb: u32 = 0;
    var ring_config: ?[]const u8 = null;
    var typed_policy: ?[]const u8 = null;
    var breaker: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limits.max_text_bytes) else if (field.number == 2 and field.wire_type == 0) kind = try pb.u32Value(&reader) else if (field.number == 38 and field.wire_type == 2) {
            _ = try reader.bytesValue();
            kind = std.math.maxInt(u32);
        } else if (field.number == 3 and field.wire_type == 2) config = try reader.bytesValue() else if (field.number == 6 and field.wire_type == 0) lb = try pb.u32Value(&reader) else if (field.number == 23 and field.wire_type == 2) ring_config = try reader.bytesValue() else if (field.number == 41 and field.wire_type == 2) typed_policy = try reader.bytesValue() else if (field.number == 10 and field.wire_type == 2) breaker = try reader.bytesValue() else if ((field.number == 24 or field.number == 43 or field.number == 19 or field.number == 42 or field.number == 48) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidCdsResource;
    if (kind != 3) return error.UnsupportedCdsFeature;
    const service = try eds(config orelse return error.InvalidCdsResource, limits.max_text_bytes);
    if (std.mem.startsWith(u8, name, "xdstp:") and service.len == 0) return error.InvalidCdsResource;
    result.value = .{ .name = name, .eds_service_name = service, .max_concurrent_requests = if (breaker) |raw| try circuit(raw, limits.max_thresholds) else 1024, .policy = if (typed_policy) |raw| try policy.typed(arena, raw, limits.max_policies, limits.max_text_bytes, 0) else try policy.legacy(arena, lb, ring_config) };
    // Converted policies must satisfy the same configuration parser/runtime
    // contract as direct callers, including complete range validation.
    const json = try std.fmt.allocPrint(arena, "{{\"loadBalancingConfig\":{s}}}", .{result.value.policy.child_json});
    var checked = @import("../../service_config.zig").ServiceConfig.parse(arena, json) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidCdsResource;
    checked.deinit();
    return result;
}

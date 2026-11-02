//! Bounded Envoy v3 ClusterLoadAssignment decoding with owned resource storage.
const std = @import("std");
const pb = @import("../../protobuf.zig");
pub const type_url = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
pub const Error = pb.Error || std.mem.Allocator.Error || error{ InvalidEdsResource, EdsLimitExceeded, UnsupportedEdsAddress };
pub const Limits = struct { max_bytes: usize = 8 * 1024 * 1024, max_localities: usize = 1024, max_endpoints: usize = 65536, max_addresses_per_endpoint: usize = 16, max_drops: usize = 256, max_text_bytes: usize = 4096, max_priority: u32 = 128 };
pub const Health = enum(u32) { unknown = 0, healthy = 1, unhealthy = 2, draining = 3, timeout = 4, degraded = 5, _ };
pub const Endpoint = struct { addresses: []const std.Io.net.IpAddress, weight: u32 = 1, health: Health = .unknown, hostname: []const u8 = "" };
pub const Locality = struct { region: []const u8 = "", zone: []const u8 = "", sub_zone: []const u8 = "", weight: u32, priority: u32, endpoints: []const Endpoint };
pub const Drop = @import("../../channel/drop_policy.zig").Category;
pub const Assignment = struct { cluster_name: []const u8, localities: []const Locality, drops: []const Drop, priority_count: usize };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    value: Assignment,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const Parser = struct {
    gpa: std.mem.Allocator,
    limits: Limits,
    endpoint_count: usize = 0,
    fn text(self: Parser, reader: *pb.Reader) Error![]const u8 {
        const value = try reader.string();
        if (value.len > self.limits.max_text_bytes) return error.EdsLimitExceeded;
        return value;
    }
    fn u32Value(_: Parser, reader: *pb.Reader) Error!u32 {
        const value = try reader.varint();
        if (value > std.math.maxInt(u32)) return error.InvalidEdsResource;
        return @intCast(value);
    }
    fn wrapper(self: Parser, bytes: []const u8) Error!u32 {
        var value: u32 = 0;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 0) value = try self.u32Value(&reader) else try reader.skip(field);
        }
        return value;
    }
    fn socket(self: Parser, bytes: []const u8) Error!std.Io.net.IpAddress {
        var host: []const u8 = "";
        var port: ?u32 = null;
        var protocol: u32 = 0;
        var resolver: []const u8 = "";
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 0) protocol = try self.u32Value(&reader) else if (field.number == 2 and field.wire_type == 2) host = try self.text(&reader) else if (field.number == 3 and field.wire_type == 0) port = try self.u32Value(&reader) else if (field.number == 4 and field.wire_type == 2) {
                _ = try self.text(&reader);
                port = null;
            } else if (field.number == 5 and field.wire_type == 2) resolver = try self.text(&reader) else try reader.skip(field);
        }
        if (protocol != 0 or resolver.len != 0) return error.UnsupportedEdsAddress;
        const value = port orelse return error.InvalidEdsResource;
        if (value == 0 or value > 65535 or host.len == 0) return error.InvalidEdsResource;
        return std.Io.net.IpAddress.parse(host, @intCast(value)) catch return error.UnsupportedEdsAddress;
    }
    fn address(self: Parser, bytes: []const u8) Error!std.Io.net.IpAddress {
        var socket_bytes: ?[]const u8 = null;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) socket_bytes = try reader.bytesValue() else if ((field.number == 2 or field.number == 3) and field.wire_type == 2) {
                _ = try reader.bytesValue();
                socket_bytes = null;
            } else try reader.skip(field);
        }
        return self.socket(socket_bytes orelse return error.UnsupportedEdsAddress);
    }
    fn endpoint(self: *Parser, bytes: []const u8) Error!Endpoint {
        var main: ?std.Io.net.IpAddress = null;
        var extras: std.ArrayList(std.Io.net.IpAddress) = .empty;
        var hostname: []const u8 = "";
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) main = try self.address(try reader.bytesValue()) else if (field.number == 3 and field.wire_type == 2) hostname = try self.text(&reader) else if (field.number == 4 and field.wire_type == 2) {
                if (extras.items.len + 1 >= self.limits.max_addresses_per_endpoint) return error.EdsLimitExceeded;
                var extra: pb.Reader = .{ .bytes = try reader.bytesValue() };
                var parsed: ?std.Io.net.IpAddress = null;
                while (try extra.next()) |nested| {
                    if (nested.number == 1 and nested.wire_type == 2) parsed = try self.address(try extra.bytesValue()) else try extra.skip(nested);
                }
                try extras.append(self.gpa, parsed orelse return error.InvalidEdsResource);
            } else try reader.skip(field);
        }
        const first = main orelse return error.InvalidEdsResource;
        const addresses = try self.gpa.alloc(std.Io.net.IpAddress, extras.items.len + 1);
        addresses[0] = first;
        @memcpy(addresses[1..], extras.items);
        return .{ .addresses = addresses, .hostname = hostname };
    }
    fn lbEndpoint(self: *Parser, bytes: []const u8) Error!?Endpoint {
        var endpoint_bytes: ?[]const u8 = null;
        var weight_bytes: ?[]const u8 = null;
        var health: Health = .unknown;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) endpoint_bytes = try reader.bytesValue() else if (field.number == 5 and field.wire_type == 2) {
                _ = try self.text(&reader);
                endpoint_bytes = null;
            } else if (field.number == 2 and field.wire_type == 0) health = @enumFromInt(try self.u32Value(&reader)) else if (field.number == 4 and field.wire_type == 2) weight_bytes = try reader.bytesValue() else try reader.skip(field);
        }
        // Match grpc-core: unsupported health statuses do not enter the set
        // and do not make their endpoint details a validation failure.
        if (health != .unknown and health != .healthy and health != .draining) return null;
        const weight = if (weight_bytes) |raw| try self.wrapper(raw) else 1;
        if (weight == 0) return error.InvalidEdsResource;
        if (self.endpoint_count >= self.limits.max_endpoints) return error.EdsLimitExceeded;
        self.endpoint_count += 1;
        var result = try self.endpoint(endpoint_bytes orelse return error.InvalidEdsResource);
        result.weight = weight;
        result.health = health;
        return result;
    }
    fn locality(self: *Parser, bytes: []const u8) Error!?Locality {
        var locality_bytes: ?[]const u8 = null;
        var weight: u32 = 0;
        var priority: u32 = 0;
        var endpoint_bytes: std.ArrayList([]const u8) = .empty;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) locality_bytes = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 2) weight = try self.wrapper(try reader.bytesValue()) else if (field.number == 5 and field.wire_type == 0) priority = try self.u32Value(&reader) else if (field.number == 2 and field.wire_type == 2) {
                if (endpoint_bytes.items.len >= self.limits.max_endpoints) return error.EdsLimitExceeded;
                try endpoint_bytes.append(self.gpa, try reader.bytesValue());
            } else if ((field.number == 7 or field.number == 8) and field.wire_type == 2) return error.InvalidEdsResource else try reader.skip(field);
        }
        if (weight == 0) return null;
        if (priority > self.limits.max_priority) return error.EdsLimitExceeded;
        var result: Locality = .{ .weight = weight, .priority = priority, .endpoints = &.{} };
        var location: pb.Reader = .{ .bytes = locality_bytes orelse return error.InvalidEdsResource };
        while (try location.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) result.region = try self.text(&location) else if (field.number == 2 and field.wire_type == 2) result.zone = try self.text(&location) else if (field.number == 3 and field.wire_type == 2) result.sub_zone = try self.text(&location) else try location.skip(field);
        }
        var endpoints: std.ArrayList(Endpoint) = .empty;
        for (endpoint_bytes.items) |raw| if (try self.lbEndpoint(raw)) |value| try endpoints.append(self.gpa, value);
        result.endpoints = try endpoints.toOwnedSlice(self.gpa);
        return result;
    }
    fn drops(self: *Parser, bytes: []const u8) Error![]const Drop {
        var drops_list: std.ArrayList(Drop) = .empty;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number != 2 or field.wire_type != 2) {
                try reader.skip(field);
                continue;
            }
            if (drops_list.items.len >= self.limits.max_drops) return error.EdsLimitExceeded;
            var overload: pb.Reader = .{ .bytes = try reader.bytesValue() };
            var category: []const u8 = "";
            var percent: ?[]const u8 = null;
            while (try overload.next()) |nested| {
                if (nested.number == 1 and nested.wire_type == 2) category = try self.text(&overload) else if (nested.number == 2 and nested.wire_type == 2) percent = try overload.bytesValue() else try overload.skip(nested);
            }
            if (category.len == 0) return error.InvalidEdsResource;
            var fraction: pb.Reader = .{ .bytes = percent orelse return error.InvalidEdsResource };
            var numerator: u32 = 0;
            var denominator: u32 = 0;
            while (try fraction.next()) |nested| {
                if (nested.number == 1 and nested.wire_type == 0) numerator = try self.u32Value(&fraction) else if (nested.number == 2 and nested.wire_type == 0) denominator = try self.u32Value(&fraction) else try fraction.skip(nested);
            }
            const factor: u32 = switch (denominator) {
                0 => 10000,
                1 => 100,
                2 => 1,
                else => return error.InvalidEdsResource,
            };
            try drops_list.append(self.gpa, .{ .category = category, .requests_per_million = @intCast(@min(@as(u64, numerator) * factor, 1000000)) });
        }
        return drops_list.toOwnedSlice(self.gpa);
    }
};
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Owned {
    if (bytes.len > limits.max_bytes or limits.max_addresses_per_endpoint == 0) return error.EdsLimitExceeded;
    var owned = Owned{ .arena = .init(allocator), .value = undefined };
    errdefer owned.deinit();
    const gpa = owned.arena.allocator();
    var parser = Parser{ .gpa = gpa, .limits = limits };
    const storage = try gpa.dupe(u8, bytes);
    var reader: pb.Reader = .{ .bytes = storage };
    var cluster_name: []const u8 = "";
    var localities: std.ArrayList(Locality) = .empty;
    var policy_bytes: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) cluster_name = try parser.text(&reader) else if (field.number == 2 and field.wire_type == 2) {
            if (localities.items.len >= limits.max_localities) return error.EdsLimitExceeded;
            if (try parser.locality(try reader.bytesValue())) |value| try localities.append(gpa, value);
        } else if (field.number == 4 and field.wire_type == 2) policy_bytes = try reader.bytesValue() else try reader.skip(field);
    }
    if (cluster_name.len == 0) return error.InvalidEdsResource;
    var priorities: usize = 0;
    for (localities.items, 0..) |location, index| {
        priorities = @max(priorities, @as(usize, location.priority) + 1);
        for (localities.items[0..index]) |previous| if (location.priority == previous.priority and std.mem.eql(u8, location.region, previous.region) and std.mem.eql(u8, location.zone, previous.zone) and std.mem.eql(u8, location.sub_zone, previous.sub_zone)) return error.InvalidEdsResource;
    }
    for (0..priorities) |priority| {
        var present = false;
        var sum: u64 = 0;
        for (localities.items) |location| if (location.priority == priority) {
            present = true;
            sum += location.weight;
        };
        if (!present or sum > std.math.maxInt(u32)) return error.InvalidEdsResource;
    }
    var addresses: std.ArrayList(std.Io.net.IpAddress) = .empty;
    for (localities.items) |location| for (location.endpoints) |endpoint| for (endpoint.addresses) |address| {
        for (addresses.items) |previous| if (std.meta.eql(address, previous)) return error.InvalidEdsResource;
        try addresses.append(gpa, address);
    };
    owned.value = .{ .cluster_name = cluster_name, .localities = try localities.toOwnedSlice(gpa), .drops = if (policy_bytes) |raw| try parser.drops(raw) else &.{}, .priority_count = priorities };
    return owned;
}

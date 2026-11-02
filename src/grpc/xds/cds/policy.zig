//! Legacy CDS and ordered typed xDS LB policy conversion.
const std = @import("std");
const pb = @import("protobuf.zig");
pub const Error = pb.Error;
pub const Result = struct {
    child_json: []const u8,
    locality_weighted: bool = false,
};
fn leaf(gpa: std.mem.Allocator, name: []const u8, options: []const u8) Error!Result {
    return .{ .child_json = try std.fmt.allocPrint(gpa, "[{{\"{s}\":{s}}}]", .{ name, options }) };
}
fn ring(gpa: std.mem.Allocator, bytes: []const u8, modern: bool) Error!Result {
    var minimum: u64 = 1024;
    var maximum: u64 = 8388608;
    var hash: u32 = 0;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == (if (modern) @as(u32, 2) else 1) and field.wire_type == 2) minimum = try pb.wrapper(try reader.bytesValue()) else if (field.number == (if (modern) @as(u32, 3) else 4) and field.wire_type == 2) maximum = try pb.wrapper(try reader.bytesValue()) else if (field.number == (if (modern) @as(u32, 1) else 3) and field.wire_type == 0) hash = try pb.u32Value(&reader) else try reader.skip(field);
    }
    if (hash > (if (modern) @as(u32, 1) else 0) or minimum == 0 or minimum > maximum or maximum > 8388608) return error.InvalidCdsResource;
    const config = try std.fmt.allocPrint(gpa, "{{\"minRingSize\":{d},\"maxRingSize\":{d}}}", .{ minimum, maximum });
    return leaf(gpa, "ring_hash_experimental", config);
}
pub fn legacy(gpa: std.mem.Allocator, value: u32, ring_config: ?[]const u8) Error!Result {
    return switch (value) {
        0 => .{ .child_json = "[{\"round_robin\":{}}]", .locality_weighted = true },
        2 => try ring(gpa, ring_config orelse &.{}, false),
        else => error.UnsupportedCdsPolicy,
    };
}
const Raw = struct { type_url: []const u8, value: []const u8 };
fn any(bytes: []const u8, limit: usize) Error!Raw {
    var type_url: []const u8 = "";
    var value: []const u8 = &.{};
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) type_url = try pb.text(&reader, limit) else if (field.number == 2 and field.wire_type == 2) value = try reader.bytesValue() else try reader.skip(field);
    }
    if (type_url.len == 0) return error.InvalidCdsResource;
    return .{ .type_url = type_url, .value = value };
}
fn extension(bytes: []const u8, limit: usize) Error!Raw {
    var config_bytes: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 2 and field.wire_type == 2) config_bytes = try reader.bytesValue() else try reader.skip(field);
    }
    return any(config_bytes orelse return error.InvalidCdsResource, limit);
}
/// Unsupported types allow ordered fallback; a recognized invalid payload
/// fails the response and cannot silently select a later policy.
pub fn typed(gpa: std.mem.Allocator, bytes: []const u8, max_policies: usize, text_limit: usize, depth: usize) Error!Result {
    if (depth >= 16) return error.CdsLimitExceeded;
    // Bound and validate the whole outer list before selecting an early
    // supported policy. Trailing wire corruption cannot escape validation.
    var check: pb.Reader = .{ .bytes = bytes };
    var count: usize = 0;
    while (try check.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            if (count >= max_policies) return error.CdsLimitExceeded;
            count += 1;
            try pb.validate(try check.bytesValue());
        } else try check.skip(field);
    }
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        var policy_reader: pb.Reader = .{ .bytes = try reader.bytesValue() };
        var config: ?[]const u8 = null;
        while (try policy_reader.next()) |nested| {
            if (nested.number == 4 and nested.wire_type == 2) config = try policy_reader.bytesValue() else try policy_reader.skip(nested);
        }
        const raw = try extension(config orelse return error.InvalidCdsResource, text_limit);
        const slash = std.mem.lastIndexOfScalar(u8, raw.type_url, '/') orelse return error.InvalidCdsResource;
        const name = raw.type_url[slash + 1 ..];
        if (std.mem.eql(u8, name, "envoy.extensions.load_balancing_policies.round_robin.v3.RoundRobin")) {
            try pb.validate(raw.value);
            return .{ .child_json = "[{\"round_robin\":{}}]" };
        }
        if (std.mem.eql(u8, name, "envoy.extensions.load_balancing_policies.ring_hash.v3.RingHash")) return ring(gpa, raw.value, true);
        if (std.mem.eql(u8, name, "envoy.extensions.load_balancing_policies.pick_first.v3.PickFirst")) {
            var shuffle = false;
            var options_reader: pb.Reader = .{ .bytes = raw.value };
            while (try options_reader.next()) |option| {
                if (option.number == 1 and option.wire_type == 0) shuffle = try options_reader.varint() != 0 else try options_reader.skip(option);
            }
            return leaf(gpa, "pick_first", if (shuffle) "{\"shuffleAddressList\":true}" else "{}");
        }
        if (std.mem.eql(u8, name, "envoy.extensions.load_balancing_policies.least_request.v3.LeastRequest")) {
            var choices: u64 = 2;
            var options_reader: pb.Reader = .{ .bytes = raw.value };
            while (try options_reader.next()) |option| {
                if (option.number == 1 and option.wire_type == 2) choices = try pb.wrapper(try options_reader.bytesValue()) else try options_reader.skip(option);
            }
            if (choices < 2 or choices > std.math.maxInt(u32)) return error.InvalidCdsResource;
            return leaf(gpa, "least_request_experimental", try std.fmt.allocPrint(gpa, "{{\"choiceCount\":{d}}}", .{choices}));
        }
        if (std.mem.eql(u8, name, "envoy.extensions.load_balancing_policies.wrr_locality.v3.WrrLocality")) {
            var options_reader: pb.Reader = .{ .bytes = raw.value };
            var child: ?[]const u8 = null;
            while (try options_reader.next()) |option| {
                if (option.number == 1 and option.wire_type == 2) child = try options_reader.bytesValue() else try options_reader.skip(option);
            }
            var result = try typed(gpa, child orelse return error.InvalidCdsResource, max_policies, text_limit, depth + 1);
            if (result.locality_weighted) return error.UnsupportedCdsPolicy;
            result.locality_weighted = true;
            return result;
        }
    }
    return error.UnsupportedCdsPolicy;
}

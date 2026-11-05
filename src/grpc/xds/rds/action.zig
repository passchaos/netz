//! Cluster/weighted selection, timeout/retry and hash attributes from RDS.
const std = @import("std");
const pb = @import("protobuf.zig");
const model = @import("model.zig");
const routing = @import("../routing/mod.zig");
fn weighted(p: anytype, bytes: []const u8) pb.Error![]const model.Weighted {
    var reader = pb.Reader{ .bytes = bytes };
    var values: std.ArrayList(model.Weighted) = .empty;
    defer values.deinit(p.allocator);
    var count: usize = 0;
    var total: u64 = 0;
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        if (count >= p.limits.max_clusters_per_route) return error.RdsLimitExceeded;
        count += 1;
        try p.noteCluster();
        var nested = pb.Reader{ .bytes = try reader.bytesValue() };
        var name: []const u8 = "";
        var weight: ?u64 = null;
        while (try nested.next()) |entry| {
            if (entry.number == 1 and entry.wire_type == 2) name = try pb.text(&nested, p.limits.max_text_bytes) else if (entry.number == 2 and entry.wire_type == 2) weight = try pb.wrapper(try nested.bytesValue()) else if (entry.number == 10 and entry.wire_type == 2) return error.UnsupportedRdsFeature else try nested.skip(entry);
        }
        if (name.len == 0 or weight == null or weight.? > std.math.maxInt(u32)) return error.InvalidRdsResource;
        if (weight.? == 0) continue;
        total += weight.?;
        if (total > std.math.maxInt(u32)) return error.InvalidRdsResource;
        try values.append(p.allocator, .{ .name = name, .key = try std.fmt.allocPrint(p.allocator, "cluster:{s}", .{name}), .weight = @intCast(weight.?) });
    }
    if (values.items.len == 0) return error.InvalidRdsResource;
    // total_weight is deprecated; grpc-core uses the sum of non-zero weights.
    return values.toOwnedSlice(p.allocator);
}
fn hash(p: anytype, bytes: []const u8) pb.Error!?model.HashPolicy {
    var reader = pb.Reader{ .bytes = bytes };
    var kind: ?@FieldType(model.HashPolicy, "kind") = null;
    var terminal = false;
    while (try reader.next()) |field| {
        if (field.number == 4 and field.wire_type == 0) terminal = try reader.varint() != 0 else if ((field.number == 1 or field.number == 6) and field.wire_type == 2) {
            var nested = pb.Reader{ .bytes = try reader.bytesValue() };
            var name: []const u8 = "";
            while (try nested.next()) |entry| {
                if (entry.number == 1 and entry.wire_type == 2) name = try pb.text(&nested, p.limits.max_text_bytes) else if (field.number == 1 and entry.number == 2 and entry.wire_type == 2) return error.UnsupportedRdsFeature else try nested.skip(entry);
            }
            if (field.number == 1) {
                if (name.len == 0) return error.InvalidRdsResource;
                kind = .{ .header = name };
            } else kind = if (std.mem.eql(u8, name, "io.grpc.channel_id")) .channel_id else null;
        } else if ((field.number == 2 or field.number == 3 or field.number == 5) and field.wire_type == 2) {
            _ = try reader.bytesValue();
            kind = null; // unsupported cookie/connection/query hash source
        } else try reader.skip(field);
    }
    return if (kind) |selected| .{ .kind = selected, .terminal = terminal } else null;
}
fn timeout(bytes: []const u8) pb.Error!?std.Io.Duration {
    var reader = pb.Reader{ .bytes = bytes };
    var maximum: ?std.Io.Duration = null;
    var grpc: ?std.Io.Duration = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) maximum = try pb.duration(try reader.bytesValue()) else if (field.number == 2 and field.wire_type == 2) grpc = try pb.duration(try reader.bytesValue()) else if (field.number == 3 and field.wire_type == 2) return error.UnsupportedRdsFeature else try reader.skip(field);
    }
    return grpc orelse maximum;
}
fn rewriteText(reader: *pb.Reader, maximum: usize) pb.Error![]const u8 {
    const value = try pb.text(reader, maximum);
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidRdsResource;
    return value;
}
fn regexRewrite(p: anytype, bytes: []const u8) pb.Error!*const model.RegexRewrite {
    var reader = pb.Reader{ .bytes = bytes };
    var pattern: ?[]const u8 = null;
    var substitution: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            var matcher = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try matcher.next()) |entry| {
                if (entry.number == 2 and entry.wire_type == 2) {
                    pattern = try pb.text(&matcher, p.limits.max_text_bytes);
                } else try matcher.skip(entry);
            }
        } else if (field.number == 2 and field.wire_type == 2) {
            substitution = try pb.text(&reader, p.limits.max_text_bytes);
        } else try reader.skip(field);
    }
    const pattern_value = pattern orelse return error.InvalidRdsResource;
    if (pattern_value.len == 0) return error.InvalidRdsResource;
    const substitution_value = substitution orelse return error.InvalidRdsResource;
    const program = try routing.regex.compile(
        p.allocator,
        pattern_value,
        p.limits.regex,
    );
    routing.regex.validateSubstitution(
        substitution_value,
        program.capture_count,
    ) catch return error.InvalidRdsResource;
    const rewrite = try p.allocator.create(model.RegexRewrite);
    rewrite.* = .{
        .program = program,
        .substitution = substitution_value,
        .limits = p.limits.regex,
    };
    return rewrite;
}
pub fn decode(p: anytype, bytes: []const u8) pb.Error!?model.Forward {
    var reader = pb.Reader{ .bytes = bytes };
    var specifier: ?u32 = null;
    var name: []const u8 = "";
    var weighted_bytes: ?[]const u8 = null;
    var duration: ?std.Io.Duration = null;
    var retry: ?@import("../../call.zig").RetryPolicy = null;
    var retry_present = false;
    var path_rewrite: ?model.PathRewrite = null;
    var host_rewrite: ?model.HostRewrite = null;
    var policies: std.ArrayList(model.HashPolicy) = .empty;
    defer policies.deinit(p.allocator);
    var hash_count: usize = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            specifier = 1;
            name = try pb.text(&reader, p.limits.max_text_bytes);
        } else if (field.number == 3 and field.wire_type == 2) {
            specifier = 3;
            weighted_bytes = try reader.bytesValue();
        } else if ((field.number == 2 or field.number == 37 or field.number == 39) and field.wire_type == 2) {
            _ = try reader.bytesValue();
            specifier = field.number;
        } else if (field.number == 9 and field.wire_type == 2) {
            retry_present = true;
            retry = try @import("retry.zig").parse(p.allocator, try reader.bytesValue(), p.limits.max_text_bytes);
        } else if (field.number == 36 and field.wire_type == 2) duration = try timeout(try reader.bytesValue()) else if (field.number == 15 and field.wire_type == 2) {
            if (hash_count >= p.limits.max_hash_policies) return error.RdsLimitExceeded;
            hash_count += 1;
            if (try hash(p, try reader.bytesValue())) |policy| try policies.append(p.allocator, policy);
        } else if (field.number == 5 and field.wire_type == 2) {
            if (path_rewrite != null) return error.InvalidRdsResource;
            path_rewrite = .{ .prefix = try rewriteText(&reader, p.limits.max_text_bytes) };
        } else if (field.number == 6 and field.wire_type == 2) {
            if (host_rewrite != null) return error.InvalidRdsResource;
            const value = try rewriteText(&reader, p.limits.max_text_bytes);
            if (value.len == 0) return error.InvalidRdsResource;
            host_rewrite = .{ .literal = value };
        } else if (field.number == 7 and field.wire_type == 2) {
            if (host_rewrite != null) return error.InvalidRdsResource;
            if ((try pb.wrapper(try reader.bytesValue())) != 0) {
                host_rewrite = .auto;
            }
        } else if (field.number == 29 and field.wire_type == 2) {
            if (host_rewrite != null) return error.InvalidRdsResource;
            const value = try rewriteText(&reader, p.limits.max_text_bytes);
            if (value.len == 0) return error.InvalidRdsResource;
            host_rewrite = .{ .header = value };
        } else if (field.number == 44 and field.wire_type == 2) {
            if (host_rewrite != null) return error.InvalidRdsResource;
            const value = try rewriteText(&reader, p.limits.max_text_bytes);
            if (std.mem.indexOfScalar(u8, value, '%') != null) {
                return error.UnsupportedRdsFeature;
            }
            if (value.len != 0) host_rewrite = .{ .literal = value };
        } else if (field.number == 45 and field.wire_type == 2) {
            if (path_rewrite != null) return error.InvalidRdsResource;
            const value = try rewriteText(&reader, p.limits.max_text_bytes);
            if (std.mem.indexOfScalar(u8, value, '%') != null) {
                return error.UnsupportedRdsFeature;
            }
            if (value.len != 0) path_rewrite = .{ .whole = value };
        } else if (field.number == 32 and field.wire_type == 2) {
            if (path_rewrite != null) return error.InvalidRdsResource;
            path_rewrite = .{ .regex = try regexRewrite(p, try reader.bytesValue()) };
        } else if (field.number == 35 or field.number == 41 or
            field.number == 23 or field.number == 28 or
            field.number == 11)
        {
            return error.UnsupportedRdsFeature;
        } else try reader.skip(field);
    }
    const kind = specifier orelse return error.InvalidRdsResource;
    if (kind != 1 and kind != 3) return null;
    const clusters = if (kind == 3) try weighted(p, weighted_bytes.?) else blk: {
        if (name.len == 0) return error.InvalidRdsResource;
        try p.noteCluster();
        const values = try p.allocator.alloc(model.Weighted, 1);
        values[0] = .{ .name = name, .key = try std.fmt.allocPrint(p.allocator, "cluster:{s}", .{name}), .weight = 1 };
        break :blk values;
    };
    var total: u32 = 0;
    for (clusters) |cluster| total += cluster.weight;
    return .{
        .clusters = clusters,
        .total_weight = total,
        .hash_policies = try policies.toOwnedSlice(p.allocator),
        .max_stream_duration = duration,
        .retry_policy = retry,
        .retry_present = retry_present,
        .path_rewrite = path_rewrite,
        .host_rewrite = host_rewrite,
    };
}

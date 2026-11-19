//! HCM route source, timeout inheritance and client-side validation.
const std = @import("std");
const model = @import("model.zig");
const pb = @import("protobuf.zig");
fn rds(bytes: []const u8, limit: usize) pb.Error![]const u8 {
    var reader = pb.Reader{ .bytes = bytes };
    var source: ?[]const u8 = null;
    var name: []const u8 = "";
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) source = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) name = try pb.text(&reader, limit) else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidLdsResource;
    try pb.source(source orelse return error.InvalidLdsResource);
    return name;
}
fn protocol(bytes: []const u8) pb.Error!?std.Io.Duration {
    var reader = pb.Reader{ .bytes = bytes };
    var maximum: ?std.Io.Duration = null;
    while (try reader.next()) |field| {
        if (field.number == 4 and field.wire_type == 2) maximum = @import("../rds/protobuf.zig").duration(try reader.bytesValue()) catch |err| return if (err == error.InvalidRdsResource) error.InvalidLdsResource else @errorCast(err) else try reader.skip(field);
    }
    return maximum;
}
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8, limits: model.Limits) pb.Error!model.Hcm {
    var reader = pb.Reader{ .bytes = bytes };
    var selected: ?@FieldType(model.Hcm, "route_source") = null;
    var maximum: ?std.Io.Duration = null;
    var filters: std.ArrayList(model.Filter) = .empty;
    defer filters.deinit(gpa);
    while (try reader.next()) |field| {
        if (field.number == 3 and field.wire_type == 2) selected = .{ .rds = try rds(try reader.bytesValue(), limits.max_text_bytes) } else if (field.number == 4 and field.wire_type == 2) selected = .{ .inline_rds = try reader.bytesValue() } else if (field.number == 31 and field.wire_type == 2) return error.UnsupportedLdsFeature else if (field.number == 35 and field.wire_type == 2) maximum = try protocol(try reader.bytesValue()) else if (field.number == 5 and field.wire_type == 2) {
            if (filters.items.len >= limits.max_http_filters) return error.LdsLimitExceeded;
            try filters.append(gpa, try @import("filter.zig").decode(try reader.bytesValue(), limits.max_text_bytes));
        } else if (field.number == 19 and field.wire_type == 0) {
            if (try reader.varint() != 0) return error.InvalidLdsResource;
        } else if (field.number == 46 and field.wire_type == 2) return error.InvalidLdsResource else try reader.skip(field);
    }
    const validated = try @import("filter.zig").validate(filters.items, gpa, limits);
    return .{
        .route_source = selected orelse return error.InvalidLdsResource,
        .max_stream_duration = maximum,
        .filters = try filters.toOwnedSlice(gpa),
        .rbac_config = validated.rbac,
        .rbac_name = validated.rbac_name,
        .fault_config = validated.fault,
        .fault_name = validated.fault_name,
        .header_mutation_config = validated.header_mutation,
        .header_mutation_name = validated.header_mutation_name,
    };
}

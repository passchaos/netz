//! Required router terminal, optional unsupported filters, and RBAC.
const std = @import("std");
const model = @import("model.zig");
const pb = @import("protobuf.zig");
const rbac = @import("rbac.zig");
fn router(bytes: []const u8) pb.Error!void {
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            _ = try @import("../rds/protobuf.zig").wrapper(try reader.bytesValue());
        } else if (field.number == 5 and field.wire_type == 2) {
            _ = try reader.string();
        } else try reader.skip(field);
    }
}
pub fn decode(bytes: []const u8, limit: usize) pb.Error!model.Filter {
    var reader = pb.Reader{ .bytes = bytes };
    var name: []const u8 = "";
    var config: ?[]const u8 = null;
    var optional = false;
    var disabled = false;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limit) else if (field.number == 4 and field.wire_type == 2) config = try reader.bytesValue() else if (field.number == 5 and field.wire_type == 2) return error.UnsupportedLdsFeature else if (field.number == 6 and field.wire_type == 0) optional = try reader.varint() != 0 else if (field.number == 7 and field.wire_type == 0) disabled = try reader.varint() != 0 else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidLdsResource;
    const typed = try pb.any(config orelse return error.InvalidLdsResource, limit);
    if (std.mem.eql(u8, typed.type_name, model.router_type)) {
        if (disabled) return error.InvalidLdsResource;
        try router(typed.value);
    } else if (std.mem.eql(u8, typed.type_name, model.rbac_type)) {
        if (disabled) return .{ .name = name, .type_name = typed.type_name, .optional = optional };
    } else if (!optional) return error.UnsupportedLdsFeature;
    return .{
        .name = name,
        .type_name = typed.type_name,
        .optional = optional,
        .config = typed.value,
    };
}
/// Validate ordering and compile the RBAC policy into the listener arena.
/// Returns the raw RBAC config the listener must recompile per projection.
pub fn validate(
    values: []const model.Filter,
    arena: std.mem.Allocator,
    limits: model.Limits,
) (pb.Error || rbac.Error)!?[]const u8 {
    var routers: usize = 0;
    var rbac_config: ?[]const u8 = null;
    for (values, 0..) |value, index| {
        for (values[0..index]) |previous| if (std.mem.eql(u8, previous.name, value.name)) return error.InvalidLdsResource;
        if (std.mem.eql(u8, value.type_name, model.router_type)) {
            routers += 1;
        } else if (std.mem.eql(u8, value.type_name, model.rbac_type)) {
            if (rbac_config != null) return error.InvalidLdsResource;
            _ = try rbac.decode(arena, value.config, .{
                .max_text_bytes = limits.max_text_bytes,
            });
            rbac_config = value.config;
        }
    }
    // Every supported filter is terminal (router) or an ordered RBAC filter.
    if (routers != 1) return error.InvalidLdsResource;
    return rbac_config;
}

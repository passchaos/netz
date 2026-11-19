//! Required router terminal, optional unsupported filters, RBAC and fault.
const std = @import("std");
const model = @import("model.zig");
const pb = @import("protobuf.zig");
const rbac = @import("rbac.zig");
const fault = @import("../../fault.zig");
const call = @import("../../call.zig");

pub const HeaderMutationPolicy = struct {
    request_add: []const call.HeaderMutation = &.{},
    request_remove: []const []const u8 = &.{},
    response_add: []const call.HeaderMutation = &.{},
    response_remove: []const []const u8 = &.{},
};

fn headerNameValid(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if ((byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '-' or byte == '.')
        {
            continue;
        }
        return false;
    }
    return true;
}

fn headerValueValid(value: []const u8) bool {
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn headerMutationOption(
    bytes: []const u8,
    limit: usize,
) pb.Error!?call.HeaderMutation {
    var reader = pb.Reader{ .bytes = bytes };
    var key: []const u8 = "";
    var value: ?[]const u8 = null;
    var raw_value: ?[]const u8 = null;
    var append: ?bool = null;
    var append_action: ?u64 = null;
    var keep_empty = false;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            var nested = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try nested.next()) |entry| {
                if (entry.number == 1 and entry.wire_type == 2) {
                    key = try pb.text(&nested, limit);
                } else if (entry.number == 2 and entry.wire_type == 2) {
                    value = try pb.text(&nested, limit);
                } else if (entry.number == 3 and entry.wire_type == 2) {
                    raw_value = try nested.bytesValue();
                } else try nested.skip(entry);
            }
        } else if (field.number == 2 and field.wire_type == 2) {
            var wrapped = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try wrapped.next()) |entry| {
                if (entry.number == 1 and entry.wire_type == 0) {
                    append = (try wrapped.varint()) != 0;
                } else try wrapped.skip(entry);
            }
        } else if (field.number == 3 and field.wire_type == 0) {
            append_action = try reader.varint();
        } else if (field.number == 4 and field.wire_type == 0) {
            keep_empty = (try reader.varint()) != 0;
        } else try reader.skip(field);
    }
    if (!headerNameValid(key)) return error.InvalidLdsResource;
    if (value != null and raw_value != null) return error.InvalidLdsResource;
    const header_value = raw_value orelse value orelse "";
    if (!headerValueValid(header_value)) return error.InvalidLdsResource;
    if (header_value.len == 0 and !keep_empty) return null;
    if (std.mem.indexOfScalar(u8, header_value, '%') != null) {
        return error.UnsupportedLdsFeature;
    }
    const action: call.HeaderMutationAction = if (append_action) |raw| switch (raw) {
        0 => .append,
        1 => .add_if_absent,
        2 => .overwrite,
        3 => .overwrite_if_exists,
        else => return error.InvalidLdsResource,
    } else if (append) |enabled|
        if (enabled) .append else .overwrite
    else
        .append;
    return .{ .name = key, .value = header_value, .action = action };
}

/// Decode the HTTP header-mutation filter. `HeaderMutation` carries one
/// `Mutations` message with request/response add and remove lists.
pub fn decodeHeaderMutation(
    arena: std.mem.Allocator,
    bytes: []const u8,
    limits: model.Limits,
) pb.Error!HeaderMutationPolicy {
    var request_add: std.ArrayList(call.HeaderMutation) = .empty;
    defer request_add.deinit(arena);
    var request_remove: std.ArrayList([]const u8) = .empty;
    defer request_remove.deinit(arena);
    var response_add: std.ArrayList(call.HeaderMutation) = .empty;
    defer response_add.deinit(arena);
    var response_remove: std.ArrayList([]const u8) = .empty;
    defer response_remove.deinit(arena);
    var total: usize = 0;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        var mutations = pb.Reader{ .bytes = try reader.bytesValue() };
        while (try mutations.next()) |entry| {
            if (entry.number == 1 and entry.wire_type == 2) {
                if (total >= limits.max_header_mutations) {
                    return error.LdsLimitExceeded;
                }
                if (try headerMutationOption(
                    try mutations.bytesValue(),
                    limits.max_text_bytes,
                )) |mutation| {
                    try request_add.append(arena, mutation);
                    total += 1;
                }
            } else if (entry.number == 2 and entry.wire_type == 2) {
                if (total >= limits.max_header_mutations) {
                    return error.LdsLimitExceeded;
                }
                const name = try pb.text(&mutations, limits.max_text_bytes);
                if (!headerNameValid(name)) return error.InvalidLdsResource;
                try request_remove.append(arena, name);
                total += 1;
            } else if (entry.number == 3 and entry.wire_type == 2) {
                if (total >= limits.max_header_mutations) {
                    return error.LdsLimitExceeded;
                }
                if (try headerMutationOption(
                    try mutations.bytesValue(),
                    limits.max_text_bytes,
                )) |mutation| {
                    try response_add.append(arena, mutation);
                    total += 1;
                }
            } else if (entry.number == 4 and entry.wire_type == 2) {
                if (total >= limits.max_header_mutations) {
                    return error.LdsLimitExceeded;
                }
                const name = try pb.text(&mutations, limits.max_text_bytes);
                if (!headerNameValid(name)) return error.InvalidLdsResource;
                try response_remove.append(arena, name);
                total += 1;
            } else try mutations.skip(entry);
        }
    }
    return .{
        .request_add = try request_add.toOwnedSlice(arena),
        .request_remove = try request_remove.toOwnedSlice(arena),
        .response_add = try response_add.toOwnedSlice(arena),
        .response_remove = try response_remove.toOwnedSlice(arena),
    };
}

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
    } else if (std.mem.eql(u8, typed.type_name, model.rbac_type) or
        std.mem.eql(u8, typed.type_name, model.fault_type) or
        std.mem.eql(u8, typed.type_name, model.header_mutation_type))
    {
        if (disabled) return .{ .name = name, .type_name = typed.type_name, .optional = optional, .disabled = true };
    } else if (!optional) return error.UnsupportedLdsFeature;
    return .{
        .name = name,
        .type_name = typed.type_name,
        .optional = optional,
        .disabled = disabled,
        .config = typed.value,
    };
}
pub const Validated = struct {
    rbac: ?[]const u8 = null,
    rbac_name: ?[]const u8 = null,
    fault: ?[]const u8 = null,
    fault_name: ?[]const u8 = null,
    header_mutation: ?[]const u8 = null,
    header_mutation_name: ?[]const u8 = null,
};

/// Validate ordering and compile the supported policies into the listener
/// arena. Returns the raw configs each projection must recompile.
pub fn validate(
    values: []const model.Filter,
    arena: std.mem.Allocator,
    limits: model.Limits,
) (pb.Error || rbac.Error || fault.Error)!Validated {
    var routers: usize = 0;
    var rbac_config: ?[]const u8 = null;
    var rbac_name: ?[]const u8 = null;
    var fault_config: ?[]const u8 = null;
    var fault_name: ?[]const u8 = null;
    var header_mutation_config: ?[]const u8 = null;
    var header_mutation_name: ?[]const u8 = null;
    var rbac_index: ?usize = null;
    var fault_index: ?usize = null;
    for (values, 0..) |value, index| {
        for (values[0..index]) |previous| if (std.mem.eql(u8, previous.name, value.name)) return error.InvalidLdsResource;
        if (value.disabled) continue;
        if (std.mem.eql(u8, value.type_name, model.router_type)) {
            routers += 1;
        } else if (std.mem.eql(u8, value.type_name, model.rbac_type)) {
            if (rbac_config != null) return error.InvalidLdsResource;
            _ = try rbac.decode(arena, value.config, .{
                .max_text_bytes = limits.max_text_bytes,
            });
            rbac_config = value.config;
            rbac_name = value.name;
            rbac_index = index;
        } else if (std.mem.eql(u8, value.type_name, model.fault_type)) {
            if (fault_config != null) return error.InvalidLdsResource;
            _ = try fault.decode(arena, value.config, .{ .max_text_bytes = limits.max_text_bytes });
            fault_config = value.config;
            fault_name = value.name;
            fault_index = index;
        } else if (std.mem.eql(u8, value.type_name, model.header_mutation_type)) {
            if (header_mutation_config != null) return error.InvalidLdsResource;
            _ = try decodeHeaderMutation(arena, value.config, limits);
            header_mutation_config = value.config;
            header_mutation_name = value.name;
        }
    }
    // Every supported filter is terminal (router), RBAC or fault injection.
    if (routers != 1) return error.InvalidLdsResource;
    // netz evaluates listener RBAC before per-attempt fault injection. A
    // fault filter placed before RBAC would observe a different order, so
    // reject it instead of silently changing the configured chain.
    if (rbac_index != null and fault_index != null and fault_index.? < rbac_index.?) return error.UnsupportedLdsFeature;
    return .{
        .rbac = rbac_config,
        .rbac_name = rbac_name,
        .fault = fault_config,
        .fault_name = fault_name,
        .header_mutation = header_mutation_config,
        .header_mutation_name = header_mutation_name,
    };
}

//! xds_wrr_locality child-policy validation.
const std = @import("std");

pub fn childPolicies(value: std.json.Value) error{InvalidServiceConfig}![]const std.json.Value {
    const object = switch (value) {
        .object => |v| v,
        else => return error.InvalidServiceConfig,
    };
    const child = object.get("childPolicy") orelse return error.InvalidServiceConfig;
    return switch (child) {
        .array => |v| if (v.items.len != 0) v.items else error.InvalidServiceConfig,
        else => error.InvalidServiceConfig,
    };
}

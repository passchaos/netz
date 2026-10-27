//! gRPC Core global healthCheckConfig. Presence of serviceName, including an
//! empty string, is what enables health checking; object presence alone does
//! not enable it. Optional null fields have the same meaning as absence.
const std = @import("std");

pub const JsonConfig = struct {
    serviceName: ?std.json.Value = null,
};

pub fn serviceName(config: ?JsonConfig) error{InvalidServiceConfig}!?[]const u8 {
    const value = (config orelse return null).serviceName orelse return null;
    const name = switch (value) {
        .string => |name| name,
        .null => return null,
        else => return error.InvalidServiceConfig,
    };
    if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidServiceConfig;
    return name;
}

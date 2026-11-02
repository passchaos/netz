//! Small wire fixtures; independent LDS/RDS peers use official Envoy schemas.
const std = @import("std");
const model = @import("model.zig");
pub const Builder = @import("../cds/testing.zig").Builder;
pub const Filter = struct { name: []const u8 = "router", type_name: []const u8 = model.router_type, value: []const u8 = "", optional: bool = false, disabled: bool = false };
pub const Options = struct {
    name: []const u8 = "frontend",
    route_name: []const u8 = "routes-a",
    inline_rds: ?[]const u8 = null,
    source: []const u8 = "\x1a\x00",
    maximum_ms: ?u32 = null,
    filters: []const Filter = &.{.{}},
    hcm_extra: []const u8 = "",
};
pub fn encode(gpa: std.mem.Allocator, options: Options) ![]u8 {
    var hcm = Builder{ .allocator = gpa };
    defer hcm.deinit();
    if (options.inline_rds) |value| {
        try hcm.bytes(4, value);
    } else {
        var rds = Builder{ .allocator = gpa };
        defer rds.deinit();
        try rds.bytes(1, options.source);
        try rds.bytes(2, options.route_name);
        try hcm.bytes(3, rds.data.items);
    }
    if (options.maximum_ms) |milliseconds| {
        var duration = Builder{ .allocator = gpa };
        defer duration.deinit();
        try duration.number(1, milliseconds / 1000);
        try duration.number(2, @as(u64, milliseconds % 1000) * std.time.ns_per_ms);
        var protocol = Builder{ .allocator = gpa };
        defer protocol.deinit();
        try protocol.bytes(4, duration.data.items);
        try hcm.bytes(35, protocol.data.items);
    }
    for (options.filters) |filter| {
        var any = Builder{ .allocator = gpa };
        defer any.deinit();
        const url = try std.fmt.allocPrint(gpa, "type.googleapis.com/{s}", .{filter.type_name});
        defer gpa.free(url);
        try any.bytes(1, url);
        try any.bytes(2, filter.value);
        var value = Builder{ .allocator = gpa };
        defer value.deinit();
        try value.bytes(1, filter.name);
        try value.bytes(4, any.data.items);
        try value.number(6, @intFromBool(filter.optional));
        try value.number(7, @intFromBool(filter.disabled));
        try hcm.bytes(5, value.data.items);
    }
    try hcm.data.appendSlice(gpa, options.hcm_extra);
    var any = Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/" ++ model.hcm_type);
    try any.bytes(2, hcm.data.items);
    var api = Builder{ .allocator = gpa };
    defer api.deinit();
    try api.bytes(1, any.data.items);
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, options.name);
    try out.bytes(19, api.data.items);
    return out.data.toOwnedSlice(gpa);
}

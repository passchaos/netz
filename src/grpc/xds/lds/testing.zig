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
pub fn headerMutation(allocator: std.mem.Allocator) ![]u8 {
    var request_header = Builder{ .allocator = allocator };
    defer request_header.deinit();
    try request_header.bytes(1, "x-req");
    try request_header.bytes(2, "one");
    var request_option = Builder{ .allocator = allocator };
    defer request_option.deinit();
    try request_option.bytes(1, request_header.data.items);
    var append = Builder{ .allocator = allocator };
    defer append.deinit();
    try append.number(1, 1);
    try request_option.bytes(2, append.data.items);
    var request_append = Builder{ .allocator = allocator };
    defer request_append.deinit();
    try request_append.bytes(2, request_option.data.items);
    var request_remove = Builder{ .allocator = allocator };
    defer request_remove.deinit();
    try request_remove.bytes(1, "x-remove");

    var response_header = Builder{ .allocator = allocator };
    defer response_header.deinit();
    try response_header.bytes(1, "x-resp");
    try response_header.bytes(2, "two");
    var response_option = Builder{ .allocator = allocator };
    defer response_option.deinit();
    try response_option.bytes(1, response_header.data.items);
    var response_append = Builder{ .allocator = allocator };
    defer response_append.deinit();
    try response_append.bytes(2, response_option.data.items);
    var response_remove = Builder{ .allocator = allocator };
    defer response_remove.deinit();
    try response_remove.bytes(1, "x-resp-remove");

    var mutations = Builder{ .allocator = allocator };
    defer mutations.deinit();
    try mutations.bytes(1, request_append.data.items);
    try mutations.bytes(1, request_remove.data.items);
    try mutations.bytes(2, response_append.data.items);
    try mutations.bytes(2, response_remove.data.items);

    var config = Builder{ .allocator = allocator };
    defer config.deinit();
    try config.bytes(1, mutations.data.items);
    return config.data.toOwnedSlice(allocator);
}

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

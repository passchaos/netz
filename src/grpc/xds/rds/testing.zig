//! Wire fixtures; official schema/runtime interop supplies the separate oracle.
const std = @import("std");
pub const Builder = @import("../cds/testing.zig").Builder;
pub const Route = struct { prefix: []const u8 = "", exact: ?[]const u8 = null, regex: ?[]const u8 = null, cluster: []const u8 = "a", match_extra: []const u8 = "", action_extra: []const u8 = "", retry: ?[]const u8 = null };
pub fn encode(gpa: std.mem.Allocator, name: []const u8, domains: []const []const u8, routes: []const Route, retry: ?[]const u8) ![]u8 {
    var host = Builder{ .allocator = gpa };
    defer host.deinit();
    for (domains) |domain| try host.bytes(2, domain);
    if (retry) |raw| try host.bytes(16, raw);
    for (routes) |route| {
        var match = Builder{ .allocator = gpa };
        defer match.deinit();
        if (route.regex) |pattern| {
            var regex = Builder{ .allocator = gpa };
            defer regex.deinit();
            try regex.bytes(2, pattern);
            try match.bytes(10, regex.data.items);
        } else if (route.exact) |path| try match.bytes(2, path) else try match.bytes(1, route.prefix);
        try match.data.appendSlice(gpa, route.match_extra);
        var action = Builder{ .allocator = gpa };
        defer action.deinit();
        try action.bytes(1, route.cluster);
        if (route.retry) |raw| try action.bytes(9, raw);
        try action.data.appendSlice(gpa, route.action_extra);
        var value = Builder{ .allocator = gpa };
        defer value.deinit();
        try value.bytes(1, match.data.items);
        try value.bytes(2, action.data.items);
        try host.bytes(3, value.data.items);
    }
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, name);
    try out.bytes(2, host.data.items);
    return out.data.toOwnedSlice(gpa);
}

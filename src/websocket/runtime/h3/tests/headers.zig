const http3 = @import("../../../../http3/mod.zig");
const std = @import("std");

pub const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub fn countHeaders(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) usize {
    var count: usize = 0;
    for (headers) |header| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, name));
    }
    return count;
}

pub fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

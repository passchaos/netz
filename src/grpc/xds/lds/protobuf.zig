//! Bounded client LDS field helpers and protobuf Any validation.
const model = @import("model.zig");
pub const Reader = @import("../../protobuf.zig").Reader;
pub const Error = model.Error;
pub fn text(reader: *Reader, limit: usize) Error![]const u8 {
    const value = try reader.string();
    if (value.len > limit) return error.LdsLimitExceeded;
    return value;
}
pub fn validate(bytes: []const u8) Error!void {
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| try reader.skip(field);
}
pub const Any = struct { type_name: []const u8, value: []const u8 };
pub fn any(bytes: []const u8, limit: usize) Error!Any {
    const std = @import("std");
    var reader = Reader{ .bytes = bytes };
    var url: []const u8 = "";
    var value: []const u8 = "";
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) url = try text(&reader, limit) else if (field.number == 2 and field.wire_type == 2) value = try reader.bytesValue() else try reader.skip(field);
    }
    if (url.len == 0) return error.InvalidLdsResource;
    const offset = std.mem.lastIndexOfScalar(u8, url, '/') orelse return error.InvalidLdsResource;
    if (offset + 1 == url.len) return error.InvalidLdsResource;
    return .{ .type_name = url[offset + 1 ..], .value = value };
}
pub fn source(bytes: []const u8) Error!void {
    _ = @import("../config_source.zig").decode(bytes) catch |err| return switch (err) {
        error.InvalidConfigSource => error.InvalidLdsResource,
        error.UnsupportedConfigSource => error.UnsupportedLdsFeature,
        else => @errorCast(err),
    };
}

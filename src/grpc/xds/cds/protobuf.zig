//! Shared bounded field helpers for CDS and typed LB policy payloads.
const std = @import("std");
pub const Reader = @import("../../protobuf.zig").Reader;
pub const Error = @import("../../protobuf.zig").Error || std.mem.Allocator.Error || error{ InvalidCdsResource, CdsLimitExceeded, UnsupportedCdsFeature, UnsupportedCdsPolicy };
pub fn text(reader: *Reader, limit: usize) Error![]const u8 {
    const value = try reader.string();
    if (value.len > limit) return error.CdsLimitExceeded;
    return value;
}
pub fn u32Value(reader: *Reader) Error!u32 {
    const value = try reader.varint();
    if (value > std.math.maxInt(u32)) return error.InvalidCdsResource;
    return @intCast(value);
}
pub fn wrapper(bytes: []const u8) Error!u64 {
    var result: u64 = 0;
    var reader: Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) result = try reader.varint() else try reader.skip(field);
    }
    return result;
}
pub fn validate(bytes: []const u8) Error!void {
    var reader: Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| try reader.skip(field);
}

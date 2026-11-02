//! Bounded primitive fields and protobuf duration conversion for RDS.
const std = @import("std");
const model = @import("model.zig");
pub const Reader = @import("../../protobuf.zig").Reader;
pub const Error = model.Error;
pub fn text(reader: *Reader, maximum: usize) Error![]const u8 {
    const value = try reader.string();
    if (value.len > maximum) return error.RdsLimitExceeded;
    return value;
}
pub fn u32Field(reader: *Reader) Error!u32 {
    const value = try reader.varint();
    if (value > std.math.maxInt(u32)) return error.InvalidRdsResource;
    return @intCast(value);
}
pub fn wrapper(bytes: []const u8) Error!u64 {
    var reader = Reader{ .bytes = bytes };
    var value: u64 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) value = try reader.varint() else try reader.skip(field);
    }
    return value;
}
pub fn duration(bytes: []const u8) Error!std.Io.Duration {
    var reader = Reader{ .bytes = bytes };
    var seconds: i64 = 0;
    var nanos: i32 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) seconds = @bitCast(try reader.varint()) else if (field.number == 2 and field.wire_type == 0) nanos = @bitCast(@as(u32, @truncate(try reader.varint()))) else try reader.skip(field);
    }
    if (seconds < 0 or seconds > 315576000000 or nanos < 0 or nanos > 999999999) return error.InvalidRdsResource;
    return .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s + nanos);
}
pub fn validate(bytes: []const u8) Error!void {
    var reader = Reader{ .bytes = bytes };
    while (try reader.next()) |field| try reader.skip(field);
}

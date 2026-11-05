//! Typed route path/header/fraction parsing; non-gRPC-only routes are skipped.
const std = @import("std");
const model = @import("model.zig");
const pb = @import("protobuf.zig");
const routing = @import("../routing/mod.zig");
pub const Result = struct { path: routing.string.Match, headers: []const routing.header.Match, fraction: ?u32 };
fn literal(kind: u32, text: []const u8, ignore: bool) routing.string.Match {
    const value = routing.string.Match.Literal{ .text = text, .ignore_case = ignore };
    return switch (kind) {
        1 => .{ .exact = value },
        2 => .{ .prefix = value },
        3 => .{ .suffix = value },
        14 => .{ .path_separated_prefix = value },
        else => .{ .contains = value },
    };
}
fn string(p: anytype, bytes: []const u8) pb.Error!routing.string.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var specifier: ?u32 = null;
    var text: []const u8 = "";
    var ignore = false;
    var regex_bytes: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if ((field.number == 1 or field.number == 2 or field.number == 3 or
            field.number == 7 or field.number == 14) and
            field.wire_type == 2)
        {
            specifier = field.number;
            text = try pb.text(&reader, p.limits.max_text_bytes);
            regex_bytes = null;
        } else if (field.number == 5 and field.wire_type == 2) {
            specifier = 5;
            regex_bytes = try reader.bytesValue();
        } else if (field.number == 6 and field.wire_type == 0) ignore = try reader.varint() != 0 else if (field.number == 8 and field.wire_type == 2) return error.UnsupportedRdsFeature else try reader.skip(field);
    }
    const kind = specifier orelse return error.InvalidRdsResource;
    if (kind == 5) return p.regex(regex_bytes.?);
    if (kind != 1 and text.len == 0) return error.InvalidRdsResource;
    if (kind == 14) {
        if (text.len < 2 or text[text.len - 1] == '/' or
            std.mem.indexOfAny(u8, text, "?#") != null)
        {
            return error.InvalidRdsResource;
        }
    }
    return literal(kind, text, ignore);
}
fn range(bytes: []const u8) pb.Error!struct { start: i64, end: i64 } {
    var reader = pb.Reader{ .bytes = bytes };
    var start: i64 = 0;
    var end: i64 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) start = @bitCast(try reader.varint()) else if (field.number == 2 and field.wire_type == 0) end = @bitCast(try reader.varint()) else try reader.skip(field);
    }
    if (end < start) return error.InvalidRdsResource;
    return .{ .start = start, .end = end };
}
fn header(p: anytype, bytes: []const u8) pb.Error!routing.header.Match {
    var reader = pb.Reader{ .bytes = bytes };
    var name: []const u8 = "";
    var invert = false;
    var condition: ?@FieldType(routing.header.Match, "condition") = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, p.limits.max_text_bytes) else if (field.number == 8 and field.wire_type == 0) invert = try reader.varint() != 0 else if (field.number == 7 and field.wire_type == 0) condition = .{ .present = try reader.varint() != 0 } else if (field.number == 6 and field.wire_type == 2) {
            const bounds = try range(try reader.bytesValue());
            condition = .{ .range = .{ .start = bounds.start, .end = bounds.end } };
        } else if (field.number == 11 and field.wire_type == 2) condition = .{ .string = try p.regex(try reader.bytesValue()) } else if (field.number == 13 and field.wire_type == 2) condition = .{ .string = try string(p, try reader.bytesValue()) } else if ((field.number == 4 or field.number == 9 or field.number == 10 or field.number == 12) and field.wire_type == 2) {
            const text = try pb.text(&reader, p.limits.max_text_bytes);
            if (field.number != 4 and text.len == 0) return error.InvalidRdsResource;
            condition = .{ .string = literal(switch (field.number) {
                4 => 1,
                9 => 2,
                10 => 3,
                else => 7,
            }, text, false) };
        } else if (field.number == 14 and field.wire_type == 0) {
            if (try reader.varint() != 0) return error.UnsupportedRdsFeature;
        } else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidRdsResource;
    return .{ .name = name, .condition = condition orelse return error.InvalidRdsResource, .invert = invert };
}
fn fraction(bytes: []const u8) pb.Error!?u32 {
    var reader = pb.Reader{ .bytes = bytes };
    var raw: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) raw = try reader.bytesValue() else try reader.skip(field);
    }
    if (raw == null) return null;
    var value_reader = pb.Reader{ .bytes = raw.? };
    var numerator: u32 = 0;
    var denominator: u32 = 0;
    while (try value_reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) numerator = try pb.u32Field(&value_reader) else if (field.number == 2 and field.wire_type == 0) denominator = try pb.u32Field(&value_reader) else try value_reader.skip(field);
    }
    const scale: u32 = switch (denominator) {
        0 => 10000,
        1 => 100,
        2 => 1,
        else => return error.InvalidRdsResource,
    };
    if (numerator > 1000000 / scale) return error.InvalidRdsResource;
    return numerator * scale;
}
pub fn decode(p: anytype, bytes: []const u8) pb.Error!?Result {
    var reader = pb.Reader{ .bytes = bytes };
    var kind: ?u32 = null;
    var path: []const u8 = "";
    var regex_bytes: ?[]const u8 = null;
    var sensitive = true;
    var skipped = false;
    var portion: ?u32 = null;
    var headers: std.ArrayList(routing.header.Match) = .empty;
    defer headers.deinit(p.allocator);
    while (try reader.next()) |field| {
        if ((field.number == 1 or field.number == 2 or field.number == 14) and field.wire_type == 2) {
            kind = field.number;
            path = try pb.text(&reader, p.limits.max_text_bytes);
            regex_bytes = null;
        } else if (field.number == 10 and field.wire_type == 2) {
            kind = 10;
            regex_bytes = try reader.bytesValue();
        } else if (field.number == 4 and field.wire_type == 2) sensitive = try pb.wrapper(try reader.bytesValue()) != 0 else if (field.number == 9 and field.wire_type == 2) portion = try fraction(try reader.bytesValue()) else if (field.number == 6 and field.wire_type == 2) {
            if (headers.items.len >= p.limits.max_headers_per_route) return error.RdsLimitExceeded;
            try headers.append(p.allocator, try header(p, try reader.bytesValue()));
        } else if ((field.number == 7 or field.number == 12) and field.wire_type == 2) {
            _ = try reader.bytesValue();
            skipped = true; // query/CONNECT routes do not match gRPC requests
        } else if ((field.number == 11 or field.number == 13 or field.number == 15) and field.wire_type == 2) return error.UnsupportedRdsFeature else try reader.skip(field);
    }
    if (skipped) return null;
    const specifier = kind orelse return error.InvalidRdsResource;
    if (specifier == 1 and path.len != 0) {
        if (path[0] != '/' or std.mem.count(u8, path, "/") > 2 or std.mem.startsWith(u8, path, "//")) return null;
    } else if (specifier == 2) {
        if (path.len == 0 or path[0] != '/') return null;
        const slash = std.mem.indexOfScalarPos(u8, path, 1, '/') orelse return null;
        if (slash == 1 or slash + 1 == path.len or std.mem.indexOfScalar(u8, path[slash + 1 ..], '/') != null) return null;
    } else if (specifier == 14) {
        if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/' or
            std.mem.indexOfAny(u8, path, "?#") != null or
            std.mem.count(u8, path, "/") > 1)
        {
            return null;
        }
    }
    const literal_kind: u32 = switch (specifier) {
        1 => 2,
        14 => 14,
        else => 1,
    };
    return .{ .path = if (specifier == 10) try p.regex(regex_bytes.?) else literal(literal_kind, path, !sensitive), .headers = try headers.toOwnedSlice(p.allocator), .fraction = portion };
}

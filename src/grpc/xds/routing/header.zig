//! Visible initial metadata, joined ASCII values, presence/range/string tests.
const std = @import("std");
const Field = @import("../../../http2/mod.zig").Hpack.HeaderField;
const String = @import("string.zig").Match;
pub const Error = std.mem.Allocator.Error || @import("regex/budget.zig").Error || error{RouteMetadataLimitExceeded};
pub const Value = struct {
    allocator: std.mem.Allocator,
    value: ?[]const u8,
    owned: ?[]u8 = null,
    pub fn deinit(self: *Value) void {
        if (self.owned) |owned| self.allocator.free(owned);
        self.* = undefined;
    }
};
pub const Request = struct {
    path: []const u8,
    authority: []const u8,
    scheme: ?[]const u8 = null,
    metadata: []const Field = &.{},
    max_header_bytes: usize = 65536,
    budget: ?@import("regex.zig").Budget = null,
    pub fn header(self: Request, gpa: std.mem.Allocator, name: []const u8) Error!Value {
        if (self.budget) |budget| try budget.check();
        var result = Value{ .allocator = gpa, .value = null };
        if (std.mem.endsWith(u8, name, "-bin")) return result;
        if (std.mem.eql(u8, name, "content-type")) result.value = "application/grpc" else if (std.mem.eql(u8, name, ":path")) result.value = self.path else if (std.mem.eql(u8, name, ":authority")) result.value = self.authority else if (std.mem.eql(u8, name, ":method")) result.value = "POST" else if (std.mem.eql(u8, name, ":scheme")) result.value = self.scheme else {
            var count: usize = 0;
            var length: usize = 0;
            for (self.metadata) |field| if (std.mem.eql(u8, field.name, name)) {
                length = std.math.add(usize, length, field.value.len) catch return error.RouteMetadataLimitExceeded;
                if (count != 0) length = std.math.add(usize, length, 1) catch return error.RouteMetadataLimitExceeded;
                if (length > self.max_header_bytes) return error.RouteMetadataLimitExceeded;
                count += 1;
                result.value = field.value;
            };
            if (count > 1) {
                const owned = try gpa.alloc(u8, length);
                var offset: usize = 0;
                var written: usize = 0;
                for (self.metadata) |field| if (std.mem.eql(u8, field.name, name)) {
                    if (written != 0) {
                        owned[offset] = ',';
                        offset += 1;
                    }
                    @memcpy(owned[offset..][0..field.value.len], field.value);
                    offset += field.value.len;
                    written += 1;
                };
                result.owned = owned;
                result.value = owned;
            }
        }
        if (result.value) |value| if (value.len > self.max_header_bytes) return error.RouteMetadataLimitExceeded;
        return result;
    }
};
pub const Range = struct { start: i64, end: i64 };

pub const DecodeLimits = struct {
    max_text_bytes: usize = 4096,
    regex: @import("regex.zig").Limits = .{},
};

pub const DecodeError = std.mem.Allocator.Error || @import("../../protobuf.zig").Error || @import("regex.zig").Error || error{
    InvalidHeaderMatcher,
    HeaderMatcherLimitExceeded,
};

fn literal(kind: u32, text: []const u8, ignore_case: bool) String {
    const value = String.Literal{ .text = text, .ignore_case = ignore_case };
    return switch (kind) {
        1 => .{ .exact = value },
        2 => .{ .prefix = value },
        3 => .{ .suffix = value },
        14 => .{ .path_separated_prefix = value },
        else => .{ .contains = value },
    };
}

fn readText(reader: *@import("../../protobuf.zig").Reader, limit: usize) DecodeError![]const u8 {
    const value = try reader.string();
    if (value.len > limit) return error.HeaderMatcherLimitExceeded;
    return value;
}

fn regexMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: DecodeLimits) DecodeError!String {
    var reader = @import("../../protobuf.zig").Reader{ .bytes = bytes };
    var pattern: ?[]const u8 = null;
    while (try reader.next()) |field| {
        // Envoy RegexMatcher: google_re2 engine = 1, regex pattern = 2.
        if (field.number == 2 and field.wire_type == 2) {
            pattern = try readText(&reader, limits.max_text_bytes);
        } else try reader.skip(field);
    }
    return String.compileRegex(arena, pattern orelse return error.InvalidHeaderMatcher, limits.regex);
}

pub fn decodeStringMatcher(arena: std.mem.Allocator, bytes: []const u8, limits: DecodeLimits) DecodeError!String {
    var reader = @import("../../protobuf.zig").Reader{ .bytes = bytes };
    var kind: ?u32 = null;
    var value_text: []const u8 = "";
    var ignore_case = false;
    var regex_bytes: ?[]const u8 = null;
    while (try reader.next()) |field| {
        // Envoy StringMatcher: exact = 1, prefix = 2, suffix = 3,
        // safe_regex = 5, contains = 7; ignore_case = 6.
        if ((field.number == 1 or field.number == 2 or field.number == 3 or
            field.number == 7) and field.wire_type == 2)
        {
            kind = field.number;
            value_text = try readText(&reader, limits.max_text_bytes);
            regex_bytes = null;
        } else if (field.number == 5 and field.wire_type == 2) {
            kind = 5;
            regex_bytes = try reader.bytesValue();
        } else if (field.number == 6 and field.wire_type == 0) {
            ignore_case = (try reader.varint()) != 0;
        } else try reader.skip(field);
    }
    const selected = kind orelse return error.InvalidHeaderMatcher;
    if (selected == 5) return regexMatcher(arena, regex_bytes.?, limits);
    if (value_text.len == 0 and selected != 1) return error.InvalidHeaderMatcher;
    return literal(selected, value_text, ignore_case);
}

fn rangeMatcher(bytes: []const u8) DecodeError!Range {
    var reader = @import("../../protobuf.zig").Reader{ .bytes = bytes };
    var start: i64 = 0;
    var end: i64 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            start = @bitCast(try reader.varint());
        } else if (field.number == 2 and field.wire_type == 0) {
            end = @bitCast(try reader.varint());
        } else try reader.skip(field);
    }
    if (end < start) return error.InvalidHeaderMatcher;
    return .{ .start = start, .end = end };
}

/// Decode an `envoy.config.route.v3.HeaderMatcher`.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8, limits: DecodeLimits) DecodeError!Match {
    var reader = @import("../../protobuf.zig").Reader{ .bytes = bytes };
    var name: []const u8 = "";
    var condition: ?Condition = null;
    var invert = false;
    var treat_missing_header_as_empty = false;
    while (try reader.next()) |field| {
        switch (field.number) {
            1 => if (field.wire_type == 2) {
                name = try readText(&reader, limits.max_text_bytes);
            } else try reader.skip(field),
            4 => if (field.wire_type == 2) {
                condition = .{ .string = literal(1, try readText(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            11 => if (field.wire_type == 2) {
                condition = .{ .string = try regexMatcher(arena, try reader.bytesValue(), limits) };
            } else try reader.skip(field),
            6 => if (field.wire_type == 2) {
                condition = .{ .range = try rangeMatcher(try reader.bytesValue()) };
            } else try reader.skip(field),
            7 => if (field.wire_type == 0) {
                condition = .{ .present = (try reader.varint()) != 0 };
            } else try reader.skip(field),
            8 => if (field.wire_type == 0) {
                invert = (try reader.varint()) != 0;
            } else try reader.skip(field),
            9 => if (field.wire_type == 2) {
                condition = .{ .string = literal(2, try readText(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            10 => if (field.wire_type == 2) {
                condition = .{ .string = literal(3, try readText(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            12 => if (field.wire_type == 2) {
                condition = .{ .string = literal(7, try readText(&reader, limits.max_text_bytes), false) };
            } else try reader.skip(field),
            13 => if (field.wire_type == 2) {
                condition = .{ .string = try decodeStringMatcher(arena, try reader.bytesValue(), limits) };
            } else try reader.skip(field),
            14 => if (field.wire_type == 0) {
                treat_missing_header_as_empty = (try reader.varint()) != 0;
            } else try reader.skip(field),
            else => try reader.skip(field),
        }
    }
    if (name.len == 0) return error.InvalidHeaderMatcher;
    return .{
        .name = name,
        .condition = condition orelse return error.InvalidHeaderMatcher,
        .invert = invert,
        .treat_missing_header_as_empty = treat_missing_header_as_empty,
    };
}

pub const Condition = union(enum) {
    string: String,
    present: bool,
    range: Range,
};

pub const Match = struct {
    name: []const u8,
    condition: Condition,
    invert: bool = false,
    /// A missing header becomes a present empty value before matching.
    treat_missing_header_as_empty: bool = false,
    pub fn matches(self: Match, gpa: std.mem.Allocator, request: Request) Error!bool {
        var header = try request.header(gpa, self.name);
        defer header.deinit();
        const value: ?[]const u8 = if (self.treat_missing_header_as_empty) header.value orelse "" else header.value;
        const result = switch (self.condition) {
            .present => |wanted| (value != null) == wanted,
            .string => |matcher| try matcher.matchesWithBudget(gpa, value orelse return false, request.budget),
            .range => |range| blk: {
                const number = integer(value orelse return false) orelse break :blk false;
                break :blk number >= range.start and number < range.end;
            },
        };
        return result != self.invert;
    }
    fn integer(raw: []const u8) ?i64 {
        const value = std.mem.trim(u8, raw, " \t\r\n\x0b\x0c");
        if (value.len == 0) return null;
        const digits = if (value[0] == '+' or value[0] == '-') value[1..] else value;
        if (digits.len == 0) return null;
        for (digits) |digit| if (!std.ascii.isDigit(digit)) return null;
        return std.fmt.parseInt(i64, value, 10) catch null;
    }
};

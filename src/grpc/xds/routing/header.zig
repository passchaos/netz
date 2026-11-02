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
pub const Match = struct {
    name: []const u8,
    condition: union(enum) { string: String, present: bool, range: struct { start: i64, end: i64 } },
    invert: bool = false,
    pub fn matches(self: Match, gpa: std.mem.Allocator, request: Request) Error!bool {
        var header = try request.header(gpa, self.name);
        defer header.deinit();
        const result = switch (self.condition) {
            .present => |wanted| (header.value != null) == wanted,
            .string => |matcher| try matcher.matchesWithBudget(gpa, header.value orelse return false, request.budget),
            .range => |range| blk: {
                const value = integer(header.value orelse return false) orelse break :blk false;
                break :blk value >= range.start and value < range.end;
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

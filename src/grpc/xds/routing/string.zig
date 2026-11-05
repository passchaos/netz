//! grpc-core string matching: ASCII-insensitive literals and RE2 full regex.
const std = @import("std");
const regex = @import("regex.zig");
const template = @import("template.zig");
pub const Match = union(enum) {
    exact: Literal,
    prefix: Literal,
    suffix: Literal,
    contains: Literal,
    /// Envoy `path_separated_prefix`: exact or prefix followed by `/`,
    /// evaluated against the path without query or fragment.
    path_separated_prefix: Literal,
    safe_regex: @import("regex/compile.zig").Program,
    /// Envoy URI-template path matcher. The arena owns the pointed-to match.
    path_template: *const template.Match,
    pub const Literal = struct { text: []const u8, ignore_case: bool = false };
    fn equal(a: []const u8, b: []const u8, ignore_case: bool) bool {
        return if (ignore_case) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
    }
    fn separatedPrefix(value: []const u8, literal: Literal) bool {
        const end = std.mem.indexOfAny(u8, value, "?#") orelse value.len;
        const path = value[0..end];
        if (path.len < literal.text.len) return false;
        if (!equal(path[0..literal.text.len], literal.text, literal.ignore_case)) {
            return false;
        }
        return path.len == literal.text.len or path[literal.text.len] == '/';
    }
    /// The caller's arena owns the compiled program/sets until all users leave.
    pub fn compileRegex(arena: std.mem.Allocator, pattern: []const u8, limits: regex.Limits) regex.Error!Match {
        const root = try @import("regex/parse.zig").parse(arena, pattern, limits);
        return .{ .safe_regex = try @import("regex/compile.zig").compile(arena, root, limits) };
    }
    pub fn compileTemplate(arena: std.mem.Allocator, pattern: []const u8, limits: template.Limits) template.Error!Match {
        const matcher = try arena.create(template.Match);
        matcher.* = try template.Match.compile(arena, pattern, limits);
        return .{ .path_template = matcher };
    }
    pub fn matches(self: Match, gpa: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error!bool {
        var captures: template.Captures = .{};
        return self.matchesWithCaptures(gpa, value, &captures) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return false,
        };
    }
    pub fn matchesWithCaptures(
        self: Match,
        gpa: std.mem.Allocator,
        value: []const u8,
        captures: *template.Captures,
    ) (std.mem.Allocator.Error || template.Error)!bool {
        return switch (self) {
            .exact => |literal| equal(value, literal.text, literal.ignore_case),
            .prefix => |literal| value.len >= literal.text.len and equal(value[0..literal.text.len], literal.text, literal.ignore_case),
            .suffix => |literal| value.len >= literal.text.len and equal(value[value.len - literal.text.len ..], literal.text, literal.ignore_case),
            .contains => |literal| blk: {
                if (value.len < literal.text.len) break :blk false;
                for (0..value.len - literal.text.len + 1) |start| if (equal(value[start..][0..literal.text.len], literal.text, literal.ignore_case)) break :blk true;
                break :blk false;
            },
            .path_separated_prefix => |literal| separatedPrefix(value, literal),
            .safe_regex => |program| blk: {
                var workspace = try regex.Workspace.init(gpa, program);
                defer workspace.deinit();
                break :blk workspace.matches(program, value);
            },
            .path_template => |matcher| matcher.match(value, captures),
        };
    }
    pub fn templateVariables(self: Match) []const []const u8 {
        return switch (self) {
            .path_template => |matcher| matcher.variables,
            else => &.{},
        };
    }
    pub fn templateMatch(self: Match) ?*const template.Match {
        return switch (self) {
            .path_template => |matcher| matcher,
            else => null,
        };
    }
    pub fn matchesWithBudget(self: Match, gpa: std.mem.Allocator, value: []const u8, budget: ?regex.Budget) (std.mem.Allocator.Error || @import("regex/budget.zig").Error)!bool {
        if (budget) |active| {
            try active.check();
            if (self == .safe_regex) {
                var workspace = try regex.Workspace.init(gpa, self.safe_regex);
                defer workspace.deinit();
                return workspace.matchesWithBudget(self.safe_regex, value, active);
            }
        }
        return self.matches(gpa, value);
    }
};

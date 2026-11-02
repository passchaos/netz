//! Owned bounded RE2 boolean/full-match engine for xDS safe-regex matchers.
const std = @import("std");
const model = @import("regex/model.zig");
pub const Error = model.Error;
pub const Limits = model.Limits;
pub const Budget = @import("regex/budget.zig").Budget;
pub const Workspace = @import("regex/execute.zig").Workspace;
pub const Regex = struct {
    arena: std.heap.ArenaAllocator,
    program: @import("regex/compile.zig").Program,
    pub fn init(gpa: std.mem.Allocator, pattern: []const u8, limits: Limits) Error!Regex {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const root = try @import("regex/parse.zig").parse(arena.allocator(), pattern, limits);
        const program = try @import("regex/compile.zig").compile(arena.allocator(), root, limits);
        return .{ .arena = arena, .program = program };
    }
    pub fn deinit(self: *Regex) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn matches(self: *const Regex, gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error!bool {
        var workspace = try Workspace.init(gpa, self.program);
        defer workspace.deinit();
        return workspace.matches(self.program, input);
    }
};
test {
    _ = @import("regex/tests.zig");
    _ = @import("regex/budget_tests.zig");
}

//! Batched independent RE2 comparison; input/output have no network dependency.
const std = @import("std");
const regex = @import("xds_regex");
const Case = struct {
    pattern: []const u8,
    inputs: []const []const u8,
    substitution: ?[]const u8 = null,
};
const Result = struct {
    err: ?[]const u8 = null,
    matches: []const bool = &.{},
    replacements: []const []const u8 = &.{},
    max_states: usize = 0,
    instructions: usize = 0,
};
pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 2) return error.InvalidArguments;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], gpa, .limited(16 * 1024 * 1024));
    const input = try std.json.parseFromSlice([]const Case, gpa, bytes, .{});
    const results = try gpa.alloc(Result, input.value.len);
    for (input.value, results) |case, *result| {
        var value = regex.Regex.init(std.heap.page_allocator, case.pattern, .{}) catch |err| {
            result.* = .{ .err = @errorName(err) };
            continue;
        };
        defer value.deinit();
        var workspace = try regex.Workspace.init(std.heap.page_allocator, value.program);
        defer workspace.deinit();
        const matches = try gpa.alloc(bool, case.inputs.len);
        result.* = .{ .matches = matches, .instructions = value.program.instructions.len };
        for (case.inputs, matches) |text, *match| {
            match.* = workspace.matches(value.program, text);
            if (workspace.stats.states_visited > value.program.instructions.len * (text.len + 1)) return error.NonLinearRegexExecution;
            result.max_states = @max(result.max_states, workspace.stats.states_visited);
        }
        if (case.substitution) |substitution| {
            var replacer = try regex.ReplaceWorkspace.init(
                std.heap.page_allocator,
                value.program,
                .{},
            );
            defer replacer.deinit();
            const replacements = try gpa.alloc([]const u8, case.inputs.len);
            for (case.inputs, replacements) |text, *replacement| {
                replacement.* = replacer.replaceAll(text, substitution) catch |err| {
                    result.err = @errorName(err);
                    break;
                };
            }
            result.replacements = replacements;
        }
    }
    var buffer: [8192]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &buffer);
    try std.json.Stringify.value(results, .{}, &output.interface);
    try output.interface.flush();
}

//! Compile interop executables without starting external peers.
const std = @import("std");

pub fn add(b: *std.Build) void {
    const filters = b.option([]const []const u8, "interop-filter", "Interop executable name or source-path substring; repeat to combine") orelse &.{};
    const compile = b.step("test-compile-interop", "Compile selected interop executables without running peers");
    var visited: std.AutoHashMapUnmanaged(*std.Build.Step, void) = .empty;
    defer visited.deinit(b.allocator);
    var count: usize = 0;
    for (b.top_level_steps.values()) |top| visit(b, &top.step, compile, filters, &visited, &count);
    if (count == 0) compile.dependOn(&b.addFail("NoMatchingInteropPrograms").step);
}

fn visit(b: *std.Build, step: *std.Build.Step, compile: *std.Build.Step, filters: []const []const u8, visited: *std.AutoHashMapUnmanaged(*std.Build.Step, void), count: *usize) void {
    const entry = visited.getOrPut(b.allocator, step) catch @panic("OOM");
    if (entry.found_existing) return;
    if (step.cast(std.Build.Step.Compile)) |artifact| {
        if (artifact.kind == .exe) {
            if (artifact.root_module.root_source_file) |source| {
                const path = source.getPath(b);
                if (std.mem.startsWith(u8, path, b.pathFromRoot("tools/interop/")) and matches(artifact.name, path, filters)) {
                    compile.dependOn(step);
                    count.* += 1;
                }
            }
        }
    }
    for (step.dependencies.items) |dependency| visit(b, dependency, compile, filters, visited, count);
}

fn matches(name: []const u8, path: []const u8, filters: []const []const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |filter| {
        if (std.mem.indexOf(u8, name, filter) != null or std.mem.indexOf(u8, path, filter) != null) return true;
    }
    return false;
}

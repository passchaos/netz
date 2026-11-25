//! Opt-in test-name progress using Zig's standard terminal runner.
const std = @import("std");

pub fn add(b: *std.Build, tests: *std.Build.Step.Compile, progress: bool) *std.Build.Step.Run {
    const run = b.addRunArtifact(tests);
    if (progress) configure(run);
    return run;
}

fn configure(run: *std.Build.Step.Run) void {
    const tests = run.producer orelse return;
    if (tests.kind == .@"test" and tests.test_runner == null and run.stdio == .zig_test) {
        // Keep the producer, executor, seed and cache arguments installed by
        // addRunArtifact. Only the server-protocol switch selects terminal mode.
        const listen = run.argv.pop().?;
        std.debug.assert(listen == .bytes and std.mem.eql(u8, listen.bytes, "--listen=-"));
        run.stdio = .inherit;
    }
}

/// Include standard auxiliary/fuzz test artifacts registered by build modules.
/// The traversal is idempotent and leaves executables and custom runners alone.
pub fn enableAll(b: *std.Build) void {
    var visited: std.AutoHashMapUnmanaged(*std.Build.Step, void) = .empty;
    defer visited.deinit(b.allocator);
    for (b.top_level_steps.values()) |top| visit(b, &top.step, &visited);
}

fn visit(b: *std.Build, step: *std.Build.Step, visited: *std.AutoHashMapUnmanaged(*std.Build.Step, void)) void {
    const entry = visited.getOrPut(b.allocator, step) catch @panic("OOM");
    if (entry.found_existing) return;
    if (step.cast(std.Build.Step.Run)) |run| configure(run);
    for (step.dependencies.items) |dependency| visit(b, dependency, visited);
}

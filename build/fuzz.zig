//! Individual fuzz entry points and cohesive corpus replay compilation.
const std = @import("std");
const specs = @import("fuzz/specs.zig");

pub fn addAll(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, netz_mod: *std.Build.Module, test_step: *std.Build.Step) void {
    specs.validateRoot(@embedFile("../test/fuzz_replay_test.zig")) catch |err| std.debug.panic("invalid fuzz replay membership: {s}", .{@errorName(err)});
    const independent = b.step("test-fuzz-replay-independent", "Replay all original fuzz roots independently for diagnosis");
    for (specs.all) |spec| {
        const tests = b.addTest(.{ .root_module = module(b, target, optimize, netz_mod, spec.root, null) });
        const run = b.addRunArtifact(tests);
        const step = b.step(spec.name, spec.description);
        step.dependOn(&run.step);
        independent.dependOn(&run.step);
    }
    const grouped = b.step("test-fuzz-replay", "Replay every original fuzz corpus with protocol groups");
    const compile = b.step("test-fuzz-replay-compile", "Compile all protocol fuzz corpus replay groups");
    for (std.enums.values(specs.Family)) |family| {
        const options = b.addOptions();
        options.addOption(specs.Family, "family", family);
        const tests = b.addTest(.{ .name = b.fmt("fuzz-replay-{s}", .{@tagName(family)}), .root_module = module(b, target, optimize, netz_mod, "test/fuzz_replay_test.zig", options.createModule()) });
        const run = b.addRunArtifact(tests);
        const step = b.step(b.fmt("test-fuzz-replay-{s}", .{@tagName(family)}), b.fmt("Replay the {s} fuzz corpus group", .{@tagName(family)}));
        step.dependOn(&run.step);
        grouped.dependOn(&run.step);
        compile.dependOn(&tests.step);
    }
    test_step.dependOn(grouped);
}

fn module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, netz_mod: *std.Build.Module, root: []const u8, options: ?*std.Build.Module) *std.Build.Module {
    const result = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
        // Preserve the existing Zig 0.16 fuzz runner StackTrace workaround.
        .error_tracing = false,
        .imports = &.{.{ .name = "netz", .module = netz_mod }},
    });
    if (options) |value| result.addImport("fuzz_replay_options", value);
    return result;
}

//! Share auxiliary compilation while retaining each isolated diagnostic root.
const std = @import("std");
const specs = @import("support_specs.zig").all;
const test_run = @import("run.zig");

pub fn add(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, netz_module: *std.Build.Module, vail_module: *std.Build.Module, filters: []const []const u8, progress: bool, full_test: *std.Build.Step) void {
    const independent = b.step("test-support-independent", "Run support test roots as separate executables");
    for (specs) |spec| {
        const module = b.createModule(.{
            .root_source_file = b.path(spec.path),
            .target = target,
            .optimize = optimize,
            .link_libc = if (spec.force_libc) true else null,
        });
        if (spec.imports != .none) module.addImport("netz", netz_module);
        if (spec.imports == .netz_vail) module.addImport("vail", vail_module);
        const tests = b.addTest(.{ .root_module = module, .filters = if (spec.apply_filters) filters else &.{} });
        const run = test_run.add(b, tests, progress);
        independent.dependOn(&run.step);
        if (spec.step) |entry| b.step(entry.name, entry.description).dependOn(&run.step);
    }
    const grouped = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("support_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "netz", .module = netz_module },
                .{ .name = "vail", .module = vail_module },
            },
        }),
        .filters = filters,
    });
    b.step("test-support-compile", "Compile grouped support tests without running them").dependOn(&grouped.step);
    const run = test_run.add(b, grouped, progress);
    b.step("test-support", "Run benchmark and server support unit tests together").dependOn(&run.step);
    full_test.dependOn(&run.step);
}

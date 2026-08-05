const std = @import("std");
const builtin = @import("builtin");

const required_zig_version = "0.16.0";

pub fn build(b: *std.Build) void {
    comptime {
        if (!std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) {
            @compileError("netz requires Zig " ++ required_zig_version ++ "; found " ++ builtin.zig_version_string);
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const netz_mod = b.addModule("netz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "netz",
        .root_module = netz_mod,
    });
    b.installArtifact(lib);

    const lib_tests = b.addTest(.{ .root_module = netz_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const package_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/package_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_package_tests = b.addRunArtifact(package_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_package_tests.step);
}

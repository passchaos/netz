const std = @import("std");

pub fn add(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, netz: *std.Build.Module, tests: *std.Build.Step) void {
    const driver = b.addExecutable(.{
        .name = "netz-http-digest-interop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/http_digest/driver.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz }},
        }),
    });
    const run = b.addSystemCommand(&.{ "uv", "run", "--script", "tools/interop/http_digest/run.py" });
    run.addArtifactArg(driver);
    if (b.args) |args| run.addArgs(args);
    b.step("interop-http-digest-python", "Verify RFC9530 HTTP digests, trailers and streaming against independent Python HTTPS peers").dependOn(&run.step);
    tests.dependOn(&run.step);
}

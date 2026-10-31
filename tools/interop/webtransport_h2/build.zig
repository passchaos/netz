const std = @import("std");

pub fn add(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, netz: *std.Build.Module, tests: *std.Build.Step) void {
    const driver = b.addExecutable(.{
        .name = "netz-webtransport-h2-interop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/webtransport_h2/driver.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz }},
        }),
    });
    const run = b.addSystemCommand(&.{ "uv", "run", "--script", "tools/interop/webtransport_h2/run.py" });
    run.addArtifactArg(driver);
    if (b.args) |args| run.addArgs(args);
    b.step("interop-webtransport-h2-python", "Verify draft-15 WebTransport HTTP2 against an independent Python peer in both directions").dependOn(&run.step);
    tests.dependOn(&run.step);
}

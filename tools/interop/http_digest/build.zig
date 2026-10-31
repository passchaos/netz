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
    const h3_driver = b.addExecutable(.{
        .name = "netz-http3-digest-interop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/http_digest/h3/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz }},
        }),
    });
    const h3 = b.addSystemCommand(&.{ "python3", "tools/interop/http_digest/h3/run.py" });
    h3.addArtifactArg(h3_driver);
    if (b.args) |args| h3.addArgs(args);
    b.step("interop-http-digest-quic-go", "Verify HTTP3 integrity digests against pinned quic-go in both roles and QUIC versions").dependOn(&h3.step);
    const all = b.step("interop-http-digest", "Verify HTTP integrity digests over HTTP1, HTTP2 and HTTP3");
    all.dependOn(&run.step);
    all.dependOn(&h3.step);
}

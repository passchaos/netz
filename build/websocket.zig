//! WebSocket Autobahn and browser interoperability steps.

const std = @import("std");

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    test_step: *std.Build.Step,
) void {
    const websocket_autobahn_server = b.addExecutable(.{
        .name = "netz-websocket-autobahn-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_autobahn_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_autobahn_client = b.addExecutable(.{
        .name = "netz-websocket-autobahn-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_autobahn_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_autobahn_client_step = b.step(
        "build-websocket-autobahn-client",
        "Build the Autobahn fuzzing-server echo testee",
    );
    websocket_autobahn_client_step.dependOn(&websocket_autobahn_client.step);
    const websocket_autobahn_client_install = b.addInstallArtifact(
        websocket_autobahn_client,
        .{},
    );
    websocket_autobahn_client_step.dependOn(&websocket_autobahn_client_install.step);
    const websocket_autobahn = b.addSystemCommand(
        &.{"tools/interop/websocket_autobahn.sh"},
    );
    websocket_autobahn.addArtifactArg(websocket_autobahn_server);
    if (b.args) |args| websocket_autobahn.addArgs(args);
    const websocket_autobahn_step = b.step(
        "interop-websocket-autobahn",
        "Run external Autobahn against netz (pass --tls for WSS)",
    );
    websocket_autobahn_step.dependOn(&websocket_autobahn.step);
    const websocket_autobahn_smoke = b.addSystemCommand(
        &.{ "python3", "tools/interop/websocket_autobahn_smoke.py" },
    );
    websocket_autobahn_smoke.addArtifactArg(websocket_autobahn_server);
    const websocket_autobahn_smoke_step = b.step(
        "interop-websocket-autobahn-smoke",
        "Run real-socket cleartext/TLS smoke for the Autobahn adapter",
    );
    websocket_autobahn_smoke_step.dependOn(&websocket_autobahn_smoke.step);
    test_step.dependOn(&websocket_autobahn_smoke.step);

    const websocket_chrome_server = b.addExecutable(.{
        .name = "netz-websocket-chrome-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_chrome_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_chrome = b.addSystemCommand(&.{
        "tools/interop/websocket_chrome.sh",
    });
    websocket_chrome.addArtifactArg(websocket_chrome_server);
    if (b.args) |args| websocket_chrome.addArgs(args);
    const websocket_chrome_step = b.step(
        "interop-websocket-chrome",
        "Exercise HTTP/1 WebSocket interoperability with Chrome (pass --tls for WSS)",
    );
    websocket_chrome_step.dependOn(&websocket_chrome.step);
}

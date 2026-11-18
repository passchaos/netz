//! gRPC C++ interop, reflection, and release-source verification steps.

const std = @import("std");
const package_version = @import("../build.zig.zon").version;

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    vail_dep: *std.Build.Dependency,
    vort_dep: *std.Build.Dependency,
    zio_dep: *std.Build.Dependency,
    regexz_dep: *std.Build.Dependency,
    webpkiz_dep: *std.Build.Dependency,
    kron_dep: *std.Build.Dependency,
    harnessz_dep: *std.Build.Dependency,
) void {
    const grpc_cpp_client = b.addExecutable(.{
        .name = "netz-grpc-cpp-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_cpp_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cpp_pick_first_failover = b.addExecutable(.{
        .name = "netz-grpc-cpp-pick-first-failover",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_cpp_pick_first_failover.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_hyper_proxy_client = b.addExecutable(.{
        .name = "netz-grpc-hyper-proxy-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_hyper_proxy_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_socks5_client = b.addExecutable(.{
        .name = "netz-grpc-socks5-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_socks5_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cpp_interop = b.addSystemCommand(
        &.{"tools/interop/grpc_cpp.sh"},
    );
    grpc_cpp_interop.addArtifactArg(grpc_cpp_client);
    grpc_cpp_interop.addArtifactArg(grpc_cpp_pick_first_failover);
    grpc_cpp_interop.addArtifactArg(grpc_hyper_proxy_client);
    grpc_cpp_interop.addArtifactArg(grpc_socks5_client);
    const grpc_cpp_interop_step = b.step(
        "interop-grpc-cpp",
        "Run netz gRPC h2c/TLS client against upstream gRPC C++",
    );
    grpc_cpp_interop_step.dependOn(&grpc_cpp_interop.step);

    const grpc_cpp_server = b.addExecutable(.{
        .name = "netz-grpc-cpp-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_cpp_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cpp_client_interop = b.addSystemCommand(
        &.{"tools/interop/grpc_cpp_client.sh"},
    );
    grpc_cpp_client_interop.addArtifactArg(grpc_cpp_server);
    const grpc_cpp_client_interop_step = b.step(
        "interop-grpc-cpp-client",
        "Run upstream gRPC C++ client against netz gRPC h2c/TLS server",
    );
    grpc_cpp_client_interop_step.dependOn(
        &grpc_cpp_client_interop.step,
    );

    const grpc_h2_ping_abuse = b.addSystemCommand(
        &.{"tools/interop/grpc_h2_ping_abuse.sh"},
    );
    grpc_h2_ping_abuse.addArtifactArg(grpc_cpp_server);
    const grpc_h2_keepalive_throttle_client = b.addExecutable(.{
        .name = "netz-grpc-h2-keepalive-throttle-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_h2_keepalive_throttle_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    grpc_h2_ping_abuse.addArtifactArg(
        grpc_h2_keepalive_throttle_client,
    );
    const grpc_h2_ping_abuse_step = b.step(
        "interop-grpc-h2-ping-abuse",
        "Verify gRPC server PING abuse GOAWAY with Rust h2",
    );
    grpc_h2_ping_abuse_step.dependOn(&grpc_h2_ping_abuse.step);

    const grpc_reflection_server = b.addExecutable(.{
        .name = "netz-grpc-reflection-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/grpc_reflection_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_reflection_interop = b.addSystemCommand(
        &.{"tools/interop/grpc_reflection.sh"},
    );
    grpc_reflection_interop.addArtifactArg(grpc_reflection_server);
    const grpc_reflection_interop_step = b.step(
        "interop-grpc-reflection",
        "Run upstream grpc_cli against netz reflection",
    );
    grpc_reflection_interop_step.dependOn(
        &grpc_reflection_interop.step,
    );

    if (b.lazyDependency("pbz", .{
        .target = target,
        .optimize = optimize,
    })) |pbz_dep| {
        const source_archive = b.addSystemCommand(&.{
            "python3",
            "tools/release/source_archive.py",
            "--root",
        });
        source_archive.addDirectoryArg(b.path("."));
        source_archive.addArg("--vail");
        source_archive.addDirectoryArg(vail_dep.path("."));
        source_archive.addArg("--vort");
        source_archive.addDirectoryArg(vort_dep.path("."));
        source_archive.addArg("--pbz");
        source_archive.addDirectoryArg(pbz_dep.path("."));
        source_archive.addArg("--kron");
        source_archive.addDirectoryArg(kron_dep.path("."));
        source_archive.addArg("--webpkiz");
        source_archive.addDirectoryArg(webpkiz_dep.path("."));
        source_archive.addArg("--regexz");
        source_archive.addDirectoryArg(regexz_dep.path("."));
        source_archive.addArg("--harnessz");
        source_archive.addDirectoryArg(harnessz_dep.path("."));
        source_archive.addArg("--zio");
        source_archive.addDirectoryArg(zio_dep.path("."));
        source_archive.addArgs(&.{ "--zig", b.graph.zig_exe });
        source_archive.addArgs(&.{ "--version", package_version });
        source_archive.addArg("--output");
        const source_archive_path = source_archive.addOutputFileArg(
            b.fmt("netz-{s}-source.tar.gz", .{package_version}),
        );
        source_archive.has_side_effects = true;
        const archive_checksum = b.addSystemCommand(&.{
            "python3",
            "tools/release/archive_checksum.py",
        });
        archive_checksum.addFileArg(source_archive_path);
        archive_checksum.addArg("--write");
        const archive_checksum_path = archive_checksum.addOutputFileArg(
            b.fmt("netz-{s}-source.tar.gz.sha256", .{package_version}),
        );
        const install_source_archive = b.addInstallFileWithDir(
            source_archive_path,
            .{ .custom = "artifacts" },
            b.fmt("netz-{s}-source.tar.gz", .{package_version}),
        );
        const install_archive_checksum = b.addInstallFileWithDir(
            archive_checksum_path,
            .{ .custom = "artifacts" },
            b.fmt("netz-{s}-source.tar.gz.sha256", .{package_version}),
        );
        const release_source_step = b.step(
            "release-source",
            "Build a deterministic source archive with vendored path dependencies",
        );
        release_source_step.dependOn(&install_source_archive.step);
        release_source_step.dependOn(&install_archive_checksum.step);

        const verify_source_archive = b.addSystemCommand(&.{
            "python3",
            "tools/release/verify_source_archive.py",
        });
        verify_source_archive.addFileArg(source_archive_path);
        verify_source_archive.addArg("--checksum");
        verify_source_archive.addFileArg(archive_checksum_path);
        verify_source_archive.addArgs(&.{ "--zig", b.graph.zig_exe });
        const verify_release_source_step = b.step(
            "verify-release-source",
            "Build and test the source archive outside the workspace layout",
        );
        verify_release_source_step.dependOn(&verify_source_archive.step);

        const generate_grpc_pbz = b.addSystemCommand(&.{"protoc"});
        generate_grpc_pbz.addPrefixedArtifactArg(
            "--plugin=protoc-gen-pbz=",
            pbz_dep.artifact("protoc-gen-pbz"),
        );
        generate_grpc_pbz.addArg("--proto_path=tools/interop");
        const grpc_pbz_output = generate_grpc_pbz
            .addPrefixedOutputDirectoryArg(
            "--pbz_out=",
            "grpc-pbz-generated",
        );
        generate_grpc_pbz.addFileInput(b.path(
            "tools/interop/grpc_pbz.proto",
        ));
        generate_grpc_pbz.addArg("grpc_pbz.proto");
        const grpc_pbz_module = b.createModule(.{
            .root_source_file = grpc_pbz_output.path(
                b,
                "grpc_pbz.pb.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "pbz",
                .module = pbz_dep.module("pbz"),
            }},
        });
        const grpc_pbz_interop = b.addExecutable(.{
            .name = "netz-grpc-pbz-interop",
            .root_module = b.createModule(.{
                .root_source_file = b.path(
                    "tools/interop/grpc_pbz.zig",
                ),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "netz", .module = netz_mod },
                    .{ .name = "grpc_pb", .module = grpc_pbz_module },
                },
            }),
        });
        grpc_pbz_interop.step.dependOn(&generate_grpc_pbz.step);
        const run_grpc_pbz_interop = b.addRunArtifact(grpc_pbz_interop);
        const grpc_pbz_interop_step = b.step(
            "interop-grpc-pbz",
            "Generate pbz bindings and exercise all four gRPC RPC shapes",
        );
        grpc_pbz_interop_step.dependOn(&run_grpc_pbz_interop.step);
    }
}

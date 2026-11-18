//! WebTransport interop and benchmark steps.

const std = @import("std");

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    test_step: *std.Build.Step,
    benchmark_counting_allocator_mod: *std.Build.Module,
) void {
    const webtransport_wtransport_server = b.addExecutable(.{
        .name = "netz-webtransport-wtransport-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/webtransport_wtransport_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const webtransport_wtransport_client = b.addExecutable(.{
        .name = "netz-webtransport-wtransport-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/webtransport_wtransport_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
        }),
    });
    const webtransport_wtransport = b.addSystemCommand(&.{
        "tools/interop/webtransport_wtransport.sh",
    });
    webtransport_wtransport.addArtifactArg(
        webtransport_wtransport_server,
    );
    webtransport_wtransport.addArtifactArg(
        webtransport_wtransport_client,
    );
    const webtransport_wtransport_step = b.step(
        "interop-webtransport-wtransport",
        "Exercise WebTransport admission, datagrams, streams, cancellation, reuse, and close with wtransport",
    );
    webtransport_wtransport_step.dependOn(
        &webtransport_wtransport.step,
    );
    const webtransport_socks5 = b.addSystemCommand(&.{
        "python3",
        "tools/interop/webtransport_socks5.py",
    });
    webtransport_socks5.addArtifactArg(webtransport_wtransport_client);
    const webtransport_socks5_step = b.step(
        "interop-webtransport-socks5",
        "Run WebTransport through independent SOCKS5 UDP relays",
    );
    webtransport_socks5_step.dependOn(&webtransport_socks5.step);
    test_step.dependOn(&webtransport_socks5.step);
    const webtransport_wtransport_bench = b.addSystemCommand(&.{
        "tools/interop/webtransport_wtransport.sh",
    });
    webtransport_wtransport_bench.addArtifactArg(
        webtransport_wtransport_server,
    );
    webtransport_wtransport_bench.addArtifactArg(
        webtransport_wtransport_client,
    );
    webtransport_wtransport_bench.addArg("--bench");
    if (b.args) |args| webtransport_wtransport_bench.addArgs(args);
    const webtransport_wtransport_bench_step = b.step(
        "bench-webtransport-wtransport",
        "Compare verified WebTransport stream upload and DATAGRAM ping-pong with wtransport",
    );
    webtransport_wtransport_bench_step.dependOn(
        &webtransport_wtransport_bench.step,
    );

    const webtransport_churn_bench = b.addExecutable(.{
        .name = "netz-webtransport-stream-churn",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/benchmarks/bench_webtransport_stream.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const webtransport_churn = b.addSystemCommand(&.{
        "tools/interop/webtransport_stream_churn.sh",
    });
    webtransport_churn.addArtifactArg(webtransport_churn_bench);
    const webtransport_churn_step = b.step(
        "interop-webtransport-stream-churn",
        "Repeat mixed WebTransport FIN/reset traffic under loss/reordering",
    );
    webtransport_churn_step.dependOn(&webtransport_churn.step);

    const webtransport_wtransport_churn = b.addSystemCommand(&.{
        "tools/interop/webtransport_wtransport_churn.sh",
    });
    webtransport_wtransport_churn.addArtifactArg(
        webtransport_wtransport_client,
    );
    webtransport_wtransport_churn.addArtifactArg(
        webtransport_wtransport_server,
    );
    const webtransport_wtransport_churn_step = b.step(
        "interop-webtransport-wtransport-churn",
        "Exercise bidirectional-role WebTransport FIN/reset recovery with wtransport",
    );
    webtransport_wtransport_churn_step.dependOn(
        &webtransport_wtransport_churn.step,
    );

    const webtransport_wtransport_churn_long = b.addSystemCommand(&.{
        "tools/interop/webtransport_wtransport_churn_long.sh",
    });
    webtransport_wtransport_churn_long.addArtifactArg(
        webtransport_wtransport_client,
    );
    webtransport_wtransport_churn_long.addArtifactArg(
        webtransport_wtransport_server,
    );
    const webtransport_wtransport_churn_long_step = b.step(
        "interop-webtransport-wtransport-churn-long",
        "Run multi-minute heterogeneous WebTransport churn with wtransport",
    );
    webtransport_wtransport_churn_long_step.dependOn(
        &webtransport_wtransport_churn_long.step,
    );

    const webtransport_chrome = b.addSystemCommand(&.{
        "tools/interop/webtransport_chrome.sh",
    });
    webtransport_chrome.addArtifactArg(
        webtransport_wtransport_server,
    );
    const webtransport_chrome_step = b.step(
        "interop-webtransport-chrome",
        "Exercise WebTransport CONNECT, datagrams, streams, cancellation, and close with Chrome",
    );
    webtransport_chrome_step.dependOn(&webtransport_chrome.step);
    const webtransport_firefox = b.addSystemCommand(&.{
        "tools/interop/webtransport_firefox.sh",
    });
    webtransport_firefox.addArtifactArg(
        webtransport_wtransport_server,
    );
    const webtransport_firefox_step = b.step(
        "interop-webtransport-firefox",
        "Exercise WebTransport Origin, datagrams, streams, cancellation, reuse, and close with Firefox",
    );
    webtransport_firefox_step.dependOn(&webtransport_firefox.step);

    const webtransport_protocol_server = b.addExecutable(.{
        .name = "netz-webtransport-protocol-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/webtransport_protocol/netz_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const webtransport_protocol_client = b.addExecutable(.{
        .name = "netz-webtransport-protocol-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/webtransport_protocol/netz_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const webtransport_protocol_build = b.step("build-webtransport-protocol", "Build native application-protocol negotiation peers");
    webtransport_protocol_build.dependOn(&b.addInstallArtifact(webtransport_protocol_server, .{}).step);
    webtransport_protocol_build.dependOn(&b.addInstallArtifact(webtransport_protocol_client, .{}).step);
    const webtransport_protocol_rust = b.addSystemCommand(&.{ "cargo", "build", "--release", "--locked", "--jobs", "2", "--manifest-path", "tools/interop/webtransport_protocol/Cargo.toml", "--target-dir", "tools/interop/webtransport_protocol/target" });
    const webtransport_protocol = b.addSystemCommand(&.{ "uv", "run", "--script", "tools/interop/webtransport_protocol/run.py" });
    webtransport_protocol.addArtifactArg(webtransport_protocol_server);
    webtransport_protocol.addArtifactArg(webtransport_protocol_client);
    webtransport_protocol.addArg("tools/interop/webtransport_protocol/target/release/netz-webtransport-protocol-peer");
    webtransport_protocol.step.dependOn(&webtransport_protocol_rust.step);
    if (b.args) |args| webtransport_protocol.addArgs(args);
    b.step("interop-webtransport-protocol", "Verify WebTransport application-protocol negotiation and scoped rejection with independent peers").dependOn(&webtransport_protocol.step);
}

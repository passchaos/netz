//! QUIC process interop and benchmark steps.

const std = @import("std");

pub fn addInterop(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    benchmark_counting_allocator_mod: *std.Build.Module,
    vail_dep: *std.Build.Dependency,
) void {
    const quic_peer_client = b.addExecutable(.{
        .name = "netz-quic-peer-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_peer_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const quic_peer_server = b.addExecutable(.{
        .name = "netz-quic-peer-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_peer_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const quic_quic_go = b.addSystemCommand(
        &.{"tools/interop/quic_quic_go.sh"},
    );
    quic_quic_go.addArtifactArg(quic_peer_client);
    quic_quic_go.addArtifactArg(quic_peer_server);
    const quic_quic_go_step = b.step(
        "interop-quic-quic-go",
        "Run verified QUIC lifecycle, migration, flow-control, and loss interop with local quic-go fixtures",
    );
    quic_quic_go_step.dependOn(&quic_quic_go.step);
    const quic_handshake_fault = b.addSystemCommand(
        &.{"tools/interop/quic_handshake_fault.sh"},
    );
    quic_handshake_fault.addArtifactArg(quic_peer_client);
    quic_handshake_fault.addArtifactArg(quic_peer_server);
    const quic_handshake_fault_step = b.step(
        "interop-quic-handshake-fault",
        "Verify bidirectional QUIC v1/v2 quic-go handshake recovery after deterministic loss/corruption",
    );
    quic_handshake_fault_step.dependOn(&quic_handshake_fault.step);
    const quic_quic_go_bench_client = b.addExecutable(.{
        .name = "netz-quic-quic-go-bench-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_quic_go_bench_client.zig",
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
    const quic_quic_go_bench_server = b.addExecutable(.{
        .name = "netz-quic-quic-go-bench-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_quic_go_bench_server.zig",
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
    const quic_quic_go_bench = b.addSystemCommand(
        &.{"tools/interop/quic_quic_go_bench.sh"},
    );
    quic_quic_go_bench.addArtifactArg(quic_quic_go_bench_client);
    quic_quic_go_bench.addArtifactArg(quic_quic_go_bench_server);
    if (b.args) |args| quic_quic_go_bench.addArgs(args);
    const quic_quic_go_bench_step = b.step(
        "bench-quic-quic-go",
        "Compare verified raw QUIC STREAM transfer against quic-go",
    );
    quic_quic_go_bench_step.dependOn(&quic_quic_go_bench.step);
    const quic_persistent_bench_exe = b.addExecutable(.{
        .name = "netz-quic-persistent-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_persistent_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const quic_persistent_bench = b.addSystemCommand(
        &.{"tools/interop/quic_persistent_benchmark.sh"},
    );
    quic_persistent_bench.addArtifactArg(quic_persistent_bench_exe);
    if (b.args) |args| quic_persistent_bench.addArgs(args);
    const quic_persistent_bench_step = b.step(
        "bench-quic-persistent-external",
        "Compare persistent QUIC echo latency and aggregate multi-connection throughput against quic-go",
    );
    quic_persistent_bench_step.dependOn(&quic_persistent_bench.step);
    const quic_handshake_bench_exe = b.addExecutable(.{
        .name = "netz-quic-handshake-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_handshake_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{ .name = "vail", .module = vail_dep.module("vail") },
            },
        }),
    });
    const quic_handshake_bench = b.addSystemCommand(
        &.{"tools/interop/quic_handshake_benchmark.sh"},
    );
    quic_handshake_bench.addArtifactArg(quic_handshake_bench_exe);
    if (b.args) |args| quic_handshake_bench.addArgs(args);
    const quic_handshake_bench_step = b.step(
        "bench-quic-handshake-external",
        "Compare fresh certificate-verified QUIC handshakes across netz/quic-go role pairs",
    );
    quic_handshake_bench_step.dependOn(&quic_handshake_bench.step);
    const quic_handshake_quinn_bench = b.addSystemCommand(
        &.{"tools/interop/quic_quinn/handshake_benchmark.sh"},
    );
    quic_handshake_quinn_bench.addArtifactArg(quic_handshake_bench_exe);
    quic_handshake_quinn_bench.addArg(@tagName(optimize));
    if (b.args) |args| quic_handshake_quinn_bench.addArgs(args);
    const quic_handshake_quinn_bench_step = b.step(
        "bench-quic-handshake-quinn",
        "Compare fresh certificate-verified QUIC handshakes with Quinn",
    );
    quic_handshake_quinn_bench_step.dependOn(
        &quic_handshake_quinn_bench.step,
    );
    const quic_quic_go_churn = b.addSystemCommand(
        &.{"tools/interop/quic_quic_go_churn.sh"},
    );
    quic_quic_go_churn.addArtifactArg(quic_quic_go_bench_client);
    quic_quic_go_churn.addArtifactArg(quic_quic_go_bench_server);
    const quic_quic_go_churn_step = b.step(
        "interop-quic-quic-go-churn",
        "Exercise raw QUIC mixed FIN/reset recovery with quic-go under loss/reordering",
    );
    quic_quic_go_churn_step.dependOn(&quic_quic_go_churn.step);

    const quic_s2n = b.addSystemCommand(
        &.{"tools/interop/quic_s2n.sh"},
    );
    quic_s2n.addArtifactArg(quic_peer_client);
    quic_s2n.addArtifactArg(quic_peer_server);
    const quic_s2n_step = b.step(
        "interop-quic-s2n",
        "Run verified QUIC stream, DATAGRAM, cancellation, and close interop with local s2n-quic",
    );
    quic_s2n_step.dependOn(&quic_s2n.step);

    const quic_quinn = b.addSystemCommand(
        &.{"tools/interop/quic_quinn.sh"},
    );
    quic_quinn.addArtifactArg(quic_peer_client);
    quic_quinn.addArtifactArg(quic_peer_server);
    const quic_quinn_step = b.step(
        "interop-quic-quinn",
        "Run verified native QUIC DATAGRAM and fault interop with local Quinn",
    );
    quic_quinn_step.dependOn(&quic_quinn.step);

    const quic_datagram_bench_client = b.addExecutable(.{
        .name = "netz-quic-datagram-bench-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_datagram_bench_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const quic_datagram_bench_server = b.addExecutable(.{
        .name = "netz-quic-datagram-bench-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_datagram_bench_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const quic_datagram_quinn_bench = b.addSystemCommand(&.{
        "tools/interop/quic_datagram_quinn_benchmark.sh",
    });
    quic_datagram_quinn_bench.addArtifactArg(quic_datagram_bench_client);
    quic_datagram_quinn_bench.addArtifactArg(quic_datagram_bench_server);
    quic_datagram_quinn_bench.addArg(@tagName(optimize));
    if (b.args) |args| quic_datagram_quinn_bench.addArgs(args);
    const quic_datagram_quinn_bench_step = b.step(
        "bench-quic-datagram-quinn",
        "Compare zio-backed single/windowed QUIC DATAGRAM latency with Quinn",
    );
    quic_datagram_quinn_bench_step.dependOn(
        &quic_datagram_quinn_bench.step,
    );
}

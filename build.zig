const std = @import("std");
const builtin = @import("builtin");
const examples = @import("build/examples.zig");
const interop = @import("build/interop.zig");
const fuzz = @import("build/fuzz.zig");
const grpc = @import("build/grpc.zig");
const mqtt = @import("build/mqtt.zig");
const http = @import("build/http.zig");
const grpc_cpp = @import("build/grpc_cpp.zig");
const websocket = @import("build/websocket.zig");
const quic = @import("build/quic.zig");
const webtransport = @import("build/webtransport.zig");
const protocols = @import("build/protocols.zig");
const focused_tests = @import("build/testing/focused.zig");

const required_zig_version = "0.16.0";
const package_version = @import("build.zig.zon").version;

pub fn build(b: *std.Build) void {
    comptime {
        if (!std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) {
            @compileError("netz requires Zig " ++ required_zig_version ++ "; found " ++ builtin.zig_version_string);
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_progress = b.option(bool, "test-progress", "Print each library, package and focused test name using Zig's standard terminal runner") orelse false;
    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Run only tests whose name contains one of these substrings",
    ) orelse &.{};
    const vail_dep = b.dependency("vail", .{
        .target = target,
        .optimize = optimize,
    });
    // An explicit -Dtarget disables Zig's automatic macOS SDK discovery, so
    // framework links (`Security`, `CoreFoundation`) need explicit search
    // paths. CI passes -Dmacos-sdk; local macOS hosts discover the SDK here.
    if (target.result.os.tag == .macos) {
        if (b.option(
            []const u8,
            "macos-sdk",
            "macOS SDK root for cross-compiled framework links",
        ) orelse std.zig.system.darwin.getSdk(
            b.allocator,
            b.graph.io,
            &target.result,
        )) |sdk| {
            const vail_module = vail_dep.module("vail");
            vail_module.addFrameworkPath(.{
                .cwd_relative = b.fmt(
                    "{s}/System/Library/Frameworks",
                    .{sdk},
                ),
            });
            vail_module.addLibraryPath(.{
                .cwd_relative = b.fmt("{s}/usr/lib", .{sdk}),
            });
            vail_module.addSystemIncludePath(.{
                .cwd_relative = b.fmt("{s}/usr/include", .{sdk}),
            });
        }
    }
    const vort_dep = b.dependency("vort", .{
        .target = target,
        .optimize = optimize,
    });
    const scheduling = b.option(
        []const u8,
        "scheduling",
        "zio scheduling discipline: single_executor, pinned, or work_stealing",
    );
    const zio_backend = b.option(
        []const u8,
        "zio-backend",
        "zio event loop backend: poll, linux, epoll, kqueue, io_uring, or iocp",
    );
    const zio_dep = b.dependency("zio", .{
        .target = target,
        .optimize = optimize,
        .scheduling = scheduling orelse "work_stealing",
        .backend = zio_backend,
    });
    const harnessz_dep = b.dependency("harnessz", .{
        .target = target,
        .optimize = optimize,
    });
    const kron_dep = b.dependency("kron", .{
        .target = target,
        .optimize = optimize,
    });
    const regexz_dep = b.dependency("regexz", .{
        .target = target,
        .optimize = optimize,
    });
    const webpkiz_dep = b.dependency("webpkiz", .{
        .target = target,
        .optimize = optimize,
    });

    const netz_mod = b.addModule("netz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "vail", .module = vail_dep.module("vail") },
            .{ .name = "vort", .module = vort_dep.module("vort") },
            .{ .name = "zio", .module = zio_dep.module("zio") },
            .{ .name = "kron", .module = kron_dep.module("kron") },
            .{ .name = "regexz", .module = regexz_dep.module("regexz") },
            .{ .name = "webpkiz", .module = webpkiz_dep.module("webpkiz") },
        },
    });
    const benchmark_counting_allocator_mod = b.createModule(.{
        .root_source_file = b.path("examples/support/counting_allocator.zig"),
        .target = target,
        .optimize = optimize,
    });
    const examples_support_mod = b.createModule(.{
        .root_source_file = b.path("examples/support/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "netz", .module = netz_mod },
            .{ .name = "harnessz", .module = harnessz_dep.module("harnessz") },
        },
    });

    const lib = b.addLibrary(.{
        .name = "netz",
        .root_module = netz_mod,
    });
    b.installArtifact(lib);

    const lib_tests = b.addTest(.{
        .root_module = netz_mod,
        .filters = test_filters,
    });
    const run_lib_tests = @import("build/testing/run.zig").add(b, lib_tests, test_progress);
    const test_lib_step = b.step(
        "test-lib",
        "Compile and run the Netz library unit tests",
    );
    test_lib_step.dependOn(&run_lib_tests.step);
    focused_tests.add(b, target, optimize, netz_mod, test_filters, test_progress);

    const package_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/package_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_package_tests = @import("build/testing/run.zig").add(b, package_tests, test_progress);
    const test_package_step = b.step(
        "test-package",
        "Compile and test the public Netz package surface",
    );
    test_package_step.dependOn(&run_package_tests.step);
    const test_compile_step = b.step(
        "test-compile",
        "Compile library and public-package tests without running them",
    );
    test_compile_step.dependOn(&lib_tests.step);
    test_compile_step.dependOn(&package_tests.step);
    const test_step = b.step("test", "Run all tests");
    fuzz.addAll(b, target, optimize, netz_mod, test_step);
    const quic_endpoint_soak_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/quic_endpoint_soak_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_endpoint_soak_tests = b.addRunArtifact(
        quic_endpoint_soak_tests,
    );
    const test_quic_endpoint_soak_step = b.step(
        "test-quic-endpoint-soak",
        "Soak authenticated QUIC endpoint connection reclamation",
    );
    test_quic_endpoint_soak_step.dependOn(
        &run_quic_endpoint_soak_tests.step,
    );
    const quic_handshake_bench_tests = b.addTest(.{
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
        .filters = test_filters,
    });
    const run_quic_handshake_bench_tests = b.addRunArtifact(
        quic_handshake_bench_tests,
    );
    const quic_persistent_bench_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_persistent_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_quic_persistent_bench_tests = b.addRunArtifact(
        quic_persistent_bench_tests,
    );
    const quic_persistent_bench_test_step = b.step(
        "test-quic-persistent-bench",
        "Test persistent QUIC benchmark payload and config helpers",
    );
    quic_persistent_bench_test_step.dependOn(
        &run_quic_persistent_bench_tests.step,
    );
    const quic_datagram_bench_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_datagram_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_quic_datagram_bench_tests = b.addRunArtifact(
        quic_datagram_bench_tests,
    );
    const quic_quic_go_churn_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_quic_go_churn.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_quic_quic_go_churn_tests = b.addRunArtifact(
        quic_quic_go_churn_tests,
    );
    const http3_quic_go_bench_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_quic_go_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_http3_quic_go_bench_tests = b.addRunArtifact(
        http3_quic_go_bench_tests,
    );
    const websocket_h3_quic_go_bench_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_websocket_h3_quic_go_bench_tests = b.addRunArtifact(
        websocket_h3_quic_go_bench_tests,
    );
    const exact_certificate_verifier_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/exact_certificate_verifier.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_exact_certificate_verifier_tests = b.addRunArtifact(
        exact_certificate_verifier_tests,
    );
    const websocket_send_shape_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/websocket_send_shape.zig",
            ),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    const run_websocket_send_shape_tests = b.addRunArtifact(
        websocket_send_shape_tests,
    );
    const mqtt_memory_limiter_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/memory_limiter.zig",
            ),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    const run_mqtt_memory_limiter_tests = b.addRunArtifact(
        mqtt_memory_limiter_tests,
    );
    const mqtt_memory_limiter_step = b.step(
        "test-mqtt-memory-limiter",
        "Test the MQTT broker hard heap-allocation limit",
    );
    mqtt_memory_limiter_step.dependOn(
        &run_mqtt_memory_limiter_tests.step,
    );
    const mqtt_pid_file_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/mqtt_pid_file.zig",
            ),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    mqtt_pid_file_tests.root_module.link_libc = true;
    const run_mqtt_pid_file_tests = b.addRunArtifact(mqtt_pid_file_tests);
    const mqtt_pid_file_step = b.step(
        "test-mqtt-pid-file",
        "Test configured MQTT broker PID-file ownership",
    );
    mqtt_pid_file_step.dependOn(&run_mqtt_pid_file_tests.step);
    const mqtt_reloadable_security_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/mqtt_reloadable_security.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_mqtt_reloadable_security_tests = b.addRunArtifact(
        mqtt_reloadable_security_tests,
    );
    const mqtt_reloadable_security_step = b.step(
        "test-mqtt-reloadable-security",
        "Test atomic MQTT password, ACL, and CRL file reloads",
    );
    mqtt_reloadable_security_step.dependOn(
        &run_mqtt_reloadable_security_tests.step,
    );
    const mqtt_reload_compatibility_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/mqtt_reload_compatibility.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_mqtt_reload_compatibility_tests = b.addRunArtifact(
        mqtt_reload_compatibility_tests,
    );
    const mqtt_reload_compatibility_step = b.step(
        "test-mqtt-reload-compatibility",
        "Test exhaustive MQTT SIGHUP field classification",
    );
    mqtt_reload_compatibility_step.dependOn(
        &run_mqtt_reload_compatibility_tests.step,
    );
    const mqtt_reloadable_identity_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/mqtt_reloadable_identity.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_mqtt_reloadable_identity_tests = b.addRunArtifact(
        mqtt_reloadable_identity_tests,
    );
    const mqtt_reloadable_identity_step = b.step(
        "test-mqtt-reloadable-identity",
        "Test atomic MQTT TLS identity, key password, client CA, and CRL reloads",
    );
    mqtt_reloadable_identity_step.dependOn(
        &run_mqtt_reloadable_identity_tests.step,
    );
    const mqtt_configured_bridges_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "examples/support/mqtt_configured_bridges.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_mqtt_configured_bridges_tests = b.addRunArtifact(
        mqtt_configured_bridges_tests,
    );
    const mqtt_configured_bridges_step = b.step(
        "test-mqtt-configured-bridges",
        "Test production MQTT bridge configuration adapters",
    );
    mqtt_configured_bridges_step.dependOn(
        &run_mqtt_configured_bridges_tests.step,
    );
    const webtransport_wtransport_bench_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/webtransport_wtransport_bench.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_webtransport_wtransport_bench_tests = b.addRunArtifact(
        webtransport_wtransport_bench_tests,
    );
    const webtransport_browser_reset_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/webtransport_browser_reset.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_webtransport_browser_reset_tests = b.addRunArtifact(
        webtransport_browser_reset_tests,
    );
    const webtransport_churn_protocol_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/webtransport_churn_protocol.zig",
            ),
            .target = target,
            .optimize = optimize,
        }),
        .filters = test_filters,
    });
    const run_webtransport_churn_protocol_tests = b.addRunArtifact(
        webtransport_churn_protocol_tests,
    );
    const websocket_slices_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_slices_benchmark_check_test.py",
    });
    const websocket_autobahn_report_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_autobahn_report_check_test.py",
    });
    const websocket_autobahn_package_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_autobahn_package_check_test.py",
    });
    const quic_quic_go_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/quic_quic_go_benchmark_check_test.py",
    });
    const quic_quic_go_auxiliary_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/quic_quic_go_auxiliary_check_test.py",
    });
    const quic_quic_go_churn_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/quic_quic_go_churn_check_test.py",
    });
    const quic_handshake_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/quic_handshake_benchmark_check_test.py",
    });
    const quic_quinn_handshake_benchmark_checker_tests = b.addSystemCommand(
        &.{
            "python3",
            "tools/interop/quic_quinn/handshake_benchmark_check_test.py",
        },
    );
    const http3_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http3_benchmark_check_test.py",
    });
    const http3_socket_traffic_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http3_socket_traffic_check_test.py",
    });
    const http3_packet_capture_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http3_packet_capture_test.py",
    });
    const http3_packet_capture_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http3_packet_capture_check_test.py",
    });
    const http3_packet_capture_compare_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http3_packet_capture_compare_test.py",
    });
    const websocket_h3_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_h3_benchmark_check_test.py",
    });
    const websocket_h2_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_h2_benchmark_check_test.py",
    });
    const websocket_mostly_idle_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_mostly_idle_benchmark_check_test.py",
    });
    const http2_cancel_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http2_cancel_benchmark_check_test.py",
    });
    const grpc_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/grpc_benchmark_check_test.py",
    });
    const grpc_benchmark_checker_step = b.step("test-grpc-benchmark-checker", "Verify shared gRPC benchmark completion and timing records");
    grpc_benchmark_checker_step.dependOn(&grpc_benchmark_checker_tests.step);
    const http1_hyper_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http1_hyper_benchmark_check_test.py",
    });
    const mqtt_broker_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_benchmark_check_test.py",
    });
    const mqtt_broker_benchmark_config_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_benchmark_config_test.py",
    });
    const mqtt_broker_matrix_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_matrix_check_test.py",
    });
    const mqtt_broker_allocator_matrix_checker_tests = b.addSystemCommand(
        &.{
            "python3",
            "tools/interop/mqtt_broker_allocator_matrix_check_test.py",
        },
    );
    const mqtt_packet_sequence_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_mosquitto_packet_sequences_test.py",
    });
    const mqtt_vector_source_lock_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_vectors/source_lock_test.py",
    });
    const mqtt_commit_log_support_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_commit_log_support_test.py",
    });
    const mqtt_outbound_bridge_support_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_outbound_bridge_support_test.py",
    });
    const mqtt_broker_config_support_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config_support_test.py",
    });
    const webtransport_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/webtransport_benchmark_check_test.py",
    });
    const webtransport_churn_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/webtransport_churn_check_test.py",
    });
    const quic_datagram_benchmark_checker_tests = b.addSystemCommand(&.{
        "python3",
        "tools/interop/quic_datagram_benchmark_check_test.py",
    });
    const source_archive_tests = b.addSystemCommand(&.{"python3"});
    source_archive_tests.addFileArg(b.path(
        "tools/release/source_archive_test.py",
    ));
    source_archive_tests.addFileInput(b.path(
        "tools/release/source_archive.py",
    ));
    source_archive_tests.addFileInput(b.path(
        "tools/release/archive_checksum.py",
    ));
    source_archive_tests.addFileInput(b.path("build.zig.zon"));
    source_archive_tests.addFileInput(b.path(
        ".github/workflows/ci.yml",
    ));
    source_archive_tests.addFileInput(b.path(
        ".github/workflows/release.yml",
    ));
    const release_tag_tests = b.addSystemCommand(&.{
        "python3",
        "tools/release/validate_tag_test.py",
    });
    release_tag_tests.addFileInput(b.path(
        "tools/release/validate_tag.py",
    ));

    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_package_tests.step);
    test_step.dependOn(&run_quic_endpoint_soak_tests.step);
    test_step.dependOn(&run_quic_handshake_bench_tests.step);
    test_step.dependOn(&run_quic_persistent_bench_tests.step);
    test_step.dependOn(&run_quic_quic_go_churn_tests.step);
    test_step.dependOn(&run_http3_quic_go_bench_tests.step);
    test_step.dependOn(&run_websocket_h3_quic_go_bench_tests.step);
    test_step.dependOn(&run_exact_certificate_verifier_tests.step);
    test_step.dependOn(&run_websocket_send_shape_tests.step);
    test_step.dependOn(&run_mqtt_memory_limiter_tests.step);
    test_step.dependOn(&run_mqtt_pid_file_tests.step);
    test_step.dependOn(&run_mqtt_reloadable_security_tests.step);
    test_step.dependOn(&run_mqtt_reload_compatibility_tests.step);
    test_step.dependOn(&run_mqtt_reloadable_identity_tests.step);
    test_step.dependOn(&run_mqtt_configured_bridges_tests.step);
    test_step.dependOn(&run_webtransport_wtransport_bench_tests.step);
    test_step.dependOn(&run_webtransport_browser_reset_tests.step);
    test_step.dependOn(&run_webtransport_churn_protocol_tests.step);
    test_step.dependOn(&websocket_slices_benchmark_checker_tests.step);
    test_step.dependOn(&websocket_autobahn_report_checker_tests.step);
    test_step.dependOn(&websocket_autobahn_package_checker_tests.step);
    test_step.dependOn(&quic_quic_go_benchmark_checker_tests.step);
    test_step.dependOn(&quic_quic_go_auxiliary_checker_tests.step);
    test_step.dependOn(&quic_quic_go_churn_checker_tests.step);
    test_step.dependOn(&quic_handshake_benchmark_checker_tests.step);
    test_step.dependOn(
        &quic_quinn_handshake_benchmark_checker_tests.step,
    );
    test_step.dependOn(&http3_benchmark_checker_tests.step);
    test_step.dependOn(&http3_socket_traffic_checker_tests.step);
    test_step.dependOn(&http3_packet_capture_tests.step);
    test_step.dependOn(&http3_packet_capture_checker_tests.step);
    test_step.dependOn(&http3_packet_capture_compare_tests.step);
    test_step.dependOn(&websocket_h2_benchmark_checker_tests.step);
    test_step.dependOn(&websocket_mostly_idle_benchmark_checker_tests.step);
    test_step.dependOn(&http2_cancel_benchmark_checker_tests.step);
    test_step.dependOn(&grpc_benchmark_checker_tests.step);
    test_step.dependOn(&http1_hyper_benchmark_checker_tests.step);
    test_step.dependOn(&mqtt_broker_benchmark_checker_tests.step);
    test_step.dependOn(&mqtt_broker_benchmark_config_tests.step);
    test_step.dependOn(&mqtt_broker_matrix_checker_tests.step);
    test_step.dependOn(&mqtt_broker_allocator_matrix_checker_tests.step);
    test_step.dependOn(&mqtt_packet_sequence_tests.step);
    test_step.dependOn(&mqtt_vector_source_lock_tests.step);
    test_step.dependOn(&mqtt_commit_log_support_tests.step);
    test_step.dependOn(&mqtt_outbound_bridge_support_tests.step);
    test_step.dependOn(&mqtt_broker_config_support_tests.step);
    test_step.dependOn(&websocket_h3_benchmark_checker_tests.step);
    test_step.dependOn(&webtransport_benchmark_checker_tests.step);
    test_step.dependOn(&webtransport_churn_checker_tests.step);
    test_step.dependOn(&quic_datagram_benchmark_checker_tests.step);
    test_step.dependOn(&source_archive_tests.step);
    test_step.dependOn(&release_tag_tests.step);
    test_step.dependOn(&run_quic_datagram_bench_tests.step);

    const interop_artifacts = interop.addAll(
        b,
        target,
        optimize,
        netz_mod,
        test_step,
    );
    const mqtt_vectors_broker = interop_artifacts.mqtt_vectors_broker;
    const mqtt_websocket_server = interop_artifacts.mqtt_websocket_server;

    mqtt.addBrokerSteps(
        b,
        test_step,
        mqtt_vectors_broker,
        mqtt_websocket_server,
    );

    websocket.addInterop(
        b,
        target,
        optimize,
        netz_mod,
        test_step,
    );

    grpc.addInterop(
        b,
        target,
        optimize,
        netz_mod,
        regexz_dep.module("regexz"),
        test_step,
    );

    http.addInterop(
        b,
        target,
        optimize,
        netz_mod,
    );

    grpc_cpp.addInterop(
        b,
        target,
        optimize,
        netz_mod,
        vail_dep,
        vort_dep,
        zio_dep,
        regexz_dep,
        webpkiz_dep,
        kron_dep,
        harnessz_dep,
    );
    protocols.addInterop(
        b,
        target,
        optimize,
        netz_mod,
        test_step,
        benchmark_counting_allocator_mod,
    );

    quic.addInterop(
        b,
        target,
        optimize,
        netz_mod,
        benchmark_counting_allocator_mod,
        vail_dep,
    );
    webtransport.addInterop(
        b,
        target,
        optimize,
        netz_mod,
        test_step,
        benchmark_counting_allocator_mod,
    );
    const example_specs = examples.specs;
    const examples_step = b.step("examples", "Build all examples");
    const h3_multipath_probe = b.addExecutable(.{
        .name = "netz-h3-multipath-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/h3_multipath_probe.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const h3_multipath_probe_install = b.addInstallArtifact(
        h3_multipath_probe,
        .{},
    );
    const h3_multipath_probe_step = b.step(
        "h3-multipath-probe",
        "Build the cross-host HTTP/3 multipath serve/probe tool",
    );
    h3_multipath_probe_step.dependOn(&h3_multipath_probe_install.step);
    const bench_step = b.step("bench", "Run all native protocol benchmarks");
    var http1_pipeline_bench_exe: ?*std.Build.Step.Compile = null;
    var http1_body_bench_exe: ?*std.Build.Step.Compile = null;
    var grpc_shared_bench_exe: ?*std.Build.Step.Compile = null;
    var http1_parse_bench_exe: ?*std.Build.Step.Compile = null;
    var quic_padding_parse_bench_exe: ?*std.Build.Step.Compile = null;
    var http3_capsule_bench_exe: ?*std.Build.Step.Compile = null;
    var http2_hpack_bench_exe: ?*std.Build.Step.Compile = null;
    var http3_qpack_bench_exe: ?*std.Build.Step.Compile = null;
    var http_content_coding_bench_exe: ?*std.Build.Step.Compile = null;
    var mqtt_retained_bench_exe: ?*std.Build.Step.Compile = null;
    var mqtt_router_match_bench_exe: ?*std.Build.Step.Compile = null;
    for (example_specs) |spec| {
        const exe = b.addExecutable(.{
            .name = spec.exe_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(spec.path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "netz", .module = netz_mod },
                    .{ .name = "harnessz", .module = harnessz_dep.module("harnessz") },
                    .{ .name = "kron", .module = kron_dep.module("kron") },
                    .{ .name = "support", .module = examples_support_mod },
                },
            }),
        });
        if (std.mem.eql(u8, spec.run_step, "bench-http1-pipeline")) {
            http1_pipeline_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http1-body")) {
            http1_body_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-grpc-shared")) {
            grpc_shared_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http1-parse")) {
            http1_parse_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-quic-padding-parse")) {
            quic_padding_parse_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http3-capsule")) {
            http3_capsule_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http2-hpack")) {
            http2_hpack_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http3-qpack")) {
            http3_qpack_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http-content-coding")) {
            http_content_coding_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-mqtt-retained")) {
            mqtt_retained_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-mqtt-router-match")) {
            mqtt_router_match_bench_exe = exe;
        }
        examples_step.dependOn(&exe.step);

        const run = b.addRunArtifact(exe);
        if (b.args) |args| run.addArgs(args);
        const run_step = b.step(spec.run_step, spec.description);
        run_step.dependOn(&run.step);
        if (std.mem.startsWith(u8, spec.run_step, "bench-") and
            !std.mem.eql(
                u8,
                spec.run_step,
                "bench-webtransport-stream-batch",
            ))
        {
            bench_step.dependOn(&run.step);
        }
    }

    const bench_record_step = b.step(
        "bench-record",
        "Record harnessz baselines for sampler-backed microbenchmarks (use -Doptimize=ReleaseFast)",
    );
    const bench_gate_step = b.step(
        "bench-gate",
        "Gate sampler-backed microbenchmarks against recorded baselines (use -Doptimize=ReleaseFast)",
    );
    const baseline_benches = [_]struct {
        exe: *std.Build.Step.Compile,
        baseline: []const u8,
    }{
        .{
            .exe = http1_parse_bench_exe.?,
            .baseline = "benchmarks/baselines/http1-parse.json",
        },
        .{
            .exe = quic_padding_parse_bench_exe.?,
            .baseline = "benchmarks/baselines/quic-padding-parse.json",
        },
        .{
            .exe = http3_capsule_bench_exe.?,
            .baseline = "benchmarks/baselines/http3-capsule.json",
        },
        .{
            .exe = http2_hpack_bench_exe.?,
            .baseline = "benchmarks/baselines/http2-hpack.json",
        },
        .{
            .exe = http3_qpack_bench_exe.?,
            .baseline = "benchmarks/baselines/http3-qpack.json",
        },
        .{
            .exe = http_content_coding_bench_exe.?,
            .baseline = "benchmarks/baselines/http-content-coding.json",
        },
        .{
            .exe = mqtt_retained_bench_exe.?,
            .baseline = "benchmarks/baselines/mqtt-retained.json",
        },
        .{
            .exe = mqtt_router_match_bench_exe.?,
            .baseline = "benchmarks/baselines/mqtt-router.json",
        },
    };
    // Sampling steps run one at a time even when the build runner is parallel:
    // concurrent benchmarks compete for cores and memory bandwidth, which
    // turns a recording or gate run into host-noise evidence.
    var previous_record: ?*std.Build.Step = null;
    var previous_gate: ?*std.Build.Step = null;
    for (baseline_benches) |bench| {
        const record = b.addRunArtifact(bench.exe);
        record.addArgs(&.{
            b.fmt("--baseline={s}", .{bench.baseline}),
            "--update-baseline",
        });
        if (b.args) |args| record.addArgs(args);
        if (previous_record) |previous| record.step.dependOn(previous);
        bench_record_step.dependOn(&record.step);
        previous_record = &record.step;
        const gate = b.addRunArtifact(bench.exe);
        gate.addArg(b.fmt("--baseline={s}", .{bench.baseline}));
        if (b.args) |args| gate.addArgs(args);
        if (previous_gate) |previous| gate.step.dependOn(previous);
        bench_gate_step.dependOn(&gate.step);
        previous_gate = &gate.step;
    }

    const evidence_audit = b.addExecutable(.{
        .name = "netz-evidence-audit",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/evidence_audit.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "harnessz",
                .module = harnessz_dep.module("harnessz"),
            }},
        }),
    });
    const run_evidence_audit = b.addRunArtifact(evidence_audit);
    if (b.args) |args| run_evidence_audit.addArgs(args);
    const evidence_audit_step = b.step(
        "verify-evidence",
        "Audit docs/evidence source hashes (report-only unless --strict)",
    );
    evidence_audit_step.dependOn(&run_evidence_audit.step);

    const grpc_cpp_bench = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_benchmark.py" });
    grpc_cpp_bench.addArtifactArg(grpc_shared_bench_exe.?);
    grpc_cpp_bench.addArgs(&.{ "--netz-build-mode", @tagName(optimize) });
    if (b.args) |args| grpc_cpp_bench.addArgs(args);
    const grpc_cpp_bench_step = b.step("bench-grpc-cpp", "Compare shared gRPC with official grpc-cpp TCP ping-pong workloads");
    grpc_cpp_bench_step.dependOn(&grpc_cpp_bench.step);

    const http1_hyper_bench = b.addSystemCommand(&.{
        "tools/interop/http1_hyper_benchmark.sh",
    });
    http1_hyper_bench.addArtifactArg(http1_pipeline_bench_exe.?);
    http1_hyper_bench.addArtifactArg(http1_body_bench_exe.?);
    http1_hyper_bench.addArg(@tagName(optimize));
    if (b.args) |args| http1_hyper_bench.addArgs(args);
    const http1_hyper_bench_step = b.step(
        "bench-http1-hyper",
        "Compare zio-backed HTTP/1 pipeline and body workloads with Hyper",
    );
    http1_hyper_bench_step.dependOn(&http1_hyper_bench.step);

    const http2_cancel_bench_client = b.addExecutable(.{
        .name = "netz-http2-cancel-bench-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_cancel_bench_client.zig",
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
    const http2_cancel_bench = b.addSystemCommand(&.{
        "tools/interop/http2_cancel_benchmark.sh",
    });
    http2_cancel_bench.addArtifactArg(http2_cancel_bench_client);
    http2_cancel_bench.addArg(@tagName(optimize));
    if (b.args) |args| http2_cancel_bench.addArgs(args);
    const http2_cancel_bench_step = b.step(
        "bench-http2-cancel-hyper",
        "Compare HTTP/2 cancellation recovery against Hyper",
    );
    http2_cancel_bench_step.dependOn(&http2_cancel_bench.step);

    const http3_public_fetch = b.addExecutable(.{
        .name = "netz-http3-public-fetch",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http/http3_fetch.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_public = b.addSystemCommand(&.{
        "sh",
        "tools/interop/http3_public.sh",
    });
    http3_public.addArtifactArg(http3_public_fetch);
    const http3_public_step = b.step(
        "interop-http3-public",
        "Verify public HTTP/3 endpoints with system trust",
    );
    http3_public_step.dependOn(&http3_public.step);

    const websocket_slices_h1 = b.addExecutable(.{
        .name = "netz-websocket-slices-h1",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/benchmarks/bench_websocket_echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{ .name = "support", .module = examples_support_mod },
            },
        }),
    });
    const websocket_slices_h2 = b.addExecutable(.{
        .name = "netz-websocket-slices-h2",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/benchmarks/bench_websocket_h2_echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{ .name = "support", .module = examples_support_mod },
            },
        }),
    });
    const websocket_slices_h3 = b.addExecutable(.{
        .name = "netz-websocket-slices-h3",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/benchmarks/bench_websocket_h3_echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{ .name = "support", .module = examples_support_mod },
            },
        }),
    });
    const websocket_slices_ab = b.addSystemCommand(&.{
        "tools/interop/websocket_slices_ab.sh",
    });
    websocket_slices_ab.addArtifactArg(websocket_slices_h1);
    websocket_slices_ab.addArtifactArg(websocket_slices_h2);
    websocket_slices_ab.addArtifactArg(websocket_slices_h3);
    const websocket_slices_ab_step = b.step(
        "bench-websocket-slices-ab",
        "Compare caller-joined and direct-slice WebSocket sends over H1/H2/H3",
    );
    websocket_slices_ab_step.dependOn(&websocket_slices_ab.step);

    const websocket_mostly_idle = b.addSystemCommand(&.{
        "tools/interop/websocket_mostly_idle_benchmark.sh",
    });
    websocket_mostly_idle.addArtifactArg(websocket_slices_h1);
    websocket_mostly_idle.addArg(@tagName(optimize));
    if (b.args) |args| websocket_mostly_idle.addArgs(args);
    const websocket_mostly_idle_step = b.step(
        "bench-websocket-mostly-idle",
        "Compare mostly-idle WebSocket memory with pinned websocket.zig",
    );
    websocket_mostly_idle_step.dependOn(&websocket_mostly_idle.step);
}

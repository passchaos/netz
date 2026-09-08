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
    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Run only tests whose name contains one of these substrings",
    ) orelse &.{};
    const vail_dep = b.dependency("vail", .{
        .target = target,
        .optimize = optimize,
    });
    const vort_dep = b.dependency("vort", .{
        .target = target,
        .optimize = optimize,
    });
    const zio_dep = b.dependency("zio", .{
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
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const package_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/package_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
        .filters = test_filters,
    });
    const run_package_tests = b.addRunArtifact(package_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_package_tests.step);

    const mqtt_mtls_server = b.addExecutable(.{
        .name = "netz-mqtt-mtls-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/mqtt_mtls_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_mtls_openssl = b.addSystemCommand(
        &.{"tools/interop/mqtt_mtls_openssl.sh"},
    );
    mqtt_mtls_openssl.addArtifactArg(mqtt_mtls_server);
    const mqtt_mtls_interop_step = b.step(
        "interop-mqtt-mtls-openssl",
        "Exercise required and optional MQTT mTLS with OpenSSL",
    );
    mqtt_mtls_interop_step.dependOn(&mqtt_mtls_openssl.step);

    const mqtt_vectors_broker = b.addExecutable(.{
        .name = "netz-mqtt-vector-broker",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/mqtt_broker.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_vectors = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_mosquitto_vectors.py",
    });
    mqtt_vectors.addArtifactArg(mqtt_vectors_broker);
    const mqtt_vectors_step = b.step(
        "interop-mqtt-mosquitto-vectors",
        "Run selected Mosquitto MQTT 5 wire vectors against netz",
    );
    mqtt_vectors_step.dependOn(&mqtt_vectors.step);

    const mqtt_live_autosave = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_live_autosave.py",
    });
    mqtt_live_autosave.addArtifactArg(mqtt_vectors_broker);
    const mqtt_live_autosave_step = b.step(
        "interop-mqtt-live-autosave",
        "Verify periodic MQTT checkpoints survive a broker crash",
    );
    mqtt_live_autosave_step.dependOn(&mqtt_live_autosave.step);

    const mqtt_broker_bench = b.addExecutable(.{
        .name = "netz-bench-mqtt-broker-compare",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/bench_mqtt_broker.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_broker_compare = b.addSystemCommand(&.{
        "tools/compare_mqtt_mosquitto.sh",
    });
    mqtt_broker_compare.addArtifactArg(mqtt_vectors_broker);
    mqtt_broker_compare.addArtifactArg(mqtt_broker_bench);
    const mqtt_broker_compare_step = b.step(
        "compare-mqtt-mosquitto",
        "Run an equal-wire MQTT QoS1 comparison against local Mosquitto",
    );
    mqtt_broker_compare_step.dependOn(&mqtt_broker_compare.step);

    const mqtt_commit_log = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_commit_log.py",
    });
    mqtt_commit_log.addArtifactArg(mqtt_vectors_broker);
    const mqtt_commit_log_step = b.step(
        "interop-mqtt-commit-log",
        "Verify MQTT per-transaction journal recovery after SIGKILL",
    );
    mqtt_commit_log_step.dependOn(&mqtt_commit_log.step);

    const mqtt_websocket_server = b.addExecutable(.{
        .name = "netz-mqtt-websocket-interop-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/mqtt_websocket_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_websocket_mosquitto = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_websocket_mosquitto.py",
    });
    mqtt_websocket_mosquitto.addArtifactArg(mqtt_websocket_server);
    const mqtt_websocket_mosquitto_step = b.step(
        "interop-mqtt-websocket-mosquitto",
        "Run Mosquitto-derived MQTT WS/WSS peers against netz",
    );
    mqtt_websocket_mosquitto_step.dependOn(
        &mqtt_websocket_mosquitto.step,
    );

    const mqtt_mount_server = b.addExecutable(.{
        .name = "netz-mqtt-mount-interop-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/mqtt_mount_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_listener_mount = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_listener_mount_mosquitto.py",
    });
    mqtt_listener_mount.addArtifactArg(mqtt_mount_server);
    const mqtt_listener_mount_step = b.step(
        "interop-mqtt-listener-mount-mosquitto",
        "Run Mosquitto-derived MQTT listener mount-point vectors",
    );
    mqtt_listener_mount_step.dependOn(&mqtt_listener_mount.step);

    const mqtt_websocket_origin = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_websocket_origin.py",
    });
    mqtt_websocket_origin.addArtifactArg(mqtt_websocket_server);
    const mqtt_websocket_origin_step = b.step(
        "interop-mqtt-websocket-origin",
        "Run Mosquitto-derived MQTT WebSocket Origin policy checks",
    );
    mqtt_websocket_origin_step.dependOn(&mqtt_websocket_origin.step);

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

    const h2spec_server = b.addExecutable(.{
        .name = "netz-h2spec-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_h2spec_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const h2spec = b.addSystemCommand(&.{
        "tools/interop/http2_h2spec.sh",
    });
    h2spec.addArtifactArg(h2spec_server);
    if (b.args) |args| h2spec.addArgs(args);
    const h2spec_step = b.step(
        "interop-http2-h2spec",
        "Run strict external h2spec against netz h2c (pass --tls for ALPN/TLS)",
    );
    h2spec_step.dependOn(&h2spec.step);

    const http2_hyper_client = b.addExecutable(.{
        .name = "netz-http2-hyper-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_hyper_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_hyper_server = b.addExecutable(.{
        .name = "netz-http2-hyper-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_hyper_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_hyper_interop = b.addSystemCommand(
        &.{"tools/interop/http2_hyper_client.sh"},
    );
    http2_hyper_interop.addArtifactArg(http2_hyper_client);
    http2_hyper_interop.addArtifactArg(http2_hyper_server);
    const http2_hyper_interop_step = b.step(
        "interop-http2-hyper-client",
        "Run bidirectional netz HTTP/2 interop with audited Hyper fixtures",
    );
    http2_hyper_interop_step.dependOn(&http2_hyper_interop.step);

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
    const grpc_cpp_interop = b.addSystemCommand(
        &.{"tools/interop/grpc_cpp.sh"},
    );
    grpc_cpp_interop.addArtifactArg(grpc_cpp_client);
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

    const http2_h2_push_client = b.addExecutable(.{
        .name = "netz-http2-h2-push-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_h2_push_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_h2_push_server = b.addExecutable(.{
        .name = "netz-http2-h2-push-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_h2_push_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_h2_push = b.addSystemCommand(
        &.{"tools/interop/http2_h2_push.sh"},
    );
    http2_h2_push.addArtifactArg(http2_h2_push_client);
    http2_h2_push.addArtifactArg(http2_h2_push_server);
    const http2_h2_push_step = b.step(
        "interop-http2-h2-push",
        "Run HTTP/2 push and informational interop with audited h2",
    );
    http2_h2_push_step.dependOn(&http2_h2_push.step);

    const http3_quic_go_client = b.addExecutable(.{
        .name = "netz-http3-quic-go-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_quic_go_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_quic_go_server = b.addExecutable(.{
        .name = "netz-http3-quic-go-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_quic_go_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_quic_go = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go.sh"},
    );
    http3_quic_go.addArtifactArg(http3_quic_go_client);
    http3_quic_go.addArtifactArg(http3_quic_go_server);
    const http3_quic_go_step = b.step(
        "interop-http3-quic-go",
        "Run bidirectional HTTP/3 body, trailer, cancellation, and informational interop with quic-go",
    );
    http3_quic_go_step.dependOn(&http3_quic_go.step);
    const http3_quic_go_bench = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go.sh"},
    );
    http3_quic_go_bench.addArtifactArg(http3_quic_go_client);
    http3_quic_go_bench.addArtifactArg(http3_quic_go_server);
    http3_quic_go_bench.addArg("--bench");
    if (b.args) |args| http3_quic_go_bench.addArgs(args);
    const http3_quic_go_bench_step = b.step(
        "bench-http3-quic-go",
        "Compare verified HTTP/3 upload and download against quic-go",
    );
    http3_quic_go_bench_step.dependOn(&http3_quic_go_bench.step);

    const websocket_h3_quic_go_client = b.addExecutable(.{
        .name = "netz-websocket-h3-quic-go-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_h3_quic_go_server = b.addExecutable(.{
        .name = "netz-websocket-h3-quic-go-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_h3_quic_go = b.addSystemCommand(
        &.{"tools/interop/websocket_h3_quic_go.sh"},
    );
    websocket_h3_quic_go.addArtifactArg(websocket_h3_quic_go_client);
    websocket_h3_quic_go.addArtifactArg(websocket_h3_quic_go_server);
    const websocket_h3_quic_go_step = b.step(
        "interop-websocket-h3-quic-go",
        "Run bidirectional RFC 9220 interoperability with quic-go",
    );
    websocket_h3_quic_go_step.dependOn(&websocket_h3_quic_go.step);
    const websocket_h3_quic_go_bench = b.addSystemCommand(
        &.{"tools/interop/websocket_h3_quic_go.sh"},
    );
    websocket_h3_quic_go_bench.addArtifactArg(
        websocket_h3_quic_go_client,
    );
    websocket_h3_quic_go_bench.addArtifactArg(
        websocket_h3_quic_go_server,
    );
    websocket_h3_quic_go_bench.addArg("--bench");
    if (b.args) |args| websocket_h3_quic_go_bench.addArgs(args);
    const websocket_h3_quic_go_bench_step = b.step(
        "bench-websocket-h3-quic-go",
        "Compare persistent RFC 9220 echo against quic-go",
    );
    websocket_h3_quic_go_bench_step.dependOn(
        &websocket_h3_quic_go_bench.step,
    );

    const http3_tquic_client = b.addExecutable(.{
        .name = "netz-http3-tquic-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_tquic_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_tquic_server = b.addExecutable(.{
        .name = "netz-http3-tquic-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_tquic_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_tquic = b.addSystemCommand(
        &.{"tools/interop/http3_tquic.sh"},
    );
    http3_tquic.addArtifactArg(http3_tquic_client);
    http3_tquic.addArtifactArg(http3_tquic_server);
    const http3_tquic_step = b.step(
        "interop-http3-tquic",
        "Run bidirectional HTTP/3 interoperability with tquic",
    );
    http3_tquic_step.dependOn(&http3_tquic.step);

    const http3_qpack_peer = b.addExecutable(.{
        .name = "netz-http3-qpack-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_qpack_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_qpack_quic_zig = b.addSystemCommand(
        &.{"tools/interop/http3_qpack_quic_zig.sh"},
    );
    http3_qpack_quic_zig.addArtifactArg(http3_qpack_peer);
    const http3_qpack_quic_zig_step = b.step(
        "interop-http3-qpack-quic-zig",
        "Decode speculative netz QPACK with quic-zig",
    );
    http3_qpack_quic_zig_step.dependOn(
        &http3_qpack_quic_zig.step,
    );

    const websocket_hyper_h2_client = b.addExecutable(.{
        .name = "netz-websocket-hyper-h2-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_hyper_h2_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_hyper_h2 = b.addSystemCommand(
        &.{"tools/interop/websocket_hyper_h2.sh"},
    );
    websocket_hyper_h2.addArtifactArg(websocket_hyper_h2_client);
    const websocket_hyper_h2_step = b.step(
        "interop-websocket-hyper-h2",
        "Run netz RFC 8441 WebSocket interop with an audited Hyper server",
    );
    websocket_hyper_h2_step.dependOn(&websocket_hyper_h2.step);

    const http1_hyper_client = b.addExecutable(.{
        .name = "netz-http1-hyper-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http1_hyper_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http1_hyper_server = b.addExecutable(.{
        .name = "netz-http1-hyper-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http1_hyper_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http1_hyper_interop = b.addSystemCommand(
        &.{"tools/interop/http1_hyper.sh"},
    );
    http1_hyper_interop.addArtifactArg(http1_hyper_client);
    http1_hyper_interop.addArtifactArg(http1_hyper_server);
    const http1_hyper_interop_step = b.step(
        "interop-http1-hyper",
        "Run bidirectional HTTP/1 body, trailer, and Expect interop with Hyper",
    );
    http1_hyper_interop_step.dependOn(&http1_hyper_interop.step);

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
    const quic_quic_go_bench_client = b.addExecutable(.{
        .name = "netz-quic-quic-go-bench-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/quic_quic_go_bench_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
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
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
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

    const quic_s2n = b.addSystemCommand(
        &.{"tools/interop/quic_s2n.sh"},
    );
    quic_s2n.addArtifactArg(quic_peer_client);
    quic_s2n.addArtifactArg(quic_peer_server);
    const quic_s2n_step = b.step(
        "interop-quic-s2n",
        "Run verified QUIC stream, cancellation, and close interop with local s2n-quic",
    );
    quic_s2n_step.dependOn(&quic_s2n.step);

    const webtransport_wtransport_server = b.addExecutable(.{
        .name = "netz-webtransport-wtransport-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/webtransport_wtransport_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
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
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
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
                "examples/bench_webtransport_stream.zig",
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

    const example_specs = [_]struct {
        exe_name: []const u8,
        path: []const u8,
        run_step: []const u8,
        description: []const u8,
    }{
        .{
            .exe_name = "netz-http1-hello",
            .path = "examples/http1_hello.zig",
            .run_step = "run-http1-hello",
            .description = "Run the HTTP/1 local client/server example",
        },
        .{
            .exe_name = "netz-http2-h2c",
            .path = "examples/http2_h2c.zig",
            .run_step = "run-http2-h2c",
            .description = "Run the HTTP/2 h2c local client/server example",
        },
        .{
            .exe_name = "netz-grpc-h2c",
            .path = "examples/grpc_h2c.zig",
            .run_step = "run-grpc-h2c",
            .description = "Run a local gRPC unary call over HTTP/2 h2c",
        },
        .{
            .exe_name = "netz-http3-handshake",
            .path = "examples/http3_handshake.zig",
            .run_step = "run-http3-handshake",
            .description = "Run the local HTTP/3 client/server handshake example",
        },
        .{
            .exe_name = "netz-websocket-echo",
            .path = "examples/websocket_echo.zig",
            .run_step = "run-websocket-echo",
            .description = "Run the WebSocket local echo example",
        },
        .{
            .exe_name = "netz-bench-websocket-frame",
            .path = "examples/bench_websocket_frame.zig",
            .run_step = "bench-websocket-frame",
            .description = "Benchmark WebSocket caller-buffer and streaming frame encoding",
        },
        .{
            .exe_name = "netz-bench-websocket-receive-buffer",
            .path = "src/websocket/runtime/message/bench_buffer.zig",
            .run_step = "bench-websocket-receive-buffer",
            .description = "Benchmark eager versus amortized WebSocket receive-buffer consumption",
        },
        .{
            .exe_name = "netz-bench-websocket-echo",
            .path = "examples/bench_websocket_echo.zig",
            .run_step = "bench-websocket-echo",
            .description = "Benchmark persistent WebSocket 4 KiB binary echo",
        },
        .{
            .exe_name = "netz-bench-websocket-h2-echo",
            .path = "examples/bench_websocket_h2_echo.zig",
            .run_step = "bench-websocket-h2-echo",
            .description = "Benchmark RFC 8441 WebSocket 4 KiB binary echo",
        },
        .{
            .exe_name = "netz-bench-websocket-h3-echo",
            .path = "examples/bench_websocket_h3_echo.zig",
            .run_step = "bench-websocket-h3-echo",
            .description = "Benchmark RFC 9220 WebSocket 4 KiB binary echo",
        },
        .{
            .exe_name = "netz-bench-mqtt-router",
            .path = "examples/bench_mqtt_router.zig",
            .run_step = "bench-mqtt-router",
            .description = "Benchmark MQTT router trie matching against a linear scan",
        },
        .{
            .exe_name = "netz-mqtt-broker",
            .path = "examples/mqtt_broker.zig",
            .run_step = "run-mqtt-broker",
            .description = "Run the bounded MQTT 5 TCP broker",
        },
        .{
            .exe_name = "netz-bench-mqtt-broker",
            .path = "examples/bench_mqtt_broker.zig",
            .run_step = "bench-mqtt-broker",
            .description = "Run the external MQTT 5 TCP broker fanout workload",
        },
        .{
            .exe_name = "netz-bench-mqtt-websocket",
            .path = "examples/bench_mqtt_websocket.zig",
            .run_step = "bench-mqtt-websocket",
            .description = "Benchmark MQTT-over-WebSocket QoS 1 publish/PUBACK round trips",
        },
        .{
            .exe_name = "netz-bench-mqtt-tls",
            .path = "examples/bench_mqtt_tls.zig",
            .run_step = "bench-mqtt-tls",
            .description = "Benchmark MQTT-over-TLS QoS 1 publish/PUBACK round trips",
        },
        .{
            .exe_name = "netz-bench-mqtt-retained",
            .path = "examples/bench_mqtt_retained.zig",
            .run_step = "bench-mqtt-retained",
            .description = "Benchmark MQTT retained-message exact and wildcard lookup",
        },
        .{
            .exe_name = "netz-bench-mqtt-session",
            .path = "examples/bench_mqtt_session.zig",
            .run_step = "bench-mqtt-session",
            .description = "Benchmark MQTT persistent-session resume, queue and drain",
        },
        .{
            .exe_name = "netz-bench-mqtt-will",
            .path = "examples/bench_mqtt_will.zig",
            .run_step = "bench-mqtt-will",
            .description = "Benchmark MQTT Will Delay scheduling and polling",
        },
        .{
            .exe_name = "netz-bench-http1-parse",
            .path = "examples/bench_http1_parse.zig",
            .run_step = "bench-http1-parse",
            .description = "Benchmark HTTP/1 borrowed head parsing against owned parsing",
        },
        .{
            .exe_name = "netz-bench-http1-pipeline",
            .path = "examples/bench_http1_pipeline.zig",
            .run_step = "bench-http1-pipeline",
            .description = "Benchmark HTTP/1 persistent 16-request pipelines",
        },
        .{
            .exe_name = "netz-bench-http1-body",
            .path = "examples/bench_http1_body.zig",
            .run_step = "bench-http1-body",
            .description = "Benchmark HTTP/1 fixed or chunked streaming bodies",
        },
        .{
            .exe_name = "netz-bench-http2-hpack",
            .path = "examples/bench_http2_hpack.zig",
            .run_step = "bench-http2-hpack",
            .description = "Benchmark HTTP/2 HPACK stateful compression against stateless helpers",
        },
        .{
            .exe_name = "netz-bench-http2-h2c",
            .path = "examples/bench_http2_h2c.zig",
            .run_step = "bench-http2-h2c",
            .description = "Benchmark HTTP/2 h2c persistent request/response round trips",
        },
        .{
            .exe_name = "netz-bench-http2-flow",
            .path = "examples/bench_http2_flow.zig",
            .run_step = "bench-http2-flow",
            .description = "Benchmark flow-controlled parallel HTTP/2 responses",
        },
        .{
            .exe_name = "netz-bench-http3-dev",
            .path = "examples/bench_http3_dev.zig",
            .run_step = "bench-http3-dev",
            .description = "Benchmark HTTP/3 cleartext development request/response round trips",
        },
        .{
            .exe_name = "netz-bench-http3-handshake-transfer",
            .path = "examples/bench_http3_handshake_transfer.zig",
            .run_step = "bench-http3-handshake-transfer",
            .description = "Benchmark HTTP/3 real-handshake paced transfer throughput",
        },
        .{
            .exe_name = "netz-http3-fetch",
            .path = "examples/http3_fetch.zig",
            .run_step = "run-http3-fetch",
            .description = "Fetch the default public endpoint over HTTP/3",
        },
        .{
            .exe_name = "netz-quic-echo",
            .path = "examples/quic_echo.zig",
            .run_step = "run-quic-echo",
            .description = "Run a local preconfigured-key QUIC echo smoke test",
        },
        .{
            .exe_name = "netz-quic-handshake-echo",
            .path = "examples/quic_handshake_echo.zig",
            .run_step = "run-quic-handshake-echo",
            .description = "Run a local real-handshake QUIC STREAM echo smoke test",
        },
        .{
            .exe_name = "netz-quic-datagram-echo",
            .path = "examples/quic_datagram_echo.zig",
            .run_step = "run-quic-datagram-echo",
            .description = "Run a local QUIC DATAGRAM echo smoke test",
        },
        .{
            .exe_name = "netz-bench-quic-datagram",
            .path = "examples/bench_quic_datagram.zig",
            .run_step = "bench-quic-datagram",
            .description = "Benchmark raw QUIC DATAGRAM throughput",
        },
        .{
            .exe_name = "netz-bench-quic-handshake-stream",
            .path = "examples/bench_quic_handshake_stream.zig",
            .run_step = "bench-quic-handshake-stream",
            .description = "Benchmark real-handshake raw QUIC STREAM throughput",
        },
        .{
            .exe_name = "netz-bench-quic-stream-ids",
            .path = "examples/bench_quic_stream_ids.zig",
            .run_step = "bench-quic-stream-ids",
            .description = "Benchmark active QUIC receive-stream ID enumeration",
        },
        .{
            .exe_name = "netz-quic-close",
            .path = "examples/quic_close.zig",
            .run_step = "run-quic-close",
            .description = "Run a local QUIC application-close smoke test",
        },
        .{
            .exe_name = "netz-bench-http3-capsule",
            .path = "examples/bench_http3_capsule.zig",
            .run_step = "bench-http3-capsule",
            .description = "Benchmark HTTP/3 Capsule Protocol parsing and caller-buffer encoding",
        },
        .{
            .exe_name = "netz-bench-http3-qpack",
            .path = "examples/bench_http3_qpack.zig",
            .run_step = "bench-http3-qpack",
            .description = "Benchmark HTTP/3 QPACK dynamic field-section encoding",
        },
        .{
            .exe_name = "netz-bench-webtransport-datagram",
            .path = "examples/bench_webtransport_datagram.zig",
            .run_step = "bench-webtransport-datagram",
            .description = "Benchmark WebTransport datagram round trips over HTTP/3",
        },
        .{
            .exe_name = "netz-bench-webtransport-stream",
            .path = "examples/bench_webtransport_stream.zig",
            .run_step = "bench-webtransport-stream",
            .description = "Benchmark incremental WebTransport stream transfer",
        },
        .{
            .exe_name = "netz-webtransport-handshake-stream",
            .path = "examples/webtransport_handshake_stream.zig",
            .run_step = "run-webtransport-handshake-stream",
            .description = "Run real-handshake WebTransport bidi/uni stream echo",
        },
        .{
            .exe_name = "netz-bench-quic-short-packet",
            .path = "examples/bench_quic_short_packet.zig",
            .run_step = "bench-quic-short-packet",
            .description = "Benchmark QUIC short packet in-place sealing against allocating sealing",
        },
        .{
            .exe_name = "netz-bench-quic-padding-parse",
            .path = "examples/bench_quic_padding_parse.zig",
            .run_step = "bench-quic-padding-parse",
            .description = "Benchmark long QUIC PADDING frame parsing",
        },
        .{
            .exe_name = "netz-bench-quic-lb",
            .path = "examples/bench_quic_lb.zig",
            .run_step = "bench-quic-lb",
            .description = "Benchmark draft-21 QUIC-LB encrypted server routing",
        },
        .{
            .exe_name = "netz-bench-quic-udp-batch",
            .path = "examples/bench_quic_udp_batch.zig",
            .run_step = "bench-quic-udp-batch",
            .description = "Benchmark QUIC UDP_SEGMENT batches against sendmmsg",
        },
        .{
            .exe_name = "netz-bench-quic-one-rtt-send",
            .path = "examples/bench_quic_one_rtt_send.zig",
            .run_step = "bench-quic-one-rtt-send",
            .description = "Benchmark QUIC 1-RTT batched protection and send",
        },
        .{
            .exe_name = "netz-bench-quic-one-rtt-receive",
            .path = "examples/bench_quic_one_rtt_receive.zig",
            .run_step = "bench-quic-one-rtt-receive",
            .description = "Benchmark QUIC 1-RTT UDP_GRO batch receive",
        },
        .{
            .exe_name = "netz-bench-quic-ack-ranges",
            .path = "examples/bench_quic_ack_ranges.zig",
            .run_step = "bench-quic-ack-ranges",
            .description = "Benchmark QUIC ACK range generation with caller storage",
        },
        .{
            .exe_name = "netz-bench-quic-stream-window",
            .path = "examples/bench_quic_stream_window.zig",
            .run_step = "bench-quic-stream-window",
            .description = "Benchmark bounded QUIC receive stream compaction",
        },
        .{
            .exe_name = "netz-bench-quic-ticket-keyring",
            .path = "examples/bench_quic_ticket_keyring.zig",
            .run_step = "bench-quic-ticket-keyring",
            .description = "Benchmark stateless QUIC session ticket seal/open",
        },
    };
    const examples_step = b.step("examples", "Build all examples");
    const bench_step = b.step("bench", "Run all native protocol benchmarks");
    for (example_specs) |spec| {
        const exe = b.addExecutable(.{
            .name = spec.exe_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(spec.path),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "netz", .module = netz_mod }},
            }),
        });
        examples_step.dependOn(&exe.step);

        const run = b.addRunArtifact(exe);
        if (b.args) |args| run.addArgs(args);
        const run_step = b.step(spec.run_step, spec.description);
        run_step.dependOn(&run.step);
        if (std.mem.startsWith(u8, spec.run_step, "bench-")) {
            bench_step.dependOn(&run.step);
        }
    }
}

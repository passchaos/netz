const std = @import("std");
const builtin = @import("builtin");

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
    const benchmark_counting_allocator_mod = b.createModule(.{
        .root_source_file = b.path("examples/support/counting_allocator.zig"),
        .target = target,
        .optimize = optimize,
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
    const test_lib_step = b.step(
        "test-lib",
        "Compile and run the Netz library unit tests",
    );
    test_lib_step.dependOn(&run_lib_tests.step);

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
    const parser_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/parser_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
            // Zig 0.16's fuzz test runner currently mixes builtin and debug
            // StackTrace types in its error-reporting branch. Omitting error
            // traces avoids that compiler-owned mismatch without changing
            // parser coverage or allocator leak checks.
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_parser_fuzz_tests = b.addRunArtifact(parser_fuzz_tests);
    const fuzz_parsers_step = b.step(
        "fuzz-parsers",
        "Fuzz bounded HTTP/WebSocket/WebTransport/MQTT parsers",
    );
    fuzz_parsers_step.dependOn(&run_parser_fuzz_tests.step);
    const stateful_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/stateful_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
            // See the parser fuzz target above: this is a Zig 0.16 fuzz-runner
            // workaround and does not disable allocator leak detection.
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_stateful_fuzz_tests = b.addRunArtifact(stateful_fuzz_tests);
    const fuzz_stateful_step = b.step(
        "fuzz-stateful",
        "Fuzz bounded HTTP/WebSocket/WebTransport/MQTT state sequences",
    );
    fuzz_stateful_step.dependOn(&run_stateful_fuzz_tests.step);
    const mqtt_live_broker_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_live_broker_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_live_broker_fuzz_tests = b.addRunArtifact(
        mqtt_live_broker_fuzz_tests,
    );
    const fuzz_mqtt_live_broker_step = b.step(
        "fuzz-mqtt-live-broker",
        "Fuzz live MQTT broker ordering and retained routing",
    );
    fuzz_mqtt_live_broker_step.dependOn(
        &run_mqtt_live_broker_fuzz_tests.step,
    );
    const mqtt_tls_live_broker_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_tls_live_broker_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_tls_live_broker_fuzz_tests = b.addRunArtifact(
        mqtt_tls_live_broker_fuzz_tests,
    );
    const fuzz_mqtt_tls_live_broker_step = b.step(
        "fuzz-mqtt-tls-live-broker",
        "Fuzz authenticated TLS MQTT broker ordering and routing",
    );
    fuzz_mqtt_tls_live_broker_step.dependOn(
        &run_mqtt_tls_live_broker_fuzz_tests.step,
    );
    const mqtt_reconnect_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_reconnect_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_reconnect_fuzz_tests = b.addRunArtifact(
        mqtt_reconnect_fuzz_tests,
    );
    const fuzz_mqtt_reconnect_step = b.step(
        "fuzz-mqtt-reconnect",
        "Fuzz live MQTT reconnect and Session recovery ordering",
    );
    fuzz_mqtt_reconnect_step.dependOn(
        &run_mqtt_reconnect_fuzz_tests.step,
    );
    const mqtt_tls_reconnect_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_tls_reconnect_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_tls_reconnect_fuzz_tests = b.addRunArtifact(
        mqtt_tls_reconnect_fuzz_tests,
    );
    const fuzz_mqtt_tls_reconnect_step = b.step(
        "fuzz-mqtt-tls-reconnect",
        "Fuzz authenticated TLS MQTT reconnect and Session recovery",
    );
    fuzz_mqtt_tls_reconnect_step.dependOn(
        &run_mqtt_tls_reconnect_fuzz_tests.step,
    );
    const mqtt_wss_reconnect_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_wss_reconnect_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_wss_reconnect_fuzz_tests = b.addRunArtifact(
        mqtt_wss_reconnect_fuzz_tests,
    );
    const fuzz_mqtt_wss_reconnect_step = b.step(
        "fuzz-mqtt-wss-reconnect",
        "Fuzz authenticated WSS MQTT reconnect and Session recovery",
    );
    fuzz_mqtt_wss_reconnect_step.dependOn(
        &run_mqtt_wss_reconnect_fuzz_tests.step,
    );
    const mqtt_bridge_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_bridge_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_bridge_fuzz_tests = b.addRunArtifact(
        mqtt_bridge_fuzz_tests,
    );
    const fuzz_mqtt_bridge_step = b.step(
        "fuzz-mqtt-bridge",
        "Fuzz live inbound MQTT bridge routing and reconnects",
    );
    fuzz_mqtt_bridge_step.dependOn(
        &run_mqtt_bridge_fuzz_tests.step,
    );
    const mqtt_tls_bridge_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_tls_bridge_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_tls_bridge_fuzz_tests = b.addRunArtifact(
        mqtt_tls_bridge_fuzz_tests,
    );
    const fuzz_mqtt_tls_bridge_step = b.step(
        "fuzz-mqtt-tls-bridge",
        "Fuzz authenticated TLS MQTT inbound bridge routing",
    );
    fuzz_mqtt_tls_bridge_step.dependOn(
        &run_mqtt_tls_bridge_fuzz_tests.step,
    );
    const mqtt_bridge_qos2_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_bridge_qos2_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_bridge_qos2_fuzz_tests = b.addRunArtifact(
        mqtt_bridge_qos2_fuzz_tests,
    );
    const fuzz_mqtt_bridge_qos2_step = b.step(
        "fuzz-mqtt-bridge-qos2",
        "Fuzz durable inbound MQTT bridge QoS 2 recovery",
    );
    fuzz_mqtt_bridge_qos2_step.dependOn(
        &run_mqtt_bridge_qos2_fuzz_tests.step,
    );
    const mqtt_tls_bridge_qos2_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_tls_bridge_qos2_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_tls_bridge_qos2_fuzz_tests = b.addRunArtifact(
        mqtt_tls_bridge_qos2_fuzz_tests,
    );
    const fuzz_mqtt_tls_bridge_qos2_step = b.step(
        "fuzz-mqtt-tls-bridge-qos2",
        "Fuzz durable inbound MQTT bridge QoS 2 over authenticated TLS",
    );
    fuzz_mqtt_tls_bridge_qos2_step.dependOn(
        &run_mqtt_tls_bridge_qos2_fuzz_tests.step,
    );
    const mqtt_outbound_bridge_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_outbound_bridge_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_outbound_bridge_fuzz_tests = b.addRunArtifact(
        mqtt_outbound_bridge_fuzz_tests,
    );
    const fuzz_mqtt_outbound_bridge_step = b.step(
        "fuzz-mqtt-outbound-bridge",
        "Fuzz outbound MQTT bridge routing and reconnects",
    );
    fuzz_mqtt_outbound_bridge_step.dependOn(
        &run_mqtt_outbound_bridge_fuzz_tests.step,
    );
    const mqtt_tls_outbound_bridge_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_tls_outbound_bridge_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_tls_outbound_bridge_fuzz_tests = b.addRunArtifact(
        mqtt_tls_outbound_bridge_fuzz_tests,
    );
    const fuzz_mqtt_tls_outbound_bridge_step = b.step(
        "fuzz-mqtt-tls-outbound-bridge",
        "Fuzz outbound MQTT bridge routing across authenticated TLS peers",
    );
    fuzz_mqtt_tls_outbound_bridge_step.dependOn(
        &run_mqtt_tls_outbound_bridge_fuzz_tests.step,
    );
    const mqtt_outbound_bridge_qos2_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_outbound_bridge_qos2_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_outbound_bridge_qos2_fuzz_tests = b.addRunArtifact(
        mqtt_outbound_bridge_qos2_fuzz_tests,
    );
    const fuzz_mqtt_outbound_bridge_qos2_step = b.step(
        "fuzz-mqtt-outbound-bridge-qos2",
        "Fuzz durable outbound MQTT bridge QoS 2 recovery",
    );
    fuzz_mqtt_outbound_bridge_qos2_step.dependOn(
        &run_mqtt_outbound_bridge_qos2_fuzz_tests.step,
    );
    const mqtt_tls_outbound_bridge_qos2_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/mqtt_tls_outbound_bridge_qos2_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_mqtt_tls_outbound_bridge_qos2_fuzz_tests = b.addRunArtifact(
        mqtt_tls_outbound_bridge_qos2_fuzz_tests,
    );
    const fuzz_mqtt_tls_outbound_bridge_qos2_step = b.step(
        "fuzz-mqtt-tls-outbound-bridge-qos2",
        "Fuzz durable outbound MQTT bridge QoS 2 across authenticated TLS peers",
    );
    fuzz_mqtt_tls_outbound_bridge_qos2_step.dependOn(
        &run_mqtt_tls_outbound_bridge_qos2_fuzz_tests.step,
    );
    const http1_connection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/http1_connection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_http1_connection_fuzz_tests = b.addRunArtifact(
        http1_connection_fuzz_tests,
    );
    const fuzz_http1_connection_step = b.step(
        "fuzz-http1-connection",
        "Fuzz live HTTP/1 connection reuse and framing",
    );
    fuzz_http1_connection_step.dependOn(
        &run_http1_connection_fuzz_tests.step,
    );
    const http1_tls_connection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/http1_tls_connection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_http1_tls_connection_fuzz_tests = b.addRunArtifact(
        http1_tls_connection_fuzz_tests,
    );
    const fuzz_http1_tls_connection_step = b.step(
        "fuzz-http1-tls-connection",
        "Fuzz authenticated HTTP/1 TLS connection state",
    );
    fuzz_http1_tls_connection_step.dependOn(
        &run_http1_tls_connection_fuzz_tests.step,
    );
    const http2_connection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/http2_connection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_http2_connection_fuzz_tests = b.addRunArtifact(
        http2_connection_fuzz_tests,
    );
    const fuzz_http2_connection_step = b.step(
        "fuzz-http2-connection",
        "Fuzz live HTTP/2 h2c connection state",
    );
    fuzz_http2_connection_step.dependOn(
        &run_http2_connection_fuzz_tests.step,
    );
    const http2_tls_connection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/http2_tls_connection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_http2_tls_connection_fuzz_tests = b.addRunArtifact(
        http2_tls_connection_fuzz_tests,
    );
    const fuzz_http2_tls_connection_step = b.step(
        "fuzz-http2-tls-connection",
        "Fuzz authenticated HTTP/2 TLS connection state",
    );
    fuzz_http2_tls_connection_step.dependOn(
        &run_http2_tls_connection_fuzz_tests.step,
    );
    const http3_connection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/http3_connection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_http3_connection_fuzz_tests = b.addRunArtifact(
        http3_connection_fuzz_tests,
    );
    const fuzz_http3_connection_step = b.step(
        "fuzz-http3-connection",
        "Fuzz authenticated HTTP/3 connection state",
    );
    fuzz_http3_connection_step.dependOn(
        &run_http3_connection_fuzz_tests.step,
    );
    const webtransport_endpoint_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/webtransport_endpoint_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_webtransport_endpoint_fuzz_tests = b.addRunArtifact(
        webtransport_endpoint_fuzz_tests,
    );
    const fuzz_webtransport_endpoint_step = b.step(
        "fuzz-webtransport-endpoint",
        "Fuzz authenticated WebTransport shared-endpoint routing",
    );
    fuzz_webtransport_endpoint_step.dependOn(
        &run_webtransport_endpoint_fuzz_tests.step,
    );
    const websocket_compression_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_compression_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_compression_fuzz_tests = b.addRunArtifact(
        websocket_compression_fuzz_tests,
    );
    const fuzz_websocket_compression_step = b.step(
        "fuzz-websocket-compression",
        "Fuzz bounded WebSocket permessage-deflate codecs",
    );
    fuzz_websocket_compression_step.dependOn(
        &run_websocket_compression_fuzz_tests.step,
    );
    const http_content_coding_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/http_content_coding_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_http_content_coding_fuzz_tests = b.addRunArtifact(
        http_content_coding_fuzz_tests,
    );
    const fuzz_http_content_coding_step = b.step(
        "fuzz-http-content-coding",
        "Fuzz bounded HTTP Content-Encoding parsing and decode",
    );
    fuzz_http_content_coding_step.dependOn(
        &run_http_content_coding_fuzz_tests.step,
    );
    const websocket_context_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_context_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_context_fuzz_tests = b.addRunArtifact(
        websocket_context_fuzz_tests,
    );
    const fuzz_websocket_context_step = b.step(
        "fuzz-websocket-context",
        "Fuzz bounded WebSocket compression context sequences",
    );
    fuzz_websocket_context_step.dependOn(
        &run_websocket_context_fuzz_tests.step,
    );
    const websocket_h1_context_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_h1_context_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_h1_context_fuzz_tests = b.addRunArtifact(
        websocket_h1_context_fuzz_tests,
    );
    const fuzz_websocket_h1_context_step = b.step(
        "fuzz-websocket-h1-context",
        "Fuzz WebSocket context takeover over live HTTP/1 connections",
    );
    fuzz_websocket_h1_context_step.dependOn(
        &run_websocket_h1_context_fuzz_tests.step,
    );
    const websocket_h1_tls_context_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_h1_tls_context_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_h1_tls_context_fuzz_tests = b.addRunArtifact(
        websocket_h1_tls_context_fuzz_tests,
    );
    const fuzz_websocket_h1_tls_context_step = b.step(
        "fuzz-websocket-h1-tls-context",
        "Fuzz WebSocket context takeover over authenticated WSS",
    );
    fuzz_websocket_h1_tls_context_step.dependOn(
        &run_websocket_h1_tls_context_fuzz_tests.step,
    );
    const websocket_h2_context_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_h2_context_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_h2_context_fuzz_tests = b.addRunArtifact(
        websocket_h2_context_fuzz_tests,
    );
    const fuzz_websocket_h2_context_step = b.step(
        "fuzz-websocket-h2-context",
        "Fuzz WebSocket context takeover over live HTTP/2 connections",
    );
    fuzz_websocket_h2_context_step.dependOn(
        &run_websocket_h2_context_fuzz_tests.step,
    );
    const websocket_h2_tls_context_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_h2_tls_context_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_h2_tls_context_fuzz_tests = b.addRunArtifact(
        websocket_h2_tls_context_fuzz_tests,
    );
    const fuzz_websocket_h2_tls_context_step = b.step(
        "fuzz-websocket-h2-tls-context",
        "Fuzz RFC 8441 context takeover over authenticated TLS",
    );
    fuzz_websocket_h2_tls_context_step.dependOn(
        &run_websocket_h2_tls_context_fuzz_tests.step,
    );
    const websocket_h3_context_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/websocket_h3_context_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_websocket_h3_context_fuzz_tests = b.addRunArtifact(
        websocket_h3_context_fuzz_tests,
    );
    const fuzz_websocket_h3_context_step = b.step(
        "fuzz-websocket-h3-context",
        "Fuzz WebSocket context takeover over live HTTP/3 connections",
    );
    fuzz_websocket_h3_context_step.dependOn(
        &run_websocket_h3_context_fuzz_tests.step,
    );
    const quic_wire_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/quic_wire_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_wire_fuzz_tests = b.addRunArtifact(quic_wire_fuzz_tests);
    const fuzz_quic_wire_step = b.step(
        "fuzz-quic-wire",
        "Fuzz bounded QUIC frames, parameters, packets, and TLS messages",
    );
    fuzz_quic_wire_step.dependOn(&run_quic_wire_fuzz_tests.step);
    const quic_protection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/quic_protection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_protection_fuzz_tests = b.addRunArtifact(
        quic_protection_fuzz_tests,
    );
    const fuzz_quic_protection_step = b.step(
        "fuzz-quic-protection",
        "Fuzz bounded QUIC packet and header protection",
    );
    fuzz_quic_protection_step.dependOn(
        &run_quic_protection_fuzz_tests.step,
    );
    const quic_connection_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/quic_connection_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_connection_fuzz_tests = b.addRunArtifact(
        quic_connection_fuzz_tests,
    );
    const fuzz_quic_connection_step = b.step(
        "fuzz-quic-connection",
        "Fuzz bounded stateful QUIC connection sequences",
    );
    fuzz_quic_connection_step.dependOn(
        &run_quic_connection_fuzz_tests.step,
    );
    const quic_path_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/quic_path_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_path_fuzz_tests = b.addRunArtifact(
        quic_path_fuzz_tests,
    );
    const fuzz_quic_path_step = b.step(
        "fuzz-quic-path",
        "Fuzz authenticated QUIC migration and rebinding state",
    );
    fuzz_quic_path_step.dependOn(&run_quic_path_fuzz_tests.step);
    const quic_handshake_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/quic_handshake_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_handshake_fuzz_tests = b.addRunArtifact(
        quic_handshake_fuzz_tests,
    );
    const fuzz_quic_handshake_step = b.step(
        "fuzz-quic-handshake",
        "Fuzz authenticated QUIC/TLS handshake recovery",
    );
    fuzz_quic_handshake_step.dependOn(
        &run_quic_handshake_fuzz_tests.step,
    );
    const quic_endpoint_fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "test/quic_endpoint_fuzz_test.zig",
            ),
            .target = target,
            .optimize = optimize,
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run_quic_endpoint_fuzz_tests = b.addRunArtifact(
        quic_endpoint_fuzz_tests,
    );
    const fuzz_quic_endpoint_step = b.step(
        "fuzz-quic-endpoint",
        "Fuzz authenticated QUIC endpoint capacity and ownership",
    );
    fuzz_quic_endpoint_step.dependOn(
        &run_quic_endpoint_fuzz_tests.step,
    );
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

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_package_tests.step);
    test_step.dependOn(&run_parser_fuzz_tests.step);
    test_step.dependOn(&run_stateful_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_live_broker_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_tls_live_broker_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_reconnect_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_tls_reconnect_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_wss_reconnect_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_bridge_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_tls_bridge_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_bridge_qos2_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_tls_bridge_qos2_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_outbound_bridge_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_tls_outbound_bridge_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_outbound_bridge_qos2_fuzz_tests.step);
    test_step.dependOn(&run_mqtt_tls_outbound_bridge_qos2_fuzz_tests.step);
    test_step.dependOn(&run_http1_connection_fuzz_tests.step);
    test_step.dependOn(&run_http1_tls_connection_fuzz_tests.step);
    test_step.dependOn(&run_http2_connection_fuzz_tests.step);
    test_step.dependOn(&run_http2_tls_connection_fuzz_tests.step);
    test_step.dependOn(&run_http3_connection_fuzz_tests.step);
    test_step.dependOn(&run_webtransport_endpoint_fuzz_tests.step);
    test_step.dependOn(&run_websocket_compression_fuzz_tests.step);
    test_step.dependOn(&run_http_content_coding_fuzz_tests.step);
    test_step.dependOn(&run_websocket_context_fuzz_tests.step);
    test_step.dependOn(&run_websocket_h1_context_fuzz_tests.step);
    test_step.dependOn(&run_websocket_h1_tls_context_fuzz_tests.step);
    test_step.dependOn(&run_websocket_h2_context_fuzz_tests.step);
    test_step.dependOn(&run_websocket_h2_tls_context_fuzz_tests.step);
    test_step.dependOn(&run_websocket_h3_context_fuzz_tests.step);
    test_step.dependOn(&run_quic_wire_fuzz_tests.step);
    test_step.dependOn(&run_quic_protection_fuzz_tests.step);
    test_step.dependOn(&run_quic_connection_fuzz_tests.step);
    test_step.dependOn(&run_quic_path_fuzz_tests.step);
    test_step.dependOn(&run_quic_handshake_fuzz_tests.step);
    test_step.dependOn(&run_quic_endpoint_fuzz_tests.step);
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
        "Exercise TLS 1.2/1.3 required and optional MQTT mTLS with OpenSSL",
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
    if (b.args) |args| mqtt_vectors.addArgs(args);
    const mqtt_vectors_step = b.step(
        "interop-mqtt-mosquitto-vectors",
        "Run selected Mosquitto MQTT 5 wire vectors against netz",
    );
    mqtt_vectors_step.dependOn(&mqtt_vectors.step);

    const mqtt_packet_sequences = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_mosquitto_packet_sequences.py",
    });
    mqtt_packet_sequences.addArtifactArg(mqtt_vectors_broker);
    if (b.args) |args| mqtt_packet_sequences.addArgs(args);
    const mqtt_packet_sequences_step = b.step(
        "interop-mqtt-mosquitto-packet-sequences",
        "Run hash-locked Mosquitto sequences with audited exact expectations",
    );
    mqtt_packet_sequences_step.dependOn(&mqtt_packet_sequences.step);

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
        "Run a same-client MQTT QoS1 comparison against local Mosquitto",
    );
    mqtt_broker_compare_step.dependOn(&mqtt_broker_compare.step);
    const mqtt_broker_matrix = b.addSystemCommand(&.{
        "tools/interop/mqtt_broker_matrix.sh",
    });
    mqtt_broker_matrix.addArtifactArg(mqtt_vectors_broker);
    mqtt_broker_matrix.addArtifactArg(mqtt_broker_bench);
    const mqtt_broker_matrix_step = b.step(
        "compare-mqtt-mosquitto-matrix",
        "Capture a fixed-shape MQTT QoS1 latency, throughput, allocation, and RSS matrix",
    );
    mqtt_broker_matrix_step.dependOn(&mqtt_broker_matrix.step);
    const mqtt_broker_allocator_matrix = b.addSystemCommand(&.{
        "tools/interop/mqtt_broker_allocator_matrix.sh",
    });
    mqtt_broker_allocator_matrix.addArtifactArg(mqtt_vectors_broker);
    mqtt_broker_allocator_matrix.addArtifactArg(mqtt_broker_bench);
    const mqtt_broker_allocator_matrix_step = b.step(
        "bench-mqtt-broker-allocator-matrix",
        "Capture fixed-shape MQTT broker allocation diagnostics",
    );
    mqtt_broker_allocator_matrix_step.dependOn(
        &mqtt_broker_allocator_matrix.step,
    );

    const mqtt_mosquitto_clients = b.addSystemCommand(&.{
        "tools/interop/mqtt_mosquitto_clients.sh",
    });
    mqtt_mosquitto_clients.addArtifactArg(mqtt_vectors_broker);
    const mqtt_mosquitto_clients_step = b.step(
        "interop-mqtt-mosquitto-clients",
        "Run real Mosquitto CLI clients against the netz MQTT broker",
    );
    mqtt_mosquitto_clients_step.dependOn(&mqtt_mosquitto_clients.step);

    const mqtt_publish_client = b.addExecutable(.{
        .name = "netz-mqtt-publish-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/mqtt_publish_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_publish_interop = b.addSystemCommand(&.{"tools/interop/mqtt_publish_mosquitto.sh"});
    mqtt_publish_interop.addArtifactArg(mqtt_publish_client);
    const mqtt_publish_interop_step = b.step(
        "interop-mqtt-publish-mosquitto",
        "Run netz synchronous QoS completion and self-delivery against Mosquitto",
    );
    mqtt_publish_interop_step.dependOn(&mqtt_publish_interop.step);

    const mqtt_rumqttc = b.addSystemCommand(&.{
        "tools/interop/mqtt_rumqttc.sh",
    });
    mqtt_rumqttc.addArtifactArg(mqtt_vectors_broker);
    const mqtt_rumqttc_step = b.step(
        "interop-mqtt-rumqttc",
        "Run real rumqttc clients against the netz MQTT broker",
    );
    mqtt_rumqttc_step.dependOn(&mqtt_rumqttc.step);

    const mqtt_rumqttc_crash = b.addSystemCommand(&.{
        "tools/interop/mqtt_rumqttc_crash.sh",
    });
    mqtt_rumqttc_crash.addArtifactArg(mqtt_vectors_broker);
    const mqtt_rumqttc_crash_step = b.step(
        "interop-mqtt-rumqttc-crash",
        "Verify rumqttc Sessions survive netz broker SIGKILL and restart",
    );
    mqtt_rumqttc_crash_step.dependOn(&mqtt_rumqttc_crash.step);

    const mqtt_outbound_bridge = b.addExecutable(.{
        .name = "netz-mqtt-outbound-bridge",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/mqtt_outbound_bridge.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_outbound_bridge_mosquitto = b.addSystemCommand(&.{
        "tools/interop/mqtt_outbound_bridge_mosquitto.sh",
    });
    mqtt_outbound_bridge_mosquitto.addArtifactArg(mqtt_outbound_bridge);
    const mqtt_outbound_bridge_mosquitto_step = b.step(
        "interop-mqtt-outbound-bridge-mosquitto",
        "Bridge and recover two real Mosquitto brokers through netz",
    );
    mqtt_outbound_bridge_mosquitto_step.dependOn(
        &mqtt_outbound_bridge_mosquitto.step,
    );

    const mqtt_commit_log = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_commit_log.py",
    });
    mqtt_commit_log.addArtifactArg(mqtt_vectors_broker);
    if (b.args) |args| mqtt_commit_log.addArgs(args);
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

    const mqtt_socks5_client = b.addExecutable(.{
        .name = "netz-mqtt-socks5-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/mqtt_socks5_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const mqtt_socks5 = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_socks5.py",
    });
    mqtt_socks5.addArtifactArg(mqtt_socks5_client);
    const mqtt_socks5_step = b.step(
        "interop-mqtt-socks5",
        "Verify native MQTT and TLS through independent SOCKS5 peers",
    );
    mqtt_socks5_step.dependOn(&mqtt_socks5.step);
    test_step.dependOn(&mqtt_socks5.step);

    const http_websocket_socks5_client = b.addExecutable(.{
        .name = "netz-http-websocket-socks5-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_websocket_socks5_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_websocket_socks5 = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http_websocket_socks5.py",
    });
    http_websocket_socks5.addArtifactArg(http_websocket_socks5_client);
    const http_websocket_socks5_step = b.step(
        "interop-http-websocket-socks5",
        "Verify HTTP(S), WebSocket, and MQTT-WS through SOCKS5",
    );
    http_websocket_socks5_step.dependOn(&http_websocket_socks5.step);
    test_step.dependOn(&http_websocket_socks5.step);

    const websocket_socks5_redirect_client = b.addExecutable(.{
        .name = "netz-websocket-socks5-redirect-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_socks5_redirect_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_socks5_redirect = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_socks5_redirect.py",
    });
    websocket_socks5_redirect.addArtifactArg(
        websocket_socks5_redirect_client,
    );
    const websocket_socks5_redirect_step = b.step(
        "interop-websocket-socks5-redirect",
        "Verify redirects and reconnects through fresh SOCKS5 tunnels",
    );
    websocket_socks5_redirect_step.dependOn(
        &websocket_socks5_redirect.step,
    );
    test_step.dependOn(&websocket_socks5_redirect.step);

    @import("tools/interop/webtransport_h2/build.zig").add(b, target, optimize, netz_mod, test_step);
    @import("tools/interop/http_digest/build.zig").add(b, target, optimize, netz_mod, test_step);

    const http_socks5_client = b.addExecutable(.{
        .name = "netz-http-socks5-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_socks5_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_socks5 = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http_socks5.py",
    });
    http_socks5.addArtifactArg(http_socks5_client);
    const http_socks5_step = b.step(
        "interop-http-socks5",
        "Verify HTTP1, HTTP2, redirects, and pooling through SOCKS5",
    );
    http_socks5_step.dependOn(&http_socks5.step);
    test_step.dependOn(&http_socks5.step);

    const socks5_udp_client = b.addExecutable(.{
        .name = "netz-socks5-udp-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/socks5_udp_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const socks5_udp = b.addSystemCommand(&.{
        "python3",
        "tools/interop/socks5_udp.py",
    });
    socks5_udp.addArtifactArg(socks5_udp_client);
    const socks5_udp_step = b.step(
        "interop-socks5-udp",
        "Verify RFC 1928 UDP ASSOCIATE against an independent relay",
    );
    socks5_udp_step.dependOn(&socks5_udp.step);
    test_step.dependOn(&socks5_udp.step);

    const http3_socks5_pool_client = b.addExecutable(.{
        .name = "netz-http3-socks5-pool-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http3_socks5_pool_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http3_socks5_pool = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http3_socks5_pool.py",
    });
    http3_socks5_pool.addArtifactArg(http3_socks5_pool_client);
    const http3_socks5_pool_step = b.step(
        "interop-http3-socks5-pool",
        "Verify unified HTTP/3 pool reuse through SOCKS5 UDP ASSOCIATE",
    );
    http3_socks5_pool_step.dependOn(&http3_socks5_pool.step);
    test_step.dependOn(&http3_socks5_pool.step);

    const mqtt_broker_config = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_broker_config.addArtifactArg(mqtt_vectors_broker);
    if (b.args) |args| mqtt_broker_config.addArgs(args);
    const mqtt_broker_config_step = b.step(
        "interop-mqtt-broker-config",
        "Exercise strict broker config across TCP/TLS/WS/WSS listeners",
    );
    mqtt_broker_config_step.dependOn(&mqtt_broker_config.step);
    test_step.dependOn(&mqtt_broker_config.step);

    const mqtt_connect_property_linear = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_connect_property_linear.addArtifactArg(mqtt_vectors_broker);
    mqtt_connect_property_linear.addArg("--only-connect-property-linear");
    if (b.args) |args| mqtt_connect_property_linear.addArgs(args);
    const mqtt_connect_property_linear_step = b.step(
        "interop-mqtt-connect-property-linear",
        "Verify source-locked linear MQTT CONNECT User Property processing",
    );
    mqtt_connect_property_linear_step.dependOn(
        &mqtt_connect_property_linear.step,
    );

    const mqtt_will_lifecycle = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_will_lifecycle.addArtifactArg(mqtt_vectors_broker);
    mqtt_will_lifecycle.addArg("--only-will-lifecycle");
    if (b.args) |args| mqtt_will_lifecycle.addArgs(args);
    const mqtt_will_lifecycle_step = b.step(
        "interop-mqtt-will-lifecycle",
        "Verify source-locked QoS0 Wills and publication-time ACL reload policy",
    );
    mqtt_will_lifecycle_step.dependOn(&mqtt_will_lifecycle.step);

    const mqtt_will_delay = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_will_delay.addArtifactArg(mqtt_vectors_broker);
    mqtt_will_delay.addArg("--only-will-delay");
    if (b.args) |args| mqtt_will_delay.addArgs(args);
    const mqtt_will_delay_step = b.step(
        "interop-mqtt-will-delay",
        "Verify source-locked Will Delay, Session expiry and replacement lifecycle",
    );
    mqtt_will_delay_step.dependOn(&mqtt_will_delay.step);

    const mqtt_session_expiry_restart = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_session_expiry_restart.addArtifactArg(mqtt_vectors_broker);
    mqtt_session_expiry_restart.addArg("--only-session-expiry-restart");
    if (b.args) |args| mqtt_session_expiry_restart.addArgs(args);
    const mqtt_session_expiry_restart_step = b.step(
        "interop-mqtt-session-expiry-restart",
        "Verify persisted Session expiry with shared queues, retained data and resubscription",
    );
    mqtt_session_expiry_restart_step.dependOn(&mqtt_session_expiry_restart.step);
    const mqtt_session_expiry_oracle_tests = b.addSystemCommand(&.{
        "python3", "-m", "unittest", "mqtt_scenarios.session_expiry_restart_test",
    });
    mqtt_session_expiry_oracle_tests.setCwd(b.path("tools/interop"));
    mqtt_session_expiry_restart_step.dependOn(&mqtt_session_expiry_oracle_tests.step);
    test_step.dependOn(&mqtt_session_expiry_oracle_tests.step);

    const mqtt_shared_properties = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_shared_properties.addArtifactArg(mqtt_vectors_broker);
    mqtt_shared_properties.addArg("--only-shared-properties");
    if (b.args) |args| mqtt_shared_properties.addArgs(args);
    const mqtt_shared_properties_step = b.step(
        "interop-mqtt-shared-properties",
        "Verify shared Session metadata across publisher teardown and process recovery",
    );
    mqtt_shared_properties_step.dependOn(&mqtt_shared_properties.step);
    const mqtt_shared_properties_checker_tests = b.addSystemCommand(&.{
        "python3", "-m", "unittest", "mqtt_shared_properties_ab_test",
    });
    mqtt_shared_properties_checker_tests.setCwd(b.path("tools/interop"));
    const mqtt_shared_properties_checker_step = b.step(
        "test-mqtt-shared-properties-benchmark",
        "Check complete shared MQTT metadata benchmark samples and accounting",
    );
    mqtt_shared_properties_checker_step.dependOn(&mqtt_shared_properties_checker_tests.step);
    test_step.dependOn(&mqtt_shared_properties_checker_tests.step);

    const mqtt_deadline_benchmark_check = b.addSystemCommand(&.{
        "python3", "-m", "unittest", "mqtt_deadline_bench.test_check",
    });
    mqtt_deadline_benchmark_check.setCwd(b.path("tools/interop"));
    const mqtt_deadline_benchmark_check_step = b.step(
        "test-mqtt-deadline-benchmark",
        "Validate complete MQTT deadline-delivery benchmark records",
    );
    mqtt_deadline_benchmark_check_step.dependOn(&mqtt_deadline_benchmark_check.step);
    test_step.dependOn(&mqtt_deadline_benchmark_check.step);

    const mqtt_broker_includes = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_config.py",
    });
    mqtt_broker_includes.addArtifactArg(mqtt_vectors_broker);
    mqtt_broker_includes.addArg("--only-include-directory");
    if (b.args) |args| mqtt_broker_includes.addArgs(args);
    const mqtt_broker_includes_step = b.step(
        "interop-mqtt-broker-includes",
        "Verify ordered include_dir startup, live reload, rollback, and file changes",
    );
    mqtt_broker_includes_step.dependOn(&mqtt_broker_includes.step);

    const mqtt_broker_tls12_ticket = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_tls12_ticket.py",
    });
    mqtt_broker_tls12_ticket.addArtifactArg(mqtt_vectors_broker);
    mqtt_broker_tls12_ticket.addArg("tls12");
    const mqtt_broker_tls12_ticket_step = b.step(
        "interop-mqtt-broker-tls12-ticket",
        "Verify configured MQTT TLS 1.2 ticket resumption with OpenSSL",
    );
    mqtt_broker_tls12_ticket_step.dependOn(
        &mqtt_broker_tls12_ticket.step,
    );
    test_step.dependOn(&mqtt_broker_tls12_ticket.step);

    const mqtt_broker_tls13_ticket = b.addSystemCommand(&.{
        "python3",
        "tools/interop/mqtt_broker_tls12_ticket.py",
    });
    mqtt_broker_tls13_ticket.addArtifactArg(mqtt_vectors_broker);
    mqtt_broker_tls13_ticket.addArg("tls13");
    const mqtt_broker_tls13_ticket_step = b.step(
        "interop-mqtt-broker-tls13-ticket",
        "Verify configured MQTT TLS 1.3 ticket resumption with OpenSSL",
    );
    mqtt_broker_tls13_ticket_step.dependOn(
        &mqtt_broker_tls13_ticket.step,
    );
    test_step.dependOn(&mqtt_broker_tls13_ticket.step);

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

    const grpc_web_chrome_server = b.addExecutable(.{
        .name = "netz-grpc-web-chrome-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_web_chrome_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_web_chrome = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_web_chrome.py" });
    grpc_web_chrome.addArtifactArg(grpc_web_chrome_server);
    if (b.args) |args| grpc_web_chrome.addArgs(args);
    const grpc_web_chrome_step = b.step("interop-grpc-web-chrome", "Verify gRPC-Web/CORS with the official JS SDK in Chromium (--tls for HTTPS; --tls --http2 for HTTP/2)");
    grpc_web_chrome_step.dependOn(&grpc_web_chrome.step);

    const grpc_response_client = b.addExecutable(.{
        .name = "netz-grpc-response-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_response_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_response = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_response.py" });
    grpc_response.addArtifactArg(grpc_response_client);
    const grpc_response_step = b.step("interop-grpc-response", "Verify native gRPC response fallback with an independent HTTP/2 peer and official grpc-js");
    grpc_response_step.dependOn(&grpc_response.step);

    const grpc_ip_literals_client = b.addExecutable(.{
        .name = "netz-grpc-ip-literals-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_ip_literals/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_ip_literals = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_ip_literals/run.py" });
    grpc_ip_literals.addArtifactArg(grpc_ip_literals_client);
    if (b.args) |args| grpc_ip_literals.addArgs(args);
    const grpc_ip_literals_step = b.step("interop-grpc-ip-literals", "Verify numeric gRPC targets, HTTP/2 authority, TLS SNI and IP SAN identity with grpc-js/OpenSSL");
    grpc_ip_literals_step.dependOn(&grpc_ip_literals.step);

    const grpc_connection_race_client = b.addExecutable(.{
        .name = "netz-grpc-connection-race-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_connection_race/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_connection_race = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_connection_race/run.py" });
    grpc_connection_race.addArtifactArg(grpc_connection_race_client);
    if (b.args) |args| grpc_connection_race.addArgs(args);
    const grpc_connection_race_step = b.step("interop-grpc-connection-race", "Verify gRPC staggered endpoint selection and stalled handshake cleanup with grpc-js over h2c/TLS");
    grpc_connection_race_step.dependOn(&grpc_connection_race.step);

    const grpc_locality_client = b.addExecutable(.{
        .name = "netz-grpc-locality-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_locality/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_locality = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_locality/run.py" });
    grpc_locality.addArtifactArg(grpc_locality_client);
    if (b.args) |args| grpc_locality.addArgs(args);
    const grpc_locality_step = b.step("interop-grpc-locality", "Verify xDS locality generation with official grpc-js-xds and ordinary/shared routing with grpc-js");
    grpc_locality_step.dependOn(&grpc_locality.step);

    const grpc_cluster_manager_client = b.addExecutable(.{
        .name = "netz-grpc-cluster-manager-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_cluster_manager/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cluster_manager = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_cluster_manager/run.py" });
    grpc_cluster_manager.addArtifactArg(grpc_cluster_manager_client);
    if (b.args) |args| grpc_cluster_manager.addArgs(args);
    const grpc_cluster_manager_step = b.step("interop-grpc-cluster-manager", "Verify per-RPC cluster picking, failed-child isolation and config updates with official grpc-js-xds/grpc-js");
    grpc_cluster_manager_step.dependOn(&grpc_cluster_manager.step);

    const grpc_ads_client = b.addExecutable(.{
        .name = "netz-grpc-ads-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_ads/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_ads = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_ads/run.py" });
    grpc_ads.addArtifactArg(grpc_ads_client);
    if (b.args) |args| grpc_ads.addArgs(args);
    const grpc_ads_step = b.step("interop-grpc-ads", "Verify v3 ADS ACK/NACK subscriptions and stream reconnect with official discovery protobufs and grpc-js");
    grpc_ads_step.dependOn(&grpc_ads.step);

    const xds_regex_module = b.createModule(.{ .root_source_file = b.path("src/grpc/xds/routing/regex.zig"), .target = target, .optimize = optimize });
    const xds_regex_client = b.addExecutable(.{
        .name = "netz-grpc-xds-regex-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_xds_matching/regex_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "xds_regex", .module = xds_regex_module }},
        }),
    });
    const xds_regex = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_xds_matching/regex_run.py" });
    xds_regex.addArtifactArg(xds_regex_client);
    if (b.args) |args| xds_regex.addArgs(args);
    const xds_regex_step = b.step("interop-grpc-xds-regex", "Compare bounded native xDS safe-regex full matching against official RE2 WASM");
    xds_regex_step.dependOn(&xds_regex.step);

    const grpc_runtime_client = b.addExecutable(.{
        .name = "netz-grpc-xds-runtime-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_xds_runtime/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_runtime = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_xds_runtime/run.py" });
    grpc_runtime.addArtifactArg(grpc_runtime_client);
    if (b.args) |args| grpc_runtime.addArgs(args);
    const grpc_runtime_step = b.step("interop-grpc-xds-runtime", "Verify automatic LDS/RDS/CDS/EDS discovery and isolated cluster RPC admission");
    grpc_runtime_step.dependOn(&grpc_runtime.step);

    const grpc_delta_client = b.addExecutable(.{
        .name = "netz-grpc-delta-ads-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_delta_ads/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_delta = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_delta_ads/run.py" });
    grpc_delta.addArtifactArg(grpc_delta_client);
    if (b.args) |args| grpc_delta.addArgs(args);
    const grpc_delta_step = b.step("interop-grpc-delta-ads", "Verify delta ADS envelopes, diffs, NACK and reconnect against official Envoy protobuf schemas");
    grpc_delta_step.dependOn(&grpc_delta.step);

    const grpc_delta_runtime_client = b.addExecutable(.{
        .name = "netz-grpc-delta-runtime-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_delta_runtime/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_delta_runtime = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_delta_runtime/run.py" });
    grpc_delta_runtime.addArtifactArg(grpc_delta_runtime_client);
    if (b.args) |args| grpc_delta_runtime.addArgs(args);
    const grpc_delta_runtime_step = b.step("interop-grpc-delta-runtime", "Verify typed delta LDS/RDS/CDS/EDS publication and explicit removals with real RPCs");
    grpc_delta_runtime_step.dependOn(&grpc_delta_runtime.step);

    const grpc_lrs_client = b.addExecutable(.{
        .name = "netz-grpc-lrs-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_lrs/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_lrs = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_lrs/run.py" });
    grpc_lrs.addArtifactArg(grpc_lrs_client);
    if (b.args) |args| grpc_lrs.addArgs(args);
    const grpc_lrs_step = b.step("interop-grpc-lrs", "Verify Load Reporting Service envelopes and counters against official Envoy schemas");
    grpc_lrs_step.dependOn(&grpc_lrs.step);

    const grpc_lrs_automatic_client = b.addExecutable(.{
        .name = "netz-grpc-lrs-automatic-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_lrs_automatic/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_lrs_automatic = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_lrs_automatic/run.py" });
    grpc_lrs_automatic.addArtifactArg(grpc_lrs_automatic_client);
    if (b.args) |args| grpc_lrs_automatic.addArgs(args);
    b.step("interop-grpc-lrs-automatic", "Verify managed CDS LRS source provenance, migration and nonblocking reporting transport").dependOn(&grpc_lrs_automatic.step);

    const grpc_impl_client = b.addExecutable(.{
        .name = "netz-grpc-cluster-impl-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_cluster_impl/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_impl = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_cluster_impl/run.py" });
    grpc_impl.addArtifactArg(grpc_impl_client);
    if (b.args) |args| grpc_impl.addArgs(args);
    const grpc_impl_step = b.step("interop-grpc-cluster-impl", "Verify selected-cluster drop/circuit isolation with official grpc-js-xds and ordinary/shared RPCs");
    grpc_impl_step.dependOn(&grpc_impl.step);

    const grpc_lds_client = b.addExecutable(.{
        .name = "netz-grpc-lds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_lds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_lds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_lds/run.py" });
    grpc_lds.addArtifactArg(grpc_lds_client);
    if (b.args) |args| grpc_lds.addArgs(args);
    const grpc_lds_step = b.step("interop-grpc-lds", "Verify official client LDS/HCM through inline/dynamic RDS and immutable RPC timeout/routing publication");
    grpc_lds_step.dependOn(&grpc_lds.step);

    const grpc_hedging_commit_client = b.addExecutable(.{
        .name = "netz-grpc-hedging-commit-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_hedging_commit/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_hedging_commit = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_hedging_commit/run.py" });
    grpc_hedging_commit.addArtifactArg(grpc_hedging_commit_client);
    if (b.args) |args| grpc_hedging_commit.addArgs(args);
    b.step("interop-grpc-hedging-commit", "Verify A6 response-head commitment, immediate hedge cancellation and call-wide transparent recovery").dependOn(&grpc_hedging_commit.step);
    test_step.dependOn(&grpc_hedging_commit.step);

    const grpc_rds_client = b.addExecutable(.{
        .name = "netz-grpc-rds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_rds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_rds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_rds/run.py" });
    grpc_rds.addArtifactArg(grpc_rds_client);
    if (b.args) |args| grpc_rds.addArgs(args);
    const grpc_rds_step = b.step("interop-grpc-rds", "Verify official RDS resources through ADS, immutable selectors and automatic unary/stream cluster dispatch");
    grpc_rds_step.dependOn(&grpc_rds.step);

    const grpc_csds_emit = b.addExecutable(.{
        .name = "netz-grpc-csds-emit",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_csds/emit.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_csds = b.addSystemCommand(&.{ "node", "tools/interop/grpc_csds/run.js" });
    grpc_csds.addArtifactArg(grpc_csds_emit);
    const grpc_csds_step = b.step("interop-grpc-csds", "Decode a netz CSDS ClientStatusResponse with the official Envoy schema");
    grpc_csds_step.dependOn(&grpc_csds.step);

    const grpc_cds_client = b.addExecutable(.{
        .name = "netz-grpc-cds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_cds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_cds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_cds/run.py" });
    grpc_cds.addArtifactArg(grpc_cds_client);
    if (b.args) |args| grpc_cds.addArgs(args);
    const grpc_cds_step = b.step("interop-grpc-cds", "Verify official CDS policy/circuit decoding and transactional CDS/EDS ADS publication with grpc-js-xds/grpc-js");
    grpc_cds_step.dependOn(&grpc_cds.step);

    const grpc_eds_client = b.addExecutable(.{
        .name = "netz-grpc-eds-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_eds/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_eds = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_eds/run.py" });
    grpc_eds.addArtifactArg(grpc_eds_client);
    if (b.args) |args| grpc_eds.addArgs(args);
    const grpc_eds_step = b.step("interop-grpc-eds", "Verify official EDS resources from ADS through typed validation, dynamic publication and priority/locality RPC routing");
    grpc_eds_step.dependOn(&grpc_eds.step);

    const grpc_eds_drop_client = b.addExecutable(.{
        .name = "netz-grpc-eds-drop-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_eds_drop/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_eds_drop = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_eds_drop/run.py" });
    grpc_eds_drop.addArtifactArg(grpc_eds_drop_client);
    if (b.args) |args| grpc_eds_drop.addArgs(args);
    const grpc_eds_drop_step = b.step("interop-grpc-eds-drop", "Verify EDS drop fractions, pre-wire RPC rejection, retry/hedging suppression and dynamic updates with official grpc-js-xds/grpc-js");
    grpc_eds_drop_step.dependOn(&grpc_eds_drop.step);

    const grpc_circuit_client = b.addExecutable(.{
        .name = "netz-grpc-circuit-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/grpc_circuit/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const grpc_circuit = b.addSystemCommand(&.{ "python3", "tools/interop/grpc_circuit/run.py" });
    grpc_circuit.addArtifactArg(grpc_circuit_client);
    if (b.args) |args| grpc_circuit.addArgs(args);
    const grpc_circuit_step = b.step("interop-grpc-circuit", "Verify shared cluster/EDS circuit budgets, changed limits and RPC permits against official grpc-js-xds/grpc-js");
    grpc_circuit_step.dependOn(&grpc_circuit.step);

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
        "Run strict h2spec against h2c, TLS 1.3, or TLS 1.2 (--tls/--tls12)",
    );
    h2spec_step.dependOn(&h2spec.step);

    const http_external_client_server = b.addExecutable(.{
        .name = "netz-http-external-client-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_external_client_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http2_nghttpd_client = b.addExecutable(.{
        .name = "netz-http2-nghttpd-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http2_nghttpd_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_external_clients = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http_external_clients.py",
    });
    http_external_clients.addArtifactArg(http_external_client_server);
    http_external_clients.addArtifactArg(http2_nghttpd_client);
    const http_external_clients_step = b.step(
        "interop-http-external-clients",
        "Run independent curl/nghttp2 peers against Netz HTTP endpoints",
    );
    http_external_clients_step.dependOn(&http_external_clients.step);

    const http_cookie_jar_peer = b.addExecutable(.{
        .name = "netz-http-cookie-jar-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_cookie_jar_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_cookie_curl = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http_cookie_curl.py",
    });
    http_cookie_curl.addArtifactArg(http_cookie_jar_peer);
    const http_cookie_curl_step = b.step(
        "interop-http-cookie-curl",
        "Compare Netz CookieJar path/order behavior with curl",
    );
    http_cookie_curl_step.dependOn(&http_cookie_curl.step);

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

    const connect_udp_hyper_peer = b.addExecutable(.{
        .name = "netz-connect-udp-hyper-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/connect_udp_hyper_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const connect_udp_hyper_interop = b.addSystemCommand(
        &.{"tools/interop/connect_udp_hyper.sh"},
    );
    connect_udp_hyper_interop.addArtifactArg(connect_udp_hyper_peer);
    const connect_udp_hyper_interop_step = b.step(
        "interop-connect-udp-hyper",
        "Run HTTP/1 and HTTP/2 CONNECT-UDP interop with Hyper",
    );
    connect_udp_hyper_interop_step.dependOn(
        &connect_udp_hyper_interop.step,
    );

    const connect_udp_h3_peer = b.addExecutable(.{
        .name = "netz-connect-udp-h3-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/connect_udp_h3_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const connect_udp_h3_interop = b.addSystemCommand(
        &.{"tools/interop/connect_udp_h3.sh"},
    );
    connect_udp_h3_interop.addArtifactArg(connect_udp_h3_peer);
    const connect_udp_h3_interop_step = b.step(
        "interop-connect-udp-h3",
        "Run bidirectional HTTP/3 CONNECT-UDP interop with h3/quinn",
    );
    connect_udp_h3_interop_step.dependOn(
        &connect_udp_h3_interop.step,
    );

    const connect_ip_h3_peer = b.addExecutable(.{
        .name = "netz-connect-ip-h3-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/connect_ip_h3_peer.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const connect_ip_h3_interop = b.addSystemCommand(
        &.{"tools/interop/connect_ip_h3.sh"},
    );
    connect_ip_h3_interop.addArtifactArg(connect_ip_h3_peer);
    const connect_ip_h3_interop_step = b.step(
        "interop-connect-ip-h3",
        "Run bidirectional HTTP/3 CONNECT-IP interop with h3/quinn",
    );
    connect_ip_h3_interop_step.dependOn(
        &connect_ip_h3_interop.step,
    );

    const http_unified_hyper_client = b.addExecutable(.{
        .name = "netz-http-unified-hyper-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http_unified_hyper_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http_unified_hyper = b.addSystemCommand(
        &.{"tools/interop/http_unified_hyper.sh"},
    );
    http_unified_hyper.addArtifactArg(http_unified_hyper_client);
    const http_unified_hyper_step = b.step(
        "interop-http-unified-hyper",
        "Run unified netz HTTP pool ALPN/reuse interop with Hyper",
    );
    http_unified_hyper_step.dependOn(&http_unified_hyper.step);

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
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
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
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
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
    const http3_quic_go_handlers = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go_handlers.sh"},
    );
    http3_quic_go_handlers.addArtifactArg(http3_quic_go_server);
    const http3_quic_go_handlers_step = b.step(
        "interop-http3-quic-go-handlers",
        "Run bounded HTTP/3 handler supervisor interop with concurrent quic-go clients",
    );
    http3_quic_go_handlers_step.dependOn(
        &http3_quic_go_handlers.step,
    );
    const http3_quic_go_bench = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go.sh"},
    );
    http3_quic_go_bench.addArtifactArg(http3_quic_go_client);
    http3_quic_go_bench.addArtifactArg(http3_quic_go_server);
    http3_quic_go_bench.addArg("--bench");
    if (b.args) |args| http3_quic_go_bench.addArgs(args);
    const http3_quic_go_bench_step = b.step(
        "bench-http3-quic-go",
        "Compare verified HTTP/3 upload/download against quic-go, with optional kernel capture",
    );
    http3_quic_go_bench_step.dependOn(&http3_quic_go_bench.step);
    const http3_quic_go_multistream = b.addSystemCommand(
        &.{"tools/interop/http3_quic_go_multistream.sh"},
    );
    http3_quic_go_multistream.addArtifactArg(http3_quic_go_client);
    http3_quic_go_multistream.addArtifactArg(http3_quic_go_server);
    if (b.args) |args| http3_quic_go_multistream.addArgs(args);
    const http3_quic_go_multistream_step = b.step(
        "bench-http3-quic-go-multistream",
        "Compare verified 4/16-stream HTTP/3 transfers against quic-go",
    );
    http3_quic_go_multistream_step.dependOn(
        &http3_quic_go_multistream.step,
    );

    const websocket_h3_quic_go_client = b.addExecutable(.{
        .name = "netz-websocket-h3-quic-go-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_client.zig",
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
    const websocket_h3_quic_go_server = b.addExecutable(.{
        .name = "netz-websocket-h3-quic-go-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_h3_quic_go_server.zig",
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
    const websocket_h3_socks5 = b.addSystemCommand(&.{
        "python3",
        "tools/interop/websocket_h3_socks5.py",
    });
    websocket_h3_socks5.addArtifactArg(websocket_h3_quic_go_client);
    const websocket_h3_socks5_step = b.step(
        "interop-websocket-h3-socks5",
        "Run RFC 9220 through an independent SOCKS5 UDP relay",
    );
    websocket_h3_socks5_step.dependOn(&websocket_h3_socks5.step);
    test_step.dependOn(&websocket_h3_socks5.step);
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
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{
                    .name = "benchmark_counting_allocator",
                    .module = benchmark_counting_allocator_mod,
                },
            },
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
    const websocket_hyper_h2_server = b.addExecutable(.{
        .name = "netz-websocket-hyper-h2-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/websocket_hyper_h2_server.zig",
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
    const websocket_hyper_h2_bench = b.addSystemCommand(
        &.{"tools/interop/websocket_hyper_h2_bench.sh"},
    );
    websocket_hyper_h2_bench.addArtifactArg(websocket_hyper_h2_client);
    websocket_hyper_h2_bench.addArtifactArg(websocket_hyper_h2_server);
    if (b.args) |args| websocket_hyper_h2_bench.addArgs(args);
    const websocket_hyper_h2_bench_step = b.step(
        "bench-websocket-hyper-h2",
        "Compare persistent RFC 8441 echo against Hyper",
    );
    websocket_hyper_h2_bench_step.dependOn(
        &websocket_hyper_h2_bench.step,
    );

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

    const http1_ocsp_client = b.addExecutable(.{
        .name = "netz-http1-ocsp-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/http1_ocsp_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const http1_ocsp_interop = b.addSystemCommand(&.{
        "python3",
        "tools/interop/http1_ocsp_client.py",
    });
    http1_ocsp_interop.addArtifactArg(http1_ocsp_client);
    const http1_ocsp_interop_step = b.step(
        "interop-http1-ocsp",
        "Require good OpenSSL TLS 1.2/1.3 OCSP staples from the HTTP/1 client",
    );
    http1_ocsp_interop_step.dependOn(&http1_ocsp_interop.step);
    test_step.dependOn(&http1_ocsp_interop.step);

    const tls12_ticket_server = b.addExecutable(.{
        .name = "netz-tls12-ticket-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/tls12_ticket_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const tls12_ticket_client = b.addExecutable(.{
        .name = "netz-tls12-ticket-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/tls12_ticket_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const tls12_ticket_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_ticket_openssl.sh"},
    );
    tls12_ticket_openssl.addArtifactArg(tls12_ticket_server);
    tls12_ticket_openssl.addArtifactArg(tls12_ticket_client);
    const tls12_ticket_openssl_step = b.step(
        "interop-tls12-ticket-openssl",
        "Verify bidirectional TLS 1.2 RFC 5077 resumption with OpenSSL",
    );
    tls12_ticket_openssl_step.dependOn(&tls12_ticket_openssl.step);
    test_step.dependOn(&tls12_ticket_openssl.step);

    const tls12_client_auth_client = b.addExecutable(.{
        .name = "netz-tls12-client-auth-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/tls12_client_auth_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const tls12_client_auth_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_client_auth_openssl.sh"},
    );
    tls12_client_auth_openssl.addArtifactArg(tls12_client_auth_client);
    tls12_client_auth_openssl.addArg("tls12");
    const tls12_client_auth_openssl_step = b.step(
        "interop-tls12-client-auth-openssl",
        "Verify matching/unmatched TLS 1.2 client identity selection against OpenSSL",
    );
    tls12_client_auth_openssl_step.dependOn(
        &tls12_client_auth_openssl.step,
    );
    test_step.dependOn(&tls12_client_auth_openssl.step);

    const tls13_client_auth_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_client_auth_openssl.sh"},
    );
    tls13_client_auth_openssl.addArtifactArg(tls12_client_auth_client);
    tls13_client_auth_openssl.addArg("tls13");
    const tls13_client_auth_openssl_step = b.step(
        "interop-tls13-client-auth-openssl",
        "Verify matching/unmatched TLS 1.3 client identity selection against OpenSSL",
    );
    tls13_client_auth_openssl_step.dependOn(
        &tls13_client_auth_openssl.step,
    );
    test_step.dependOn(&tls13_client_auth_openssl.step);

    const tls13_ticket_openssl = b.addSystemCommand(
        &.{"tools/interop/tls12_ticket_openssl.sh"},
    );
    tls13_ticket_openssl.addArtifactArg(tls12_ticket_server);
    tls13_ticket_openssl.addArtifactArg(tls12_ticket_client);
    tls13_ticket_openssl.addArg("tls13");
    const tls13_ticket_openssl_step = b.step(
        "interop-tls13-ticket-openssl",
        "Verify bidirectional TLS 1.3 session-ticket resumption with OpenSSL",
    );
    tls13_ticket_openssl_step.dependOn(&tls13_ticket_openssl.step);
    test_step.dependOn(&tls13_ticket_openssl.step);

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
            .exe_name = "netz-bench-mqtt-shared-properties",
            .path = "examples/bench_mqtt_shared_properties.zig",
            .run_step = "bench-mqtt-shared-properties",
            .description = "Benchmark shared MQTT Session metadata allocations and logical ownership",
        },
        .{
            .exe_name = "netz-bench-mqtt-commit-log",
            .path = "examples/bench_mqtt_commit_log.zig",
            .run_step = "bench-mqtt-commit-log",
            .description = "Measure MQTT snapshot serialization, journal append and fsync costs",
        },
        .{
            .exe_name = "netz-bench-mqtt-session",
            .path = "examples/bench_mqtt_session.zig",
            .run_step = "bench-mqtt-session",
            .description = "Benchmark MQTT persistent-session resume, queue and drain",
        },
        .{
            .exe_name = "netz-bench-mqtt-deadline",
            .path = "examples/bench_mqtt_deadline.zig",
            .run_step = "bench-mqtt-deadline",
            .description = "Benchmark complete QoS 1/2 delivery through deadline Session replay",
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
            .exe_name = "netz-bench-http-content-coding",
            .path = "examples/bench_http_content_coding.zig",
            .run_step = "bench-http-content-coding",
            .description = "Benchmark bounded HTTP Content-Encoding decode",
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
            .exe_name = "netz-bench-grpc-shared",
            .path = "examples/bench_grpc_shared.zig",
            .run_step = "bench-grpc-shared",
            .description = "Benchmark shared gRPC persistent ping-pong and RPC creation",
        },
        .{
            .exe_name = "netz-bench-grpc-unary",
            .path = "examples/bench_grpc_unary.zig",
            .run_step = "bench-grpc-unary",
            .description = "Benchmark ordinary gRPC unary persistent round trips",
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
            .exe_name = "netz-bench-quic-endpoint-cid-sync",
            .path = "examples/bench_quic_endpoint_cid_sync.zig",
            .run_step = "bench-quic-endpoint-cid-sync",
            .description = "Benchmark shared-endpoint CID route synchronization",
        },
        .{
            .exe_name = "netz-bench-quic-connection-router",
            .path = "examples/bench_quic_connection_router.zig",
            .run_step = "bench-quic-connection-router",
            .description = "Benchmark shared-endpoint CID routing",
        },
        .{
            .exe_name = "netz-bench-quic-endpoint-timers",
            .path = "examples/bench_quic_endpoint_timers.zig",
            .run_step = "bench-quic-endpoint-timers",
            .description = "Benchmark shared-endpoint timer scheduler scaling",
        },
        .{
            .exe_name = "netz-bench-io-deadline",
            .path = "examples/bench_io_deadline.zig",
            .run_step = "bench-io-deadline",
            .description = "Benchmark zio-backed timed I/O deadline overhead",
        },
        .{
            .exe_name = "netz-bench-quic-endpoint-pending",
            .path = "examples/bench_quic_endpoint_pending.zig",
            .run_step = "bench-quic-endpoint-pending",
            .description = "Benchmark shared-endpoint pending packet lookup scaling",
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
            .exe_name = "netz-bench-connect-udp-capsule",
            .path = "examples/bench_connect_udp_capsule.zig",
            .run_step = "bench-connect-udp-capsule",
            .description = "Benchmark CONNECT-UDP Capsule Session send and receive paths",
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
            .exe_name = "netz-bench-webtransport-stream-batch",
            .path = "examples/bench_webtransport_stream_batch.zig",
            .run_step = "bench-webtransport-stream-batch",
            .description = "Benchmark WebTransport steady stream-batch staging",
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
    var http1_pipeline_bench_exe: ?*std.Build.Step.Compile = null;
    var http1_body_bench_exe: ?*std.Build.Step.Compile = null;
    var grpc_shared_bench_exe: ?*std.Build.Step.Compile = null;
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
        if (std.mem.eql(u8, spec.run_step, "bench-http1-pipeline")) {
            http1_pipeline_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-http1-body")) {
            http1_body_bench_exe = exe;
        } else if (std.mem.eql(u8, spec.run_step, "bench-grpc-shared")) {
            grpc_shared_bench_exe = exe;
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
            .root_source_file = b.path("examples/http3_fetch.zig"),
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
            .root_source_file = b.path("examples/bench_websocket_echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_slices_h2 = b.addExecutable(.{
        .name = "netz-websocket-slices-h2",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/bench_websocket_h2_echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const websocket_slices_h3 = b.addExecutable(.{
        .name = "netz-websocket-slices-h3",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/bench_websocket_h3_echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
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

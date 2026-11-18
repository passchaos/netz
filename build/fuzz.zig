//! Fuzz target registration for the Netz build.
//!
//! Every target compiles one `test/*_fuzz_test.zig` module against the public
//! `netz` module and exposes a `fuzz-*` step. Corpus replay and coverage-guided
//! runs are documented in `docs/build.md`.

const std = @import("std");

pub fn addAll(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    test_step: *std.Build.Step,
) void {
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

    const run_proxy_fuzz_tests = addSimpleFuzzTarget(
        b,
        target,
        optimize,
        netz_mod,
        "fuzz-proxy",
        "Fuzz bounded application-proxy wire codecs",
        "test/proxy_fuzz_test.zig",
    );
    const run_wireguard_mesh_fuzz_tests = addSimpleFuzzTarget(
        b,
        target,
        optimize,
        netz_mod,
        "fuzz-wireguard-mesh",
        "Fuzz bounded WireGuard and mesh wire codecs",
        "test/wireguard_mesh_fuzz_test.zig",
    );
    test_step.dependOn(&run_proxy_fuzz_tests.step);
    test_step.dependOn(&run_wireguard_mesh_fuzz_tests.step);
}

fn addSimpleFuzzTarget(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    name: []const u8,
    description: []const u8,
    root_file: []const u8,
) *std.Build.Step.Run {
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_file),
            .target = target,
            .optimize = optimize,
            // See the parser fuzz target above: this is a Zig 0.16 fuzz-runner
            // workaround and does not disable allocator leak detection.
            .error_tracing = false,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    const run = b.addRunArtifact(tests);
    const step = b.step(name, description);
    step.dependOn(&run.step);
    return run;
}

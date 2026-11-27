//! MQTT and HTTP interop/live-peer verification steps.

const std = @import("std");

pub const Artifacts = struct {
    mqtt_vectors_broker: *std.Build.Step.Compile,
    mqtt_websocket_server: *std.Build.Step.Compile,
};

pub fn addAll(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    netz_mod: *std.Build.Module,
    test_step: *std.Build.Step,
) Artifacts {
    const harnessz_dep = b.dependency("harnessz", .{
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
    const shadowsocks_server = b.addExecutable(.{
        .name = "netz-shadowsocks-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/shadowsocks_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step(
        "build-shadowsocks-server",
        "Build the standalone Shadowsocks AEAD TCP server",
    ).dependOn(&b.addInstallArtifact(shadowsocks_server, .{}).step);
    const shadowsocks_gate = b.addSystemCommand(&.{"tools/interop/shadowsocks_sing_box.sh"});
    shadowsocks_gate.addArtifactArg(shadowsocks_server);
    if (b.args) |args| shadowsocks_gate.addArgs(args);
    b.step(
        "interop-shadowsocks-sing-box",
        "Verify the netz Shadowsocks AEAD server against a sing-box client",
    ).dependOn(&shadowsocks_gate.step);
    const trojan_server = b.addExecutable(.{
        .name = "netz-trojan-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/trojan_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step(
        "build-trojan-server",
        "Build the standalone Trojan TLS server",
    ).dependOn(&b.addInstallArtifact(trojan_server, .{}).step);
    const trojan_gate = b.addSystemCommand(&.{"tools/interop/trojan_sing_box.sh"});
    trojan_gate.addArtifactArg(trojan_server);
    if (b.args) |args| trojan_gate.addArgs(args);
    b.step(
        "interop-trojan-sing-box",
        "Verify the netz Trojan TLS server against a sing-box client",
    ).dependOn(&trojan_gate.step);
    const vless_server = b.addExecutable(.{
        .name = "netz-vless-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/vless_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step(
        "build-vless-server",
        "Build the standalone VLESS TLS server",
    ).dependOn(&b.addInstallArtifact(vless_server, .{}).step);
    const vless_gate = b.addSystemCommand(&.{"tools/interop/vless_sing_box.sh"});
    vless_gate.addArtifactArg(vless_server);
    if (b.args) |args| vless_gate.addArgs(args);
    b.step(
        "interop-vless-sing-box",
        "Verify the netz VLESS TLS server against a sing-box client",
    ).dependOn(&vless_gate.step);
    const vmess_server = b.addExecutable(.{
        .name = "netz-vmess-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/vmess_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step(
        "build-vmess-server",
        "Build the standalone VMess AEAD TLS server",
    ).dependOn(&b.addInstallArtifact(vmess_server, .{}).step);
    const vmess_gate = b.addSystemCommand(&.{"tools/interop/vmess_sing_box.sh"});
    vmess_gate.addArtifactArg(vmess_server);
    if (b.args) |args| vmess_gate.addArgs(args);
    b.step(
        "interop-vmess-sing-box",
        "Verify the netz VMess AEAD TLS server against a sing-box client",
    ).dependOn(&vmess_gate.step);
    const tuic_server = b.addExecutable(.{
        .name = "netz-tuic-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/tuic_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "netz", .module = netz_mod }},
        }),
    });
    b.step(
        "build-tuic-server",
        "Build the standalone TUIC v5 QUIC server",
    ).dependOn(&b.addInstallArtifact(tuic_server, .{}).step);
    const tuic_gate = b.addSystemCommand(&.{"tools/interop/tuic_sing_box.sh"});
    tuic_gate.addArtifactArg(tuic_server);
    if (b.args) |args| tuic_gate.addArgs(args);
    b.step(
        "interop-tuic-sing-box",
        "Verify the netz TUIC v5 server against a sing-box client",
    ).dependOn(&tuic_gate.step);
    const target_writer_probe_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy_target_writer_probe.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = netz_mod.link_libc,
    });
    var probe_imports = netz_mod.import_table.iterator();
    while (probe_imports.next()) |entry| target_writer_probe_mod.addImport(entry.key_ptr.*, entry.value_ptr.*);
    const target_writer_probe = b.addExecutable(.{
        .name = "netz-proxy-target-writer-probe",
        .root_module = target_writer_probe_mod,
    });
    b.step("build-proxy-target-writer-probe", "Build the standalone target-writer service and retained-storage probe")
        .dependOn(&b.addInstallArtifact(target_writer_probe, .{}).step);
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
            .root_source_file = b.path("examples/mqtt/mqtt_broker.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{ .name = "support", .module = examples_support_mod },
            },
        }),
    });
    b.step("build-mqtt-vector-broker", "Build the standalone MQTT wire-vector broker").dependOn(&b.addInstallArtifact(mqtt_vectors_broker, .{}).step);
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
            .root_source_file = b.path("examples/benchmarks/bench_mqtt_broker.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "netz", .module = netz_mod },
                .{ .name = "support", .module = examples_support_mod },
            },
        }),
    });
    const mqtt_broker_compare = b.addSystemCommand(&.{
        "tools/compare_mqtt_mosquitto.sh",
    });
    b.step(
        "build-mqtt-bench",
        "Build the standalone MQTT broker benchmark driver",
    ).dependOn(&b.addInstallArtifact(mqtt_broker_bench, .{}).step);
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

    @import("../tools/interop/webtransport_h2/build.zig").add(b, target, optimize, netz_mod, test_step);
    @import("../tools/interop/http_digest/build.zig").add(b, target, optimize, netz_mod, test_step);

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
    return .{
        .mqtt_vectors_broker = mqtt_vectors_broker,
        .mqtt_websocket_server = mqtt_websocket_server,
    };
}

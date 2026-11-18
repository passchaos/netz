//! MQTT broker and interop verification steps.

const std = @import("std");

pub fn addBrokerSteps(
    b: *std.Build,
    test_step: *std.Build.Step,
    mqtt_vectors_broker: *std.Build.Step.Compile,
    mqtt_websocket_server: *std.Build.Step.Compile,
) void {
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
}

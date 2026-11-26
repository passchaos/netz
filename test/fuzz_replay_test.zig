//! All original corpus callbacks, grouped by protocol for shared compilation.
const options = @import("fuzz_replay_options");

comptime {
    switch (options.family) {
        .codecs => {
            _ = @import("parser_fuzz_test.zig");
            _ = @import("stateful_fuzz_test.zig");
            _ = @import("websocket_compression_fuzz_test.zig");
            _ = @import("http_content_coding_fuzz_test.zig");
            _ = @import("websocket_context_fuzz_test.zig");
            _ = @import("quic_wire_fuzz_test.zig");
            _ = @import("quic_protection_fuzz_test.zig");
            _ = @import("proxy_fuzz_test.zig");
            _ = @import("wireguard_mesh_fuzz_test.zig");
        },
        .http1 => {
            _ = @import("http1_connection_fuzz_test.zig");
            _ = @import("http1_tls_connection_fuzz_test.zig");
            _ = @import("websocket_h1_context_fuzz_test.zig");
            _ = @import("websocket_h1_tls_context_fuzz_test.zig");
        },
        .http2 => {
            _ = @import("http2_connection_fuzz_test.zig");
            _ = @import("http2_tls_connection_fuzz_test.zig");
            _ = @import("websocket_h2_context_fuzz_test.zig");
            _ = @import("websocket_h2_tls_context_fuzz_test.zig");
        },
        .http3 => {
            _ = @import("http3_connection_fuzz_test.zig");
            _ = @import("webtransport_endpoint_fuzz_test.zig");
            _ = @import("websocket_h3_context_fuzz_test.zig");
        },
        .mqtt_bridge => {
            _ = @import("mqtt_bridge_fuzz_test.zig");
            _ = @import("mqtt_tls_bridge_fuzz_test.zig");
            _ = @import("mqtt_bridge_qos2_fuzz_test.zig");
            _ = @import("mqtt_tls_bridge_qos2_fuzz_test.zig");
        },
        .mqtt_outbound => {
            _ = @import("mqtt_outbound_bridge_fuzz_test.zig");
            _ = @import("mqtt_tls_outbound_bridge_fuzz_test.zig");
            _ = @import("mqtt_outbound_bridge_qos2_fuzz_test.zig");
            _ = @import("mqtt_tls_outbound_bridge_qos2_fuzz_test.zig");
        },
        .mqtt_sessions => {
            _ = @import("mqtt_live_broker_fuzz_test.zig");
            _ = @import("mqtt_tls_live_broker_fuzz_test.zig");
            _ = @import("mqtt_reconnect_fuzz_test.zig");
            _ = @import("mqtt_tls_reconnect_fuzz_test.zig");
            _ = @import("mqtt_wss_reconnect_fuzz_test.zig");
        },
        .quic => {
            _ = @import("quic_connection_fuzz_test.zig");
            _ = @import("quic_path_fuzz_test.zig");
            _ = @import("quic_handshake_fuzz_test.zig");
            _ = @import("quic_endpoint_fuzz_test.zig");
        },
    }
}

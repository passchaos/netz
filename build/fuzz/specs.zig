//! Shared membership for independent fuzz targets and grouped corpus replay.
const std = @import("std");

pub const Family = enum { codecs, http1, http2, http3, mqtt_bridge, mqtt_outbound, mqtt_sessions, quic };
pub const Spec = struct { name: []const u8, description: []const u8, root: []const u8, family: Family };

pub const all = [_]Spec{
    .{ .name = "fuzz-parsers", .description = "Fuzz bounded HTTP/WebSocket/WebTransport/MQTT parsers", .root = "test/parser_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-stateful", .description = "Fuzz bounded HTTP/WebSocket/WebTransport/MQTT state sequences", .root = "test/stateful_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-mqtt-live-broker", .description = "Fuzz live MQTT broker ordering and retained routing", .root = "test/mqtt_live_broker_fuzz_test.zig", .family = .mqtt_sessions },
    .{ .name = "fuzz-mqtt-tls-live-broker", .description = "Fuzz authenticated TLS MQTT broker ordering and routing", .root = "test/mqtt_tls_live_broker_fuzz_test.zig", .family = .mqtt_sessions },
    .{ .name = "fuzz-mqtt-reconnect", .description = "Fuzz live MQTT reconnect and Session recovery ordering", .root = "test/mqtt_reconnect_fuzz_test.zig", .family = .mqtt_sessions },
    .{ .name = "fuzz-mqtt-tls-reconnect", .description = "Fuzz authenticated TLS MQTT reconnect and Session recovery", .root = "test/mqtt_tls_reconnect_fuzz_test.zig", .family = .mqtt_sessions },
    .{ .name = "fuzz-mqtt-wss-reconnect", .description = "Fuzz authenticated WSS MQTT reconnect and Session recovery", .root = "test/mqtt_wss_reconnect_fuzz_test.zig", .family = .mqtt_sessions },
    .{ .name = "fuzz-mqtt-bridge", .description = "Fuzz live inbound MQTT bridge routing and reconnects", .root = "test/mqtt_bridge_fuzz_test.zig", .family = .mqtt_bridge },
    .{ .name = "fuzz-mqtt-tls-bridge", .description = "Fuzz authenticated TLS MQTT inbound bridge routing", .root = "test/mqtt_tls_bridge_fuzz_test.zig", .family = .mqtt_bridge },
    .{ .name = "fuzz-mqtt-bridge-qos2", .description = "Fuzz durable inbound MQTT bridge QoS 2 recovery", .root = "test/mqtt_bridge_qos2_fuzz_test.zig", .family = .mqtt_bridge },
    .{ .name = "fuzz-mqtt-tls-bridge-qos2", .description = "Fuzz durable inbound MQTT bridge QoS 2 over authenticated TLS", .root = "test/mqtt_tls_bridge_qos2_fuzz_test.zig", .family = .mqtt_bridge },
    .{ .name = "fuzz-mqtt-outbound-bridge", .description = "Fuzz outbound MQTT bridge routing and reconnects", .root = "test/mqtt_outbound_bridge_fuzz_test.zig", .family = .mqtt_outbound },
    .{ .name = "fuzz-mqtt-tls-outbound-bridge", .description = "Fuzz outbound MQTT bridge routing across authenticated TLS peers", .root = "test/mqtt_tls_outbound_bridge_fuzz_test.zig", .family = .mqtt_outbound },
    .{ .name = "fuzz-mqtt-outbound-bridge-qos2", .description = "Fuzz durable outbound MQTT bridge QoS 2 recovery", .root = "test/mqtt_outbound_bridge_qos2_fuzz_test.zig", .family = .mqtt_outbound },
    .{ .name = "fuzz-mqtt-tls-outbound-bridge-qos2", .description = "Fuzz durable outbound MQTT bridge QoS 2 across authenticated TLS peers", .root = "test/mqtt_tls_outbound_bridge_qos2_fuzz_test.zig", .family = .mqtt_outbound },
    .{ .name = "fuzz-http1-connection", .description = "Fuzz live HTTP/1 connection reuse and framing", .root = "test/http1_connection_fuzz_test.zig", .family = .http1 },
    .{ .name = "fuzz-http1-tls-connection", .description = "Fuzz authenticated HTTP/1 TLS connection state", .root = "test/http1_tls_connection_fuzz_test.zig", .family = .http1 },
    .{ .name = "fuzz-http2-connection", .description = "Fuzz live HTTP/2 h2c connection state", .root = "test/http2_connection_fuzz_test.zig", .family = .http2 },
    .{ .name = "fuzz-http2-tls-connection", .description = "Fuzz authenticated HTTP/2 TLS connection state", .root = "test/http2_tls_connection_fuzz_test.zig", .family = .http2 },
    .{ .name = "fuzz-http3-connection", .description = "Fuzz authenticated HTTP/3 connection state", .root = "test/http3_connection_fuzz_test.zig", .family = .http3 },
    .{ .name = "fuzz-webtransport-endpoint", .description = "Fuzz authenticated WebTransport shared-endpoint routing", .root = "test/webtransport_endpoint_fuzz_test.zig", .family = .http3 },
    .{ .name = "fuzz-websocket-compression", .description = "Fuzz bounded WebSocket permessage-deflate codecs", .root = "test/websocket_compression_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-http-content-coding", .description = "Fuzz bounded HTTP Content-Encoding parsing and decode", .root = "test/http_content_coding_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-websocket-context", .description = "Fuzz bounded WebSocket compression context sequences", .root = "test/websocket_context_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-websocket-h1-context", .description = "Fuzz WebSocket context takeover over live HTTP/1 connections", .root = "test/websocket_h1_context_fuzz_test.zig", .family = .http1 },
    .{ .name = "fuzz-websocket-h1-tls-context", .description = "Fuzz WebSocket context takeover over authenticated WSS", .root = "test/websocket_h1_tls_context_fuzz_test.zig", .family = .http1 },
    .{ .name = "fuzz-websocket-h2-context", .description = "Fuzz WebSocket context takeover over live HTTP/2 connections", .root = "test/websocket_h2_context_fuzz_test.zig", .family = .http2 },
    .{ .name = "fuzz-websocket-h2-tls-context", .description = "Fuzz RFC 8441 context takeover over authenticated TLS", .root = "test/websocket_h2_tls_context_fuzz_test.zig", .family = .http2 },
    .{ .name = "fuzz-websocket-h3-context", .description = "Fuzz WebSocket context takeover over live HTTP/3 connections", .root = "test/websocket_h3_context_fuzz_test.zig", .family = .http3 },
    .{ .name = "fuzz-quic-wire", .description = "Fuzz bounded QUIC frames, parameters, packets, and TLS messages", .root = "test/quic_wire_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-quic-protection", .description = "Fuzz bounded QUIC packet and header protection", .root = "test/quic_protection_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-quic-connection", .description = "Fuzz bounded stateful QUIC connection sequences", .root = "test/quic_connection_fuzz_test.zig", .family = .quic },
    .{ .name = "fuzz-quic-path", .description = "Fuzz authenticated QUIC migration and rebinding state", .root = "test/quic_path_fuzz_test.zig", .family = .quic },
    .{ .name = "fuzz-quic-handshake", .description = "Fuzz authenticated QUIC/TLS handshake recovery", .root = "test/quic_handshake_fuzz_test.zig", .family = .quic },
    .{ .name = "fuzz-quic-endpoint", .description = "Fuzz authenticated QUIC endpoint capacity and ownership", .root = "test/quic_endpoint_fuzz_test.zig", .family = .quic },
    .{ .name = "fuzz-proxy", .description = "Fuzz bounded application-proxy wire codecs", .root = "test/proxy_fuzz_test.zig", .family = .codecs },
    .{ .name = "fuzz-wireguard-mesh", .description = "Fuzz bounded WireGuard and mesh wire codecs", .root = "test/wireguard_mesh_fuzz_test.zig", .family = .codecs },
};

pub fn validateRoot(source: []const u8) error{ InvalidImport, DuplicateRoot, MissingRoot, WrongFamily }!void {
    var seen = [_]bool{false} ** all.len;
    var family: ?Family = null;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len != 0 and line[0] == '.') {
            if (std.mem.indexOf(u8, line, " =>")) |end| {
                family = std.meta.stringToEnum(Family, line[1..end]) orelse return error.WrongFamily;
            }
        }
        const marker = "@import(\"";
        const begin = (std.mem.indexOf(u8, line, marker) orelse continue) + marker.len;
        const end = begin + (std.mem.indexOfScalar(u8, line[begin..], '"') orelse return error.InvalidImport);
        const path = line[begin..end];
        if (std.mem.eql(u8, path, "fuzz_replay_options")) continue;
        const index = for (all, 0..) |spec, index| {
            if (std.mem.eql(u8, path, spec.root["test/".len..])) break index;
        } else return error.InvalidImport;
        if (seen[index]) return error.DuplicateRoot;
        if (family == null or family.? != all[index].family) return error.WrongFamily;
        seen[index] = true;
    }
    for (seen) |present| if (!present) return error.MissingRoot;
}

//! Finite MQTT WS/WSS server for Mosquitto-derived process interoperability.

const std = @import("std");
const netz = @import("netz");

const tls_test = netz.tls.testing;
const max_packet_size: usize = 128 * 1024;
const expected_payload_len: usize = 36 * 1821;

const Transport = enum { ws, wss, proxy_ws, proxy_wss, origin };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    const transport = std.meta.stringToEnum(Transport, args[1]) orelse
        return error.InvalidArguments;
    const protocol: netz.mqtt.ProtocolVersion = if (std.mem.eql(
        u8,
        args[2],
        "v31",
    ))
        .v3_1
    else if (std.mem.eql(
        u8,
        args[2],
        "v311",
    ))
        .v3_1_1
    else if (std.mem.eql(u8, args[2], "v5"))
        .v5
    else
        return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, args[3], 10);

    const allocator = init.gpa;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);

    switch (transport) {
        .ws, .proxy_ws, .origin => {
            var server = try netz.mqtt.websocket_runtime.Server.listen(
                allocator,
                io,
                address,
                .{
                    .limits = .{
                        .max_packet_size = max_packet_size,
                        .proxy_protocol = if (transport == .proxy_ws)
                            .v1
                        else
                            null,
                    },
                    .max_head_bytes = 16 * 1024,
                    .allowed_origins = if (transport == .origin)
                        &.{"https://example.org"}
                    else
                        &.{},
                },
            );
            defer server.deinit();
            std.debug.print(
                "netz MQTT WS interop server listening " ++
                    "client_io=python-socket server_io=zio-std-io\n",
                .{},
            );
            if (transport == .origin) {
                try std.testing.expectError(
                    error.InvalidOrigin,
                    server.accept(.{ .protocol = protocol }),
                );
            }
            try serveOne(
                &server,
                protocol,
                transport == .origin,
                transport == .proxy_ws,
            );
        },
        .wss, .proxy_wss => {
            var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
            try std.base64.standard.Decoder.decode(
                &certificate_der,
                tls_test.certificate_base64,
            );
            const key_pair = try tls_test.serverKeyPair();
            var server = try netz.mqtt.websocket_runtime.TlsServer.listen(
                allocator,
                io,
                address,
                .{
                    .identity = .{
                        .certificate_chain = &.{&certificate_der},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = key_pair,
                        } },
                    },
                    .limits = .{
                        .max_packet_size = max_packet_size,
                        .proxy_protocol = if (transport == .proxy_wss)
                            .v2
                        else
                            null,
                    },
                    .max_head_bytes = 16 * 1024,
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                },
            );
            defer server.deinit();
            std.debug.print(
                "netz MQTT WSS interop server listening " ++
                    "client_io=python-socket server_io=zio-std-io\n",
                .{},
            );
            try serveOne(
                &server,
                protocol,
                false,
                transport == .proxy_wss,
            );
        },
    }
}

fn serveOne(
    server: anytype,
    protocol: netz.mqtt.ProtocolVersion,
    origin_mode: bool,
    proxy_mode: bool,
) !void {
    var accepted = try server.accept(.{
        .protocol = protocol,
        .max_outgoing_inflight = 20,
        .topic_alias_maximum = 10,
    });
    defer accepted.deinit(server.allocator);

    const expected_client_id = if (origin_mode)
        "origin-allowed"
    else switch (protocol) {
        .v3_1 => "mosquitto-ws-v31",
        .v3_1_1 => "mosquitto-ws-v311",
        .v5 => "mosquitto-ws-v5",
    };
    try std.testing.expectEqualStrings(
        expected_client_id,
        accepted.connect.connect.client_id,
    );
    if (proxy_mode) {
        const metadata = accepted.connection.proxyMetadata() orelse
            return error.MissingProxyMetadata;
        try std.testing.expectEqual(
            @as(u16, 6275),
            accepted.connection.remoteAddress().ip4.port,
        );
        try std.testing.expectEqual(
            if (@TypeOf(server.*) == netz.mqtt.websocket_runtime.TlsServer)
                netz.mqtt.proxy_protocol.Version.v2
            else
                netz.mqtt.proxy_protocol.Version.v1,
            metadata.version,
        );
    }
    if (origin_mode) {
        var disconnect = try accepted.connection.readDisconnect();
        defer disconnect.deinit(server.allocator);
        return;
    }

    var publish = try accepted.connection.readPublish();
    defer publish.deinit(server.allocator);
    try std.testing.expectEqual(netz.mqtt.QoS.at_least_once, publish.publish.qos);
    try std.testing.expectEqualStrings(
        "interop/mosquitto/to-netz",
        publish.publish.topic,
    );
    try std.testing.expectEqual(
        @as(usize, expected_payload_len),
        publish.publish.payload.len,
    );
    for (publish.publish.payload, 0..) |byte, index| {
        const pattern = "abcdefghijklmnopqrstuvwxyz0123456789";
        if (byte != pattern[index % pattern.len]) {
            return error.InvalidInteropPayload;
        }
    }
    try accepted.connection.writePubAck(
        publish.publish.packet_id.?,
        0,
    );

    // The client deliberately coalesces this MQTT packet after the final
    // bytes of its PUBLISH while splitting that PUBLISH across two WebSocket
    // messages. Reading it here proves both byte-stream boundary directions.
    try accepted.connection.readPingReq();
    try accepted.connection.writePingResp();
    // The peer sends another PUBLISH immediately before a legal client-side
    // PINGREQ. Consume the application packet first, then answer liveness in
    // exact MQTT byte-stream order.
    var interleaved = try accepted.connection.readPublish();
    defer interleaved.deinit(server.allocator);
    try std.testing.expectEqualStrings(
        "interop/mosquitto/during-ping",
        interleaved.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "interleaved-publish",
        interleaved.publish.payload,
    );
    try accepted.connection.readPingReq();
    try accepted.connection.writePingResp();

    try accepted.connection.publish(
        "interop/netz/to-mosquitto",
        "netz-websocket-reply",
        .{ .qos = .at_least_once },
    );
    var disconnect = try accepted.connection.readDisconnect();
    defer disconnect.deinit(server.allocator);
}

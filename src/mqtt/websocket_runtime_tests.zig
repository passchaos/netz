const std = @import("std");
const mqtt = @import("mod.zig");
const runtime = @import("runtime.zig");
const mqtt_ws = @import("websocket_runtime.zig");
const reconnect = @import("reconnect.zig");
const websocket_runtime = @import("../websocket/mod.zig").runtime;
const tls_stream = @import("../tls/mod.zig").stream;
const tls_testing = @import("../tls/testing.zig");

const max_packet_size: usize = 4096;

fn writeStreamAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (written == 0) return error.ConnectionClosed;
        offset += written;
    }
}

test "MQTT 5 WebSocket runtime negotiates mqtt and completes QoS 1 and 2" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{ .max_packet_size = max_packet_size },
            .max_head_bytes = max_packet_size,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "mqtt-ws-v5",
                accepted.connect.connect.client_id,
            );

            var qos1 = try accepted.connection.readPublish();
            defer qos1.deinit(server_ptr.allocator);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, qos1.publish.qos);
            try std.testing.expectEqualStrings("ws/qos1", qos1.publish.topic);
            try std.testing.expectEqualStrings("one", qos1.publish.payload);
            try accepted.connection.writePubAck(qos1.publish.packet_id.?, 0);

            var qos2 = try accepted.connection.readPublish();
            defer qos2.deinit(server_ptr.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, qos2.publish.qos);
            try std.testing.expectEqualStrings("ws/qos2", qos2.publish.topic);
            try std.testing.expectEqualStrings("two", qos2.publish.payload);
            try accepted.connection.writePubRec(qos2.publish.packet_id.?, 0);

            var pubrel = try accepted.connection.readPubRel();
            defer pubrel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                qos2.publish.packet_id.?,
                pubrel.ack.packet_id,
            );
            try accepted.connection.writePubComp(pubrel.ack.packet_id, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try mqtt_ws.Client.connect(allocator, io, server.address(), .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mqtt-ws-v5",
            .limits = .{ .max_packet_size = max_packet_size },
            .max_outgoing_inflight = 2,
        },
        .host = "127.0.0.1",
        .target = "/mqtt",
        .max_head_bytes = max_packet_size,
    });
    defer client.close();
    try client.publish("ws/qos1", "one", .{ .qos = .at_least_once });
    try client.publish("ws/qos2", "two", .{ .qos = .exactly_once });
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket server caller timeout spans Upgrade and CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{ .max_packet_size = max_packet_size },
            .max_head_bytes = max_packet_size,
        },
    );
    defer server.deinit();
    try std.testing.expectError(
        error.Timeout,
        server.acceptPendingWithTimeout(
            .{ .connect_timeout = .fromSeconds(1) },
            .fromMilliseconds(20),
        ),
    );

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.acceptPendingWithTimeout(
                .{ .connect_timeout = .fromSeconds(1) },
                .fromMilliseconds(50),
            ) catch |err| {
                self.err = err;
                return;
            };
            pending.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var ws = try websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "localhost",
            .target = "/mqtt",
            .protocols = &.{"mqtt"},
        },
    );
    defer ws.close();
    try std.Io.sleep(io, .fromMilliseconds(25), .awake);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT WebSocket server consumes PROXY v1 before HTTP Upgrade" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_packet_size = max_packet_size,
                .proxy_protocol = .v1,
                .proxy_header_timeout = .fromSeconds(1),
            },
            .max_head_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            const source = accepted.connection.remoteAddress();
            if (metadata.version != .v1 or source != .ip4 or
                source.ip4.port != 6275 or
                !std.mem.eql(u8, &source.ip4.bytes, &.{ 192, 0, 2, 5 }))
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    try writeStreamAll(
        io,
        stream,
        "PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n",
    );
    const ws = try websocket_runtime.Client.connectAcceptedStream(
        allocator,
        io,
        stream,
        .{
            .host = "localhost",
            .target = "/mqtt",
            .protocols = &.{"mqtt"},
            .limits = .{
                .max_head_bytes = max_packet_size,
                .max_frame_bytes = max_packet_size,
                .max_message_bytes = max_packet_size,
            },
        },
    );
    stream_owned = false;
    var connection = try runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-websocket",
    });
    try std.testing.expect(attempt.accepted());
    var accepted = try attempt.requireAccepted();
    defer accepted.deinit(allocator);
    try accepted.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS server negotiates mqtt and completes QoS 1" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .max_head_bytes = max_packet_size,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{
                .protocol = .v5,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            if (accepted.connection.peerCertificates() != null) {
                shared.err = error.UnexpectedPeerCertificate;
                return;
            }
            var publish = accepted.connection.readPublish() catch |err| {
                shared.err = err;
                return;
            };
            defer publish.deinit(shared.server.allocator);
            if (!std.mem.eql(
                u8,
                publish.publish.topic,
                "wss/qos1",
            )) {
                shared.err = error.UnexpectedPacket;
                return;
            }
            accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            ) catch |err| {
                shared.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_ws.Client.connectUri(
        allocator,
        io,
        uri,
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-wss-v5",
                .limits = .{ .max_packet_size = max_packet_size },
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
            .max_head_bytes = max_packet_size,
        },
    );
    defer client.close();
    try client.publish(
        "wss/qos1",
        "encrypted websocket mqtt",
        .{ .qos = .at_least_once },
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS client connects and reconnects through hostname" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = max_packet_size },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for ([_][]const u8{
                "wss-host",
                "wss-reconnect-host",
                "wss-reconnect-host",
                "wss-address",
                "wss-address",
            }, 0..) |client_id, index| {
                var accepted = try self.server.accept(.{
                    .protocol = .v5,
                    .session_present = index == 2 or index == 4,
                });
                try std.testing.expectEqualStrings(
                    client_id,
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
                accepted.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const options: mqtt_ws.ConnectOptions = .{
        .mqtt = .{
            .client_id = "placeholder",
            .network_connect_timeout = .fromSeconds(1),
        },
        .target = "/mqtt",
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    };

    var direct = try mqtt_ws.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        blk: {
            var direct_options = options;
            direct_options.mqtt.client_id = "wss-host";
            break :blk direct_options;
        },
    );
    defer direct.close();
    try direct.disconnect(0);

    var connector = mqtt_ws.TlsHostReconnectConnector{
        .host = "localhost",
        .port = server.address().ip4.port,
        .options = options,
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "wss-reconnect-host",
            .clean_start = false,
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    try client.disconnect(0);
    const second = try client.connect();
    try std.testing.expect(second.session_present);
    try client.disconnect(0);

    var address_connector = mqtt_ws.TlsAddressReconnectConnector{
        .address = server.address(),
        .tls_host = "localhost",
        .options = options,
    };
    var address_shutdown: std.Io.Event = .unset;
    var address_client = try reconnect.Client.initConnector(
        allocator,
        io,
        address_connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "wss-address",
            .clean_start = false,
        },
        .{},
        &address_shutdown,
    );
    defer address_client.deinit();
    _ = try address_client.connect();
    try address_client.disconnect(0);
    const address_second = try address_client.connect();
    try std.testing.expect(address_second.session_present);
    try address_client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS server consumes PROXY v2 before TLS and Upgrade" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_packet_size = max_packet_size,
                .proxy_protocol = .v2,
                .proxy_header_timeout = .fromSeconds(1),
            },
            .max_head_bytes = max_packet_size,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            if (metadata.version != .v2 or
                accepted.connection.remoteAddress().ip4.port != 6275)
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    try writeStreamAll(io, stream, &(mqtt.proxy_protocol.v2_signature ++
        [_]u8{ 0x21, 0x11, 0x00, 0x0c } ++
        [_]u8{
            192, 0, 2, 5, 127, 0, 0, 1, 0x18, 0x83, 0x07, 0x5b,
        }));
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const ws = try websocket_runtime.Client.connectAcceptedTlsStream(
        allocator,
        io,
        stream,
        "localhost",
        .{
            .host = "localhost",
            .target = "/mqtt",
            .protocols = &.{"mqtt"},
            .limits = .{
                .max_head_bytes = max_packet_size,
                .max_frame_bytes = max_packet_size,
                .max_message_bytes = max_packet_size,
            },
        },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    );
    stream_owned = false;
    var connection = try runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-wss",
    });
    try std.testing.expect(attempt.accepted());
    var accepted = try attempt.requireAccepted();
    defer accepted.deinit(allocator);
    try accepted.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS client identity completes authenticated QoS 1" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .max_head_bytes = max_packet_size,
            .client_auth = .{ .verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        expected_certificate: *const [tls_testing.certificate_der_len]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{
                .protocol = .v5,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const chain = accepted.connection.peerCertificates() orelse {
                shared.err = error.MissingPeerCertificate;
                return;
            };
            if (chain.len != 1 or !std.mem.eql(
                u8,
                chain[0],
                shared.expected_certificate,
            )) {
                shared.err = error.InvalidPeerCertificate;
                return;
            }
            var publish =
                accepted.connection.readPublish() catch |err| {
                    shared.err = err;
                    return;
                };
            defer publish.deinit(shared.server.allocator);
            if (!std.mem.eql(
                u8,
                publish.publish.topic,
                "wss/mtls/qos1",
            )) {
                shared.err = error.UnexpectedPacket;
                return;
            }
            accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            ) catch |err| {
                shared.err = err;
            };
        }
    };
    var shared = Shared{
        .server = &server,
        .expected_certificate = &certificate_der,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_ws.Client.connectUri(
        allocator,
        io,
        uri,
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-wss-mtls",
                .limits = .{ .max_packet_size = max_packet_size },
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .max_head_bytes = max_packet_size,
        },
    );
    defer client.close();
    const server_chain = client.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqual(@as(usize, 1), server_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        &certificate_der,
        server_chain[0],
    );
    try client.publish(
        "wss/mtls/qos1",
        "authenticated websocket mqtt",
        .{ .qos = .at_least_once },
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT 3.1.1 WebSocket runtime uses shared session state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v3_1_1 });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.ProtocolVersion.v3_1_1,
                accepted.connection.protocol,
            );
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("ws/v3", publish.publish.topic);
            try std.testing.expectEqualStrings("payload", publish.publish.payload);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try mqtt_ws.Client.connect(allocator, io, server.address(), .{
        .mqtt = .{
            .protocol = .v3_1_1,
            .client_id = "mqtt-ws-v3",
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .host = "127.0.0.1",
    });
    defer client.close();
    try client.publish("ws/v3", "payload", .{});

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket client connects through ws URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(
                server_ptr.allocator,
            );
            try std.testing.expectEqualStrings(
                "mqtt-ws-uri",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(
                server_ptr.allocator,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_ws.Client.connectUri(allocator, io, uri, .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mqtt-ws-uri",
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .max_head_bytes = max_packet_size,
    });
    defer client.close();
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket client connects through hostname" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "mqtt-ws-host",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try mqtt_ws.Client.connectHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-ws-host",
                .network_connect_timeout = .fromSeconds(1),
            },
            .target = "/mqtt",
        },
    );
    defer client.close();
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket reconnect client reuses hostname connector" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                var accepted = try self.server.accept(.{
                    .protocol = .v5,
                    .session_present = index != 0,
                });
                try std.testing.expectEqualStrings(
                    "reconnect-ws-host",
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
                accepted.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connector = mqtt_ws.HostReconnectConnector{
        .host = "localhost",
        .port = server.address().ip4.port,
        .options = .{
            .mqtt = .{
                .client_id = "placeholder",
                .network_connect_timeout = .fromSeconds(1),
            },
            .target = "/mqtt",
        },
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-ws-host",
            .clean_start = false,
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    try client.disconnect(0);
    const second = try client.connect();
    try std.testing.expect(second.session_present);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket client follows Server Reference CONNACK" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer redirector.deinit();
    var destination = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer destination.deinit();

    const Shared = struct {
        redirector: *mqtt_ws.Server,
        destination: *mqtt_ws.Server,
        reference: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.redirector.accept(.{
                .protocol = .v5,
                .reason_code = 0x9d,
                .server_reference = self.reference,
            });
            defer first.deinit(self.redirector.allocator);
            var second = try self.destination.accept(.{ .protocol = .v5 });
            defer second.deinit(self.destination.allocator);
            try std.testing.expectEqualStrings(
                "mqtt-ws-redirect",
                second.connect.connect.client_id,
            );
            var disconnect = try second.connection.readDisconnect();
            defer disconnect.deinit(self.destination.allocator);
        }
    };
    const reference = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/redirected-mqtt",
        .{destination.address().ip4.port},
    );
    defer allocator.free(reference);
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .reference = reference,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/mqtt",
        .{redirector.address().ip4.port},
    );
    defer allocator.free(initial_uri);
    var result = try mqtt_ws.Client.connectUriFollowingRedirects(
        allocator,
        io,
        initial_uri,
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-ws-redirect",
                .limits = .{ .max_packet_size = max_packet_size },
            },
            .max_head_bytes = max_packet_size,
        },
        .{ .max_redirects = 1 },
    );
    defer result.deinit(allocator);
    try result.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket reader preserves MQTT byte stream across messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = max_packet_size,
            .max_frame_bytes = max_packet_size,
            .max_message_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *websocket_runtime.Server) !void {
            var ws = try server_ptr.accept(.{
                .protocols = &.{"mqtt"},
                .require_subprotocol = true,
            });
            defer ws.close();

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.http.allocator);
            try mqtt.writePing(&encoded, server_ptr.http.allocator, false);
            try mqtt.writePing(&encoded, server_ptr.http.allocator, false);
            // First MQTT packet spans two WebSocket messages; the second packet
            // shares the latter message. This is the byte-stream behavior used
            // by rumqtt's WsStream and must not depend on message boundaries.
            try ws.sendBinary(encoded.items[0..1]);
            try ws.sendBinary(encoded.items[1..]);

            var first = try ws.receiveMessage();
            defer first.deinit(server_ptr.http.allocator);
            var second = try ws.receiveMessage();
            defer second.deinit(server_ptr.http.allocator);
            try mqtt.validatePing(first.payload, true);
            try mqtt.validatePing(second.payload, true);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ws = try websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .protocols = &.{"mqtt"},
            .limits = .{
                .max_head_bytes = max_packet_size,
                .max_frame_bytes = max_packet_size,
                .max_message_bytes = max_packet_size,
            },
        },
    );
    var connection = try runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    defer connection.close();
    try connection.readPingReq();
    try connection.writePingResp();
    try connection.readPingReq();
    try connection.writePingResp();

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT reconnect client reuses WebSocket connector" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            first.deinit(self.server.allocator);
            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var connector = mqtt_ws.ReconnectConnector{
        .uri = uri,
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .max_head_bytes = max_packet_size,
        },
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-ws",
            .clean_start = false,
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var first = (try client.pollWithTimeout(.fromSeconds(10))) orelse
        return error.TestExpectedConnectEvent;
    defer first.deinit(allocator);
    try std.testing.expect(first == .connected);
    var second = (try client.pollWithTimeout(.fromSeconds(10))) orelse
        return error.TestExpectedReconnectEvent;
    defer second.deinit(allocator);
    try std.testing.expect(second == .connected);
    try std.testing.expect(second.connected.session_present);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn testReconnectClientAutomaticallyResumesWssTicket(
    comptime protocol_policy: tls_stream.VersionPolicy,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var keyring = try tls_stream.Tls13TicketKeyring.init(.{
        .id = 19,
        .secret = [_]u8{0x39} ** tls_stream.tls13_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = protocol_policy,
            .alpn_protocols = &.{"http/1.1"},
            .tls12_session_tickets = if (protocol_policy == .tls12_only) .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            } else null,
            .tls13_session_tickets = if (protocol_policy == .tls13_only) .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            } else null,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        resumed: [2]bool = .{ false, false },
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                var accepted = try self.server.accept(.{
                    .protocol = .v5,
                    .session_present = index != 0,
                });
                defer accepted.deinit(self.server.allocator);
                self.resumed[index] =
                    accepted.connection.wasTlsSessionResumed() orelse
                    return error.MissingTlsMetadata;
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var connector = mqtt_ws.ReconnectConnector{
        .uri = uri,
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = protocol_policy,
        },
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-wss",
            .clean_start = false,
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    const first = try client.connectWithTimeout(.fromSeconds(10));
    try std.testing.expect(!first.session_present);
    try std.testing.expect(!client.connection().?.wasTlsSessionResumed().?);
    try client.disconnect(0);
    const second = try client.connectWithTimeout(.fromSeconds(10));
    try std.testing.expect(second.session_present);
    try std.testing.expect(client.connection().?.wasTlsSessionResumed().?);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(bool, &.{ false, true }, &shared.resumed);
}

test "MQTT reconnect client automatically resumes TLS 1.2 WSS tickets" {
    try testReconnectClientAutomaticallyResumesWssTicket(.tls12_only);
}

test "MQTT reconnect client automatically resumes TLS 1.3 WSS tickets" {
    try testReconnectClientAutomaticallyResumesWssTicket(.tls13_only);
}

test "MQTT WebSocket server requires mqtt subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_packet_size = max_packet_size } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            std.testing.expectError(
                error.InvalidSubprotocol,
                shared.server.accept(.{}),
            ) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.ConnectionClosed,
        websocket_runtime.Client.connect(
            allocator,
            io,
            server.address(),
            .{
                .host = "127.0.0.1",
                .protocols = &.{"chat"},
                .limits = .{
                    .max_head_bytes = max_packet_size,
                    .max_frame_bytes = max_packet_size,
                    .max_message_bytes = max_packet_size,
                },
            },
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket adapter rejects text messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = max_packet_size,
            .max_frame_bytes = max_packet_size,
            .max_message_bytes = max_packet_size,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *websocket_runtime.Server) !void {
            var ws = try server_ptr.accept(.{
                .protocols = &.{"mqtt"},
                .require_subprotocol = true,
            });
            defer ws.close();
            try ws.sendText("not-mqtt");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ws = try websocket_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .protocols = &.{"mqtt"},
            .limits = .{
                .max_head_bytes = max_packet_size,
                .max_frame_bytes = max_packet_size,
                .max_message_bytes = max_packet_size,
            },
        },
    );
    var connection = try runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    defer connection.close();
    try std.testing.expectError(
        error.InvalidWebSocketMessage,
        connection.readPingReq(),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT WebSocket server enforces Origin allowlist" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try mqtt_ws.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{ .max_packet_size = max_packet_size },
            .allowed_origins = &.{"https://example.org"},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_ws.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_ws.Server) !void {
            try std.testing.expectError(
                error.InvalidOrigin,
                server_ptr.accept(.{ .protocol = .v5 }),
            );
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "mqtt-origin-allowed",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.ConnectionClosed,
        mqtt_ws.Client.connect(allocator, io, server.address(), .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-origin-denied",
            },
            .host = "127.0.0.1",
            .origin = "https://denied.example",
        }),
    );
    var client = try mqtt_ws.Client.connect(allocator, io, server.address(), .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mqtt-origin-allowed",
        },
        .host = "127.0.0.1",
        .origin = "https://example.org",
    });
    defer client.close();
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS listener bounds an idle TLS handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try mqtt_ws.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls_handshake_timeout = .fromMilliseconds(75),
        },
    );
    defer server.deinit();
    try std.testing.expectError(
        error.Timeout,
        server.acceptPendingWithTimeout(
            .{ .connect_timeout = .fromSeconds(1) },
            .fromMilliseconds(20),
        ),
    );

    const Shared = struct {
        server: *mqtt_ws.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            accepted.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT vail WSS client bounds an idle server handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const key_pair = try tls_testing.serverKeyPair();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );

    const Shared = struct {
        io: std.Io,
        listener: *std.Io.net.Server,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(
                self.io,
                .fromMilliseconds(250),
                .awake,
            ) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://127.0.0.1:{d}/mqtt",
        .{listener.socket.address.ip4.port},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUri(allocator, io, uri, .{
            .mqtt = .{ .client_id = "wss-timeout" },
            // Supplying an identity deliberately selects the vail path.
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .server_verifier = .{},
            .tls_handshake_timeout = .fromMilliseconds(75),
        }),
    );
    thread.join();
    joined = true;
}

test "MQTT standard WSS client bounds an idle server handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://127.0.0.1:{d}/mqtt",
        .{listener.socket.address.ip4.port},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUri(allocator, io, uri, .{
            .mqtt = .{ .client_id = "wss-std-timeout" },
            .tls = .{ .verify_host = false },
            .tls_handshake_timeout = .fromMilliseconds(20),
        }),
    );
    thread.join();
}

test "MQTT WebSocket reconnect connector preserves network timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var connector = mqtt_ws.ReconnectConnector{
        .uri = "ws://127.0.0.1:1/mqtt",
        .options = .{ .mqtt = .{
            .client_id = "placeholder",
            .network_connect_timeout = .zero,
        } },
    };
    try std.testing.expectError(
        error.Timeout,
        connector.connector().connectAttempt(allocator, io, .{
            .client_id = "reconnect-timeout",
            .network_connect_timeout = .fromSeconds(1),
        }),
    );
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    var certificate_der: [tls_testing.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

const std = @import("std");
const mqtt_runtime = @import("../runtime.zig");
const mqtt_ws = @import("../websocket_runtime.zig");
const reconnect = @import("../reconnect.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const websocket_runtime = @import("../../websocket/runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;
const max_packet_size: usize = 4096;

fn acceptProxyTunnel(
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: *net.Server,
    expected_target: []const u8,
) !net.Stream {
    const stream = try listener.accept(io);
    var owned = true;
    errdefer if (owned) stream.close(io);
    var connect = try http1_runtime.readRequestFromStream(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = max_packet_size, .max_body_bytes = 0 },
        .{},
    );
    defer connect.deinit(allocator);
    try std.testing.expect(connect.request.method == .CONNECT);
    try std.testing.expectEqualStrings(expected_target, connect.request.target);
    try std.testing.expectEqualStrings(
        "Basic bXF0dC1wcm94eQ==",
        connect.request.header("proxy-authorization").?,
    );
    try std.testing.expect(connect.request.header("authorization") == null);
    try http1_runtime.writeResponseToStream(
        allocator,
        io,
        stream,
        .{ .status = 200, .request_method = .CONNECT },
    );
    owned = false;
    return stream;
}

fn acceptMqttOnWebSocketStream(
    comptime WebSocketServer: type,
    allocator: std.mem.Allocator,
    server: *WebSocketServer,
    stream: net.Stream,
    expected_host: []const u8,
    expected_target: []const u8,
    accept_options: mqtt_runtime.AcceptOptions,
) !mqtt_runtime.AcceptedClient {
    var pending = try server.receiveStreamUpgradeRequest(stream, .{
        .protocols = &.{"mqtt"},
        .require_subprotocol = true,
    });
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    try std.testing.expectEqualStrings(expected_target, pending.target());
    try std.testing.expectEqualStrings(expected_host, pending.header("host").?);
    try std.testing.expectEqualStrings(
        "Bearer mqtt-origin",
        pending.header("authorization").?,
    );
    try std.testing.expect(pending.header("proxy-authorization") == null);
    const ws = try pending.accept();
    pending_owned = false;
    var connection = try mqtt_runtime.Connection.initWebSocket(
        allocator,
        ws,
        .v5,
        .{ .max_packet_size = max_packet_size },
        16,
        16,
    );
    errdefer connection.close();
    return connection.accept(accept_options);
}

fn proxyOptions() mqtt_ws.HttpProxyOptions {
    return .{ .headers = &.{.{
        .name = "Proxy-Authorization",
        .value = "Basic bXF0dC1wcm94eQ==",
    }} };
}

fn connectOptions(client_id: []const u8) mqtt_ws.ConnectOptions {
    return .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = client_id,
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .extra_headers = &.{.{
            .name = "Authorization",
            .value = "Bearer mqtt-origin",
        }},
        .max_head_bytes = max_packet_size,
    };
}

fn proxyUri(
    buffer: []u8,
    proxy: *const net.Server,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "http://127.0.0.1:{d}",
        .{proxy.socket.address.getPort()},
    );
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
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

test "MQTT WS URI connects through HTTP CONNECT proxy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "localhost:80",
            );
            var accepted = try acceptMqttOnWebSocketStream(
                websocket_runtime.Server,
                allocator,
                self.server,
                stream,
                "localhost",
                "/mqtt?tenant=one",
                .{ .protocol = .v5 },
            );
            defer accepted.deinit(allocator);
            try std.testing.expectEqualStrings(
                "mqtt-proxy-ws",
                accepted.connect.connect.client_id,
            );
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(allocator);
            try std.testing.expectEqualStrings(
                "proxy/ws",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings("payload", publish.publish.payload);
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );
            var disconnect = try accepted.connection.readDisconnect();
            disconnect.deinit(allocator);
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    var client = try mqtt_ws.Client.connectUriViaProxyWithTimeout(
        allocator,
        io,
        try proxyUri(&proxy_uri_buffer, &proxy),
        "ws://localhost/mqtt?tenant=one#not-on-wire",
        connectOptions("mqtt-proxy-ws"),
        proxyOptions(),
        .fromSeconds(3),
    );
    defer client.close();
    try client.publish(
        "proxy/ws",
        "payload",
        .{ .qos = .at_least_once },
    );
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS URI authenticates origin through HTTP CONNECT proxy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try websocket_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *websocket_runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "localhost:443",
            );
            var accepted = try acceptMqttOnWebSocketStream(
                websocket_runtime.TlsServer,
                allocator,
                self.server,
                stream,
                "localhost",
                "/mqtt",
                .{ .protocol = .v5 },
            );
            defer accepted.deinit(allocator);
            try std.testing.expectEqualStrings(
                "mqtt-proxy-wss",
                accepted.connect.connect.client_id,
            );
            var disconnect = try accepted.connection.readDisconnect();
            disconnect.deinit(allocator);
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var options = connectOptions("mqtt-proxy-wss");
    options.tls = .{ .ca_bundle = .{
        .bundle = &ca_bundle,
        .lock = &ca_lock,
    } };
    var proxy_uri_buffer: [64]u8 = undefined;
    var client = try mqtt_ws.Client.connectUriViaProxyWithTimeout(
        allocator,
        io,
        try proxyUri(&proxy_uri_buffer, &proxy),
        "wss://localhost/mqtt#not-on-wire",
        options,
        proxyOptions(),
        .fromSeconds(3),
    );
    defer client.close();
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket proxy reconnect connector reopens CONNECT tunnel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                const stream = try acceptProxyTunnel(
                    allocator,
                    self.io,
                    self.proxy,
                    "reconnect.example:80",
                );
                var accepted = try acceptMqttOnWebSocketStream(
                    websocket_runtime.Server,
                    allocator,
                    self.server,
                    stream,
                    "reconnect.example",
                    "/mqtt",
                    .{
                        .protocol = .v5,
                        .session_present = index != 0,
                    },
                );
                try std.testing.expectEqualStrings(
                    "mqtt-proxy-reconnect",
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(allocator);
                accepted.deinit(allocator);
            }
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    var connector = mqtt_ws.ProxyReconnectConnector{
        .proxy_uri = try proxyUri(&proxy_uri_buffer, &proxy),
        .uri = "ws://reconnect.example/mqtt",
        .options = connectOptions("placeholder"),
        .proxy_options = proxyOptions(),
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "mqtt-proxy-reconnect",
            .clean_start = false,
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    const first = try client.connectWithTimeout(.fromSeconds(3));
    try std.testing.expect(!first.session_present);
    try client.disconnect(0);
    const second = try client.connectWithTimeout(.fromSeconds(3));
    try std.testing.expect(second.session_present);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WSS proxy reconnect resumes TLS 1.3 session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var keyring = try tls_stream.Tls13TicketKeyring.init(.{
        .id = 29,
        .secret = [_]u8{0x59} ** tls_stream.tls13_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try websocket_runtime.TlsServer.listen(
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
            .alpn_protocols = &.{"http/1.1"},
            .tls13_session_tickets = .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *websocket_runtime.TlsServer,
        resumed: [2]bool = .{ false, false },
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                const stream = try acceptProxyTunnel(
                    allocator,
                    self.io,
                    self.proxy,
                    "localhost:443",
                );
                var accepted = try acceptMqttOnWebSocketStream(
                    websocket_runtime.TlsServer,
                    allocator,
                    self.server,
                    stream,
                    "localhost",
                    "/mqtt",
                    .{
                        .protocol = .v5,
                        .session_present = index != 0,
                    },
                );
                self.resumed[index] =
                    accepted.connection.wasTlsSessionResumed() orelse
                    return error.MissingTlsMetadata;
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(allocator);
                accepted.deinit(allocator);
            }
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    var options = connectOptions("placeholder");
    options.server_verifier = .{
        .pinned_ecdsa_p256_public_key = public_key,
    };
    options.alpn_protocols = &.{"http/1.1"};
    var connector = mqtt_ws.ProxyReconnectConnector{
        .proxy_uri = try proxyUri(&proxy_uri_buffer, &proxy),
        .uri = "wss://localhost/mqtt",
        .options = options,
        .proxy_options = proxyOptions(),
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "mqtt-proxy-wss-resume",
            .clean_start = false,
            .limits = .{ .max_packet_size = max_packet_size },
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    const first = try client.connectWithTimeout(.fromSeconds(5));
    try std.testing.expect(!first.session_present);
    try std.testing.expect(!client.connection().?.wasTlsSessionResumed().?);
    try client.disconnect(0);
    const second = try client.connectWithTimeout(.fromSeconds(5));
    try std.testing.expect(second.session_present);
    try std.testing.expect(client.connection().?.wasTlsSessionResumed().?);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(bool, &.{ false, true }, &shared.resumed);
}

test "MQTT WebSocket redirects retain HTTP CONNECT proxy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var server = try websocket_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = max_packet_size },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *websocket_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const first_stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "initial.example:80",
            );
            var first = try acceptMqttOnWebSocketStream(
                websocket_runtime.Server,
                allocator,
                self.server,
                first_stream,
                "initial.example:80",
                "/mqtt",
                .{
                    .protocol = .v5,
                    .reason_code = 0x9d,
                    .server_reference = "ws://redirected.example/next",
                },
            );
            first.deinit(allocator);

            const second_stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "redirected.example:80",
            );
            var second = try acceptMqttOnWebSocketStream(
                websocket_runtime.Server,
                allocator,
                self.server,
                second_stream,
                "redirected.example:80",
                "/next",
                .{ .protocol = .v5 },
            );
            defer second.deinit(allocator);
            try std.testing.expectEqualStrings(
                "mqtt-proxy-redirect",
                second.connect.connect.client_id,
            );
            var disconnect = try second.connection.readDisconnect();
            disconnect.deinit(allocator);
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    var result = try mqtt_ws.Client.connectUriViaProxyFollowingRedirectsWithTimeout(
        allocator,
        io,
        try proxyUri(&proxy_uri_buffer, &proxy),
        "ws://initial.example/mqtt",
        connectOptions("mqtt-proxy-redirect"),
        proxyOptions(),
        .{ .max_redirects = 1 },
        .fromSeconds(5),
    );
    defer result.deinit(allocator);
    try result.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT WebSocket proxy timeout rejects expired budget before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUriViaProxyWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://127.0.0.1:1",
            "ws://localhost/mqtt",
            connectOptions("mqtt-proxy-timeout"),
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUriViaProxyFollowingRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://127.0.0.1:1",
            "ws://localhost/mqtt",
            connectOptions("mqtt-proxy-redirect-timeout"),
            .{},
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        mqtt_ws.Client.connectUriFollowingRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "ws://127.0.0.1:1/mqtt",
            connectOptions("mqtt-redirect-timeout"),
            .{},
            .zero,
        ),
    );
}

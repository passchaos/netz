const std = @import("std");
const mqtt = @import("mod.zig");
const runtime = @import("runtime.zig");
const websocket = @import("../websocket/mod.zig");
const websocket_runtime = websocket.runtime;
const http1_runtime = @import("../http1/mod.zig").runtime;

const net = std.Io.net;
const mqtt_subprotocol = "mqtt";

/// MQTT-over-WebSocket listener.
///
/// The HTTP opening handshake succeeds only when the client offers the
/// registered `mqtt` subprotocol. permessage-deflate is deliberately disabled:
/// MQTT has its own packet-size limits, and compression would make those limits
/// depend on decompression rather than the peer's MQTT Control Packet bytes.
pub const Server = struct {
    allocator: std.mem.Allocator,
    websocket_server: websocket_runtime.Server,
    limits: runtime.Limits,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: ListenOptions,
    ) runtime.Error!Server {
        return .{
            .allocator = allocator,
            .websocket_server = try .listen(
                allocator,
                io,
                bind_address,
                websocketLimits(options.limits, options.max_head_bytes),
            ),
            .limits = options.limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.websocket_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.websocket_server.address();
    }

    pub fn accept(
        self: *Server,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.AcceptedClient {
        var ws = try self.websocket_server.accept(.{
            .protocols = &.{mqtt_subprotocol},
            .require_subprotocol = true,
        });
        var ws_owned = true;
        errdefer if (ws_owned) ws.close();

        var connection = runtime.Connection.initWebSocket(
            self.allocator,
            ws,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        ws_owned = false;
        errdefer connection.close();
        return connection.accept(options);
    }
};

pub const ListenOptions = struct {
    limits: runtime.Limits = .{},
    max_head_bytes: usize = 64 * 1024,
};

/// MQTT-over-WSS listener.
///
/// TLS 1.3 termination and optional client authentication are delegated to the
/// generic WebSocket TLS listener. MQTT still requires the registered `mqtt`
/// subprotocol and enters the same broker-side state machine as WS/TCP/TLS.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    websocket_server: websocket_runtime.TlsServer,
    limits: runtime.Limits,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) runtime.Error!TlsServer {
        return .{
            .allocator = allocator,
            .websocket_server = try .listen(
                allocator,
                io,
                bind_address,
                .{
                    .identity = options.identity,
                    .limits = websocketLimits(
                        options.limits,
                        options.max_head_bytes,
                    ),
                    .cipher_suites = options.cipher_suites,
                    .max_client_hello_size = options.max_client_hello_size,
                    .max_client_handshake_size = options.max_client_handshake_size,
                    .client_auth = options.client_auth,
                    .tcp_nodelay = options.tcp_nodelay,
                },
            ),
            .limits = options.limits,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.websocket_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: TlsServer) net.IpAddress {
        return self.websocket_server.address();
    }

    pub fn accept(
        self: *TlsServer,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.AcceptedClient {
        var ws = try self.websocket_server.accept(.{
            .protocols = &.{mqtt_subprotocol},
            .require_subprotocol = true,
        });
        var ws_owned = true;
        errdefer if (ws_owned) ws.close();

        var connection = runtime.Connection.initWebSocket(
            self.allocator,
            ws,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        ws_owned = false;
        errdefer connection.close();
        return connection.accept(options);
    }

    pub fn serveConcurrent(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        max_connections: usize,
        options: runtime.AcceptOptions,
    ) runtime.AsyncServeError!runtime.ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(
            ?anyerror,
            max_connections,
        );
        errdefer self.allocator.free(results);
        @memset(results, null);
        for (results) |*result| {
            var accepted = try self.accept(options);
            errdefer accepted.deinit(self.allocator);
            group.async(
                self.websocket_server.io,
                TlsServeTask(HandlerContext).run,
                .{TlsServeTask(HandlerContext){
                    .accepted = accepted,
                    .context = context,
                    .handler = handler,
                    .result = result,
                    .allocator = self.allocator,
                }},
            );
        }
        try group.await(self.websocket_server.io);
        return .{
            .allocator = self.allocator,
            .errors = results,
        };
    }
};

pub const TlsListenOptions = struct {
    identity: @import("vail").tls.auth.ServerIdentity,
    limits: runtime.Limits = .{},
    max_head_bytes: usize = 64 * 1024,
    cipher_suites: []const @import("vail").tls.cipher_suite.Suite =
        &@import("vail").tls.cipher_suite.default_preference,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    client_auth: ?@import("vail").tls.client_auth.ServerPolicy = null,
    tcp_nodelay: bool = true,
};

fn TlsServeTask(comptime HandlerContext: type) type {
    return struct {
        accepted: runtime.AcceptedClient,
        context: *HandlerContext,
        handler: *const fn (
            *HandlerContext,
            *runtime.AcceptedClient,
        ) runtime.Error!void,
        result: *?anyerror,
        allocator: std.mem.Allocator,

        fn run(task: @This()) std.Io.Cancelable!void {
            var accepted = task.accepted;
            defer accepted.deinit(task.allocator);
            task.handler(task.context, &accepted) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

/// MQTT-over-WebSocket client with strict `Sec-WebSocket-Protocol: mqtt`
/// negotiation. `connectUri*` supports both `ws://` and `wss://` through the
/// existing WebSocket TLS client.
pub const Client = struct {
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectWithConnAck(allocator, io, address, options);
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectAttempt(allocator, io, address, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connect(
            allocator,
            io,
            address,
            websocketConnectOptions(options),
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriWithConnAck(
            allocator,
            io,
            uri,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriAttempt(allocator, io, uri, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectUriTls(
            allocator,
            io,
            uri,
            websocketConnectOptions(options),
            options.tls,
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }
};

pub const ConnectOptions = struct {
    mqtt: runtime.ConnectOptions,
    host: []const u8 = "",
    target: []const u8 = "/mqtt",
    max_head_bytes: usize = 64 * 1024,
    tcp_nodelay: bool = true,
    tls: http1_runtime.TlsClientOptions = .{},
};

fn websocketLimits(
    limits: runtime.Limits,
    max_head_bytes: usize,
) websocket_runtime.Limits {
    return .{
        .max_head_bytes = max_head_bytes,
        .max_frame_bytes = limits.max_packet_size,
        .max_message_bytes = limits.max_packet_size,
    };
}

fn websocketConnectOptions(
    options: ConnectOptions,
) websocket_runtime.ConnectOptions {
    return .{
        .host = options.host,
        .target = options.target,
        .protocols = &.{mqtt_subprotocol},
        .tcp_nodelay = options.tcp_nodelay,
        .limits = websocketLimits(
            options.mqtt.limits,
            options.max_head_bytes,
        ),
    };
}

fn connectWebSocketAttempt(
    allocator: std.mem.Allocator,
    ws: websocket_runtime.Connection,
    options: runtime.ConnectOptions,
) runtime.Error!runtime.ConnectAttempt {
    if (ws.selected_protocol == null or
        !std.mem.eql(u8, ws.selected_protocol.?, mqtt_subprotocol))
    {
        var invalid_ws = ws;
        invalid_ws.close();
        return error.InvalidSubprotocol;
    }

    var connection = runtime.Connection.initWebSocket(
        allocator,
        ws,
        options.protocol,
        options.limits,
        options.max_outgoing_inflight,
        options.topic_alias_maximum,
    );
    connection.max_incoming_inflight =
        mqtt.receiveMaximum(options.properties) orelse
        options.max_outgoing_inflight;
    connection.peer_maximum_qos = options.peer_maximum_qos;
    connection.peer_retain_available = options.peer_retain_available;
    errdefer connection.close();
    return connection.establishClient(options);
}
